use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use fsring_abi::ids::{FileId, LinkId, OpId, TransactionId};
use fsring_abi::layout::op;
use fsring_abi::msgs::{create_result, file_attributes, SizeState};
use fsring_abi::validate::completion_status;
use fsring_user::{CommitEffect, CommitRequest, FileSystemResult, PrepareResult, PreparedRequest};

use crate::identity::{
    ExistingOpenNamespaceEffect, ExistingOpenSizeEffect, GenerationDomain, NativeKey, RegistryError,
};
use crate::path::{component_from_utf16le, Component};
use crate::{metadata, status, windows, MirrorFs};

const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const SUPPORTED_CREATE_OPTIONS: u32 = FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE;
const SUPPORTED_BASIC_ATTRIBUTES: u32 = file_attributes::SETTABLE_BASIC_MASK;
const SUPPORTED_OPEN_ATTRIBUTES: u32 = SUPPORTED_BASIC_ATTRIBUTES | file_attributes::DIRECTORY;
const SUPPORTED_SHARE_ACCESS: u32 =
    windows::FILE_SHARE_READ | windows::FILE_SHARE_WRITE | windows::FILE_SHARE_DELETE;
const SECURITY_INFORMATION: u32 = windows::OWNER_SECURITY_INFORMATION
    | windows::GROUP_SECURITY_INFORMATION
    | windows::DACL_SECURITY_INFORMATION;

#[derive(Clone, Debug)]
pub(crate) enum CreatePlan {
    Existing {
        file_id: FileId,
        link_id: LinkId,
        is_directory: bool,
        basic_attributes: u32,
        parent_namespace_generation: u64,
    },
    Prospective {
        component: Component,
        is_directory: bool,
        parent_namespace_generation: u64,
    },
}

#[derive(Clone)]
pub(crate) struct PendingOpen {
    pub transaction_id: TransactionId,
    pub request: PreparedRequest,
    pub result: PrepareResult,
    pub path: PathBuf,
    pub parent_native: NativeKey,
    pub target_native: Option<NativeKey>,
    pub prospective_file_id: FileId,
    pub create_plan: CreatePlan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenState {
    Live,
    Cleaned,
}

pub(crate) struct OpenRecord {
    #[allow(dead_code)]
    pub handle: windows::NativeHandle,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub relative_path: PathBuf,
    #[allow(dead_code)]
    pub granted_access: u32,
    pub(crate) share_access: u32,
    pub state: OpenState,
}

pub(crate) struct PendingOpenTable {
    pending_by_op: HashMap<OpId, PendingOpen>,
    pending_by_tx: HashMap<TransactionId, OpId>,
}

impl std::fmt::Debug for PendingOpenTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingOpenTable")
            .field("pending_by_op_len", &self.pending_by_op.len())
            .field("pending_by_tx_len", &self.pending_by_tx.len())
            .finish()
    }
}

impl PendingOpenTable {
    pub(crate) fn new() -> Self {
        Self {
            pending_by_op: HashMap::new(),
            pending_by_tx: HashMap::new(),
        }
    }

    fn validate(&self) -> Result<(), ()> {
        if self.pending_by_op.len() != self.pending_by_tx.len() {
            return Err(());
        }
        for (op_id, record) in &self.pending_by_op {
            if *op_id != record.request.op_id
                || is_zero_transaction(record.transaction_id)
                || self.pending_by_tx.get(&record.transaction_id) != Some(op_id)
            {
                return Err(());
            }
        }
        if self.pending_by_tx.iter().any(|(transaction_id, op_id)| {
            self.pending_by_op
                .get(op_id)
                .is_none_or(|record| record.transaction_id != *transaction_id)
        }) {
            return Err(());
        }
        Ok(())
    }

    fn replay_or_preflight(
        &mut self,
        request: &PreparedRequest,
        transaction_id: TransactionId,
    ) -> FileSystemResult<Option<PrepareResult>> {
        self.validate().map_err(|()| internal())?;
        if let Some(existing) = self.pending_by_op.get(&request.op_id) {
            return if existing.request == *request {
                Ok(Some(existing.result.clone()))
            } else {
                Err(terminal(completion_status::DATA_ERROR))
            };
        }
        if is_zero_transaction(transaction_id) || self.pending_by_tx.contains_key(&transaction_id) {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        self.pending_by_op
            .try_reserve(1)
            .map_err(|_| terminal(completion_status::INSUFFICIENT_RESOURCES))?;
        self.pending_by_tx
            .try_reserve(1)
            .map_err(|_| terminal(completion_status::INSUFFICIENT_RESOURCES))?;
        Ok(None)
    }

    fn insert_preflighted(&mut self, record: PendingOpen) {
        let op_id = record.request.op_id;
        let transaction_id = record.transaction_id;
        debug_assert!(!self.pending_by_op.contains_key(&op_id));
        debug_assert!(!self.pending_by_tx.contains_key(&transaction_id));
        self.pending_by_tx.insert(transaction_id, op_id);
        self.pending_by_op.insert(op_id, record);
        debug_assert!(self.validate().is_ok());
    }

    fn exact(&self, request: &CommitRequest) -> FileSystemResult<&PendingOpen> {
        self.validate().map_err(|()| internal())?;
        let op_id = self
            .pending_by_tx
            .get(&request.transaction_id)
            .ok_or_else(|| terminal(completion_status::DATA_ERROR))?;
        if *op_id != request.op_id {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        let record = self.pending_by_op.get(op_id).ok_or_else(internal)?;
        if record.transaction_id != request.transaction_id || record.request.op_id != request.op_id
        {
            return Err(internal());
        }
        Ok(record)
    }

    fn remove_exact(&mut self, transaction_id: TransactionId) -> Result<Option<PendingOpen>, ()> {
        self.validate()?;
        let Some(op_id) = self.pending_by_tx.get(&transaction_id).copied() else {
            return Ok(None);
        };
        let record = self.pending_by_op.get(&op_id).ok_or(())?;
        if record.transaction_id != transaction_id {
            return Err(());
        }
        self.pending_by_tx.remove(&transaction_id);
        let removed = self.pending_by_op.remove(&op_id).ok_or(())?;
        debug_assert!(self.validate().is_ok());
        Ok(Some(removed))
    }
}

pub(crate) struct OpenTable {
    opens_by_kernel_id: HashMap<u64, OpenRecord>,
}

pub(crate) struct OpenPathPlan {
    replacements: Vec<Option<PathBuf>>,
}

struct OpenReopenEntry {
    old_path: PathBuf,
    new_path: PathBuf,
    granted_access: u32,
    share_access: u32,
    directory: bool,
    placeholder: Option<windows::NativeHandle>,
}

pub(crate) struct OpenReopenPlan {
    entries: Vec<Option<OpenReopenEntry>>,
    reopened: Vec<Option<windows::NativeHandle>>,
}

impl OpenReopenPlan {
    /// Drop every old subtree handle after replacing it with an already-opened
    /// root placeholder. No path work, allocation, or fallible lookup occurs.
    pub(crate) fn release_old_handles(&mut self, table: &mut OpenTable) {
        for ((_, record), entry) in table.opens_by_kernel_id.iter_mut().zip(&mut self.entries) {
            if let Some(entry) = entry {
                if let Some(mut placeholder) = entry.placeholder.take() {
                    std::mem::swap(&mut record.handle, &mut placeholder);
                    drop(placeholder);
                }
            }
        }
    }

    pub(crate) fn reopen(&mut self, new_paths: bool) -> io::Result<()> {
        for (entry, reopened) in self.entries.iter().zip(&mut self.reopened) {
            *reopened = entry
                .as_ref()
                .map(|entry| {
                    windows::open_existing(
                        if new_paths {
                            &entry.new_path
                        } else {
                            &entry.old_path
                        },
                        entry.granted_access,
                        entry.share_access,
                        entry.directory,
                    )
                })
                .transpose()?;
        }
        Ok(())
    }

    pub(crate) fn install_handles(self, table: &mut OpenTable) {
        for (((_, record), entry), handle) in table
            .opens_by_kernel_id
            .iter_mut()
            .zip(self.entries)
            .zip(self.reopened)
        {
            if entry.is_some() {
                if let Some(handle) = handle {
                    record.handle = handle;
                }
            }
        }
    }
}

impl OpenPathPlan {
    /// Apply a path plan prepared against the unchanged open table. The table
    /// is not structurally mutated between preparation and this commit, so the
    /// same iteration visits the same records; the tail only moves owned paths.
    pub(crate) fn commit(self, table: &mut OpenTable) {
        for ((_, record), replacement) in table.opens_by_kernel_id.iter_mut().zip(self.replacements)
        {
            if let Some(path) = replacement {
                record.relative_path = path;
            }
        }
    }
}

impl std::fmt::Debug for OpenTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenTable")
            .field("opens_by_kernel_id_len", &self.opens_by_kernel_id.len())
            .finish()
    }
}

impl OpenTable {
    pub(crate) fn new() -> Self {
        Self {
            opens_by_kernel_id: HashMap::new(),
        }
    }

    pub(crate) fn preflight_rename_paths(
        &self,
        source_file: FileId,
        source_link: LinkId,
        old_path: &Path,
        new_path: &Path,
        directory: bool,
    ) -> FileSystemResult<OpenPathPlan> {
        self.validate().map_err(|()| internal())?;
        let mut replacements = Vec::new();
        replacements
            .try_reserve_exact(self.opens_by_kernel_id.len())
            .map_err(|_| terminal(completion_status::INSUFFICIENT_RESOURCES))?;
        for record in self.opens_by_kernel_id.values() {
            let selected = if directory {
                record.relative_path.starts_with(old_path)
            } else {
                record.file_id == source_file && record.link_id == source_link
            };
            let replacement = if selected {
                let suffix = record
                    .relative_path
                    .strip_prefix(old_path)
                    .map_err(|_| internal())?;
                Some(new_path.join(suffix))
            } else {
                None
            };
            replacements.push(replacement);
        }
        Ok(OpenPathPlan { replacements })
    }

    pub(crate) fn preflight_subtree_reopen(
        &self,
        root: &Path,
        old_path: &Path,
        new_path: &Path,
    ) -> FileSystemResult<OpenReopenPlan> {
        self.validate().map_err(|()| internal())?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.opens_by_kernel_id.len())
            .map_err(|_| terminal(completion_status::INSUFFICIENT_RESOURCES))?;
        for record in self.opens_by_kernel_id.values() {
            let entry = if record.relative_path.starts_with(old_path) {
                let suffix = record
                    .relative_path
                    .strip_prefix(old_path)
                    .map_err(|_| internal())?;
                let old_path = root.join(&record.relative_path);
                let new_path = root.join(new_path).join(suffix);
                let native = windows::metadata(&record.handle)
                    .map_err(|error| status::from_io(op::MUTATE, &error))?;
                let placeholder = windows::open_existing(root, 0, SUPPORTED_SHARE_ACCESS, true)
                    .map_err(|error| status::from_io(op::MUTATE, &error))?;
                Some(OpenReopenEntry {
                    old_path,
                    new_path,
                    granted_access: record.granted_access,
                    share_access: record.share_access,
                    directory: native.is_directory,
                    placeholder: Some(placeholder),
                })
            } else {
                None
            };
            entries.push(entry);
        }
        let mut reopened = Vec::new();
        reopened
            .try_reserve_exact(entries.len())
            .map_err(|_| terminal(completion_status::INSUFFICIENT_RESOURCES))?;
        reopened.resize_with(entries.len(), || None);
        Ok(OpenReopenPlan { entries, reopened })
    }

    fn validate(&self) -> Result<(), ()> {
        if self
            .opens_by_kernel_id
            .iter()
            .any(|(kernel_open_id, record)| {
                *kernel_open_id == 0
                    || record.file_id == FileId::ZERO
                    || record.link_id == LinkId::ZERO
                    || record.relative_path.as_os_str().is_empty()
                    || record.share_access & !SUPPORTED_SHARE_ACCESS != 0
            })
        {
            return Err(());
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn get(&self, kernel_open_id: u64) -> FileSystemResult<&OpenRecord> {
        self.validate().map_err(|()| internal())?;
        match self.opens_by_kernel_id.get(&kernel_open_id) {
            Some(record) if record.state == OpenState::Live => Ok(record),
            Some(_) | None => Err(internal()),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn get_mut(&mut self, kernel_open_id: u64) -> FileSystemResult<&mut OpenRecord> {
        self.validate().map_err(|()| internal())?;
        match self.opens_by_kernel_id.get_mut(&kernel_open_id) {
            Some(record) if record.state == OpenState::Live => Ok(record),
            Some(_) | None => Err(internal()),
        }
    }

    fn preflight_insert(&mut self, kernel_open_id: u64) -> FileSystemResult<()> {
        self.validate().map_err(|()| internal())?;
        if kernel_open_id == 0 || self.opens_by_kernel_id.contains_key(&kernel_open_id) {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        self.opens_by_kernel_id
            .try_reserve(1)
            .map_err(|_| terminal(completion_status::INSUFFICIENT_RESOURCES))
    }

    fn insert_preflighted(&mut self, kernel_open_id: u64, record: OpenRecord) {
        debug_assert!(!self.opens_by_kernel_id.contains_key(&kernel_open_id));
        self.opens_by_kernel_id.insert(kernel_open_id, record);
        debug_assert!(self.validate().is_ok());
    }

    fn cleanup(&mut self, kernel_open_id: u64) {
        if self.validate().is_err() {
            debug_assert!(false, "corrupt provider open table at CLEANUP");
            return;
        }
        if let Some(record) = self.opens_by_kernel_id.get_mut(&kernel_open_id) {
            record.state = OpenState::Cleaned;
        }
    }

    fn close(&mut self, kernel_open_id: u64) {
        if self.validate().is_err() {
            debug_assert!(false, "corrupt provider open table at CLOSE");
            return;
        }
        match self.opens_by_kernel_id.get(&kernel_open_id) {
            Some(record) if record.state == OpenState::Live => {
                debug_assert!(false, "provider CLOSE requires a CLEANED open");
            }
            Some(_) => {
                let _dropped_once = self.opens_by_kernel_id.remove(&kernel_open_id);
            }
            None => {}
        }
    }
}

impl MirrorFs {
    /// Validate and retain one backing-nonmutating OPEN transaction.
    ///
    /// Identical OpId replay returns the stored result and ignores the fresh
    /// transaction candidate; Task 16's `FileSystem` implementation delegates
    /// to this direct-provider surface after semantic decode.
    pub fn prepare_open(
        &mut self,
        request: &PreparedRequest,
        transaction_id: TransactionId,
    ) -> FileSystemResult<PrepareResult> {
        if let Some(replayed) = self.pending.replay_or_preflight(request, transaction_id)? {
            return Ok(replayed);
        }

        let component = validate_prepare_scalars(request)?;
        if let Some(descriptor) = &request.requested_security_descriptor {
            windows::validate_security_descriptor(descriptor)
                .map_err(|error| status::from_io(op::PREPARE_OPEN, &error))?;
        }
        let relative_path = self
            .identities
            .child_relative_path(self.root_file_id, request.parent_id, &component)
            .map_err(|error| registry_prepare_error(error, true))?;
        let path = self.root.join(&relative_path);
        let parent_relative_path = relative_path.parent().unwrap_or_else(|| Path::new(""));
        let parent_path = self.root.join(parent_relative_path);
        let parent_file = self
            .identities
            .file(request.parent_id)
            .map_err(|error| registry_prepare_error(error, true))?
            .clone();
        let parent_native = parent_file.native.ok_or_else(internal)?;
        let parent_handle = windows::open_existing(&parent_path, 0, SUPPORTED_SHARE_ACCESS, true)
            .map_err(|error| status::from_io(op::PREPARE_OPEN, &error))?;
        let current_parent_native = windows::metadata(&parent_handle)
            .map_err(|error| status::from_io(op::PREPARE_OPEN, &error))?;
        if current_parent_native.key != parent_native || !current_parent_native.is_directory {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        let existing = inspect_existing_target(self, &path)?;
        let (result, target_native, prospective_file_id, create_plan) =
            if let Some(target) = existing {
                validate_existing_disposition_and_type(request, target.native.is_directory)?;
                let descriptor = windows::query_security(&path, SECURITY_INFORMATION)
                    .map_err(|error| status::from_io(op::PREPARE_OPEN, &error))?;
                let (file_id, link_id) = self
                    .identities
                    .observe_native_and_install_link(
                        self.root_file_id,
                        target.native.key,
                        target.native.file_size,
                        request.parent_id,
                        component.clone(),
                    )
                    .map_err(|error| registry_prepare_error(error, false))?;
                let file = self.identities.file(file_id).map_err(|_| internal())?;
                let fields =
                    metadata::file_info_fields(&target.native, file).map_err(|_| internal())?;
                (
                    PrepareResult {
                        file_id,
                        link_id,
                        sizes: fields.sizes,
                        namespace_generation: fields.namespace_generation,
                        security_generation: fields.security_generation,
                        security_descriptor: descriptor,
                        object_flags: 0,
                    },
                    Some(target.native.key),
                    file_id,
                    CreatePlan::Existing {
                        file_id,
                        link_id,
                        is_directory: target.native.is_directory,
                        basic_attributes: target.native.attributes & SUPPORTED_BASIC_ATTRIBUTES,
                        parent_namespace_generation: parent_file.namespace_generation,
                    },
                )
            } else {
                validate_absent_disposition(request.disposition)?;
                let is_directory = request.create_options & FILE_DIRECTORY_FILE != 0;
                let descriptor = match &request.requested_security_descriptor {
                    Some(descriptor) => descriptor.clone(),
                    None => windows::query_security(&parent_path, SECURITY_INFORMATION)
                        .map_err(|error| status::from_io(op::PREPARE_OPEN, &error))?,
                };
                let file_id = self
                    .identities
                    .allocate_prospective(0)
                    .map_err(|error| registry_prepare_error(error, false))?;
                let file = self.identities.file(file_id).map_err(|_| internal())?;
                (
                    PrepareResult {
                        file_id,
                        link_id: LinkId::ZERO,
                        sizes: SizeState {
                            allocation_size: 0,
                            file_size: 0,
                            valid_data_length: 0,
                            size_epoch: file.size_epoch,
                        },
                        namespace_generation: file.namespace_generation,
                        security_generation: file.security_generation,
                        security_descriptor: descriptor,
                        object_flags: 0,
                    },
                    None,
                    file_id,
                    CreatePlan::Prospective {
                        component,
                        is_directory,
                        parent_namespace_generation: parent_file.namespace_generation,
                    },
                )
            };

        self.pending.insert_preflighted(PendingOpen {
            transaction_id,
            request: request.clone(),
            result: result.clone(),
            path: relative_path,
            parent_native,
            target_native,
            prospective_file_id,
            create_plan,
        });
        Ok(result)
    }

    /// Apply the exact prepared transaction and retain one LIVE native handle.
    pub fn commit_open(&mut self, request: &CommitRequest) -> FileSystemResult<CommitEffect> {
        let pending = self.pending.exact(request)?.clone();
        if request.commit_flags != 0
            || request.expected_namespace_generation != pending.result.namespace_generation
            || request.expected_security_generation != pending.result.security_generation
        {
            return Err(terminal(completion_status::RETRY));
        }
        self.opens.preflight_insert(request.kernel_open_id)?;
        self.revalidate_pending(&pending)?;

        let (existing_reservation, create_reservation) = match &pending.create_plan {
            CreatePlan::Existing {
                file_id,
                basic_attributes,
                parent_namespace_generation: _,
                ..
            } => (
                Some(
                    self.identities
                        .preflight_existing_open(
                            *file_id,
                            pending.result.namespace_generation,
                            pending.result.security_generation,
                            pending.result.sizes.size_epoch,
                            if matches!(
                                pending.request.disposition,
                                FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
                            ) {
                                ExistingOpenSizeEffect::Truncate
                            } else {
                                ExistingOpenSizeEffect::Preserve
                            },
                            if replacement_changes_basic_attributes(
                                pending.request.disposition,
                                pending.request.file_attributes,
                                *basic_attributes,
                            ) {
                                ExistingOpenNamespaceEffect::Advance
                            } else {
                                ExistingOpenNamespaceEffect::Preserve
                            },
                        )
                        .map_err(registry_commit_error)?,
                ),
                None,
            ),
            CreatePlan::Prospective {
                component,
                parent_namespace_generation,
                ..
            } => {
                let reservation = self
                    .identities
                    .preflight_create_open(
                        pending.request.parent_id,
                        *parent_namespace_generation,
                        pending.prospective_file_id,
                        pending.result.namespace_generation,
                        pending.result.security_generation,
                        component,
                        &pending.path,
                    )
                    .map_err(registry_commit_error)?;
                (None, Some(reservation))
            }
        };

        let full_path = self.root.join(&pending.path);
        let (handle, create_result, visible_effect) = apply_open_effect(
            &full_path,
            request.granted_access,
            pending.request.share_access,
            &pending,
        )?;
        let native = match windows::metadata(&handle) {
            Ok(native) => native,
            Err(_error) if visible_effect => return Err(internal()),
            Err(error) => return Err(status::from_io(op::COMMIT_OPEN, &error)),
        };
        if metadata::validate_native_projection(&native).is_err()
            || native.key.volume_serial != self.volume.volume_serial
        {
            return Err(if visible_effect {
                internal()
            } else {
                terminal(completion_status::RETRY)
            });
        }

        let (file_id, link_id, volume_commit_sequence) = match pending.create_plan {
            CreatePlan::Existing {
                file_id,
                link_id,
                is_directory,
                ..
            } => {
                if pending.target_native != Some(native.key) || native.is_directory != is_directory
                {
                    return Err(if visible_effect {
                        internal()
                    } else {
                        terminal(completion_status::RETRY)
                    });
                }
                if !matches!(
                    pending.request.disposition,
                    FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
                ) && pending.result.sizes.valid_data_length > native.file_size
                {
                    return Err(if visible_effect {
                        internal()
                    } else {
                        terminal(completion_status::RETRY)
                    });
                }
                let effect = self
                    .identities
                    .finalize_existing_open(existing_reservation.ok_or_else(internal)?);
                (file_id, link_id, effect.volume_sequence)
            }
            CreatePlan::Prospective { is_directory, .. } => {
                if native.is_directory != is_directory {
                    return Err(internal());
                }
                let effect = self
                    .identities
                    .finalize_create_open(create_reservation.ok_or_else(internal)?, native.key)
                    .map_err(|_| internal())?;
                (
                    pending.prospective_file_id,
                    effect.value,
                    effect.volume_sequence,
                )
            }
        };
        let file = self.identities.file(file_id).map_err(|_| internal())?;
        let fields = metadata::file_info_fields(&native, file).map_err(|_| internal())?;
        let effect = CommitEffect {
            create_result,
            file_id,
            link_id,
            sizes: fields.sizes,
            namespace_generation: fields.namespace_generation,
            security_generation: fields.security_generation,
            volume_commit_sequence,
        };
        self.opens.insert_preflighted(
            request.kernel_open_id,
            OpenRecord {
                handle,
                file_id,
                link_id,
                relative_path: pending.path,
                granted_access: request.granted_access,
                share_access: pending.request.share_access,
                state: OpenState::Live,
            },
        );
        self.pending
            .remove_exact(request.transaction_id)
            .map_err(|()| internal())?
            .ok_or_else(internal)?;
        Ok(effect)
    }

    /// Idempotently remove exactly one pending transaction/index pair.
    pub fn abort_open(&mut self, transaction_id: TransactionId) {
        if self.pending.remove_exact(transaction_id).is_err() {
            debug_assert!(false, "corrupt provider pending table at ABORT");
        }
    }

    /// Transition a retained provider open from LIVE to CLEANED.
    pub fn cleanup_open(&mut self, kernel_open_id: u64) {
        self.opens.cleanup(kernel_open_id);
    }

    /// Drop exactly one CLEANED native handle; complete absence is idempotent.
    pub fn close_open(&mut self, kernel_open_id: u64) {
        self.opens.close(kernel_open_id);
    }

    fn revalidate_pending(&self, pending: &PendingOpen) -> FileSystemResult<()> {
        let parent = self
            .identities
            .file(pending.request.parent_id)
            .map_err(registry_commit_error)?;
        let expected_parent_generation = match &pending.create_plan {
            CreatePlan::Existing {
                parent_namespace_generation,
                ..
            }
            | CreatePlan::Prospective {
                parent_namespace_generation,
                ..
            } => *parent_namespace_generation,
        };
        if parent.native != Some(pending.parent_native)
            || parent.namespace_generation != expected_parent_generation
        {
            return Err(terminal(completion_status::RETRY));
        }
        let parent_path = self
            .root
            .join(pending.path.parent().unwrap_or_else(|| Path::new("")));
        let parent_handle = windows::open_existing(&parent_path, 0, SUPPORTED_SHARE_ACCESS, true)
            .map_err(|error| status::from_io(op::COMMIT_OPEN, &error))?;
        let parent_native = windows::metadata(&parent_handle)
            .map_err(|error| status::from_io(op::COMMIT_OPEN, &error))?;
        if parent_native.key != pending.parent_native || !parent_native.is_directory {
            return Err(terminal(completion_status::RETRY));
        }

        match &pending.create_plan {
            CreatePlan::Existing {
                file_id, link_id, ..
            } => {
                let file = self
                    .identities
                    .file(*file_id)
                    .map_err(registry_commit_error)?;
                let link = self
                    .identities
                    .link(*link_id)
                    .map_err(registry_commit_error)?;
                if file.native != pending.target_native
                    || file.namespace_generation != pending.result.namespace_generation
                    || file.security_generation != pending.result.security_generation
                    || link.parent != pending.request.parent_id
                    || link.child != *file_id
                    || link.relative_path != pending.path
                {
                    return Err(terminal(completion_status::RETRY));
                }
            }
            CreatePlan::Prospective { .. } => {}
        }
        Ok(())
    }
}

struct InspectedTarget {
    native: windows::NativeMetadata,
}

fn inspect_existing_target(
    provider: &MirrorFs,
    path: &Path,
) -> FileSystemResult<Option<InspectedTarget>> {
    let attributes = match windows::attributes(path) {
        Ok(attributes) => attributes,
        Err(error) if is_not_found(&error) => return Ok(None),
        Err(error) => return Err(status::from_io(op::PREPARE_OPEN, &error)),
    };
    if attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(terminal(completion_status::NOT_SUPPORTED));
    }
    let canonical =
        std::fs::canonicalize(path).map_err(|error| status::from_io(op::PREPARE_OPEN, &error))?;
    if !canonical.starts_with(&provider.root) {
        return Err(terminal(completion_status::ACCESS_DENIED));
    }
    let canonical_attributes = windows::attributes(&canonical)
        .map_err(|error| status::from_io(op::PREPARE_OPEN, &error))?;
    if canonical_attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(terminal(completion_status::NOT_SUPPORTED));
    }
    let is_directory = canonical_attributes & windows::FILE_ATTRIBUTE_DIRECTORY != 0;
    let handle = windows::open_existing(&canonical, 0, SUPPORTED_SHARE_ACCESS, is_directory)
        .map_err(|error| status::from_io(op::PREPARE_OPEN, &error))?;
    let native =
        windows::metadata(&handle).map_err(|error| status::from_io(op::PREPARE_OPEN, &error))?;
    metadata::validate_native_projection(&native)
        .map_err(|error| status::from_io(op::PREPARE_OPEN, &error))?;
    if native.is_directory != is_directory
        || native.key.volume_serial != provider.volume.volume_serial
    {
        return Err(terminal(completion_status::DATA_ERROR));
    }
    Ok(Some(InspectedTarget { native }))
}

fn validate_prepare_scalars(request: &PreparedRequest) -> FileSystemResult<Component> {
    if request.extended_attributes.is_some() {
        return Err(terminal(completion_status::NOT_SUPPORTED));
    }
    if request.disposition > FILE_OVERWRITE_IF
        || request.open_flags != 0
        || request.share_access & !SUPPORTED_SHARE_ACCESS != 0
    {
        return Err(terminal(completion_status::DATA_ERROR));
    }
    if request.create_options & FILE_OPEN_REPARSE_POINT != 0
        || request.create_options & !SUPPORTED_CREATE_OPTIONS != 0
        || request.file_attributes & !SUPPORTED_OPEN_ATTRIBUTES != 0
    {
        return Err(terminal(completion_status::NOT_SUPPORTED));
    }
    if request.create_options & SUPPORTED_CREATE_OPTIONS == SUPPORTED_CREATE_OPTIONS
        || (request.file_attributes & file_attributes::NORMAL != 0
            && request.file_attributes != file_attributes::NORMAL)
        || (request.file_attributes & file_attributes::DIRECTORY != 0
            && request.create_options & FILE_DIRECTORY_FILE == 0)
    {
        return Err(terminal(completion_status::DATA_ERROR));
    }
    component_from_utf16le(&request.name)
}

fn validate_existing_disposition_and_type(
    request: &PreparedRequest,
    is_directory: bool,
) -> FileSystemResult<()> {
    if request.disposition == FILE_CREATE {
        return Err(terminal(completion_status::OBJECT_NAME_COLLISION));
    }
    let wants_directory = request.create_options & FILE_DIRECTORY_FILE != 0;
    let wants_file = request.create_options & FILE_NON_DIRECTORY_FILE != 0;
    if wants_directory && !is_directory {
        return Err(terminal(completion_status::NOT_A_DIRECTORY));
    }
    if wants_file && is_directory {
        return Err(terminal(completion_status::FILE_IS_A_DIRECTORY));
    }
    if is_directory
        && matches!(
            request.disposition,
            FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
        )
    {
        return Err(terminal(completion_status::FILE_IS_A_DIRECTORY));
    }
    Ok(())
}

fn validate_absent_disposition(disposition: u32) -> FileSystemResult<()> {
    if matches!(disposition, FILE_OPEN | FILE_OVERWRITE) {
        Err(terminal(completion_status::OBJECT_NAME_NOT_FOUND))
    } else {
        Ok(())
    }
}

fn apply_open_effect(
    path: &Path,
    access: u32,
    share: u32,
    pending: &PendingOpen,
) -> FileSystemResult<(windows::NativeHandle, u32, bool)> {
    match &pending.create_plan {
        CreatePlan::Existing { is_directory, .. } if *is_directory => {
            apply_existing_directory_open_effect(path, access, share, pending.request.disposition)
        }
        CreatePlan::Existing {
            basic_attributes, ..
        } => {
            let native_disposition = match pending.request.disposition {
                FILE_SUPERSEDE | FILE_OVERWRITE_IF => windows::CREATE_ALWAYS,
                FILE_OPEN => windows::OPEN_EXISTING,
                FILE_OPEN_IF => windows::OPEN_ALWAYS,
                FILE_OVERWRITE => windows::TRUNCATE_EXISTING,
                _ => return Err(internal()),
            };
            let (handle, existed) = windows::create_file(
                path,
                truncate_access(native_disposition, access),
                share,
                native_disposition,
                replacement_create_attributes(pending.request.file_attributes, *basic_attributes),
                None,
            )
            .map_err(|error| status::from_io(op::COMMIT_OPEN, &error))?;
            let (handle, create_result, visible_effect) = finish_file_outcome(
                handle,
                classify_file_outcome(true, pending.request.disposition, existed),
            )?;
            let basic_effect = if is_replacing_disposition(pending.request.disposition) {
                apply_requested_basic_info(
                    &handle,
                    path,
                    pending.request.file_attributes,
                    visible_effect,
                )?
            } else {
                false
            };
            Ok((handle, create_result, visible_effect || basic_effect))
        }
        CreatePlan::Prospective {
            is_directory: true, ..
        } => apply_prospective_directory_open_effect(path, access, share, pending),
        CreatePlan::Prospective { .. } => {
            let disposition = match pending.request.disposition {
                FILE_SUPERSEDE | FILE_OVERWRITE_IF => windows::CREATE_ALWAYS,
                FILE_CREATE => windows::CREATE_NEW,
                FILE_OPEN_IF => windows::OPEN_ALWAYS,
                _ => return Err(internal()),
            };
            let (handle, existed) = windows::create_file(
                path,
                access,
                share,
                disposition,
                create_attributes(pending.request.file_attributes),
                Some(&pending.result.security_descriptor),
            )
            .map_err(|error| status::from_io(op::COMMIT_OPEN, &error))?;
            finish_file_outcome(
                handle,
                classify_file_outcome(false, pending.request.disposition, existed),
            )
        }
    }
}

fn apply_existing_directory_open_effect(
    path: &Path,
    access: u32,
    share: u32,
    disposition: u32,
) -> FileSystemResult<(windows::NativeHandle, u32, bool)> {
    match disposition {
        FILE_OPEN => {
            let handle = windows::open_existing(path, access, share, true)
                .map_err(|error| status::from_io(op::COMMIT_OPEN, &error))?;
            Ok((handle, create_result::OPENED, false))
        }
        FILE_OPEN_IF => {
            if create_directory_if_absent(path, None)? {
                return Err(internal());
            }
            let handle = windows::open_existing(path, access, share, true)
                .map_err(|error| status::from_io(op::COMMIT_OPEN, &error))?;
            Ok((handle, create_result::OPENED, false))
        }
        _ => Err(internal()),
    }
}

fn apply_prospective_directory_open_effect(
    path: &Path,
    access: u32,
    share: u32,
    pending: &PendingOpen,
) -> FileSystemResult<(windows::NativeHandle, u32, bool)> {
    if !matches!(
        pending.request.disposition,
        FILE_SUPERSEDE | FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF
    ) {
        return Err(internal());
    }
    let created = create_directory_if_absent(path, Some(&pending.result.security_descriptor))?;
    if !created {
        return Err(if pending.request.disposition == FILE_OPEN_IF {
            terminal(completion_status::RETRY)
        } else {
            terminal(completion_status::OBJECT_NAME_COLLISION)
        });
    }

    let handle = windows::open_existing(path, access, share, true).map_err(|_| internal())?;
    apply_requested_basic_info(&handle, path, pending.request.file_attributes, true)?;
    Ok((handle, create_result::CREATED, true))
}

fn create_directory_if_absent(path: &Path, descriptor: Option<&[u8]>) -> FileSystemResult<bool> {
    match windows::create_directory(path, descriptor) {
        Ok(()) => Ok(true),
        Err(error) if is_already_exists(&error) => Ok(false),
        Err(error) => Err(status::from_io(op::COMMIT_OPEN, &error)),
    }
}

fn is_replacing_disposition(disposition: u32) -> bool {
    matches!(
        disposition,
        FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
    )
}

fn replacement_changes_basic_attributes(
    disposition: u32,
    requested_attributes: u32,
    prepared_basic_attributes: u32,
) -> bool {
    let requested_basic_attributes = requested_attributes & SUPPORTED_BASIC_ATTRIBUTES;
    is_replacing_disposition(disposition)
        && requested_basic_attributes != 0
        && requested_basic_attributes != prepared_basic_attributes
}

fn replacement_create_attributes(requested_attributes: u32, prepared_basic_attributes: u32) -> u32 {
    let required_existing_attributes =
        prepared_basic_attributes & (file_attributes::HIDDEN | file_attributes::SYSTEM);
    let attributes = create_attributes(requested_attributes) | required_existing_attributes;
    if attributes & !file_attributes::NORMAL == 0 {
        attributes
    } else {
        attributes & !file_attributes::NORMAL
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileOutcome {
    Success {
        create_result: u32,
        visible_effect: bool,
    },
    Retry,
    Internal,
}

fn classify_file_outcome(prepared_existing: bool, disposition: u32, existed: bool) -> FileOutcome {
    match (prepared_existing, disposition, existed) {
        (true, FILE_SUPERSEDE, true) => FileOutcome::Success {
            create_result: create_result::SUPERSEDED,
            visible_effect: true,
        },
        (true, FILE_OPEN, true) | (true, FILE_OPEN_IF, true) => FileOutcome::Success {
            create_result: create_result::OPENED,
            visible_effect: false,
        },
        (true, FILE_OVERWRITE | FILE_OVERWRITE_IF, true) => FileOutcome::Success {
            create_result: create_result::OVERWRITTEN,
            visible_effect: true,
        },
        (true, FILE_SUPERSEDE | FILE_OPEN_IF | FILE_OVERWRITE_IF, false) => FileOutcome::Internal,
        (false, FILE_OPEN_IF, true) => FileOutcome::Retry,
        (false, FILE_SUPERSEDE | FILE_OVERWRITE_IF, true) => FileOutcome::Internal,
        (false, FILE_SUPERSEDE | FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF, false) => {
            FileOutcome::Success {
                create_result: create_result::CREATED,
                visible_effect: true,
            }
        }
        _ => FileOutcome::Internal,
    }
}

fn finish_file_outcome(
    handle: windows::NativeHandle,
    outcome: FileOutcome,
) -> FileSystemResult<(windows::NativeHandle, u32, bool)> {
    match outcome {
        FileOutcome::Success {
            create_result,
            visible_effect,
        } => Ok((handle, create_result, visible_effect)),
        FileOutcome::Retry => Err(terminal(completion_status::RETRY)),
        FileOutcome::Internal => Err(internal()),
    }
}

fn apply_requested_basic_info(
    handle: &windows::NativeHandle,
    path: &Path,
    attributes: u32,
    earlier_visible_effect: bool,
) -> FileSystemResult<bool> {
    let attributes = attributes & !file_attributes::DIRECTORY;
    if attributes == 0 {
        return Ok(false);
    }
    match windows::set_basic_info(
        handle,
        path,
        windows::NativeBasicInfoUpdate {
            attributes: Some(attributes),
            ..windows::NativeBasicInfoUpdate::default()
        },
    ) {
        Ok(()) => Ok(true),
        Err(error) if earlier_visible_effect || error.effect_applied() => Err(internal()),
        Err(error) => Err(status::from_io(op::COMMIT_OPEN, error.source_io())),
    }
}

fn create_attributes(attributes: u32) -> u32 {
    let attributes = attributes & !(file_attributes::DIRECTORY | file_attributes::REPARSE_POINT);
    if attributes == 0 {
        windows::FILE_ATTRIBUTE_NORMAL
    } else {
        attributes
    }
}

fn truncate_access(disposition: u32, access: u32) -> u32 {
    if disposition == windows::TRUNCATE_EXISTING
        && access & windows::FILE_GENERIC_WRITE == windows::FILE_GENERIC_WRITE
    {
        access | GENERIC_WRITE
    } else {
        access
    }
}

fn registry_prepare_error(error: RegistryError, parent_lookup: bool) -> fsring_user::ProviderError {
    match error {
        RegistryError::MissingFile(_) if parent_lookup => {
            terminal(completion_status::OBJECT_PATH_NOT_FOUND)
        }
        RegistryError::MissingName | RegistryError::MissingNative => {
            terminal(completion_status::OBJECT_NAME_NOT_FOUND)
        }
        RegistryError::CounterExhausted(_) => terminal(completion_status::INSUFFICIENT_RESOURCES),
        RegistryError::CapacityExhausted => terminal(completion_status::INSUFFICIENT_RESOURCES),
        _ => terminal(completion_status::DATA_ERROR),
    }
}

fn registry_commit_error(error: RegistryError) -> fsring_user::ProviderError {
    match error {
        RegistryError::StaleGeneration { .. }
        | RegistryError::MissingFile(_)
        | RegistryError::MissingLink(_)
        | RegistryError::MissingName
        | RegistryError::MissingNative
        | RegistryError::NameCollision { .. }
        | RegistryError::NativeCollision { .. }
        | RegistryError::FileNativeConflict { .. } => terminal(completion_status::RETRY),
        RegistryError::CounterExhausted(GenerationDomain::VolumeSequence)
        | RegistryError::CounterExhausted(GenerationDomain::LinkIdentity)
        | RegistryError::CounterExhausted(GenerationDomain::Namespace)
        | RegistryError::CounterExhausted(GenerationDomain::Size) => {
            terminal(completion_status::INSUFFICIENT_RESOURCES)
        }
        RegistryError::CapacityExhausted => terminal(completion_status::INSUFFICIENT_RESOURCES),
        _ => terminal(completion_status::DATA_ERROR),
    }
}

fn is_zero_transaction(transaction_id: TransactionId) -> bool {
    transaction_id.lo == 0 && transaction_id.hi == 0
}

fn is_not_found(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || matches!(error.raw_os_error(), Some(2 | 3))
}

fn is_already_exists(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AlreadyExists || matches!(error.raw_os_error(), Some(80 | 183))
}

fn terminal(status: i32) -> fsring_user::ProviderError {
    fsring_user::ProviderError::terminal(status)
}

fn internal() -> fsring_user::ProviderError {
    fsring_user::ProviderError::internal()
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use fsring_abi::codec::try_decode;
    use fsring_abi::ids::{OpId, TransactionId};
    use fsring_abi::msgs::{create_result, file_attributes, CommitOpenV2, PrepareOpenV2};
    use fsring_user::{CommitRequest, PreparedRequest};

    use crate::MirrorFs;

    use super::{classify_file_outcome, FileOutcome, OpenRecord, OpenState};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = Path::new(r"D:\temp").join(format!(
                "winfsr-mirrorfs-open-unit-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.parent() == Some(Path::new(r"D:\temp")) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn request(op: u64, parent: fsring_abi::ids::FileId, name: &str) -> PreparedRequest {
        let mut raw: PrepareOpenV2 = try_decode(&[0_u8; 192]).unwrap();
        raw.op_id = OpId { lo: op, hi: 0 };
        raw.parent_id = parent;
        raw.desired_access = 0x0012_0089;
        raw.share_access = 7;
        raw.disposition = 2;
        raw.create_options = 0x40;
        raw.file_attributes = file_attributes::NORMAL;
        PreparedRequest::from_raw(
            raw,
            name.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            None,
            None,
        )
    }

    fn commit(
        request: &PreparedRequest,
        transaction_id: TransactionId,
        kernel_open_id: u64,
        namespace_generation: u64,
        security_generation: u64,
    ) -> CommitRequest {
        let mut raw: CommitOpenV2 = try_decode(&[0_u8; 104]).unwrap();
        raw.op_id = request.op_id;
        raw.transaction_id = transaction_id;
        raw.kernel_open_id = kernel_open_id;
        raw.expected_namespace_generation = namespace_generation;
        raw.expected_security_generation = security_generation;
        raw.granted_access = 0x0012_0089;
        CommitRequest::from_raw(raw)
    }

    #[test]
    fn pending_indexes_stay_joint_across_replay_abort_and_commit() {
        let temp = TestRoot::new();
        let mut provider = MirrorFs::open(temp.path()).unwrap();
        let request = request(1, provider.root_file_id(), "pending.txt");
        let tx = TransactionId { lo: 1, hi: 0 };
        let prepared = provider.prepare_open(&request, tx).unwrap();
        provider.pending.validate().unwrap();
        provider.opens.validate().unwrap();
        assert_eq!(provider.pending.pending_by_op.len(), 1);
        assert_eq!(provider.pending.pending_by_tx.len(), 1);

        provider
            .prepare_open(&request, TransactionId { lo: 2, hi: 0 })
            .unwrap();
        assert_eq!(provider.pending.pending_by_op.len(), 1);
        assert_eq!(provider.pending.pending_by_tx.len(), 1);
        provider.abort_open(TransactionId { lo: 2, hi: 0 });
        assert_eq!(provider.pending.pending_by_op.len(), 1);

        provider
            .commit_open(&commit(
                &request,
                tx,
                1,
                prepared.namespace_generation,
                prepared.security_generation,
            ))
            .unwrap();
        provider.pending.validate().unwrap();
        provider.opens.validate().unwrap();
        assert!(provider.pending.pending_by_op.is_empty());
        assert!(provider.pending.pending_by_tx.is_empty());
        assert_eq!(provider.opens.opens_by_kernel_id.len(), 1);
        assert_eq!(
            provider
                .opens
                .opens_by_kernel_id
                .get(&1)
                .unwrap()
                .share_access,
            request.share_access
        );
    }

    #[test]
    fn live_close_debug_contract_never_removes_or_drops_the_open_record() {
        let temp = TestRoot::new();
        let mut provider = MirrorFs::open(temp.path()).unwrap();
        let request = request(2, provider.root_file_id(), "live.txt");
        let tx = TransactionId { lo: 3, hi: 0 };
        let prepared = provider.prepare_open(&request, tx).unwrap();
        provider
            .commit_open(&commit(
                &request,
                tx,
                2,
                prepared.namespace_generation,
                prepared.security_generation,
            ))
            .unwrap();

        let assertion = catch_unwind(AssertUnwindSafe(|| provider.close_open(2)));
        if cfg!(debug_assertions) {
            assert!(assertion.is_err(), "debug builds assert LIVE close");
        } else {
            assert!(
                assertion.is_ok(),
                "release builds retain LIVE without panic"
            );
        }
        assert!(provider.opens.opens_by_kernel_id.contains_key(&2));
        provider.cleanup_open(2);
        provider.close_open(2);
        assert!(!provider.opens.opens_by_kernel_id.contains_key(&2));
        provider.pending.validate().unwrap();
        provider.opens.validate().unwrap();
    }

    #[test]
    fn open_table_accessors_validate_live_missing_corrupt_and_cleaned_records() {
        let temp = TestRoot::new();
        let mut provider = MirrorFs::open(temp.path()).unwrap();
        let first_request = request(3, provider.root_file_id(), "accessor.txt");
        let tx = TransactionId { lo: 4, hi: 0 };
        let prepared = provider.prepare_open(&first_request, tx).unwrap();
        provider
            .commit_open(&commit(
                &first_request,
                tx,
                3,
                prepared.namespace_generation,
                prepared.security_generation,
            ))
            .unwrap();

        let live: &OpenRecord = provider.opens.get(3).unwrap();
        assert_eq!(live.state, OpenState::Live);
        assert_eq!(live.relative_path, PathBuf::from("accessor.txt"));
        let live_file_id = live.file_id;
        let live_mut: &mut OpenRecord = provider.opens.get_mut(3).unwrap();
        assert_eq!(live_mut.file_id, live_file_id);

        assert_eq!(
            provider.opens.get(999).err().unwrap().status(),
            fsring_abi::validate::completion_status::IO_DEVICE_ERROR
        );
        assert_eq!(
            provider.opens.get_mut(999).err().unwrap().status(),
            fsring_abi::validate::completion_status::IO_DEVICE_ERROR
        );

        provider.cleanup_open(3);
        assert_eq!(
            provider.opens.get(3).err().unwrap().status(),
            fsring_abi::validate::completion_status::IO_DEVICE_ERROR
        );
        assert_eq!(
            provider.opens.get_mut(3).err().unwrap().status(),
            fsring_abi::validate::completion_status::IO_DEVICE_ERROR
        );
        provider.close_open(3);

        let request = request(4, provider.root_file_id(), "corrupt-accessor.txt");
        let tx = TransactionId { lo: 5, hi: 0 };
        let prepared = provider.prepare_open(&request, tx).unwrap();
        provider
            .commit_open(&commit(
                &request,
                tx,
                4,
                prepared.namespace_generation,
                prepared.security_generation,
            ))
            .unwrap();
        provider
            .opens
            .opens_by_kernel_id
            .get_mut(&4)
            .unwrap()
            .share_access = u32::MAX;
        assert_eq!(
            provider.opens.get(4).err().unwrap().status(),
            fsring_abi::validate::completion_status::IO_DEVICE_ERROR
        );
        assert_eq!(
            provider.opens.get_mut(4).err().unwrap().status(),
            fsring_abi::validate::completion_status::IO_DEVICE_ERROR
        );
    }

    #[test]
    fn actual_createfile_outcome_classifies_prepare_commit_races_by_effect() {
        assert_eq!(
            classify_file_outcome(true, super::FILE_OPEN_IF, false),
            FileOutcome::Internal
        );
        assert_eq!(
            classify_file_outcome(false, super::FILE_OPEN_IF, true),
            FileOutcome::Retry
        );
        for disposition in [super::FILE_SUPERSEDE, super::FILE_OVERWRITE_IF] {
            assert_eq!(
                classify_file_outcome(false, disposition, true),
                FileOutcome::Internal
            );
        }
        assert_eq!(
            classify_file_outcome(false, super::FILE_OPEN_IF, false),
            FileOutcome::Success {
                create_result: create_result::CREATED,
                visible_effect: true,
            }
        );
    }

    #[test]
    fn truncating_open_size_reservation_exhaustion_is_registered_pre_effect() {
        assert_eq!(
            super::registry_commit_error(crate::identity::RegistryError::CounterExhausted(
                crate::identity::GenerationDomain::Size,
            ))
            .status(),
            fsring_abi::validate::completion_status::INSUFFICIENT_RESOURCES
        );
    }
}
