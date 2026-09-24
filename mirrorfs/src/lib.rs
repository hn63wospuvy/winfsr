// These foundation modules are consumed by the provider tasks that follow.
// Keep their exact crate-private API without widening it solely to suppress
// dead-code warnings while this first package slice stands alone.
#[cfg_attr(not(test), allow(dead_code))]
mod identity;
// Task 8 supplies projection/discovery seams consumed by Task 9 and later.
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
#[cfg(windows)]
#[allow(dead_code)]
mod metadata;
#[cfg(windows)]
mod opens;
#[cfg_attr(not(test), allow(dead_code))]
mod path;
#[cfg_attr(not(test), allow(dead_code))]
mod status;
// Task 6 establishes the complete crate-private Win32 surface for the provider
// tasks that follow, before this crate slice has production consumers for it.
#[allow(dead_code)]
#[cfg(windows)]
mod windows;

#[cfg(windows)]
use std::io;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::path::{Path, PathBuf};

#[cfg(windows)]
use fsring_abi::ids::{FileId, TransactionId};
#[cfg(windows)]
use fsring_abi::layout::op;
#[cfg(windows)]
use fsring_abi::msgs::{
    basic_info_set_mask, link_flags, rename_flags, security_information, LinkV1, RenameV1,
    SetBasicInfoV1, SizeState, UnlinkV1,
};
#[cfg(windows)]
use fsring_abi::validate::completion_status;
#[cfg(windows)]
use fsring_user::{
    CommitEffect, CommitRequest, DecodedBody, DirCandidate, FileInfoFields, FileSystem,
    FileSystemResult, MutationContext, MutationEffect, MutationRequest, PrepareResult,
    PreparedRequest, ProviderError, QueryDirRequest, Replaced, VolumeSizeFields, WriteEffect,
    WriteOutcome, WriteRequest,
};
#[cfg(windows)]
use identity::{DirectoryObservation, IdentityRegistry};

#[cfg(windows)]
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct Discovered {
    pub handle: windows::NativeHandle,
    pub file_id: FileId,
    pub link_id: fsring_abi::ids::LinkId,
    pub relative_path: PathBuf,
    pub native: windows::NativeMetadata,
}

#[cfg(windows)]
#[derive(Clone)]
struct MutationOpenPreflight {
    file_id: FileId,
    link_id: fsring_abi::ids::LinkId,
    path: PathBuf,
    native: windows::NativeMetadata,
    retained_sizes: SizeState,
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum SizeMutationKind {
    Allocation,
    EndOfFile,
    ValidDataLength,
}

/// Failure while constructing or validating a MirrorFS provider.
#[derive(Debug)]
pub enum MirrorFsError {
    Io(std::io::Error),
    NotDirectory,
    ReparsePoint,
    NonLocalVolume,
    NonNtfsVolume,
    InvalidComponent,
}

impl std::fmt::Display for MirrorFsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "mirror filesystem I/O error: {error}"),
            Self::NotDirectory => formatter.write_str("backing root is not a directory"),
            Self::ReparsePoint => formatter.write_str("backing root is a reparse point"),
            Self::NonLocalVolume => formatter.write_str("backing root is not on a local volume"),
            Self::NonNtfsVolume => formatter.write_str("backing root is not on an NTFS volume"),
            Self::InvalidComponent => formatter.write_str("invalid path component"),
        }
    }
}

impl std::error::Error for MirrorFsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for MirrorFsError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub struct MirrorFs {
    // Read by contained discovery, whose first production caller lands in Task 9.
    #[allow(dead_code)]
    root: PathBuf,
    // Retained to pin the opened backing root for the provider lifetime.
    #[allow(dead_code)]
    root_handle: windows::NativeHandle,
    volume: windows::VolumeGeometry,
    identities: IdentityRegistry,
    root_file_id: FileId,
    pending: opens::PendingOpenTable,
    opens: opens::OpenTable,
}

#[cfg(windows)]
impl MirrorFs {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, MirrorFsError> {
        let requested_root = root.as_ref();
        let requested_attributes = windows::attributes(requested_root)?;
        validate_root_attributes(requested_attributes)?;

        let root = std::fs::canonicalize(requested_root)?;
        if !root.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "canonical backing root is not absolute",
            )
            .into());
        }
        validate_root_attributes(windows::attributes(&root)?)?;

        let volume = windows::volume_geometry(&root)?;
        validate_volume_contract(&volume)?;
        let root_handle = windows::open_existing(
            &root,
            0,
            windows::FILE_SHARE_READ | windows::FILE_SHARE_WRITE | windows::FILE_SHARE_DELETE,
            true,
        )?;
        let native = windows::metadata(&root_handle)?;
        if native.attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(MirrorFsError::ReparsePoint);
        }
        if !native.is_directory {
            return Err(MirrorFsError::NotDirectory);
        }
        metadata::validate_native_projection(&native)?;
        if native.key.volume_serial != volume.volume_serial {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "backing root native identity disagrees with its volume",
            )
            .into());
        }

        let mut identities = IdentityRegistry::new();
        let root_file_id = identities
            .install_root(native.key, native.file_size)
            .map_err(registry_io_error)?;

        Ok(Self {
            root,
            root_handle,
            volume,
            identities,
            root_file_id,
            pending: opens::PendingOpenTable::new(),
            opens: opens::OpenTable::new(),
        })
    }

    pub fn root_file_id(&self) -> FileId {
        self.root_file_id
    }

    /// Read from a retained LIVE file handle without changing its stream
    /// position. A zero count is a successful provider result; the daemon
    /// translates it to the ABI's END_OF_FILE completion.
    pub fn read(
        &mut self,
        kernel_open_id: u64,
        offset: u64,
        buffer: &mut [u8],
    ) -> FileSystemResult<usize> {
        let record = self.opens.get(kernel_open_id)?;
        if record.granted_access & windows::FILE_READ_DATA == 0 {
            return Err(terminal(completion_status::ACCESS_DENIED));
        }
        validate_open_native(
            record,
            &self.identities,
            self.volume.volume_serial,
            op::READ,
            true,
        )?;
        windows::read_at(&record.handle, offset, buffer)
            .map_err(|error| status::from_io(op::READ, &error))
    }

    /// Apply one positional write and commit its exact positive prefix.
    ///
    /// All registry prerequisites and counters are reserved before native I/O.
    /// The reservation is finalized infallibly after the native metadata
    /// refresh, so a positive native write never encounters a recoverable
    /// provider-state failure afterward.
    pub fn write(
        &mut self,
        kernel_open_id: u64,
        offset: u64,
        expected_size_epoch: u64,
        data: &[u8],
    ) -> FileSystemResult<WriteOutcome> {
        if data.is_empty() || u32::try_from(data.len()).is_err() {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        let requested_end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| ProviderError::internal())?)
            .ok_or_else(|| terminal(completion_status::DATA_ERROR))?;

        let record = self.opens.get(kernel_open_id)?;
        if record.granted_access & windows::FILE_WRITE_DATA == 0 {
            return Err(terminal(completion_status::ACCESS_DENIED));
        }
        let file_id = record.file_id;
        let registered = self
            .identities
            .file(file_id)
            .map_err(|_| ProviderError::internal())?;
        if registered.size_epoch != expected_size_epoch {
            return Err(terminal(completion_status::RETRY));
        }
        let old_valid_data_length = registered.valid_data_length;
        let before = validate_open_native(
            record,
            &self.identities,
            self.volume.volume_serial,
            op::WRITE,
            true,
        )?;
        let may_change_size =
            requested_end > before.file_size || requested_end > old_valid_data_length;
        let reservation = self
            .identities
            .preflight_write(file_id, expected_size_epoch, may_change_size)
            .map_err(write_preflight_error)?;

        let written = windows::write_at(&record.handle, offset, data)
            .map_err(|error| status::from_io(op::WRITE, &error))?;
        if written == 0 {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        if written > data.len() {
            return Err(ProviderError::internal());
        }
        let information = u32::try_from(written).map_err(|_| ProviderError::internal())?;
        let committed_end = offset
            .checked_add(u64::from(information))
            .ok_or_else(ProviderError::internal)?;
        let after = windows::metadata(&record.handle).map_err(|_| ProviderError::internal())?;
        if metadata::validate_native_projection(&after).is_err()
            || after.key != before.key
            || after.key.volume_serial != self.volume.volume_serial
            || after.is_directory
        {
            return Err(ProviderError::internal());
        }

        let valid_data_length = old_valid_data_length.max(committed_end);
        let size_changed =
            after.file_size != before.file_size || valid_data_length != old_valid_data_length;
        if size_changed && !may_change_size {
            return Err(ProviderError::internal());
        }
        let finalized = self
            .identities
            .finalize_write(reservation, size_changed.then_some(valid_data_length))
            .map_err(|_| ProviderError::internal())?;
        let sizes = metadata::file_info_fields(&after, &finalized.file)
            .map_err(|_| ProviderError::internal())?
            .sizes;
        debug_assert_eq!(sizes.size_epoch, finalized.effect.size_epoch);
        debug_assert_eq!(sizes.valid_data_length, finalized.effect.valid_data_length);

        Ok(WriteOutcome {
            information,
            effect: WriteEffect {
                sizes,
                volume_commit_sequence: finalized.effect.volume_sequence,
            },
        })
    }

    /// Persist buffered data for one retained LIVE handle.
    pub fn flush(&mut self, kernel_open_id: u64) -> FileSystemResult<()> {
        let record = self.opens.get(kernel_open_id)?;
        windows::flush(&record.handle).map_err(|error| status::from_io(op::FLUSH, &error))
    }

    /// Refresh canonical native file metadata and combine it with the
    /// mount-lifetime registry generations and valid-data length.
    pub fn query_info(&mut self, kernel_open_id: u64) -> FileSystemResult<FileInfoFields> {
        let record = self.opens.get(kernel_open_id)?;
        if record.granted_access & windows::FILE_READ_ATTRIBUTES == 0 {
            return Err(terminal(completion_status::ACCESS_DENIED));
        }
        let native = validate_open_native(
            record,
            &self.identities,
            self.volume.volume_serial,
            op::QUERY_INFO,
            false,
        )?;
        let file = self
            .identities
            .file(record.file_id)
            .map_err(|_| ProviderError::internal())?;
        metadata::file_info_fields(&native, file).map_err(|_| ProviderError::internal())
    }

    /// Enumerate one retained LIVE directory into provider-order candidates.
    ///
    /// Pattern matching, snapshot paging, cookies, and wire encoding remain
    /// exclusively owned by `fsring_user::DirEnumerator`. This method scans
    /// every native entry first and publishes the resulting FileId/LinkId
    /// observations only after the complete batch has validated.
    pub fn query_dir(&mut self, kernel_open_id: u64) -> FileSystemResult<Vec<DirCandidate>> {
        let (directory_file_id, directory_relative_path) = {
            let record = self.opens.get(kernel_open_id)?;
            // FILE_LIST_DIRECTORY and FILE_READ_DATA share bit 0 for directory
            // and file handles respectively.
            if record.granted_access & windows::FILE_READ_DATA == 0 {
                return Err(terminal(completion_status::ACCESS_DENIED));
            }
            let native = validate_open_native(
                record,
                &self.identities,
                self.volume.volume_serial,
                op::QUERY_DIR,
                false,
            )?;
            if !native.is_directory {
                return Err(terminal(completion_status::DATA_ERROR));
            }
            let retained_link = self
                .identities
                .link(record.link_id)
                .map_err(|_| ProviderError::internal())?;
            if retained_link.child != record.file_id
                || retained_link.relative_path != record.relative_path
            {
                return Err(ProviderError::internal());
            }
            (record.file_id, record.relative_path.clone())
        };

        let directory_path = self.root.join(&directory_relative_path);
        let directory_attributes = windows::attributes(&directory_path)
            .map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
        if directory_attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(terminal(completion_status::NOT_SUPPORTED));
        }
        let canonical_directory = std::fs::canonicalize(&directory_path)
            .map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
        if !canonical_directory.starts_with(&self.root) {
            return Err(ProviderError::internal());
        }
        let current_handle = windows::open_existing(
            &canonical_directory,
            0,
            windows::FILE_SHARE_READ | windows::FILE_SHARE_WRITE | windows::FILE_SHARE_DELETE,
            true,
        )
        .map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
        let current_native = windows::metadata(&current_handle)
            .map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
        let retained_file = self
            .identities
            .file(directory_file_id)
            .map_err(|_| ProviderError::internal())?;
        if current_native.key.volume_serial != self.volume.volume_serial
            || retained_file.native != Some(current_native.key)
            || !current_native.is_directory
            || metadata::validate_native_projection(&current_native).is_err()
        {
            return Err(ProviderError::internal());
        }

        struct ScannedEntry {
            name: Box<[u8]>,
            native: windows::NativeMetadata,
        }

        let directory = std::fs::read_dir(&canonical_directory)
            .map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
        let mut scanned = Vec::new();
        let mut observations = Vec::new();
        for entry in directory {
            let entry = entry.map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
            let os_name = entry.file_name();
            if os_name == std::ffi::OsStr::new(".") || os_name == std::ffi::OsStr::new("..") {
                continue;
            }
            let name: Box<[u8]> = os_name
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let component = path::component_from_utf16le(&name)?;
            let candidate_path = canonical_directory.join(component.as_os_str());
            let candidate_attributes = windows::attributes(&candidate_path)
                .map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
            if candidate_attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(terminal(completion_status::NOT_SUPPORTED));
            }
            let canonical_candidate = std::fs::canonicalize(&candidate_path)
                .map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
            if !canonical_candidate.starts_with(&self.root) {
                return Err(ProviderError::internal());
            }
            let canonical_attributes = windows::attributes(&canonical_candidate)
                .map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
            if canonical_attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(terminal(completion_status::NOT_SUPPORTED));
            }
            let is_directory = canonical_attributes & windows::FILE_ATTRIBUTE_DIRECTORY != 0;
            let handle = windows::open_existing(
                &canonical_candidate,
                0,
                windows::FILE_SHARE_READ | windows::FILE_SHARE_WRITE | windows::FILE_SHARE_DELETE,
                is_directory,
            )
            .map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
            let native = windows::metadata(&handle)
                .map_err(|error| status::from_io(op::QUERY_DIR, &error))?;
            if native.key.volume_serial != self.volume.volume_serial
                || native.is_directory != is_directory
                || metadata::validate_native_projection(&native).is_err()
            {
                return Err(ProviderError::internal());
            }
            observations.push(DirectoryObservation {
                native: native.key,
                valid_data_length: native.file_size,
                name: component,
            });
            scanned.push(ScannedEntry { name, native });
        }

        let reservation = self
            .identities
            .preflight_directory_observations(self.root_file_id, directory_file_id, observations)
            .map_err(query_dir_registry_error)?;
        if reservation.entries().len() != scanned.len() {
            return Err(ProviderError::internal());
        }
        let mut candidates = Vec::new();
        candidates
            .try_reserve(scanned.len())
            .map_err(|_| terminal(completion_status::INSUFFICIENT_RESOURCES))?;
        for (scanned, identity) in scanned.into_iter().zip(reservation.entries()) {
            let fields =
                metadata::dir_entry_fields(&scanned.native, &identity.file, &identity.link)
                    .map_err(|_| ProviderError::internal())?;
            candidates.push(DirCandidate {
                name: scanned.name,
                fields,
            });
        }
        let committed = self
            .identities
            .finalize_directory_observations(reservation)
            .map_err(|_| ProviderError::internal())?;
        debug_assert_eq!(committed.len(), candidates.len());
        Ok(candidates)
    }

    /// Refresh the accepted backing volume and return its canonical size
    /// geometry. A serial change means the mount's captured identity is no
    /// longer the volume being queried and is an internal consistency stop.
    pub fn query_volume(&mut self) -> FileSystemResult<VolumeSizeFields> {
        let refreshed = windows::volume_geometry(&self.volume.root)
            .map_err(|error| status::from_io(op::QUERY_VOLUME, &error))?;
        if refreshed.root != self.volume.root
            || refreshed.volume_serial != self.volume.volume_serial
            || validate_volume_contract(&refreshed).is_err()
        {
            return Err(ProviderError::internal());
        }
        metadata::volume_size_fields(&refreshed).map_err(|_| ProviderError::internal())
    }

    /// Apply exactly the selected basic-information fields and commit the
    /// namespace/metadata generation lane.
    pub fn set_basic_info(
        &mut self,
        kernel_open_id: u64,
        expected_namespace_generation: u64,
        body: &SetBasicInfoV1,
    ) -> FileSystemResult<MutationEffect> {
        let mut update = metadata::basic_info_update(body)
            .map_err(|_| terminal(completion_status::DATA_ERROR))?;
        let preflight =
            self.preflight_mutation_open(kernel_open_id, windows::FILE_WRITE_ATTRIBUTES)?;
        if body.set_mask & basic_info_set_mask::CHANGE_TIME == 0 {
            // SetFileTime/SetFileAttributesW advance NTFS change-time as an
            // implicit side effect. Restore the refreshed retained value so
            // the ABI's field-selection contract changes only named fields.
            update.change_time = Some(preflight.native.change_time);
        }
        let record = self.opens.get(kernel_open_id)?;
        let commit = self
            .identities
            .preflight_metadata_commit(preflight.file_id, expected_namespace_generation)
            .map_err(metadata_preflight_error)?;

        let finalized = match windows::set_basic_info(&record.handle, &preflight.path, update) {
            Ok(()) => commit.commit(),
            Err(error) if !error.effect_applied() => {
                return Err(status::from_io(op::MUTATE, error.source_io()));
            }
            Err(_) => {
                // One of the wrapper's earlier Win32 calls is already visible.
                // Commit the reserved lane immediately, then stop internally
                // instead of publishing a retry/terminal for a partial effect.
                let _committed_partial_effect = commit.commit();
                return Err(ProviderError::internal());
            }
        };

        let after = self.refresh_mutation_open(kernel_open_id, &preflight)?;
        if !selected_basic_info_matches(&after, body)
            || after.file_size != preflight.native.file_size
            || after.allocation_size != preflight.native.allocation_size
        {
            return Err(ProviderError::internal());
        }
        let sizes = metadata::file_info_fields(&after, &finalized.file)
            .map_err(|_| ProviderError::internal())?
            .sizes;
        if size_tuple(sizes) != size_tuple(preflight.retained_sizes) {
            return Err(ProviderError::internal());
        }

        Ok(MutationEffect {
            file_id: preflight.file_id,
            new_link_id: fsring_abi::ids::LinkId::ZERO,
            replaced: None,
            link_count: after.link_count,
            namespace_generation: finalized.effect.value,
            source_parent_generation: 0,
            target_parent_generation: 0,
            parent_generation: 0,
            sizes,
            retained_sizes: preflight.retained_sizes,
            volume_commit_sequence: finalized.effect.volume_sequence,
            security_generation: 0,
        })
    }

    /// Apply one open-targeted metadata/size/security mutation from the
    /// fully decoded request retained by `fsring-user`.
    pub fn mutate_open(
        &mut self,
        kernel_open_id: u64,
        request: &MutationRequest,
    ) -> FileSystemResult<MutationEffect> {
        match request.body() {
            DecodedBody::SetBasicInfo { raw } => {
                self.set_basic_info(kernel_open_id, request.expected_namespace_generation(), raw)
            }
            DecodedBody::SetAllocationSize { raw } => self.set_allocation_size(
                kernel_open_id,
                request.expected_size_epoch(),
                raw.new_size,
            ),
            DecodedBody::SetEndOfFile { raw } => {
                self.set_end_of_file(kernel_open_id, request.expected_size_epoch(), raw.new_size)
            }
            DecodedBody::SetValidDataLength { raw } => self.set_valid_data_length(
                kernel_open_id,
                request.expected_size_epoch(),
                raw.new_size,
            ),
            DecodedBody::SetSecurity { raw, descriptor } => self.set_security(
                kernel_open_id,
                request.expected_security_generation(),
                raw.security_information,
                descriptor,
            ),
            DecodedBody::Rename { raw, name } => {
                self.rename_namespace(kernel_open_id, request, raw, name)
            }
            DecodedBody::Link { raw, name } => {
                self.link_namespace(kernel_open_id, request, raw, name)
            }
            DecodedBody::Unlink { raw } => self.unlink_namespace(kernel_open_id, request, raw),
        }
    }

    /// Resolve the backing-state fact required by the second mutation
    /// validation pass. RENAME also verifies every generation and identity
    /// used to derive the same-parent relationship.
    pub fn mutation_context(
        &mut self,
        request: &MutationRequest,
    ) -> FileSystemResult<MutationContext> {
        let DecodedBody::Rename { raw, .. } = request.body() else {
            return Ok(MutationContext {
                same_parent_rename: false,
            });
        };
        let source = self
            .identities
            .link(raw.source_link_id)
            .map_err(namespace_registry_error)?
            .clone();
        self.identities
            .expect_namespace_generation(source.child, request.expected_namespace_generation())
            .map_err(namespace_registry_error)?;
        self.identities
            .expect_namespace_generation(source.parent, raw.expected_source_parent_generation)
            .map_err(namespace_registry_error)?;
        self.identities
            .expect_namespace_generation(
                raw.target_parent_id,
                raw.expected_target_parent_generation,
            )
            .map_err(namespace_registry_error)?;
        self.validate_registered_path(source.child, &source.relative_path, None)?;
        let target_parent_path = self
            .identities
            .file_relative_path(self.root_file_id, raw.target_parent_id)
            .map_err(namespace_registry_error)?;
        self.validate_registered_path(raw.target_parent_id, &target_parent_path, Some(true))?;
        Ok(MutationContext {
            same_parent_rename: source.parent == raw.target_parent_id,
        })
    }

    fn rename_namespace(
        &mut self,
        _kernel_open_id: u64,
        request: &MutationRequest,
        body: &RenameV1,
        name: &[u8],
    ) -> FileSystemResult<MutationEffect> {
        let component = path::component_from_utf16le(name)?;
        let source = self
            .identities
            .link(body.source_link_id)
            .map_err(namespace_registry_error)?
            .clone();
        let source_native =
            self.validate_registered_path(source.child, &source.relative_path, None)?;
        self.identities
            .expect_namespace_generation(source.child, request.expected_namespace_generation())
            .map_err(namespace_registry_error)?;
        self.identities
            .expect_namespace_generation(source.parent, body.expected_source_parent_generation)
            .map_err(namespace_registry_error)?;
        self.identities
            .expect_namespace_generation(
                body.target_parent_id,
                body.expected_target_parent_generation,
            )
            .map_err(namespace_registry_error)?;
        let target_relative_path = self
            .identities
            .child_relative_path(self.root_file_id, body.target_parent_id, &component)
            .map_err(namespace_registry_error)?;
        let target_parent_relative_path = self
            .identities
            .file_relative_path(self.root_file_id, body.target_parent_id)
            .map_err(namespace_registry_error)?;
        self.validate_registered_path(
            body.target_parent_id,
            &target_parent_relative_path,
            Some(true),
        )?;

        let (baseline, reconciled_replacement, reconciled_native) = self
            .reconcile_replacement_target(
                body.target_parent_id,
                &component,
                &target_relative_path,
            )?;
        let (replacement, replacement_native) = match reconciled_replacement {
            Some(record) if record.id == source.id => (None, None),
            record => (record, reconciled_native),
        };
        let replace = body.flags & rename_flags::REPLACE_IF_EXISTS != 0;
        if replacement.is_some() && !replace {
            return Err(terminal(completion_status::OBJECT_NAME_COLLISION));
        }
        let replacement_link_count = replacement_native
            .map(|native| {
                native
                    .link_count
                    .checked_sub(1)
                    .ok_or_else(ProviderError::internal)
            })
            .transpose()?;
        let source_file_before = self
            .identities
            .file(source.child)
            .map_err(namespace_registry_error)?
            .clone();
        let retained_sizes = metadata::file_info_fields(&source_native, &source_file_before)
            .map_err(|_| ProviderError::internal())?
            .sizes;

        let mut staged = baseline.clone();
        if let Some(record) = &replacement {
            staged
                .unlink_link(record.id)
                .map_err(namespace_registry_error)?;
        }
        staged
            .rename_link(
                source.id,
                body.target_parent_id,
                component,
                target_relative_path.clone(),
            )
            .map_err(namespace_registry_error)?;
        let mut touched = vec![source.child, source.parent, body.target_parent_id];
        if let Some(record) = &replacement {
            touched.push(record.child);
        }
        let sequence = staged
            .normalize_namespace_stage(&baseline, Some(source.id), &touched)
            .map_err(namespace_registry_error)?
            .volume_sequence;
        let open_plan = self.opens.preflight_rename_paths(
            source.child,
            source.id,
            &source.relative_path,
            &target_relative_path,
            source_native.is_directory,
        )?;
        let mut reopen_plan = source_native
            .is_directory
            .then(|| {
                self.opens.preflight_subtree_reopen(
                    &self.root,
                    &source.relative_path,
                    &target_relative_path,
                )
            })
            .transpose()?;
        if let Some(plan) = &mut reopen_plan {
            plan.release_old_handles(&mut self.opens);
        }

        let native_result = windows::move_file(
            &self.root.join(&source.relative_path),
            &self.root.join(&target_relative_path),
            replace,
        );
        if let Err(error) = native_result {
            if let Some(mut plan) = reopen_plan {
                plan.reopen(false).map_err(|_| ProviderError::internal())?;
                plan.install_handles(&mut self.opens);
            }
            return Err(status::from_io(op::MUTATE, &error));
        }

        std::mem::swap(&mut self.identities, &mut staged);
        open_plan.commit(&mut self.opens);
        if let Some(mut plan) = reopen_plan {
            plan.reopen(true).map_err(|_| ProviderError::internal())?;
            plan.install_handles(&mut self.opens);
        }

        let after = self
            .validate_registered_path(
                source.child,
                &target_relative_path,
                Some(source_native.is_directory),
            )
            .map_err(|_| ProviderError::internal())?;
        if after.key != source_native.key {
            return Err(ProviderError::internal());
        }
        let file = self
            .identities
            .file(source.child)
            .map_err(|_| ProviderError::internal())?;
        let sizes = metadata::file_info_fields(&after, file)
            .map_err(|_| ProviderError::internal())?
            .sizes;
        if size_tuple(sizes) != size_tuple(retained_sizes) {
            return Err(ProviderError::internal());
        }
        let replaced = replacement
            .map(|record| {
                let replaced_file = self
                    .identities
                    .file(record.child)
                    .map_err(|_| ProviderError::internal())?;
                Ok(Replaced {
                    file_id: record.child,
                    link_id: record.id,
                    namespace_generation: replaced_file.namespace_generation,
                    link_count: if record.child == source.child {
                        after.link_count
                    } else {
                        replacement_link_count.ok_or_else(ProviderError::internal)?
                    },
                })
            })
            .transpose()?;
        Ok(MutationEffect {
            file_id: source.child,
            new_link_id: fsring_abi::ids::LinkId::ZERO,
            replaced,
            link_count: after.link_count,
            namespace_generation: file.namespace_generation,
            source_parent_generation: self
                .identities
                .file(source.parent)
                .map_err(|_| ProviderError::internal())?
                .namespace_generation,
            target_parent_generation: self
                .identities
                .file(body.target_parent_id)
                .map_err(|_| ProviderError::internal())?
                .namespace_generation,
            parent_generation: 0,
            sizes,
            retained_sizes,
            volume_commit_sequence: sequence,
            security_generation: 0,
        })
    }

    fn link_namespace(
        &mut self,
        kernel_open_id: u64,
        request: &MutationRequest,
        body: &LinkV1,
        name: &[u8],
    ) -> FileSystemResult<MutationEffect> {
        let component = path::component_from_utf16le(name)?;
        let open = self.opens.get(kernel_open_id)?;
        let source_native = validate_open_native(
            open,
            &self.identities,
            self.volume.volume_serial,
            op::MUTATE,
            true,
        )?;
        validate_open_path(
            open,
            &self.identities,
            &self.root,
            self.volume.volume_serial,
            op::MUTATE,
        )?;
        if open.file_id != body.source_file_id {
            return Err(terminal(completion_status::OBJECT_NAME_NOT_FOUND));
        }
        self.identities
            .expect_namespace_generation(
                body.source_file_id,
                request.expected_namespace_generation(),
            )
            .map_err(namespace_registry_error)?;
        self.identities
            .expect_namespace_generation(
                body.target_parent_id,
                body.expected_target_parent_generation,
            )
            .map_err(namespace_registry_error)?;
        let source_link = self
            .identities
            .link(open.link_id)
            .map_err(namespace_registry_error)?
            .clone();
        let target_relative_path = self
            .identities
            .child_relative_path(self.root_file_id, body.target_parent_id, &component)
            .map_err(namespace_registry_error)?;
        let target_parent_relative_path = self
            .identities
            .file_relative_path(self.root_file_id, body.target_parent_id)
            .map_err(namespace_registry_error)?;
        self.validate_registered_path(
            body.target_parent_id,
            &target_parent_relative_path,
            Some(true),
        )?;
        let (baseline, replacement, replacement_native) = self.reconcile_replacement_target(
            body.target_parent_id,
            &component,
            &target_relative_path,
        )?;
        let replace = body.flags & link_flags::REPLACE_IF_EXISTS != 0;
        if replacement.is_some() && !replace {
            return Err(terminal(completion_status::OBJECT_NAME_COLLISION));
        }
        if replacement_native.is_some_and(|native| native.is_directory) {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        let replacement_link_count = replacement_native
            .map(|native| {
                native
                    .link_count
                    .checked_sub(1)
                    .ok_or_else(ProviderError::internal)
            })
            .transpose()?;
        let source_file_before = self
            .identities
            .file(body.source_file_id)
            .map_err(namespace_registry_error)?
            .clone();
        let retained_sizes = metadata::file_info_fields(&source_native, &source_file_before)
            .map_err(|_| ProviderError::internal())?
            .sizes;

        let mut removal_stage = baseline.clone();
        if let Some(record) = &replacement {
            removal_stage
                .unlink_link(record.id)
                .map_err(namespace_registry_error)?;
            removal_stage
                .normalize_namespace_stage(&baseline, None, &[record.child, body.target_parent_id])
                .map_err(namespace_registry_error)?;
        }
        let mut staged = baseline.clone();
        if let Some(record) = &replacement {
            staged
                .unlink_link(record.id)
                .map_err(namespace_registry_error)?;
        }
        let created = staged
            .create_link(
                body.target_parent_id,
                body.source_file_id,
                component,
                target_relative_path.clone(),
            )
            .map_err(namespace_registry_error)?
            .value;
        let mut touched = vec![body.source_file_id, body.target_parent_id];
        if let Some(record) = &replacement {
            touched.push(record.child);
        }
        let sequence = staged
            .normalize_namespace_stage(&baseline, Some(created), &touched)
            .map_err(namespace_registry_error)?
            .volume_sequence;

        let target_path = self.root.join(&target_relative_path);
        if replacement.is_some() {
            std::fs::remove_file(&target_path)
                .map_err(|error| status::from_io(op::MUTATE, &error))?;
        }
        if let Err(error) =
            windows::create_hard_link(&target_path, &self.root.join(&source_link.relative_path))
        {
            if replacement.is_some() {
                std::mem::swap(&mut self.identities, &mut removal_stage);
                return Err(ProviderError::internal());
            }
            return Err(status::from_io(op::MUTATE, &error));
        }
        std::mem::swap(&mut self.identities, &mut staged);

        let after = self
            .validate_registered_path(body.source_file_id, &target_relative_path, Some(false))
            .map_err(|_| ProviderError::internal())?;
        if after.key != source_native.key {
            return Err(ProviderError::internal());
        }
        let file = self
            .identities
            .file(body.source_file_id)
            .map_err(|_| ProviderError::internal())?;
        let sizes = metadata::file_info_fields(&after, file)
            .map_err(|_| ProviderError::internal())?
            .sizes;
        let replaced = replacement
            .map(|record| {
                let replaced_file = self
                    .identities
                    .file(record.child)
                    .map_err(|_| ProviderError::internal())?;
                Ok(Replaced {
                    file_id: record.child,
                    link_id: record.id,
                    namespace_generation: replaced_file.namespace_generation,
                    link_count: if record.child == body.source_file_id {
                        after.link_count
                    } else {
                        replacement_link_count.ok_or_else(ProviderError::internal)?
                    },
                })
            })
            .transpose()?;
        Ok(MutationEffect {
            file_id: body.source_file_id,
            new_link_id: created,
            replaced,
            link_count: after.link_count,
            namespace_generation: file.namespace_generation,
            source_parent_generation: 0,
            target_parent_generation: self
                .identities
                .file(body.target_parent_id)
                .map_err(|_| ProviderError::internal())?
                .namespace_generation,
            parent_generation: 0,
            sizes,
            retained_sizes,
            volume_commit_sequence: sequence,
            security_generation: 0,
        })
    }

    fn unlink_namespace(
        &mut self,
        _kernel_open_id: u64,
        request: &MutationRequest,
        body: &UnlinkV1,
    ) -> FileSystemResult<MutationEffect> {
        let link = self
            .identities
            .link(body.link_id)
            .map_err(namespace_registry_error)?
            .clone();
        if link.parent != body.parent_id {
            return Err(terminal(completion_status::OBJECT_NAME_NOT_FOUND));
        }
        let native = self.validate_registered_path(link.child, &link.relative_path, None)?;
        self.identities
            .expect_namespace_generation(link.child, request.expected_namespace_generation())
            .map_err(namespace_registry_error)?;
        self.identities
            .expect_namespace_generation(body.parent_id, body.expected_parent_generation)
            .map_err(namespace_registry_error)?;
        let file_before = self
            .identities
            .file(link.child)
            .map_err(namespace_registry_error)?
            .clone();
        let retained_sizes = metadata::file_info_fields(&native, &file_before)
            .map_err(|_| ProviderError::internal())?
            .sizes;
        let remaining_link_count = native
            .link_count
            .checked_sub(1)
            .ok_or_else(ProviderError::internal)?;

        let baseline = self.identities.clone();
        let mut staged = baseline.clone();
        if let Err(error) = staged.unlink_link(link.id) {
            if native.is_directory && matches!(error, identity::RegistryError::CorruptRelativePath)
            {
                return Err(terminal(completion_status::DIRECTORY_NOT_EMPTY));
            }
            return Err(namespace_registry_error(error));
        }
        let sequence = staged
            .normalize_namespace_stage(&baseline, None, &[link.child, link.parent])
            .map_err(namespace_registry_error)?
            .volume_sequence;
        let path = self.root.join(&link.relative_path);
        let native_result = if native.is_directory {
            std::fs::remove_dir(&path)
        } else {
            std::fs::remove_file(&path)
        };
        native_result.map_err(|error| status::from_io(op::MUTATE, &error))?;
        std::mem::swap(&mut self.identities, &mut staged);

        let file = self
            .identities
            .file(link.child)
            .map_err(|_| ProviderError::internal())?;
        let sizes = SizeState {
            size_epoch: file.size_epoch,
            ..retained_sizes
        };
        Ok(MutationEffect {
            file_id: link.child,
            new_link_id: fsring_abi::ids::LinkId::ZERO,
            replaced: None,
            link_count: remaining_link_count,
            namespace_generation: file.namespace_generation,
            source_parent_generation: 0,
            target_parent_generation: 0,
            parent_generation: self
                .identities
                .file(link.parent)
                .map_err(|_| ProviderError::internal())?
                .namespace_generation,
            sizes,
            retained_sizes,
            volume_commit_sequence: sequence,
            security_generation: 0,
        })
    }

    fn validate_registered_path(
        &self,
        file_id: FileId,
        relative_path: &Path,
        expected_directory: Option<bool>,
    ) -> FileSystemResult<windows::NativeMetadata> {
        let path = self.root.join(relative_path);
        let attributes =
            windows::attributes(&path).map_err(|error| status::from_io(op::MUTATE, &error))?;
        if attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(terminal(completion_status::NOT_SUPPORTED));
        }
        let canonical =
            std::fs::canonicalize(&path).map_err(|error| status::from_io(op::MUTATE, &error))?;
        if !canonical.starts_with(&self.root) {
            return Err(ProviderError::internal());
        }
        let is_directory = attributes & windows::FILE_ATTRIBUTE_DIRECTORY != 0;
        if expected_directory.is_some_and(|expected| expected != is_directory) {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        let handle = windows::open_existing(
            &canonical,
            0,
            windows::FILE_SHARE_READ | windows::FILE_SHARE_WRITE | windows::FILE_SHARE_DELETE,
            is_directory,
        )
        .map_err(|error| status::from_io(op::MUTATE, &error))?;
        let native =
            windows::metadata(&handle).map_err(|error| status::from_io(op::MUTATE, &error))?;
        let file = self
            .identities
            .file(file_id)
            .map_err(namespace_registry_error)?;
        if native.key.volume_serial != self.volume.volume_serial
            || file.native != Some(native.key)
            || native.is_directory != is_directory
            || metadata::validate_native_projection(&native).is_err()
        {
            return Err(ProviderError::internal());
        }
        Ok(native)
    }

    /// Inspect a possible native replacement and reconcile it into a private
    /// registry snapshot. An unseen FileId/LinkId is not published unless the
    /// later backing mutation succeeds and swaps this snapshot into place.
    fn reconcile_replacement_target(
        &self,
        parent: FileId,
        component: &path::Component,
        relative_path: &Path,
    ) -> FileSystemResult<(
        IdentityRegistry,
        Option<identity::LinkRecord>,
        Option<windows::NativeMetadata>,
    )> {
        let indexed = match self.identities.link_by_name(parent, component.key()) {
            Ok(record) => Some(record.clone()),
            Err(identity::RegistryError::MissingName) => None,
            Err(error) => return Err(namespace_registry_error(error)),
        };
        let native = self.inspect_contained_native_path(relative_path)?;
        match (indexed, native) {
            (None, None) => Ok((self.identities.clone(), None, None)),
            (Some(_), None) => Err(terminal(completion_status::RETRY)),
            (Some(record), Some(native)) => {
                let file = self
                    .identities
                    .file(record.child)
                    .map_err(namespace_registry_error)?;
                if file.native != Some(native.key) {
                    return Err(terminal(completion_status::RETRY));
                }
                Ok((self.identities.clone(), Some(record), Some(native)))
            }
            (None, Some(native)) => {
                let mut staged = self.identities.clone();
                let (file_id, link_id) = staged
                    .observe_native_and_install_link(
                        self.root_file_id,
                        native.key,
                        native.file_size,
                        parent,
                        component.clone(),
                    )
                    .map_err(namespace_registry_error)?;
                let record = staged
                    .link(link_id)
                    .map_err(|_| ProviderError::internal())?
                    .clone();
                if record.child != file_id || record.relative_path != relative_path {
                    return Err(ProviderError::internal());
                }
                Ok((staged, Some(record), Some(native)))
            }
        }
    }

    fn inspect_contained_native_path(
        &self,
        relative_path: &Path,
    ) -> FileSystemResult<Option<windows::NativeMetadata>> {
        let path = self.root.join(relative_path);
        let attributes = match windows::attributes(&path) {
            Ok(attributes) => attributes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(status::from_io(op::MUTATE, &error)),
        };
        if attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(terminal(completion_status::NOT_SUPPORTED));
        }
        let canonical =
            std::fs::canonicalize(&path).map_err(|error| status::from_io(op::MUTATE, &error))?;
        if !canonical.starts_with(&self.root) {
            return Err(ProviderError::internal());
        }
        let is_directory = attributes & windows::FILE_ATTRIBUTE_DIRECTORY != 0;
        let handle = windows::open_existing(
            &canonical,
            0,
            windows::FILE_SHARE_READ | windows::FILE_SHARE_WRITE | windows::FILE_SHARE_DELETE,
            is_directory,
        )
        .map_err(|error| status::from_io(op::MUTATE, &error))?;
        let native =
            windows::metadata(&handle).map_err(|error| status::from_io(op::MUTATE, &error))?;
        if native.key.volume_serial != self.volume.volume_serial
            || native.is_directory != is_directory
            || metadata::validate_native_projection(&native).is_err()
        {
            return Err(ProviderError::internal());
        }
        Ok(Some(native))
    }

    /// Request a native allocation reservation while preserving EOF and VDL.
    pub fn set_allocation_size(
        &mut self,
        kernel_open_id: u64,
        expected_size_epoch: u64,
        new_size: u64,
    ) -> FileSystemResult<MutationEffect> {
        self.set_size(
            kernel_open_id,
            expected_size_epoch,
            new_size,
            SizeMutationKind::Allocation,
        )
    }

    /// Change EOF, clamping VDL on shrink and preserving it on extension.
    pub fn set_end_of_file(
        &mut self,
        kernel_open_id: u64,
        expected_size_epoch: u64,
        new_size: u64,
    ) -> FileSystemResult<MutationEffect> {
        self.set_size(
            kernel_open_id,
            expected_size_epoch,
            new_size,
            SizeMutationKind::EndOfFile,
        )
    }

    /// Change the tracked/native valid-data length without changing EOF.
    pub fn set_valid_data_length(
        &mut self,
        kernel_open_id: u64,
        expected_size_epoch: u64,
        new_size: u64,
    ) -> FileSystemResult<MutationEffect> {
        self.set_size(
            kernel_open_id,
            expected_size_epoch,
            new_size,
            SizeMutationKind::ValidDataLength,
        )
    }

    fn set_size(
        &mut self,
        kernel_open_id: u64,
        expected_size_epoch: u64,
        new_size: u64,
        kind: SizeMutationKind,
    ) -> FileSystemResult<MutationEffect> {
        let new_size = metadata::checked_mutation_size(new_size)
            .map_err(|_| terminal(completion_status::DATA_ERROR))?;
        let preflight = self.preflight_mutation_open(kernel_open_id, windows::FILE_WRITE_DATA)?;
        if preflight.native.is_directory {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        let record = self.opens.get(kernel_open_id)?;
        let commit = self
            .identities
            .preflight_size_commit(preflight.file_id, expected_size_epoch)
            .map_err(size_preflight_error)?;
        let valid_data_length = match kind {
            SizeMutationKind::Allocation => preflight.retained_sizes.valid_data_length,
            SizeMutationKind::EndOfFile => preflight.retained_sizes.valid_data_length.min(new_size),
            SizeMutationKind::ValidDataLength => {
                if new_size < preflight.retained_sizes.valid_data_length
                    || new_size > preflight.native.file_size
                {
                    return Err(terminal(completion_status::DATA_ERROR));
                }
                new_size
            }
        };

        let native_result = match kind {
            SizeMutationKind::Allocation => windows::set_allocation_size(&record.handle, new_size),
            SizeMutationKind::EndOfFile => record.handle.set_len(new_size),
            SizeMutationKind::ValidDataLength => {
                windows::set_valid_data_length(&record.handle, new_size)
            }
        };
        if let Err(error) = native_result {
            return Err(status::from_io(op::MUTATE, &error));
        }
        let finalized = commit.commit(valid_data_length);

        let after = self.refresh_mutation_open(kernel_open_id, &preflight)?;
        let native_relationship_holds = match kind {
            SizeMutationKind::Allocation => {
                after.file_size == preflight.native.file_size
                    && after.allocation_size >= new_size.max(after.file_size)
            }
            SizeMutationKind::EndOfFile => {
                after.file_size == new_size && after.allocation_size >= after.file_size
            }
            SizeMutationKind::ValidDataLength => {
                after.file_size == preflight.native.file_size
                    && after.allocation_size == preflight.native.allocation_size
            }
        };
        if !native_relationship_holds {
            return Err(ProviderError::internal());
        }
        let sizes = metadata::file_info_fields(&after, &finalized.file)
            .map_err(|_| ProviderError::internal())?
            .sizes;
        if sizes.size_epoch != finalized.effect.size_epoch
            || sizes.valid_data_length != valid_data_length
        {
            return Err(ProviderError::internal());
        }

        Ok(MutationEffect {
            file_id: preflight.file_id,
            new_link_id: fsring_abi::ids::LinkId::ZERO,
            replaced: None,
            link_count: after.link_count,
            namespace_generation: 0,
            source_parent_generation: 0,
            target_parent_generation: 0,
            parent_generation: 0,
            sizes,
            retained_sizes: preflight.retained_sizes,
            volume_commit_sequence: finalized.effect.volume_sequence,
            security_generation: 0,
        })
    }

    fn preflight_mutation_open(
        &self,
        kernel_open_id: u64,
        required_access: u32,
    ) -> FileSystemResult<MutationOpenPreflight> {
        let record = self.opens.get(kernel_open_id)?;
        if record.granted_access & required_access != required_access {
            return Err(terminal(completion_status::ACCESS_DENIED));
        }
        let handle_native = validate_open_native(
            record,
            &self.identities,
            self.volume.volume_serial,
            op::MUTATE,
            false,
        )?;
        let path_native = validate_open_path(
            record,
            &self.identities,
            &self.root,
            self.volume.volume_serial,
            op::MUTATE,
        )?;
        if path_native.key != handle_native.key
            || path_native.is_directory != handle_native.is_directory
        {
            return Err(ProviderError::internal());
        }
        let file = self
            .identities
            .file(record.file_id)
            .map_err(|_| ProviderError::internal())?;
        let retained_sizes = metadata::file_info_fields(&handle_native, file)
            .map_err(|_| ProviderError::internal())?
            .sizes;
        Ok(MutationOpenPreflight {
            file_id: record.file_id,
            link_id: record.link_id,
            path: self.root.join(&record.relative_path),
            native: handle_native,
            retained_sizes,
        })
    }

    fn refresh_mutation_open(
        &self,
        kernel_open_id: u64,
        preflight: &MutationOpenPreflight,
    ) -> FileSystemResult<windows::NativeMetadata> {
        let record = self
            .opens
            .get(kernel_open_id)
            .map_err(|_| ProviderError::internal())?;
        if record.file_id != preflight.file_id || record.link_id != preflight.link_id {
            return Err(ProviderError::internal());
        }
        let handle_native = validate_open_native(
            record,
            &self.identities,
            self.volume.volume_serial,
            op::MUTATE,
            false,
        )
        .map_err(|_| ProviderError::internal())?;
        let path_native = validate_open_path(
            record,
            &self.identities,
            &self.root,
            self.volume.volume_serial,
            op::MUTATE,
        )
        .map_err(|_| ProviderError::internal())?;
        if handle_native.key != preflight.native.key
            || path_native.key != preflight.native.key
            || handle_native.is_directory != preflight.native.is_directory
            || path_native.is_directory != preflight.native.is_directory
        {
            return Err(ProviderError::internal());
        }
        Ok(handle_native)
    }

    /// Query a complete native self-relative security descriptor for one LIVE
    /// retained open using exactly the ABI-accepted information mask.
    pub fn query_security(
        &mut self,
        kernel_open_id: u64,
        security_information: u32,
    ) -> FileSystemResult<Vec<u8>> {
        if security_information == 0
            || security_information & !security_information::QUERY_ACCEPTED_MASK != 0
        {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        let record = self.opens.get(kernel_open_id)?;
        let required_access = query_security_access(security_information);
        if record.granted_access & required_access != required_access {
            return Err(terminal(completion_status::ACCESS_DENIED));
        }
        validate_open_native(
            record,
            &self.identities,
            self.volume.volume_serial,
            op::QUERY_SECURITY,
            false,
        )?;
        validate_open_path(
            record,
            &self.identities,
            &self.root,
            self.volume.volume_serial,
            op::QUERY_SECURITY,
        )?;
        let path = self.root.join(&record.relative_path);
        windows::query_security(&path, security_information)
            .map(Vec::from)
            .map_err(|error| status::from_io(op::QUERY_SECURITY, &error))
    }

    /// Apply an exact validated security-information selection, refresh its
    /// native descriptor, and commit only the security generation lane.
    pub fn set_security(
        &mut self,
        kernel_open_id: u64,
        expected_security_generation: u64,
        security_information: u32,
        descriptor: &[u8],
    ) -> FileSystemResult<MutationEffect> {
        if security_information == 0 || security_information & !security_information::SET_MASK != 0
        {
            return Err(terminal(completion_status::DATA_ERROR));
        }
        windows::validate_security_descriptor(descriptor)
            .map_err(|_| terminal(completion_status::INVALID_SECURITY_DESCR))?;

        let (file_id, link_id, path, before_native, committed_sizes) = {
            let record = self.opens.get(kernel_open_id)?;
            let required_access = set_security_access(security_information);
            if record.granted_access & required_access != required_access {
                return Err(terminal(completion_status::ACCESS_DENIED));
            }
            let handle_native = validate_open_native(
                record,
                &self.identities,
                self.volume.volume_serial,
                op::MUTATE,
                false,
            )?;
            let path_native = validate_open_path(
                record,
                &self.identities,
                &self.root,
                self.volume.volume_serial,
                op::MUTATE,
            )?;
            if path_native.key != handle_native.key
                || path_native.is_directory != handle_native.is_directory
            {
                return Err(ProviderError::internal());
            }
            let file = self
                .identities
                .file(record.file_id)
                .map_err(|_| ProviderError::internal())?;
            let committed_sizes = metadata::file_info_fields(&handle_native, file)
                .map_err(|_| ProviderError::internal())?
                .sizes;
            (
                record.file_id,
                record.link_id,
                self.root.join(&record.relative_path),
                handle_native,
                committed_sizes,
            )
        };

        let commit = self
            .identities
            .preflight_security_commit(file_id, expected_security_generation)
            .map_err(security_preflight_error)?;

        // SetFileSecurityW inside this wrapper is the single native effect
        // boundary. On success the pinned commit performs only infallible
        // scalar assignments; no allocation, lookup, path work, validation, or
        // panic is possible before the security generation and volume sequence
        // agree with the visible backing effect.
        windows::set_security(&path, security_information, descriptor)
            .map_err(|error| status::from_io(op::MUTATE, &error))?;
        let finalized = commit.commit();

        // Fallible native refresh starts only after registry commit. Any
        // impossible mismatch is an internal stop, but can no longer leave a
        // visible security change paired with stale generation/sequence state.
        let _refreshed_descriptor = windows::query_security(&path, security_information)
            .map_err(|_| ProviderError::internal())?;
        let record = self.opens.get(kernel_open_id)?;
        if record.file_id != file_id || record.link_id != link_id {
            return Err(ProviderError::internal());
        }
        let after_native = validate_open_native(
            record,
            &self.identities,
            self.volume.volume_serial,
            op::MUTATE,
            false,
        )
        .map_err(|_| ProviderError::internal())?;
        let after_path = validate_open_path(
            record,
            &self.identities,
            &self.root,
            self.volume.volume_serial,
            op::MUTATE,
        )
        .map_err(|_| ProviderError::internal())?;
        if after_native.key != before_native.key
            || after_path.key != before_native.key
            || after_native.is_directory != before_native.is_directory
            || after_path.is_directory != before_native.is_directory
        {
            return Err(ProviderError::internal());
        }
        debug_assert_eq!(finalized.file.security_generation, finalized.effect.value);

        Ok(MutationEffect {
            file_id,
            new_link_id: fsring_abi::ids::LinkId::ZERO,
            replaced: None,
            link_count: before_native.link_count,
            namespace_generation: 0,
            source_parent_generation: 0,
            target_parent_generation: 0,
            parent_generation: 0,
            sizes: committed_sizes,
            retained_sizes: committed_sizes,
            volume_commit_sequence: finalized.effect.volume_sequence,
            security_generation: finalized.effect.value,
        })
    }

    /// Discover one existing child from registered identity state.
    ///
    /// Containment here assumes the E2 trusted backing is not concurrently
    /// replaced between attribute/canonical checks and the final open. Fully
    /// handle-relative traversal hardening is intentionally deferred.
    #[allow(dead_code)]
    pub(crate) fn discover_child(
        &mut self,
        parent: FileId,
        name: path::Component,
    ) -> Result<Discovered, MirrorFsError> {
        let relative_path = self
            .identities
            .child_relative_path(self.root_file_id, parent, &name)
            .map_err(registry_io_error)?;
        let candidate = self.root.join(&relative_path);

        let candidate_attributes = windows::attributes(&candidate)?;
        if candidate_attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(MirrorFsError::ReparsePoint);
        }
        let canonical = std::fs::canonicalize(&candidate)?;
        if !canonical.starts_with(&self.root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "discovered path escaped the canonical backing root",
            )
            .into());
        }
        let canonical_attributes = windows::attributes(&canonical)?;
        if canonical_attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(MirrorFsError::ReparsePoint);
        }
        let is_directory = canonical_attributes & windows::FILE_ATTRIBUTE_DIRECTORY != 0;
        let handle = windows::open_existing(
            &canonical,
            0,
            windows::FILE_SHARE_READ | windows::FILE_SHARE_WRITE | windows::FILE_SHARE_DELETE,
            is_directory,
        )?;
        let native = windows::metadata(&handle)?;
        metadata::validate_native_projection(&native)?;
        if native.is_directory != is_directory
            || native.key.volume_serial != self.volume.volume_serial
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "discovered native identity disagrees with the backing volume",
            )
            .into());
        }

        let (file_id, link_id) = self
            .identities
            .observe_native_and_install_link(
                self.root_file_id,
                native.key,
                native.file_size,
                parent,
                name,
            )
            .map_err(registry_io_error)?;
        Ok(Discovered {
            handle,
            file_id,
            link_id,
            relative_path,
            native,
        })
    }
}

#[cfg(windows)]
impl FileSystem for MirrorFs {
    fn prepare(
        &mut self,
        request: &PreparedRequest,
        transaction_id: TransactionId,
    ) -> FileSystemResult<PrepareResult> {
        self.prepare_open(request, transaction_id)
    }

    fn commit(&mut self, request: &CommitRequest) -> FileSystemResult<CommitEffect> {
        self.commit_open(request)
    }

    fn abort(&mut self, transaction_id: TransactionId) {
        self.abort_open(transaction_id);
    }

    fn cleanup(&mut self, kernel_open_id: u64) {
        self.cleanup_open(kernel_open_id);
    }

    fn close(&mut self, kernel_open_id: u64) {
        self.close_open(kernel_open_id);
    }

    fn read(
        &mut self,
        kernel_open_id: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> FileSystemResult<usize> {
        MirrorFs::read(self, kernel_open_id, offset, buf)
    }

    fn write(
        &mut self,
        kernel_open_id: u64,
        request: &WriteRequest,
    ) -> FileSystemResult<WriteOutcome> {
        MirrorFs::write(
            self,
            kernel_open_id,
            request.offset(),
            request.expected_size_epoch(),
            request.data(),
        )
    }

    fn flush(&mut self, kernel_open_id: u64) -> FileSystemResult<()> {
        MirrorFs::flush(self, kernel_open_id)
    }

    fn query_dir(
        &mut self,
        kernel_open_id: u64,
        _request: &QueryDirRequest,
    ) -> FileSystemResult<Vec<DirCandidate>> {
        MirrorFs::query_dir(self, kernel_open_id)
    }

    fn query_info(&mut self, kernel_open_id: u64) -> FileSystemResult<FileInfoFields> {
        MirrorFs::query_info(self, kernel_open_id)
    }

    fn query_volume(&mut self) -> FileSystemResult<VolumeSizeFields> {
        MirrorFs::query_volume(self)
    }

    fn query_security(
        &mut self,
        kernel_open_id: u64,
        security_information: u32,
    ) -> FileSystemResult<Vec<u8>> {
        MirrorFs::query_security(self, kernel_open_id, security_information)
    }

    fn mutation_context(&mut self, request: &MutationRequest) -> FileSystemResult<MutationContext> {
        MirrorFs::mutation_context(self, request)
    }

    fn mutate(&mut self, request: &MutationRequest) -> FileSystemResult<MutationEffect> {
        self.mutate_open(request.kernel_open_id(), request)
    }
}

#[cfg(windows)]
fn validate_open_native(
    record: &opens::OpenRecord,
    identities: &IdentityRegistry,
    volume_serial: u32,
    opcode: u16,
    requires_file: bool,
) -> FileSystemResult<windows::NativeMetadata> {
    let native =
        windows::metadata(&record.handle).map_err(|error| status::from_io(opcode, &error))?;
    let file = identities
        .file(record.file_id)
        .map_err(|_| ProviderError::internal())?;
    if requires_file && native.is_directory {
        return Err(terminal(completion_status::DATA_ERROR));
    }
    if native.key.volume_serial != volume_serial
        || file.native != Some(native.key)
        || metadata::validate_native_projection(&native).is_err()
    {
        return Err(ProviderError::internal());
    }
    Ok(native)
}

#[cfg(windows)]
fn validate_open_path(
    record: &opens::OpenRecord,
    identities: &IdentityRegistry,
    root: &Path,
    volume_serial: u32,
    opcode: u16,
) -> FileSystemResult<windows::NativeMetadata> {
    let link = identities
        .link(record.link_id)
        .map_err(|_| ProviderError::internal())?;
    if link.child != record.file_id || link.relative_path != record.relative_path {
        return Err(ProviderError::internal());
    }
    let path = root.join(&record.relative_path);
    let attributes = windows::attributes(&path).map_err(|error| status::from_io(opcode, &error))?;
    if attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(terminal(completion_status::NOT_SUPPORTED));
    }
    let canonical =
        std::fs::canonicalize(&path).map_err(|error| status::from_io(opcode, &error))?;
    if !canonical.starts_with(root) {
        return Err(ProviderError::internal());
    }
    let is_directory = attributes & windows::FILE_ATTRIBUTE_DIRECTORY != 0;
    let handle = windows::open_existing(
        &canonical,
        0,
        windows::FILE_SHARE_READ | windows::FILE_SHARE_WRITE | windows::FILE_SHARE_DELETE,
        is_directory,
    )
    .map_err(|error| status::from_io(opcode, &error))?;
    let native = windows::metadata(&handle).map_err(|error| status::from_io(opcode, &error))?;
    let file = identities
        .file(record.file_id)
        .map_err(|_| ProviderError::internal())?;
    if native.key.volume_serial != volume_serial
        || native.is_directory != is_directory
        || file.native != Some(native.key)
        || metadata::validate_native_projection(&native).is_err()
    {
        return Err(ProviderError::internal());
    }
    Ok(native)
}

#[cfg(windows)]
fn query_security_access(information: u32) -> u32 {
    let mut access = 0;
    if information
        & (security_information::OWNER | security_information::GROUP | security_information::DACL)
        != 0
    {
        access |= windows::READ_CONTROL;
    }
    if information & security_information::SACL != 0 {
        access |= windows::ACCESS_SYSTEM_SECURITY;
    }
    access
}

#[cfg(windows)]
fn set_security_access(information: u32) -> u32 {
    let mut access = 0;
    if information & (security_information::OWNER | security_information::GROUP) != 0 {
        access |= windows::WRITE_OWNER;
    }
    if information
        & (security_information::DACL
            | security_information::ATTRIBUTE
            | security_information::PROTECTED_DACL
            | security_information::UNPROTECTED_DACL)
        != 0
    {
        access |= windows::WRITE_DAC;
    }
    if information
        & (security_information::SACL
            | security_information::SCOPE
            | security_information::PROTECTED_SACL
            | security_information::UNPROTECTED_SACL)
        != 0
    {
        access |= windows::ACCESS_SYSTEM_SECURITY;
    }
    if information & security_information::LABEL != 0 {
        access |= windows::WRITE_OWNER;
    }
    if information & security_information::BACKUP != 0 {
        access |= windows::WRITE_DAC | windows::WRITE_OWNER | windows::ACCESS_SYSTEM_SECURITY;
    }
    access
}

#[cfg(windows)]
fn selected_basic_info_matches(native: &windows::NativeMetadata, body: &SetBasicInfoV1) -> bool {
    (body.set_mask & basic_info_set_mask::CREATION_TIME == 0
        || native.creation_time == body.creation_time)
        && (body.set_mask & basic_info_set_mask::LAST_ACCESS_TIME == 0
            || native.last_access_time == body.last_access_time)
        && (body.set_mask & basic_info_set_mask::LAST_WRITE_TIME == 0
            || native.last_write_time == body.last_write_time)
        && (body.set_mask & basic_info_set_mask::CHANGE_TIME == 0
            || native.change_time == body.change_time)
        && (body.set_mask & basic_info_set_mask::FILE_ATTRIBUTES == 0
            || native.attributes == body.attributes)
}

#[cfg(windows)]
fn size_tuple(sizes: SizeState) -> (u64, u64, u64, u64) {
    (
        sizes.allocation_size,
        sizes.file_size,
        sizes.valid_data_length,
        sizes.size_epoch,
    )
}

#[cfg(windows)]
fn metadata_preflight_error(error: identity::RegistryError) -> ProviderError {
    match error {
        identity::RegistryError::StaleGeneration {
            domain: identity::GenerationDomain::Namespace,
            ..
        } => terminal(completion_status::RETRY),
        identity::RegistryError::CounterExhausted(_) => {
            terminal(completion_status::INSUFFICIENT_RESOURCES)
        }
        _ => ProviderError::internal(),
    }
}

#[cfg(windows)]
fn size_preflight_error(error: identity::RegistryError) -> ProviderError {
    match error {
        identity::RegistryError::StaleGeneration {
            domain: identity::GenerationDomain::Size,
            ..
        } => terminal(completion_status::RETRY),
        identity::RegistryError::CounterExhausted(_) => {
            terminal(completion_status::INSUFFICIENT_RESOURCES)
        }
        _ => ProviderError::internal(),
    }
}

#[cfg(windows)]
fn security_preflight_error(error: identity::RegistryError) -> ProviderError {
    match error {
        identity::RegistryError::StaleGeneration {
            domain: identity::GenerationDomain::Security,
            ..
        } => terminal(completion_status::RETRY),
        identity::RegistryError::CounterExhausted(_) => {
            terminal(completion_status::INSUFFICIENT_RESOURCES)
        }
        _ => ProviderError::internal(),
    }
}

#[cfg(windows)]
fn write_preflight_error(error: identity::RegistryError) -> ProviderError {
    match error {
        identity::RegistryError::StaleGeneration {
            domain: identity::GenerationDomain::Size,
            ..
        } => terminal(completion_status::RETRY),
        identity::RegistryError::CounterExhausted(_) => {
            terminal(completion_status::INSUFFICIENT_RESOURCES)
        }
        _ => ProviderError::internal(),
    }
}

#[cfg(windows)]
fn query_dir_registry_error(error: identity::RegistryError) -> ProviderError {
    match error {
        identity::RegistryError::CapacityExhausted
        | identity::RegistryError::CounterExhausted(_) => {
            terminal(completion_status::INSUFFICIENT_RESOURCES)
        }
        _ => ProviderError::internal(),
    }
}

#[cfg(windows)]
fn namespace_registry_error(error: identity::RegistryError) -> ProviderError {
    match error {
        identity::RegistryError::StaleGeneration {
            domain: identity::GenerationDomain::Namespace,
            ..
        } => terminal(completion_status::RETRY),
        identity::RegistryError::MissingFile(_)
        | identity::RegistryError::MissingLink(_)
        | identity::RegistryError::MissingName
        | identity::RegistryError::MissingPath(_) => {
            terminal(completion_status::OBJECT_NAME_NOT_FOUND)
        }
        identity::RegistryError::NameCollision { .. }
        | identity::RegistryError::DuplicateRelativePath => {
            terminal(completion_status::OBJECT_NAME_COLLISION)
        }
        identity::RegistryError::CounterExhausted(_)
        | identity::RegistryError::CapacityExhausted => {
            terminal(completion_status::INSUFFICIENT_RESOURCES)
        }
        _ => ProviderError::internal(),
    }
}

#[cfg(windows)]
fn terminal(status: i32) -> ProviderError {
    ProviderError::terminal(status)
}

#[cfg(windows)]
fn validate_root_attributes(attributes: u32) -> Result<(), MirrorFsError> {
    if attributes & windows::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(MirrorFsError::ReparsePoint);
    }
    if attributes & windows::FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(MirrorFsError::NotDirectory);
    }
    Ok(())
}

#[cfg(windows)]
fn validate_volume_contract(volume: &windows::VolumeGeometry) -> Result<(), MirrorFsError> {
    if volume.drive_type != windows::DRIVE_FIXED {
        return Err(MirrorFsError::NonLocalVolume);
    }
    if !volume
        .filesystem_name
        .to_string_lossy()
        .eq_ignore_ascii_case("NTFS")
    {
        return Err(MirrorFsError::NonNtfsVolume);
    }
    Ok(())
}

#[cfg(windows)]
fn registry_io_error(error: identity::RegistryError) -> MirrorFsError {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("identity registry rejected validated backing state: {error:?}"),
    )
    .into()
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    #[cfg(windows)]
    use std::ffi::OsString;
    use std::io;
    #[cfg(windows)]
    use std::path::PathBuf;
    #[cfg(windows)]
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(windows)]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(windows)]
    use fsring_abi::codec::try_decode;
    #[cfg(windows)]
    use fsring_abi::ids::{OpId, TransactionId};
    #[cfg(windows)]
    use fsring_abi::msgs::{file_attributes, CommitOpenV2, PrepareOpenV2};
    #[cfg(windows)]
    use fsring_user::{CommitRequest, PreparedRequest, ProviderError};

    #[cfg(not(windows))]
    use super::MirrorFsError;
    #[cfg(windows)]
    use super::{
        path::component_from_utf16le, set_security_access, validate_volume_contract, windows,
        MirrorFs, MirrorFsError,
    };

    #[cfg(windows)]
    static NEXT_DISCOVERY_ROOT: AtomicU64 = AtomicU64::new(1);

    #[cfg(windows)]
    struct DiscoveryRoot {
        path: PathBuf,
        reparse_points: Vec<PathBuf>,
    }

    #[cfg(windows)]
    impl DiscoveryRoot {
        fn new(case: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = NEXT_DISCOVERY_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = PathBuf::from(r"D:\temp").join(format!(
                "winfsr-mirrorfs-unit-{case}-{}-{sequence}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self {
                path,
                reparse_points: Vec::new(),
            }
        }

        fn track_reparse(&mut self, path: PathBuf) {
            assert_eq!(path.parent(), Some(self.path.as_path()));
            self.reparse_points.push(path);
        }
    }

    #[cfg(windows)]
    impl Drop for DiscoveryRoot {
        fn drop(&mut self) {
            for path in self.reparse_points.iter().rev() {
                let _ = std::fs::remove_dir(path).or_else(|_| std::fs::remove_file(path));
            }
            let owned_name = self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("winfsr-mirrorfs-unit-"));
            if self.path.parent() == Some(std::path::Path::new(r"D:\temp")) && owned_name {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    #[cfg(windows)]
    fn component(name: &str) -> crate::path::Component {
        let bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        component_from_utf16le(&bytes).unwrap()
    }

    #[cfg(windows)]
    fn committed_request(
        parent: fsring_abi::ids::FileId,
        name: &str,
        directory: bool,
        op_id: u64,
    ) -> PreparedRequest {
        let mut raw: PrepareOpenV2 = try_decode(&[0_u8; 192]).unwrap();
        raw.op_id = OpId { lo: op_id, hi: 0 };
        raw.parent_id = parent;
        raw.desired_access = windows::FILE_GENERIC_READ | windows::FILE_GENERIC_WRITE;
        raw.share_access =
            windows::FILE_SHARE_READ | windows::FILE_SHARE_WRITE | windows::FILE_SHARE_DELETE;
        raw.disposition = 1;
        raw.create_options = if directory { 1 } else { 0x40 };
        raw.file_attributes = if directory {
            file_attributes::DIRECTORY
        } else {
            file_attributes::NORMAL
        };
        let name = name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        PreparedRequest::from_raw(raw, name, None, None)
    }

    #[cfg(windows)]
    fn commit_request(
        request: &PreparedRequest,
        transaction_id: u64,
        kernel_open_id: u64,
        namespace_generation: u64,
        security_generation: u64,
    ) -> CommitRequest {
        commit_request_with_access(
            request,
            transaction_id,
            kernel_open_id,
            namespace_generation,
            security_generation,
            windows::FILE_GENERIC_READ | windows::FILE_GENERIC_WRITE,
        )
    }

    #[cfg(windows)]
    fn commit_request_with_access(
        request: &PreparedRequest,
        transaction_id: u64,
        kernel_open_id: u64,
        namespace_generation: u64,
        security_generation: u64,
        granted_access: u32,
    ) -> CommitRequest {
        let mut raw: CommitOpenV2 = try_decode(&[0_u8; 104]).unwrap();
        raw.op_id = request.op_id;
        raw.transaction_id = TransactionId {
            lo: transaction_id,
            hi: 0,
        };
        raw.expected_namespace_generation = namespace_generation;
        raw.expected_security_generation = security_generation;
        raw.kernel_open_id = kernel_open_id;
        raw.granted_access = granted_access;
        CommitRequest::from_raw(raw)
    }

    #[cfg(windows)]
    fn native_metadata(path: &std::path::Path, directory: bool) -> windows::NativeMetadata {
        let handle = windows::open_existing(
            path,
            0,
            windows::FILE_SHARE_READ | windows::FILE_SHARE_WRITE | windows::FILE_SHARE_DELETE,
            directory,
        )
        .unwrap();
        windows::metadata(&handle).unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn contained_discovery_registers_nested_identity_and_projects_metadata() {
        let root = DiscoveryRoot::new("nested");
        let directory = root.path.join("parent");
        let child = directory.join("child.bin");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(&child, b"native bytes").unwrap();
        let mut provider = MirrorFs::open(&root.path).unwrap();

        let parent = provider
            .discover_child(provider.root_file_id(), component("parent"))
            .unwrap();
        let discovered = provider
            .discover_child(parent.file_id, component("child.bin"))
            .unwrap();
        let file = provider.identities.file(discovered.file_id).unwrap();
        let link = provider.identities.link(discovered.link_id).unwrap();
        let info = crate::metadata::file_info_fields(&discovered.native, file).unwrap();
        let entry = crate::metadata::dir_entry_fields(&discovered.native, file, link).unwrap();

        assert_eq!(
            discovered.relative_path,
            PathBuf::from("parent").join("child.bin")
        );
        assert_eq!(
            windows::metadata(&discovered.handle).unwrap(),
            discovered.native
        );
        assert_eq!(info.sizes.file_size, 12);
        assert_eq!(info.sizes.valid_data_length, 12);
        assert_eq!(info.attributes, discovered.native.attributes);
        assert_eq!(info.link_count, discovered.native.link_count);
        assert_eq!(entry.file_id, discovered.file_id);
        assert_eq!(entry.link_id, discovered.link_id);
        assert_eq!(entry.namespace_generation, link.namespace_generation);
    }

    #[cfg(windows)]
    #[test]
    fn current_token_sacl_wrapper_is_exactly_privileged_or_denied_without_registry_effect() {
        const SECURITY_INFORMATION: u32 = windows::OWNER_SECURITY_INFORMATION
            | windows::GROUP_SECURITY_INFORMATION
            | windows::DACL_SECURITY_INFORMATION;
        const ACCESS_DENIED: i32 = 5;
        const PRIVILEGE_NOT_HELD: i32 = 1314;

        fn normalize_control(descriptor: &[u8]) -> Vec<u8> {
            let mut normalized = descriptor.to_vec();
            let control = u16::from_le_bytes([normalized[2], normalized[3]]);
            let semantic_control = control & (0x0010 | 0x0004 | 0x8000);
            normalized[2..4].copy_from_slice(&semantic_control.to_le_bytes());
            normalized
        }

        let root = DiscoveryRoot::new("sacl-current-token");
        let path = root.path.join("secured.bin");
        std::fs::write(&path, b"owned SACL probe").unwrap();
        let mut provider = MirrorFs::open(&root.path).unwrap();
        let discovered = provider
            .discover_child(provider.root_file_id(), component("secured.bin"))
            .unwrap();
        let before_file = provider
            .identities
            .file(discovered.file_id)
            .unwrap()
            .clone();
        let before_descriptor = windows::query_security(&path, SECURITY_INFORMATION).unwrap();
        let before_bytes = std::fs::read(&path).unwrap();

        let outcome = match windows::query_security(&path, windows::SACL_SECURITY_INFORMATION) {
            Ok(sacl) => {
                match windows::set_security(&path, windows::SACL_SECURITY_INFORMATION, &sacl) {
                    Ok(()) => {
                        let refreshed =
                            windows::query_security(&path, windows::SACL_SECURITY_INFORMATION)
                                .unwrap();
                        assert!((20..=65_536).contains(&refreshed.len()));
                        "native SACL query/set succeeded"
                    }
                    Err(error) => {
                        assert!(matches!(
                            error.raw_os_error(),
                            Some(ACCESS_DENIED) | Some(PRIVILEGE_NOT_HELD)
                        ));
                        "native SACL query succeeded; set lacked privilege"
                    }
                }
            }
            Err(error) => {
                assert!(matches!(
                    error.raw_os_error(),
                    Some(ACCESS_DENIED) | Some(PRIVILEGE_NOT_HELD)
                ));
                "native SACL query lacked privilege"
            }
        };
        println!("{outcome}");

        let after_descriptor = windows::query_security(&path, SECURITY_INFORMATION).unwrap();
        assert_eq!(
            normalize_control(&after_descriptor),
            normalize_control(&before_descriptor)
        );
        assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
        assert_eq!(
            provider.identities.file(discovered.file_id).unwrap(),
            &before_file
        );
        let sequence = provider
            .identities
            .record_existing_effect(discovered.file_id)
            .unwrap()
            .volume_sequence;
        assert_eq!(sequence, 1, "direct wrapper failure consumed no sequence");
    }

    #[cfg(windows)]
    #[test]
    fn contained_discovery_rejects_reparse_before_identity_installation() {
        let mut root = DiscoveryRoot::new("reparse-child");
        let target = root.path.join("target");
        let link = root.path.join("link");
        std::fs::create_dir(&target).unwrap();
        std::os::windows::fs::symlink_dir(&target, &link).unwrap();
        root.track_reparse(link);
        let target_native = native_metadata(&target, true);
        let mut provider = MirrorFs::open(&root.path).unwrap();

        assert!(matches!(
            provider.discover_child(provider.root_file_id(), component("link")),
            Err(MirrorFsError::ReparsePoint)
        ));
        assert!(matches!(
            provider.identities.file_id_for_native(target_native.key),
            Err(crate::identity::RegistryError::MissingNative)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn contained_discovery_rejects_a_registered_parent_swapped_outside_root() {
        let mut root = DiscoveryRoot::new("escape");
        let outside = DiscoveryRoot::new("outside");
        let parent_path = root.path.join("parent");
        std::fs::create_dir(&parent_path).unwrap();
        std::fs::write(outside.path.join("escaped.bin"), b"outside").unwrap();
        let mut provider = MirrorFs::open(&root.path).unwrap();
        let parent = provider
            .discover_child(provider.root_file_id(), component("parent"))
            .unwrap();
        std::fs::remove_dir(&parent_path).unwrap();
        std::os::windows::fs::symlink_dir(&outside.path, &parent_path).unwrap();
        root.track_reparse(parent_path);

        match provider.discover_child(parent.file_id, component("escaped.bin")) {
            Err(MirrorFsError::Io(error)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied)
            }
            other => panic!("root escape returned {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn root_file_id_is_stored_and_stable_after_backing_root_removal() {
        let fixture = DiscoveryRoot::new("root-id-stable");
        let original = fixture.path.join("backing");
        let renamed = fixture.path.join("renamed");
        std::fs::create_dir(&original).unwrap();
        let provider = MirrorFs::open(&original).unwrap();
        let installed = provider.root_file_id;

        std::fs::rename(&original, &renamed).unwrap();
        std::fs::remove_dir(&renamed).unwrap();

        assert_eq!(provider.root_file_id(), installed);
        assert_eq!(provider.root_file_id(), installed);
    }

    #[cfg(windows)]
    fn volume(filesystem_name: &str, drive_type: u32) -> windows::VolumeGeometry {
        windows::VolumeGeometry {
            root: PathBuf::from(r"D:\"),
            filesystem_name: OsString::from(filesystem_name),
            drive_type,
            volume_serial: 7,
            total_allocation_units: 100,
            available_allocation_units: 50,
            sectors_per_allocation_unit: 8,
            bytes_per_sector: 512,
        }
    }

    #[cfg(windows)]
    #[test]
    fn volume_contract_accepts_fixed_ntfs_case_insensitively() {
        for filesystem_name in ["NTFS", "ntfs", "NtFs"] {
            validate_volume_contract(&volume(filesystem_name, windows::DRIVE_FIXED)).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn volume_contract_rejects_fat32_and_refs_exactly() {
        for filesystem_name in ["FAT32", "ReFS"] {
            assert!(matches!(
                validate_volume_contract(&volume(filesystem_name, windows::DRIVE_FIXED)),
                Err(MirrorFsError::NonNtfsVolume)
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn volume_contract_rejects_remote_and_removable_drives_exactly() {
        const DRIVE_REMOVABLE: u32 = 2;
        const DRIVE_REMOTE: u32 = 4;

        for drive_type in [DRIVE_REMOVABLE, DRIVE_REMOTE] {
            assert!(matches!(
                validate_volume_contract(&volume("NTFS", drive_type)),
                Err(MirrorFsError::NonLocalVolume)
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn every_set_security_information_bit_requires_the_exact_retained_access() {
        use fsring_abi::msgs::security_information;

        let cases = [
            (security_information::OWNER, windows::WRITE_OWNER),
            (security_information::GROUP, windows::WRITE_OWNER),
            (security_information::DACL, windows::WRITE_DAC),
            (security_information::SACL, windows::ACCESS_SYSTEM_SECURITY),
            (security_information::LABEL, windows::WRITE_OWNER),
            (security_information::ATTRIBUTE, windows::WRITE_DAC),
            (security_information::SCOPE, windows::ACCESS_SYSTEM_SECURITY),
            (
                security_information::BACKUP,
                windows::WRITE_DAC | windows::WRITE_OWNER | windows::ACCESS_SYSTEM_SECURITY,
            ),
            (security_information::PROTECTED_DACL, windows::WRITE_DAC),
            (security_information::UNPROTECTED_DACL, windows::WRITE_DAC),
            (
                security_information::PROTECTED_SACL,
                windows::ACCESS_SYSTEM_SECURITY,
            ),
            (
                security_information::UNPROTECTED_SACL,
                windows::ACCESS_SYSTEM_SECURITY,
            ),
        ];
        let mut all_bits = 0;
        let mut all_access = 0;
        for (information, access) in cases {
            assert_eq!(
                set_security_access(information),
                access,
                "information bit {information:#010x}"
            );
            all_bits |= information;
            all_access |= access;
        }
        assert_eq!(all_bits, security_information::SET_MASK);
        assert_eq!(
            set_security_access(security_information::OWNER | security_information::DACL),
            windows::WRITE_OWNER | windows::WRITE_DAC
        );
        assert_eq!(
            set_security_access(security_information::SET_MASK),
            all_access
        );
    }

    #[cfg(windows)]
    #[test]
    fn deterministic_short_write_reports_exact_prefix_and_zero_is_data_error() {
        let root = DiscoveryRoot::new("short-write");
        let path = root.path.join("short.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let mut provider = MirrorFs::open(&root.path).unwrap();
        let request = committed_request(provider.root_file_id(), "short.bin", false, 300);
        let prepared = provider
            .prepare_open(&request, TransactionId { lo: 1300, hi: 0 })
            .unwrap();
        let committed = provider
            .commit_open(&commit_request(
                &request,
                1300,
                5300,
                prepared.namespace_generation,
                prepared.security_generation,
            ))
            .unwrap();

        let outcome = windows::with_short_write_limit(3, || {
            provider.write(5300, 7, committed.sizes.size_epoch, b"abcdef")
        })
        .expect("short prefix commits");
        assert_eq!(outcome.information, 3);
        assert_eq!(outcome.effect.volume_commit_sequence, 2);
        assert_eq!(outcome.effect.sizes.size_epoch, committed.sizes.size_epoch);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"0123456abc",
            "the requested maximum extended EOF but the committed short prefix did not"
        );

        let before = std::fs::read(&path).unwrap();
        let zero = windows::with_short_write_limit(0, || {
            provider.write(5300, 0, outcome.effect.sizes.size_epoch, b"must not commit")
        });
        match zero {
            Ok(_) => panic!("zero native write must not commit"),
            Err(error) => assert_eq!(
                error.status(),
                fsring_abi::validate::completion_status::DATA_ERROR
            ),
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);

        provider.cleanup_open(5300);
        provider.close_open(5300);
    }

    #[cfg(windows)]
    #[test]
    fn query_info_accepts_a_committed_directory_handle() {
        let root = DiscoveryRoot::new("directory-query-info");
        std::fs::create_dir(root.path.join("directory")).unwrap();
        let mut provider = MirrorFs::open(&root.path).unwrap();
        let request = committed_request(provider.root_file_id(), "directory", true, 301);
        let prepared = provider
            .prepare_open(&request, TransactionId { lo: 1301, hi: 0 })
            .unwrap();
        provider
            .commit_open(&commit_request(
                &request,
                1301,
                5301,
                prepared.namespace_generation,
                prepared.security_generation,
            ))
            .unwrap();

        let fields = provider
            .query_info(5301)
            .expect("canonical info supports directories");
        assert_ne!(fields.attributes & file_attributes::DIRECTORY, 0);
        fsring_user::build_file_info(&fields).unwrap();

        let mut byte = [0_u8; 1];
        assert_eq!(
            provider.read(5301, 0, &mut byte).unwrap_err().status(),
            fsring_abi::validate::completion_status::DATA_ERROR
        );
        match provider.write(5301, 0, prepared.sizes.size_epoch, b"x") {
            Ok(_) => panic!("directory WRITE must fail"),
            Err(error) => assert_eq!(
                error.status(),
                fsring_abi::validate::completion_status::DATA_ERROR
            ),
        }

        provider.cleanup_open(5301);
        provider.close_open(5301);
    }

    #[cfg(windows)]
    #[test]
    fn refreshed_volume_identity_change_is_internal_corruption() {
        let root = DiscoveryRoot::new("volume-identity-change");
        let mut provider = MirrorFs::open(&root.path).unwrap();
        provider.volume.volume_serial ^= 1;

        assert_eq!(
            provider.query_volume().unwrap_err(),
            ProviderError::internal()
        );
    }

    #[cfg(windows)]
    #[test]
    fn retained_granted_access_rejects_write_before_native_effect() {
        let root = DiscoveryRoot::new("granted-read-only");
        let path = root.path.join("read-only-open.bin");
        std::fs::write(&path, b"unchanged").unwrap();
        let mut provider = MirrorFs::open(&root.path).unwrap();
        let request = committed_request(provider.root_file_id(), "read-only-open.bin", false, 302);
        let prepared = provider
            .prepare_open(&request, TransactionId { lo: 1302, hi: 0 })
            .unwrap();
        provider
            .commit_open(&commit_request_with_access(
                &request,
                1302,
                5302,
                prepared.namespace_generation,
                prepared.security_generation,
                windows::FILE_GENERIC_READ,
            ))
            .unwrap();

        match provider.write(5302, 0, prepared.sizes.size_epoch, b"blocked") {
            Ok(_) => panic!("read-only grant must reject WRITE"),
            Err(error) => assert_eq!(
                error.status(),
                fsring_abi::validate::completion_status::ACCESS_DENIED
            ),
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"unchanged");

        provider.cleanup_open(5302);
        provider.close_open(5302);
    }

    #[test]
    fn construction_errors_have_stable_display_messages() {
        let cases = [
            (
                MirrorFsError::NotDirectory,
                "backing root is not a directory",
            ),
            (
                MirrorFsError::ReparsePoint,
                "backing root is a reparse point",
            ),
            (
                MirrorFsError::NonLocalVolume,
                "backing root is not on a local volume",
            ),
            (
                MirrorFsError::NonNtfsVolume,
                "backing root is not on an NTFS volume",
            ),
            (MirrorFsError::InvalidComponent, "invalid path component"),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn io_error_display_and_source_preserve_the_underlying_error() {
        let error = MirrorFsError::Io(io::Error::other("I/O sentinel"));

        assert_eq!(
            error.to_string(),
            "mirror filesystem I/O error: I/O sentinel"
        );
        assert_eq!(error.source().unwrap().to_string(), "I/O sentinel");
    }

    #[test]
    fn io_error_converts_into_the_construction_error() {
        let error: MirrorFsError = io::Error::new(io::ErrorKind::PermissionDenied, "denied").into();

        match error {
            MirrorFsError::Io(source) => {
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
                assert_eq!(source.to_string(), "denied");
            }
            other => panic!("expected I/O variant, got {other:?}"),
        }
    }
}
