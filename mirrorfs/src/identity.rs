use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use fsring_abi::ids::{FileId, LinkId};

use crate::path::{Component, NormalizedName};

type NormalizedPath = Vec<NormalizedName>;

#[cfg(test)]
thread_local! {
    static DIRECTORY_BATCH_GLOBAL_LINK_SCANS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_directory_batch_global_link_scan() {
    DIRECTORY_BATCH_GLOBAL_LINK_SCANS.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
fn reset_directory_batch_global_link_scans() {
    DIRECTORY_BATCH_GLOBAL_LINK_SCANS.with(|count| count.set(0));
}

#[cfg(test)]
fn directory_batch_global_link_scans() -> u64 {
    DIRECTORY_BATCH_GLOBAL_LINK_SCANS.with(std::cell::Cell::get)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct NativeKey {
    pub volume_serial: u32,
    pub file_index: u64,
}

impl NativeKey {
    pub(crate) const ZERO: Self = Self {
        volume_serial: 0,
        file_index: 0,
    };

    fn is_zero(self) -> bool {
        self == Self::ZERO
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenerationDomain {
    FileIdentity,
    LinkIdentity,
    Namespace,
    Security,
    Size,
    VolumeSequence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegistryError {
    InvalidNativeKey,
    MissingFile(FileId),
    MissingLink(LinkId),
    MissingName,
    MissingNative,
    MissingPath(FileId),
    AmbiguousPath(FileId),
    CorruptRelativePath,
    DuplicateRelativePath,
    StaleGeneration {
        domain: GenerationDomain,
        expected: u64,
        actual: u64,
    },
    NameCollision {
        parent: FileId,
    },
    NativeCollision {
        native: NativeKey,
        existing: FileId,
        requested: FileId,
    },
    FileNativeConflict {
        file: FileId,
    },
    CounterExhausted(GenerationDomain),
    CapacityExhausted,
    CorruptCounter(GenerationDomain),
    CorruptFileRecord,
    CorruptLinkRecord,
    CorruptNativeIndex,
    CorruptNameIndex,
    CorruptChildIndex,
    CorruptPathIndex,
    ContainedRootLink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RegistryEffect<T> {
    pub value: T,
    pub volume_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WriteEffect {
    pub volume_sequence: u64,
    pub size_epoch: u64,
    pub valid_data_length: u64,
    pub size_changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WriteFinalization {
    pub effect: WriteEffect,
    pub file: FileRecord,
}

pub(crate) struct CreateOpenReservation {
    parent: FileId,
    child: FileId,
    link_id: LinkId,
    name_key: NormalizedName,
    by_path_key: NormalizedPath,
    path_by_link_key: NormalizedPath,
    child_links: HashSet<LinkId>,
    link_record: LinkRecord,
    file_updates: Vec<(FileId, FileRecord)>,
    next_link_id: u64,
    next_namespace_generation: u64,
    volume_sequence: u64,
    next_volume_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExistingOpenSizeEffect {
    Preserve,
    Truncate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExistingOpenNamespaceEffect {
    Preserve,
    Advance,
}

pub(crate) struct ExistingOpenReservation {
    file: FileRecord,
    next_namespace_generation: u64,
    next_size_epoch: u64,
    volume_sequence: u64,
    next_volume_sequence: u64,
}

pub(crate) struct WriteReservation {
    file: FileRecord,
    reserved_size_epoch: Option<u64>,
    next_size_epoch: u64,
    volume_sequence: u64,
    next_volume_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MetadataFinalization {
    pub effect: RegistryEffect<u64>,
    pub file: FileRecord,
}

pub(crate) struct MetadataCommit<'a> {
    file: &'a mut FileRecord,
    next_namespace_generation: &'a mut u64,
    next_volume_sequence: &'a mut u64,
    namespace_generation: u64,
    following_namespace_generation: u64,
    volume_sequence: u64,
    following_volume_sequence: u64,
}

impl MetadataCommit<'_> {
    /// Commit an already-visible native basic-information effect using only
    /// scalar assignments and a scalar-only record copy.
    pub(crate) fn commit(self) -> MetadataFinalization {
        self.file.namespace_generation = self.namespace_generation;
        *self.next_namespace_generation = self.following_namespace_generation;
        *self.next_volume_sequence = self.following_volume_sequence;
        MetadataFinalization {
            effect: RegistryEffect {
                value: self.namespace_generation,
                volume_sequence: self.volume_sequence,
            },
            file: copy_file_record(self.file),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SizeMutationEffect {
    pub volume_sequence: u64,
    pub size_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SizeFinalization {
    pub effect: SizeMutationEffect,
    pub file: FileRecord,
}

pub(crate) struct SizeCommit<'a> {
    file: &'a mut FileRecord,
    next_size_epoch: &'a mut u64,
    next_volume_sequence: &'a mut u64,
    size_epoch: u64,
    following_size_epoch: u64,
    volume_sequence: u64,
    following_volume_sequence: u64,
}

impl SizeCommit<'_> {
    /// Commit an already-visible native size effect. All relationships and
    /// counter reservations were proved by preflight; this tail cannot fail.
    pub(crate) fn commit(self, valid_data_length: u64) -> SizeFinalization {
        self.file.size_epoch = self.size_epoch;
        self.file.valid_data_length = valid_data_length;
        *self.next_size_epoch = self.following_size_epoch;
        *self.next_volume_sequence = self.following_volume_sequence;
        SizeFinalization {
            effect: SizeMutationEffect {
                volume_sequence: self.volume_sequence,
                size_epoch: self.size_epoch,
            },
            file: copy_file_record(self.file),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SecurityReservation {
    file: FileRecord,
    security_generation: u64,
    next_security_generation: u64,
    volume_sequence: u64,
    next_volume_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SecurityFinalization {
    pub effect: RegistryEffect<u64>,
    pub file: FileRecord,
}

pub(crate) struct SecurityCommit<'a> {
    file: &'a mut FileRecord,
    next_security_generation: &'a mut u64,
    next_volume_sequence: &'a mut u64,
    security_generation: u64,
    following_security_generation: u64,
    volume_sequence: u64,
    following_volume_sequence: u64,
}

impl SecurityCommit<'_> {
    /// Commit the already-visible native security effect.
    ///
    /// Preflight pins direct mutable references to the exact record and both
    /// counters. This tail performs only scalar assignments and a scalar-only
    /// FileRecord copy: no lookup, allocation, validation, panic, or fallible
    /// branch remains between the native effect boundary and registry commit.
    pub(crate) fn commit(self) -> SecurityFinalization {
        self.file.security_generation = self.security_generation;
        *self.next_security_generation = self.following_security_generation;
        *self.next_volume_sequence = self.following_volume_sequence;
        SecurityFinalization {
            effect: RegistryEffect {
                value: self.security_generation,
                volume_sequence: self.volume_sequence,
            },
            file: copy_file_record(self.file),
        }
    }
}

fn copy_file_record(file: &FileRecord) -> FileRecord {
    FileRecord {
        id: file.id,
        native: file.native,
        namespace_generation: file.namespace_generation,
        security_generation: file.security_generation,
        size_epoch: file.size_epoch,
        valid_data_length: file.valid_data_length,
    }
}

pub(crate) struct DirectoryObservation {
    pub native: NativeKey,
    pub valid_data_length: u64,
    pub name: Component,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct DirectoryEntryIdentity {
    pub file: FileRecord,
    pub link: LinkRecord,
}

struct PlannedDirectoryLink {
    record: LinkRecord,
    name_key: NormalizedName,
    by_path_key: NormalizedPath,
    path_by_link_key: NormalizedPath,
}

struct ChildLinkPlan {
    child: FileId,
    expected: Vec<LinkId>,
    replacement: HashSet<LinkId>,
}

pub(crate) struct DirectoryObservationReservation {
    entries: Vec<DirectoryEntryIdentity>,
    expected_files: Vec<FileRecord>,
    expected_links: Vec<LinkRecord>,
    new_files: Vec<(NativeKey, FileRecord)>,
    new_links: Vec<PlannedDirectoryLink>,
    child_links: Vec<ChildLinkPlan>,
    base_counters: [u64; 6],
    next_file_id: u64,
    next_link_id: u64,
    next_namespace_generation: u64,
    next_security_generation: u64,
    next_size_epoch: u64,
}

impl DirectoryObservationReservation {
    pub(crate) fn entries(&self) -> &[DirectoryEntryIdentity] {
        &self.entries
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileRecord {
    pub id: FileId,
    pub native: Option<NativeKey>,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub size_epoch: u64,
    pub valid_data_length: u64,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct LinkRecord {
    pub id: LinkId,
    pub parent: FileId,
    pub child: FileId,
    pub name: Component,
    pub relative_path: PathBuf,
    pub namespace_generation: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct IdentityRegistry {
    files: HashMap<FileId, FileRecord>,
    by_native: HashMap<NativeKey, FileId>,
    links: HashMap<LinkId, LinkRecord>,
    by_name: HashMap<(FileId, NormalizedName), LinkId>,
    contained_root: Option<FileId>,
    by_child: HashMap<FileId, HashSet<LinkId>>,
    by_path: HashMap<NormalizedPath, LinkId>,
    path_by_link: HashMap<LinkId, NormalizedPath>,
    next_file_id: u64,
    next_link_id: u64,
    next_namespace_generation: u64,
    next_security_generation: u64,
    next_size_epoch: u64,
    next_volume_sequence: u64,
}

impl IdentityRegistry {
    pub(crate) fn new() -> Self {
        Self {
            files: HashMap::new(),
            by_native: HashMap::new(),
            links: HashMap::new(),
            by_name: HashMap::new(),
            contained_root: None,
            by_child: HashMap::new(),
            by_path: HashMap::new(),
            path_by_link: HashMap::new(),
            next_file_id: 1,
            next_link_id: 1,
            next_namespace_generation: 1,
            next_security_generation: 1,
            next_size_epoch: 1,
            next_volume_sequence: 1,
        }
    }

    #[cfg(feature = "fuzzing")]
    pub(crate) fn assert_fuzz_invariants(&self) {
        self.validate()
            .expect("the identity registry must preserve every cross-index invariant");
        assert!(self.files.keys().all(|id| *id != FileId::ZERO));
        assert!(self.links.keys().all(|id| *id != LinkId::ZERO));
        assert!(self
            .files
            .values()
            .all(|record| record.namespace_generation != 0
                && record.security_generation != 0
                && record.size_epoch != 0));
        assert!(self
            .links
            .values()
            .all(|record| record.namespace_generation != 0));
    }

    fn validate(&self) -> Result<(), RegistryError> {
        self.validate_counter(self.next_file_id, GenerationDomain::FileIdentity)?;
        self.validate_counter(self.next_link_id, GenerationDomain::LinkIdentity)?;
        self.validate_counter(self.next_namespace_generation, GenerationDomain::Namespace)?;
        self.validate_counter(self.next_security_generation, GenerationDomain::Security)?;
        self.validate_counter(self.next_size_epoch, GenerationDomain::Size)?;
        self.validate_counter(self.next_volume_sequence, GenerationDomain::VolumeSequence)?;

        let mut native_owners = HashSet::with_capacity(self.files.len());
        for (id, record) in &self.files {
            if *id == FileId::ZERO
                || id.hi != 0
                || record.id != *id
                || record.namespace_generation == 0
                || record.security_generation == 0
                || record.size_epoch == 0
            {
                return Err(RegistryError::CorruptFileRecord);
            }
            if self.next_file_id <= id.lo {
                return Err(RegistryError::CorruptCounter(
                    GenerationDomain::FileIdentity,
                ));
            }
            if self.next_namespace_generation <= record.namespace_generation {
                return Err(RegistryError::CorruptCounter(GenerationDomain::Namespace));
            }
            if self.next_security_generation <= record.security_generation {
                return Err(RegistryError::CorruptCounter(GenerationDomain::Security));
            }
            if self.next_size_epoch <= record.size_epoch {
                return Err(RegistryError::CorruptCounter(GenerationDomain::Size));
            }

            if let Some(native) = record.native {
                if native.is_zero()
                    || !native_owners.insert(native)
                    || self.by_native.get(&native) != Some(id)
                {
                    return Err(RegistryError::CorruptNativeIndex);
                }
            }
        }

        for (native, id) in &self.by_native {
            if native.is_zero()
                || self
                    .files
                    .get(id)
                    .is_none_or(|record| record.native != Some(*native))
            {
                return Err(RegistryError::CorruptNativeIndex);
            }
        }

        let mut bindings = HashSet::with_capacity(self.links.len());
        let mut expected_by_child: HashMap<FileId, HashSet<LinkId>> = HashMap::new();
        let mut indexed_paths = HashSet::with_capacity(self.links.len());
        let mut paths_by_link = HashMap::with_capacity(self.links.len());
        for (id, record) in &self.links {
            if *id == LinkId::ZERO
                || id.hi != 0
                || record.id != *id
                || record.namespace_generation == 0
                || !self.files.contains_key(&record.parent)
                || !self.files.contains_key(&record.child)
            {
                return Err(RegistryError::CorruptLinkRecord);
            }
            if self.next_link_id <= id.lo {
                return Err(RegistryError::CorruptCounter(
                    GenerationDomain::LinkIdentity,
                ));
            }
            if self.next_namespace_generation <= record.namespace_generation {
                return Err(RegistryError::CorruptCounter(GenerationDomain::Namespace));
            }

            let binding = (record.parent, record.name.key().clone());
            if !bindings.insert(binding.clone()) || self.by_name.get(&binding) != Some(id) {
                return Err(RegistryError::CorruptNameIndex);
            }

            let path = normalized_relative_path(&record.relative_path)?;
            if !indexed_paths.insert(path.clone()) {
                return Err(RegistryError::DuplicateRelativePath);
            }
            paths_by_link.insert(*id, path);
            expected_by_child
                .entry(record.child)
                .or_default()
                .insert(*id);
        }

        for ((parent, name), id) in &self.by_name {
            let Some(record) = self.links.get(id) else {
                return Err(RegistryError::CorruptNameIndex);
            };
            if !self.files.contains_key(parent)
                || record.id != *id
                || record.parent != *parent
                || record.name.key() != name
            {
                return Err(RegistryError::CorruptNameIndex);
            }
        }

        if self.by_child != expected_by_child {
            return Err(RegistryError::CorruptChildIndex);
        }
        for (child, ids) in &self.by_child {
            if ids.is_empty()
                || !self.files.contains_key(child)
                || ids.iter().any(|id| {
                    self.links
                        .get(id)
                        .is_none_or(|record| record.child != *child)
                })
            {
                return Err(RegistryError::CorruptChildIndex);
            }
        }
        if self
            .links
            .values()
            .any(|record| !valid_relative_path(&record.relative_path, &record.name))
        {
            return Err(RegistryError::CorruptRelativePath);
        }
        if let Some(root) = self.contained_root {
            self.checked_file(root)?;
            self.validate_contained_paths(root, &paths_by_link)?;
        }
        if paths_by_link.iter().any(|(id, path)| {
            self.path_by_link.get(id) != Some(path) || self.by_path.get(path) != Some(id)
        }) {
            return Err(RegistryError::CorruptPathIndex);
        }
        if self.by_path.len() != self.links.len()
            || self.path_by_link.len() != self.links.len()
            || self.by_path.iter().any(|(path, id)| {
                self.path_by_link.get(id) != Some(path) || !self.links.contains_key(id)
            })
            || self.path_by_link.iter().any(|(id, path)| {
                self.by_path.get(path) != Some(id) || !self.links.contains_key(id)
            })
        {
            return Err(RegistryError::CorruptPathIndex);
        }

        Ok(())
    }

    fn validate_counter(
        &self,
        counter: u64,
        domain: GenerationDomain,
    ) -> Result<(), RegistryError> {
        if counter == 0 {
            Err(RegistryError::CorruptCounter(domain))
        } else {
            Ok(())
        }
    }

    pub(crate) fn install_root(
        &mut self,
        native: NativeKey,
        valid_data_length: u64,
    ) -> Result<FileId, RegistryError> {
        self.validate()?;
        if native.is_zero() {
            return Err(RegistryError::InvalidNativeKey);
        }
        if let Some(root) = self.contained_root {
            return match self.by_native.get(&native).copied() {
                Some(id) if id == root => Ok(root),
                _ => Err(RegistryError::CorruptRelativePath),
            };
        }
        if !self.links.is_empty() {
            return Err(RegistryError::CorruptRelativePath);
        }

        let root = self.observe_native(native, valid_data_length)?;
        self.contained_root = Some(root);
        Ok(root)
    }

    pub(crate) fn observe_native(
        &mut self,
        native: NativeKey,
        valid_data_length: u64,
    ) -> Result<FileId, RegistryError> {
        self.validate()?;
        if native.is_zero() {
            return Err(RegistryError::InvalidNativeKey);
        }
        if let Some(&id) = self.by_native.get(&native) {
            let record = self
                .files
                .get(&id)
                .ok_or(RegistryError::CorruptNativeIndex)?;
            if record.id != id || record.native != Some(native) {
                return Err(RegistryError::CorruptNativeIndex);
            }
            return Ok(id);
        }
        if self
            .files
            .values()
            .any(|record| record.native == Some(native))
        {
            return Err(RegistryError::CorruptNativeIndex);
        }

        self.allocate_file(Some(native), valid_data_length)
    }

    /// Observe an existing native stream and its namespace link as one
    /// all-or-nothing registry change. Initial identity generations are
    /// allocated for newly observed records; discovery allocates no backing
    /// effect volume sequence.
    pub(crate) fn observe_native_and_install_link(
        &mut self,
        root: FileId,
        native: NativeKey,
        valid_data_length: u64,
        parent: FileId,
        name: Component,
    ) -> Result<(FileId, LinkId), RegistryError> {
        self.validate()?;
        if native.is_zero() {
            return Err(RegistryError::InvalidNativeKey);
        }
        let (relative_path, relative_path_key) =
            self.checked_child_relative_path(root, parent, &name)?;

        let name_key = name.key().clone();
        if let Some(&link_id) = self.by_name.get(&(parent, name_key.clone())) {
            let link = self.checked_link(link_id)?;
            self.validate_name_index(link)?;
            let child = self.checked_file(link.child)?;
            if child.native != Some(native) {
                return Err(RegistryError::NameCollision { parent });
            }
            if self.path_by_link.get(&link_id) != Some(&relative_path_key) {
                return Err(RegistryError::CorruptRelativePath);
            }
            return Ok((child.id, link.id));
        }
        self.ensure_name_available(parent, &name_key, None)?;
        self.ensure_path_available(&relative_path_key)?;

        let existing_child = self.by_native.get(&native).copied();
        let file_id = existing_child.unwrap_or(FileId {
            lo: self.next_file_id,
            hi: 0,
        });
        if let Some(existing_child) = existing_child {
            let record = self.checked_file(existing_child)?;
            if record.native != Some(native) {
                return Err(RegistryError::CorruptNativeIndex);
            }
        } else if self.files.contains_key(&file_id) {
            return Err(RegistryError::CorruptFileRecord);
        }
        self.preflight_contained_link_insertion(file_id)?;

        let link_id = LinkId {
            lo: self.next_link_id,
            hi: 0,
        };
        if self.links.contains_key(&link_id) {
            return Err(RegistryError::CorruptLinkRecord);
        }

        let next_file_id = if existing_child.is_none() {
            Some(reserve_one(
                self.next_file_id,
                GenerationDomain::FileIdentity,
            )?)
        } else {
            None
        };
        let next_link_id = reserve_one(self.next_link_id, GenerationDomain::LinkIdentity)?;
        let namespace_count = if existing_child.is_some() { 1 } else { 2 };
        let next_namespace = reserve_many(
            self.next_namespace_generation,
            namespace_count,
            GenerationDomain::Namespace,
        )?;
        let next_security = if existing_child.is_none() {
            Some(reserve_one(
                self.next_security_generation,
                GenerationDomain::Security,
            )?)
        } else {
            None
        };
        let next_size = if existing_child.is_none() {
            Some(reserve_one(self.next_size_epoch, GenerationDomain::Size)?)
        } else {
            None
        };

        let link_generation = self
            .next_namespace_generation
            .checked_add(u64::from(existing_child.is_none()))
            .ok_or(RegistryError::CounterExhausted(GenerationDomain::Namespace))?;
        let new_file_counters = match (next_file_id, next_security, next_size) {
            (Some(file), Some(security), Some(size)) if existing_child.is_none() => {
                Some((file, security, size))
            }
            (None, None, None) if existing_child.is_some() => None,
            _ => {
                return Err(RegistryError::CorruptCounter(
                    GenerationDomain::FileIdentity,
                ))
            }
        };

        if let Some((next_file_id, next_security, next_size)) = new_file_counters {
            self.files.insert(
                file_id,
                FileRecord {
                    id: file_id,
                    native: Some(native),
                    namespace_generation: self.next_namespace_generation,
                    security_generation: self.next_security_generation,
                    size_epoch: self.next_size_epoch,
                    valid_data_length,
                },
            );
            self.by_native.insert(native, file_id);
            self.next_file_id = next_file_id;
            self.next_security_generation = next_security;
            self.next_size_epoch = next_size;
        }
        self.links.insert(
            link_id,
            LinkRecord {
                id: link_id,
                parent,
                child: file_id,
                name,
                relative_path,
                namespace_generation: link_generation,
            },
        );
        self.by_name.insert((parent, name_key), link_id);
        self.insert_link_indices(link_id, file_id, relative_path_key);
        self.next_link_id = next_link_id;
        self.next_namespace_generation = next_namespace;
        Ok((file_id, link_id))
    }

    /// Preflight one complete provider-order directory observation without
    /// publishing identities or indices.
    ///
    /// Query discovery is not a backing mutation and allocates no volume
    /// sequence. New native streams and namespace links receive checked,
    /// mount-lifetime IDs/generations in provider order. All collection
    /// capacity needed by finalization is reserved before this token returns;
    /// finalization therefore consists only of non-fallible inserts and
    /// counter assignment.
    pub(crate) fn preflight_directory_observations(
        &mut self,
        root: FileId,
        parent: FileId,
        observations: Vec<DirectoryObservation>,
    ) -> Result<DirectoryObservationReservation, RegistryError> {
        self.validate()?;
        self.checked_file(parent)?;

        let count = observations.len();
        let outgoing_capacity = self
            .links
            .len()
            .checked_add(1)
            .ok_or(RegistryError::CapacityExhausted)?;
        let mut outgoing_parents: HashSet<FileId> = HashSet::new();
        outgoing_parents
            .try_reserve(outgoing_capacity)
            .map_err(|_| RegistryError::CapacityExhausted)?;
        #[cfg(test)]
        record_directory_batch_global_link_scan();
        outgoing_parents.extend(self.links.values().map(|link| link.parent));
        let mut planned_inbound_children: HashSet<FileId> = HashSet::new();
        planned_inbound_children
            .try_reserve(count)
            .map_err(|_| RegistryError::CapacityExhausted)?;

        let mut entries = Vec::new();
        let mut new_files: Vec<(NativeKey, FileRecord)> = Vec::new();
        let mut new_links: Vec<PlannedDirectoryLink> = Vec::new();
        let mut expected_files = Vec::new();
        let mut expected_links = Vec::new();
        let mut planned_native: HashMap<NativeKey, usize> = HashMap::new();
        let mut planned_names: HashSet<NormalizedName> = HashSet::new();
        let mut planned_paths: HashSet<NormalizedPath> = HashSet::new();
        let mut expected_file_ids: HashSet<FileId> = HashSet::new();
        let mut expected_link_ids: HashSet<LinkId> = HashSet::new();
        for result in [
            entries.try_reserve(count),
            new_files.try_reserve(count),
            new_links.try_reserve(count),
            expected_files.try_reserve(count),
            expected_links.try_reserve(count),
            planned_native.try_reserve(count),
            planned_names.try_reserve(count),
            planned_paths.try_reserve(count),
            expected_file_ids.try_reserve(count),
            expected_link_ids.try_reserve(count),
        ] {
            result.map_err(|_| RegistryError::CapacityExhausted)?;
        }

        let base_counters = [
            self.next_file_id,
            self.next_link_id,
            self.next_namespace_generation,
            self.next_security_generation,
            self.next_size_epoch,
            self.next_volume_sequence,
        ];
        let mut next_file_id = self.next_file_id;
        let mut next_link_id = self.next_link_id;
        let mut next_namespace_generation = self.next_namespace_generation;
        let mut next_security_generation = self.next_security_generation;
        let mut next_size_epoch = self.next_size_epoch;

        for observation in observations {
            if observation.native.is_zero() {
                return Err(RegistryError::InvalidNativeKey);
            }
            let (relative_path, path_key) =
                self.checked_child_relative_path(root, parent, &observation.name)?;
            let name_key = observation.name.key().clone();
            if planned_names.contains(&name_key) || planned_paths.contains(&path_key) {
                return Err(RegistryError::NameCollision { parent });
            }

            if let Some(&link_id) = self.by_name.get(&(parent, name_key.clone())) {
                let link = self.checked_link(link_id)?;
                self.validate_name_index(link)?;
                let file = self.checked_file(link.child)?;
                if file.native != Some(observation.native) {
                    return Err(RegistryError::NameCollision { parent });
                }
                if self.path_by_link.get(&link_id) != Some(&path_key)
                    || link.relative_path != relative_path
                {
                    return Err(RegistryError::CorruptRelativePath);
                }
                planned_names.insert(name_key);
                planned_paths.insert(path_key);
                if expected_file_ids.insert(file.id) {
                    expected_files.push(file.clone());
                }
                if expected_link_ids.insert(link.id) {
                    expected_links.push(link.clone());
                }
                entries.push(DirectoryEntryIdentity {
                    file: file.clone(),
                    link: link.clone(),
                });
                continue;
            }

            // `validate()` proved `by_name` is the complete reverse index, so
            // the failed O(1) lookup above proves this binding is absent.
            self.ensure_path_available(&path_key)?;

            let file = if let Some(&file_id) = self.by_native.get(&observation.native) {
                let file = self.checked_file(file_id)?;
                if file.native != Some(observation.native) {
                    return Err(RegistryError::CorruptNativeIndex);
                }
                if expected_file_ids.insert(file.id) {
                    expected_files.push(file.clone());
                }
                file.clone()
            } else if let Some(&planned_index) = planned_native.get(&observation.native) {
                new_files
                    .get(planned_index)
                    .map(|(_, record)| record.clone())
                    .ok_or(RegistryError::CorruptNativeIndex)?
            } else {
                let file_id = FileId {
                    lo: next_file_id,
                    hi: 0,
                };
                if self.files.contains_key(&file_id) {
                    return Err(RegistryError::CorruptFileRecord);
                }
                let file = FileRecord {
                    id: file_id,
                    native: Some(observation.native),
                    namespace_generation: next_namespace_generation,
                    security_generation: next_security_generation,
                    size_epoch: next_size_epoch,
                    valid_data_length: observation.valid_data_length,
                };
                next_file_id = reserve_one(next_file_id, GenerationDomain::FileIdentity)?;
                next_namespace_generation =
                    reserve_one(next_namespace_generation, GenerationDomain::Namespace)?;
                next_security_generation =
                    reserve_one(next_security_generation, GenerationDomain::Security)?;
                next_size_epoch = reserve_one(next_size_epoch, GenerationDomain::Size)?;
                let planned_index = new_files.len();
                planned_native.insert(observation.native, planned_index);
                new_files.push((observation.native, file.clone()));
                file
            };
            if file.id == root {
                return Err(RegistryError::ContainedRootLink);
            }
            let child_has_inbound =
                self.by_child.contains_key(&file.id) || planned_inbound_children.contains(&file.id);
            let child_has_outgoing = outgoing_parents.contains(&file.id) || file.id == parent;
            if child_has_inbound && child_has_outgoing {
                return Err(RegistryError::AmbiguousPath(file.id));
            }

            let link_id = LinkId {
                lo: next_link_id,
                hi: 0,
            };
            if self.links.contains_key(&link_id) {
                return Err(RegistryError::CorruptLinkRecord);
            }
            let link = LinkRecord {
                id: link_id,
                parent,
                child: file.id,
                name: observation.name,
                relative_path,
                namespace_generation: next_namespace_generation,
            };
            next_link_id = reserve_one(next_link_id, GenerationDomain::LinkIdentity)?;
            next_namespace_generation =
                reserve_one(next_namespace_generation, GenerationDomain::Namespace)?;
            planned_names.insert(name_key.clone());
            let by_path_key = path_key.clone();
            let path_by_link_key = path_key.clone();
            planned_paths.insert(path_key);
            new_links.push(PlannedDirectoryLink {
                record: link.clone(),
                name_key,
                by_path_key,
                path_by_link_key,
            });
            planned_inbound_children.insert(file.id);
            outgoing_parents.insert(parent);
            entries.push(DirectoryEntryIdentity { file, link });
        }

        for result in [
            self.files.try_reserve(new_files.len()),
            self.by_native.try_reserve(new_files.len()),
            self.links.try_reserve(new_links.len()),
            self.by_name.try_reserve(new_links.len()),
            self.by_path.try_reserve(new_links.len()),
            self.path_by_link.try_reserve(new_links.len()),
        ] {
            result.map_err(|_| RegistryError::CapacityExhausted)?;
        }

        let mut grouped: Vec<(FileId, Vec<LinkId>)> = Vec::new();
        grouped
            .try_reserve(new_links.len())
            .map_err(|_| RegistryError::CapacityExhausted)?;
        let mut grouped_index: HashMap<FileId, usize> = HashMap::new();
        grouped_index
            .try_reserve(new_links.len())
            .map_err(|_| RegistryError::CapacityExhausted)?;
        for planned in &new_links {
            if let Some(&index) = grouped_index.get(&planned.record.child) {
                let links = &mut grouped[index].1;
                links
                    .try_reserve(1)
                    .map_err(|_| RegistryError::CapacityExhausted)?;
                links.push(planned.record.id);
            } else {
                let mut links = Vec::new();
                links
                    .try_reserve(1)
                    .map_err(|_| RegistryError::CapacityExhausted)?;
                links.push(planned.record.id);
                grouped_index.insert(planned.record.child, grouped.len());
                grouped.push((planned.record.child, links));
            }
        }

        let new_child_sets = grouped
            .iter()
            .filter(|(child, _)| !self.by_child.contains_key(child))
            .count();
        self.by_child
            .try_reserve(new_child_sets)
            .map_err(|_| RegistryError::CapacityExhausted)?;
        let mut child_links = Vec::new();
        child_links
            .try_reserve(grouped.len())
            .map_err(|_| RegistryError::CapacityExhausted)?;
        for (child, links) in grouped {
            let existing_len = self.by_child.get(&child).map_or(0, HashSet::len);
            let mut expected = Vec::new();
            expected
                .try_reserve(existing_len)
                .map_err(|_| RegistryError::CapacityExhausted)?;
            let mut replacement = HashSet::new();
            replacement
                .try_reserve(existing_len + links.len())
                .map_err(|_| RegistryError::CapacityExhausted)?;
            if let Some(existing) = self.by_child.get(&child) {
                expected.extend(existing.iter().copied());
                replacement.extend(existing.iter().copied());
            }
            replacement.extend(links);
            child_links.push(ChildLinkPlan {
                child,
                expected,
                replacement,
            });
        }

        Ok(DirectoryObservationReservation {
            entries,
            expected_files,
            expected_links,
            new_files,
            new_links,
            child_links,
            base_counters,
            next_file_id,
            next_link_id,
            next_namespace_generation,
            next_security_generation,
            next_size_epoch,
        })
    }

    pub(crate) fn finalize_directory_observations(
        &mut self,
        reservation: DirectoryObservationReservation,
    ) -> Result<Vec<DirectoryEntryIdentity>, RegistryError> {
        self.validate()?;
        let current_counters = [
            self.next_file_id,
            self.next_link_id,
            self.next_namespace_generation,
            self.next_security_generation,
            self.next_size_epoch,
            self.next_volume_sequence,
        ];
        let domains = [
            GenerationDomain::FileIdentity,
            GenerationDomain::LinkIdentity,
            GenerationDomain::Namespace,
            GenerationDomain::Security,
            GenerationDomain::Size,
            GenerationDomain::VolumeSequence,
        ];
        for index in 0..current_counters.len() {
            if current_counters[index] != reservation.base_counters[index] {
                return Err(RegistryError::CorruptCounter(domains[index]));
            }
        }
        if reservation
            .expected_files
            .iter()
            .any(|record| self.files.get(&record.id) != Some(record))
        {
            return Err(RegistryError::CorruptFileRecord);
        }
        if reservation.expected_links.iter().any(|record| {
            self.links.get(&record.id).is_none_or(|current| {
                current.id != record.id
                    || current.parent != record.parent
                    || current.child != record.child
                    || current.name.key() != record.name.key()
                    || current.name.as_os_str() != record.name.as_os_str()
                    || current.relative_path != record.relative_path
                    || current.namespace_generation != record.namespace_generation
            })
        }) {
            return Err(RegistryError::CorruptLinkRecord);
        }
        for (native, record) in &reservation.new_files {
            if self.files.contains_key(&record.id) {
                return Err(RegistryError::CorruptFileRecord);
            }
            if let Some(existing) = self.by_native.get(native) {
                return Err(RegistryError::NativeCollision {
                    native: *native,
                    existing: *existing,
                    requested: record.id,
                });
            }
        }
        for planned in &reservation.new_links {
            if self.links.contains_key(&planned.record.id) {
                return Err(RegistryError::CorruptLinkRecord);
            }
            if self
                .by_name
                .contains_key(&(planned.record.parent, planned.name_key.clone()))
            {
                return Err(RegistryError::NameCollision {
                    parent: planned.record.parent,
                });
            }
            if self.by_path.contains_key(&planned.by_path_key)
                || self.path_by_link.contains_key(&planned.record.id)
            {
                return Err(RegistryError::DuplicateRelativePath);
            }
        }
        for plan in &reservation.child_links {
            match self.by_child.get(&plan.child) {
                Some(existing)
                    if existing.len() == plan.expected.len()
                        && plan.expected.iter().all(|id| existing.contains(id)) => {}
                None if plan.expected.is_empty() => {}
                _ => return Err(RegistryError::CorruptChildIndex),
            }
        }

        // Allocation-free publication starts here. Preflight reserved every
        // destination collection, and each namespace path has two owned keys
        // so both reverse indices can consume one without cloning.
        for (native, record) in reservation.new_files {
            let id = record.id;
            self.files.insert(id, record);
            self.by_native.insert(native, id);
        }
        for planned in reservation.new_links {
            let id = planned.record.id;
            let parent = planned.record.parent;
            self.links.insert(id, planned.record);
            self.by_name.insert((parent, planned.name_key), id);
            self.by_path.insert(planned.by_path_key, id);
            self.path_by_link.insert(id, planned.path_by_link_key);
        }
        for plan in reservation.child_links {
            self.by_child.insert(plan.child, plan.replacement);
        }
        self.next_file_id = reservation.next_file_id;
        self.next_link_id = reservation.next_link_id;
        self.next_namespace_generation = reservation.next_namespace_generation;
        self.next_security_generation = reservation.next_security_generation;
        self.next_size_epoch = reservation.next_size_epoch;
        Ok(reservation.entries)
    }

    pub(crate) fn child_relative_path(
        &self,
        root: FileId,
        parent: FileId,
        name: &Component,
    ) -> Result<PathBuf, RegistryError> {
        self.validate()?;
        self.checked_child_relative_path(root, parent, name)
            .map(|(path, _)| path)
    }

    pub(crate) fn file_relative_path(
        &self,
        root: FileId,
        file: FileId,
    ) -> Result<PathBuf, RegistryError> {
        self.validate()?;
        self.indexed_file_path(root, file).map(|(path, _)| path)
    }

    fn checked_child_relative_path(
        &self,
        root: FileId,
        parent: FileId,
        name: &Component,
    ) -> Result<(PathBuf, NormalizedPath), RegistryError> {
        if self.contained_root != Some(root) {
            return Err(RegistryError::MissingPath(root));
        }
        let (parent_path, mut parent_key) = self.indexed_file_path(root, parent)?;
        parent_key.push(name.key().clone());
        Ok((parent_path.join(name.as_os_str()), parent_key))
    }

    fn validate_contained_paths(
        &self,
        root: FileId,
        paths_by_link: &HashMap<LinkId, NormalizedPath>,
    ) -> Result<(), RegistryError> {
        if self.by_child.contains_key(&root) {
            return Err(RegistryError::CorruptRelativePath);
        }

        for record in self.links.values() {
            let (parent_path, mut parent_key) =
                self.validated_file_path(root, record.parent, paths_by_link)?;
            let expected = parent_path.join(record.name.as_os_str());
            if record.relative_path != expected {
                return Err(RegistryError::CorruptRelativePath);
            }
            parent_key.push(record.name.key().clone());
            if paths_by_link.get(&record.id) != Some(&parent_key) {
                return Err(RegistryError::CorruptRelativePath);
            }
        }
        Ok(())
    }

    fn validated_file_path(
        &self,
        root: FileId,
        id: FileId,
        paths_by_link: &HashMap<LinkId, NormalizedPath>,
    ) -> Result<(PathBuf, NormalizedPath), RegistryError> {
        self.checked_file(id)?;
        if id == root {
            return Ok((PathBuf::new(), Vec::new()));
        }
        let inbound = self
            .by_child
            .get(&id)
            .ok_or(RegistryError::MissingPath(id))?;
        if inbound.len() != 1 {
            return Err(RegistryError::AmbiguousPath(id));
        }
        let link_id = *inbound
            .iter()
            .next()
            .ok_or(RegistryError::MissingPath(id))?;
        let link = self.checked_link(link_id)?;
        let path = paths_by_link
            .get(&link_id)
            .ok_or(RegistryError::CorruptPathIndex)?;
        Ok((link.relative_path.clone(), path.clone()))
    }

    fn indexed_file_path(
        &self,
        root: FileId,
        id: FileId,
    ) -> Result<(PathBuf, NormalizedPath), RegistryError> {
        self.checked_file(id)?;
        if id == root {
            return Ok((PathBuf::new(), Vec::new()));
        }
        let inbound = self
            .by_child
            .get(&id)
            .ok_or(RegistryError::MissingPath(id))?;
        if inbound.len() != 1 {
            return Err(RegistryError::AmbiguousPath(id));
        }
        let link_id = *inbound
            .iter()
            .next()
            .ok_or(RegistryError::MissingPath(id))?;
        let link = self.checked_link(link_id)?;
        let path = self
            .path_by_link
            .get(&link_id)
            .ok_or(RegistryError::CorruptPathIndex)?;
        Ok((link.relative_path.clone(), path.clone()))
    }

    pub(crate) fn allocate_prospective(
        &mut self,
        valid_data_length: u64,
    ) -> Result<FileId, RegistryError> {
        self.validate()?;
        self.allocate_file(None, valid_data_length)
    }

    fn allocate_file(
        &mut self,
        native: Option<NativeKey>,
        valid_data_length: u64,
    ) -> Result<FileId, RegistryError> {
        let id = FileId {
            lo: self.next_file_id,
            hi: 0,
        };
        if self.files.contains_key(&id) {
            return Err(RegistryError::CorruptFileRecord);
        }
        if let Some(key) = native {
            if self.by_native.contains_key(&key)
                || self.files.values().any(|record| record.native == Some(key))
            {
                return Err(RegistryError::CorruptNativeIndex);
            }
        }

        let next_file_id = reserve_one(self.next_file_id, GenerationDomain::FileIdentity)?;
        let next_namespace =
            reserve_one(self.next_namespace_generation, GenerationDomain::Namespace)?;
        let next_security = reserve_one(self.next_security_generation, GenerationDomain::Security)?;
        let next_size = reserve_one(self.next_size_epoch, GenerationDomain::Size)?;

        let record = FileRecord {
            id,
            native,
            namespace_generation: self.next_namespace_generation,
            security_generation: self.next_security_generation,
            size_epoch: self.next_size_epoch,
            valid_data_length,
        };
        self.files.insert(id, record);
        if let Some(key) = native {
            self.by_native.insert(key, id);
        }
        self.next_file_id = next_file_id;
        self.next_namespace_generation = next_namespace;
        self.next_security_generation = next_security;
        self.next_size_epoch = next_size;
        Ok(id)
    }

    pub(crate) fn bind_native(
        &mut self,
        id: FileId,
        native: NativeKey,
    ) -> Result<(), RegistryError> {
        self.validate()?;
        if native.is_zero() {
            return Err(RegistryError::InvalidNativeKey);
        }
        let current = self.checked_file(id)?.native;
        if let Some(current) = current {
            if current != native {
                return Err(RegistryError::FileNativeConflict { file: id });
            }
            return match self.by_native.get(&native) {
                Some(indexed) if *indexed == id => Ok(()),
                _ => Err(RegistryError::CorruptNativeIndex),
            };
        }

        if let Some(&existing) = self.by_native.get(&native) {
            let existing_record = self
                .files
                .get(&existing)
                .ok_or(RegistryError::CorruptNativeIndex)?;
            if existing_record.id != existing || existing_record.native != Some(native) {
                return Err(RegistryError::CorruptNativeIndex);
            }
            return Err(RegistryError::NativeCollision {
                native,
                existing,
                requested: id,
            });
        }
        if self
            .files
            .values()
            .any(|record| record.native == Some(native))
        {
            return Err(RegistryError::CorruptNativeIndex);
        }

        let mut updated = self.checked_file(id)?.clone();
        updated.native = Some(native);
        self.files.insert(id, updated);
        self.by_native.insert(native, id);
        Ok(())
    }

    pub(crate) fn file_id_for_native(&self, native: NativeKey) -> Result<FileId, RegistryError> {
        self.validate()?;
        if native.is_zero() {
            return Err(RegistryError::InvalidNativeKey);
        }
        let Some(&id) = self.by_native.get(&native) else {
            return if self
                .files
                .values()
                .any(|record| record.native == Some(native))
            {
                Err(RegistryError::CorruptNativeIndex)
            } else {
                Err(RegistryError::MissingNative)
            };
        };
        let record = self
            .files
            .get(&id)
            .ok_or(RegistryError::CorruptNativeIndex)?;
        if record.id != id || record.native != Some(native) {
            return Err(RegistryError::CorruptNativeIndex);
        }
        Ok(id)
    }

    pub(crate) fn file(&self, id: FileId) -> Result<&FileRecord, RegistryError> {
        self.validate()?;
        self.checked_file(id)
    }

    fn checked_file(&self, id: FileId) -> Result<&FileRecord, RegistryError> {
        let record = self.files.get(&id).ok_or(RegistryError::MissingFile(id))?;
        if record.id != id {
            return Err(RegistryError::CorruptFileRecord);
        }
        Ok(record)
    }

    pub(crate) fn install_link(
        &mut self,
        parent: FileId,
        child: FileId,
        name: Component,
        relative_path: PathBuf,
    ) -> Result<LinkId, RegistryError> {
        self.validate()?;
        self.checked_file(parent)?;
        self.checked_file(child)?;
        self.preflight_contained_link_insertion(child)?;

        let key = name.key().clone();
        self.ensure_name_available(parent, &key, None)?;
        let path = self.prepare_link_path(parent, &name, &relative_path)?;
        self.ensure_path_available(&path)?;
        let id = LinkId {
            lo: self.next_link_id,
            hi: 0,
        };
        if self.links.contains_key(&id) {
            return Err(RegistryError::CorruptLinkRecord);
        }
        let next_link_id = reserve_one(self.next_link_id, GenerationDomain::LinkIdentity)?;
        let next_namespace =
            reserve_one(self.next_namespace_generation, GenerationDomain::Namespace)?;

        let record = LinkRecord {
            id,
            parent,
            child,
            name,
            relative_path,
            namespace_generation: self.next_namespace_generation,
        };
        self.links.insert(id, record);
        self.by_name.insert((parent, key), id);
        self.insert_link_indices(id, child, path);
        self.next_link_id = next_link_id;
        self.next_namespace_generation = next_namespace;
        Ok(id)
    }

    pub(crate) fn create_link(
        &mut self,
        parent: FileId,
        child: FileId,
        name: Component,
        relative_path: PathBuf,
    ) -> Result<RegistryEffect<LinkId>, RegistryError> {
        self.validate()?;
        self.checked_file(parent)?;
        self.checked_file(child)?;
        self.preflight_contained_link_insertion(child)?;

        let key = name.key().clone();
        self.ensure_name_available(parent, &key, None)?;
        let path = self.prepare_link_path(parent, &name, &relative_path)?;
        self.ensure_path_available(&path)?;
        let id = LinkId {
            lo: self.next_link_id,
            hi: 0,
        };
        if self.links.contains_key(&id) {
            return Err(RegistryError::CorruptLinkRecord);
        }

        let touched = unique_file_ids([child, parent, parent]);
        let generation_count = u64::try_from(1 + touched.len())
            .map_err(|_| RegistryError::CounterExhausted(GenerationDomain::Namespace))?;
        let next_link_id = reserve_one(self.next_link_id, GenerationDomain::LinkIdentity)?;
        let next_namespace = reserve_many(
            self.next_namespace_generation,
            generation_count,
            GenerationDomain::Namespace,
        )?;
        let next_volume = reserve_one(self.next_volume_sequence, GenerationDomain::VolumeSequence)?;

        let link_generation = self.next_namespace_generation;
        let file_updates = self.prepare_namespace_updates(&touched, link_generation + 1)?;
        for (file_id, record) in file_updates {
            self.files.insert(file_id, record);
        }
        self.links.insert(
            id,
            LinkRecord {
                id,
                parent,
                child,
                name,
                relative_path,
                namespace_generation: link_generation,
            },
        );
        self.by_name.insert((parent, key), id);
        self.insert_link_indices(id, child, path);
        self.next_link_id = next_link_id;
        self.next_namespace_generation = next_namespace;
        let volume_sequence = self.next_volume_sequence;
        self.next_volume_sequence = next_volume;
        Ok(RegistryEffect {
            value: id,
            volume_sequence,
        })
    }

    pub(crate) fn bind_native_and_create_link(
        &mut self,
        parent: FileId,
        child: FileId,
        native: NativeKey,
        name: Component,
        relative_path: PathBuf,
    ) -> Result<RegistryEffect<LinkId>, RegistryError> {
        let parent_generation = self.file(parent)?.namespace_generation;
        let child_record = self.file(child)?.clone();
        let reservation = self.preflight_create_open(
            parent,
            parent_generation,
            child,
            child_record.namespace_generation,
            child_record.security_generation,
            &name,
            &relative_path,
        )?;
        self.finalize_create_open(reservation, native)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preflight_create_open(
        &mut self,
        parent: FileId,
        expected_parent_namespace_generation: u64,
        child: FileId,
        expected_child_namespace_generation: u64,
        expected_child_security_generation: u64,
        name: &Component,
        relative_path: &Path,
    ) -> Result<CreateOpenReservation, RegistryError> {
        let reservation = self.prepare_create_open(
            parent,
            expected_parent_namespace_generation,
            child,
            expected_child_namespace_generation,
            expected_child_security_generation,
            name.clone(),
            relative_path.to_path_buf(),
        )?;
        self.reserve_create_open_capacity()?;
        Ok(reservation)
    }

    pub(crate) fn finalize_create_open(
        &mut self,
        mut reservation: CreateOpenReservation,
        native: NativeKey,
    ) -> Result<RegistryEffect<LinkId>, RegistryError> {
        if native.is_zero() {
            return Err(RegistryError::InvalidNativeKey);
        }
        if let Some(&existing) = self.by_native.get(&native) {
            return Err(RegistryError::NativeCollision {
                native,
                existing,
                requested: reservation.child,
            });
        }
        if self
            .files
            .values()
            .any(|record| record.native == Some(native))
        {
            return Err(RegistryError::CorruptNativeIndex);
        }
        for (file_id, record) in &mut reservation.file_updates {
            if *file_id == reservation.child {
                record.native = Some(native);
            }
        }
        for (file_id, record) in reservation.file_updates {
            self.files.insert(file_id, record);
        }
        self.by_native.insert(native, reservation.child);
        self.links
            .insert(reservation.link_id, reservation.link_record);
        self.by_name.insert(
            (reservation.parent, reservation.name_key),
            reservation.link_id,
        );
        self.by_child
            .insert(reservation.child, reservation.child_links);
        self.by_path
            .insert(reservation.by_path_key, reservation.link_id);
        self.path_by_link
            .insert(reservation.link_id, reservation.path_by_link_key);
        self.next_link_id = reservation.next_link_id;
        self.next_namespace_generation = reservation.next_namespace_generation;
        self.next_volume_sequence = reservation.next_volume_sequence;
        Ok(RegistryEffect {
            value: reservation.link_id,
            volume_sequence: reservation.volume_sequence,
        })
    }

    fn reserve_create_open_capacity(&mut self) -> Result<(), RegistryError> {
        for result in [
            self.by_native.try_reserve(1),
            self.links.try_reserve(1),
            self.by_name.try_reserve(1),
            self.by_child.try_reserve(1),
            self.by_path.try_reserve(1),
            self.path_by_link.try_reserve(1),
        ] {
            result.map_err(|_| RegistryError::CapacityExhausted)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_create_open(
        &self,
        parent: FileId,
        expected_parent_namespace_generation: u64,
        child: FileId,
        expected_child_namespace_generation: u64,
        expected_child_security_generation: u64,
        name: Component,
        relative_path: PathBuf,
    ) -> Result<CreateOpenReservation, RegistryError> {
        self.validate()?;
        let parent_record = self.checked_file(parent)?;
        expect_generation(
            GenerationDomain::Namespace,
            expected_parent_namespace_generation,
            parent_record.namespace_generation,
        )?;
        let child_record = self.checked_file(child)?;
        expect_generation(
            GenerationDomain::Namespace,
            expected_child_namespace_generation,
            child_record.namespace_generation,
        )?;
        expect_generation(
            GenerationDomain::Security,
            expected_child_security_generation,
            child_record.security_generation,
        )?;
        if child_record.native.is_some() {
            return Err(RegistryError::FileNativeConflict { file: child });
        }
        self.preflight_contained_link_insertion(child)?;

        let name_key = name.key().clone();
        self.ensure_name_available(parent, &name_key, None)?;
        let by_path_key = self.prepare_link_path(parent, &name, &relative_path)?;
        self.ensure_path_available(&by_path_key)?;
        let path_by_link_key = by_path_key.clone();
        let link_id = LinkId {
            lo: self.next_link_id,
            hi: 0,
        };
        if self.links.contains_key(&link_id) {
            return Err(RegistryError::CorruptLinkRecord);
        }
        let touched = unique_file_ids([child, parent, parent]);
        let generation_count = u64::try_from(1 + touched.len())
            .map_err(|_| RegistryError::CounterExhausted(GenerationDomain::Namespace))?;
        let next_link_id = reserve_one(self.next_link_id, GenerationDomain::LinkIdentity)?;
        let next_namespace_generation = reserve_many(
            self.next_namespace_generation,
            generation_count,
            GenerationDomain::Namespace,
        )?;
        let next_volume_sequence =
            reserve_one(self.next_volume_sequence, GenerationDomain::VolumeSequence)?;

        let link_generation = self.next_namespace_generation;
        let file_updates = self.prepare_namespace_updates(&touched, link_generation + 1)?;
        let mut child_links = self.by_child.get(&child).cloned().unwrap_or_default();
        child_links
            .try_reserve(1)
            .map_err(|_| RegistryError::CapacityExhausted)?;
        child_links.insert(link_id);
        let link_record = LinkRecord {
            id: link_id,
            parent,
            child,
            name,
            relative_path,
            namespace_generation: link_generation,
        };
        Ok(CreateOpenReservation {
            parent,
            child,
            link_id,
            name_key,
            by_path_key,
            path_by_link_key,
            child_links,
            link_record,
            file_updates,
            next_link_id,
            next_namespace_generation,
            volume_sequence: self.next_volume_sequence,
            next_volume_sequence,
        })
    }

    pub(crate) fn link(&self, id: LinkId) -> Result<&LinkRecord, RegistryError> {
        self.validate()?;
        let record = self.checked_link(id)?;
        self.validate_name_index(record)?;
        Ok(record)
    }

    pub(crate) fn link_by_name(
        &self,
        parent: FileId,
        name: &NormalizedName,
    ) -> Result<&LinkRecord, RegistryError> {
        self.validate()?;
        self.checked_file(parent)?;
        let id = *self
            .by_name
            .get(&(parent, name.clone()))
            .ok_or(RegistryError::MissingName)?;
        let record = self.links.get(&id).ok_or(RegistryError::CorruptNameIndex)?;
        if record.id != id || record.parent != parent || record.name.key() != name {
            return Err(RegistryError::CorruptNameIndex);
        }
        Ok(record)
    }

    pub(crate) fn rename_link(
        &mut self,
        id: LinkId,
        new_parent: FileId,
        new_name: Component,
        relative_path: PathBuf,
    ) -> Result<RegistryEffect<LinkId>, RegistryError> {
        self.validate()?;
        let record = self.checked_link(id)?;
        self.validate_name_index(record)?;
        let old_parent = record.parent;
        let child = record.child;
        let old_key = record.name.key().clone();
        let old_relative_path = record.relative_path.clone();
        let old_path = self
            .path_by_link
            .get(&id)
            .ok_or(RegistryError::CorruptPathIndex)?
            .clone();
        self.checked_file(old_parent)?;
        self.checked_file(new_parent)?;
        self.checked_file(child)?;
        let new_key = new_name.key().clone();
        self.ensure_name_available(new_parent, &new_key, Some(id))?;
        let new_path = self.prepare_link_path(new_parent, &new_name, &relative_path)?;

        if new_path.len() > old_path.len() && new_path.starts_with(&old_path) {
            return Err(RegistryError::CorruptRelativePath);
        }
        let affected: HashSet<LinkId> = if self.contained_root.is_some() {
            self.path_by_link
                .iter()
                .filter_map(|(link_id, path)| path.starts_with(&old_path).then_some(*link_id))
                .collect()
        } else {
            HashSet::from([id])
        };
        let mut replacement_paths = HashSet::with_capacity(affected.len());
        let mut path_updates = Vec::with_capacity(affected.len());
        for affected_id in &affected {
            let affected_record = self.checked_link(*affected_id)?;
            let affected_path = self
                .path_by_link
                .get(affected_id)
                .ok_or(RegistryError::CorruptPathIndex)?;
            let suffix = affected_path
                .strip_prefix(old_path.as_slice())
                .ok_or(RegistryError::CorruptPathIndex)?;
            let mut replacement_path = new_path.clone();
            replacement_path.extend_from_slice(suffix);
            if !replacement_paths.insert(replacement_path.clone()) {
                return Err(RegistryError::DuplicateRelativePath);
            }
            if let Some(existing) = self.by_path.get(&replacement_path) {
                if !affected.contains(existing) {
                    return Err(RegistryError::DuplicateRelativePath);
                }
            }

            let replacement_relative_path = if *affected_id == id {
                relative_path.clone()
            } else {
                let suffix = affected_record
                    .relative_path
                    .strip_prefix(&old_relative_path)
                    .map_err(|_| RegistryError::CorruptRelativePath)?;
                relative_path.join(suffix)
            };
            let mut replacement_record = affected_record.clone();
            replacement_record.relative_path = replacement_relative_path;
            if *affected_id == id {
                replacement_record.parent = new_parent;
                replacement_record.name = new_name.clone();
                replacement_record.namespace_generation = self.next_namespace_generation;
            }
            path_updates.push((
                *affected_id,
                affected_path.clone(),
                replacement_path,
                replacement_record,
            ));
        }

        let touched = unique_file_ids([child, old_parent, new_parent]);
        let generation_count = u64::try_from(1 + touched.len())
            .map_err(|_| RegistryError::CounterExhausted(GenerationDomain::Namespace))?;
        let next_namespace = reserve_many(
            self.next_namespace_generation,
            generation_count,
            GenerationDomain::Namespace,
        )?;
        let next_volume = reserve_one(self.next_volume_sequence, GenerationDomain::VolumeSequence)?;

        let link_generation = self.next_namespace_generation;
        let file_updates = self.prepare_namespace_updates(&touched, link_generation + 1)?;
        for (file_id, record) in file_updates {
            self.files.insert(file_id, record);
        }

        if old_parent != new_parent || old_key != new_key {
            self.by_name.remove(&(old_parent, old_key));
            self.by_name.insert((new_parent, new_key), id);
        }
        for (_, old_path, _, _) in &path_updates {
            self.by_path.remove(old_path);
        }
        for (affected_id, _, replacement_path, replacement_record) in path_updates {
            self.links.insert(affected_id, replacement_record);
            self.by_path.insert(replacement_path.clone(), affected_id);
            self.path_by_link.insert(affected_id, replacement_path);
        }
        self.next_namespace_generation = next_namespace;
        let volume_sequence = self.next_volume_sequence;
        self.next_volume_sequence = next_volume;
        Ok(RegistryEffect {
            value: id,
            volume_sequence,
        })
    }

    pub(crate) fn unlink_link(
        &mut self,
        id: LinkId,
    ) -> Result<RegistryEffect<LinkId>, RegistryError> {
        self.validate()?;
        let record = self.checked_link(id)?;
        self.validate_name_index(record)?;
        let parent = record.parent;
        let child = record.child;
        let key = record.name.key().clone();
        let path = self
            .path_by_link
            .get(&id)
            .ok_or(RegistryError::CorruptPathIndex)?
            .clone();
        self.checked_file(parent)?;
        self.checked_file(child)?;
        if self.contained_root.is_some()
            && self
                .by_child
                .get(&child)
                .is_some_and(|links| links.len() == 1)
            && self.links.values().any(|link| link.parent == child)
        {
            return Err(RegistryError::CorruptRelativePath);
        }

        let touched = unique_file_ids([child, parent, parent]);
        let generation_count = u64::try_from(touched.len())
            .map_err(|_| RegistryError::CounterExhausted(GenerationDomain::Namespace))?;
        let next_namespace = reserve_many(
            self.next_namespace_generation,
            generation_count,
            GenerationDomain::Namespace,
        )?;
        let next_volume = reserve_one(self.next_volume_sequence, GenerationDomain::VolumeSequence)?;

        let file_updates =
            self.prepare_namespace_updates(&touched, self.next_namespace_generation)?;
        for (file_id, record) in file_updates {
            self.files.insert(file_id, record);
        }
        self.by_name.remove(&(parent, key));
        self.remove_link_indices(id, child, &path);
        self.links.remove(&id);
        self.next_namespace_generation = next_namespace;
        let volume_sequence = self.next_volume_sequence;
        self.next_volume_sequence = next_volume;
        Ok(RegistryEffect {
            value: id,
            volume_sequence,
        })
    }

    /// Normalize a fully staged namespace mutation to one logical generation
    /// allocation set and exactly one volume sequence.
    ///
    /// The staged clone may have used the ordinary rename/link/unlink helpers
    /// to build all map/path changes. Replacement composes two such helpers,
    /// so this pre-effect pass rewrites only the affected scalar lanes to the
    /// single-operation allocation plan derived from `baseline`.
    pub(crate) fn normalize_namespace_stage(
        &mut self,
        baseline: &Self,
        stamped_link: Option<LinkId>,
        touched: &[FileId],
    ) -> Result<RegistryEffect<()>, RegistryError> {
        baseline.validate()?;
        self.validate()?;
        let mut unique = Vec::with_capacity(touched.len());
        for id in touched {
            baseline.checked_file(*id)?;
            self.checked_file(*id)?;
            if !unique.contains(id) {
                unique.push(*id);
            }
        }
        let link_slots = u64::from(stamped_link.is_some());
        let file_slots = u64::try_from(unique.len())
            .map_err(|_| RegistryError::CounterExhausted(GenerationDomain::Namespace))?;
        let next_namespace_generation = reserve_many(
            baseline.next_namespace_generation,
            link_slots
                .checked_add(file_slots)
                .ok_or(RegistryError::CounterExhausted(GenerationDomain::Namespace))?,
            GenerationDomain::Namespace,
        )?;
        let next_volume_sequence = reserve_one(
            baseline.next_volume_sequence,
            GenerationDomain::VolumeSequence,
        )?;
        let mut file_updates = Vec::with_capacity(unique.len());
        for (offset, id) in unique.into_iter().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| RegistryError::CounterExhausted(GenerationDomain::Namespace))?;
            let generation = baseline
                .next_namespace_generation
                .checked_add(link_slots)
                .and_then(|value| value.checked_add(offset))
                .ok_or(RegistryError::CounterExhausted(GenerationDomain::Namespace))?;
            let mut record = self.checked_file(id)?.clone();
            record.namespace_generation = generation;
            file_updates.push((id, record));
        }
        if let Some(link_id) = stamped_link {
            let mut record = self.checked_link(link_id)?.clone();
            record.namespace_generation = baseline.next_namespace_generation;
            self.links.insert(link_id, record);
        }
        for (id, record) in file_updates {
            self.files.insert(id, record);
        }
        self.next_namespace_generation = next_namespace_generation;
        self.next_volume_sequence = next_volume_sequence;
        self.validate()?;
        Ok(RegistryEffect {
            value: (),
            volume_sequence: baseline.next_volume_sequence,
        })
    }

    pub(crate) fn advance_namespace(
        &mut self,
        id: FileId,
    ) -> Result<RegistryEffect<u64>, RegistryError> {
        self.validate()?;
        self.checked_file(id)?;
        let next_generation =
            reserve_one(self.next_namespace_generation, GenerationDomain::Namespace)?;
        let next_volume = reserve_one(self.next_volume_sequence, GenerationDomain::VolumeSequence)?;

        let value = self.next_namespace_generation;
        self.files
            .get_mut(&id)
            .ok_or(RegistryError::CorruptFileRecord)?
            .namespace_generation = value;
        self.next_namespace_generation = next_generation;
        let volume_sequence = self.next_volume_sequence;
        self.next_volume_sequence = next_volume;
        Ok(RegistryEffect {
            value,
            volume_sequence,
        })
    }

    pub(crate) fn preflight_metadata_commit(
        &mut self,
        id: FileId,
        expected_namespace_generation: u64,
    ) -> Result<MetadataCommit<'_>, RegistryError> {
        self.validate()?;
        let file = self.checked_file(id)?;
        expect_generation(
            GenerationDomain::Namespace,
            expected_namespace_generation,
            file.namespace_generation,
        )?;
        if file.native.is_none() {
            return Err(RegistryError::MissingNative);
        }
        let namespace_generation = self.next_namespace_generation;
        let following_namespace_generation =
            reserve_one(namespace_generation, GenerationDomain::Namespace)?;
        let volume_sequence = self.next_volume_sequence;
        let following_volume_sequence =
            reserve_one(volume_sequence, GenerationDomain::VolumeSequence)?;
        let file = self
            .files
            .get_mut(&id)
            .ok_or(RegistryError::CorruptFileRecord)?;
        Ok(MetadataCommit {
            file,
            next_namespace_generation: &mut self.next_namespace_generation,
            next_volume_sequence: &mut self.next_volume_sequence,
            namespace_generation,
            following_namespace_generation,
            volume_sequence,
            following_volume_sequence,
        })
    }

    pub(crate) fn advance_security(
        &mut self,
        id: FileId,
    ) -> Result<RegistryEffect<u64>, RegistryError> {
        let expected = self.file(id)?.security_generation;
        self.preflight_security(id, expected)
            .and_then(|reservation| self.finalize_security(reservation))
            .map(|finalized| finalized.effect)
    }

    pub(crate) fn preflight_security(
        &self,
        id: FileId,
        expected_security_generation: u64,
    ) -> Result<SecurityReservation, RegistryError> {
        self.validate()?;
        let file = self.checked_file(id)?;
        expect_generation(
            GenerationDomain::Security,
            expected_security_generation,
            file.security_generation,
        )?;
        if file.native.is_none() {
            return Err(RegistryError::MissingNative);
        }
        let next_security_generation =
            reserve_one(self.next_security_generation, GenerationDomain::Security)?;
        let next_volume_sequence =
            reserve_one(self.next_volume_sequence, GenerationDomain::VolumeSequence)?;
        Ok(SecurityReservation {
            file: file.clone(),
            security_generation: self.next_security_generation,
            next_security_generation,
            volume_sequence: self.next_volume_sequence,
            next_volume_sequence,
        })
    }

    pub(crate) fn preflight_security_commit(
        &mut self,
        id: FileId,
        expected_security_generation: u64,
    ) -> Result<SecurityCommit<'_>, RegistryError> {
        self.validate()?;
        let file = self.checked_file(id)?;
        expect_generation(
            GenerationDomain::Security,
            expected_security_generation,
            file.security_generation,
        )?;
        if file.native.is_none() {
            return Err(RegistryError::MissingNative);
        }
        let security_generation = self.next_security_generation;
        let following_security_generation =
            reserve_one(security_generation, GenerationDomain::Security)?;
        let volume_sequence = self.next_volume_sequence;
        let following_volume_sequence =
            reserve_one(volume_sequence, GenerationDomain::VolumeSequence)?;
        let file = self
            .files
            .get_mut(&id)
            .ok_or(RegistryError::CorruptFileRecord)?;
        Ok(SecurityCommit {
            file,
            next_security_generation: &mut self.next_security_generation,
            next_volume_sequence: &mut self.next_volume_sequence,
            security_generation,
            following_security_generation,
            volume_sequence,
            following_volume_sequence,
        })
    }

    pub(crate) fn finalize_security(
        &mut self,
        reservation: SecurityReservation,
    ) -> Result<SecurityFinalization, RegistryError> {
        let installed = self
            .files
            .get(&reservation.file.id)
            .ok_or(RegistryError::CorruptFileRecord)?;
        if installed.security_generation != reservation.file.security_generation {
            return Err(RegistryError::StaleGeneration {
                domain: GenerationDomain::Security,
                expected: reservation.file.security_generation,
                actual: installed.security_generation,
            });
        }
        if installed != &reservation.file || installed.native.is_none() {
            return Err(RegistryError::CorruptFileRecord);
        }
        if self.next_security_generation != reservation.security_generation
            || reservation.security_generation.checked_add(1)
                != Some(reservation.next_security_generation)
        {
            return Err(RegistryError::CorruptCounter(GenerationDomain::Security));
        }
        if self.next_volume_sequence != reservation.volume_sequence
            || reservation.volume_sequence.checked_add(1) != Some(reservation.next_volume_sequence)
        {
            return Err(RegistryError::CorruptCounter(
                GenerationDomain::VolumeSequence,
            ));
        }

        let mut file = reservation.file;
        file.security_generation = reservation.security_generation;
        let installed = self
            .files
            .get_mut(&file.id)
            .ok_or(RegistryError::CorruptFileRecord)?;
        *installed = file.clone();
        self.next_security_generation = reservation.next_security_generation;
        self.next_volume_sequence = reservation.next_volume_sequence;
        Ok(SecurityFinalization {
            effect: RegistryEffect {
                value: file.security_generation,
                volume_sequence: reservation.volume_sequence,
            },
            file,
        })
    }

    pub(crate) fn advance_size(
        &mut self,
        id: FileId,
        valid_data_length: u64,
    ) -> Result<RegistryEffect<u64>, RegistryError> {
        self.validate()?;
        self.checked_file(id)?;
        let next_epoch = reserve_one(self.next_size_epoch, GenerationDomain::Size)?;
        let next_volume = reserve_one(self.next_volume_sequence, GenerationDomain::VolumeSequence)?;

        let value = self.next_size_epoch;
        let record = self
            .files
            .get_mut(&id)
            .ok_or(RegistryError::CorruptFileRecord)?;
        record.size_epoch = value;
        record.valid_data_length = valid_data_length;
        self.next_size_epoch = next_epoch;
        let volume_sequence = self.next_volume_sequence;
        self.next_volume_sequence = next_volume;
        Ok(RegistryEffect {
            value,
            volume_sequence,
        })
    }

    pub(crate) fn preflight_size_commit(
        &mut self,
        id: FileId,
        expected_size_epoch: u64,
    ) -> Result<SizeCommit<'_>, RegistryError> {
        self.validate()?;
        let file = self.checked_file(id)?;
        expect_generation(GenerationDomain::Size, expected_size_epoch, file.size_epoch)?;
        if file.native.is_none() {
            return Err(RegistryError::MissingNative);
        }
        let size_epoch = self.next_size_epoch;
        let following_size_epoch = reserve_one(size_epoch, GenerationDomain::Size)?;
        let volume_sequence = self.next_volume_sequence;
        let following_volume_sequence =
            reserve_one(volume_sequence, GenerationDomain::VolumeSequence)?;
        let file = self
            .files
            .get_mut(&id)
            .ok_or(RegistryError::CorruptFileRecord)?;
        Ok(SizeCommit {
            file,
            next_size_epoch: &mut self.next_size_epoch,
            next_volume_sequence: &mut self.next_volume_sequence,
            size_epoch,
            following_size_epoch,
            volume_sequence,
            following_volume_sequence,
        })
    }

    pub(crate) fn record_existing_effect(
        &mut self,
        id: FileId,
    ) -> Result<RegistryEffect<()>, RegistryError> {
        let record = self.file(id)?.clone();
        let reservation = self.preflight_existing_open(
            id,
            record.namespace_generation,
            record.security_generation,
            record.size_epoch,
            ExistingOpenSizeEffect::Preserve,
            ExistingOpenNamespaceEffect::Preserve,
        )?;
        Ok(self.finalize_existing_open(reservation))
    }

    pub(crate) fn preflight_existing_open(
        &self,
        id: FileId,
        expected_namespace_generation: u64,
        expected_security_generation: u64,
        expected_size_epoch: u64,
        size_effect: ExistingOpenSizeEffect,
        namespace_effect: ExistingOpenNamespaceEffect,
    ) -> Result<ExistingOpenReservation, RegistryError> {
        self.prepare_existing_open(
            id,
            expected_namespace_generation,
            expected_security_generation,
            expected_size_epoch,
            size_effect,
            namespace_effect,
        )
    }

    pub(crate) fn finalize_existing_open(
        &mut self,
        reservation: ExistingOpenReservation,
    ) -> RegistryEffect<()> {
        debug_assert_eq!(self.next_volume_sequence, reservation.volume_sequence);
        debug_assert!(self.files.contains_key(&reservation.file.id));
        let id = reservation.file.id;
        self.files.insert(id, reservation.file);
        self.next_namespace_generation = reservation.next_namespace_generation;
        self.next_size_epoch = reservation.next_size_epoch;
        self.next_volume_sequence = reservation.next_volume_sequence;
        RegistryEffect {
            value: (),
            volume_sequence: reservation.volume_sequence,
        }
    }

    fn prepare_existing_open(
        &self,
        id: FileId,
        expected_namespace_generation: u64,
        expected_security_generation: u64,
        expected_size_epoch: u64,
        size_effect: ExistingOpenSizeEffect,
        namespace_effect: ExistingOpenNamespaceEffect,
    ) -> Result<ExistingOpenReservation, RegistryError> {
        self.validate()?;
        let record = self.checked_file(id)?;
        expect_generation(
            GenerationDomain::Namespace,
            expected_namespace_generation,
            record.namespace_generation,
        )?;
        expect_generation(
            GenerationDomain::Security,
            expected_security_generation,
            record.security_generation,
        )?;
        expect_generation(
            GenerationDomain::Size,
            expected_size_epoch,
            record.size_epoch,
        )?;
        if record.native.is_none() {
            return Err(RegistryError::MissingNative);
        }
        let next_volume_sequence =
            reserve_one(self.next_volume_sequence, GenerationDomain::VolumeSequence)?;
        let mut file = record.clone();
        let next_size_epoch = match size_effect {
            ExistingOpenSizeEffect::Preserve => self.next_size_epoch,
            ExistingOpenSizeEffect::Truncate => {
                let next = reserve_one(self.next_size_epoch, GenerationDomain::Size)?;
                file.size_epoch = self.next_size_epoch;
                file.valid_data_length = 0;
                next
            }
        };
        let next_namespace_generation = match namespace_effect {
            ExistingOpenNamespaceEffect::Preserve => self.next_namespace_generation,
            ExistingOpenNamespaceEffect::Advance => {
                let next =
                    reserve_one(self.next_namespace_generation, GenerationDomain::Namespace)?;
                file.namespace_generation = self.next_namespace_generation;
                next
            }
        };
        Ok(ExistingOpenReservation {
            file,
            next_namespace_generation,
            next_size_epoch,
            volume_sequence: self.next_volume_sequence,
            next_volume_sequence,
        })
    }

    pub(crate) fn preflight_write(
        &self,
        id: FileId,
        expected_size_epoch: u64,
        may_change_size: bool,
    ) -> Result<WriteReservation, RegistryError> {
        self.validate()?;
        let record = self.checked_file(id)?;
        expect_generation(
            GenerationDomain::Size,
            expected_size_epoch,
            record.size_epoch,
        )?;
        if record.native.is_none() {
            return Err(RegistryError::MissingNative);
        }
        let next_volume_sequence =
            reserve_one(self.next_volume_sequence, GenerationDomain::VolumeSequence)?;
        let (reserved_size_epoch, next_size_epoch) = if may_change_size {
            (
                Some(self.next_size_epoch),
                reserve_one(self.next_size_epoch, GenerationDomain::Size)?,
            )
        } else {
            (None, self.next_size_epoch)
        };
        Ok(WriteReservation {
            file: record.clone(),
            reserved_size_epoch,
            next_size_epoch,
            volume_sequence: self.next_volume_sequence,
            next_volume_sequence,
        })
    }

    pub(crate) fn finalize_write(
        &mut self,
        reservation: WriteReservation,
        changed_valid_data_length: Option<u64>,
    ) -> Result<WriteFinalization, RegistryError> {
        if self.next_volume_sequence != reservation.volume_sequence
            || reservation.volume_sequence.checked_add(1) != Some(reservation.next_volume_sequence)
        {
            return Err(RegistryError::CorruptCounter(
                GenerationDomain::VolumeSequence,
            ));
        }
        if reservation.file.native.is_none()
            || self.files.get(&reservation.file.id) != Some(&reservation.file)
        {
            return Err(RegistryError::CorruptFileRecord);
        }
        match reservation.reserved_size_epoch {
            Some(reserved_size_epoch) => {
                if self.next_size_epoch != reserved_size_epoch
                    || reserved_size_epoch.checked_add(1) != Some(reservation.next_size_epoch)
                {
                    return Err(RegistryError::CorruptCounter(GenerationDomain::Size));
                }
            }
            None => {
                if self.next_size_epoch != reservation.next_size_epoch
                    || changed_valid_data_length.is_some()
                {
                    return Err(RegistryError::CorruptCounter(GenerationDomain::Size));
                }
            }
        }
        if changed_valid_data_length
            .is_some_and(|valid_data_length| valid_data_length < reservation.file.valid_data_length)
        {
            return Err(RegistryError::CorruptFileRecord);
        }

        let size_changed = changed_valid_data_length.is_some();
        let mut file = reservation.file;
        if let Some(valid_data_length) = changed_valid_data_length {
            let Some(size_epoch) = reservation.reserved_size_epoch else {
                return Err(RegistryError::CorruptCounter(GenerationDomain::Size));
            };
            file.size_epoch = size_epoch;
            file.valid_data_length = valid_data_length;
        }
        let Some(installed) = self.files.get_mut(&file.id) else {
            return Err(RegistryError::CorruptFileRecord);
        };
        let effect = WriteEffect {
            volume_sequence: reservation.volume_sequence,
            size_epoch: file.size_epoch,
            valid_data_length: file.valid_data_length,
            size_changed,
        };
        *installed = file.clone();
        if size_changed {
            self.next_size_epoch = reservation.next_size_epoch;
        }
        self.next_volume_sequence = reservation.next_volume_sequence;
        Ok(WriteFinalization { effect, file })
    }

    pub(crate) fn expect_security_generation(
        &self,
        id: FileId,
        expected: u64,
    ) -> Result<(), RegistryError> {
        self.validate()?;
        let actual = self.checked_file(id)?.security_generation;
        expect_generation(GenerationDomain::Security, expected, actual)
    }

    pub(crate) fn expect_namespace_generation(
        &self,
        id: FileId,
        expected: u64,
    ) -> Result<(), RegistryError> {
        self.validate()?;
        let actual = self.checked_file(id)?.namespace_generation;
        expect_generation(GenerationDomain::Namespace, expected, actual)
    }

    pub(crate) fn expect_size_epoch(&self, id: FileId, expected: u64) -> Result<(), RegistryError> {
        self.validate()?;
        let actual = self.checked_file(id)?.size_epoch;
        expect_generation(GenerationDomain::Size, expected, actual)
    }

    fn checked_link(&self, id: LinkId) -> Result<&LinkRecord, RegistryError> {
        let record = self.links.get(&id).ok_or(RegistryError::MissingLink(id))?;
        if record.id != id {
            return Err(RegistryError::CorruptLinkRecord);
        }
        Ok(record)
    }

    fn prepare_namespace_updates(
        &self,
        ids: &[FileId],
        first_generation: u64,
    ) -> Result<Vec<(FileId, FileRecord)>, RegistryError> {
        let mut updates = Vec::with_capacity(ids.len());
        for (generation, id) in (first_generation..).zip(ids.iter()) {
            let mut record = self.checked_file(*id)?.clone();
            record.namespace_generation = generation;
            updates.push((*id, record));
        }
        Ok(updates)
    }

    fn validate_name_index(&self, record: &LinkRecord) -> Result<(), RegistryError> {
        match self
            .by_name
            .get(&(record.parent, record.name.key().clone()))
        {
            Some(indexed) if *indexed == record.id => Ok(()),
            _ => Err(RegistryError::CorruptNameIndex),
        }
    }

    fn ensure_name_available(
        &self,
        parent: FileId,
        key: &NormalizedName,
        retained: Option<LinkId>,
    ) -> Result<(), RegistryError> {
        let Some(&indexed) = self.by_name.get(&(parent, key.clone())) else {
            #[cfg(test)]
            record_directory_batch_global_link_scan();
            return if self
                .links
                .values()
                .any(|record| record.parent == parent && record.name.key() == key)
            {
                Err(RegistryError::CorruptNameIndex)
            } else {
                Ok(())
            };
        };
        let record = self
            .links
            .get(&indexed)
            .ok_or(RegistryError::CorruptNameIndex)?;
        if record.id != indexed || record.parent != parent || record.name.key() != key {
            return Err(RegistryError::CorruptNameIndex);
        }
        if retained == Some(indexed) {
            Ok(())
        } else {
            Err(RegistryError::NameCollision { parent })
        }
    }

    fn prepare_link_path(
        &self,
        parent: FileId,
        name: &Component,
        relative_path: &Path,
    ) -> Result<NormalizedPath, RegistryError> {
        if !valid_relative_path(relative_path, name) {
            return Err(RegistryError::CorruptRelativePath);
        }
        let path = normalized_relative_path(relative_path)?;
        if let Some(root) = self.contained_root {
            let (expected_relative_path, expected_path) =
                self.checked_child_relative_path(root, parent, name)?;
            if relative_path != expected_relative_path || path != expected_path {
                return Err(RegistryError::CorruptRelativePath);
            }
        }
        Ok(path)
    }

    fn preflight_contained_link_insertion(&self, child: FileId) -> Result<(), RegistryError> {
        let Some(root) = self.contained_root else {
            return Ok(());
        };
        if child == root {
            return Err(RegistryError::ContainedRootLink);
        }
        if self.by_child.contains_key(&child) {
            #[cfg(test)]
            record_directory_batch_global_link_scan();
            if self.links.values().any(|link| link.parent == child) {
                return Err(RegistryError::AmbiguousPath(child));
            }
        }
        Ok(())
    }

    fn ensure_path_available(&self, path: &[NormalizedName]) -> Result<(), RegistryError> {
        if self.by_path.contains_key(path) {
            Err(RegistryError::DuplicateRelativePath)
        } else {
            Ok(())
        }
    }

    fn insert_link_indices(&mut self, id: LinkId, child: FileId, path: NormalizedPath) {
        self.by_child.entry(child).or_default().insert(id);
        self.by_path.insert(path.clone(), id);
        self.path_by_link.insert(id, path);
    }

    fn remove_link_indices(&mut self, id: LinkId, child: FileId, path: &[NormalizedName]) {
        if let Some(inbound) = self.by_child.get_mut(&child) {
            inbound.remove(&id);
            if inbound.is_empty() {
                self.by_child.remove(&child);
            }
        }
        self.by_path.remove(path);
        self.path_by_link.remove(&id);
    }
}

fn reserve_one(current: u64, domain: GenerationDomain) -> Result<u64, RegistryError> {
    reserve_many(current, 1, domain)
}

fn valid_relative_path(path: &Path, name: &Component) -> bool {
    !path.is_absolute()
        && path.file_name() == Some(name.as_os_str())
        && path
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
}

fn normalized_relative_path(path: &Path) -> Result<NormalizedPath, RegistryError> {
    let mut normalized = Vec::new();
    for part in path.components() {
        let std::path::Component::Normal(name) = part else {
            return Err(RegistryError::CorruptRelativePath);
        };
        normalized.push(normalized_os_name(name)?);
    }
    if normalized.is_empty() {
        return Err(RegistryError::CorruptRelativePath);
    }
    Ok(normalized)
}

#[cfg(windows)]
fn normalized_os_name(name: &std::ffi::OsStr) -> Result<NormalizedName, RegistryError> {
    use std::os::windows::ffi::OsStrExt;

    let bytes: Vec<u8> = name.encode_wide().flat_map(u16::to_le_bytes).collect();
    crate::path::component_from_utf16le(&bytes)
        .map(|component| component.key().clone())
        .map_err(|_| RegistryError::CorruptRelativePath)
}

#[cfg(not(windows))]
fn normalized_os_name(name: &std::ffi::OsStr) -> Result<NormalizedName, RegistryError> {
    let bytes: Vec<u8> = name
        .to_string_lossy()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    crate::path::component_from_utf16le(&bytes)
        .map(|component| component.key().clone())
        .map_err(|_| RegistryError::CorruptRelativePath)
}

fn reserve_many(current: u64, count: u64, domain: GenerationDomain) -> Result<u64, RegistryError> {
    if current == 0 {
        return Err(RegistryError::CorruptCounter(domain));
    }
    current
        .checked_add(count)
        .ok_or(RegistryError::CounterExhausted(domain))
}

fn unique_file_ids(ids: [FileId; 3]) -> Vec<FileId> {
    let mut unique = Vec::with_capacity(ids.len());
    for id in ids {
        if !unique.contains(&id) {
            unique.push(id);
        }
    }
    unique
}

fn expect_generation(
    domain: GenerationDomain,
    expected: u64,
    actual: u64,
) -> Result<(), RegistryError> {
    if expected == actual {
        Ok(())
    } else {
        Err(RegistryError::StaleGeneration {
            domain,
            expected,
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    use fsring_abi::ids::{FileId, LinkId};

    use crate::path::{component_from_utf16le, Component, NormalizedName};

    use super::{
        directory_batch_global_link_scans, reset_directory_batch_global_link_scans,
        DirectoryObservation, ExistingOpenNamespaceEffect, ExistingOpenSizeEffect,
        GenerationDomain, IdentityRegistry, LinkRecord, NativeKey, RegistryError,
        SecurityFinalization,
    };

    type FileSnapshot = (FileId, FileId, Option<NativeKey>, u64, u64, u64, u64);

    #[derive(Debug, PartialEq, Eq)]
    struct RegistrySnapshot {
        files: Vec<FileSnapshot>,
        by_native: Vec<(NativeKey, FileId)>,
        links: Vec<(LinkId, LinkId, FileId, FileId, String, PathBuf, u64)>,
        by_name: Vec<(FileId, String, LinkId)>,
        contained_root: Option<FileId>,
        by_child: Vec<(FileId, Vec<LinkId>)>,
        by_path: Vec<(String, LinkId)>,
        path_by_link: Vec<(LinkId, String)>,
        counters: [u64; 6],
    }

    fn native(file_index: u64) -> NativeKey {
        NativeKey {
            volume_serial: 7,
            file_index,
        }
    }

    fn component(value: &str) -> Component {
        let bytes: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        component_from_utf16le(&bytes).unwrap()
    }

    fn name_key(value: &str) -> NormalizedName {
        component(value).key().clone()
    }

    fn path_key(value: &str) -> Vec<NormalizedName> {
        value.split('/').map(name_key).collect()
    }

    fn file(lo: u64) -> FileId {
        FileId { lo, hi: 0 }
    }

    fn install_file(registry: &mut IdentityRegistry, file_index: u64) -> FileId {
        registry.observe_native(native(file_index), 0).unwrap()
    }

    fn install_link(
        registry: &mut IdentityRegistry,
        parent: FileId,
        child: FileId,
        name: &str,
    ) -> LinkId {
        registry
            .install_link(parent, child, component(name), PathBuf::from(name))
            .unwrap()
    }

    fn install_indexed_link_fixture(
        registry: &mut IdentityRegistry,
        parent: FileId,
        child: FileId,
        name: Component,
        relative_path: PathBuf,
        path: Vec<NormalizedName>,
    ) -> LinkId {
        let id = LinkId {
            lo: registry.next_link_id,
            hi: 0,
        };
        registry.next_link_id += 1;
        let generation = registry.next_namespace_generation;
        registry.next_namespace_generation += 1;
        registry.links.insert(
            id,
            LinkRecord {
                id,
                parent,
                child,
                name: name.clone(),
                relative_path,
                namespace_generation: generation,
            },
        );
        registry.by_name.insert((parent, name.key().clone()), id);
        registry.by_child.entry(child).or_default().insert(id);
        registry.by_path.insert(path.clone(), id);
        registry.path_by_link.insert(id, path);
        id
    }

    #[test]
    fn directory_observation_batch_is_atomic_and_replay_stable() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(1), 0).unwrap();
        let before = snapshot(&registry);
        let reservation = registry
            .preflight_directory_observations(
                root,
                root,
                vec![
                    DirectoryObservation {
                        native: native(2),
                        valid_data_length: 12,
                        name: component("first.bin"),
                    },
                    DirectoryObservation {
                        native: native(2),
                        valid_data_length: 12,
                        name: component("second.bin"),
                    },
                ],
            )
            .unwrap();
        let stale_reservation = registry
            .preflight_directory_observations(
                root,
                root,
                vec![
                    DirectoryObservation {
                        native: native(2),
                        valid_data_length: 12,
                        name: component("first.bin"),
                    },
                    DirectoryObservation {
                        native: native(2),
                        valid_data_length: 12,
                        name: component("second.bin"),
                    },
                ],
            )
            .unwrap();
        let planned = &reservation.new_links[0];
        assert_eq!(planned.by_path_key, planned.path_by_link_key);
        assert_ne!(
            planned.by_path_key.as_ptr(),
            planned.path_by_link_key.as_ptr(),
            "finalization requires two independently owned path keys so it can move both"
        );
        assert_eq!(
            snapshot(&registry),
            before,
            "preflight must not publish semantic identity state"
        );
        assert_eq!(
            reservation.entries()[0].file.id,
            reservation.entries()[1].file.id
        );
        assert_ne!(
            reservation.entries()[0].link.id,
            reservation.entries()[1].link.id
        );
        let installed = registry
            .finalize_directory_observations(reservation)
            .unwrap();
        let after_first = snapshot(&registry);
        assert_eq!(
            registry
                .finalize_directory_observations(stale_reservation)
                .err(),
            Some(RegistryError::CorruptCounter(
                GenerationDomain::FileIdentity
            ))
        );
        assert_eq!(
            snapshot(&registry),
            after_first,
            "a stale second reservation must not reuse IDs or mutate indices"
        );

        let replay = registry
            .preflight_directory_observations(
                root,
                root,
                vec![
                    DirectoryObservation {
                        native: native(2),
                        valid_data_length: 12,
                        name: component("first.bin"),
                    },
                    DirectoryObservation {
                        native: native(2),
                        valid_data_length: 12,
                        name: component("second.bin"),
                    },
                ],
            )
            .unwrap();
        assert_eq!(replay.entries(), installed.as_slice());
        let replayed = registry.finalize_directory_observations(replay).unwrap();
        assert_eq!(replayed, installed);
        assert_eq!(
            snapshot(&registry),
            after_first,
            "replay must not allocate IDs or generations"
        );
    }

    #[test]
    fn late_directory_observation_counter_failure_publishes_nothing() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(1), 0).unwrap();
        registry.next_file_id = u64::MAX - 1;
        let before = snapshot(&registry);

        let error = registry
            .preflight_directory_observations(
                root,
                root,
                vec![
                    DirectoryObservation {
                        native: native(2),
                        valid_data_length: 1,
                        name: component("would-fit.bin"),
                    },
                    DirectoryObservation {
                        native: native(3),
                        valid_data_length: 1,
                        name: component("would-overflow.bin"),
                    },
                ],
            )
            .err()
            .expect("late counter exhaustion");
        assert_eq!(
            error,
            RegistryError::CounterExhausted(GenerationDomain::FileIdentity)
        );
        assert_eq!(
            snapshot(&registry),
            before,
            "a late batch failure must not leave the first identity installed"
        );
    }

    #[test]
    fn directory_batch_planning_has_one_global_scan_not_one_per_entry() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(1), 0).unwrap();
        let shared_native = native(10_000);
        for index in 0..128 {
            let key = if index == 0 {
                shared_native
            } else {
                native(10_000 + index)
            };
            registry
                .observe_native_and_install_link(
                    root,
                    key,
                    4,
                    root,
                    component(&format!("registered-{index:03}.bin")),
                )
                .unwrap();
        }
        let observations = (0..64)
            .map(|index| DirectoryObservation {
                native: shared_native,
                valid_data_length: 4,
                name: component(&format!("new-hard-link-{index:03}.bin")),
            })
            .collect();
        let before = snapshot(&registry);
        reset_directory_batch_global_link_scans();

        let reservation = registry
            .preflight_directory_observations(root, root, observations)
            .unwrap();

        assert_eq!(
            directory_batch_global_link_scans(),
            1,
            "batch planning may precompute outgoing parents once, never rescan all links per entry"
        );
        assert_eq!(snapshot(&registry), before);
        let entries = registry
            .finalize_directory_observations(reservation)
            .unwrap();
        assert_eq!(entries.len(), 64);
        assert!(entries
            .iter()
            .all(|entry| entry.file.id == entries[0].file.id));
        let distinct_links: HashSet<_> = entries.iter().map(|entry| entry.link.id).collect();
        assert_eq!(distinct_links.len(), entries.len());
    }

    fn snapshot(registry: &IdentityRegistry) -> RegistrySnapshot {
        let mut files: Vec<_> = registry
            .files
            .iter()
            .map(|(key, record)| {
                (
                    *key,
                    record.id,
                    record.native,
                    record.namespace_generation,
                    record.security_generation,
                    record.size_epoch,
                    record.valid_data_length,
                )
            })
            .collect();
        files.sort_by_key(|(key, ..)| (key.hi, key.lo));

        let mut by_native: Vec<_> = registry
            .by_native
            .iter()
            .map(|(key, id)| (*key, *id))
            .collect();
        by_native.sort_by_key(|(key, id)| (key.volume_serial, key.file_index, id.hi, id.lo));

        let mut links: Vec<_> = registry
            .links
            .iter()
            .map(|(key, record)| {
                (
                    *key,
                    record.id,
                    record.parent,
                    record.child,
                    format!("{:?}", record.name),
                    record.relative_path.clone(),
                    record.namespace_generation,
                )
            })
            .collect();
        links.sort_by_key(|(key, ..)| (key.hi, key.lo));

        let mut by_name: Vec<_> = registry
            .by_name
            .iter()
            .map(|((parent, key), id)| (*parent, format!("{key:?}"), *id))
            .collect();
        by_name.sort_by(|left, right| {
            (left.0.hi, left.0.lo, &left.1, left.2.hi, left.2.lo)
                .cmp(&(right.0.hi, right.0.lo, &right.1, right.2.hi, right.2.lo))
        });

        let mut by_child: Vec<_> = registry
            .by_child
            .iter()
            .map(|(child, links)| {
                let mut links: Vec<_> = links.iter().copied().collect();
                links.sort_by_key(|id| (id.hi, id.lo));
                (*child, links)
            })
            .collect();
        by_child.sort_by_key(|(child, _)| (child.hi, child.lo));

        let mut by_path: Vec<_> = registry
            .by_path
            .iter()
            .map(|(path, id)| (format!("{path:?}"), *id))
            .collect();
        by_path.sort_by(|left, right| left.0.cmp(&right.0));

        let mut path_by_link: Vec<_> = registry
            .path_by_link
            .iter()
            .map(|(id, path)| (*id, format!("{path:?}")))
            .collect();
        path_by_link.sort_by_key(|(id, _)| (id.hi, id.lo));

        RegistrySnapshot {
            files,
            by_native,
            links,
            by_name,
            contained_root: registry.contained_root,
            by_child,
            by_path,
            path_by_link,
            counters: [
                registry.next_file_id,
                registry.next_link_id,
                registry.next_namespace_generation,
                registry.next_security_generation,
                registry.next_size_epoch,
                registry.next_volume_sequence,
            ],
        }
    }

    #[test]
    fn root_installation_records_nonzero_identity_and_generations() {
        let mut registry = IdentityRegistry::new();

        let root = registry.install_root(native(1), 23).unwrap();
        let record = registry.file(root).unwrap();

        assert_eq!(root, file(1));
        assert_eq!(record.native, Some(native(1)));
        assert_ne!(record.namespace_generation, 0);
        assert_ne!(record.security_generation, 0);
        assert_ne!(record.size_epoch, 0);
        assert_eq!(record.valid_data_length, 23);
        assert_eq!(registry.file_id_for_native(native(1)).unwrap(), root);
    }

    #[test]
    fn observing_the_same_native_key_deduplicates_file_identity() {
        let mut registry = IdentityRegistry::new();

        let first = registry.observe_native(native(2), 4).unwrap();
        let second = registry.observe_native(native(2), 99).unwrap();

        assert_eq!(first, second);
        assert_eq!(registry.file(first).unwrap().valid_data_length, 4);
        assert_eq!(registry.files.len(), 1);
        assert_eq!(registry.by_native.len(), 1);
    }

    #[test]
    fn atomic_observation_preflights_new_file_and_link_before_mutation() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(3), 0).unwrap();
        registry.next_link_id = u64::MAX;
        let before = snapshot(&registry);

        assert_eq!(
            registry
                .observe_native_and_install_link(root, native(4), 17, root, component("child"),),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::LinkIdentity
            ))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn atomic_observation_preflights_known_file_link_before_mutation() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(5), 0).unwrap();
        let child = install_file(&mut registry, 6);
        registry.next_namespace_generation = u64::MAX;
        let before = snapshot(&registry);

        assert_eq!(
            registry
                .observe_native_and_install_link(root, native(6), 99, root, component("known"),),
            Err(RegistryError::CounterExhausted(GenerationDomain::Namespace))
        );
        assert_eq!(snapshot(&registry), before);
        assert_eq!(registry.file(child).unwrap().valid_data_length, 0);
    }

    #[test]
    fn atomic_observation_is_idempotent_for_a_case_variant_of_the_same_native_name() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(7), 0).unwrap();
        let first = registry
            .observe_native_and_install_link(root, native(8), 23, root, component("same"))
            .unwrap();
        assert_eq!(registry.next_volume_sequence, 1);
        let before = snapshot(&registry);

        let replay = registry
            .observe_native_and_install_link(root, native(8), 999, root, component("SAME"))
            .unwrap();

        assert_eq!(replay, first);
        assert_eq!(snapshot(&registry), before);
        assert_eq!(registry.file(first.0).unwrap().valid_data_length, 23);
        let stored = registry.link(first.1).unwrap();
        assert_eq!(stored.name.as_os_str(), std::ffi::OsStr::new("same"));
        assert_eq!(stored.relative_path, PathBuf::from("same"));
    }

    #[test]
    fn atomic_observation_rejects_name_native_collision_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(9), 0).unwrap();
        registry
            .observe_native_and_install_link(root, native(10), 0, root, component("occupied"))
            .unwrap();
        let before = snapshot(&registry);

        assert_eq!(
            registry.observe_native_and_install_link(
                root,
                native(11),
                0,
                root,
                component("OCCUPIED"),
            ),
            Err(RegistryError::NameCollision { parent: root })
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn atomic_observation_rejects_corruption_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(12), 0).unwrap();
        registry
            .observe_native_and_install_link(root, native(13), 0, root, component("present"))
            .unwrap();
        registry.by_name.clear();
        let before = snapshot(&registry);

        assert_eq!(
            registry.observe_native_and_install_link(root, native(14), 0, root, component("new"),),
            Err(RegistryError::CorruptNameIndex)
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn atomic_observation_derives_nested_paths_from_registered_parents() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(15), 0).unwrap();
        let parent = registry
            .observe_native_and_install_link(root, native(16), 0, root, component("parent"))
            .unwrap()
            .0;

        let child = registry
            .observe_native_and_install_link(root, native(17), 0, parent, component("child"))
            .unwrap();

        assert_eq!(
            registry.link(child.1).unwrap().relative_path,
            PathBuf::from("parent").join("child")
        );
        assert_eq!(
            registry
                .child_relative_path(root, parent, &component("next"))
                .unwrap(),
            PathBuf::from("parent").join("next")
        );
    }

    #[test]
    fn atomic_observation_rejects_missing_and_ambiguous_parent_paths_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(18), 0).unwrap();
        let missing_parent = install_file(&mut registry, 19);
        let before_missing = snapshot(&registry);

        assert_eq!(
            registry.observe_native_and_install_link(
                root,
                native(20),
                0,
                missing_parent,
                component("child"),
            ),
            Err(RegistryError::MissingPath(missing_parent))
        );
        assert_eq!(snapshot(&registry), before_missing);

        let parent = registry
            .observe_native_and_install_link(root, native(21), 0, root, component("first"))
            .unwrap()
            .0;
        install_link(&mut registry, root, parent, "second");
        let before_ambiguous = snapshot(&registry);
        assert_eq!(
            registry.observe_native_and_install_link(
                root,
                native(22),
                0,
                parent,
                component("child"),
            ),
            Err(RegistryError::AmbiguousPath(parent))
        );
        assert_eq!(snapshot(&registry), before_ambiguous);
    }

    #[test]
    fn atomic_observation_rejects_wrong_parent_prefix_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(23), 0).unwrap();
        let parent = registry
            .observe_native_and_install_link(root, native(24), 0, root, component("parent"))
            .unwrap()
            .0;
        let child = registry
            .observe_native_and_install_link(root, native(25), 0, parent, component("child"))
            .unwrap();
        registry.links.get_mut(&child.1).unwrap().relative_path =
            PathBuf::from("wrong").join("child");
        let before = snapshot(&registry);

        assert_eq!(
            registry.observe_native_and_install_link(root, native(26), 0, root, component("new"),),
            Err(RegistryError::CorruptRelativePath)
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn atomic_observation_rejects_duplicate_relative_paths_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(27), 0).unwrap();
        let first = registry
            .observe_native_and_install_link(root, native(28), 0, root, component("first"))
            .unwrap();
        let second = registry
            .observe_native_and_install_link(root, native(29), 0, root, component("second"))
            .unwrap();
        let duplicate = registry.link(first.1).unwrap().relative_path.clone();
        registry.links.get_mut(&second.1).unwrap().relative_path = duplicate;
        let before = snapshot(&registry);

        assert_eq!(
            registry.observe_native_and_install_link(root, native(30), 0, root, component("new"),),
            Err(RegistryError::DuplicateRelativePath)
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn atomic_observation_replay_rejects_path_mismatch_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(31), 0).unwrap();
        let observed = registry
            .observe_native_and_install_link(root, native(32), 0, root, component("same"))
            .unwrap();
        registry.links.get_mut(&observed.1).unwrap().relative_path =
            PathBuf::from("wrong").join("same");
        let before = snapshot(&registry);

        assert_eq!(
            registry.observe_native_and_install_link(root, native(32), 0, root, component("same"),),
            Err(RegistryError::CorruptRelativePath)
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn contained_discovery_rejects_corrupt_child_and_path_indices_without_mutation() {
        let mut missing_child = IdentityRegistry::new();
        let root = missing_child.install_root(native(33), 0).unwrap();
        let observed = missing_child
            .observe_native_and_install_link(root, native(34), 0, root, component("child"))
            .unwrap();
        missing_child.by_child.remove(&observed.0);
        let before = snapshot(&missing_child);
        assert_eq!(
            missing_child.observe_native_and_install_link(
                root,
                native(35),
                0,
                root,
                component("new"),
            ),
            Err(RegistryError::CorruptChildIndex)
        );
        assert_eq!(snapshot(&missing_child), before);

        let mut dangling_path = IdentityRegistry::new();
        let root = dangling_path.install_root(native(36), 0).unwrap();
        dangling_path
            .observe_native_and_install_link(root, native(37), 0, root, component("child"))
            .unwrap();
        dangling_path
            .by_path
            .insert(path_key("dangling"), LinkId { lo: 999, hi: 0 });
        let before = snapshot(&dangling_path);
        assert_eq!(
            dangling_path.child_relative_path(root, root, &component("new")),
            Err(RegistryError::CorruptPathIndex)
        );
        assert_eq!(snapshot(&dangling_path), before);

        let mut reverse_mismatch = IdentityRegistry::new();
        let root = reverse_mismatch.install_root(native(38), 0).unwrap();
        let observed = reverse_mismatch
            .observe_native_and_install_link(root, native(39), 0, root, component("child"))
            .unwrap();
        reverse_mismatch
            .path_by_link
            .insert(observed.1, path_key("wrong"));
        let before = snapshot(&reverse_mismatch);
        assert_eq!(
            reverse_mismatch.child_relative_path(root, root, &component("new")),
            Err(RegistryError::CorruptPathIndex)
        );
        assert_eq!(snapshot(&reverse_mismatch), before);
    }

    #[test]
    fn normalized_path_collision_is_rejected_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let first_parent = install_file(&mut registry, 40);
        let second_parent = install_file(&mut registry, 41);
        let first_child = install_file(&mut registry, 42);
        let second_child = install_file(&mut registry, 43);
        registry
            .install_link(
                first_parent,
                first_child,
                component("same"),
                PathBuf::from("same"),
            )
            .unwrap();
        let before = snapshot(&registry);

        assert_eq!(
            registry.install_link(
                second_parent,
                second_child,
                component("SAME"),
                PathBuf::from("SAME"),
            ),
            Err(RegistryError::DuplicateRelativePath)
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn contained_cycle_is_rejected_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(44), 0).unwrap();
        let parent = registry
            .observe_native_and_install_link(root, native(45), 0, root, component("parent"))
            .unwrap();
        let child = registry
            .observe_native_and_install_link(root, native(46), 0, parent.0, component("child"))
            .unwrap();
        let before = snapshot(&registry);

        assert_eq!(
            registry.rename_link(
                parent.1,
                child.0,
                component("parent"),
                PathBuf::from("parent/child/parent"),
            ),
            Err(RegistryError::CorruptRelativePath)
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn contained_discovery_handles_a_deep_chain_without_recursive_derivation() {
        const DEPTH: usize = 1_024;

        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(47), 0).unwrap();
        let mut parent = root;
        let mut relative_path = PathBuf::new();
        let mut normalized_path = Vec::new();
        for _ in 0..DEPTH {
            let child = registry.allocate_file(None, 0).unwrap();
            let name = component("node");
            relative_path.push(name.as_os_str());
            normalized_path.push(name.key().clone());
            install_indexed_link_fixture(
                &mut registry,
                parent,
                child,
                name,
                relative_path.clone(),
                normalized_path.clone(),
            );
            parent = child;
        }

        let path = registry
            .child_relative_path(root, parent, &component("leaf"))
            .unwrap();
        assert_eq!(path.components().count(), DEPTH + 1);
        assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("leaf")));
    }

    #[test]
    fn distinct_names_get_distinct_link_ids_for_one_native_file() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 10);
        let child = install_file(&mut registry, 11);

        let first = install_link(&mut registry, parent, child, "alpha");
        let second = install_link(&mut registry, parent, child, "beta");

        assert_ne!(first, second);
        assert_eq!(registry.link(first).unwrap().child, child);
        assert_eq!(registry.link(second).unwrap().child, child);
        assert_eq!(
            registry
                .link_by_name(parent, &name_key("ALPHA"))
                .unwrap()
                .id,
            first
        );
        assert_eq!(
            registry.link_by_name(parent, &name_key("beta")).unwrap().id,
            second
        );
    }

    #[test]
    fn rename_preserves_link_id_and_replaces_only_its_name_binding() {
        let mut registry = IdentityRegistry::new();
        let old_parent = install_file(&mut registry, 20);
        let new_parent = install_file(&mut registry, 21);
        let child = install_file(&mut registry, 22);
        let retained = install_link(&mut registry, old_parent, child, "before");
        let neighbor = install_link(&mut registry, old_parent, child, "neighbor");

        let effect = registry
            .rename_link(
                retained,
                new_parent,
                component("after"),
                PathBuf::from("new/after"),
            )
            .unwrap();

        assert_eq!(effect.value, retained);
        assert_ne!(effect.volume_sequence, 0);
        assert_eq!(
            registry
                .link_by_name(new_parent, &name_key("AFTER"))
                .unwrap()
                .id,
            retained
        );
        assert_eq!(
            registry
                .link_by_name(old_parent, &name_key("neighbor"))
                .unwrap()
                .id,
            neighbor
        );
        assert!(matches!(
            registry.link_by_name(old_parent, &name_key("before")),
            Err(RegistryError::MissingName)
        ));
        assert_eq!(registry.links.len(), 2);
        assert_eq!(registry.by_name.len(), 2);
    }

    #[test]
    fn unlink_retires_only_the_selected_binding() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 30);
        let child = install_file(&mut registry, 31);
        let removed = install_link(&mut registry, parent, child, "removed");
        let retained = install_link(&mut registry, parent, child, "retained");

        let effect = registry.unlink_link(removed).unwrap();

        assert_eq!(effect.value, removed);
        assert_ne!(effect.volume_sequence, 0);
        assert!(matches!(
            registry.link(removed),
            Err(RegistryError::MissingLink(missing)) if missing == removed
        ));
        assert!(matches!(
            registry.link_by_name(parent, &name_key("removed")),
            Err(RegistryError::MissingName)
        ));
        assert_eq!(
            registry
                .link_by_name(parent, &name_key("retained"))
                .unwrap()
                .id,
            retained
        );
        assert!(registry.file(child).is_ok());
    }

    #[test]
    fn create_rename_and_unlink_keep_contained_path_indices_consistent() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(32_000), 0).unwrap();
        let child = install_file(&mut registry, 32_001);

        let created = registry
            .create_link(root, child, component("created"), PathBuf::from("created"))
            .unwrap()
            .value;
        assert_eq!(registry.by_child.get(&child).unwrap().len(), 1);
        assert!(registry.by_child.get(&child).unwrap().contains(&created));
        assert_eq!(registry.by_path.get(&path_key("CREATED")), Some(&created));
        assert_eq!(
            registry.path_by_link.get(&created),
            Some(&path_key("created"))
        );

        registry
            .rename_link(
                created,
                root,
                component("renamed"),
                PathBuf::from("renamed"),
            )
            .unwrap();
        assert!(!registry.by_path.contains_key(&path_key("created")));
        assert_eq!(registry.by_path.get(&path_key("RENAMED")), Some(&created));
        assert_eq!(
            registry.path_by_link.get(&created),
            Some(&path_key("renamed"))
        );

        registry.unlink_link(created).unwrap();
        assert!(!registry.by_child.contains_key(&child));
        assert!(!registry.by_path.contains_key(&path_key("renamed")));
        assert!(!registry.path_by_link.contains_key(&created));
        assert!(registry.validate().is_ok());
    }

    #[test]
    fn contained_rename_reindexes_descendants_after_complete_preflight() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(32_010), 0).unwrap();
        let parent = registry
            .observe_native_and_install_link(root, native(32_011), 0, root, component("parent"))
            .unwrap();
        let child = registry
            .observe_native_and_install_link(root, native(32_012), 0, parent.0, component("child"))
            .unwrap();

        registry
            .rename_link(
                parent.1,
                root,
                component("renamed"),
                PathBuf::from("renamed"),
            )
            .unwrap();

        assert_eq!(
            registry.link(child.1).unwrap().relative_path,
            PathBuf::from("renamed/child")
        );
        assert!(!registry.by_path.contains_key(&path_key("parent/child")));
        assert_eq!(
            registry.by_path.get(&path_key("RENAMED/CHILD")),
            Some(&child.1)
        );
        assert_eq!(
            registry.path_by_link.get(&child.1),
            Some(&path_key("renamed/child"))
        );
        assert!(registry.validate().is_ok());
    }

    #[test]
    fn contained_root_rejects_inbound_links_from_every_applicable_insertion_api() {
        let mut observed = IdentityRegistry::new();
        let root = observed.install_root(native(32_020), 0).unwrap();
        let before = snapshot(&observed);
        assert_eq!(
            observed.observe_native_and_install_link(
                root,
                native(32_020),
                0,
                root,
                component("self"),
            ),
            Err(RegistryError::ContainedRootLink)
        );
        assert_eq!(snapshot(&observed), before);
        assert!(observed.validate().is_ok());

        let mut installed = IdentityRegistry::new();
        let root = installed.install_root(native(32_021), 0).unwrap();
        let before = snapshot(&installed);
        assert_eq!(
            installed.install_link(root, root, component("self"), PathBuf::from("self")),
            Err(RegistryError::ContainedRootLink)
        );
        assert_eq!(snapshot(&installed), before);
        assert!(installed.validate().is_ok());

        let mut created = IdentityRegistry::new();
        let root = created.install_root(native(32_022), 0).unwrap();
        let before = snapshot(&created);
        assert_eq!(
            created.create_link(root, root, component("self"), PathBuf::from("self")),
            Err(RegistryError::ContainedRootLink)
        );
        assert_eq!(snapshot(&created), before);
        assert!(created.validate().is_ok());
    }

    #[test]
    fn contained_parent_rejects_a_second_inbound_link_from_all_four_insertion_apis() {
        let mut observed = IdentityRegistry::new();
        let root = observed.install_root(native(32_030), 0).unwrap();
        let directory = observed
            .observe_native_and_install_link(root, native(32_031), 0, root, component("dir"))
            .unwrap()
            .0;
        observed
            .observe_native_and_install_link(root, native(32_032), 0, directory, component("child"))
            .unwrap();
        let before = snapshot(&observed);
        assert_eq!(
            observed.observe_native_and_install_link(
                root,
                native(32_031),
                0,
                root,
                component("alias"),
            ),
            Err(RegistryError::AmbiguousPath(directory))
        );
        assert_eq!(snapshot(&observed), before);
        assert!(observed.validate().is_ok());

        let mut installed = IdentityRegistry::new();
        let root = installed.install_root(native(32_040), 0).unwrap();
        let directory = installed
            .observe_native_and_install_link(root, native(32_041), 0, root, component("dir"))
            .unwrap()
            .0;
        installed
            .observe_native_and_install_link(root, native(32_042), 0, directory, component("child"))
            .unwrap();
        let before = snapshot(&installed);
        assert_eq!(
            installed.install_link(root, directory, component("alias"), PathBuf::from("alias"),),
            Err(RegistryError::AmbiguousPath(directory))
        );
        assert_eq!(snapshot(&installed), before);
        assert!(installed.validate().is_ok());

        let mut created = IdentityRegistry::new();
        let root = created.install_root(native(32_050), 0).unwrap();
        let directory = created
            .observe_native_and_install_link(root, native(32_051), 0, root, component("dir"))
            .unwrap()
            .0;
        created
            .observe_native_and_install_link(root, native(32_052), 0, directory, component("child"))
            .unwrap();
        let before = snapshot(&created);
        assert_eq!(
            created.create_link(root, directory, component("alias"), PathBuf::from("alias"),),
            Err(RegistryError::AmbiguousPath(directory))
        );
        assert_eq!(snapshot(&created), before);
        assert!(created.validate().is_ok());

        let mut bound = IdentityRegistry::new();
        let root = bound.install_root(native(32_060), 0).unwrap();
        let directory = bound.allocate_prospective(0).unwrap();
        bound
            .install_link(root, directory, component("dir"), PathBuf::from("dir"))
            .unwrap();
        let child = bound.allocate_prospective(0).unwrap();
        bound
            .install_link(
                directory,
                child,
                component("child"),
                PathBuf::from("dir/child"),
            )
            .unwrap();
        let before = snapshot(&bound);
        assert_eq!(
            bound.bind_native_and_create_link(
                root,
                directory,
                native(32_061),
                component("alias"),
                PathBuf::from("alias"),
            ),
            Err(RegistryError::AmbiguousPath(directory))
        );
        assert_eq!(snapshot(&bound), before);
        assert_eq!(bound.file(directory).unwrap().native, None);
        assert!(bound.validate().is_ok());
    }

    #[test]
    fn contained_leaf_preserves_valid_multiple_hard_links() {
        let mut registry = IdentityRegistry::new();
        let root = registry.install_root(native(32_070), 0).unwrap();
        let leaf = registry
            .observe_native_and_install_link(root, native(32_071), 0, root, component("leaf"))
            .unwrap()
            .0;

        let alias = registry
            .create_link(root, leaf, component("alias"), PathBuf::from("alias"))
            .unwrap();

        assert_ne!(alias.volume_sequence, 0);
        assert_eq!(registry.by_child.get(&leaf).unwrap().len(), 2);
        assert!(registry.validate().is_ok());
    }

    #[test]
    fn prospective_file_binds_once_to_native_identity() {
        let mut registry = IdentityRegistry::new();
        let prospective = registry.allocate_prospective(17).unwrap();

        assert_eq!(registry.file(prospective).unwrap().native, None);
        registry.bind_native(prospective, native(40)).unwrap();
        registry.bind_native(prospective, native(40)).unwrap();

        assert_eq!(registry.file(prospective).unwrap().native, Some(native(40)));
        assert_eq!(
            registry.file_id_for_native(native(40)).unwrap(),
            prospective
        );
    }

    #[test]
    fn conflicting_native_associations_are_typed_and_do_not_mutate() {
        let mut registry = IdentityRegistry::new();
        let first = registry.allocate_prospective(0).unwrap();
        let second = registry.allocate_prospective(0).unwrap();
        registry.bind_native(first, native(50)).unwrap();

        let before = snapshot(&registry);
        assert_eq!(
            registry.bind_native(first, native(51)),
            Err(RegistryError::FileNativeConflict { file: first })
        );
        assert_eq!(snapshot(&registry), before);

        assert_eq!(
            registry.bind_native(second, native(50)),
            Err(RegistryError::NativeCollision {
                native: native(50),
                existing: first,
                requested: second,
            })
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn namespace_security_and_size_lanes_advance_independently() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 60);
        let initial = registry.file(id).unwrap();
        let namespace = initial.namespace_generation;
        let security = initial.security_generation;
        let size = initial.size_epoch;

        let namespace_effect = registry.advance_namespace(id).unwrap();
        let after_namespace = registry.file(id).unwrap();
        assert_eq!(after_namespace.namespace_generation, namespace_effect.value);
        assert_ne!(after_namespace.namespace_generation, namespace);
        assert_eq!(after_namespace.security_generation, security);
        assert_eq!(after_namespace.size_epoch, size);

        let security_effect = registry.advance_security(id).unwrap();
        let after_security = registry.file(id).unwrap();
        assert_eq!(after_security.security_generation, security_effect.value);
        assert_eq!(after_security.namespace_generation, namespace_effect.value);
        assert_eq!(after_security.size_epoch, size);

        let size_effect = registry.advance_size(id, 61).unwrap();
        let after_size = registry.file(id).unwrap();
        assert_eq!(after_size.size_epoch, size_effect.value);
        assert_eq!(after_size.namespace_generation, namespace_effect.value);
        assert_eq!(after_size.security_generation, security_effect.value);
        assert_eq!(after_size.valid_data_length, 61);
    }

    #[test]
    fn each_successful_backing_effect_allocates_exactly_one_volume_sequence() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 70);
        let child = install_file(&mut registry, 71);
        let installed = install_link(&mut registry, parent, child, "old");

        let namespace = registry.advance_namespace(child).unwrap();
        let security = registry.advance_security(child).unwrap();
        let size = registry.advance_size(child, 1).unwrap();
        let rename = registry
            .rename_link(installed, parent, component("new"), PathBuf::from("new"))
            .unwrap();
        let unlink = registry.unlink_link(installed).unwrap();

        assert_eq!(namespace.volume_sequence, 1);
        assert_eq!(security.volume_sequence, 2);
        assert_eq!(size.volume_sequence, 3);
        assert_eq!(rename.volume_sequence, 4);
        assert_eq!(unlink.volume_sequence, 5);
        assert_eq!(registry.next_volume_sequence, 6);
    }

    #[test]
    fn hard_link_effect_installs_one_binding_and_allocates_one_volume_sequence() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 75);
        let child = install_file(&mut registry, 76);
        let parent_generation = registry.file(parent).unwrap().namespace_generation;
        let child_generation = registry.file(child).unwrap().namespace_generation;

        let effect = registry
            .create_link(parent, child, component("linked"), PathBuf::from("linked"))
            .unwrap();

        assert_ne!(effect.value, LinkId::ZERO);
        assert_eq!(effect.volume_sequence, 1);
        assert_eq!(
            registry
                .link_by_name(parent, &name_key("LINKED"))
                .unwrap()
                .id,
            effect.value
        );
        assert_ne!(
            registry.file(parent).unwrap().namespace_generation,
            parent_generation
        );
        assert_ne!(
            registry.file(child).unwrap().namespace_generation,
            child_generation
        );
        assert_eq!(registry.next_volume_sequence, 2);
    }

    #[test]
    fn rejected_backing_effect_does_not_allocate_a_volume_sequence() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 80);
        let before = registry.next_volume_sequence;

        assert_eq!(
            registry.advance_namespace(file(999)),
            Err(RegistryError::MissingFile(file(999)))
        );
        assert_eq!(registry.next_volume_sequence, before);
        assert!(registry.advance_namespace(id).is_ok());
        assert_eq!(registry.next_volume_sequence, before + 1);
    }

    #[test]
    fn stale_generation_is_distinct_from_missing_identity() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 90);
        let file_record = registry.file(id).unwrap();
        let namespace = file_record.namespace_generation;
        let security = file_record.security_generation;
        let size = file_record.size_epoch;

        assert_eq!(
            registry.expect_namespace_generation(id, namespace + 1),
            Err(RegistryError::StaleGeneration {
                domain: GenerationDomain::Namespace,
                expected: namespace + 1,
                actual: namespace,
            })
        );
        assert_eq!(
            registry.expect_security_generation(id, security + 1),
            Err(RegistryError::StaleGeneration {
                domain: GenerationDomain::Security,
                expected: security + 1,
                actual: security,
            })
        );
        assert_eq!(
            registry.expect_size_epoch(id, size + 1),
            Err(RegistryError::StaleGeneration {
                domain: GenerationDomain::Size,
                expected: size + 1,
                actual: size,
            })
        );
        assert_eq!(
            registry.expect_security_generation(file(999), 1),
            Err(RegistryError::MissingFile(file(999)))
        );
    }

    #[test]
    fn name_collision_leaves_both_link_indexes_unchanged() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 100);
        let child = install_file(&mut registry, 101);
        install_link(&mut registry, parent, child, "same");
        let before = snapshot(&registry);

        assert_eq!(
            registry.install_link(parent, child, component("SAME"), PathBuf::from("SAME")),
            Err(RegistryError::NameCollision { parent })
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn corrupt_reverse_index_is_reported_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 110);
        registry.by_native.insert(native(111), id);
        let before = snapshot(&registry);

        assert_eq!(
            registry.observe_native(native(111), 0),
            Err(RegistryError::CorruptNativeIndex)
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn missing_native_reverse_index_cannot_create_duplicate_file_identity() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 115);
        registry.by_native.remove(&native(115));
        let before = snapshot(&registry);

        assert_eq!(
            registry.observe_native(native(115), 0),
            Err(RegistryError::CorruptNativeIndex)
        );
        assert_eq!(snapshot(&registry), before);
        assert_eq!(registry.files.len(), 1);
        assert_eq!(registry.files.get(&id).unwrap().native, Some(native(115)));
    }

    #[test]
    fn missing_name_reverse_index_cannot_create_duplicate_link_binding() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 116);
        let child = install_file(&mut registry, 117);
        install_link(&mut registry, parent, child, "same");
        registry.by_name.clear();
        let before = snapshot(&registry);

        assert_eq!(
            registry.install_link(parent, child, component("SAME"), PathBuf::from("SAME")),
            Err(RegistryError::CorruptNameIndex)
        );
        assert_eq!(snapshot(&registry), before);
        assert_eq!(registry.links.len(), 1);
    }

    #[test]
    fn zeroed_counter_is_corruption_and_cannot_emit_zero_generation() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 118);
        registry.next_namespace_generation = 0;
        let before = snapshot(&registry);

        assert_eq!(
            registry.advance_namespace(id),
            Err(RegistryError::CorruptCounter(GenerationDomain::Namespace))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn file_id_allocator_refuses_wrap_without_mutation() {
        let mut registry = IdentityRegistry::new();
        registry.next_file_id = u64::MAX;
        let before = snapshot(&registry);

        assert_eq!(
            registry.allocate_prospective(0),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::FileIdentity
            ))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn link_id_allocator_refuses_wrap_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 120);
        let child = install_file(&mut registry, 121);
        registry.next_link_id = u64::MAX;
        let before = snapshot(&registry);

        assert_eq!(
            registry.install_link(parent, child, component("x"), PathBuf::from("x")),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::LinkIdentity
            ))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn namespace_allocator_refuses_wrap_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 130);
        registry.next_namespace_generation = u64::MAX;
        let before = snapshot(&registry);

        assert_eq!(
            registry.advance_namespace(id),
            Err(RegistryError::CounterExhausted(GenerationDomain::Namespace))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn security_allocator_refuses_wrap_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 140);
        registry.next_security_generation = u64::MAX;
        let before = snapshot(&registry);

        assert_eq!(
            registry.advance_security(id),
            Err(RegistryError::CounterExhausted(GenerationDomain::Security))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn security_reservation_finalizes_exactly_one_lane_and_volume_sequence() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 141);
        let before = registry.file(id).unwrap().clone();
        let before_reservation = snapshot(&registry);
        let reservation = registry
            .preflight_security(id, before.security_generation)
            .unwrap();

        assert_eq!(snapshot(&registry), before_reservation);
        let finalized = registry.finalize_security(reservation).unwrap();
        let after = registry.file(id).unwrap();

        assert_eq!(finalized.file, *after);
        assert_eq!(finalized.effect.value, after.security_generation);
        assert_eq!(finalized.effect.volume_sequence, 1);
        assert_ne!(after.security_generation, before.security_generation);
        assert_eq!(after.namespace_generation, before.namespace_generation);
        assert_eq!(after.size_epoch, before.size_epoch);
        assert_eq!(after.valid_data_length, before.valid_data_length);
        assert_eq!(registry.next_volume_sequence, 2);
    }

    #[test]
    fn pinned_security_commit_is_nonmutating_until_its_infallible_tail() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 145);
        let before = snapshot(&registry);
        let generation = registry.file(id).unwrap().security_generation;
        {
            let _aborted = registry.preflight_security_commit(id, generation).unwrap();
        }
        assert_eq!(snapshot(&registry), before);

        let commit = registry.preflight_security_commit(id, generation).unwrap();
        let finalized: SecurityFinalization = commit.commit();
        let after = registry.file(id).unwrap();
        assert_eq!(finalized.file, *after);
        assert_eq!(finalized.effect.value, after.security_generation);
        assert_eq!(finalized.effect.volume_sequence, 1);
        assert_eq!(after.namespace_generation, before.files[0].3);
        assert_eq!(after.size_epoch, before.files[0].5);
        assert_eq!(registry.next_volume_sequence, 2);
    }

    #[test]
    fn stale_duplicate_security_reservation_is_typed_and_nonmutating() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 142);
        let generation = registry.file(id).unwrap().security_generation;
        let first = registry.preflight_security(id, generation).unwrap();
        let duplicate = registry.preflight_security(id, generation).unwrap();

        registry.finalize_security(first).unwrap();
        let committed = snapshot(&registry);
        assert_eq!(
            registry.finalize_security(duplicate),
            Err(RegistryError::StaleGeneration {
                domain: GenerationDomain::Security,
                expected: generation,
                actual: registry.file(id).unwrap().security_generation,
            })
        );
        assert_eq!(snapshot(&registry), committed);
    }

    #[test]
    fn security_finalizer_rejects_changed_file_snapshot_without_rewinding_state() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 144);
        let generation = registry.file(id).unwrap().security_generation;
        let reservation = registry.preflight_security(id, generation).unwrap();
        registry.advance_namespace(id).unwrap();
        let changed = snapshot(&registry);

        assert_eq!(
            registry.finalize_security(reservation),
            Err(RegistryError::CorruptFileRecord)
        );
        assert_eq!(snapshot(&registry), changed);
    }

    #[test]
    fn dropped_and_exhausted_security_reservations_do_not_mutate() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 143);
        let generation = registry.file(id).unwrap().security_generation;
        let before_drop = snapshot(&registry);
        {
            let _released = registry.preflight_security(id, generation).unwrap();
        }
        assert_eq!(snapshot(&registry), before_drop);

        registry.next_security_generation = u64::MAX;
        let before_security_exhaustion = snapshot(&registry);
        assert_eq!(
            registry.preflight_security(id, generation),
            Err(RegistryError::CounterExhausted(GenerationDomain::Security))
        );
        assert_eq!(snapshot(&registry), before_security_exhaustion);

        registry.next_security_generation = generation + 1;
        registry.next_volume_sequence = u64::MAX;
        let before_volume_exhaustion = snapshot(&registry);
        assert_eq!(
            registry.preflight_security(id, generation),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::VolumeSequence
            ))
        );
        assert_eq!(snapshot(&registry), before_volume_exhaustion);
    }

    #[test]
    fn size_allocator_refuses_wrap_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 150);
        registry.next_size_epoch = u64::MAX;
        let before = snapshot(&registry);

        assert_eq!(
            registry.advance_size(id, 99),
            Err(RegistryError::CounterExhausted(GenerationDomain::Size))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn volume_sequence_allocator_refuses_wrap_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 160);
        registry.next_volume_sequence = u64::MAX;
        let before = snapshot(&registry);

        assert_eq!(
            registry.advance_namespace(id),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::VolumeSequence
            ))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn root_installation_preflights_every_counter_before_mutating_indexes() {
        let mut registry = IdentityRegistry::new();
        registry.next_security_generation = u64::MAX;
        let before = snapshot(&registry);

        assert_eq!(
            registry.install_root(native(170), 0),
            Err(RegistryError::CounterExhausted(GenerationDomain::Security))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn link_installation_preflights_every_counter_before_mutating_indexes() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 180);
        let child = install_file(&mut registry, 181);
        registry.next_namespace_generation = u64::MAX;
        let before = snapshot(&registry);

        assert_eq!(
            registry.install_link(parent, child, component("x"), PathBuf::from("x")),
            Err(RegistryError::CounterExhausted(GenerationDomain::Namespace))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn allocator_outputs_are_never_zero_and_never_reused() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 190);
        let first_file = registry.allocate_prospective(0).unwrap();
        let first_link = install_link(&mut registry, parent, first_file, "first");
        registry.unlink_link(first_link).unwrap();
        let second_file = registry.allocate_prospective(0).unwrap();
        let second_link = install_link(&mut registry, parent, second_file, "second");

        assert_ne!(first_file, FileId::ZERO);
        assert_ne!(first_link, LinkId::ZERO);
        assert_ne!(second_file, first_file);
        assert_ne!(second_link, first_link);
    }

    #[test]
    fn native_key_is_unconditional_and_zero_key_is_rejected_without_mutation() {
        let mut registry = IdentityRegistry::new();
        let before = snapshot(&registry);

        assert_eq!(
            registry.observe_native(NativeKey::ZERO, 0),
            Err(RegistryError::InvalidNativeKey)
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn every_lookup_validates_unrelated_file_records_and_native_bijection() {
        let mut registry = IdentityRegistry::new();
        let valid = install_file(&mut registry, 200);
        let corrupt = install_file(&mut registry, 201);
        registry
            .files
            .get_mut(&corrupt)
            .unwrap()
            .security_generation = 0;
        let before = snapshot(&registry);

        assert_eq!(registry.file(valid), Err(RegistryError::CorruptFileRecord));
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn dangling_and_none_native_aliases_are_corruption_before_mutation() {
        let mut dangling = IdentityRegistry::new();
        let existing = install_file(&mut dangling, 202);
        dangling.by_native.insert(native(999), file(999));
        let before = snapshot(&dangling);
        assert_eq!(
            dangling.allocate_prospective(0),
            Err(RegistryError::CorruptNativeIndex)
        );
        assert_eq!(snapshot(&dangling), before);
        assert!(dangling.files.contains_key(&existing));

        let mut none_alias = IdentityRegistry::new();
        let prospective = none_alias.allocate_prospective(0).unwrap();
        none_alias.by_native.insert(native(203), prospective);
        let before = snapshot(&none_alias);
        assert_eq!(
            none_alias.file(prospective),
            Err(RegistryError::CorruptNativeIndex)
        );
        assert_eq!(snapshot(&none_alias), before);
    }

    #[test]
    fn duplicate_native_ownership_is_corruption_before_mutation() {
        let mut registry = IdentityRegistry::new();
        let first = install_file(&mut registry, 204);
        let second = registry.allocate_prospective(0).unwrap();
        registry.files.get_mut(&second).unwrap().native = Some(native(204));
        let before = snapshot(&registry);

        assert_eq!(
            registry.advance_security(first),
            Err(RegistryError::CorruptNativeIndex)
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn file_map_key_id_and_allocator_position_are_validated() {
        let mut bad_id = IdentityRegistry::new();
        let id = install_file(&mut bad_id, 205);
        bad_id.files.get_mut(&id).unwrap().id = file(999);
        let before = snapshot(&bad_id);
        assert_eq!(
            bad_id.file_id_for_native(native(205)),
            Err(RegistryError::CorruptFileRecord)
        );
        assert_eq!(snapshot(&bad_id), before);

        let mut reused_counter = IdentityRegistry::new();
        let id = install_file(&mut reused_counter, 206);
        reused_counter.next_file_id = id.lo;
        let before = snapshot(&reused_counter);
        assert_eq!(
            reused_counter.file(id),
            Err(RegistryError::CorruptCounter(
                GenerationDomain::FileIdentity
            ))
        );
        assert_eq!(snapshot(&reused_counter), before);
    }

    #[test]
    fn link_lookup_distinguishes_missing_name_from_absent_reverse_index() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 210);
        let child = install_file(&mut registry, 211);
        install_link(&mut registry, parent, child, "present");

        assert!(matches!(
            registry.link_by_name(parent, &name_key("absent")),
            Err(RegistryError::MissingName)
        ));

        registry.by_name.remove(&(parent, name_key("present")));
        let before = snapshot(&registry);
        assert_eq!(
            registry.link_by_name(parent, &name_key("present")),
            Err(RegistryError::CorruptNameIndex)
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn dangling_duplicate_and_malformed_link_indexes_are_exact_corruption() {
        use super::LinkRecord;

        let mut dangling = IdentityRegistry::new();
        let parent = install_file(&mut dangling, 212);
        let child = install_file(&mut dangling, 213);
        dangling
            .by_name
            .insert((parent, name_key("dangling")), LinkId { lo: 77, hi: 0 });
        let before = snapshot(&dangling);
        assert_eq!(
            dangling.install_link(parent, child, component("new"), PathBuf::from("new")),
            Err(RegistryError::CorruptNameIndex)
        );
        assert_eq!(snapshot(&dangling), before);

        let mut duplicate = IdentityRegistry::new();
        let parent = install_file(&mut duplicate, 214);
        let child = install_file(&mut duplicate, 215);
        install_link(&mut duplicate, parent, child, "same");
        let duplicate_id = LinkId { lo: 90, hi: 0 };
        duplicate.links.insert(
            duplicate_id,
            LinkRecord {
                id: duplicate_id,
                parent,
                child,
                name: component("SAME"),
                relative_path: PathBuf::from("SAME"),
                namespace_generation: 90,
            },
        );
        duplicate.next_link_id = 91;
        duplicate.next_namespace_generation = 91;
        let before = snapshot(&duplicate);
        assert_eq!(duplicate.file(parent), Err(RegistryError::CorruptNameIndex));
        assert_eq!(snapshot(&duplicate), before);

        let mut malformed = IdentityRegistry::new();
        let parent = install_file(&mut malformed, 216);
        let child = install_file(&mut malformed, 217);
        let id = install_link(&mut malformed, parent, child, "bad");
        malformed.links.get_mut(&id).unwrap().namespace_generation = 0;
        let before = snapshot(&malformed);
        assert_eq!(malformed.file(child), Err(RegistryError::CorruptLinkRecord));
        assert_eq!(snapshot(&malformed), before);
    }

    #[test]
    fn rejected_create_rename_and_unlink_have_exact_unchanged_snapshots() {
        let mut registry = IdentityRegistry::new();
        let old_parent = install_file(&mut registry, 220);
        let new_parent = install_file(&mut registry, 221);
        let child = install_file(&mut registry, 222);
        let source = install_link(&mut registry, old_parent, child, "source");
        install_link(&mut registry, new_parent, child, "occupied");

        let before = snapshot(&registry);
        assert_eq!(
            registry.create_link(
                new_parent,
                child,
                component("OCCUPIED"),
                PathBuf::from("occupied")
            ),
            Err(RegistryError::NameCollision { parent: new_parent })
        );
        assert_eq!(snapshot(&registry), before);

        assert_eq!(
            registry.rename_link(
                source,
                new_parent,
                component("occupied"),
                PathBuf::from("occupied")
            ),
            Err(RegistryError::NameCollision { parent: new_parent })
        );
        assert_eq!(snapshot(&registry), before);

        registry
            .by_name
            .insert((old_parent, name_key("source")), LinkId { lo: 99, hi: 0 });
        let corrupt_before = snapshot(&registry);
        assert_eq!(
            registry.unlink_link(source),
            Err(RegistryError::CorruptNameIndex)
        );
        assert_eq!(snapshot(&registry), corrupt_before);
    }

    #[test]
    fn namespace_generation_assignment_deduplicates_same_file_exactly_once() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 230);
        let start = registry.next_namespace_generation;

        let effect = registry
            .create_link(id, id, component("self"), PathBuf::from("self"))
            .unwrap();

        assert_eq!(
            registry.link(effect.value).unwrap().namespace_generation,
            start
        );
        assert_eq!(registry.file(id).unwrap().namespace_generation, start + 1);
        assert_eq!(registry.next_namespace_generation, start + 2);
    }

    #[test]
    fn cross_parent_rename_assigns_each_namespace_generation_exactly() {
        let mut registry = IdentityRegistry::new();
        let old_parent = install_file(&mut registry, 231);
        let new_parent = install_file(&mut registry, 232);
        let child = install_file(&mut registry, 233);
        let id = install_link(&mut registry, old_parent, child, "old");
        let start = registry.next_namespace_generation;

        registry
            .rename_link(id, new_parent, component("new"), PathBuf::from("new"))
            .unwrap();

        assert_eq!(registry.link(id).unwrap().namespace_generation, start);
        assert_eq!(
            registry.file(child).unwrap().namespace_generation,
            start + 1
        );
        assert_eq!(
            registry.file(old_parent).unwrap().namespace_generation,
            start + 2
        );
        assert_eq!(
            registry.file(new_parent).unwrap().namespace_generation,
            start + 3
        );
        assert_eq!(registry.next_namespace_generation, start + 4);
    }

    #[test]
    fn combined_prospective_bind_and_link_is_one_atomic_effect() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 240);
        let child = registry.allocate_prospective(8).unwrap();
        let start = registry.next_namespace_generation;

        let effect = registry
            .bind_native_and_create_link(
                parent,
                child,
                native(241),
                component("created"),
                PathBuf::from("created"),
            )
            .unwrap();

        assert_eq!(effect.volume_sequence, 1);
        assert_eq!(registry.file(child).unwrap().native, Some(native(241)));
        assert_eq!(registry.file_id_for_native(native(241)).unwrap(), child);
        assert_eq!(
            registry.link(effect.value).unwrap().namespace_generation,
            start
        );
        assert_eq!(
            registry.file(child).unwrap().namespace_generation,
            start + 1
        );
        assert_eq!(
            registry.file(parent).unwrap().namespace_generation,
            start + 2
        );
        assert_eq!(registry.next_namespace_generation, start + 3);
    }

    #[test]
    fn combined_bind_link_preflights_conflicts_and_corruption_without_mutation() {
        let mut native_conflict = IdentityRegistry::new();
        let parent = install_file(&mut native_conflict, 242);
        let owner = install_file(&mut native_conflict, 243);
        let child = native_conflict.allocate_prospective(0).unwrap();
        let before = snapshot(&native_conflict);
        assert_eq!(
            native_conflict.bind_native_and_create_link(
                parent,
                child,
                native(243),
                component("new"),
                PathBuf::from("new")
            ),
            Err(RegistryError::NativeCollision {
                native: native(243),
                existing: owner,
                requested: child,
            })
        );
        assert_eq!(snapshot(&native_conflict), before);

        let mut name_conflict = IdentityRegistry::new();
        let parent = install_file(&mut name_conflict, 244);
        let existing = install_file(&mut name_conflict, 245);
        install_link(&mut name_conflict, parent, existing, "occupied");
        let child = name_conflict.allocate_prospective(0).unwrap();
        let before = snapshot(&name_conflict);
        assert_eq!(
            name_conflict.bind_native_and_create_link(
                parent,
                child,
                native(246),
                component("OCCUPIED"),
                PathBuf::from("occupied")
            ),
            Err(RegistryError::NameCollision { parent })
        );
        assert_eq!(snapshot(&name_conflict), before);

        let mut already_bound = IdentityRegistry::new();
        let parent = install_file(&mut already_bound, 247);
        let child = install_file(&mut already_bound, 248);
        let before = snapshot(&already_bound);
        assert_eq!(
            already_bound.bind_native_and_create_link(
                parent,
                child,
                native(248),
                component("new"),
                PathBuf::from("new")
            ),
            Err(RegistryError::FileNativeConflict { file: child })
        );
        assert_eq!(snapshot(&already_bound), before);

        let mut corrupt = IdentityRegistry::new();
        let parent = install_file(&mut corrupt, 249);
        let child = corrupt.allocate_prospective(0).unwrap();
        corrupt.by_native.insert(native(999), file(999));
        let before = snapshot(&corrupt);
        assert_eq!(
            corrupt.bind_native_and_create_link(
                parent,
                child,
                native(250),
                component("new"),
                PathBuf::from("new")
            ),
            Err(RegistryError::CorruptNativeIndex)
        );
        assert_eq!(snapshot(&corrupt), before);
    }

    #[test]
    fn combined_bind_link_exhausts_each_required_counter_without_mutation() {
        for domain in [
            GenerationDomain::LinkIdentity,
            GenerationDomain::Namespace,
            GenerationDomain::VolumeSequence,
        ] {
            let mut registry = IdentityRegistry::new();
            let parent = install_file(&mut registry, 251);
            let child = registry.allocate_prospective(0).unwrap();
            match domain {
                GenerationDomain::LinkIdentity => registry.next_link_id = u64::MAX,
                GenerationDomain::Namespace => registry.next_namespace_generation = u64::MAX,
                GenerationDomain::VolumeSequence => registry.next_volume_sequence = u64::MAX,
                _ => unreachable!(),
            }
            let before = snapshot(&registry);

            assert_eq!(
                registry.bind_native_and_create_link(
                    parent,
                    child,
                    native(252),
                    component("new"),
                    PathBuf::from("new")
                ),
                Err(RegistryError::CounterExhausted(domain))
            );
            assert_eq!(snapshot(&registry), before);
        }
    }

    #[test]
    fn existing_object_commit_allocates_only_one_volume_sequence() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 260);
        let before = registry.file(id).unwrap();
        let generations = (
            before.namespace_generation,
            before.security_generation,
            before.size_epoch,
            before.valid_data_length,
        );

        let effect = registry.record_existing_effect(id).unwrap();

        assert_eq!(effect.volume_sequence, 1);
        let after = registry.file(id).unwrap();
        assert_eq!(
            (
                after.namespace_generation,
                after.security_generation,
                after.size_epoch,
                after.valid_data_length,
            ),
            generations
        );

        let before = snapshot(&registry);
        assert_eq!(
            registry.record_existing_effect(file(999)),
            Err(RegistryError::MissingFile(file(999)))
        );
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn open_commit_preflights_are_nonmutating_and_match_their_finalizers() {
        let mut registry = IdentityRegistry::new();
        let parent = install_file(&mut registry, 270);
        let child = registry.allocate_prospective(0).unwrap();
        let child_record = registry.file(child).unwrap().clone();
        let parent_generation = registry.file(parent).unwrap().namespace_generation;
        let before = snapshot(&registry);

        let reservation = registry
            .preflight_create_open(
                parent,
                parent_generation,
                child,
                child_record.namespace_generation,
                child_record.security_generation,
                &component("created"),
                Path::new("created"),
            )
            .unwrap();
        assert_eq!(snapshot(&registry), before);
        assert!(reservation.child_links.capacity() >= 1);
        assert_eq!(reservation.by_path_key, reservation.path_by_link_key);

        let effect = registry
            .finalize_create_open(reservation, native(271))
            .unwrap();
        assert_eq!(effect.volume_sequence, 1);
        assert_eq!(registry.file(child).unwrap().native, Some(native(271)));

        let generations = registry.file(child).unwrap().clone();
        let before = snapshot(&registry);
        let reservation = registry
            .preflight_existing_open(
                child,
                generations.namespace_generation,
                generations.security_generation,
                generations.size_epoch,
                ExistingOpenSizeEffect::Preserve,
                ExistingOpenNamespaceEffect::Preserve,
            )
            .unwrap();
        assert_eq!(snapshot(&registry), before);
        let effect = registry.finalize_existing_open(reservation);
        assert_eq!(effect.volume_sequence, 2);
        assert_eq!(
            registry.file(child).unwrap().size_epoch,
            generations.size_epoch
        );
    }

    #[test]
    fn open_commit_preflight_rejects_stale_collision_corruption_and_counters() {
        let mut stale = IdentityRegistry::new();
        let parent = install_file(&mut stale, 280);
        let child = stale.allocate_prospective(0).unwrap();
        let child_record = stale.file(child).unwrap().clone();
        let before = snapshot(&stale);
        assert!(matches!(
            stale.preflight_create_open(
                parent,
                stale.file(parent).unwrap().namespace_generation + 1,
                child,
                child_record.namespace_generation,
                child_record.security_generation,
                &component("new"),
                Path::new("new"),
            ),
            Err(RegistryError::StaleGeneration { .. })
        ));
        assert_eq!(snapshot(&stale), before);

        let owner = install_file(&mut stale, 281);
        install_link(&mut stale, parent, owner, "occupied");
        let before = snapshot(&stale);
        assert!(matches!(
            stale.preflight_create_open(
                parent,
                stale.file(parent).unwrap().namespace_generation,
                child,
                child_record.namespace_generation,
                child_record.security_generation,
                &component("occupied"),
                Path::new("occupied"),
            ),
            Err(RegistryError::NameCollision { parent: _ })
        ));
        assert_eq!(snapshot(&stale), before);

        let mut exhausted = IdentityRegistry::new();
        let existing = install_file(&mut exhausted, 282);
        let record = exhausted.file(existing).unwrap().clone();
        exhausted.next_volume_sequence = u64::MAX;
        let before = snapshot(&exhausted);
        assert!(matches!(
            exhausted.preflight_existing_open(
                existing,
                record.namespace_generation,
                record.security_generation,
                record.size_epoch,
                ExistingOpenSizeEffect::Preserve,
                ExistingOpenNamespaceEffect::Preserve,
            ),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::VolumeSequence
            ))
        ));
        assert_eq!(snapshot(&exhausted), before);

        let mut corrupt = IdentityRegistry::new();
        let existing = install_file(&mut corrupt, 283);
        let record = corrupt.file(existing).unwrap().clone();
        corrupt.by_native.clear();
        let before = snapshot(&corrupt);
        assert!(matches!(
            corrupt.preflight_existing_open(
                existing,
                record.namespace_generation,
                record.security_generation,
                record.size_epoch,
                ExistingOpenSizeEffect::Preserve,
                ExistingOpenNamespaceEffect::Preserve,
            ),
            Err(RegistryError::CorruptNativeIndex)
        ));
        assert_eq!(snapshot(&corrupt), before);
    }

    #[test]
    fn existing_open_reservation_preserves_or_advances_size_state_by_disposition() {
        let mut preserve = IdentityRegistry::new();
        let id = install_file(&mut preserve, 284);
        let record = preserve.file(id).unwrap().clone();
        let before = snapshot(&preserve);
        let reservation = preserve
            .preflight_existing_open(
                id,
                record.namespace_generation,
                record.security_generation,
                record.size_epoch,
                ExistingOpenSizeEffect::Preserve,
                ExistingOpenNamespaceEffect::Preserve,
            )
            .unwrap();
        assert_eq!(snapshot(&preserve), before);
        let effect = preserve.finalize_existing_open(reservation);
        let final_record = preserve.file(id).unwrap();
        assert_eq!(effect.volume_sequence, 1);
        assert_eq!(final_record.valid_data_length, record.valid_data_length);
        assert_eq!(final_record.size_epoch, record.size_epoch);

        let mut truncate = IdentityRegistry::new();
        let id = install_file(&mut truncate, 285);
        let record = truncate.file(id).unwrap().clone();
        let reservation = truncate
            .preflight_existing_open(
                id,
                record.namespace_generation,
                record.security_generation,
                record.size_epoch,
                ExistingOpenSizeEffect::Truncate,
                ExistingOpenNamespaceEffect::Preserve,
            )
            .unwrap();
        let effect = truncate.finalize_existing_open(reservation);
        let final_record = truncate.file(id).unwrap();
        assert_eq!(effect.volume_sequence, 1);
        assert_eq!(final_record.valid_data_length, 0);
        assert_eq!(final_record.size_epoch, record.size_epoch + 1);
    }

    #[test]
    fn truncating_existing_open_exhausts_size_counter_before_any_mutation() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 286);
        let record = registry.file(id).unwrap().clone();
        registry.next_size_epoch = u64::MAX;
        let before = snapshot(&registry);

        assert!(matches!(
            registry.preflight_existing_open(
                id,
                record.namespace_generation,
                record.security_generation,
                record.size_epoch,
                ExistingOpenSizeEffect::Truncate,
                ExistingOpenNamespaceEffect::Preserve,
            ),
            Err(RegistryError::CounterExhausted(GenerationDomain::Size))
        ));
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn existing_open_namespace_reservation_advances_once_or_preserves_exactly() {
        let mut changed = IdentityRegistry::new();
        let id = install_file(&mut changed, 287);
        let record = changed.file(id).unwrap().clone();
        let assigned_namespace = changed.next_namespace_generation;
        let before = snapshot(&changed);
        let reservation = changed
            .preflight_existing_open(
                id,
                record.namespace_generation,
                record.security_generation,
                record.size_epoch,
                ExistingOpenSizeEffect::Truncate,
                ExistingOpenNamespaceEffect::Advance,
            )
            .unwrap();
        assert_eq!(snapshot(&changed), before);
        let effect = changed.finalize_existing_open(reservation);
        assert_eq!(effect.volume_sequence, 1);
        assert_eq!(
            changed.file(id).unwrap().namespace_generation,
            assigned_namespace
        );
        assert_eq!(changed.next_namespace_generation, assigned_namespace + 1);

        let mut preserved = IdentityRegistry::new();
        let id = install_file(&mut preserved, 288);
        let record = preserved.file(id).unwrap().clone();
        preserved.next_namespace_generation = u64::MAX;
        let reservation = preserved
            .preflight_existing_open(
                id,
                record.namespace_generation,
                record.security_generation,
                record.size_epoch,
                ExistingOpenSizeEffect::Preserve,
                ExistingOpenNamespaceEffect::Preserve,
            )
            .unwrap();
        preserved.finalize_existing_open(reservation);
        assert_eq!(
            preserved.file(id).unwrap().namespace_generation,
            record.namespace_generation
        );
        assert_eq!(preserved.next_namespace_generation, u64::MAX);
    }

    #[test]
    fn existing_open_namespace_exhaustion_is_preflight_nonmutating() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 289);
        let record = registry.file(id).unwrap().clone();
        registry.next_namespace_generation = u64::MAX;
        let before = snapshot(&registry);

        assert!(matches!(
            registry.preflight_existing_open(
                id,
                record.namespace_generation,
                record.security_generation,
                record.size_epoch,
                ExistingOpenSizeEffect::Truncate,
                ExistingOpenNamespaceEffect::Advance,
            ),
            Err(RegistryError::CounterExhausted(GenerationDomain::Namespace))
        ));
        assert_eq!(snapshot(&registry), before);
    }

    #[test]
    fn positive_write_without_size_change_keeps_epoch_but_gets_sequence() {
        let mut registry = IdentityRegistry::new();
        let id = registry.observe_native(native(261), 12).unwrap();
        let expected = registry.file(id).unwrap().size_epoch;
        registry.next_size_epoch = u64::MAX;

        let reservation = registry
            .preflight_write(id, expected, false)
            .expect("in-place write does not reserve a size epoch");
        let effect = registry.finalize_write(reservation, None).unwrap().effect;

        assert_eq!(effect.volume_sequence, 1);
        assert!(!effect.size_changed);
        assert_eq!(effect.size_epoch, expected);
        assert_eq!(effect.valid_data_length, 12);
        assert_eq!(registry.next_size_epoch, u64::MAX);
    }

    #[test]
    fn write_with_size_change_advances_epoch_and_returns_final_size_state() {
        let mut registry = IdentityRegistry::new();
        let id = registry.observe_native(native(262), 12).unwrap();
        let expected = registry.file(id).unwrap().size_epoch;

        let reservation = registry
            .preflight_write(id, expected, true)
            .expect("size-changing write reserves all counters");
        let finalized = registry.finalize_write(reservation, Some(19)).unwrap();
        let effect = finalized.effect;

        assert_eq!(effect.volume_sequence, 1);
        assert!(effect.size_changed);
        assert_ne!(effect.size_epoch, expected);
        assert_eq!(effect.valid_data_length, 19);
        assert_eq!(&finalized.file, registry.file(id).unwrap());
        assert_eq!(registry.file(id).unwrap().size_epoch, effect.size_epoch);
        assert_eq!(registry.file(id).unwrap().valid_data_length, 19);
    }

    #[test]
    fn unused_write_size_reservation_does_not_consume_the_epoch() {
        let mut registry = IdentityRegistry::new();
        let id = registry.observe_native(native(266), 12).unwrap();
        let expected = registry.file(id).unwrap().size_epoch;
        let next_size_before = registry.next_size_epoch;

        let reservation = registry
            .preflight_write(id, expected, true)
            .expect("requested maximum extent may change size");
        let effect = registry.finalize_write(reservation, None).unwrap().effect;

        assert!(!effect.size_changed);
        assert_eq!(effect.size_epoch, expected);
        assert_eq!(registry.next_size_epoch, next_size_before);
        assert_eq!(effect.volume_sequence, 1);
    }

    #[test]
    fn stale_write_reservation_is_typed_corruption_without_state_rewind() {
        let mut registry = IdentityRegistry::new();
        let id = registry.observe_native(native(267), 12).unwrap();
        let expected = registry.file(id).unwrap().size_epoch;
        let first = registry.preflight_write(id, expected, false).unwrap();
        let stale = registry.preflight_write(id, expected, false).unwrap();

        let first_finalized = registry
            .finalize_write(first, None)
            .expect("first reservation finalizes");
        let after_first = snapshot(&registry);
        assert_eq!(first_finalized.effect.volume_sequence, 1);

        assert_eq!(
            registry.finalize_write(stale, None),
            Err(RegistryError::CorruptCounter(
                GenerationDomain::VolumeSequence
            ))
        );
        assert_eq!(snapshot(&registry), after_first);
    }

    #[test]
    fn write_finalizer_rejects_exact_record_and_size_counter_changes_nonmutatingly() {
        let mut changed_vdl = IdentityRegistry::new();
        let id = changed_vdl.observe_native(native(268), 12).unwrap();
        let expected = changed_vdl.file(id).unwrap().size_epoch;
        let reservation = changed_vdl.preflight_write(id, expected, true).unwrap();
        changed_vdl.files.get_mut(&id).unwrap().valid_data_length = 11;
        let before = snapshot(&changed_vdl);
        assert_eq!(
            changed_vdl.finalize_write(reservation, Some(19)),
            Err(RegistryError::CorruptFileRecord)
        );
        assert_eq!(snapshot(&changed_vdl), before);

        let mut changed_native = IdentityRegistry::new();
        let id = changed_native.observe_native(native(270), 12).unwrap();
        let expected = changed_native.file(id).unwrap().size_epoch;
        let reservation = changed_native.preflight_write(id, expected, true).unwrap();
        changed_native.files.get_mut(&id).unwrap().native = Some(native(271));
        let before = snapshot(&changed_native);
        assert_eq!(
            changed_native.finalize_write(reservation, Some(19)),
            Err(RegistryError::CorruptFileRecord)
        );
        assert_eq!(snapshot(&changed_native), before);

        let mut changed_epoch = IdentityRegistry::new();
        let id = changed_epoch.observe_native(native(272), 12).unwrap();
        let expected = changed_epoch.file(id).unwrap().size_epoch;
        let reservation = changed_epoch.preflight_write(id, expected, true).unwrap();
        changed_epoch.files.get_mut(&id).unwrap().size_epoch += 1;
        let before = snapshot(&changed_epoch);
        assert_eq!(
            changed_epoch.finalize_write(reservation, Some(19)),
            Err(RegistryError::CorruptFileRecord)
        );
        assert_eq!(snapshot(&changed_epoch), before);

        let mut changed_counter = IdentityRegistry::new();
        let id = changed_counter.observe_native(native(269), 12).unwrap();
        let expected = changed_counter.file(id).unwrap().size_epoch;
        let reservation = changed_counter.preflight_write(id, expected, true).unwrap();
        changed_counter.next_size_epoch += 1;
        let before = snapshot(&changed_counter);
        assert_eq!(
            changed_counter.finalize_write(reservation, Some(19)),
            Err(RegistryError::CorruptCounter(GenerationDomain::Size))
        );
        assert_eq!(snapshot(&changed_counter), before);
    }

    #[test]
    fn write_preflights_expected_epoch_and_both_allocators_without_mutation() {
        let mut stale = IdentityRegistry::new();
        let id = install_file(&mut stale, 263);
        let actual = stale.file(id).unwrap().size_epoch;
        let stale_expected = actual + 1;
        let before = snapshot(&stale);
        assert!(matches!(
            stale.preflight_write(id, stale_expected, false),
            Err(RegistryError::StaleGeneration {
                domain: GenerationDomain::Size,
                expected,
                actual: observed,
            }) if expected == stale_expected && observed == actual
        ));
        assert_eq!(snapshot(&stale), before);

        let mut size_full = IdentityRegistry::new();
        let id = install_file(&mut size_full, 264);
        let expected = size_full.file(id).unwrap().size_epoch;
        size_full.next_size_epoch = u64::MAX;
        let before = snapshot(&size_full);
        assert!(matches!(
            size_full.preflight_write(id, expected, true),
            Err(RegistryError::CounterExhausted(GenerationDomain::Size))
        ));
        assert_eq!(snapshot(&size_full), before);

        let mut volume_full = IdentityRegistry::new();
        let id = install_file(&mut volume_full, 265);
        let expected = volume_full.file(id).unwrap().size_epoch;
        volume_full.next_volume_sequence = u64::MAX;
        let before = snapshot(&volume_full);
        assert!(matches!(
            volume_full.preflight_write(id, expected, true),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::VolumeSequence
            ))
        ));
        assert_eq!(snapshot(&volume_full), before);
    }

    #[test]
    fn metadata_commit_is_infallible_and_advances_only_namespace_and_volume() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 272);
        let before = registry.file(id).unwrap().clone();
        let commit = registry
            .preflight_metadata_commit(id, before.namespace_generation)
            .unwrap();
        let finalized = commit.commit();
        let after = registry.file(id).unwrap();

        assert!(after.namespace_generation > before.namespace_generation);
        assert_eq!(finalized.file, *after);
        assert_eq!(finalized.effect.value, after.namespace_generation);
        assert_eq!(finalized.effect.volume_sequence, 1);
        assert_eq!(after.security_generation, before.security_generation);
        assert_eq!(after.size_epoch, before.size_epoch);
        assert_eq!(after.valid_data_length, before.valid_data_length);
    }

    #[test]
    fn metadata_commit_preflights_stale_and_each_counter_without_mutation() {
        let mut stale = IdentityRegistry::new();
        let id = install_file(&mut stale, 273);
        let actual = stale.file(id).unwrap().namespace_generation;
        let before = snapshot(&stale);
        assert!(matches!(
            stale.preflight_metadata_commit(id, actual + 1),
            Err(RegistryError::StaleGeneration {
                domain: GenerationDomain::Namespace,
                ..
            })
        ));
        assert_eq!(snapshot(&stale), before);

        let mut namespace_full = IdentityRegistry::new();
        let id = install_file(&mut namespace_full, 274);
        let expected = namespace_full.file(id).unwrap().namespace_generation;
        namespace_full.next_namespace_generation = u64::MAX;
        let before = snapshot(&namespace_full);
        assert!(matches!(
            namespace_full.preflight_metadata_commit(id, expected),
            Err(RegistryError::CounterExhausted(GenerationDomain::Namespace))
        ));
        assert_eq!(snapshot(&namespace_full), before);

        let mut volume_full = IdentityRegistry::new();
        let id = install_file(&mut volume_full, 275);
        let expected = volume_full.file(id).unwrap().namespace_generation;
        volume_full.next_volume_sequence = u64::MAX;
        let before = snapshot(&volume_full);
        assert!(matches!(
            volume_full.preflight_metadata_commit(id, expected),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::VolumeSequence
            ))
        ));
        assert_eq!(snapshot(&volume_full), before);
    }

    #[test]
    fn size_commit_is_infallible_and_advances_only_size_and_volume() {
        let mut registry = IdentityRegistry::new();
        let id = install_file(&mut registry, 276);
        let before = registry.file(id).unwrap().clone();
        let commit = registry
            .preflight_size_commit(id, before.size_epoch)
            .unwrap();
        let finalized = commit.commit(7);
        let after = registry.file(id).unwrap();

        assert!(after.size_epoch > before.size_epoch);
        assert_eq!(after.valid_data_length, 7);
        assert_eq!(finalized.file, *after);
        assert_eq!(finalized.effect.size_epoch, after.size_epoch);
        assert_eq!(finalized.effect.volume_sequence, 1);
        assert_eq!(after.namespace_generation, before.namespace_generation);
        assert_eq!(after.security_generation, before.security_generation);
    }

    #[test]
    fn size_commit_preflights_stale_and_each_counter_without_mutation() {
        let mut stale = IdentityRegistry::new();
        let id = install_file(&mut stale, 277);
        let actual = stale.file(id).unwrap().size_epoch;
        let before = snapshot(&stale);
        assert!(matches!(
            stale.preflight_size_commit(id, actual + 1),
            Err(RegistryError::StaleGeneration {
                domain: GenerationDomain::Size,
                ..
            })
        ));
        assert_eq!(snapshot(&stale), before);

        let mut size_full = IdentityRegistry::new();
        let id = install_file(&mut size_full, 278);
        let expected = size_full.file(id).unwrap().size_epoch;
        size_full.next_size_epoch = u64::MAX;
        let before = snapshot(&size_full);
        assert!(matches!(
            size_full.preflight_size_commit(id, expected),
            Err(RegistryError::CounterExhausted(GenerationDomain::Size))
        ));
        assert_eq!(snapshot(&size_full), before);

        let mut volume_full = IdentityRegistry::new();
        let id = install_file(&mut volume_full, 279);
        let expected = volume_full.file(id).unwrap().size_epoch;
        volume_full.next_volume_sequence = u64::MAX;
        let before = snapshot(&volume_full);
        assert!(matches!(
            volume_full.preflight_size_commit(id, expected),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::VolumeSequence
            ))
        ));
        assert_eq!(snapshot(&volume_full), before);
    }

    #[test]
    fn zero_counter_in_every_lane_is_corruption_without_mutation() {
        for domain in [
            GenerationDomain::FileIdentity,
            GenerationDomain::LinkIdentity,
            GenerationDomain::Namespace,
            GenerationDomain::Security,
            GenerationDomain::Size,
            GenerationDomain::VolumeSequence,
        ] {
            let mut registry = IdentityRegistry::new();
            let parent = install_file(&mut registry, 270);
            let child = registry.allocate_prospective(0).unwrap();
            match domain {
                GenerationDomain::FileIdentity => registry.next_file_id = 0,
                GenerationDomain::LinkIdentity => registry.next_link_id = 0,
                GenerationDomain::Namespace => registry.next_namespace_generation = 0,
                GenerationDomain::Security => registry.next_security_generation = 0,
                GenerationDomain::Size => registry.next_size_epoch = 0,
                GenerationDomain::VolumeSequence => registry.next_volume_sequence = 0,
            }
            let before = snapshot(&registry);

            let error = match domain {
                GenerationDomain::FileIdentity => registry.allocate_prospective(0).unwrap_err(),
                GenerationDomain::LinkIdentity => registry
                    .install_link(parent, child, component("new"), PathBuf::from("new"))
                    .unwrap_err(),
                GenerationDomain::Namespace => registry.advance_namespace(parent).unwrap_err(),
                GenerationDomain::Security => registry.advance_security(parent).unwrap_err(),
                GenerationDomain::Size => registry.advance_size(parent, 1).unwrap_err(),
                GenerationDomain::VolumeSequence => {
                    registry.record_existing_effect(parent).unwrap_err()
                }
            };
            assert_eq!(error, RegistryError::CorruptCounter(domain));
            assert_eq!(snapshot(&registry), before);
        }
    }

    #[test]
    fn create_rename_and_unlink_counter_rejections_are_exactly_nonmutating() {
        let mut create = IdentityRegistry::new();
        let parent = install_file(&mut create, 280);
        let child = install_file(&mut create, 281);
        create.next_volume_sequence = u64::MAX;
        let before = snapshot(&create);
        assert_eq!(
            create.create_link(parent, child, component("new"), PathBuf::from("new")),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::VolumeSequence
            ))
        );
        assert_eq!(snapshot(&create), before);

        let mut rename = IdentityRegistry::new();
        let parent = install_file(&mut rename, 282);
        let child = install_file(&mut rename, 283);
        let link = install_link(&mut rename, parent, child, "old");
        rename.next_namespace_generation = u64::MAX;
        let before = snapshot(&rename);
        assert_eq!(
            rename.rename_link(link, parent, component("new"), PathBuf::from("new")),
            Err(RegistryError::CounterExhausted(GenerationDomain::Namespace))
        );
        assert_eq!(snapshot(&rename), before);

        let mut unlink = IdentityRegistry::new();
        let parent = install_file(&mut unlink, 284);
        let child = install_file(&mut unlink, 285);
        let link = install_link(&mut unlink, parent, child, "old");
        unlink.next_volume_sequence = u64::MAX;
        let before = snapshot(&unlink);
        assert_eq!(
            unlink.unlink_link(link),
            Err(RegistryError::CounterExhausted(
                GenerationDomain::VolumeSequence
            ))
        );
        assert_eq!(snapshot(&unlink), before);
    }
}
