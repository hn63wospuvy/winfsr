//! Pure ABI 2.1 query-side validators.
//!
//! Query layouts live in `msgs::query`; this module validates their wire
//! structure and numeric relations on caller-owned snapshots. It performs no
//! Unicode normalization, upcasing, or wildcard matching.

use core::mem::size_of;

use crate::{
    codec::try_decode,
    features::{protocol_feature, FeatureSet},
    limits::{MAX_CANONICAL_DIR_ENTRY_BYTES, MAX_COMPONENT_UTF16_CODE_UNITS, MAX_CONTROL_BLOB},
    msgs::{
        buffer_access, file_attributes, query_dir_flags, query_dir_result_flags, query_info_class,
        query_volume_class, security_information, BufferRef, ControlHeader, DirEntryV1, FileInfoV1,
        FsctlV1, QueryDirResultV1, QueryDirV2, QueryInfoV1, QuerySecurityV1, QueryVolumeV1,
        VolumeSizeInfoV1, CONTROL_VERSION_V1, CONTROL_VERSION_V2,
    },
    slots::{
        validate_buffer_ref, BufferRefError, BufferRefPolicy, BufferRefRule, EmptyBufferRule,
        ValidatedBuffer,
    },
};

use super::control::ControlError;
use super::messages::{
    validate_size_state_v21, validate_stored_component_utf16, GrantBindingV21,
    MessageValidationError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryValidationError {
    Message(MessageValidationError),
    EntryAlignment,
    EntryOverrun,
    EntryCount,
    NameBounds,
    CookieSuccessor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryDirFormV21 {
    InitialMatchAll,
    InitialExpression { exact_pattern: bool },
    Continuation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireFormV21 {
    RecoveryRequest,
    JournalV1Attach,
    MappedRwFlag,
    MappingBufferKind,
    ReparseMutation,
    ReparseAttribute,
    SparseMutation,
    PtDonation,
    PtNotification,
    QuerySecurityRequest,
    SetSecurityMutation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedQueryDirResultV1 {
    entry_count: u32,
    next_cookie: u64,
    eof: bool,
}

impl ValidatedQueryDirResultV1 {
    pub const fn entry_count(&self) -> u32 {
        self.entry_count
    }

    pub const fn next_cookie(&self) -> u64 {
        self.next_cookie
    }

    pub const fn eof(&self) -> bool {
        self.eof
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedQueryDirV2 {
    output: ValidatedBuffer,
    form: QueryDirFormV21,
}

impl ValidatedQueryDirV2 {
    pub const fn output(&self) -> ValidatedBuffer {
        self.output
    }

    pub const fn form(&self) -> QueryDirFormV21 {
        self.form
    }
}

fn validate_query_header(
    header: ControlHeader,
    version: u16,
    size: usize,
) -> Result<(), MessageValidationError> {
    if header.struct_version != version {
        return Err(MessageValidationError::Control(
            ControlError::RevisionMismatch,
        ));
    }
    if header.required_flags != 0 {
        return Err(MessageValidationError::Control(
            ControlError::UnsupportedRequiredFlags,
        ));
    }
    if usize::try_from(header.struct_size).ok() != Some(size) {
        return Err(MessageValidationError::Control(ControlError::InvalidSize));
    }
    Ok(())
}

fn validate_output(
    reference: &BufferRef,
    binding: GrantBindingV21<'_>,
) -> Result<ValidatedBuffer, MessageValidationError> {
    let value = validate_buffer_ref(
        reference,
        &BufferRefRule::Grant {
            grant: binding.grant,
            expected_session_epoch: binding.expected_session_epoch,
            expected_owner: binding.expected_owner,
            policy: BufferRefPolicy::Exact,
            empty: EmptyBufferRule::Forbidden,
        },
    )
    .map_err(MessageValidationError::Grant)?;
    if reference.access != buffer_access::U2K_WRITE {
        return Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch,
        ));
    }
    Ok(value)
}

pub fn validate_query_info_v1(
    request: &QueryInfoV1,
    output: GrantBindingV21<'_>,
) -> Result<ValidatedBuffer, MessageValidationError> {
    validate_query_header(request.header, CONTROL_VERSION_V1, size_of::<QueryInfoV1>())?;
    if request.flags != 0 || request.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if request.info_class != query_info_class::CANONICAL {
        return Err(MessageValidationError::InvalidScalar);
    }
    let value = validate_output(&request.output, output)?;
    if request.output.length < 104 {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(value)
}

pub fn validate_query_volume_v1(
    request: &QueryVolumeV1,
    output: GrantBindingV21<'_>,
) -> Result<ValidatedBuffer, MessageValidationError> {
    validate_query_header(
        request.header,
        CONTROL_VERSION_V1,
        size_of::<QueryVolumeV1>(),
    )?;
    if request.flags != 0 || request.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if request.info_class != query_volume_class::SIZE {
        return Err(MessageValidationError::InvalidScalar);
    }
    let value = validate_output(&request.output, output)?;
    if request.output.length < 40 {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(value)
}

pub fn validate_query_security_v1(
    request: &QuerySecurityV1,
    output: GrantBindingV21<'_>,
) -> Result<ValidatedBuffer, MessageValidationError> {
    validate_query_header(
        request.header,
        CONTROL_VERSION_V1,
        size_of::<QuerySecurityV1>(),
    )?;
    if request.flags != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if request.security_information == 0
        || request.security_information & !security_information::QUERY_ACCEPTED_MASK != 0
    {
        return Err(MessageValidationError::InvalidScalar);
    }
    let value = validate_output(&request.output, output)?;
    if request.output.length != 65_536 {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(value)
}

pub fn validate_dir_pattern_utf16(bytes: &[u8]) -> Result<bool, MessageValidationError> {
    if bytes.is_empty()
        || bytes.len() % 2 != 0
        || bytes.len() > (MAX_COMPONENT_UTF16_CODE_UNITS as usize) * 2
    {
        return Err(MessageValidationError::InvalidScalar);
    }
    let count = bytes.len() / 2;
    let mut index = 0;
    let mut wildcard_seen = false;
    while index < count {
        let unit = u16::from_le_bytes([bytes[2 * index], bytes[2 * index + 1]]);
        match unit {
            0x0000 | 0x002f | 0x003a | 0x005c => {
                return Err(MessageValidationError::InvalidScalar);
            }
            0x0022 | 0x002a | 0x003c | 0x003e | 0x003f => {
                wildcard_seen = true;
            }
            0xd800..=0xdbff => {
                if index + 1 >= count {
                    return Err(MessageValidationError::InvalidScalar);
                }
                let low = u16::from_le_bytes([bytes[2 * (index + 1)], bytes[2 * (index + 1) + 1]]);
                if !(0xdc00..=0xdfff).contains(&low) {
                    return Err(MessageValidationError::InvalidScalar);
                }
                index += 1;
            }
            0xdc00..=0xdfff => {
                return Err(MessageValidationError::InvalidScalar);
            }
            _ => {}
        }
        index += 1;
    }
    Ok(!wildcard_seen)
}

pub fn validate_query_dir_v2(
    request: &QueryDirV2,
    blob: &[u8],
    output: GrantBindingV21<'_>,
) -> Result<ValidatedQueryDirV2, QueryValidationError> {
    if request.header.struct_version != CONTROL_VERSION_V2 {
        return Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ));
    }
    if request.header.required_flags != 0 {
        return Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags),
        ));
    }
    if usize::try_from(request.header.struct_size).ok() != Some(blob.len()) || blob.len() < 64 {
        return Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::InvalidSize),
        ));
    }
    if request.flags & !query_dir_flags::ALL != 0 || request.reserved != 0 {
        return Err(QueryValidationError::Message(
            MessageValidationError::FlagsOrReserved,
        ));
    }
    if request.enumeration_generation == 0 {
        return Err(QueryValidationError::Message(
            MessageValidationError::Identity,
        ));
    }
    let restart = request.flags & query_dir_flags::RESTART != 0;
    let exact_flag = request.flags & query_dir_flags::EXACT_PATTERN != 0;
    let form = if restart {
        if request.enumeration_cookie != 0 {
            return Err(QueryValidationError::Message(
                MessageValidationError::Relationship,
            ));
        }
        if request.pattern.offset == 0 && request.pattern.length == 0 {
            if blob.len() != 64 || exact_flag {
                return Err(QueryValidationError::Message(
                    MessageValidationError::Relationship,
                ));
            }
            QueryDirFormV21::InitialMatchAll
        } else {
            if request.pattern.offset != 64 || request.pattern.length == 0 {
                return Err(QueryValidationError::Message(
                    MessageValidationError::Relationship,
                ));
            }
            // The align8 arithmetic stays in u64 so an adversarial pattern
            // length cannot overflow a 32-bit usize before the equality check.
            let unpadded64 = 64u64 + u64::from(request.pattern.length);
            let padded64 = unpadded64.div_ceil(8) * 8;
            if blob.len() as u64 != padded64 {
                return Err(QueryValidationError::Message(
                    MessageValidationError::Control(ControlError::InvalidSize),
                ));
            }
            let unpadded = blob.len() - ((padded64 - unpadded64) as usize);
            let mut index = unpadded;
            while index < blob.len() {
                if blob[index] != 0 {
                    return Err(QueryValidationError::Message(
                        MessageValidationError::InvalidScalar,
                    ));
                }
                index += 1;
            }
            let exact = validate_dir_pattern_utf16(&blob[64..unpadded])
                .map_err(QueryValidationError::Message)?;
            if exact != exact_flag {
                return Err(QueryValidationError::Message(
                    MessageValidationError::Relationship,
                ));
            }
            QueryDirFormV21::InitialExpression {
                exact_pattern: exact,
            }
        }
    } else {
        if request.enumeration_cookie == 0 {
            return Err(QueryValidationError::Message(
                MessageValidationError::Identity,
            ));
        }
        if exact_flag {
            return Err(QueryValidationError::Message(
                MessageValidationError::FlagsOrReserved,
            ));
        }
        if request.pattern.offset != 0 || request.pattern.length != 0 || blob.len() != 64 {
            return Err(QueryValidationError::Message(
                MessageValidationError::Relationship,
            ));
        }
        QueryDirFormV21::Continuation
    };
    let output_value =
        validate_output(&request.output, output).map_err(QueryValidationError::Message)?;
    if request.output.length < 40 || request.output.length > MAX_CONTROL_BLOB {
        return Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar,
        ));
    }
    Ok(ValidatedQueryDirV2 {
        output: output_value,
        form,
    })
}

fn validate_dir_entry(
    entry: &DirEntryV1,
    blob: &[u8],
    cursor: usize,
) -> Result<(), QueryValidationError> {
    if entry.header.struct_version != 1 {
        return Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ));
    }
    if entry.header.required_flags != 0 {
        return Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags),
        ));
    }
    if entry.header.struct_size % 8 != 0 {
        return Err(QueryValidationError::EntryAlignment);
    }
    let struct_size = entry.header.struct_size as usize;
    let end = match cursor.checked_add(struct_size) {
        Some(end) => end,
        None => return Err(QueryValidationError::EntryOverrun),
    };
    if struct_size < 136 || end > blob.len() {
        return Err(QueryValidationError::EntryOverrun);
    }
    if entry.name.offset != 136 || entry.name.length == 0 {
        return Err(QueryValidationError::NameBounds);
    }
    // The align8 arithmetic stays in u64 so an adversarial name length cannot
    // overflow a 32-bit usize before the equality check; afterwards the name
    // length is bounded by the 648-byte canonical entry cap.
    let unpadded64 = 136u64 + u64::from(entry.name.length);
    let padded64 = unpadded64.div_ceil(8) * 8;
    if u64::from(entry.header.struct_size) != padded64
        || entry.header.struct_size > MAX_CANONICAL_DIR_ENTRY_BYTES
    {
        return Err(QueryValidationError::NameBounds);
    }
    let name_length = entry.name.length as usize;
    if entry.flags != 0 || entry.reserved != 0 {
        return Err(QueryValidationError::Message(
            MessageValidationError::FlagsOrReserved,
        ));
    }
    if (entry.file_id.lo == 0 && entry.file_id.hi == 0)
        || (entry.link_id.lo == 0 && entry.link_id.hi == 0)
        || entry.namespace_generation == 0
    {
        return Err(QueryValidationError::Message(
            MessageValidationError::Identity,
        ));
    }
    if entry.attributes & !file_attributes::ACCEPTED_MASK_V21 != 0
        || (entry.attributes & file_attributes::NORMAL != 0
            && entry.attributes != file_attributes::NORMAL)
    {
        return Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar,
        ));
    }
    if entry.reparse_tag != 0 {
        return Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar,
        ));
    }
    if entry.creation_time < 0
        || entry.last_access_time < 0
        || entry.last_write_time < 0
        || entry.change_time < 0
    {
        return Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar,
        ));
    }
    validate_size_state_v21(entry.sizes).map_err(QueryValidationError::Message)?;
    let name_start = cursor + 136;
    validate_stored_component_utf16(&blob[name_start..name_start + name_length])
        .map_err(QueryValidationError::Message)?;
    let mut index = name_start + name_length;
    while index < end {
        if blob[index] != 0 {
            return Err(QueryValidationError::Message(
                MessageValidationError::InvalidScalar,
            ));
        }
        index += 1;
    }
    Ok(())
}

pub fn validate_query_dir_result_v1(
    result: &QueryDirResultV1,
    blob: &[u8],
    input_cookie: u64,
) -> Result<ValidatedQueryDirResultV1, QueryValidationError> {
    if result.header.struct_version != 1 {
        return Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ));
    }
    if result.header.required_flags != 0 {
        return Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags),
        ));
    }
    if usize::try_from(result.header.struct_size).ok() != Some(blob.len()) || blob.len() < 40 {
        return Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::InvalidSize),
        ));
    }
    if result.flags & !query_dir_result_flags::EOF != 0 {
        return Err(QueryValidationError::Message(
            MessageValidationError::FlagsOrReserved,
        ));
    }
    if result.required_length != 0 || result.reserved != 0 {
        return Err(QueryValidationError::Message(
            MessageValidationError::FlagsOrReserved,
        ));
    }
    let eof = result.flags & query_dir_result_flags::EOF != 0;
    if result.entries.offset == 0 && result.entries.length == 0 {
        if blob.len() != 40 {
            return Err(QueryValidationError::EntryOverrun);
        }
        if result.entry_count != 0 || !eof {
            return Err(QueryValidationError::EntryCount);
        }
    } else {
        if result.entries.offset != 40 || result.entries.length as usize != blob.len() - 40 {
            return Err(QueryValidationError::EntryOverrun);
        }
        if result.entry_count == 0 {
            return Err(QueryValidationError::EntryCount);
        }
        let mut cursor = 40usize;
        let mut index = 0u32;
        while index < result.entry_count {
            if cursor == blob.len() {
                return Err(QueryValidationError::EntryCount);
            }
            if blob.len() - cursor < 136 {
                return Err(QueryValidationError::EntryOverrun);
            }
            // try_decode cannot fail here because the guard above proved at
            // least 136 bytes remain; the Err arm is defensive only.
            let entry: DirEntryV1 = match try_decode(&blob[cursor..]) {
                Ok(entry) => entry,
                Err(_) => return Err(QueryValidationError::EntryOverrun),
            };
            validate_dir_entry(&entry, blob, cursor)?;
            cursor += entry.header.struct_size as usize;
            index += 1;
        }
        if cursor != blob.len() {
            return Err(QueryValidationError::EntryCount);
        }
    }
    if eof {
        if result.next_cookie != 0 {
            return Err(QueryValidationError::CookieSuccessor);
        }
    } else {
        let expected = match input_cookie.checked_add(u64::from(result.entry_count)) {
            Some(expected) => expected,
            None => return Err(QueryValidationError::CookieSuccessor),
        };
        if result.next_cookie != expected {
            return Err(QueryValidationError::CookieSuccessor);
        }
    }
    Ok(ValidatedQueryDirResultV1 {
        entry_count: result.entry_count,
        next_cookie: result.next_cookie,
        eof,
    })
}

/// The embedded `ControlHeader` is deliberately not validated at this layer;
/// result-header echo rules belong to the Wave 8 result plumbing.
pub fn validate_file_info_v1(info: &FileInfoV1) -> Result<(), MessageValidationError> {
    if info.flags != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if info.namespace_generation == 0 || info.security_generation == 0 {
        return Err(MessageValidationError::Identity);
    }
    if info.attributes & !file_attributes::ACCEPTED_MASK_V21 != 0
        || (info.attributes & file_attributes::NORMAL != 0
            && info.attributes != file_attributes::NORMAL)
    {
        return Err(MessageValidationError::InvalidScalar);
    }
    if info.reparse_tag != 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    if info.creation_time < 0
        || info.last_access_time < 0
        || info.last_write_time < 0
        || info.change_time < 0
    {
        return Err(MessageValidationError::InvalidScalar);
    }
    validate_size_state_v21(info.sizes)
}

/// The embedded `ControlHeader` is deliberately not validated at this layer;
/// result-header echo rules belong to the Wave 8 result plumbing.
pub fn validate_volume_size_info_v1(info: &VolumeSizeInfoV1) -> Result<(), MessageValidationError> {
    if info.flags != 0 || info.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if info.available_allocation_units > info.total_allocation_units {
        return Err(MessageValidationError::Relationship);
    }
    if !info.bytes_per_sector.is_power_of_two()
        || info.bytes_per_sector < 512
        || info.bytes_per_sector > 65_536
    {
        return Err(MessageValidationError::InvalidScalar);
    }
    if info.sectors_per_allocation_unit == 0 || !info.sectors_per_allocation_unit.is_power_of_two()
    {
        return Err(MessageValidationError::InvalidScalar);
    }
    let cluster = u64::from(info.bytes_per_sector) * u64::from(info.sectors_per_allocation_unit);
    if cluster > 16_777_216 {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(())
}

pub const fn validate_fsctl_emission_v21(_request: &FsctlV1) -> Result<(), MessageValidationError> {
    Err(MessageValidationError::IllegalWireForm)
}

pub const fn validate_feature_wire_legality_v21(
    features: FeatureSet,
    form: WireFormV21,
) -> Result<(), MessageValidationError> {
    let legal = match form {
        WireFormV21::RecoveryRequest | WireFormV21::JournalV1Attach => {
            features.contains(protocol_feature::HOT_RESTART)
                && features.contains(protocol_feature::EXACTLY_ONCE)
        }
        WireFormV21::MappedRwFlag => features.contains(protocol_feature::MMAP),
        WireFormV21::MappingBufferKind => features.contains(protocol_feature::MAPPED_IO),
        WireFormV21::ReparseMutation | WireFormV21::ReparseAttribute => {
            features.contains(protocol_feature::REPARSE)
        }
        WireFormV21::SparseMutation => false,
        WireFormV21::PtDonation | WireFormV21::PtNotification => {
            features.contains(protocol_feature::PT)
        }
        WireFormV21::QuerySecurityRequest | WireFormV21::SetSecurityMutation => {
            features.contains(protocol_feature::SECURITY)
        }
    };
    if legal {
        Ok(())
    } else {
        Err(MessageValidationError::IllegalWireForm)
    }
}
