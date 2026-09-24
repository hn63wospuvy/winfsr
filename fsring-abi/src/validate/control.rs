use core::convert::TryFrom;

use crate::{
    codec::try_decode,
    msgs::{BlobSlice, ControlHeader},
    validate::CheckedRange32,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    ShortPrefix,
    RevisionMismatch,
    UnsupportedRequiredFlags,
    InvalidSize,
    InvalidRange,
    InvalidAlignment,
    NonZeroReserved,
    UnsupportedSchema,
    UnclassifiedTail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlVersionSchema {
    pub version: u16,
    pub accepted_required_flags: u16,
    pub minimum_size: u32,
}

/// Header plus the exact caller-owned private snapshot bounded by `struct_size`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedControlPrefix<'a> {
    header: ControlHeader,
    bytes: &'a [u8],
}

impl<'a> ValidatedControlPrefix<'a> {
    pub const fn header(&self) -> ControlHeader {
        self.header
    }

    pub const fn struct_size(&self) -> usize {
        self.bytes.len()
    }

    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmptySliceRule {
    Forbidden,
    CanonicalAbsent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobSliceRule {
    pub minimum_offset: u32,
    pub alignment: u32,
    pub empty: EmptySliceRule,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailSegmentKind {
    Payload,
    ZeroPadding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailSegment {
    pub range: CheckedRange32,
    pub kind: TailSegmentKind,
}

pub fn validate_control_prefix<'a>(
    input: &'a [u8],
    legal_versions: &[u16],
    accepted_required_flags: u16,
    minimum_size: u32,
) -> Result<ValidatedControlPrefix<'a>, ControlError> {
    if input.len() < core::mem::size_of::<ControlHeader>() {
        return Err(ControlError::ShortPrefix);
    }
    validate_uniform_registry(legal_versions, minimum_size)?;
    let header = try_decode::<ControlHeader>(input).map_err(|_| ControlError::ShortPrefix)?;
    if !legal_versions.contains(&header.struct_version) {
        return Err(ControlError::RevisionMismatch);
    }
    finish_prefix(input, header, accepted_required_flags, minimum_size)
}

pub fn validate_control_prefix_with_schemas<'a>(
    input: &'a [u8],
    schemas: &[ControlVersionSchema],
) -> Result<ValidatedControlPrefix<'a>, ControlError> {
    if input.len() < core::mem::size_of::<ControlHeader>() {
        return Err(ControlError::ShortPrefix);
    }
    validate_schema_registry(schemas)?;
    let header = try_decode::<ControlHeader>(input).map_err(|_| ControlError::ShortPrefix)?;
    let mut selected = None;
    for schema in schemas {
        if schema.version == header.struct_version {
            selected = Some(*schema);
            break;
        }
    }
    let schema = selected.ok_or(ControlError::RevisionMismatch)?;
    finish_prefix(
        input,
        header,
        schema.accepted_required_flags,
        schema.minimum_size,
    )
}

fn validate_uniform_registry(
    legal_versions: &[u16],
    minimum_size: u32,
) -> Result<(), ControlError> {
    if legal_versions.is_empty() || minimum_size < core::mem::size_of::<ControlHeader>() as u32 {
        return Err(ControlError::UnsupportedSchema);
    }
    for (index, version) in legal_versions.iter().enumerate() {
        if *version == 0 || legal_versions[..index].contains(version) {
            return Err(ControlError::UnsupportedSchema);
        }
    }
    Ok(())
}

fn validate_schema_registry(schemas: &[ControlVersionSchema]) -> Result<(), ControlError> {
    if schemas.is_empty() {
        return Err(ControlError::UnsupportedSchema);
    }
    for (index, schema) in schemas.iter().enumerate() {
        if schema.version == 0
            || schema.minimum_size < core::mem::size_of::<ControlHeader>() as u32
            || schemas[..index]
                .iter()
                .any(|prior| prior.version == schema.version)
        {
            return Err(ControlError::UnsupportedSchema);
        }
    }
    Ok(())
}

fn finish_prefix<'a>(
    input: &'a [u8],
    header: ControlHeader,
    accepted_required_flags: u16,
    minimum_size: u32,
) -> Result<ValidatedControlPrefix<'a>, ControlError> {
    if header.required_flags & !accepted_required_flags != 0 {
        return Err(ControlError::UnsupportedRequiredFlags);
    }
    if header.struct_size < minimum_size {
        return Err(ControlError::InvalidSize);
    }
    let struct_size = usize::try_from(header.struct_size).map_err(|_| ControlError::InvalidSize)?;
    if struct_size > input.len() {
        return Err(ControlError::InvalidSize);
    }
    Ok(ValidatedControlPrefix {
        header,
        bytes: &input[..struct_size],
    })
}

pub fn resolve_blob_slice(
    slice: BlobSlice,
    struct_size: u32,
    rule: BlobSliceRule,
) -> Result<Option<CheckedRange32>, ControlError> {
    if rule.alignment == 0 || !rule.alignment.is_power_of_two() {
        return Err(ControlError::UnsupportedSchema);
    }
    if slice.length == 0 {
        return if slice.offset == 0 && rule.empty == EmptySliceRule::CanonicalAbsent {
            Ok(None)
        } else {
            Err(ControlError::InvalidRange)
        };
    }
    if slice.offset < rule.minimum_offset {
        return Err(ControlError::InvalidRange);
    }
    if slice.offset & (rule.alignment - 1) != 0 {
        return Err(ControlError::InvalidAlignment);
    }
    let end = slice
        .offset
        .checked_add(slice.length)
        .ok_or(ControlError::InvalidRange)?;
    if end > struct_size {
        return Err(ControlError::InvalidRange);
    }
    Ok(Some(CheckedRange32 {
        start: slice.offset,
        end,
    }))
}

pub fn validate_tail_coverage(
    prefix: &ValidatedControlPrefix<'_>,
    known_size: u32,
    segments: &[TailSegment],
    allow_optional_extension: bool,
) -> Result<(), ControlError> {
    if known_size < core::mem::size_of::<ControlHeader>() as u32 {
        return Err(ControlError::UnsupportedSchema);
    }
    let mut cursor = usize::try_from(known_size).map_err(|_| ControlError::InvalidRange)?;
    if cursor > prefix.bytes.len() {
        return Err(ControlError::InvalidRange);
    }
    for segment in segments {
        let start = usize::try_from(segment.range.start).map_err(|_| ControlError::InvalidRange)?;
        let end = usize::try_from(segment.range.end).map_err(|_| ControlError::InvalidRange)?;
        if start >= end || end > prefix.bytes.len() || start < cursor {
            return Err(ControlError::InvalidRange);
        }
        if start > cursor {
            return Err(ControlError::UnclassifiedTail);
        }
        if segment.kind == TailSegmentKind::ZeroPadding
            && prefix.bytes[start..end].iter().any(|byte| *byte != 0)
        {
            return Err(ControlError::NonZeroReserved);
        }
        cursor = end;
    }
    if cursor < prefix.bytes.len() && !allow_optional_extension {
        return Err(ControlError::UnclassifiedTail);
    }
    Ok(())
}
