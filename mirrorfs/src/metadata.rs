use std::io;

use fsring_abi::msgs::{
    basic_info_set_mask, file_attributes, ControlHeader, SetBasicInfoV1, SizeState,
    VolumeSizeInfoV1, CONTROL_VERSION_V1,
};
use fsring_abi::validate::{validate_size_state_v21, validate_volume_size_info_v1};
use fsring_abi::MAX_FILE_SIZE;
use fsring_user::{DirEntryFields, FileInfoFields, VolumeSizeFields};

use crate::identity::{FileRecord, LinkRecord};
use crate::windows::{NativeBasicInfoUpdate, NativeMetadata, VolumeGeometry};

pub(crate) fn basic_info_update(body: &SetBasicInfoV1) -> io::Result<NativeBasicInfoUpdate> {
    if body.header.struct_size != core::mem::size_of::<SetBasicInfoV1>() as u32
        || body.header.struct_version != CONTROL_VERSION_V1
        || body.header.required_flags != 0
    {
        return Err(invalid_mutation("invalid basic-information V1 header"));
    }
    if body.set_mask == 0 || body.set_mask & !basic_info_set_mask::ALL != 0 {
        return Err(invalid_mutation("invalid basic-information selection"));
    }
    let selects_attributes = body.set_mask & basic_info_set_mask::FILE_ATTRIBUTES != 0;
    if selects_attributes != (body.attributes != 0)
        || body.attributes & !file_attributes::SETTABLE_BASIC_MASK != 0
        || (body.attributes & file_attributes::NORMAL != 0
            && body.attributes != file_attributes::NORMAL)
    {
        return Err(invalid_mutation("invalid basic file attributes"));
    }
    for (time, bit) in [
        (body.creation_time, basic_info_set_mask::CREATION_TIME),
        (body.last_access_time, basic_info_set_mask::LAST_ACCESS_TIME),
        (body.last_write_time, basic_info_set_mask::LAST_WRITE_TIME),
        (body.change_time, basic_info_set_mask::CHANGE_TIME),
    ] {
        let selected = body.set_mask & bit != 0;
        if (selected && time <= 0) || (!selected && time != 0) {
            return Err(invalid_mutation(
                "selected basic times must be positive and unselected times zero",
            ));
        }
    }
    Ok(NativeBasicInfoUpdate {
        creation_time: (body.set_mask & basic_info_set_mask::CREATION_TIME != 0)
            .then_some(body.creation_time),
        last_access_time: (body.set_mask & basic_info_set_mask::LAST_ACCESS_TIME != 0)
            .then_some(body.last_access_time),
        last_write_time: (body.set_mask & basic_info_set_mask::LAST_WRITE_TIME != 0)
            .then_some(body.last_write_time),
        change_time: (body.set_mask & basic_info_set_mask::CHANGE_TIME != 0)
            .then_some(body.change_time),
        attributes: selects_attributes.then_some(body.attributes),
    })
}

pub(crate) fn checked_mutation_size(size: u64) -> io::Result<u64> {
    if size > MAX_FILE_SIZE {
        return Err(invalid_mutation("requested size exceeds ABI/native range"));
    }
    Ok(size)
}

pub(crate) fn validate_native_projection(native: &NativeMetadata) -> io::Result<()> {
    if native.attributes & !file_attributes::ACCEPTED_MASK_V21 != 0
        || (native.attributes & file_attributes::NORMAL != 0
            && native.attributes != file_attributes::NORMAL)
        || native.attributes & file_attributes::REPARSE_POINT != 0
        || (native.attributes & file_attributes::DIRECTORY != 0) != native.is_directory
        || native.link_count == 0
        || [
            native.creation_time,
            native.last_access_time,
            native.last_write_time,
            native.change_time,
        ]
        .into_iter()
        .any(|time| time < 0)
    {
        return Err(invalid_metadata(
            "native metadata cannot be represented by ABI 2.1",
        ));
    }

    checked_sizes(native, native.file_size, 1).map(|_| ())
}

pub(crate) fn file_info_fields(
    native: &NativeMetadata,
    file: &FileRecord,
) -> io::Result<FileInfoFields> {
    validate_native_projection(native)?;
    if file.native != Some(native.key)
        || file.namespace_generation == 0
        || file.security_generation == 0
    {
        return Err(invalid_metadata(
            "native metadata disagrees with the registered file identity",
        ));
    }

    Ok(FileInfoFields {
        creation_time: native.creation_time,
        last_access_time: native.last_access_time,
        last_write_time: native.last_write_time,
        change_time: native.change_time,
        sizes: checked_sizes(native, file.valid_data_length, file.size_epoch)?,
        namespace_generation: file.namespace_generation,
        security_generation: file.security_generation,
        attributes: native.attributes,
        link_count: native.link_count,
    })
}

pub(crate) fn dir_entry_fields(
    native: &NativeMetadata,
    file: &FileRecord,
    link: &LinkRecord,
) -> io::Result<DirEntryFields> {
    validate_native_projection(native)?;
    if file.native != Some(native.key) || link.child != file.id || link.namespace_generation == 0 {
        return Err(invalid_metadata(
            "native metadata disagrees with the registered link identity",
        ));
    }

    Ok(DirEntryFields {
        file_id: file.id,
        link_id: link.id,
        sizes: checked_sizes(native, file.valid_data_length, file.size_epoch)?,
        creation_time: native.creation_time,
        last_access_time: native.last_access_time,
        last_write_time: native.last_write_time,
        change_time: native.change_time,
        namespace_generation: link.namespace_generation,
        attributes: native.attributes,
    })
}

pub(crate) fn volume_size_fields(volume: &VolumeGeometry) -> io::Result<VolumeSizeFields> {
    let fields = VolumeSizeFields {
        total_allocation_units: volume.total_allocation_units,
        available_allocation_units: volume.available_allocation_units,
        sectors_per_allocation_unit: volume.sectors_per_allocation_unit,
        bytes_per_sector: volume.bytes_per_sector,
    };
    let info = VolumeSizeInfoV1 {
        header: ControlHeader {
            struct_size: core::mem::size_of::<VolumeSizeInfoV1>() as u32,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        total_allocation_units: fields.total_allocation_units,
        available_allocation_units: fields.available_allocation_units,
        sectors_per_allocation_unit: fields.sectors_per_allocation_unit,
        bytes_per_sector: fields.bytes_per_sector,
        flags: 0,
        reserved: 0,
    };
    validate_volume_size_info_v1(&info)
        .map_err(|_| invalid_metadata("native volume geometry violates ABI 2.1"))?;
    Ok(fields)
}

fn checked_sizes(
    native: &NativeMetadata,
    valid_data_length: u64,
    size_epoch: u64,
) -> io::Result<SizeState> {
    let sizes = SizeState {
        allocation_size: native.allocation_size,
        file_size: native.file_size,
        valid_data_length,
        size_epoch,
    };
    validate_size_state_v21(sizes)
        .map_err(|_| invalid_metadata("native and registered sizes violate ABI 2.1"))?;
    Ok(sizes)
}

fn invalid_metadata(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_mutation(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use fsring_abi::ids::{FileId, LinkId};
    use fsring_abi::msgs::file_attributes;

    use crate::identity::{FileRecord, LinkRecord, NativeKey};
    use crate::path::component_from_utf16le;
    use crate::windows::{NativeMetadata, VolumeGeometry};

    use super::{
        dir_entry_fields, file_info_fields, validate_native_projection, volume_size_fields,
    };

    fn component(name: &str) -> crate::path::Component {
        let bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        component_from_utf16le(&bytes).unwrap()
    }

    fn native() -> NativeMetadata {
        NativeMetadata {
            key: NativeKey {
                volume_serial: 7,
                file_index: 9,
            },
            creation_time: 11,
            last_access_time: 12,
            last_write_time: 13,
            change_time: 14,
            allocation_size: 4096,
            file_size: 37,
            attributes: file_attributes::ARCHIVE,
            link_count: 3,
            is_directory: false,
        }
    }

    fn file() -> FileRecord {
        FileRecord {
            id: FileId { lo: 21, hi: 0 },
            native: Some(native().key),
            namespace_generation: 31,
            security_generation: 32,
            size_epoch: 33,
            valid_data_length: 29,
        }
    }

    fn link() -> LinkRecord {
        LinkRecord {
            id: LinkId { lo: 41, hi: 0 },
            parent: FileId { lo: 1, hi: 0 },
            child: file().id,
            name: component("entry.bin"),
            relative_path: PathBuf::from("entry.bin"),
            namespace_generation: 42,
        }
    }

    fn volume() -> VolumeGeometry {
        VolumeGeometry {
            root: PathBuf::from(r"D:\"),
            filesystem_name: OsString::from("NTFS"),
            drive_type: 3,
            volume_serial: 7,
            total_allocation_units: 100,
            available_allocation_units: 50,
            sectors_per_allocation_unit: 8,
            bytes_per_sector: 512,
        }
    }

    #[test]
    fn file_info_preserves_native_fields_and_independent_file_generations() {
        let fields = file_info_fields(&native(), &file()).unwrap();

        assert_eq!(fields.creation_time, 11);
        assert_eq!(fields.last_access_time, 12);
        assert_eq!(fields.last_write_time, 13);
        assert_eq!(fields.change_time, 14);
        assert_eq!(fields.sizes.allocation_size, 4096);
        assert_eq!(fields.sizes.file_size, 37);
        assert_eq!(fields.sizes.valid_data_length, 29);
        assert_eq!(fields.sizes.size_epoch, 33);
        assert_eq!(fields.namespace_generation, 31);
        assert_eq!(fields.security_generation, 32);
        assert_eq!(fields.attributes, file_attributes::ARCHIVE);
        assert_eq!(fields.link_count, 3);
        fsring_user::build_file_info(&fields).unwrap();
    }

    #[test]
    fn dir_entry_preserves_native_fields_and_link_generation() {
        let fields = dir_entry_fields(&native(), &file(), &link()).unwrap();

        assert_eq!(fields.file_id, file().id);
        assert_eq!(fields.link_id, link().id);
        assert_eq!(fields.sizes.allocation_size, 4096);
        assert_eq!(fields.sizes.file_size, 37);
        assert_eq!(fields.sizes.valid_data_length, 29);
        assert_eq!(fields.sizes.size_epoch, 33);
        assert_eq!(fields.creation_time, 11);
        assert_eq!(fields.last_access_time, 12);
        assert_eq!(fields.last_write_time, 13);
        assert_eq!(fields.change_time, 14);
        assert_eq!(fields.namespace_generation, 42);
        assert_eq!(fields.attributes, file_attributes::ARCHIVE);
    }

    #[test]
    fn projection_rejects_unrepresentable_native_attributes_and_sizes() {
        let mut invalid_attributes = native();
        invalid_attributes.attributes = 0x0040_0000;
        assert!(validate_native_projection(&invalid_attributes).is_err());

        let mut invalid_vdl = file();
        invalid_vdl.valid_data_length = native().file_size + 1;
        assert!(file_info_fields(&native(), &invalid_vdl).is_err());
    }

    #[test]
    fn volume_projection_rejects_sector_sizes_outside_frozen_bounds() {
        for bytes_per_sector in [256, 131_072] {
            let mut geometry = volume();
            geometry.bytes_per_sector = bytes_per_sector;
            assert!(volume_size_fields(&geometry).is_err());
        }
    }

    #[test]
    fn volume_projection_rejects_oversized_cluster_and_available_count() {
        let mut oversized_cluster = volume();
        oversized_cluster.bytes_per_sector = 65_536;
        oversized_cluster.sectors_per_allocation_unit = 512;
        assert!(volume_size_fields(&oversized_cluster).is_err());

        let mut excessive_available = volume();
        excessive_available.available_allocation_units =
            excessive_available.total_allocation_units + 1;
        assert!(volume_size_fields(&excessive_available).is_err());
    }

    #[test]
    fn volume_projection_accepts_frozen_sector_and_cluster_boundaries() {
        for (bytes_per_sector, sectors_per_allocation_unit) in
            [(512, 1), (65_536, 1), (65_536, 256)]
        {
            let mut geometry = volume();
            geometry.bytes_per_sector = bytes_per_sector;
            geometry.sectors_per_allocation_unit = sectors_per_allocation_unit;
            let fields = volume_size_fields(&geometry).unwrap();
            fsring_user::build_volume_size_info(&fields).unwrap();
        }
    }
}
