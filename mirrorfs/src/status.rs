use std::io;

use fsring_abi::validate::{completion_status, is_registered_completion_status_v21};
use fsring_user::ProviderError;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_WRITE_PROTECT: i32 = 19;
const ERROR_NOT_READY: i32 = 21;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_FILE_EXISTS: i32 = 80;
const ERROR_DISK_FULL: i32 = 112;
const ERROR_DIR_NOT_EMPTY: i32 = 145;
const ERROR_ALREADY_EXISTS: i32 = 183;
const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
const ERROR_INVALID_SECURITY_DESCR: i32 = 1338;

pub(crate) fn select_for_opcode(opcode: u16, candidate: i32) -> ProviderError {
    if candidate != completion_status::SUCCESS
        && candidate != completion_status::PENDING
        && is_registered_completion_status_v21(opcode, candidate)
    {
        return ProviderError::terminal(candidate);
    }

    if is_registered_completion_status_v21(opcode, completion_status::DATA_ERROR) {
        ProviderError::terminal(completion_status::DATA_ERROR)
    } else {
        // Success-only and unknown rows have no legal terminal provider status.
        // The daemon recognizes this unregistered sentinel as an internal stop
        // and never publishes it to the ring.
        ProviderError::internal()
    }
}

pub(crate) fn from_io(opcode: u16, error: &io::Error) -> ProviderError {
    let candidate = error
        .raw_os_error()
        .and_then(named_windows_status)
        .unwrap_or_else(|| status_from_kind(error.kind()));
    select_for_opcode(opcode, candidate)
}

fn named_windows_status(raw: i32) -> Option<i32> {
    match raw {
        ERROR_FILE_NOT_FOUND => Some(completion_status::OBJECT_NAME_NOT_FOUND),
        ERROR_PATH_NOT_FOUND => Some(completion_status::OBJECT_PATH_NOT_FOUND),
        ERROR_ACCESS_DENIED => Some(completion_status::ACCESS_DENIED),
        ERROR_WRITE_PROTECT => Some(completion_status::MEDIA_WRITE_PROTECTED),
        ERROR_NOT_READY => Some(completion_status::DEVICE_NOT_READY),
        ERROR_SHARING_VIOLATION => Some(completion_status::SHARING_VIOLATION),
        ERROR_DISK_FULL => Some(completion_status::DISK_FULL),
        ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => Some(completion_status::OBJECT_NAME_COLLISION),
        ERROR_DIR_NOT_EMPTY => Some(completion_status::DIRECTORY_NOT_EMPTY),
        ERROR_PRIVILEGE_NOT_HELD => Some(completion_status::PRIVILEGE_NOT_HELD),
        ERROR_INVALID_SECURITY_DESCR => Some(completion_status::INVALID_SECURITY_DESCR),
        _ => None,
    }
}

fn status_from_kind(kind: io::ErrorKind) -> i32 {
    match kind {
        io::ErrorKind::NotFound => completion_status::OBJECT_NAME_NOT_FOUND,
        io::ErrorKind::PermissionDenied => completion_status::ACCESS_DENIED,
        io::ErrorKind::AlreadyExists => completion_status::OBJECT_NAME_COLLISION,
        io::ErrorKind::TimedOut => completion_status::IO_TIMEOUT,
        io::ErrorKind::Unsupported => completion_status::NOT_SUPPORTED,
        io::ErrorKind::Interrupted => completion_status::CANCELLED,
        _ => completion_status::DATA_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use fsring_abi::layout::op;
    use fsring_abi::validate::{completion_status, is_registered_completion_status_v21};

    use super::{from_io, select_for_opcode};

    const FALLIBLE_OPCODES: [u16; 10] = [
        op::PREPARE_OPEN,
        op::COMMIT_OPEN,
        op::READ,
        op::WRITE,
        op::FLUSH,
        op::QUERY_INFO,
        op::MUTATE,
        op::QUERY_DIR,
        op::QUERY_VOLUME,
        op::QUERY_SECURITY,
    ];

    #[test]
    fn named_windows_errors_map_to_semantic_registered_statuses() {
        let cases = [
            (
                op::PREPARE_OPEN,
                2,
                completion_status::OBJECT_NAME_NOT_FOUND,
            ),
            (
                op::PREPARE_OPEN,
                3,
                completion_status::OBJECT_PATH_NOT_FOUND,
            ),
            (op::READ, 5, completion_status::ACCESS_DENIED),
            (op::WRITE, 19, completion_status::MEDIA_WRITE_PROTECTED),
            (op::FLUSH, 21, completion_status::DEVICE_NOT_READY),
            (op::PREPARE_OPEN, 32, completion_status::SHARING_VIOLATION),
            (
                op::PREPARE_OPEN,
                80,
                completion_status::OBJECT_NAME_COLLISION,
            ),
            (op::WRITE, 112, completion_status::DISK_FULL),
            (op::MUTATE, 145, completion_status::DIRECTORY_NOT_EMPTY),
            (
                op::PREPARE_OPEN,
                183,
                completion_status::OBJECT_NAME_COLLISION,
            ),
            (op::MUTATE, 1314, completion_status::PRIVILEGE_NOT_HELD),
            (op::MUTATE, 1338, completion_status::INVALID_SECURITY_DESCR),
        ];

        for (opcode, raw, expected) in cases {
            let error = from_io(opcode, &io::Error::from_raw_os_error(raw));
            assert_eq!(error.status(), expected, "Win32 error {raw}");
            assert!(is_registered_completion_status_v21(opcode, error.status()));
        }
    }

    #[test]
    fn unmapped_io_error_uses_registered_data_error() {
        let error = from_io(op::QUERY_INFO, &io::Error::from_raw_os_error(0x7fff_ffff));

        assert_eq!(error.status(), completion_status::DATA_ERROR);
        assert!(is_registered_completion_status_v21(
            op::QUERY_INFO,
            error.status()
        ));
    }

    #[test]
    fn standard_io_error_kinds_map_through_opcode_selection() {
        let cases = [
            (
                op::PREPARE_OPEN,
                io::ErrorKind::NotFound,
                completion_status::OBJECT_NAME_NOT_FOUND,
            ),
            (
                op::READ,
                io::ErrorKind::PermissionDenied,
                completion_status::ACCESS_DENIED,
            ),
            (
                op::PREPARE_OPEN,
                io::ErrorKind::AlreadyExists,
                completion_status::OBJECT_NAME_COLLISION,
            ),
            (
                op::FLUSH,
                io::ErrorKind::TimedOut,
                completion_status::IO_TIMEOUT,
            ),
            (
                op::QUERY_INFO,
                io::ErrorKind::Unsupported,
                completion_status::NOT_SUPPORTED,
            ),
            (
                op::QUERY_VOLUME,
                io::ErrorKind::Interrupted,
                completion_status::CANCELLED,
            ),
            (
                op::READ,
                io::ErrorKind::AlreadyExists,
                completion_status::DATA_ERROR,
            ),
        ];

        for (opcode, kind, expected) in cases {
            let error = from_io(opcode, &io::Error::new(kind, "test error"));
            assert_eq!(error.status(), expected, "I/O kind {kind:?}");
            assert!(is_registered_completion_status_v21(opcode, error.status()));
        }
    }

    #[test]
    fn selection_preserves_registered_terminal_status() {
        let error = select_for_opcode(op::READ, completion_status::ACCESS_DENIED);

        assert_eq!(error.status(), completion_status::ACCESS_DENIED);
    }

    #[test]
    fn selection_replaces_success_pending_and_row_mismatch_with_data_error() {
        for candidate in [
            completion_status::SUCCESS,
            completion_status::PENDING,
            completion_status::OBJECT_NAME_NOT_FOUND,
            i32::MAX,
        ] {
            let error = select_for_opcode(op::READ, candidate);
            assert_eq!(error.status(), completion_status::DATA_ERROR);
        }
    }

    #[test]
    fn selection_is_registered_and_terminal_for_every_fallible_opcode() {
        for opcode in FALLIBLE_OPCODES {
            for candidate in [
                completion_status::SUCCESS,
                completion_status::PENDING,
                completion_status::DATA_ERROR,
                completion_status::PRIVILEGE_NOT_HELD,
                i32::MIN,
            ] {
                let status = select_for_opcode(opcode, candidate).status();
                assert_ne!(status, completion_status::SUCCESS);
                assert_ne!(status, completion_status::PENDING);
                assert!(
                    is_registered_completion_status_v21(opcode, status),
                    "opcode {opcode:#06x}, candidate {candidate:#010x}, selected {status:#010x}"
                );
            }
        }
    }

    #[test]
    fn retry_is_preserved_only_for_rows_that_register_it() {
        for opcode in [op::COMMIT_OPEN, op::WRITE, op::MUTATE] {
            assert_eq!(
                select_for_opcode(opcode, completion_status::RETRY).status(),
                completion_status::RETRY
            );
        }
        assert_eq!(
            select_for_opcode(op::READ, completion_status::RETRY).status(),
            completion_status::DATA_ERROR
        );
    }

    #[test]
    fn success_only_and_unknown_opcodes_return_internal_stop_sentinel() {
        for opcode in [op::ABORT_OPEN, op::CLEANUP, op::CLOSE, u16::MAX] {
            assert_eq!(
                select_for_opcode(opcode, completion_status::ACCESS_DENIED),
                fsring_user::ProviderError::internal()
            );
        }
    }
}
