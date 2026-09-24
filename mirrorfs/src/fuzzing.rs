//! Pure fuzz drivers for the provider's state machines.
//!
//! This module is feature-gated so ordinary provider builds expose no testing
//! surface. The drivers intentionally call the production parser, status
//! selector, identity registry, and open-lifecycle engine instead of carrying
//! model copies in the fuzz package.

use std::collections::HashSet;
use std::io;
use std::mem::size_of;
use std::path::{Component as PathComponent, Path, PathBuf};

use fsring_abi::codec::{try_decode, Pod};
use fsring_abi::ids::{FileId, LinkId, OpId, TransactionId};
use fsring_abi::msgs::{create_result, CommitOpenV2, PrepareOpenV2, SizeState};
use fsring_abi::validate::{
    completion_status, is_registered_completion_status_v21, validate_stored_component_utf16,
};
use fsring_user::{
    CommitEffect, CommitRequest, OpenLifecycle, PrepareResult, PreparedRequest, RowState,
};

use crate::identity::{IdentityRegistry, NativeKey};
use crate::path::component_from_utf16le;

const MAX_STEPS: usize = 64;

/// Exercise arbitrary UTF-16LE as one contained path component.
pub fn exercise_path(data: &[u8]) {
    let Ok(component) = component_from_utf16le(data) else {
        return;
    };

    assert!(validate_stored_component_utf16(data).is_ok());
    let path = Path::new(component.as_os_str());
    assert!(!path.is_absolute());
    let mut components = path.components();
    assert!(matches!(components.next(), Some(PathComponent::Normal(_))));
    assert!(components.next().is_none());
    assert_eq!(path.file_name(), Some(component.as_os_str()));
}

/// Exercise the complete opcode/raw-Win32-error status selector.
pub fn exercise_status(data: &[u8]) {
    let opcode = u16::from_le_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    ]);
    let raw = i32::from_le_bytes([
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
        data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0),
    ]);
    let status = crate::status::from_io(opcode, &io::Error::from_raw_os_error(raw)).status();

    let registered_terminal = status != completion_status::SUCCESS
        && status != completion_status::PENDING
        && is_registered_completion_status_v21(opcode, status);
    assert!(
        registered_terminal || status == completion_status::IO_DEVICE_ERROR,
        "status selection must return a registered terminal or the internal-stop sentinel"
    );
}

/// Exercise arbitrary identity allocation/binding/link/generation sequences.
pub fn exercise_identity(data: &[u8]) {
    let mut registry = IdentityRegistry::new();
    let root = registry
        .install_root(
            NativeKey {
                volume_serial: 1,
                file_index: 1,
            },
            0,
        )
        .expect("the fixed nonzero root identity is valid");
    let mut files = vec![root];
    let mut links = Vec::new();
    let mut issued_files = HashSet::from([root]);
    let mut issued_links = HashSet::new();

    for (step, chunk) in data.chunks(8).take(MAX_STEPS).enumerate() {
        let selector = chunk.first().copied().unwrap_or(0);
        let file = files[usize::from(chunk.get(1).copied().unwrap_or(0)) % files.len()];
        let native = NativeKey {
            volume_serial: u32::from(chunk.get(2).copied().unwrap_or(0)).max(1),
            file_index: u64::from(chunk.get(3).copied().unwrap_or(0)).max(1),
        };
        let name = safe_component(selector, step);
        let relative = PathBuf::from(name.as_os_str());

        match selector % 8 {
            0 => {
                if let Ok(id) = registry.allocate_prospective(u64::from(selector)) {
                    assert!(
                        issued_files.insert(id),
                        "FileId values must never be reused"
                    );
                    files.push(id);
                }
            }
            1 => {
                let _ = registry.bind_native(file, native);
            }
            2 => {
                if file != root {
                    if let Ok(effect) = registry.create_link(root, file, name, relative) {
                        let id = effect.value;
                        assert!(
                            issued_links.insert(id),
                            "LinkId values must never be reused"
                        );
                        links.push(id);
                    }
                }
            }
            3 => {
                if let Some(&id) = choose(&links, chunk.get(4).copied().unwrap_or(0)) {
                    let _ = registry.rename_link(id, root, name, relative);
                }
            }
            4 => {
                if let Some(&id) = choose(&links, chunk.get(4).copied().unwrap_or(0)) {
                    let _ = registry.unlink_link(id);
                }
            }
            5 => {
                let _ = registry.advance_namespace(file);
            }
            6 => {
                let _ = registry.advance_security(file);
            }
            _ => {
                let _ = registry.advance_size(file, u64::from(chunk.get(5).copied().unwrap_or(0)));
            }
        }

        registry.assert_fuzz_invariants();
        assert!(issued_files.iter().all(|id| *id != FileId::ZERO));
        assert!(issued_links.iter().all(|id| *id != LinkId::ZERO));
    }
}

/// Exercise arbitrary prepare/replay/abort/commit-state sequences.
pub fn exercise_pending(data: &[u8]) {
    let mut lifecycle = OpenLifecycle::new(1);

    for (step, chunk) in data.chunks(8).take(MAX_STEPS).enumerate() {
        let selector = chunk.first().copied().unwrap_or(0);
        let op_id = OpId {
            lo: u64::from(chunk.get(1).copied().unwrap_or(0)).saturating_add(1),
            hi: 0,
        };
        let transaction_id = TransactionId {
            lo: u64::from(chunk.get(2).copied().unwrap_or(0)),
            hi: 0,
        };
        let kernel_open_id = u64::from(chunk.get(3).copied().unwrap_or(0)).saturating_add(1);

        match selector % 6 {
            0 | 1 => {
                let request = prepared(op_id, selector, step);
                let first = lifecycle.prepare(
                    request.clone(),
                    prepare_result(),
                    u16::from(chunk.get(4).copied().unwrap_or(0)),
                    transaction_id,
                );
                if selector % 6 == 1 {
                    let alternate = TransactionId {
                        lo: transaction_id.lo.wrapping_add(1),
                        hi: transaction_id.hi,
                    };
                    let replay = lifecycle.prepare(
                        request.clone(),
                        prepare_result(),
                        u16::from(chunk.get(4).copied().unwrap_or(0)),
                        alternate,
                    );
                    if let Ok(stored) = first {
                        assert_eq!(replay, Ok(stored));
                    } else if let Ok(stored) = replay {
                        let confirmed = lifecycle.prepare(
                            request,
                            prepare_result(),
                            u16::from(chunk.get(4).copied().unwrap_or(0)),
                            TransactionId {
                                lo: alternate.lo.wrapping_add(1),
                                hi: alternate.hi,
                            },
                        );
                        assert_eq!(confirmed, Ok(stored));
                    }
                }
            }
            2 => {
                let _ = lifecycle.abort(transaction_id);
                assert_eq!(lifecycle.abort(transaction_id), Ok(()));
            }
            3 => {
                let request = commit_request(op_id, transaction_id, kernel_open_id);
                let committed = lifecycle.commit(&request, commit_effect());
                if committed.is_ok() {
                    assert_eq!(lifecycle.row_state(kernel_open_id), Some(RowState::Live));
                    assert!(!lifecycle.has_prepare(op_id));
                }
            }
            4 => {
                let first = lifecycle.cleanup(kernel_open_id);
                if first.is_ok() {
                    assert_eq!(lifecycle.cleanup(kernel_open_id), Ok(()));
                }
            }
            _ => {
                let first = lifecycle.close(kernel_open_id);
                if first.is_ok() && lifecycle.row_state(kernel_open_id).is_none() {
                    assert_eq!(lifecycle.close(kernel_open_id), Ok(()));
                }
            }
        }

        lifecycle.assert_invariants();
    }
}

fn safe_component(selector: u8, step: usize) -> crate::path::Component {
    let name = format!("n{selector:02x}_{:02x}", step & 0xff);
    let bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    component_from_utf16le(&bytes).expect("the generated ASCII name is one valid component")
}

fn choose<T>(items: &[T], selector: u8) -> Option<&T> {
    (!items.is_empty()).then(|| &items[usize::from(selector) % items.len()])
}

fn zeroed_pod<T: Pod>() -> T {
    let bytes = vec![0_u8; size_of::<T>()];
    try_decode(&bytes).expect("an exact-size byte buffer decodes into a POD wire record")
}

fn prepared(op_id: OpId, selector: u8, step: usize) -> PreparedRequest {
    let mut raw: PrepareOpenV2 = zeroed_pod();
    raw.op_id = op_id;
    let name = format!("p{selector:02x}_{:02x}", step & 0xff).into_bytes();
    PreparedRequest::from_raw(raw, name.into_boxed_slice(), None, None)
}

fn prepare_result() -> PrepareResult {
    PrepareResult {
        file_id: FileId { lo: 1, hi: 0 },
        link_id: LinkId { lo: 1, hi: 0 },
        sizes: size_state(),
        namespace_generation: 1,
        security_generation: 1,
        security_descriptor: Box::new([]),
        object_flags: 0,
    }
}

fn commit_request(
    op_id: OpId,
    transaction_id: TransactionId,
    kernel_open_id: u64,
) -> CommitRequest {
    let mut raw: CommitOpenV2 = zeroed_pod();
    raw.op_id = op_id;
    raw.transaction_id = transaction_id;
    raw.expected_namespace_generation = 1;
    raw.expected_security_generation = 1;
    raw.kernel_open_id = kernel_open_id;
    CommitRequest::from_raw(raw)
}

fn commit_effect() -> CommitEffect {
    CommitEffect {
        create_result: create_result::OPENED,
        file_id: FileId { lo: 1, hi: 0 },
        link_id: LinkId { lo: 1, hi: 0 },
        sizes: size_state(),
        namespace_generation: 1,
        security_generation: 1,
        volume_commit_sequence: 1,
    }
}

fn size_state() -> SizeState {
    SizeState {
        allocation_size: 0,
        file_size: 0,
        valid_data_length: 0,
        size_epoch: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{exercise_identity, exercise_path, exercise_pending, exercise_status};

    #[test]
    fn smoke_all_pure_fuzz_drivers() {
        let data: Vec<u8> = (0..=255).collect();
        exercise_path(&data);
        exercise_status(&data);
        exercise_identity(&data);
        exercise_pending(&data);
    }

    #[test]
    fn pending_zero_candidate_then_nonzero_candidate_remains_consistent() {
        exercise_pending(&[1, 0, 0, 0, 0]);
    }
}
