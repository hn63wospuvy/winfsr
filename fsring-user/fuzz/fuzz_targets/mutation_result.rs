#![no_main]
//! Fuzz the mutation result builder: an arbitrary provider effect over a valid
//! decoded RENAME/LINK/UNLINK request must never panic, and any produced result
//! is internally validated by `validate_mutation_success_v2` (so a bad effect
//! surfaces as `Err`, never as illegal wire bytes).

use libfuzzer_sys::fuzz_target;

use fsring_abi::ids::{FileId, LinkId};
use fsring_abi::msgs::SizeState;
use fsring_user::testkit::MutationFixture;
use fsring_user::{build_mutation_result, decode_mutation, MutationEffect, Replaced};

/// A `u64` drawn from a single fuzz byte (default 1 when short).
fn byte_u64(data: &[u8], i: usize) -> u64 {
    u64::from(data.get(i).copied().unwrap_or(1))
}

fn sizes() -> SizeState {
    SizeState {
        allocation_size: 0,
        file_size: 0,
        valid_data_length: 0,
        size_epoch: 1,
    }
}

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or(0);
    let fx = match selector % 3 {
        0 => MutationFixture::rename(),
        1 => MutationFixture::link(),
        _ => MutationFixture::unlink(),
    };
    // The fixtures are always valid, so decode succeeds; be defensive anyway.
    let req = match decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false) {
        Ok(req) => req,
        Err(_) => return,
    };

    let replaced = if selector & 0x80 != 0 {
        Some(Replaced {
            file_id: FileId {
                lo: byte_u64(data, 1),
                hi: 0,
            },
            link_id: LinkId {
                lo: byte_u64(data, 2),
                hi: 0,
            },
            namespace_generation: byte_u64(data, 3),
            link_count: byte_u64(data, 4) as u32,
        })
    } else {
        None
    };
    let effect = MutationEffect {
        file_id: FileId {
            lo: byte_u64(data, 5).max(1),
            hi: 0,
        },
        new_link_id: LinkId {
            lo: byte_u64(data, 6).max(1),
            hi: 0,
        },
        replaced,
        link_count: byte_u64(data, 7) as u32,
        namespace_generation: byte_u64(data, 8),
        source_parent_generation: byte_u64(data, 9),
        target_parent_generation: byte_u64(data, 10),
        parent_generation: byte_u64(data, 11),
        sizes: sizes(),
        retained_sizes: sizes(),
        volume_commit_sequence: byte_u64(data, 12).max(1),
        security_generation: 0,
    };

    if let Ok(bytes) = build_mutation_result(&req, &effect, &fx.table, fx.owner) {
        // A produced result passed the ABI success validator; its bytes are the
        // canonical lengths.
        assert_eq!(bytes.result.len(), 112);
        assert!(matches!(bytes.kind_result.len(), 112 | 104 | 56));
    }
});
