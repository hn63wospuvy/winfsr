use core::mem::{align_of, offset_of, size_of};
use std::{
    fs,
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
};

use fsring_abi::{
    control::{
        self, boot_context_init_state, boot_context_slot_offset_v1, boot_context_slot_state,
        checked_boot_context_publication_sequence, checked_next_load_generation,
        checked_next_mount_sequence, mount_id_from_burned_sequence, retire_mount_state,
        BootContextHeaderV1, BootContextSlotV1, BootCounterError, BootIdentityError,
        BootSequenceError, BOOT_CONTEXT_ATTACH_REQUIRED_PUBLICATIONS, BOOT_CONTEXT_HEADER_BYTES,
        BOOT_CONTEXT_HEADER_REQUIRED_PUBLICATIONS, BOOT_CONTEXT_INITIAL_SEQUENCE,
        BOOT_CONTEXT_LOCK_NAME, BOOT_CONTEXT_MAGIC, BOOT_CONTEXT_RETIRE_KEY_BYTES,
        BOOT_CONTEXT_SECTION_BYTES, BOOT_CONTEXT_SECTION_NAME, BOOT_CONTEXT_SEQUENCE_STEP,
        BOOT_CONTEXT_SERVICE_SID_BUFFER_BYTES, BOOT_CONTEXT_SERVICE_SID_BYTES,
        BOOT_CONTEXT_SETUP_REQUIRED_PUBLICATIONS, BOOT_CONTEXT_SLOT_BYTES, BOOT_CONTEXT_SLOT_COUNT,
        BOOT_CONTEXT_STARTUP_RETIRE_REQUIRED_PUBLICATIONS, BOOT_CONTEXT_USED_BYTES,
        BOOT_CONTEXT_VERSION,
    },
    digest::{
        boot_context_header_digest_v1, boot_context_slot_digest_v1, derive_retire_token_v2,
        derive_state_token_v2, retire_token_eq, BootTokenError, StateTokenInput,
        BOOT_CONTEXT_HEADER_DIGEST_DOMAIN, BOOT_CONTEXT_SLOT_DIGEST_DOMAIN, RETIRE_TOKEN_DOMAIN_V2,
        STATE_TOKEN_DOMAIN_V2,
    },
    validate::{
        is_dedicated_service_sid_v1, validate_boot_context_header_v1,
        validate_boot_context_section_v1, validate_boot_context_slot_v1,
        BootContextValidationError,
    },
    BootInstanceId, FeatureSet, MountId, RetireToken, FSRING_ABI_MINOR,
};

type RetireTokenDeriver =
    fn(&[u8; 32], BootInstanceId, MountId, &[u8]) -> Result<RetireToken, BootTokenError>;
type StateTokenDeriver =
    fn(&[u8; 32], StateTokenInput, &[u8]) -> Result<RetireToken, BootTokenError>;

macro_rules! assert_not_impl {
    ($type:ty: $trait:path) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<Marker> {
                fn marker() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            struct ForbiddenImpl;
            impl<T: ?Sized + $trait> AmbiguousIfImpl<ForbiddenImpl> for T {}
            let _ = <$type as AmbiguousIfImpl<_>>::marker;
        };
    };
}

assert_not_impl!(BootContextHeaderV1: Default);
assert_not_impl!(BootContextHeaderV1: core::fmt::Debug);
assert_not_impl!(BootContextHeaderV1: PartialEq);
assert_not_impl!(BootContextHeaderV1: Eq);
assert_not_impl!(BootContextSlotV1: Default);
assert_not_impl!(BootContextSlotV1: core::fmt::Debug);
assert_not_impl!(BootContextSlotV1: PartialEq);
assert_not_impl!(BootContextSlotV1: Eq);
assert_not_impl!(BootSequenceError: fsring_abi::codec::Pod);
assert_not_impl!(BootCounterError: fsring_abi::codec::Pod);
assert_not_impl!(BootIdentityError: fsring_abi::codec::Pod);
assert_not_impl!(BootTokenError: fsring_abi::codec::Pod);
assert_not_impl!(BootContextValidationError: fsring_abi::codec::Pod);
assert_not_impl!(StateTokenInput: fsring_abi::codec::Pod);

const CONST_SLOT_OFFSET: Option<u32> = boot_context_slot_offset_v1(0);
const CONST_PUBLICATION_SEQUENCE: Result<u64, BootSequenceError> =
    checked_boot_context_publication_sequence(2, 5);
const CONST_NEXT_MOUNT_SEQUENCE: Result<u64, BootCounterError> = checked_next_mount_sequence(0);
const CONST_NEXT_LOAD_GENERATION: Result<u64, BootCounterError> = checked_next_load_generation(1);
const CONST_MOUNT_ID: Result<MountId, BootIdentityError> = mount_id_from_burned_sequence(1, 2);

const KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const SID: [u8; 32] = [
    1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0,
];
const BOOT: BootInstanceId = BootInstanceId {
    lo: 0x0123_4567_89ab_cdef,
    hi: 0xfedc_ba98_7654_3210,
};
const MOUNT: MountId = MountId {
    lo: 0x1112_1314_1516_1718,
    hi: 0x2122_2324_2526_2728,
};
const ABSENT_QUERY: MountId = MountId {
    lo: 0,
    hi: 0x2122_2324_2526_2728,
};
const RESTART_FEATURES: FeatureSet = FeatureSet { words: [0x1c, 0] };

const HEADER_DIGEST_HEX: &str = "c1da704cda64d9db098c8da497aafeb2f9a7459a38ec10b65c63ba48cec33852";
const SLOT_7_DIGEST_HEX: &str = "23eb4ce9f79eaeb24074d730b1ebb8f61abb3b13e7afa810a6c8958db9bcb55d";
const RETIRE_TOKEN_HEX: &str = "e69ec8f348eab016fd089bb96903d8f8";
const ACTIVE_STATE_TOKEN_HEX: &str = "08c9b6c6f41313d24feb5b328b2f3d31";
const ABSENT_INVENTORY_TOKEN_HEX: &str = "25c3df2e2761319d9d3eb8d8ec66ad67";
const ABSENT_EXACT_TOKEN_HEX: &str = "7f2a44809c8f7b61066a9ef758e88a6f";
const GRACE_STATE_TOKEN_HEX: &str = "445fc105b0bad5510e3e062f691f988b";
const BOUND_RECONCILING_STATE_TOKEN_HEX: &str = "6cc7136603f0196c5e4926cca4a37ffd";
const ACTIVE_MAX_FEATURE_TOKEN_HEX: &str = "5db17f892042ea55c3b68ca6362772d7";
const INITIAL_HEADER_DIGEST_HEX: &str =
    "58f2f292559167e0df9d74c6863f36bf04028ff32e73accd382a2a4898e0f6bf";
const INITIAL_SLOT_0_DIGEST_HEX: &str =
    "9bda4ed63f96cc2d901d727c079793e9a16147d56601b240c0992a75bc3dfdf2";
const INITIAL_SLOT_63_DIGEST_HEX: &str =
    "6af51987a44062151cce55000934e264e68e36ae01b24f798a1a2b22b6e8ef8b";
const INITIAL_SECTION_SHA256_HEX: &str =
    "00f52abd1b3a196a08aab7bd1e50753b3e3761d0d7f98a0228f59e30f1ab3dde";
// Wave 10 activation rebaseline: this is now the SHA-256 of the activated ABI
// 2.1 header. Waves 11-14 rewrite documents only and must not change it.
const FROZEN_HEADER_SHA256_HEX: &str =
    "7bc16346475e8bd786306368ef90d80e6f3009b8cc44adc11ca6dfd60509ab2d";
const HEADER_IMAGE_HEX: &str = concat!(
    "465352494e474243010000000001000000000100000100004000000002000000",
    "000000000000000002000000000000001817161514131211e7e8e9eaebecedee",
    "0700000000000000f8ffffffffffffffefcdab89674523011032547698badcfe",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "c1da704cda64d9db098c8da497aafeb2f9a7459a38ec10b65c63ba48cec33852",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
);
const LIVE_SLOT_7_IMAGE_HEX: &str = concat!(
    "0600000000000000020000002000000005000000000000000807060504030201",
    "08070605040302012827262524232221efcdab89674523011032547698badcfe",
    "03000000000000001c0000000000000000000000000000000100000000000000",
    "0106000000000005500000000100000002000000030000000400000005000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "23eb4ce9f79eaeb24074d730b1ebb8f61abb3b13e7afa810a6c8958db9bcb55d",
);

fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut out = [0u8; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("non-lowercase-hex test literal"),
            }
        }
        out[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    out
}

fn reference_is_dedicated_service_sid(service_sid: &[u8]) -> bool {
    service_sid.len() == 32
        && service_sid[0] == 1
        && service_sid[1] == 6
        && service_sid[2..8] == [0, 0, 0, 0, 0, 5]
        && service_sid[8..12] == 80u32.to_le_bytes()
}

fn assert_exact_derive_line(
    relative_path: &str,
    declaration: &str,
    expected_derive: &str,
    expected_repr: Option<&str>,
) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    let source = fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = source.lines().collect();
    let matches: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (line.trim() == declaration).then_some(index))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected one uncommented declaration line for {declaration}",
    );
    let declaration_index = matches[0];
    let preceding: Vec<&str> = lines[..declaration_index]
        .iter()
        .rev()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(preceding[0], expected_derive);
    if let Some(expected_repr) = expected_repr {
        assert_eq!(preceding[1], expected_repr);
    }
}

fn assert_locked_trait_source_contracts() {
    let wire_derive = "#[derive(Clone, Copy)]";
    let wire_repr = "#[repr(C, align(64))]";
    assert_exact_derive_line(
        "src/control/boot.rs",
        "pub struct BootContextHeaderV1 {",
        wire_derive,
        Some(wire_repr),
    );
    assert_exact_derive_line(
        "src/control/boot.rs",
        "pub struct BootContextSlotV1 {",
        wire_derive,
        Some(wire_repr),
    );

    let helper_derive = "#[derive(Clone, Copy, Debug, PartialEq, Eq)]";
    for declaration in [
        "pub enum BootSequenceError {",
        "pub enum BootCounterError {",
        "pub enum BootIdentityError {",
    ] {
        assert_exact_derive_line("src/control/boot.rs", declaration, helper_derive, None);
    }
    assert_exact_derive_line(
        "src/digest.rs",
        "pub struct StateTokenInput {",
        helper_derive,
        None,
    );
    assert_exact_derive_line(
        "src/digest.rs",
        "pub enum BootTokenError {",
        helper_derive,
        None,
    );
    assert_exact_derive_line(
        "src/validate/boot.rs",
        "pub enum BootContextValidationError {",
        helper_derive,
        None,
    );
}

fn encode<T: fsring_abi::codec::Pod>(value: &T) -> Vec<u8> {
    let mut bytes = vec![0u8; size_of::<T>()];
    fsring_abi::codec::try_encode(value, &mut bytes).unwrap();
    bytes
}

fn sample_header() -> BootContextHeaderV1 {
    let mut header = BootContextHeaderV1 {
        magic: BOOT_CONTEXT_MAGIC,
        format_version: BOOT_CONTEXT_VERSION,
        header_size: BOOT_CONTEXT_HEADER_BYTES,
        context_size: BOOT_CONTEXT_SECTION_BYTES,
        slot_size: BOOT_CONTEXT_SLOT_BYTES,
        slot_count: BOOT_CONTEXT_SLOT_COUNT,
        init_state: boot_context_init_state::READY,
        flags: 0,
        reserved0: 0,
        header_sequence: 2,
        mount_sequence: 0x1112_1314_1516_1718,
        mount_sequence_complement: 0x1112_1314_1516_1718 ^ u64::MAX,
        load_generation: 7,
        load_generation_complement: 7 ^ u64::MAX,
        boot_instance_id: BOOT,
        per_boot_retire_key: KEY,
        digest: [0; 32],
        reserved: [0; 96],
    };
    header.digest = boot_context_header_digest_v1(&header);
    header
}

fn sample_live_slot(index: u32) -> BootContextSlotV1 {
    sample_slot_for_state(index, boot_context_slot_state::LIVE)
}

fn sample_slot_for_state(index: u32, state: u32) -> BootContextSlotV1 {
    let mut service_sid = [0u8; 68];
    service_sid[..32].copy_from_slice(&SID);
    let (sequence, load_generation, latest_session_epoch) = match state {
        boot_context_slot_state::STAGING => (4, 7, 1),
        boot_context_slot_state::LIVE => (6, 5, 3),
        boot_context_slot_state::TERMINALIZING => (8, 5, 3),
        boot_context_slot_state::TERMINAL => (8, 5, 3),
        _ => (6, 5, 3),
    };
    let mut slot = BootContextSlotV1 {
        sequence,
        state,
        service_sid_length: 32,
        load_generation,
        mount_sequence: 0x0102_0304_0506_0708,
        mount_id: MountId {
            lo: 0x0102_0304_0506_0708,
            hi: 0x2122_2324_2526_2728,
        },
        boot_instance_id: BOOT,
        latest_session_epoch,
        selected_features: RESTART_FEATURES,
        journal_version: 1,
        flags: 0,
        service_sid,
        reserved: [0; 60],
        digest: [0; 32],
    };
    slot.digest = boot_context_slot_digest_v1(index, &slot).unwrap();
    slot
}

fn sample_free_slot(index: u32, sequence: u64) -> BootContextSlotV1 {
    let mut slot = BootContextSlotV1 {
        sequence,
        state: boot_context_slot_state::FREE,
        service_sid_length: 0,
        load_generation: 0,
        mount_sequence: 0,
        mount_id: MountId::ZERO,
        boot_instance_id: BootInstanceId::ZERO,
        latest_session_epoch: 0,
        selected_features: FeatureSet { words: [0, 0] },
        journal_version: 0,
        flags: 0,
        service_sid: [0; 68],
        reserved: [0; 60],
        digest: [0; 32],
    };
    slot.digest = boot_context_slot_digest_v1(index, &slot).unwrap();
    slot
}

fn resign_header(header: &mut BootContextHeaderV1) {
    header.digest = [0; 32];
    header.digest = boot_context_header_digest_v1(header);
}

fn resign_slot(index: u32, slot: &mut BootContextSlotV1) {
    slot.digest = [0; 32];
    slot.digest = boot_context_slot_digest_v1(index, slot).unwrap();
}

fn token_bytes(token: RetireToken) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&token.lo.to_le_bytes());
    bytes[8..].copy_from_slice(&token.hi.to_le_bytes());
    bytes
}

fn state_input(state: u16, mount_id: MountId, features: FeatureSet) -> StateTokenInput {
    StateTokenInput {
        boot_instance_id: BOOT,
        result_mount_id: mount_id,
        mount_state: state,
        latest_session_epoch: 0x3132_3334_3536_3738,
        selected_features: features,
        journal_version: 1,
    }
}

struct ReferenceSha256;

impl ReferenceSha256 {
    const ROUND_CONSTANTS: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn digest(input: &[u8]) -> [u8; 32] {
        let mut state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut chunks = input.chunks_exact(64);
        for chunk in &mut chunks {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            Self::compress(&mut state, &block);
        }

        let remainder = chunks.remainder();
        let mut tail = [0u8; 128];
        tail[..remainder.len()].copy_from_slice(remainder);
        tail[remainder.len()] = 0x80;
        let padded_len = if remainder.len() < 56 { 64 } else { 128 };
        let bit_len = (input.len() as u64).wrapping_mul(8);
        tail[padded_len - 8..padded_len].copy_from_slice(&bit_len.to_be_bytes());
        for block in tail[..padded_len].chunks_exact(64) {
            let mut fixed = [0u8; 64];
            fixed.copy_from_slice(block);
            Self::compress(&mut state, &fixed);
        }

        let mut output = [0u8; 32];
        for (chunk, word) in output.chunks_exact_mut(4).zip(state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut schedule = [0u32; 64];
        for (word, bytes) in schedule[..16].iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for (index, schedule_word) in schedule.iter().enumerate() {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(Self::ROUND_CONSTANTS[index])
                .wrapping_add(*schedule_word);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(value);
        }
    }
}

fn put_u32_le_reference(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64_le_reference(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn encode_header_reference(header: &BootContextHeaderV1) -> [u8; 256] {
    let mut output = [0u8; 256];
    put_u64_le_reference(&mut output, 0, header.magic);
    put_u32_le_reference(&mut output, 8, header.format_version);
    put_u32_le_reference(&mut output, 12, header.header_size);
    put_u32_le_reference(&mut output, 16, header.context_size);
    put_u32_le_reference(&mut output, 20, header.slot_size);
    put_u32_le_reference(&mut output, 24, header.slot_count);
    put_u32_le_reference(&mut output, 28, header.init_state);
    put_u32_le_reference(&mut output, 32, header.flags);
    put_u32_le_reference(&mut output, 36, header.reserved0);
    put_u64_le_reference(&mut output, 40, header.header_sequence);
    put_u64_le_reference(&mut output, 48, header.mount_sequence);
    put_u64_le_reference(&mut output, 56, header.mount_sequence_complement);
    put_u64_le_reference(&mut output, 64, header.load_generation);
    put_u64_le_reference(&mut output, 72, header.load_generation_complement);
    put_u64_le_reference(&mut output, 80, header.boot_instance_id.lo);
    put_u64_le_reference(&mut output, 88, header.boot_instance_id.hi);
    output[96..128].copy_from_slice(&header.per_boot_retire_key);
    output[128..160].copy_from_slice(&header.digest);
    output[160..256].copy_from_slice(&header.reserved);
    output
}

fn encode_slot_reference(slot: &BootContextSlotV1) -> [u8; 256] {
    let mut output = [0u8; 256];
    put_u64_le_reference(&mut output, 0, slot.sequence);
    put_u32_le_reference(&mut output, 8, slot.state);
    put_u32_le_reference(&mut output, 12, slot.service_sid_length);
    put_u64_le_reference(&mut output, 16, slot.load_generation);
    put_u64_le_reference(&mut output, 24, slot.mount_sequence);
    put_u64_le_reference(&mut output, 32, slot.mount_id.lo);
    put_u64_le_reference(&mut output, 40, slot.mount_id.hi);
    put_u64_le_reference(&mut output, 48, slot.boot_instance_id.lo);
    put_u64_le_reference(&mut output, 56, slot.boot_instance_id.hi);
    put_u64_le_reference(&mut output, 64, slot.latest_session_epoch);
    put_u64_le_reference(&mut output, 72, slot.selected_features.words[0]);
    put_u64_le_reference(&mut output, 80, slot.selected_features.words[1]);
    put_u32_le_reference(&mut output, 88, slot.journal_version);
    put_u32_le_reference(&mut output, 92, slot.flags);
    output[96..164].copy_from_slice(&slot.service_sid);
    output[164..224].copy_from_slice(&slot.reserved);
    output[224..256].copy_from_slice(&slot.digest);
    output
}

fn reference_header_digest(header: &BootContextHeaderV1) -> [u8; 32] {
    let mut canonical = *header;
    canonical.digest = [0; 32];
    let image = encode_header_reference(&canonical);
    let mut input = Vec::with_capacity(22 + image.len());
    input.extend_from_slice(b"FSRING-BOOT-HEADER-v1\0");
    input.extend_from_slice(&image);
    ReferenceSha256::digest(&input)
}

fn reference_slot_digest(index: u32, slot: &BootContextSlotV1) -> [u8; 32] {
    let mut canonical = *slot;
    canonical.digest = [0; 32];
    let image = encode_slot_reference(&canonical);
    let mut input = Vec::with_capacity(20 + 4 + image.len());
    input.extend_from_slice(b"FSRING-BOOT-SLOT-v1\0");
    input.extend_from_slice(&index.to_le_bytes());
    input.extend_from_slice(&image);
    ReferenceSha256::digest(&input)
}

fn initial_header_reference() -> BootContextHeaderV1 {
    let mut header = BootContextHeaderV1 {
        magic: BOOT_CONTEXT_MAGIC,
        format_version: BOOT_CONTEXT_VERSION,
        header_size: BOOT_CONTEXT_HEADER_BYTES,
        context_size: BOOT_CONTEXT_SECTION_BYTES,
        slot_size: BOOT_CONTEXT_SLOT_BYTES,
        slot_count: BOOT_CONTEXT_SLOT_COUNT,
        init_state: boot_context_init_state::READY,
        flags: 0,
        reserved0: 0,
        header_sequence: BOOT_CONTEXT_INITIAL_SEQUENCE,
        mount_sequence: 0,
        mount_sequence_complement: u64::MAX,
        load_generation: 1,
        load_generation_complement: u64::MAX - 1,
        boot_instance_id: BOOT,
        per_boot_retire_key: KEY,
        digest: [0; 32],
        reserved: [0; 96],
    };
    header.digest = reference_header_digest(&header);
    header
}

fn initial_free_slot_reference(index: u32) -> BootContextSlotV1 {
    let mut slot = BootContextSlotV1 {
        sequence: BOOT_CONTEXT_INITIAL_SEQUENCE,
        state: boot_context_slot_state::FREE,
        service_sid_length: 0,
        load_generation: 0,
        mount_sequence: 0,
        mount_id: MountId::ZERO,
        boot_instance_id: BootInstanceId::ZERO,
        latest_session_epoch: 0,
        selected_features: FeatureSet { words: [0, 0] },
        journal_version: 0,
        flags: 0,
        service_sid: [0; 68],
        reserved: [0; 60],
        digest: [0; 32],
    };
    slot.digest = reference_slot_digest(index, &slot);
    slot
}

fn initial_section_reference() -> Vec<u8> {
    let mut section = vec![0u8; BOOT_CONTEXT_SECTION_BYTES as usize];
    section[..BOOT_CONTEXT_HEADER_BYTES as usize]
        .copy_from_slice(&encode_header_reference(&initial_header_reference()));
    for index in 0..BOOT_CONTEXT_SLOT_COUNT {
        let offset = boot_context_slot_offset_v1(index).unwrap() as usize;
        section[offset..offset + BOOT_CONTEXT_SLOT_BYTES as usize]
            .copy_from_slice(&encode_slot_reference(&initial_free_slot_reference(index)));
    }
    section
}

fn sample_valid_section() -> Vec<u8> {
    let mut section = vec![0u8; BOOT_CONTEXT_SECTION_BYTES as usize];
    section[..BOOT_CONTEXT_HEADER_BYTES as usize].copy_from_slice(&encode(&sample_header()));
    for index in 0..BOOT_CONTEXT_SLOT_COUNT {
        let offset = boot_context_slot_offset_v1(index).unwrap() as usize;
        section[offset..offset + BOOT_CONTEXT_SLOT_BYTES as usize]
            .copy_from_slice(&encode(&sample_free_slot(index, 2)));
    }
    section
}

fn put_slot(section: &mut [u8], index: u32, slot: &BootContextSlotV1) {
    let offset = boot_context_slot_offset_v1(index).unwrap() as usize;
    section[offset..offset + BOOT_CONTEXT_SLOT_BYTES as usize].copy_from_slice(&encode(slot));
}

fn put_header(section: &mut [u8], header: &BootContextHeaderV1) {
    section[..BOOT_CONTEXT_HEADER_BYTES as usize].copy_from_slice(&encode(header));
}

fn assert_header_error(header: &BootContextHeaderV1, expected: BootContextValidationError) {
    assert_header_input_error(&encode(header), expected);
}

fn assert_header_input_error(input: &[u8], expected: BootContextValidationError) {
    match validate_boot_context_header_v1(input) {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("invalid header was accepted; expected {expected:?}"),
    }
}

fn assert_slot_error(
    header: &BootContextHeaderV1,
    index: u32,
    slot: &BootContextSlotV1,
    expected: BootContextValidationError,
) {
    assert_slot_input_error(header, index, &encode(slot), expected);
}

fn assert_slot_input_error(
    header: &BootContextHeaderV1,
    index: u32,
    input: &[u8],
    expected: BootContextValidationError,
) {
    match validate_boot_context_slot_v1(header, index, input) {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("invalid slot was accepted; expected {expected:?}"),
    }
}

fn assert_header_revalidation_error(
    header: &BootContextHeaderV1,
    valid_slot: &BootContextSlotV1,
    invalid_slot: &BootContextSlotV1,
    expected: BootContextValidationError,
) {
    assert_slot_error(header, 0, valid_slot, expected);
    assert_slot_error(header, 0, invalid_slot, expected);
}

fn assert_section_error(input: &[u8], expected: BootContextValidationError) {
    match validate_boot_context_section_v1(input) {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("invalid section was accepted; expected {expected:?}"),
    }
}

#[test]
fn wave4a_public_surface_compiles() {
    fn assert_wire_traits<T: Clone + Copy>() {}
    fn assert_helper_traits<T: Clone + Copy + core::fmt::Debug + PartialEq + Eq>() {}

    assert_wire_traits::<BootContextHeaderV1>();
    assert_wire_traits::<BootContextSlotV1>();
    assert_helper_traits::<BootSequenceError>();
    assert_helper_traits::<BootCounterError>();
    assert_helper_traits::<BootIdentityError>();
    assert_helper_traits::<BootTokenError>();
    assert_helper_traits::<BootContextValidationError>();
    assert_helper_traits::<StateTokenInput>();
    let _: fn(u32) -> Option<u32> = boot_context_slot_offset_v1;
    let _: fn(u64, u32) -> Result<u64, BootSequenceError> =
        checked_boot_context_publication_sequence;
    let _: fn(u64) -> Result<u64, BootCounterError> = checked_next_mount_sequence;
    let _: fn(u64) -> Result<u64, BootCounterError> = checked_next_load_generation;
    let _: fn(u64, u64) -> Result<MountId, BootIdentityError> = mount_id_from_burned_sequence;
    let _: fn(&[u8]) -> bool = is_dedicated_service_sid_v1;
    let _: fn(&BootContextHeaderV1) -> [u8; 32] = boot_context_header_digest_v1;
    let _: fn(u32, &BootContextSlotV1) -> Option<[u8; 32]> = boot_context_slot_digest_v1;
    let _: fn(&[u8]) -> Result<BootContextHeaderV1, BootContextValidationError> =
        validate_boot_context_header_v1;
    let _: fn(
        &BootContextHeaderV1,
        u32,
        &[u8],
    ) -> Result<BootContextSlotV1, BootContextValidationError> = validate_boot_context_slot_v1;
    let _: fn(&[u8]) -> Result<BootContextHeaderV1, BootContextValidationError> =
        validate_boot_context_section_v1;
    let _: RetireTokenDeriver = derive_retire_token_v2;
    let _: StateTokenDeriver = derive_state_token_v2;
    let _: fn(RetireToken, RetireToken) -> bool = retire_token_eq;
    let _ = (
        size_of::<BootContextHeaderV1>(),
        align_of::<BootContextSlotV1>(),
        offset_of!(BootContextHeaderV1, magic),
        size_of::<FeatureSet>(),
        control::FSRING_MOUNT_CONTROL,
        BOOT_CONTEXT_SECTION_BYTES,
        BOOT_CONTEXT_HEADER_BYTES,
        BOOT_CONTEXT_SLOT_BYTES,
        BOOT_CONTEXT_SLOT_COUNT,
        BOOT_CONTEXT_USED_BYTES,
        BOOT_CONTEXT_MAGIC,
        BOOT_CONTEXT_VERSION,
        BOOT_CONTEXT_INITIAL_SEQUENCE,
        BOOT_CONTEXT_SEQUENCE_STEP,
        BOOT_CONTEXT_RETIRE_KEY_BYTES,
        BOOT_CONTEXT_SERVICE_SID_BYTES,
        BOOT_CONTEXT_SERVICE_SID_BUFFER_BYTES,
        BOOT_CONTEXT_SETUP_REQUIRED_PUBLICATIONS,
        BOOT_CONTEXT_ATTACH_REQUIRED_PUBLICATIONS,
        BOOT_CONTEXT_STARTUP_RETIRE_REQUIRED_PUBLICATIONS,
        BOOT_CONTEXT_HEADER_REQUIRED_PUBLICATIONS,
        BOOT_CONTEXT_SECTION_NAME,
        BOOT_CONTEXT_LOCK_NAME,
        boot_context_init_state::EMPTY,
        boot_context_init_state::INITIALIZING,
        boot_context_init_state::READY,
        boot_context_slot_state::FREE,
        boot_context_slot_state::STAGING,
        boot_context_slot_state::LIVE,
        boot_context_slot_state::TERMINALIZING,
        boot_context_slot_state::TERMINAL,
        BOOT_CONTEXT_HEADER_DIGEST_DOMAIN,
        BOOT_CONTEXT_SLOT_DIGEST_DOMAIN,
        RETIRE_TOKEN_DOMAIN_V2,
        STATE_TOKEN_DOMAIN_V2,
    );
    let _ = (
        BootSequenceError::InvalidCurrent,
        BootSequenceError::InvalidPublicationCount,
        BootSequenceError::Exhausted,
        BootCounterError::InvalidCurrent,
        BootCounterError::Exhausted,
        BootIdentityError::ZeroMountSequence,
        BootIdentityError::ZeroRandomHigh,
        BootTokenError::ZeroKey,
        BootTokenError::ZeroBootInstanceId,
        BootTokenError::InvalidMountState,
        BootTokenError::InvalidStateFields,
        BootTokenError::InvalidMountId,
        BootTokenError::InvalidServiceSid,
    );
    let _ = (
        BootContextValidationError::InvalidLength,
        BootContextValidationError::SlotIndex,
        BootContextValidationError::HeaderFormat,
        BootContextValidationError::HeaderInitState,
        BootContextValidationError::HeaderSequence,
        BootContextValidationError::HeaderDigest,
        BootContextValidationError::HeaderFlagsOrReserved,
        BootContextValidationError::HeaderComplement,
        BootContextValidationError::HeaderBootInstanceId,
        BootContextValidationError::HeaderRetireKey,
        BootContextValidationError::HeaderLoadGeneration,
        BootContextValidationError::SlotState,
        BootContextValidationError::SlotSequence,
        BootContextValidationError::SlotDigest,
        BootContextValidationError::SlotFlagsOrReserved,
        BootContextValidationError::SlotFreeShape,
        BootContextValidationError::SlotServiceSid,
        BootContextValidationError::SlotBootInstanceId,
        BootContextValidationError::SlotMountSequence,
        BootContextValidationError::SlotMountId,
        BootContextValidationError::SlotLoadGeneration,
        BootContextValidationError::SlotSessionEpoch,
        BootContextValidationError::SlotFeatures,
        BootContextValidationError::SlotJournalVersion,
        BootContextValidationError::DuplicateMountSequence,
        BootContextValidationError::ImmutableTail,
    );
    assert_eq!(CONST_SLOT_OFFSET, Some(BOOT_CONTEXT_HEADER_BYTES));
    assert_eq!(CONST_PUBLICATION_SEQUENCE, Ok(12));
    assert_eq!(CONST_NEXT_MOUNT_SEQUENCE, Ok(1));
    assert_eq!(CONST_NEXT_LOAD_GENERATION, Ok(2));
    assert_eq!(CONST_MOUNT_ID, Ok(MountId { lo: 1, hi: 2 }));
    assert_locked_trait_source_contracts();
    assert_eq!(
        boot_context_slot_offset_v1(0),
        Some(BOOT_CONTEXT_HEADER_BYTES),
    );
}

#[test]
fn boot_context_constants_names_domains_and_states_are_exact() {
    assert_eq!(BOOT_CONTEXT_SECTION_BYTES, 65_536);
    assert_eq!(BOOT_CONTEXT_HEADER_BYTES, 256);
    assert_eq!(BOOT_CONTEXT_SLOT_BYTES, 256);
    assert_eq!(BOOT_CONTEXT_SLOT_COUNT, 64);
    assert_eq!(BOOT_CONTEXT_USED_BYTES, 16_640);
    assert_eq!(BOOT_CONTEXT_MAGIC, 0x4342_474e_4952_5346);
    assert_eq!(BOOT_CONTEXT_VERSION, 1);
    assert_eq!(BOOT_CONTEXT_INITIAL_SEQUENCE, 2);
    assert_eq!(BOOT_CONTEXT_SEQUENCE_STEP, 2);
    assert_eq!(BOOT_CONTEXT_RETIRE_KEY_BYTES, 32);
    assert_eq!(BOOT_CONTEXT_SERVICE_SID_BYTES, 32);
    assert_eq!(BOOT_CONTEXT_SERVICE_SID_BUFFER_BYTES, 68);
    assert_eq!(BOOT_CONTEXT_SETUP_REQUIRED_PUBLICATIONS, 5);
    assert_eq!(BOOT_CONTEXT_ATTACH_REQUIRED_PUBLICATIONS, 4);
    assert_eq!(BOOT_CONTEXT_STARTUP_RETIRE_REQUIRED_PUBLICATIONS, 2);
    assert_eq!(BOOT_CONTEXT_HEADER_REQUIRED_PUBLICATIONS, 1);
    assert_eq!(
        BOOT_CONTEXT_SECTION_NAME,
        "\\KernelObjects\\FsRingBootContext-v1",
    );
    assert_eq!(
        BOOT_CONTEXT_LOCK_NAME,
        "\\KernelObjects\\FsRingBootContextLock-v1",
    );
    assert_eq!(control::FSRING_MOUNT_CONTROL, 1);

    assert_eq!(boot_context_init_state::EMPTY, 0);
    assert_eq!(boot_context_init_state::INITIALIZING, 1);
    assert_eq!(boot_context_init_state::READY, 2);
    assert_eq!(boot_context_slot_state::FREE, 0);
    assert_eq!(boot_context_slot_state::STAGING, 1);
    assert_eq!(boot_context_slot_state::LIVE, 2);
    assert_eq!(boot_context_slot_state::TERMINALIZING, 3);
    assert_eq!(boot_context_slot_state::TERMINAL, 4);

    assert_eq!(BOOT_CONTEXT_HEADER_DIGEST_DOMAIN.len(), 22);
    assert_eq!(
        BOOT_CONTEXT_HEADER_DIGEST_DOMAIN,
        b"FSRING-BOOT-HEADER-v1\0"
    );
    assert_eq!(BOOT_CONTEXT_SLOT_DIGEST_DOMAIN.len(), 20);
    assert_eq!(BOOT_CONTEXT_SLOT_DIGEST_DOMAIN, b"FSRING-BOOT-SLOT-v1\0");
    assert_eq!(RETIRE_TOKEN_DOMAIN_V2.len(), 17);
    assert_eq!(RETIRE_TOKEN_DOMAIN_V2, b"FSRING-RETIRE-v2\0");
    assert_eq!(STATE_TOKEN_DOMAIN_V2.len(), 22);
    assert_eq!(STATE_TOKEN_DOMAIN_V2, b"FSRING-MOUNT-STATE-v2\0");
    assert_eq!(BOOT_CONTEXT_HEADER_DIGEST_DOMAIN.last(), Some(&0));
    assert_eq!(BOOT_CONTEXT_SLOT_DIGEST_DOMAIN.last(), Some(&0));
    assert_eq!(RETIRE_TOKEN_DOMAIN_V2.last(), Some(&0));
    assert_eq!(STATE_TOKEN_DOMAIN_V2.last(), Some(&0));
}

#[test]
fn boot_context_header_layout_is_256_by_64_and_gapless() {
    fn assert_pod<T: fsring_abi::codec::Pod>() {}

    assert_pod::<BootContextHeaderV1>();
    assert_eq!(size_of::<BootContextHeaderV1>(), 256);
    assert_eq!(align_of::<BootContextHeaderV1>(), 64);
    assert_eq!(offset_of!(BootContextHeaderV1, magic), 0);
    assert_eq!(offset_of!(BootContextHeaderV1, format_version), 8);
    assert_eq!(offset_of!(BootContextHeaderV1, header_size), 12);
    assert_eq!(offset_of!(BootContextHeaderV1, context_size), 16);
    assert_eq!(offset_of!(BootContextHeaderV1, slot_size), 20);
    assert_eq!(offset_of!(BootContextHeaderV1, slot_count), 24);
    assert_eq!(offset_of!(BootContextHeaderV1, init_state), 28);
    assert_eq!(offset_of!(BootContextHeaderV1, flags), 32);
    assert_eq!(offset_of!(BootContextHeaderV1, reserved0), 36);
    assert_eq!(offset_of!(BootContextHeaderV1, header_sequence), 40);
    assert_eq!(offset_of!(BootContextHeaderV1, mount_sequence), 48);
    assert_eq!(
        offset_of!(BootContextHeaderV1, mount_sequence_complement),
        56
    );
    assert_eq!(offset_of!(BootContextHeaderV1, load_generation), 64);
    assert_eq!(
        offset_of!(BootContextHeaderV1, load_generation_complement),
        72
    );
    assert_eq!(offset_of!(BootContextHeaderV1, boot_instance_id), 80);
    assert_eq!(offset_of!(BootContextHeaderV1, per_boot_retire_key), 96);
    assert_eq!(offset_of!(BootContextHeaderV1, digest), 128);
    assert_eq!(offset_of!(BootContextHeaderV1, reserved), 160);
    assert_eq!(
        offset_of!(BootContextHeaderV1, reserved) + size_of::<[u8; 96]>(),
        size_of::<BootContextHeaderV1>(),
    );

    let bytes = encode(&sample_header());
    let decoded = fsring_abi::codec::try_decode::<BootContextHeaderV1>(&bytes).unwrap();
    assert_eq!(encode(&decoded), bytes);
    assert_eq!(bytes, decode_hex::<256>(HEADER_IMAGE_HEX));
}

#[test]
fn boot_context_slot_layout_is_256_by_64_and_gapless() {
    fn assert_pod<T: fsring_abi::codec::Pod>() {}

    assert_pod::<BootContextSlotV1>();
    assert_eq!(size_of::<BootContextSlotV1>(), 256);
    assert_eq!(align_of::<BootContextSlotV1>(), 64);
    assert_eq!(offset_of!(BootContextSlotV1, sequence), 0);
    assert_eq!(offset_of!(BootContextSlotV1, state), 8);
    assert_eq!(offset_of!(BootContextSlotV1, service_sid_length), 12);
    assert_eq!(offset_of!(BootContextSlotV1, load_generation), 16);
    assert_eq!(offset_of!(BootContextSlotV1, mount_sequence), 24);
    assert_eq!(offset_of!(BootContextSlotV1, mount_id), 32);
    assert_eq!(offset_of!(BootContextSlotV1, boot_instance_id), 48);
    assert_eq!(offset_of!(BootContextSlotV1, latest_session_epoch), 64);
    assert_eq!(offset_of!(BootContextSlotV1, selected_features), 72);
    assert_eq!(offset_of!(BootContextSlotV1, journal_version), 88);
    assert_eq!(offset_of!(BootContextSlotV1, flags), 92);
    assert_eq!(offset_of!(BootContextSlotV1, service_sid), 96);
    assert_eq!(offset_of!(BootContextSlotV1, reserved), 164);
    assert_eq!(offset_of!(BootContextSlotV1, digest), 224);
    assert_eq!(
        offset_of!(BootContextSlotV1, digest) + size_of::<[u8; 32]>(),
        size_of::<BootContextSlotV1>(),
    );

    let bytes = encode(&sample_live_slot(7));
    let decoded = fsring_abi::codec::try_decode::<BootContextSlotV1>(&bytes).unwrap();
    assert_eq!(encode(&decoded), bytes);
    assert_eq!(bytes, decode_hex::<256>(LIVE_SLOT_7_IMAGE_HEX));
}

#[test]
fn slot_offsets_sequences_counters_and_mount_ids_are_checked() {
    assert_eq!(boot_context_slot_offset_v1(0), Some(256));
    assert_eq!(boot_context_slot_offset_v1(63), Some(16_384));
    assert_eq!(boot_context_slot_offset_v1(64), None);
    assert_eq!(boot_context_slot_offset_v1(u32::MAX), None);

    assert_eq!(checked_boot_context_publication_sequence(2, 1), Ok(4));
    assert_eq!(checked_boot_context_publication_sequence(2, 2), Ok(6));
    assert_eq!(checked_boot_context_publication_sequence(2, 4), Ok(10));
    assert_eq!(checked_boot_context_publication_sequence(2, 5), Ok(12));
    let boundaries = [
        (1, u64::MAX - 3, u64::MAX - 1, u64::MAX - 1),
        (2, u64::MAX - 5, u64::MAX - 1, u64::MAX - 3),
        (3, u64::MAX - 7, u64::MAX - 1, u64::MAX - 5),
        (4, u64::MAX - 9, u64::MAX - 1, u64::MAX - 7),
        (5, u64::MAX - 11, u64::MAX - 1, u64::MAX - 9),
    ];
    for (publications, current, final_sequence, first_exhausted) in boundaries {
        assert_eq!(
            checked_boot_context_publication_sequence(current, publications),
            Ok(final_sequence),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(first_exhausted, publications),
            Err(BootSequenceError::Exhausted),
        );
    }
    for current in [0, 1, 3, u64::MAX] {
        assert_eq!(
            checked_boot_context_publication_sequence(current, 1),
            Err(BootSequenceError::InvalidCurrent),
        );
    }
    assert_eq!(
        checked_boot_context_publication_sequence(2, 0),
        Err(BootSequenceError::InvalidPublicationCount),
    );
    assert_eq!(
        checked_boot_context_publication_sequence(2, u32::MAX),
        Ok(2 + 2 * u32::MAX as u64),
    );

    assert_eq!(checked_next_mount_sequence(0), Ok(1));
    assert_eq!(checked_next_mount_sequence(1), Ok(2));
    assert_eq!(checked_next_mount_sequence(u64::MAX - 1), Ok(u64::MAX));
    assert_eq!(
        checked_next_mount_sequence(u64::MAX),
        Err(BootCounterError::Exhausted),
    );
    assert_eq!(
        checked_next_load_generation(0),
        Err(BootCounterError::InvalidCurrent),
    );
    assert_eq!(checked_next_load_generation(1), Ok(2));
    assert_eq!(checked_next_load_generation(u64::MAX - 1), Ok(u64::MAX));
    assert_eq!(
        checked_next_load_generation(u64::MAX),
        Err(BootCounterError::Exhausted),
    );

    assert_eq!(
        mount_id_from_burned_sequence(0, 0),
        Err(BootIdentityError::ZeroMountSequence),
    );
    assert_eq!(
        mount_id_from_burned_sequence(0, 1),
        Err(BootIdentityError::ZeroMountSequence),
    );
    assert_eq!(
        mount_id_from_burned_sequence(1, 0),
        Err(BootIdentityError::ZeroRandomHigh),
    );
    assert_eq!(
        mount_id_from_burned_sequence(1, 1),
        Ok(MountId { lo: 1, hi: 1 }),
    );
    assert_eq!(
        mount_id_from_burned_sequence(u64::MAX, u64::MAX),
        Ok(MountId {
            lo: u64::MAX,
            hi: u64::MAX,
        }),
    );
}

#[test]
fn dedicated_service_sid_predicate_is_byte_exact() {
    assert!(reference_is_dedicated_service_sid(&SID));
    assert!(is_dedicated_service_sid_v1(&SID));
    let mut extended = [0u8; 69];
    extended[..SID.len()].copy_from_slice(&SID);
    for length in 0..=69 {
        let candidate = &extended[..length];
        assert_eq!(
            is_dedicated_service_sid_v1(candidate),
            reference_is_dedicated_service_sid(candidate),
            "SID length {length} diverged from the closed reference predicate",
        );
    }

    for byte_index in 0..SID.len() {
        for value in 0u8..=u8::MAX {
            let mut candidate = SID;
            candidate[byte_index] = value;
            assert_eq!(
                is_dedicated_service_sid_v1(&candidate),
                reference_is_dedicated_service_sid(&candidate),
                "SID byte {byte_index} substitution {value} diverged",
            );
        }
    }
    for first_rid in [0u32, 1, 79, 81, 82, 0x0001_0050, u32::MAX] {
        let mut malformed = SID;
        malformed[8..12].copy_from_slice(&first_rid.to_le_bytes());
        assert_eq!(
            is_dedicated_service_sid_v1(&malformed),
            reference_is_dedicated_service_sid(&malformed),
        );
        assert!(!is_dedicated_service_sid_v1(&malformed));
    }

    let mut generic_service_sid = [0u8; 16];
    generic_service_sid[..8].copy_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5]);
    generic_service_sid[8..12].copy_from_slice(&80u32.to_le_bytes());
    assert!(!is_dedicated_service_sid_v1(&generic_service_sid));

    let mut zero_suffix = SID;
    zero_suffix[12..].fill(0);
    assert!(is_dedicated_service_sid_v1(&zero_suffix));
}

#[test]
fn header_digest_has_literal_little_endian_golden() {
    let header = sample_header();
    let expected = decode_hex::<32>(HEADER_DIGEST_HEX);
    assert_eq!(header.digest, expected);
    assert_eq!(boot_context_header_digest_v1(&header), expected);
    assert_eq!(reference_header_digest(&header), expected);

    let mut changed_digest = header;
    changed_digest.digest = [0xa5; 32];
    assert_eq!(boot_context_header_digest_v1(&changed_digest), expected);

    let canonical = encode_header_reference(&header);
    for offset in [
        0usize, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 56, 64, 72, 80, 88,
    ] {
        let mut changed = canonical;
        changed[offset] ^= 1;
        changed[128..160].fill(0);
        let changed_header =
            fsring_abi::codec::try_decode::<BootContextHeaderV1>(&changed).unwrap();
        assert_ne!(
            boot_context_header_digest_v1(&changed_header),
            expected,
            "numeric limb beginning at byte {offset} was not hashed",
        );
    }
    for offset in [96usize, 127, 160, 255] {
        let mut changed = canonical;
        changed[offset] ^= 1;
        changed[128..160].fill(0);
        let changed_header =
            fsring_abi::codec::try_decode::<BootContextHeaderV1>(&changed).unwrap();
        assert_ne!(
            boot_context_header_digest_v1(&changed_header),
            expected,
            "canonical byte {offset} was not hashed",
        );
    }
    assert_eq!(header.header_sequence, 2);
    let mut next_sequence = header;
    next_sequence.header_sequence = 4;
    assert_ne!(boot_context_header_digest_v1(&next_sequence), expected);
    assert_eq!(
        encode_header_reference(&header),
        decode_hex::<256>(HEADER_IMAGE_HEX)
    );
}

#[test]
fn slot_digest_binds_index_and_has_literal_golden() {
    let slot = sample_live_slot(7);
    let expected = decode_hex::<32>(SLOT_7_DIGEST_HEX);
    assert_eq!(slot.digest, expected);
    assert_eq!(boot_context_slot_digest_v1(7, &slot), Some(expected));
    assert_eq!(reference_slot_digest(7, &slot), expected);
    assert_ne!(boot_context_slot_digest_v1(6, &slot), Some(expected));
    assert_eq!(boot_context_slot_digest_v1(64, &slot), None);
    assert_eq!(boot_context_slot_digest_v1(u32::MAX, &slot), None);

    let mut changed_digest = slot;
    changed_digest.digest = [0xa5; 32];
    assert_eq!(
        boot_context_slot_digest_v1(7, &changed_digest),
        Some(expected)
    );
    assert_eq!(slot.sequence, 6);
    let mut next_sequence = slot;
    next_sequence.sequence = 8;
    assert_ne!(
        boot_context_slot_digest_v1(7, &next_sequence),
        Some(expected)
    );
}

#[test]
fn retire_token_has_literal_golden_and_projection() {
    let token = derive_retire_token_v2(&KEY, BOOT, MOUNT, &SID).unwrap();
    assert_eq!(token_bytes(token), decode_hex::<16>(RETIRE_TOKEN_HEX));
    assert_eq!(token.lo, 0x16b0_ea48_f3c8_9ee6);
    assert_eq!(token.hi, 0xf8d8_0369_b99b_08fd);

    let mut sid_buffer = [0u8; 68];
    sid_buffer[..32].copy_from_slice(&SID);
    sid_buffer[32..].fill(0xa5);
    assert_eq!(
        derive_retire_token_v2(&KEY, BOOT, MOUNT, &sid_buffer[..32]),
        Ok(token),
    );
}

#[test]
fn state_tokens_have_active_and_absent_goldens() {
    let epoch = 0x3132_3334_3536_3738;
    for (state, expected_hex) in [
        (retire_mount_state::ACTIVE, ACTIVE_STATE_TOKEN_HEX),
        (retire_mount_state::GRACE, GRACE_STATE_TOKEN_HEX),
        (
            retire_mount_state::BOUND_RECONCILING,
            BOUND_RECONCILING_STATE_TOKEN_HEX,
        ),
    ] {
        let input = state_input(state, MOUNT, RESTART_FEATURES);
        assert_eq!(input.latest_session_epoch, epoch);
        assert_eq!(
            token_bytes(derive_state_token_v2(&KEY, input, &SID).unwrap()),
            decode_hex::<16>(expected_hex),
        );
    }

    let active_max = state_input(
        retire_mount_state::ACTIVE,
        MOUNT,
        FeatureSet { words: [0x9f, 0] },
    );
    assert_eq!(
        token_bytes(derive_state_token_v2(&KEY, active_max, &SID).unwrap()),
        decode_hex::<16>(ACTIVE_MAX_FEATURE_TOKEN_HEX),
    );

    let inventory = StateTokenInput {
        boot_instance_id: BOOT,
        result_mount_id: MountId::ZERO,
        mount_state: retire_mount_state::ABSENT,
        latest_session_epoch: 0,
        selected_features: FeatureSet { words: [0, 0] },
        journal_version: 0,
    };
    assert_eq!(
        token_bytes(derive_state_token_v2(&KEY, inventory, &SID).unwrap()),
        decode_hex::<16>(ABSENT_INVENTORY_TOKEN_HEX),
    );
    let exact = StateTokenInput {
        result_mount_id: ABSENT_QUERY,
        ..inventory
    };
    assert_eq!(
        token_bytes(derive_state_token_v2(&KEY, exact, &SID).unwrap()),
        decode_hex::<16>(ABSENT_EXACT_TOKEN_HEX),
    );
    let other_one_zero_limb = StateTokenInput {
        result_mount_id: MountId {
            lo: MOUNT.lo,
            hi: 0,
        },
        ..inventory
    };
    assert!(derive_state_token_v2(&KEY, other_one_zero_limb, &SID).is_ok());
}

#[test]
fn token_domains_inputs_and_comparison_fail_closed() {
    assert_ne!(
        RETIRE_TOKEN_DOMAIN_V2.as_slice(),
        STATE_TOKEN_DOMAIN_V2.as_slice()
    );
    let active = state_input(retire_mount_state::ACTIVE, MOUNT, RESTART_FEATURES);
    let retire = derive_retire_token_v2(&KEY, BOOT, MOUNT, &SID).unwrap();
    let state = derive_state_token_v2(&KEY, active, &SID).unwrap();
    assert_ne!(retire, state);

    for boot_instance_id in [
        BootInstanceId { lo: 0, hi: 1 },
        BootInstanceId { lo: 1, hi: 0 },
    ] {
        assert!(derive_retire_token_v2(&KEY, boot_instance_id, MOUNT, &SID).is_ok());
        let input = StateTokenInput {
            boot_instance_id,
            ..active
        };
        assert!(derive_state_token_v2(&KEY, input, &SID).is_ok());
    }

    let zero_key = [0u8; 32];
    assert_eq!(
        derive_retire_token_v2(&zero_key, BootInstanceId::ZERO, MountId::ZERO, &[]),
        Err(BootTokenError::ZeroKey),
    );
    assert_eq!(
        derive_state_token_v2(
            &zero_key,
            StateTokenInput {
                boot_instance_id: BootInstanceId::ZERO,
                result_mount_id: MountId::ZERO,
                mount_state: u16::MAX,
                latest_session_epoch: 1,
                selected_features: FeatureSet {
                    words: [u64::MAX, u64::MAX],
                },
                journal_version: u32::MAX,
            },
            &[],
        ),
        Err(BootTokenError::ZeroKey),
    );
    assert_eq!(
        derive_retire_token_v2(&KEY, BootInstanceId::ZERO, MountId::ZERO, &[]),
        Err(BootTokenError::ZeroBootInstanceId),
    );
    assert_eq!(
        derive_state_token_v2(
            &KEY,
            StateTokenInput {
                boot_instance_id: BootInstanceId::ZERO,
                result_mount_id: MountId::ZERO,
                mount_state: u16::MAX,
                latest_session_epoch: 0,
                selected_features: FeatureSet {
                    words: [u64::MAX, u64::MAX],
                },
                journal_version: u32::MAX,
            },
            &[],
        ),
        Err(BootTokenError::ZeroBootInstanceId),
    );

    for mount_id in [MountId { lo: 0, hi: 1 }, MountId { lo: 1, hi: 0 }] {
        assert_eq!(
            derive_retire_token_v2(&KEY, BOOT, mount_id, &SID),
            Err(BootTokenError::InvalidMountId),
        );
    }
    assert_eq!(
        derive_retire_token_v2(&KEY, BOOT, MountId::ZERO, &[]),
        Err(BootTokenError::InvalidMountId),
    );

    for mount_state in [0, retire_mount_state::TERMINAL, 6, u16::MAX] {
        assert_eq!(
            derive_state_token_v2(
                &KEY,
                StateTokenInput {
                    mount_state,
                    result_mount_id: MountId::ZERO,
                    ..active
                },
                &[],
            ),
            Err(BootTokenError::InvalidMountState),
        );
    }
    let mut invalid_fields = active;
    invalid_fields.latest_session_epoch = 0;
    assert_eq!(
        derive_state_token_v2(&KEY, invalid_fields, &SID),
        Err(BootTokenError::InvalidStateFields),
    );
    for features in [
        FeatureSet { words: [0x1c, 0] },
        FeatureSet { words: [0x9f, 0] },
    ] {
        assert!(derive_state_token_v2(
            &KEY,
            StateTokenInput {
                selected_features: features,
                ..active
            },
            &SID,
        )
        .is_ok());
    }
    for missing_bit in [2u8, 3, 4] {
        let features = FeatureSet {
            words: [0x1c & !(1u64 << missing_bit), 0],
        };
        assert_eq!(
            derive_state_token_v2(
                &KEY,
                StateTokenInput {
                    selected_features: features,
                    ..active
                },
                &SID,
            ),
            Err(BootTokenError::InvalidStateFields),
        );
    }
    for forbidden_bit in [5u8, 6, 8, 9, 10] {
        let features = FeatureSet {
            words: [0x1c | (1u64 << forbidden_bit), 0],
        };
        assert_eq!(
            derive_state_token_v2(
                &KEY,
                StateTokenInput {
                    selected_features: features,
                    ..active
                },
                &SID,
            ),
            Err(BootTokenError::InvalidStateFields),
        );
    }
    for features in [
        FeatureSet {
            words: [u64::MAX, 0],
        },
        FeatureSet { words: [0x1c, 1] },
    ] {
        assert_eq!(
            derive_state_token_v2(
                &KEY,
                StateTokenInput {
                    selected_features: features,
                    ..active
                },
                &SID,
            ),
            Err(BootTokenError::InvalidStateFields),
        );
    }
    for journal_version in [0, 2, u32::MAX] {
        assert_eq!(
            derive_state_token_v2(
                &KEY,
                StateTokenInput {
                    journal_version,
                    ..active
                },
                &SID,
            ),
            Err(BootTokenError::InvalidStateFields),
        );
    }
    for mount_id in [MountId { lo: 0, hi: 1 }, MountId { lo: 1, hi: 0 }] {
        assert_eq!(
            derive_state_token_v2(
                &KEY,
                StateTokenInput {
                    result_mount_id: mount_id,
                    ..active
                },
                &SID,
            ),
            Err(BootTokenError::InvalidMountId),
        );
    }
    assert_eq!(
        derive_state_token_v2(
            &KEY,
            StateTokenInput {
                result_mount_id: MountId::ZERO,
                latest_session_epoch: 0,
                ..active
            },
            &[],
        ),
        Err(BootTokenError::InvalidStateFields),
    );
    assert_eq!(
        derive_state_token_v2(
            &KEY,
            StateTokenInput {
                result_mount_id: MountId::ZERO,
                ..active
            },
            &[],
        ),
        Err(BootTokenError::InvalidMountId),
    );

    let absent = StateTokenInput {
        boot_instance_id: BOOT,
        result_mount_id: MountId::ZERO,
        mount_state: retire_mount_state::ABSENT,
        latest_session_epoch: 0,
        selected_features: FeatureSet { words: [0, 0] },
        journal_version: 0,
    };
    for malformed in [
        StateTokenInput {
            latest_session_epoch: 1,
            ..absent
        },
        StateTokenInput {
            selected_features: RESTART_FEATURES,
            ..absent
        },
        StateTokenInput {
            journal_version: 1,
            ..absent
        },
    ] {
        assert_eq!(
            derive_state_token_v2(&KEY, malformed, &SID),
            Err(BootTokenError::InvalidStateFields),
        );
    }

    let mut sid_buffer = [0u8; 69];
    sid_buffer[..32].copy_from_slice(&SID);
    for length in 0..=69 {
        if length == 32 {
            continue;
        }
        assert_eq!(
            derive_retire_token_v2(&KEY, BOOT, MOUNT, &sid_buffer[..length]),
            Err(BootTokenError::InvalidServiceSid),
        );
        assert_eq!(
            derive_state_token_v2(&KEY, active, &sid_buffer[..length]),
            Err(BootTokenError::InvalidServiceSid),
        );
    }
    for byte_index in [0usize, 1, 2, 7, 8] {
        let mut malformed = SID;
        malformed[byte_index] ^= 1;
        assert_eq!(
            derive_retire_token_v2(&KEY, BOOT, MOUNT, &malformed),
            Err(BootTokenError::InvalidServiceSid),
        );
        assert_eq!(
            derive_state_token_v2(&KEY, active, &malformed),
            Err(BootTokenError::InvalidServiceSid),
        );
    }

    assert!(retire_token_eq(retire, retire));
    assert!(!retire_token_eq(
        retire,
        RetireToken {
            lo: retire.lo ^ 1,
            hi: retire.hi,
        },
    ));
    assert!(!retire_token_eq(
        retire,
        RetireToken {
            lo: retire.lo,
            hi: retire.hi ^ 1,
        },
    ));
    assert!(!retire_token_eq(
        retire,
        RetireToken {
            lo: retire.lo ^ 1,
            hi: retire.hi ^ 1,
        },
    ));
}

#[test]
fn header_validator_has_exact_precedence_and_invariants() {
    let base = sample_header();
    let base_bytes = encode(&base);
    assert!(validate_boot_context_header_v1(&base_bytes).is_ok());
    assert_header_input_error(
        &base_bytes[..255],
        BootContextValidationError::InvalidLength,
    );
    let mut extended = base_bytes.clone();
    extended.push(0);
    assert_header_input_error(&extended, BootContextValidationError::InvalidLength);
    let mut malformed_format = base;
    malformed_format.magic ^= 1;
    resign_header(&mut malformed_format);
    let malformed_format_bytes = encode(&malformed_format);
    assert_header_input_error(
        &malformed_format_bytes[..255],
        BootContextValidationError::InvalidLength,
    );
    let mut malformed_format_extended = malformed_format_bytes;
    malformed_format_extended.push(0);
    assert_header_input_error(
        &malformed_format_extended,
        BootContextValidationError::InvalidLength,
    );

    for offset in [0usize, 8, 12, 16, 20, 24] {
        let mut bytes = base_bytes.clone();
        bytes[offset] ^= 1;
        let mut header = fsring_abi::codec::try_decode::<BootContextHeaderV1>(&bytes).unwrap();
        resign_header(&mut header);
        assert_header_error(&header, BootContextValidationError::HeaderFormat);
    }
    for init_state in [
        boot_context_init_state::EMPTY,
        boot_context_init_state::INITIALIZING,
        3,
        u32::MAX,
    ] {
        let mut header = base;
        header.init_state = init_state;
        resign_header(&mut header);
        assert_header_error(&header, BootContextValidationError::HeaderInitState);
    }
    for sequence in [0, 1, 3, u64::MAX] {
        let mut header = base;
        header.header_sequence = sequence;
        resign_header(&mut header);
        assert_header_error(&header, BootContextValidationError::HeaderSequence);
    }
    let mut stale_digest = base;
    stale_digest.mount_sequence ^= 1;
    assert_header_error(&stale_digest, BootContextValidationError::HeaderDigest);

    let mut flags = base;
    flags.flags = 1;
    resign_header(&mut flags);
    assert_header_error(&flags, BootContextValidationError::HeaderFlagsOrReserved);
    let mut reserved0 = base;
    reserved0.reserved0 = 1;
    resign_header(&mut reserved0);
    assert_header_error(
        &reserved0,
        BootContextValidationError::HeaderFlagsOrReserved,
    );
    for index in 0..base.reserved.len() {
        let mut header = base;
        header.reserved[index] = 1;
        resign_header(&mut header);
        assert_header_error(&header, BootContextValidationError::HeaderFlagsOrReserved);
    }

    let mut mount_complement = base;
    mount_complement.mount_sequence_complement ^= 1;
    resign_header(&mut mount_complement);
    assert_header_error(
        &mount_complement,
        BootContextValidationError::HeaderComplement,
    );
    let mut load_complement = base;
    load_complement.load_generation_complement ^= 1;
    resign_header(&mut load_complement);
    assert_header_error(
        &load_complement,
        BootContextValidationError::HeaderComplement,
    );

    let mut zero_boot = base;
    zero_boot.boot_instance_id = BootInstanceId::ZERO;
    resign_header(&mut zero_boot);
    assert_header_error(&zero_boot, BootContextValidationError::HeaderBootInstanceId);
    for boot_instance_id in [
        BootInstanceId { lo: 0, hi: 1 },
        BootInstanceId { lo: 1, hi: 0 },
    ] {
        let mut header = base;
        header.boot_instance_id = boot_instance_id;
        resign_header(&mut header);
        assert!(validate_boot_context_header_v1(&encode(&header)).is_ok());
    }
    let mut zero_key = base;
    zero_key.per_boot_retire_key = [0; 32];
    resign_header(&mut zero_key);
    assert_header_error(&zero_key, BootContextValidationError::HeaderRetireKey);
    let mut zero_generation = base;
    zero_generation.load_generation = 0;
    zero_generation.load_generation_complement = u64::MAX;
    resign_header(&mut zero_generation);
    assert_header_error(
        &zero_generation,
        BootContextValidationError::HeaderLoadGeneration,
    );

    let mut exhausted = base;
    exhausted.mount_sequence = u64::MAX;
    exhausted.mount_sequence_complement = 0;
    exhausted.load_generation = u64::MAX;
    exhausted.load_generation_complement = 0;
    resign_header(&mut exhausted);
    assert!(validate_boot_context_header_v1(&encode(&exhausted)).is_ok());

    let mut precedence = base;
    precedence.magic ^= 1;
    precedence.init_state = 3;
    precedence.header_sequence = 0;
    precedence.flags = 1;
    assert_header_error(&precedence, BootContextValidationError::HeaderFormat);
    let mut precedence = base;
    precedence.init_state = 3;
    precedence.header_sequence = 0;
    precedence.flags = 1;
    assert_header_error(&precedence, BootContextValidationError::HeaderInitState);
    let mut precedence = base;
    precedence.header_sequence = 0;
    precedence.flags = 1;
    assert_header_error(&precedence, BootContextValidationError::HeaderSequence);
    let mut precedence = base;
    precedence.digest[0] ^= 1;
    precedence.flags = 1;
    assert_header_error(&precedence, BootContextValidationError::HeaderDigest);
    let mut precedence = base;
    precedence.flags = 1;
    precedence.mount_sequence_complement ^= 1;
    resign_header(&mut precedence);
    assert_header_error(
        &precedence,
        BootContextValidationError::HeaderFlagsOrReserved,
    );
    let mut precedence = base;
    precedence.mount_sequence_complement ^= 1;
    precedence.boot_instance_id = BootInstanceId::ZERO;
    resign_header(&mut precedence);
    assert_header_error(&precedence, BootContextValidationError::HeaderComplement);
    let mut precedence = base;
    precedence.boot_instance_id = BootInstanceId::ZERO;
    precedence.per_boot_retire_key = [0; 32];
    resign_header(&mut precedence);
    assert_header_error(
        &precedence,
        BootContextValidationError::HeaderBootInstanceId,
    );
    let mut precedence = base;
    precedence.per_boot_retire_key = [0; 32];
    precedence.load_generation = 0;
    precedence.load_generation_complement = u64::MAX;
    resign_header(&mut precedence);
    assert_header_error(&precedence, BootContextValidationError::HeaderRetireKey);
}

#[test]
fn slot_validator_accepts_all_states_and_rejects_closed_shape() {
    let header = sample_header();
    let free = sample_free_slot(0, 2);
    assert!(validate_boot_context_slot_v1(&header, 0, &encode(&free)).is_ok());
    for state in [
        boot_context_slot_state::STAGING,
        boot_context_slot_state::LIVE,
        boot_context_slot_state::TERMINALIZING,
        boot_context_slot_state::TERMINAL,
    ] {
        let slot = sample_slot_for_state(0, state);
        assert!(validate_boot_context_slot_v1(&header, 0, &encode(&slot)).is_ok());
    }

    for state in [5, u32::MAX] {
        let mut slot = sample_live_slot(0);
        slot.state = state;
        resign_slot(0, &mut slot);
        assert_slot_error(&header, 0, &slot, BootContextValidationError::SlotState);
    }
    for sequence in [0, 1, 3, u64::MAX] {
        let mut slot = sample_live_slot(0);
        slot.sequence = sequence;
        resign_slot(0, &mut slot);
        assert_slot_error(&header, 0, &slot, BootContextValidationError::SlotSequence);
    }
    let mut stale_digest = sample_live_slot(0);
    stale_digest.digest[0] ^= 1;
    assert_slot_error(
        &header,
        0,
        &stale_digest,
        BootContextValidationError::SlotDigest,
    );
    let mut flags = sample_live_slot(0);
    flags.flags = 1;
    resign_slot(0, &mut flags);
    assert_slot_error(
        &header,
        0,
        &flags,
        BootContextValidationError::SlotFlagsOrReserved,
    );
    for index in 0..60 {
        let mut slot = sample_live_slot(0);
        slot.reserved[index] = 1;
        resign_slot(0, &mut slot);
        assert_slot_error(
            &header,
            0,
            &slot,
            BootContextValidationError::SlotFlagsOrReserved,
        );
    }

    let free_bytes = encode(&free);
    for byte_index in 8..224 {
        let mut malformed = free_bytes.clone();
        malformed[byte_index] ^= 1;
        let mut slot = fsring_abi::codec::try_decode::<BootContextSlotV1>(&malformed).unwrap();
        resign_slot(0, &mut slot);
        let result = validate_boot_context_slot_v1(&header, 0, &encode(&slot));
        assert!(result.is_err(), "FREE byte {byte_index} was accepted");
        if byte_index >= 12 {
            let expected = if (92..96).contains(&byte_index) || (164..224).contains(&byte_index) {
                BootContextValidationError::SlotFlagsOrReserved
            } else {
                BootContextValidationError::SlotFreeShape
            };
            match result {
                Err(actual) => assert_eq!(
                    actual, expected,
                    "FREE byte {byte_index} returned the wrong error",
                ),
                Ok(_) => unreachable!(),
            }
        }
    }

    for sid_length in (0..=68).chain(core::iter::once(u32::MAX)) {
        if sid_length == 32 {
            continue;
        }
        let mut slot = sample_live_slot(0);
        slot.service_sid_length = sid_length;
        resign_slot(0, &mut slot);
        assert_slot_error(
            &header,
            0,
            &slot,
            BootContextValidationError::SlotServiceSid,
        );
    }
    for byte_index in 0..SID.len() {
        for value in 0u8..=u8::MAX {
            let mut slot = sample_live_slot(0);
            slot.service_sid[byte_index] = value;
            resign_slot(0, &mut slot);
            let expected = reference_is_dedicated_service_sid(&slot.service_sid[..32]);
            match validate_boot_context_slot_v1(&header, 0, &encode(&slot)) {
                Ok(_) => assert!(
                    expected,
                    "slot accepted non-dedicated SID byte {byte_index}={value}",
                ),
                Err(error) => {
                    assert!(!expected, "slot rejected dedicated SID substitution");
                    assert_eq!(error, BootContextValidationError::SlotServiceSid);
                }
            }
        }
    }
    for first_rid in [79u32, 81] {
        let mut slot = sample_live_slot(0);
        slot.service_sid[8..12].copy_from_slice(&first_rid.to_le_bytes());
        resign_slot(0, &mut slot);
        assert_slot_error(
            &header,
            0,
            &slot,
            BootContextValidationError::SlotServiceSid,
        );
    }
    for padding_index in 32..68 {
        let mut slot = sample_live_slot(0);
        slot.service_sid[padding_index] = 1;
        resign_slot(0, &mut slot);
        assert_slot_error(
            &header,
            0,
            &slot,
            BootContextValidationError::SlotServiceSid,
        );
    }
    let mut zero_suffix = sample_live_slot(0);
    zero_suffix.service_sid[12..32].fill(0);
    resign_slot(0, &mut zero_suffix);
    assert!(validate_boot_context_slot_v1(&header, 0, &encode(&zero_suffix)).is_ok());
}

#[test]
fn slot_validator_enforces_identity_generation_features_and_sequence_space() {
    let header = sample_header();
    let base = sample_live_slot(0);

    let mut slot = base;
    slot.boot_instance_id.lo ^= 1;
    resign_slot(0, &mut slot);
    assert_slot_error(
        &header,
        0,
        &slot,
        BootContextValidationError::SlotBootInstanceId,
    );
    let mut slot = base;
    slot.boot_instance_id.hi ^= 1;
    resign_slot(0, &mut slot);
    assert_slot_error(
        &header,
        0,
        &slot,
        BootContextValidationError::SlotBootInstanceId,
    );
    let mut at_mount_counter = base;
    at_mount_counter.mount_sequence = header.mount_sequence;
    at_mount_counter.mount_id.lo = header.mount_sequence;
    resign_slot(0, &mut at_mount_counter);
    assert!(validate_boot_context_slot_v1(&header, 0, &encode(&at_mount_counter)).is_ok());
    for mount_sequence in [0, header.mount_sequence + 1] {
        let mut slot = base;
        slot.mount_sequence = mount_sequence;
        slot.mount_id.lo = mount_sequence;
        resign_slot(0, &mut slot);
        assert_slot_error(
            &header,
            0,
            &slot,
            BootContextValidationError::SlotMountSequence,
        );
    }
    let mut slot = base;
    slot.mount_id.lo ^= 1;
    resign_slot(0, &mut slot);
    assert_slot_error(
        &header,
        0,
        &slot,
        BootContextValidationError::SlotMountSequence,
    );
    let mut slot = base;
    slot.mount_id.hi = 0;
    resign_slot(0, &mut slot);
    assert_slot_error(&header, 0, &slot, BootContextValidationError::SlotMountId);

    for state in [
        boot_context_slot_state::LIVE,
        boot_context_slot_state::TERMINALIZING,
        boot_context_slot_state::TERMINAL,
    ] {
        for generation in [1, header.load_generation] {
            let mut slot = sample_slot_for_state(0, state);
            slot.load_generation = generation;
            resign_slot(0, &mut slot);
            assert!(validate_boot_context_slot_v1(&header, 0, &encode(&slot)).is_ok());
        }
    }

    for generation in [0, header.load_generation + 1] {
        let mut slot = base;
        slot.load_generation = generation;
        resign_slot(0, &mut slot);
        assert_slot_error(
            &header,
            0,
            &slot,
            BootContextValidationError::SlotLoadGeneration,
        );
    }
    let mut staging = sample_slot_for_state(0, boot_context_slot_state::STAGING);
    staging.load_generation = header.load_generation - 1;
    resign_slot(0, &mut staging);
    assert_slot_error(
        &header,
        0,
        &staging,
        BootContextValidationError::SlotLoadGeneration,
    );
    let mut slot = base;
    slot.latest_session_epoch = 0;
    resign_slot(0, &mut slot);
    assert_slot_error(
        &header,
        0,
        &slot,
        BootContextValidationError::SlotSessionEpoch,
    );
    let mut staging = sample_slot_for_state(0, boot_context_slot_state::STAGING);
    staging.latest_session_epoch = 2;
    resign_slot(0, &mut staging);
    assert_slot_error(
        &header,
        0,
        &staging,
        BootContextValidationError::SlotSessionEpoch,
    );

    for features in [
        FeatureSet { words: [0x1c, 0] },
        FeatureSet { words: [0x9f, 0] },
    ] {
        let mut slot = base;
        slot.selected_features = features;
        resign_slot(0, &mut slot);
        assert!(validate_boot_context_slot_v1(&header, 0, &encode(&slot)).is_ok());
    }
    for missing_bit in [2u8, 3, 4] {
        let mut slot = base;
        slot.selected_features.words[0] &= !(1u64 << missing_bit);
        resign_slot(0, &mut slot);
        assert_slot_error(&header, 0, &slot, BootContextValidationError::SlotFeatures);
    }
    for forbidden_bit in [5u8, 6, 8, 9, 10] {
        let mut slot = base;
        slot.selected_features.words[0] |= 1u64 << forbidden_bit;
        resign_slot(0, &mut slot);
        assert_slot_error(&header, 0, &slot, BootContextValidationError::SlotFeatures);
    }
    for features in [
        FeatureSet { words: [0x1c, 1] },
        FeatureSet {
            words: [u64::MAX, u64::MAX],
        },
    ] {
        let mut slot = base;
        slot.selected_features = features;
        resign_slot(0, &mut slot);
        assert_slot_error(&header, 0, &slot, BootContextValidationError::SlotFeatures);
    }
    for journal_version in [0, 2, u32::MAX] {
        let mut slot = base;
        slot.journal_version = journal_version;
        resign_slot(0, &mut slot);
        assert_slot_error(
            &header,
            0,
            &slot,
            BootContextValidationError::SlotJournalVersion,
        );
    }

    let sequence_cases = [
        (boot_context_slot_state::FREE, 2, 0),
        (boot_context_slot_state::STAGING, 4, 2),
        (boot_context_slot_state::LIVE, 6, 4),
        (boot_context_slot_state::TERMINALIZING, 8, 6),
        (boot_context_slot_state::TERMINAL, 8, 6),
    ];
    for (state, minimum, below) in sequence_cases {
        let mut valid = if state == boot_context_slot_state::FREE {
            sample_free_slot(0, minimum)
        } else {
            sample_slot_for_state(0, state)
        };
        valid.sequence = minimum;
        resign_slot(0, &mut valid);
        assert!(validate_boot_context_slot_v1(&header, 0, &encode(&valid)).is_ok());

        let mut invalid = valid;
        invalid.sequence = below;
        resign_slot(0, &mut invalid);
        assert_slot_error(
            &header,
            0,
            &invalid,
            BootContextValidationError::SlotSequence,
        );
    }

    let remaining_capacity = [
        (boot_context_slot_state::STAGING, u64::MAX - 9, u64::MAX - 7),
        (boot_context_slot_state::LIVE, u64::MAX - 7, u64::MAX - 5),
        (
            boot_context_slot_state::TERMINALIZING,
            u64::MAX - 5,
            u64::MAX - 3,
        ),
        (
            boot_context_slot_state::TERMINAL,
            u64::MAX - 3,
            u64::MAX - 1,
        ),
    ];
    for (state, boundary, beyond) in remaining_capacity {
        let mut slot = sample_slot_for_state(0, state);
        slot.sequence = boundary;
        resign_slot(0, &mut slot);
        assert!(validate_boot_context_slot_v1(&header, 0, &encode(&slot)).is_ok());
        slot.sequence = beyond;
        resign_slot(0, &mut slot);
        assert_slot_error(&header, 0, &slot, BootContextValidationError::SlotSequence);
    }
    let exhausted_free = sample_free_slot(0, u64::MAX - 1);
    assert!(validate_boot_context_slot_v1(&header, 0, &encode(&exhausted_free)).is_ok());

    let mut mixed = sample_live_slot(0);
    mixed.sequence = u64::MAX - 5;
    mixed.mount_sequence = 0;
    mixed.mount_id.lo = 0;
    resign_slot(0, &mut mixed);
    assert_slot_error(
        &header,
        0,
        &mixed,
        BootContextValidationError::SlotMountSequence,
    );

    let mut precedence = base;
    precedence.state = 5;
    precedence.sequence = 0;
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotState,
    );
    let mut precedence = base;
    precedence.sequence = 0;
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotSequence,
    );
    let mut precedence = base;
    precedence.flags = 1;
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotDigest,
    );
    let mut precedence = base;
    precedence.flags = 1;
    precedence.service_sid[0] = 0;
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotFlagsOrReserved,
    );
    let mut precedence = base;
    precedence.service_sid[0] = 0;
    precedence.boot_instance_id.lo ^= 1;
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotServiceSid,
    );
    let mut precedence = base;
    precedence.boot_instance_id.lo ^= 1;
    precedence.mount_sequence = 0;
    precedence.mount_id.lo = 0;
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotBootInstanceId,
    );
    let mut precedence = base;
    precedence.mount_sequence = 0;
    precedence.mount_id.lo ^= 1;
    precedence.mount_id.hi = 0;
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotMountSequence,
    );
    let mut precedence = base;
    precedence.mount_id.lo ^= 1;
    precedence.mount_id.hi = 0;
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotMountSequence,
    );
    let mut precedence = base;
    precedence.mount_id.hi = 0;
    precedence.load_generation = 0;
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotMountId,
    );
    let mut precedence = base;
    precedence.load_generation = 0;
    precedence.latest_session_epoch = 0;
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotLoadGeneration,
    );
    let mut precedence = base;
    precedence.latest_session_epoch = 0;
    precedence.selected_features.words[0] &= !(1 << 2);
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotSessionEpoch,
    );
    let mut precedence = base;
    precedence.selected_features.words[0] &= !(1 << 2);
    precedence.journal_version = 0;
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotFeatures,
    );
    let mut precedence = base;
    precedence.journal_version = 0;
    precedence.sequence = 4;
    resign_slot(0, &mut precedence);
    assert_slot_error(
        &header,
        0,
        &precedence,
        BootContextValidationError::SlotJournalVersion,
    );
    let mut free_precedence = sample_free_slot(0, 2);
    free_precedence.flags = 1;
    free_precedence.service_sid_length = 1;
    resign_slot(0, &mut free_precedence);
    assert_slot_error(
        &header,
        0,
        &free_precedence,
        BootContextValidationError::SlotFlagsOrReserved,
    );
    let mut staging_precedence = sample_slot_for_state(0, boot_context_slot_state::STAGING);
    staging_precedence.load_generation = header.load_generation - 1;
    staging_precedence.latest_session_epoch = 2;
    resign_slot(0, &mut staging_precedence);
    assert_slot_error(
        &header,
        0,
        &staging_precedence,
        BootContextValidationError::SlotLoadGeneration,
    );
    let mut staging_precedence = sample_slot_for_state(0, boot_context_slot_state::STAGING);
    staging_precedence.latest_session_epoch = 2;
    staging_precedence.selected_features.words[0] &= !(1 << 2);
    resign_slot(0, &mut staging_precedence);
    assert_slot_error(
        &header,
        0,
        &staging_precedence,
        BootContextValidationError::SlotFeatures,
    );
    let mut staging_precedence = sample_slot_for_state(0, boot_context_slot_state::STAGING);
    staging_precedence.sequence = 2;
    staging_precedence.load_generation = header.load_generation - 1;
    staging_precedence.latest_session_epoch = 2;
    resign_slot(0, &mut staging_precedence);
    assert_slot_error(
        &header,
        0,
        &staging_precedence,
        BootContextValidationError::SlotSequence,
    );
}

#[test]
fn slot_validator_revalidates_the_supplied_header() {
    let base_header = sample_header();
    let valid_slot = sample_live_slot(0);
    let mut invalid_slot = sample_live_slot(0);
    invalid_slot.mount_sequence = 0;
    invalid_slot.mount_id.lo = 0;
    resign_slot(0, &mut invalid_slot);

    let mut invalid_header = base_header;
    invalid_header.magic ^= 1;
    resign_header(&mut invalid_header);
    let invalid_slot_bytes = encode(&invalid_slot);
    assert_slot_input_error(
        &invalid_header,
        64,
        &invalid_slot_bytes[..255],
        BootContextValidationError::InvalidLength,
    );
    let mut extended_slot = invalid_slot_bytes.clone();
    extended_slot.push(0);
    assert_slot_input_error(
        &invalid_header,
        64,
        &extended_slot,
        BootContextValidationError::InvalidLength,
    );
    assert_slot_input_error(
        &invalid_header,
        64,
        &invalid_slot_bytes,
        BootContextValidationError::SlotIndex,
    );

    let mut header = base_header;
    header.magic ^= 1;
    assert_header_revalidation_error(
        &header,
        &valid_slot,
        &invalid_slot,
        BootContextValidationError::HeaderFormat,
    );
    let mut header = base_header;
    header.init_state = boot_context_init_state::INITIALIZING;
    assert_header_revalidation_error(
        &header,
        &valid_slot,
        &invalid_slot,
        BootContextValidationError::HeaderInitState,
    );
    let mut header = base_header;
    header.header_sequence = 0;
    assert_header_revalidation_error(
        &header,
        &valid_slot,
        &invalid_slot,
        BootContextValidationError::HeaderSequence,
    );
    let mut header = base_header;
    header.digest[0] ^= 1;
    assert_header_revalidation_error(
        &header,
        &valid_slot,
        &invalid_slot,
        BootContextValidationError::HeaderDigest,
    );
    let mut header = base_header;
    header.flags = 1;
    resign_header(&mut header);
    assert_header_revalidation_error(
        &header,
        &valid_slot,
        &invalid_slot,
        BootContextValidationError::HeaderFlagsOrReserved,
    );
    let mut header = base_header;
    header.mount_sequence_complement ^= 1;
    resign_header(&mut header);
    assert_header_revalidation_error(
        &header,
        &valid_slot,
        &invalid_slot,
        BootContextValidationError::HeaderComplement,
    );
    let mut header = base_header;
    header.boot_instance_id = BootInstanceId::ZERO;
    resign_header(&mut header);
    assert_header_revalidation_error(
        &header,
        &valid_slot,
        &invalid_slot,
        BootContextValidationError::HeaderBootInstanceId,
    );
    let mut header = base_header;
    header.per_boot_retire_key = [0; 32];
    resign_header(&mut header);
    assert_header_revalidation_error(
        &header,
        &valid_slot,
        &invalid_slot,
        BootContextValidationError::HeaderRetireKey,
    );
    let mut header = base_header;
    header.load_generation = 0;
    header.load_generation_complement = u64::MAX;
    resign_header(&mut header);
    assert_header_revalidation_error(
        &header,
        &valid_slot,
        &invalid_slot,
        BootContextValidationError::HeaderLoadGeneration,
    );
}

#[test]
fn section_validator_checks_every_slot_uniqueness_and_tail() {
    let valid = sample_valid_section();
    assert_eq!(valid.len(), 65_536);
    assert!(validate_boot_context_section_v1(&valid).is_ok());
    let mut invalid_length = valid.clone();
    let mut bad_format_header = sample_header();
    bad_format_header.magic ^= 1;
    resign_header(&mut bad_format_header);
    put_header(&mut invalid_length, &bad_format_header);
    let slot_0 = boot_context_slot_offset_v1(0).unwrap() as usize;
    invalid_length[slot_0 + 224] ^= 1;
    invalid_length[BOOT_CONTEXT_USED_BYTES as usize] = 1;
    assert_section_error(
        &invalid_length[..65_535],
        BootContextValidationError::InvalidLength,
    );
    let mut too_long = invalid_length;
    too_long.push(0);
    assert_section_error(&too_long, BootContextValidationError::InvalidLength);

    let base_header = sample_header();
    let mut invalid_headers = Vec::new();
    let mut header = base_header;
    header.magic ^= 1;
    resign_header(&mut header);
    invalid_headers.push((header, BootContextValidationError::HeaderFormat));
    let mut header = base_header;
    header.init_state = boot_context_init_state::INITIALIZING;
    resign_header(&mut header);
    invalid_headers.push((header, BootContextValidationError::HeaderInitState));
    let mut header = base_header;
    header.header_sequence = 0;
    resign_header(&mut header);
    invalid_headers.push((header, BootContextValidationError::HeaderSequence));
    let mut header = base_header;
    header.digest[0] ^= 1;
    invalid_headers.push((header, BootContextValidationError::HeaderDigest));
    let mut header = base_header;
    header.flags = 1;
    resign_header(&mut header);
    invalid_headers.push((header, BootContextValidationError::HeaderFlagsOrReserved));
    let mut header = base_header;
    header.mount_sequence_complement ^= 1;
    resign_header(&mut header);
    invalid_headers.push((header, BootContextValidationError::HeaderComplement));
    let mut header = base_header;
    header.boot_instance_id = BootInstanceId::ZERO;
    resign_header(&mut header);
    invalid_headers.push((header, BootContextValidationError::HeaderBootInstanceId));
    let mut header = base_header;
    header.per_boot_retire_key = [0; 32];
    resign_header(&mut header);
    invalid_headers.push((header, BootContextValidationError::HeaderRetireKey));
    let mut header = base_header;
    header.load_generation = 0;
    header.load_generation_complement = u64::MAX;
    resign_header(&mut header);
    invalid_headers.push((header, BootContextValidationError::HeaderLoadGeneration));
    for (header, expected) in invalid_headers {
        let mut section = valid.clone();
        put_header(&mut section, &header);
        let slot_0 = boot_context_slot_offset_v1(0).unwrap() as usize;
        section[slot_0 + 224] ^= 1;
        section[BOOT_CONTEXT_USED_BYTES as usize] = 1;
        assert_section_error(&section, expected);
    }

    for index in 0..BOOT_CONTEXT_SLOT_COUNT {
        let mut corrupt = valid.clone();
        let offset = boot_context_slot_offset_v1(index).unwrap() as usize;
        corrupt[offset + 224] ^= 1;
        match validate_boot_context_section_v1(&corrupt) {
            Err(actual) => assert_eq!(
                actual,
                BootContextValidationError::SlotDigest,
                "slot {index} was not validated",
            ),
            Ok(_) => panic!("corrupt slot {index} was accepted"),
        }
    }

    let mut all_live = valid.clone();
    let mut slots = Vec::new();
    for index in 0..BOOT_CONTEXT_SLOT_COUNT {
        let mut slot = sample_live_slot(index);
        slot.mount_sequence = u64::from(index) + 1;
        slot.mount_id = MountId {
            lo: slot.mount_sequence,
            hi: 0x1000 + u64::from(index),
        };
        resign_slot(index, &mut slot);
        put_slot(&mut all_live, index, &slot);
        slots.push(slot);
    }
    assert!(validate_boot_context_section_v1(&all_live).is_ok());

    let mut exact_duplicate = all_live.clone();
    let mut duplicate = slots[63];
    duplicate.mount_sequence = slots[0].mount_sequence;
    duplicate.mount_id = slots[0].mount_id;
    resign_slot(63, &mut duplicate);
    put_slot(&mut exact_duplicate, 63, &duplicate);
    assert_section_error(
        &exact_duplicate,
        BootContextValidationError::DuplicateMountSequence,
    );

    let mut different_hi = all_live.clone();
    duplicate.mount_id.hi ^= 1;
    resign_slot(63, &mut duplicate);
    put_slot(&mut different_hi, 63, &duplicate);
    assert_section_error(
        &different_hi,
        BootContextValidationError::DuplicateMountSequence,
    );

    let mut semantic_before_duplicate = all_live.clone();
    let mut malformed_duplicate = slots[63];
    malformed_duplicate.mount_sequence = slots[0].mount_sequence;
    malformed_duplicate.mount_id = slots[0].mount_id;
    malformed_duplicate.journal_version = 0;
    resign_slot(63, &mut malformed_duplicate);
    put_slot(&mut semantic_before_duplicate, 63, &malformed_duplicate);
    assert_section_error(
        &semantic_before_duplicate,
        BootContextValidationError::SlotJournalVersion,
    );

    let mut duplicate_before_tail = exact_duplicate.clone();
    duplicate_before_tail[BOOT_CONTEXT_USED_BYTES as usize] = 1;
    assert_section_error(
        &duplicate_before_tail,
        BootContextValidationError::DuplicateMountSequence,
    );

    let mut ascending_slots = valid.clone();
    let earlier_offset = boot_context_slot_offset_v1(2).unwrap() as usize;
    ascending_slots[earlier_offset + 224] ^= 1;
    let mut later_slot = sample_free_slot(5, 2);
    later_slot.state = u32::MAX;
    resign_slot(5, &mut later_slot);
    put_slot(&mut ascending_slots, 5, &later_slot);
    assert_section_error(&ascending_slots, BootContextValidationError::SlotDigest);

    let tail_start = BOOT_CONTEXT_USED_BYTES as usize;
    for offset in [tail_start, (tail_start + 65_535) / 2, 65_535] {
        let mut corrupt = valid.clone();
        corrupt[offset] = 1;
        assert_section_error(&corrupt, BootContextValidationError::ImmutableTail);
    }
    let mut slot_before_tail = valid;
    let slot_63 = boot_context_slot_offset_v1(63).unwrap() as usize;
    slot_before_tail[slot_63 + 224] ^= 1;
    slot_before_tail[tail_start] = 1;
    assert_section_error(&slot_before_tail, BootContextValidationError::SlotDigest);
}

#[test]
fn initial_ready_section_has_canonical_full_image_hash() {
    assert_eq!(
        ReferenceSha256::digest(b""),
        decode_hex::<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    );
    assert_eq!(
        ReferenceSha256::digest(b"abc"),
        decode_hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    );

    let header = initial_header_reference();
    let slot_0 = initial_free_slot_reference(0);
    let slot_63 = initial_free_slot_reference(63);
    assert_eq!(header.digest, decode_hex::<32>(INITIAL_HEADER_DIGEST_HEX),);
    assert_eq!(slot_0.digest, decode_hex::<32>(INITIAL_SLOT_0_DIGEST_HEX),);
    assert_eq!(slot_63.digest, decode_hex::<32>(INITIAL_SLOT_63_DIGEST_HEX),);
    assert_eq!(boot_context_header_digest_v1(&header), header.digest);
    assert_eq!(boot_context_slot_digest_v1(0, &slot_0), Some(slot_0.digest));
    assert_eq!(
        boot_context_slot_digest_v1(63, &slot_63),
        Some(slot_63.digest),
    );

    let section = initial_section_reference();
    assert_eq!(section.len(), BOOT_CONTEXT_SECTION_BYTES as usize);
    assert_eq!(
        &section[..BOOT_CONTEXT_HEADER_BYTES as usize],
        encode_header_reference(&header).as_slice(),
    );
    for index in 0..BOOT_CONTEXT_SLOT_COUNT {
        let offset = boot_context_slot_offset_v1(index).unwrap() as usize;
        let slot_bytes = &section[offset..offset + BOOT_CONTEXT_SLOT_BYTES as usize];
        let slot = fsring_abi::codec::try_decode::<BootContextSlotV1>(slot_bytes).unwrap();
        assert_eq!(slot.sequence, BOOT_CONTEXT_INITIAL_SEQUENCE);
        assert_eq!(slot.state, boot_context_slot_state::FREE);
        assert!(slot_bytes[8..224].iter().all(|byte| *byte == 0));
        assert_eq!(
            slot.digest,
            reference_slot_digest(index, &slot),
            "FREE slot {index} did not bind its index",
        );
    }
    assert!(section[BOOT_CONTEXT_USED_BYTES as usize..]
        .iter()
        .all(|byte| *byte == 0));
    assert_eq!(
        ReferenceSha256::digest(&section),
        decode_hex::<32>(INITIAL_SECTION_SHA256_HEX),
    );
    assert!(validate_boot_context_section_v1(&section).is_ok());
}

#[test]
fn slice_apis_reject_lengths_indices_and_mutations_without_panicking() {
    let header = sample_header();
    let header_bytes = encode(&header);
    let free = sample_free_slot(0, 2);
    let free_bytes = encode(&free);
    let live = sample_live_slot(0);
    let live_bytes = encode(&live);
    let section = sample_valid_section();
    let active = state_input(retire_mount_state::ACTIVE, MOUNT, RESTART_FEATURES);
    let mut sid_buffer = [0u8; 69];
    sid_buffer[..SID.len()].copy_from_slice(&SID);

    for length in 0..=69 {
        let sid = &sid_buffer[..length];
        match catch_unwind(AssertUnwindSafe(|| is_dedicated_service_sid_v1(sid))) {
            Ok(accepted) => assert_eq!(accepted, length == 32),
            Err(_) => panic!("SID predicate panicked at length {length}"),
        }
        match catch_unwind(AssertUnwindSafe(|| {
            derive_retire_token_v2(&KEY, BOOT, MOUNT, sid)
        })) {
            Ok(Ok(_)) => assert_eq!(length, 32),
            Ok(Err(error)) => {
                assert_ne!(length, 32);
                assert_eq!(error, BootTokenError::InvalidServiceSid);
            }
            Err(_) => panic!("retire derivation panicked at SID length {length}"),
        }
        match catch_unwind(AssertUnwindSafe(|| {
            derive_state_token_v2(&KEY, active, sid)
        })) {
            Ok(Ok(_)) => assert_eq!(length, 32),
            Ok(Err(error)) => {
                assert_ne!(length, 32);
                assert_eq!(error, BootTokenError::InvalidServiceSid);
            }
            Err(_) => panic!("state derivation panicked at SID length {length}"),
        }
    }

    for length in 0..=257 {
        let mut input = vec![0u8; length];
        let copied = length.min(header_bytes.len());
        input[..copied].copy_from_slice(&header_bytes[..copied]);
        match catch_unwind(AssertUnwindSafe(|| validate_boot_context_header_v1(&input))) {
            Ok(Ok(_)) => assert_eq!(length, 256),
            Ok(Err(error)) => {
                assert_ne!(length, 256);
                assert_eq!(error, BootContextValidationError::InvalidLength);
            }
            Err(_) => panic!("header validator panicked at length {length}"),
        }

        input.fill(0);
        let copied = length.min(live_bytes.len());
        input[..copied].copy_from_slice(&live_bytes[..copied]);
        match catch_unwind(AssertUnwindSafe(|| {
            validate_boot_context_slot_v1(&header, 0, &input)
        })) {
            Ok(Ok(_)) => assert_eq!(length, 256),
            Ok(Err(error)) => {
                assert_ne!(length, 256);
                assert_eq!(error, BootContextValidationError::InvalidLength);
            }
            Err(_) => panic!("slot validator panicked at length {length}"),
        }
    }

    for length in [
        0usize, 1, 255, 256, 257, 16_383, 16_384, 16_639, 16_640, 65_535, 65_536, 65_537,
    ] {
        let mut input = section.clone();
        input.resize(length, 0);
        match catch_unwind(AssertUnwindSafe(|| {
            validate_boot_context_section_v1(&input)
        })) {
            Ok(Ok(_)) => assert_eq!(length, 65_536),
            Ok(Err(error)) => {
                assert_ne!(length, 65_536);
                assert_eq!(error, BootContextValidationError::InvalidLength);
            }
            Err(_) => panic!("section validator panicked at length {length}"),
        }
    }

    for index in [63, 64, u32::MAX] {
        let slot = sample_free_slot(index.min(63), 2);
        let bytes = encode(&slot);
        match catch_unwind(AssertUnwindSafe(|| boot_context_slot_offset_v1(index))) {
            Ok(offset) => assert_eq!(offset.is_some(), index == 63),
            Err(_) => panic!("slot offset panicked at index {index}"),
        }
        match catch_unwind(AssertUnwindSafe(|| {
            boot_context_slot_digest_v1(index, &slot)
        })) {
            Ok(digest) => assert_eq!(digest.is_some(), index == 63),
            Err(_) => panic!("slot digest panicked at index {index}"),
        }
        match catch_unwind(AssertUnwindSafe(|| {
            validate_boot_context_slot_v1(&header, index, &bytes)
        })) {
            Ok(Ok(_)) => assert_eq!(index, 63),
            Ok(Err(error)) => {
                assert_ne!(index, 63);
                assert_eq!(error, BootContextValidationError::SlotIndex);
            }
            Err(_) => panic!("slot validator panicked at index {index}"),
        }
    }

    for byte_index in 0..header_bytes.len() {
        let mut mutated = header_bytes.clone();
        mutated[byte_index] ^= 1;
        match catch_unwind(AssertUnwindSafe(|| {
            validate_boot_context_header_v1(&mutated)
        })) {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("header mutation byte {byte_index} was accepted"),
            Err(_) => panic!("header mutation byte {byte_index} panicked"),
        }
    }
    for (label, bytes) in [("FREE", &free_bytes), ("LIVE", &live_bytes)] {
        for byte_index in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[byte_index] ^= 1;
            match catch_unwind(AssertUnwindSafe(|| {
                validate_boot_context_slot_v1(&header, 0, &mutated)
            })) {
                Ok(Err(_)) => {}
                Ok(Ok(_)) => panic!("{label} mutation byte {byte_index} was accepted"),
                Err(_) => panic!("{label} mutation byte {byte_index} panicked"),
            }
        }
    }

    let tail_start = BOOT_CONTEXT_USED_BYTES as usize;
    for byte_index in [tail_start, (tail_start + 65_535) / 2, 65_535] {
        let mut mutated = section.clone();
        mutated[byte_index] ^= 1;
        match catch_unwind(AssertUnwindSafe(|| {
            validate_boot_context_section_v1(&mutated)
        })) {
            Ok(Err(error)) => assert_eq!(error, BootContextValidationError::ImmutableTail),
            Ok(Ok(_)) => panic!("tail mutation byte {byte_index} was accepted"),
            Err(_) => panic!("tail mutation byte {byte_index} panicked"),
        }
    }
}

#[test]
fn wave4a_keeps_abi_identity_and_header_frozen() {
    // Wave 10 activation rebaseline: identity is now 2.1, the header is the
    // activated 2.1 contract (frozen at the new SHA for Waves 11-14), and the
    // Wave 4a boot-context wire types are now exported. Only `digest` remains
    // cbindgen-hidden; internal digest/error/domain items stay out of the header.
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.2.1");
    assert_eq!(FSRING_ABI_MINOR, 1);
    let frozen_header = include_bytes!("../include/fsring_abi.h");
    assert_eq!(
        ReferenceSha256::digest(frozen_header),
        decode_hex::<32>(FROZEN_HEADER_SHA256_HEX),
    );

    let crate_root = include_str!("../src/lib.rs");
    assert_eq!(crate_root.matches("/// cbindgen:ignore").count(), 1);
    assert!(crate_root.contains("/// cbindgen:ignore\npub mod digest;"));

    let header_text = core::str::from_utf8(frozen_header).unwrap();
    // The Wave 4a boot-context wire types are now part of the activated contract.
    assert!(header_text.contains("BootContextHeaderV1"));
    assert!(header_text.contains("BootContextSlotV1"));
    // Digest-only, error, and domain items remain internal.
    for forbidden in [
        "BootTokenError",
        "StateTokenInput",
        "BOOT_CONTEXT_HEADER_DIGEST_DOMAIN",
        "boot_context_header_digest_v1",
        "boot_context_slot_digest_v1",
        "derive_retire_token_v2",
        "derive_state_token_v2",
        "retire_token_eq",
    ] {
        assert!(
            !header_text.contains(forbidden),
            "digest-only item leaked into the activated C header: {forbidden}",
        );
    }
}
