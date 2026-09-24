use crate::{
    control::{
        retire_mount_state, BootContextHeaderV1, BootContextSlotV1, BOOT_CONTEXT_SLOT_COUNT,
    },
    features::FeatureSet,
    ids::{BootInstanceId, FileId, MountId, OpId, RetireToken, TransactionId},
    layout::FSRING_ABI_MAJOR,
    limits::{validate_file_range, MAX_COMPONENT_UTF16_CODE_UNITS},
    msgs::{journal_version, mutation_kind, rw_flags, BlobSlice},
    op,
};

pub const BOOT_CONTEXT_HEADER_DIGEST_DOMAIN: &[u8; 22] = b"FSRING-BOOT-HEADER-v1\0";
pub const BOOT_CONTEXT_SLOT_DIGEST_DOMAIN: &[u8; 20] = b"FSRING-BOOT-SLOT-v1\0";
pub const RETIRE_TOKEN_DOMAIN_V2: &[u8; 17] = b"FSRING-RETIRE-v2\0";
pub const STATE_TOKEN_DOMAIN_V2: &[u8; 22] = b"FSRING-MOUNT-STATE-v2\0";
pub const EXTERNAL_DIR_CHANGE_DIGEST_DOMAIN: &[u8; 30] = b"FSRING-EXTERNAL-DIR-CHANGE-v1\0";

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_len: u64,
}

pub fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(input);
    digest.finalize()
}

/// Section 14.2 external directory-change semantic digest. `canonical_envelope`
/// is the full `NotifyEnvelopeV2` bytes through the body `struct_size`; session
/// credit and BufferRef coordinates never appear in the image.
pub fn external_dir_change_semantic_digest_v1(
    mount_id: MountId,
    canonical_envelope: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(EXTERNAL_DIR_CHANGE_DIGEST_DOMAIN);
    hash.update(&mount_id.lo.to_le_bytes());
    hash.update(&mount_id.hi.to_le_bytes());
    hash.update(canonical_envelope);
    hash.finalize()
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            block_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.total_len = self.total_len.wrapping_add(input.len() as u64);

        if self.block_len != 0 {
            let needed = 64 - self.block_len;
            let copied = core::cmp::min(needed, input.len());
            self.block[self.block_len..self.block_len + copied].copy_from_slice(&input[..copied]);
            self.block_len += copied;
            input = &input[copied..];
            if self.block_len == 64 {
                let block = self.block;
                self.compress(&block);
                self.block_len = 0;
            }
        }

        while input.len() >= 64 {
            self.block.copy_from_slice(&input[..64]);
            let block = self.block;
            self.compress(&block);
            input = &input[64..];
        }

        if !input.is_empty() {
            self.block[..input.len()].copy_from_slice(input);
            self.block_len = input.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.block[self.block_len] = 0x80;
        self.block_len += 1;

        if self.block_len > 56 {
            self.block[self.block_len..].fill(0);
            let block = self.block;
            self.compress(&block);
            self.block = [0; 64];
            self.block_len = 0;
        }

        self.block[self.block_len..56].fill(0);
        self.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.block;
        self.compress(&block);

        let mut output = [0u8; 32];
        let mut index = 0usize;
        while index < self.state.len() {
            let offset = index * 4;
            output[offset..offset + 4].copy_from_slice(&self.state[index].to_be_bytes());
            index += 1;
        }
        output
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 64];
        let mut index = 0usize;
        while index < 16 {
            let offset = index * 4;
            words[index] = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
            index += 1;
        }
        while index < words.len() {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
            index += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        index = 0;
        while index < words.len() {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
            index += 1;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; 64];
        if key.len() > key_block.len() {
            let mut hash = Sha256::new();
            hash.update(key);
            key_block[..32].copy_from_slice(&hash.finalize());
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut inner_pad = [0x36u8; 64];
        let mut outer_pad = [0x5cu8; 64];
        let mut index = 0usize;
        while index < key_block.len() {
            inner_pad[index] ^= key_block[index];
            outer_pad[index] ^= key_block[index];
            index += 1;
        }

        let mut inner = Sha256::new();
        inner.update(&inner_pad);
        let mut outer = Sha256::new();
        outer.update(&outer_pad);
        Self { inner, outer }
    }

    fn update(&mut self, input: &[u8]) {
        self.inner.update(input);
    }

    fn finalize(mut self) -> [u8; 32] {
        let inner_digest = self.inner.finalize();
        self.outer.update(&inner_digest);
        self.outer.finalize()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateTokenInput {
    pub boot_instance_id: BootInstanceId,
    pub result_mount_id: MountId,
    pub mount_state: u16,
    pub latest_session_epoch: u64,
    pub selected_features: FeatureSet,
    pub journal_version: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootTokenError {
    ZeroKey,
    ZeroBootInstanceId,
    InvalidMountState,
    InvalidStateFields,
    InvalidMountId,
    InvalidServiceSid,
}

fn put_u32(output: &mut [u8; 256], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8; 256], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn encode_header(header: &BootContextHeaderV1) -> [u8; 256] {
    let mut output = [0u8; 256];
    put_u64(&mut output, 0, header.magic);
    put_u32(&mut output, 8, header.format_version);
    put_u32(&mut output, 12, header.header_size);
    put_u32(&mut output, 16, header.context_size);
    put_u32(&mut output, 20, header.slot_size);
    put_u32(&mut output, 24, header.slot_count);
    put_u32(&mut output, 28, header.init_state);
    put_u32(&mut output, 32, header.flags);
    put_u32(&mut output, 36, header.reserved0);
    put_u64(&mut output, 40, header.header_sequence);
    put_u64(&mut output, 48, header.mount_sequence);
    put_u64(&mut output, 56, header.mount_sequence_complement);
    put_u64(&mut output, 64, header.load_generation);
    put_u64(&mut output, 72, header.load_generation_complement);
    put_u64(&mut output, 80, header.boot_instance_id.lo);
    put_u64(&mut output, 88, header.boot_instance_id.hi);
    output[96..128].copy_from_slice(&header.per_boot_retire_key);
    output[128..160].fill(0);
    output[160..256].copy_from_slice(&header.reserved);
    output
}

fn encode_slot(slot: &BootContextSlotV1) -> [u8; 256] {
    let mut output = [0u8; 256];
    put_u64(&mut output, 0, slot.sequence);
    put_u32(&mut output, 8, slot.state);
    put_u32(&mut output, 12, slot.service_sid_length);
    put_u64(&mut output, 16, slot.load_generation);
    put_u64(&mut output, 24, slot.mount_sequence);
    put_u64(&mut output, 32, slot.mount_id.lo);
    put_u64(&mut output, 40, slot.mount_id.hi);
    put_u64(&mut output, 48, slot.boot_instance_id.lo);
    put_u64(&mut output, 56, slot.boot_instance_id.hi);
    put_u64(&mut output, 64, slot.latest_session_epoch);
    put_u64(&mut output, 72, slot.selected_features.words[0]);
    put_u64(&mut output, 80, slot.selected_features.words[1]);
    put_u32(&mut output, 88, slot.journal_version);
    put_u32(&mut output, 92, slot.flags);
    output[96..164].copy_from_slice(&slot.service_sid);
    output[164..224].copy_from_slice(&slot.reserved);
    output[224..256].fill(0);
    output
}

pub fn boot_context_header_digest_v1(header: &BootContextHeaderV1) -> [u8; 32] {
    let image = encode_header(header);
    let mut hash = Sha256::new();
    hash.update(BOOT_CONTEXT_HEADER_DIGEST_DOMAIN);
    hash.update(&image);
    hash.finalize()
}

pub fn boot_context_slot_digest_v1(slot_index: u32, slot: &BootContextSlotV1) -> Option<[u8; 32]> {
    if slot_index >= BOOT_CONTEXT_SLOT_COUNT {
        return None;
    }
    let image = encode_slot(slot);
    let mut hash = Sha256::new();
    hash.update(BOOT_CONTEXT_SLOT_DIGEST_DOMAIN);
    hash.update(&slot_index.to_le_bytes());
    hash.update(&image);
    Some(hash.finalize())
}

fn key_is_all_zero(key: &[u8; 32]) -> bool {
    let mut aggregate = 0u8;
    let mut index = 0usize;
    while index < key.len() {
        aggregate |= key[index];
        index += 1;
    }
    aggregate == 0
}

fn token_from_hmac(hmac: HmacSha256) -> RetireToken {
    let digest = hmac.finalize();
    RetireToken {
        lo: u64::from_le_bytes([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        ]),
        hi: u64::from_le_bytes([
            digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
            digest[15],
        ]),
    }
}

pub fn derive_retire_token_v2(
    key: &[u8; 32],
    boot_instance_id: BootInstanceId,
    mount_id: MountId,
    service_sid: &[u8],
) -> Result<RetireToken, BootTokenError> {
    if key_is_all_zero(key) {
        return Err(BootTokenError::ZeroKey);
    }
    if boot_instance_id.lo | boot_instance_id.hi == 0 {
        return Err(BootTokenError::ZeroBootInstanceId);
    }
    if mount_id.lo == 0 || mount_id.hi == 0 {
        return Err(BootTokenError::InvalidMountId);
    }
    if !crate::validate::is_dedicated_service_sid_v1(service_sid) {
        return Err(BootTokenError::InvalidServiceSid);
    }

    let mut hmac = HmacSha256::new(key);
    hmac.update(RETIRE_TOKEN_DOMAIN_V2);
    hmac.update(&boot_instance_id.lo.to_le_bytes());
    hmac.update(&boot_instance_id.hi.to_le_bytes());
    hmac.update(&mount_id.lo.to_le_bytes());
    hmac.update(&mount_id.hi.to_le_bytes());
    hmac.update(&32u32.to_le_bytes());
    hmac.update(service_sid);
    Ok(token_from_hmac(hmac))
}

pub fn derive_state_token_v2(
    key: &[u8; 32],
    input: StateTokenInput,
    service_sid: &[u8],
) -> Result<RetireToken, BootTokenError> {
    if key_is_all_zero(key) {
        return Err(BootTokenError::ZeroKey);
    }
    if input.boot_instance_id.lo | input.boot_instance_id.hi == 0 {
        return Err(BootTokenError::ZeroBootInstanceId);
    }

    match input.mount_state {
        retire_mount_state::ABSENT => {
            if input.latest_session_epoch != 0
                || input.selected_features.words[0] != 0
                || input.selected_features.words[1] != 0
                || input.journal_version != 0
            {
                return Err(BootTokenError::InvalidStateFields);
            }
        }
        retire_mount_state::ACTIVE
        | retire_mount_state::GRACE
        | retire_mount_state::BOUND_RECONCILING => {
            if input.latest_session_epoch == 0
                || input.selected_features.words[0] & !0x9f != 0
                || input.selected_features.words[1] != 0
                || input.selected_features.words[0] & 0x1c != 0x1c
                || input.journal_version != 1
            {
                return Err(BootTokenError::InvalidStateFields);
            }
        }
        _ => return Err(BootTokenError::InvalidMountState),
    }

    if input.mount_state != retire_mount_state::ABSENT
        && (input.result_mount_id.lo == 0 || input.result_mount_id.hi == 0)
    {
        return Err(BootTokenError::InvalidMountId);
    }
    if !crate::validate::is_dedicated_service_sid_v1(service_sid) {
        return Err(BootTokenError::InvalidServiceSid);
    }

    let mut hmac = HmacSha256::new(key);
    hmac.update(STATE_TOKEN_DOMAIN_V2);
    hmac.update(&input.boot_instance_id.lo.to_le_bytes());
    hmac.update(&input.boot_instance_id.hi.to_le_bytes());
    hmac.update(&input.result_mount_id.lo.to_le_bytes());
    hmac.update(&input.result_mount_id.hi.to_le_bytes());
    hmac.update(&input.mount_state.to_le_bytes());
    hmac.update(&0u16.to_le_bytes());
    hmac.update(&input.latest_session_epoch.to_le_bytes());
    hmac.update(&input.selected_features.words[0].to_le_bytes());
    hmac.update(&input.selected_features.words[1].to_le_bytes());
    hmac.update(&input.journal_version.to_le_bytes());
    hmac.update(&32u32.to_le_bytes());
    hmac.update(service_sid);
    Ok(token_from_hmac(hmac))
}

#[inline(never)]
pub fn retire_token_eq(left: RetireToken, right: RetireToken) -> bool {
    ((left.lo ^ right.lo) | (left.hi ^ right.hi)) == 0
}

pub const OP_DIGEST_DOMAIN: &[u8; 16] = b"FSRING-OP-DIGEST";
pub const OP_DIGEST_FORMAT_V1: u16 = 1;
pub const OP_DIGEST_PREFIX_BYTES: u32 = 64;
pub const COMMIT_OPEN_DIGEST_V1_PREFIX_BYTES: u32 = 112;
pub const WRITE_DIGEST_V1_PREFIX_BYTES: u32 = 72;
pub const MUTATION_DIGEST_V1_PREFIX_BYTES: u32 = 64;
pub const MAX_JOURNALED_WRITE_BYTES_PER_REQUEST: u32 = 16_777_216;
pub const MAX_IMMUTABLE_WRITE_BYTES_PER_MOUNT: u64 = 268_435_456;

const JOURNALED_RW_FLAGS: u32 = rw_flags::PAGING
    | rw_flags::NOCACHE
    | rw_flags::WRITE_THROUGH
    | rw_flags::MAPPED
    | rw_flags::SYNC_PAGING
    | rw_flags::EXTENDING
    | rw_flags::ZERO_RANGE_VALID;

const MAX_STORED_COMPONENT_BYTES: u32 = MAX_COMPONENT_UTF16_CODE_UNITS * 2;
const MAX_MUTATION_BODY_BYTES: u32 = 65_560;
const MAX_DIGEST_SECURITY_DESCRIPTOR_BYTES: u32 = 65_536;
const MAX_DIGEST_EA_BYTES: u32 = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpDigestError {
    UnsupportedOpcode,
    MutationKindPairing,
    ZeroIdentity,
    FlagsOrReserved,
    InvalidScalar,
    SliceGeometry,
    LengthMismatch,
    Range,
}

/// Canonical COMMIT_OPEN transcript; section 12 `CommitOpenDigestV1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitOpenDigestV1 {
    pub parent_id: FileId,
    pub transaction_id: TransactionId,
    pub kernel_open_id: u64,
    pub expected_namespace_generation: u64,
    pub expected_security_generation: u64,
    pub desired_access: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub create_options: u32,
    pub file_attributes: u32,
    pub open_flags: u32,
    pub granted_access: u32,
    pub commit_flags: u32,
    pub name: BlobSlice,
    pub requested_security_descriptor: BlobSlice,
    pub ea: BlobSlice,
}

/// Canonical WRITE transcript; section 12 `WriteDigestV1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteDigestV1 {
    pub file_id: FileId,
    pub kernel_open_id: u64,
    pub offset: u64,
    pub size_epoch: u64,
    pub initialized_offset: u64,
    pub length: u32,
    pub initialized_length: u32,
    pub rw_flags: u32,
    pub reserved: u32,
    pub data: BlobSlice,
}

/// Canonical MUTATE transcript; section 12 `MutationDigestV1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutationDigestV1 {
    pub file_id: FileId,
    pub kernel_open_id: u64,
    pub expected_namespace_generation: u64,
    pub expected_size_epoch: u64,
    pub expected_security_generation: u64,
    pub mutation_kind: u16,
    pub mutation_flags: u16,
    pub body_length: u32,
    pub body: BlobSlice,
}

fn put_blob_at(output: &mut [u8], offset: usize, value: BlobSlice) {
    output[offset..offset + 4].copy_from_slice(&value.offset.to_le_bytes());
    output[offset + 4..offset + 8].copy_from_slice(&value.length.to_le_bytes());
}

pub fn encode_commit_open_digest_prefix_v1(transcript: &CommitOpenDigestV1) -> [u8; 112] {
    let mut out = [0u8; 112];
    out[0..8].copy_from_slice(&transcript.parent_id.lo.to_le_bytes());
    out[8..16].copy_from_slice(&transcript.parent_id.hi.to_le_bytes());
    out[16..24].copy_from_slice(&transcript.transaction_id.lo.to_le_bytes());
    out[24..32].copy_from_slice(&transcript.transaction_id.hi.to_le_bytes());
    out[32..40].copy_from_slice(&transcript.kernel_open_id.to_le_bytes());
    out[40..48].copy_from_slice(&transcript.expected_namespace_generation.to_le_bytes());
    out[48..56].copy_from_slice(&transcript.expected_security_generation.to_le_bytes());
    out[56..60].copy_from_slice(&transcript.desired_access.to_le_bytes());
    out[60..64].copy_from_slice(&transcript.share_access.to_le_bytes());
    out[64..68].copy_from_slice(&transcript.disposition.to_le_bytes());
    out[68..72].copy_from_slice(&transcript.create_options.to_le_bytes());
    out[72..76].copy_from_slice(&transcript.file_attributes.to_le_bytes());
    out[76..80].copy_from_slice(&transcript.open_flags.to_le_bytes());
    out[80..84].copy_from_slice(&transcript.granted_access.to_le_bytes());
    out[84..88].copy_from_slice(&transcript.commit_flags.to_le_bytes());
    put_blob_at(&mut out, 88, transcript.name);
    put_blob_at(&mut out, 96, transcript.requested_security_descriptor);
    put_blob_at(&mut out, 104, transcript.ea);
    out
}

pub fn encode_write_digest_prefix_v1(transcript: &WriteDigestV1) -> [u8; 72] {
    let mut out = [0u8; 72];
    out[0..8].copy_from_slice(&transcript.file_id.lo.to_le_bytes());
    out[8..16].copy_from_slice(&transcript.file_id.hi.to_le_bytes());
    out[16..24].copy_from_slice(&transcript.kernel_open_id.to_le_bytes());
    out[24..32].copy_from_slice(&transcript.offset.to_le_bytes());
    out[32..40].copy_from_slice(&transcript.size_epoch.to_le_bytes());
    out[40..48].copy_from_slice(&transcript.initialized_offset.to_le_bytes());
    out[48..52].copy_from_slice(&transcript.length.to_le_bytes());
    out[52..56].copy_from_slice(&transcript.initialized_length.to_le_bytes());
    out[56..60].copy_from_slice(&transcript.rw_flags.to_le_bytes());
    out[60..64].copy_from_slice(&transcript.reserved.to_le_bytes());
    put_blob_at(&mut out, 64, transcript.data);
    out
}

pub fn encode_mutation_digest_prefix_v1(transcript: &MutationDigestV1) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..8].copy_from_slice(&transcript.file_id.lo.to_le_bytes());
    out[8..16].copy_from_slice(&transcript.file_id.hi.to_le_bytes());
    out[16..24].copy_from_slice(&transcript.kernel_open_id.to_le_bytes());
    out[24..32].copy_from_slice(&transcript.expected_namespace_generation.to_le_bytes());
    out[32..40].copy_from_slice(&transcript.expected_size_epoch.to_le_bytes());
    out[40..48].copy_from_slice(&transcript.expected_security_generation.to_le_bytes());
    out[48..50].copy_from_slice(&transcript.mutation_kind.to_le_bytes());
    out[50..52].copy_from_slice(&transcript.mutation_flags.to_le_bytes());
    out[52..56].copy_from_slice(&transcript.body_length.to_le_bytes());
    put_blob_at(&mut out, 56, transcript.body);
    out
}

/// Streaming section 12 operation-digest builder over the 64-byte prefix
/// plus exactly `semantic_length` semantic bytes.
pub struct OpDigestBuilder {
    hash: Sha256,
    remaining: u32,
}

impl core::fmt::Debug for OpDigestBuilder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OpDigestBuilder")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl OpDigestBuilder {
    pub fn new(
        mount_id: MountId,
        op_id: OpId,
        opcode: u16,
        mutation_kind: u16,
        semantic_length: u32,
    ) -> Result<Self, OpDigestError> {
        if !matches!(opcode, op::COMMIT_OPEN | op::WRITE | op::MUTATE) {
            return Err(OpDigestError::UnsupportedOpcode);
        }
        if (opcode == op::MUTATE) != (mutation_kind != 0) {
            return Err(OpDigestError::MutationKindPairing);
        }
        if opcode == op::MUTATE && !mutation_kind_is_journaled_v21(mutation_kind) {
            return Err(OpDigestError::InvalidScalar);
        }
        if op_id.lo == 0 && op_id.hi == 0 {
            return Err(OpDigestError::ZeroIdentity);
        }
        if mount_id.lo == 0 || mount_id.hi == 0 {
            return Err(OpDigestError::ZeroIdentity);
        }

        let mut prefix = [0u8; 64];
        prefix[0..16].copy_from_slice(OP_DIGEST_DOMAIN);
        prefix[16..18].copy_from_slice(&OP_DIGEST_FORMAT_V1.to_le_bytes());
        prefix[18..20].copy_from_slice(&FSRING_ABI_MAJOR.to_le_bytes());
        prefix[20..24].copy_from_slice(&journal_version::V1.to_le_bytes());
        prefix[24..32].copy_from_slice(&mount_id.lo.to_le_bytes());
        prefix[32..40].copy_from_slice(&mount_id.hi.to_le_bytes());
        prefix[40..48].copy_from_slice(&op_id.lo.to_le_bytes());
        prefix[48..56].copy_from_slice(&op_id.hi.to_le_bytes());
        prefix[56..58].copy_from_slice(&opcode.to_le_bytes());
        prefix[58..60].copy_from_slice(&mutation_kind.to_le_bytes());
        prefix[60..64].copy_from_slice(&semantic_length.to_le_bytes());

        let mut hash = Sha256::new();
        hash.update(&prefix);
        Ok(Self {
            hash,
            remaining: semantic_length,
        })
    }

    pub fn update(&mut self, input: &[u8]) -> Result<(), OpDigestError> {
        let length = match u32::try_from(input.len()) {
            Ok(length) if length <= self.remaining => length,
            _ => return Err(OpDigestError::LengthMismatch),
        };
        self.remaining -= length;
        self.hash.update(input);
        Ok(())
    }

    pub fn finalize(self) -> Result<[u8; 32], OpDigestError> {
        if self.remaining != 0 {
            return Err(OpDigestError::LengthMismatch);
        }
        Ok(self.hash.finalize())
    }
}

/// One tail slice in the canonical semantic byte stream: `cursor` is the
/// next expected offset relative to the start of `semantic_bytes`.
fn take_tail(
    cursor: u32,
    slice: BlobSlice,
    required: bool,
    minimum: u32,
    maximum: u32,
) -> Result<u32, OpDigestError> {
    if slice.offset == 0 && slice.length == 0 {
        if required {
            return Err(OpDigestError::SliceGeometry);
        }
        return Ok(cursor);
    }
    if slice.offset != cursor || slice.length == 0 {
        return Err(OpDigestError::SliceGeometry);
    }
    if slice.length < minimum || slice.length > maximum {
        return Err(OpDigestError::InvalidScalar);
    }
    cursor
        .checked_add(slice.length)
        .ok_or(OpDigestError::SliceGeometry)
}

fn require_matching_bytes(slice: BlobSlice, bytes: &[u8]) -> Result<(), OpDigestError> {
    if bytes.len() as u64 != u64::from(slice.length) {
        return Err(OpDigestError::LengthMismatch);
    }
    Ok(())
}

pub fn commit_open_operation_digest_v1(
    mount_id: MountId,
    op_id: OpId,
    transcript: &CommitOpenDigestV1,
    name: &[u8],
    requested_security_descriptor: &[u8],
    ea: &[u8],
) -> Result<[u8; 32], OpDigestError> {
    if (transcript.parent_id.lo == 0 && transcript.parent_id.hi == 0)
        || (transcript.transaction_id.lo == 0 && transcript.transaction_id.hi == 0)
        || transcript.kernel_open_id == 0
        || transcript.expected_namespace_generation == 0
        || transcript.expected_security_generation == 0
    {
        return Err(OpDigestError::ZeroIdentity);
    }

    let cursor = take_tail(
        COMMIT_OPEN_DIGEST_V1_PREFIX_BYTES,
        transcript.name,
        true,
        2,
        MAX_STORED_COMPONENT_BYTES,
    )?;
    if transcript.name.length % 2 != 0 {
        return Err(OpDigestError::InvalidScalar);
    }
    let cursor = take_tail(
        cursor,
        transcript.requested_security_descriptor,
        false,
        20,
        MAX_DIGEST_SECURITY_DESCRIPTOR_BYTES,
    )?;
    let cursor = take_tail(cursor, transcript.ea, false, 1, MAX_DIGEST_EA_BYTES)?;

    require_matching_bytes(transcript.name, name)?;
    require_matching_bytes(
        transcript.requested_security_descriptor,
        requested_security_descriptor,
    )?;
    require_matching_bytes(transcript.ea, ea)?;

    let mut builder = OpDigestBuilder::new(mount_id, op_id, op::COMMIT_OPEN, 0, cursor)?;
    builder.update(&encode_commit_open_digest_prefix_v1(transcript))?;
    builder.update(name)?;
    builder.update(requested_security_descriptor)?;
    builder.update(ea)?;
    builder.finalize()
}

pub fn write_operation_digest_begin_v1(
    mount_id: MountId,
    op_id: OpId,
    transcript: &WriteDigestV1,
) -> Result<OpDigestBuilder, OpDigestError> {
    if (transcript.file_id.lo == 0 && transcript.file_id.hi == 0)
        || transcript.kernel_open_id == 0
        || transcript.size_epoch == 0
    {
        return Err(OpDigestError::ZeroIdentity);
    }
    if transcript.rw_flags & !JOURNALED_RW_FLAGS != 0 || transcript.reserved != 0 {
        return Err(OpDigestError::FlagsOrReserved);
    }
    if transcript.length == 0
        || transcript.length > MAX_JOURNALED_WRITE_BYTES_PER_REQUEST
        || transcript.initialized_length > transcript.length
    {
        return Err(OpDigestError::InvalidScalar);
    }
    if validate_file_range(transcript.offset, u64::from(transcript.length), false).is_err() {
        return Err(OpDigestError::Range);
    }
    if transcript.initialized_length != 0
        && validate_file_range(
            transcript.initialized_offset,
            u64::from(transcript.initialized_length),
            false,
        )
        .is_err()
    {
        return Err(OpDigestError::Range);
    }
    if transcript.data.offset != WRITE_DIGEST_V1_PREFIX_BYTES
        || transcript.data.length != transcript.length
    {
        return Err(OpDigestError::SliceGeometry);
    }

    let semantic_length = WRITE_DIGEST_V1_PREFIX_BYTES
        .checked_add(transcript.length)
        .ok_or(OpDigestError::SliceGeometry)?;
    let mut builder = OpDigestBuilder::new(mount_id, op_id, op::WRITE, 0, semantic_length)?;
    builder.update(&encode_write_digest_prefix_v1(transcript))?;
    Ok(builder)
}

pub fn write_operation_digest_v1(
    mount_id: MountId,
    op_id: OpId,
    transcript: &WriteDigestV1,
    data: &[u8],
) -> Result<[u8; 32], OpDigestError> {
    let mut builder = write_operation_digest_begin_v1(mount_id, op_id, transcript)?;
    require_matching_bytes(transcript.data, data)?;
    builder.update(data)?;
    builder.finalize()
}

const fn mutation_kind_is_journaled_v21(kind: u16) -> bool {
    kind >= mutation_kind::SET_BASIC_INFO && kind <= mutation_kind::SET_SECURITY
}

pub fn mutation_operation_digest_v1(
    mount_id: MountId,
    op_id: OpId,
    transcript: &MutationDigestV1,
    body: &[u8],
) -> Result<[u8; 32], OpDigestError> {
    if (transcript.file_id.lo == 0 && transcript.file_id.hi == 0) || transcript.kernel_open_id == 0
    {
        return Err(OpDigestError::ZeroIdentity);
    }
    if !mutation_kind_is_journaled_v21(transcript.mutation_kind) {
        return Err(OpDigestError::InvalidScalar);
    }
    if transcript.mutation_flags != 0 {
        return Err(OpDigestError::FlagsOrReserved);
    }

    let requires_namespace = matches!(
        transcript.mutation_kind,
        mutation_kind::SET_BASIC_INFO
            | mutation_kind::RENAME
            | mutation_kind::LINK
            | mutation_kind::UNLINK
    );
    let requires_epoch = matches!(
        transcript.mutation_kind,
        mutation_kind::SET_ALLOCATION_SIZE
            | mutation_kind::SET_END_OF_FILE
            | mutation_kind::SET_VALID_DATA_LENGTH
    );
    let requires_security = transcript.mutation_kind == mutation_kind::SET_SECURITY;
    if (requires_namespace && transcript.expected_namespace_generation == 0)
        || (requires_epoch && transcript.expected_size_epoch == 0)
        || (requires_security && transcript.expected_security_generation == 0)
    {
        return Err(OpDigestError::ZeroIdentity);
    }
    if (!requires_namespace && transcript.expected_namespace_generation != 0)
        || (!requires_epoch && transcript.expected_size_epoch != 0)
        || (!requires_security && transcript.expected_security_generation != 0)
    {
        return Err(OpDigestError::InvalidScalar);
    }

    if transcript.body.offset != MUTATION_DIGEST_V1_PREFIX_BYTES
        || transcript.body.length != transcript.body_length
    {
        return Err(OpDigestError::SliceGeometry);
    }
    if transcript.body_length < 8
        || transcript.body_length % 8 != 0
        || transcript.body_length > MAX_MUTATION_BODY_BYTES
    {
        return Err(OpDigestError::InvalidScalar);
    }
    require_matching_bytes(transcript.body, body)?;
    let declared_size = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    if declared_size != transcript.body_length {
        return Err(OpDigestError::InvalidScalar);
    }

    let semantic_length = MUTATION_DIGEST_V1_PREFIX_BYTES
        .checked_add(transcript.body_length)
        .ok_or(OpDigestError::SliceGeometry)?;
    let mut builder = OpDigestBuilder::new(
        mount_id,
        op_id,
        op::MUTATE,
        transcript.mutation_kind,
        semantic_length,
    )?;
    builder.update(&encode_mutation_digest_prefix_v1(transcript))?;
    builder.update(body)?;
    builder.finalize()
}

/// Constant-time 32-byte operation-digest comparison.
#[inline(never)]
pub fn operation_digest_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut aggregate = 0u8;
    let mut index = 0usize;
    while index < left.len() {
        aggregate |= left[index] ^ right[index];
        index += 1;
    }
    aggregate == 0
}

#[cfg(test)]
mod tests {
    use super::{sha256_bytes, HmacSha256, Sha256};

    fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        let mut out = [0u8; N];
        let mut index = 0usize;
        while index < N {
            fn nibble(value: u8) -> u8 {
                match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    _ => panic!("non-lowercase-hex test literal"),
                }
            }
            out[index] =
                (nibble(text.as_bytes()[index * 2]) << 4) | nibble(text.as_bytes()[index * 2 + 1]);
            index += 1;
        }
        out
    }

    fn sha256(input: &[u8]) -> [u8; 32] {
        sha256_bytes(input)
    }

    fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
        let mut hmac = HmacSha256::new(key);
        hmac.update(input);
        hmac.finalize()
    }

    fn assert_hmac_case(key: &[u8], input: &[u8], expected_hex: &str) {
        let expected = decode_hex::<32>(expected_hex);
        assert_eq!(hmac_sha256(key, input), expected);

        let mut bytewise = HmacSha256::new(key);
        for byte in input.chunks(1) {
            bytewise.update(byte);
        }
        assert_eq!(bytewise.finalize(), expected);

        for split in 0..=input.len() {
            let mut partitioned = HmacSha256::new(key);
            partitioned.update(&input[..split]);
            partitioned.update(&input[split..]);
            assert_eq!(partitioned.finalize(), expected, "split {split}");
        }
    }

    #[test]
    fn sha256_empty_and_abc_match_standard_vectors() {
        assert_eq!(
            sha256(b""),
            decode_hex::<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        );
        assert_eq!(
            sha256(b"abc"),
            decode_hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        );
    }

    #[test]
    fn sha256_padding_boundaries_match_literal_vectors() {
        assert_eq!(
            sha256(&[b'a'; 55]),
            decode_hex::<32>("9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
        );
        assert_eq!(
            sha256(&[b'a'; 56]),
            decode_hex::<32>("b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
        );
        assert_eq!(
            sha256(&[b'a'; 63]),
            decode_hex::<32>("7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"),
        );
        assert_eq!(
            sha256(&[b'a'; 64]),
            decode_hex::<32>("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"),
        );
        assert_eq!(
            sha256(&[b'a'; 65]),
            decode_hex::<32>("635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"),
        );

        let mut bytes = [0u8; 256];
        let mut index = 0usize;
        while index < bytes.len() {
            bytes[index] = index as u8;
            index += 1;
        }
        assert_eq!(
            sha256(&bytes),
            decode_hex::<32>("40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"),
        );
    }

    #[test]
    fn sha256_streaming_partitions_match_one_shot() {
        let mut bytes = [0u8; 256];
        let mut index = 0usize;
        while index < bytes.len() {
            bytes[index] = index as u8;
            index += 1;
        }
        let expected = sha256(&bytes);
        assert_eq!(
            expected,
            decode_hex::<32>("40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"),
        );

        for split in 0..=bytes.len() {
            let mut partitioned = Sha256::new();
            partitioned.update(&bytes[..split]);
            partitioned.update(&bytes[split..]);
            assert_eq!(partitioned.finalize(), expected, "split {split}");
        }
        for width in [1usize, 7, 31, 55, 56, 63, 64, 65, 127] {
            let mut chunked = Sha256::new();
            for chunk in bytes.chunks(width) {
                chunked.update(chunk);
            }
            assert_eq!(chunked.finalize(), expected, "chunk width {width}");
        }
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_cases_1_through_4() {
        assert_hmac_case(
            &[0x0b; 20],
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
        assert_hmac_case(
            b"Jefe",
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        );
        assert_hmac_case(
            &[0xaa; 20],
            &[0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        );
        let mut case_4_key = [0u8; 25];
        let mut index = 0usize;
        while index < case_4_key.len() {
            case_4_key[index] = index as u8 + 1;
            index += 1;
        }
        assert_hmac_case(
            &case_4_key,
            &[0xcd; 50],
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_long_key_cases_6_and_7() {
        let key = [0xaa; 131];
        assert_hmac_case(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        );
        assert_hmac_case(
            &key,
            concat!(
                "This is a test using a larger than block-size key and a larger",
                " than block-size data. The key needs to be hashed before being",
                " used by the HMAC algorithm."
            )
            .as_bytes(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        );
    }
}
