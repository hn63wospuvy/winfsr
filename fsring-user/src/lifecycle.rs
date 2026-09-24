//! The volatile daemon-side open-lifecycle state machine.
//!
//! Open-prepare records keyed by `OpId`, the `TransactionId` index, the durable
//! OPEN row `ABSENT -> LIVE -> CLEANED -> ABSENT`, idempotence, and the
//! retained-open/prepare caps. Pure and `std`-only — no ring, no section, no
//! `unsafe`. Provider-supplied result values are stored and returned as data;
//! the engine owns only protocol correctness. Durable persistence and the wire
//! result write-back are PENDING (see the design's non-goals).

use std::collections::HashMap;

use fsring_abi::durable::MAX_RETAINED_PREPARE_BYTES_PER_MOUNT;
use fsring_abi::ids::{FileId, LinkId, OpId, TransactionId};
use fsring_abi::limits::{
    MAX_RETAINED_OPENS_GLOBAL, MAX_RETAINED_OPENS_PER_MOUNT, MAX_RETAINED_OPENS_PER_RING,
};
use fsring_abi::msgs::{create_result, SizeState};

use crate::error::LifecycleFault;
use crate::openbody::{CommitRequest, PreparedRequest};

/// Fixed per-record overhead charged alongside the variable name/SD/EA bytes
/// against the mount's retained-prepare byte cap. A host-model constant (the
/// real durable charge is the persistence layer, PENDING); chosen well above any
/// single record's fixed request/result state.
const FIXED_PREPARE_OVERHEAD: u64 = 512;

/// The provider-supplied successful PREPARE result — value data the engine
/// retains in the open-prepare record and echoes on idempotent replay. Treated
/// as opaque data, never as authority.
#[derive(Clone)]
pub struct PrepareResult {
    pub file_id: FileId,
    pub link_id: LinkId,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub security_descriptor: Box<[u8]>,
    pub object_flags: u32,
}

/// The provider-supplied COMMIT effect: the filesystem transaction's outcome the
/// provider computed (`create_result`, the committed identity/sizes/generations,
/// and the mount-wide `volume_commit_sequence`). Input to the engine, not
/// authority.
#[derive(Clone)]
pub struct CommitEffect {
    pub create_result: u32,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub volume_commit_sequence: u64,
}

/// The engine's COMMIT output: the committed-result values a caller (E) encodes
/// into the 112-byte `CommitOpenResultV2` for the U2K reply grant.
#[derive(Clone)]
pub struct CommittedResult {
    pub provider_open_cookie: u64,
    pub create_result: u32,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub volume_commit_sequence: u64,
}

/// The durable OPEN row's live state. `ABSENT` is modeled by the row's absence
/// from the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowState {
    Live,
    Cleaned,
}

/// One durable OPEN row (volatile here). The immutable recovery snapshot
/// (`OpenRecoveryPayloadV1`) that a restart/`REPLAY_OPEN` would read is the
/// durable half (PENDING); the in-band lifecycle needs only the state and the
/// owning ring for the retained-open ticket refund.
struct OpenRow {
    state: RowState,
    owning_ring: u16,
}

/// One restart-stable open-prepare record (volatile here): the exact semantic
/// request by value, the successful result, its `TransactionId`, and the byte
/// charge held against the mount cap.
struct OpenPrepareRecord {
    transaction_id: TransactionId,
    request: PreparedRequest,
    result: PrepareResult,
    owning_ring: u16,
    charged_bytes: u64,
}

/// The volatile open-lifecycle engine for one mount/session.
pub struct OpenLifecycle {
    session_epoch: u64,
    prepares: HashMap<OpId, OpenPrepareRecord>,
    tx_index: HashMap<TransactionId, OpId>,
    rows: HashMap<u64, OpenRow>,
    retained_prepare_bytes: u64,
    global_opens: u32,
    mount_opens: u32,
    ring_opens: HashMap<u16, u32>,
    next_cookie: u64,
}

impl OpenLifecycle {
    /// A fresh engine for one bound session.
    pub fn new(session_epoch: u64) -> Self {
        Self {
            session_epoch,
            prepares: HashMap::new(),
            tx_index: HashMap::new(),
            rows: HashMap::new(),
            retained_prepare_bytes: 0,
            global_opens: 0,
            mount_opens: 0,
            ring_opens: HashMap::new(),
            next_cookie: 1,
        }
    }

    /// The session epoch this engine was bound to.
    pub fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    /// The retained-prepare byte charge of `request` (fixed overhead plus the
    /// variable name/SD/EA input bytes).
    fn charge_of(request: &PreparedRequest) -> u64 {
        let mut charge = FIXED_PREPARE_OVERHEAD + request.name.len() as u64;
        if let Some(sd) = &request.requested_security_descriptor {
            charge += sd.len() as u64;
        }
        if let Some(ea) = &request.extended_attributes {
            charge += ea.len() as u64;
        }
        charge
    }

    /// Admit a PREPARE_OPEN: record the open-prepare row + index and return the
    /// nonzero `transaction_id`. An identical replay (same `op_id`, same semantic
    /// bytes) returns the stored `transaction_id`; a differing replay is a
    /// protocol fault; a zero/colliding `transaction_id` is corruption; the
    /// retained-prepare cap is enforced non-mutatingly.
    pub fn prepare(
        &mut self,
        request: PreparedRequest,
        result: PrepareResult,
        owning_ring: u16,
        transaction_id: TransactionId,
    ) -> Result<TransactionId, LifecycleFault> {
        // Idempotent replay: a live record for this OpId with identical semantic
        // bytes returns the stored TransactionId; differing bytes are a fault.
        if let Some(existing) = self.prepares.get(&request.op_id) {
            return if existing.request == request {
                Ok(existing.transaction_id)
            } else {
                Err(LifecycleFault::PrepareBytesMismatch)
            };
        }
        // A new open: a zero or already-indexed TransactionId cannot key a record.
        if (transaction_id.lo == 0 && transaction_id.hi == 0)
            || self.tx_index.contains_key(&transaction_id)
        {
            return Err(LifecycleFault::TransactionIdCollision);
        }
        // Charge the mount's retained-prepare bytes non-mutatingly on overflow.
        let charge = Self::charge_of(&request);
        let next = self
            .retained_prepare_bytes
            .checked_add(charge)
            .ok_or(LifecycleFault::PrepareQuota)?;
        if next > MAX_RETAINED_PREPARE_BYTES_PER_MOUNT {
            return Err(LifecycleFault::PrepareQuota);
        }
        self.retained_prepare_bytes = next;
        let op_id = request.op_id;
        self.tx_index.insert(transaction_id, op_id);
        self.prepares.insert(
            op_id,
            OpenPrepareRecord {
                transaction_id,
                request,
                result,
                owning_ring,
                charged_bytes: charge,
            },
        );
        Ok(transaction_id)
    }

    /// Resolve a prepared open (by `transaction_id`) into a durable `OPEN(LIVE)`
    /// row: verify the `op_id` and expected generations against the retained
    /// record, reserve the retained-open ticket, create the row at
    /// `kernel_open_id`, retire the record + index (refunding its prepare bytes),
    /// and issue a session-local `provider_open_cookie`.
    pub fn commit(
        &mut self,
        request: &CommitRequest,
        effect: CommitEffect,
    ) -> Result<CommittedResult, LifecycleFault> {
        self.preflight_commit(request)?;
        // The provider effect's create_result must be in the wire registry
        // (SUPERSEDED..OVERWRITTEN); EXISTS(4)/DOES_NOT_EXIST(5) are illegal.
        if effect.create_result > create_result::OVERWRITTEN {
            return Err(LifecycleFault::IllegalCreateResult);
        }
        let next_cookie = self
            .next_cookie
            .checked_add(1)
            .ok_or(LifecycleFault::CounterExhausted)?;
        let op_key = request.op_id;
        let owning_ring = self
            .prepares
            .get(&op_key)
            .expect("preflight proved record present")
            .owning_ring;
        self.reserve_open(owning_ring);

        let record = self.prepares.remove(&op_key).expect("record present");
        self.tx_index.remove(&record.transaction_id);
        self.retained_prepare_bytes = self
            .retained_prepare_bytes
            .saturating_sub(record.charged_bytes);
        self.rows.insert(
            request.kernel_open_id,
            OpenRow {
                state: RowState::Live,
                owning_ring,
            },
        );
        let provider_open_cookie = self.next_cookie;
        self.next_cookie = next_cookie;
        Ok(CommittedResult {
            provider_open_cookie,
            create_result: effect.create_result,
            file_id: effect.file_id,
            link_id: effect.link_id,
            sizes: effect.sizes,
            namespace_generation: effect.namespace_generation,
            security_generation: effect.security_generation,
            volume_commit_sequence: effect.volume_commit_sequence,
        })
    }

    /// Check all request, retained-record, row, quota, and counter conditions
    /// before a provider is allowed to perform COMMIT. Never mutates state.
    pub fn preflight_commit(&self, request: &CommitRequest) -> Result<(), LifecycleFault> {
        let op_key = *self
            .tx_index
            .get(&request.transaction_id)
            .ok_or(LifecycleFault::UnknownTransaction)?;
        if op_key != request.op_id {
            return Err(LifecycleFault::OpIdMismatch);
        }
        let record = self
            .prepares
            .get(&op_key)
            .ok_or(LifecycleFault::UnknownTransaction)?;
        if record.result.namespace_generation != request.expected_namespace_generation
            || record.result.security_generation != request.expected_security_generation
        {
            return Err(LifecycleFault::SemanticMismatch);
        }
        if self.rows.contains_key(&request.kernel_open_id) {
            return Err(LifecycleFault::RowCorruption);
        }
        self.check_open_capacity(record.owning_ring)?;
        self.next_cookie
            .checked_add(1)
            .ok_or(LifecycleFault::CounterExhausted)?;
        Ok(())
    }

    /// Check retained-open bounds in global -> mount -> ring order without
    /// moving any counter.
    fn check_open_capacity(&self, ring: u16) -> Result<(), LifecycleFault> {
        if self.global_opens >= MAX_RETAINED_OPENS_GLOBAL {
            return Err(LifecycleFault::OpenQuota);
        }
        if self.mount_opens >= MAX_RETAINED_OPENS_PER_MOUNT {
            return Err(LifecycleFault::OpenQuota);
        }
        let ring_count = self.ring_opens.get(&ring).copied().unwrap_or(0);
        if ring_count >= MAX_RETAINED_OPENS_PER_RING {
            return Err(LifecycleFault::OpenQuota);
        }
        Ok(())
    }

    /// Increment the retained-open counters after successful preflight.
    fn reserve_open(&mut self, ring: u16) {
        self.global_opens += 1;
        self.mount_opens += 1;
        *self.ring_opens.entry(ring).or_insert(0) += 1;
    }

    /// Delete the exact open-prepare record + index pair named by
    /// `transaction_id`. Joint absence (never prepared, or already
    /// committed/aborted) is idempotent success; a one-sided pair is corruption.
    pub fn abort(&mut self, transaction_id: TransactionId) -> Result<(), LifecycleFault> {
        match self.tx_index.remove(&transaction_id) {
            Some(op_key) => {
                // Defensive: unreachable through the public API (the index and
                // record are always inserted/removed together), so a one-sided
                // pair only arises from durable-state corruption — detecting that
                // is the durable ACCOUNTING/persistence half (PENDING).
                let record = self
                    .prepares
                    .remove(&op_key)
                    .ok_or(LifecycleFault::RowCorruption)?;
                self.retained_prepare_bytes = self
                    .retained_prepare_bytes
                    .saturating_sub(record.charged_bytes);
                Ok(())
            }
            None => Ok(()), // joint absence is idempotent success
        }
    }

    /// Transition the OPEN row at `kernel_open_id` `LIVE -> CLEANED`. An exact
    /// `CLEANED` retry is idempotent success; `ABSENT`/unknown is corruption
    /// (`05` §7.4). Consumes no retained-open ticket.
    pub fn cleanup(&mut self, kernel_open_id: u64) -> Result<(), LifecycleFault> {
        match self.rows.get_mut(&kernel_open_id) {
            Some(row) => match row.state {
                RowState::Live => {
                    row.state = RowState::Cleaned;
                    Ok(())
                }
                RowState::Cleaned => Ok(()), // idempotent retry
            },
            None => Err(LifecycleFault::RowCorruption), // ABSENT / unknown
        }
    }

    /// Transition the OPEN row at `kernel_open_id` `CLEANED -> ABSENT`, refunding
    /// the retained-open ticket exactly once. A complete `ABSENT` reissue is
    /// idempotent success; a `LIVE` row is corruption (`05` §8).
    pub fn close(&mut self, kernel_open_id: u64) -> Result<(), LifecycleFault> {
        match self.rows.get(&kernel_open_id) {
            Some(row) => match row.state {
                RowState::Cleaned => {
                    let owning_ring = row.owning_ring;
                    self.rows.remove(&kernel_open_id);
                    self.refund_open(owning_ring); // exactly once
                    Ok(())
                }
                RowState::Live => Err(LifecycleFault::RowCorruption),
            },
            None => Ok(()), // complete ABSENT is idempotent success
        }
    }

    /// Refund one retained-open ticket in reverse (ring -> mount -> global);
    /// saturating so a redundant/erroneous call can never underflow.
    fn refund_open(&mut self, ring: u16) {
        if let Some(count) = self.ring_opens.get_mut(&ring) {
            *count = count.saturating_sub(1);
        }
        self.mount_opens = self.mount_opens.saturating_sub(1);
        self.global_opens = self.global_opens.saturating_sub(1);
    }

    /// The state of the OPEN row at `kernel_open_id`, or `None` for `ABSENT`.
    pub fn row_state(&self, kernel_open_id: u64) -> Option<RowState> {
        self.rows.get(&kernel_open_id).map(|row| row.state)
    }

    /// The count of live retained opens (the global reservation).
    pub fn live_opens(&self) -> u32 {
        self.global_opens
    }

    /// True if an open-prepare record for `op_id` is live.
    pub fn has_prepare(&self, op_id: OpId) -> bool {
        self.prepares.contains_key(&op_id)
    }

    /// The mount's current retained-prepare byte total.
    pub fn retained_prepare_bytes(&self) -> u64 {
        self.retained_prepare_bytes
    }

    #[cfg(test)]
    pub(crate) fn exhaust_cookie_counter_for_test(&mut self) {
        self.next_cookie = u64::MAX;
    }

    /// Assert the engine's cross-field invariants (for tests and the fuzz
    /// harness): the index and record sets are in bijection, every retained-open
    /// ticket corresponds to exactly one live row across all three counters, and
    /// the retained-prepare byte total equals the sum of the live charges.
    pub fn assert_invariants(&self) {
        assert_eq!(
            self.tx_index.len(),
            self.prepares.len(),
            "tx index and record set must stay in bijection"
        );
        for (transaction_id, op_id) in &self.tx_index {
            let record = self
                .prepares
                .get(op_id)
                .expect("every index entry points to a live record");
            assert_eq!(
                record.transaction_id, *transaction_id,
                "the record must carry the indexing transaction id"
            );
        }
        let ring_sum: u32 = self.ring_opens.values().sum();
        assert_eq!(
            self.global_opens, self.mount_opens,
            "single mount: global == mount"
        );
        assert_eq!(
            self.global_opens, ring_sum,
            "global == sum of ring counters"
        );
        assert_eq!(
            self.global_opens as usize,
            self.rows.len(),
            "one retained-open ticket per live row"
        );
        let charged: u64 = self.prepares.values().map(|r| r.charged_bytes).sum();
        assert_eq!(
            self.retained_prepare_bytes, charged,
            "retained-prepare bytes == sum of live charges"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsring_abi::codec::try_decode;
    use fsring_abi::msgs::{create_result, CommitOpenV2, PrepareOpenV2};

    fn op(lo: u64) -> OpId {
        OpId { lo, hi: 0 }
    }
    fn tx(lo: u64) -> TransactionId {
        TransactionId { lo, hi: 0 }
    }
    fn sizes() -> SizeState {
        SizeState {
            allocation_size: 0,
            file_size: 0,
            valid_data_length: 0,
            size_epoch: 1,
        }
    }
    fn prepared(op_lo: u64, name: &[u8]) -> PreparedRequest {
        // The engine keys/compares on the semantic fields only, so a zeroed raw
        // with just `op_id` set is a faithful synthetic request (the retained
        // raw is exercised by openbody's own build_prepare_result tests).
        let mut raw: PrepareOpenV2 = try_decode(&[0u8; 192]).expect("zeroed PrepareOpenV2");
        raw.op_id = op(op_lo);
        PreparedRequest::from_raw(raw, name.to_vec().into_boxed_slice(), None, None)
    }
    fn result() -> PrepareResult {
        PrepareResult {
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: sizes(),
            namespace_generation: 1,
            security_generation: 1,
            security_descriptor: vec![0u8; 20].into_boxed_slice(),
            object_flags: 0,
        }
    }
    fn commit_req(op_lo: u64, tx_lo: u64, koid: u64, ns: u64, sec: u64) -> CommitRequest {
        let mut raw: CommitOpenV2 = try_decode(&[0u8; 104]).expect("zeroed CommitOpenV2");
        raw.op_id = op(op_lo);
        raw.transaction_id = tx(tx_lo);
        raw.expected_namespace_generation = ns;
        raw.expected_security_generation = sec;
        raw.kernel_open_id = koid;
        raw.granted_access = 1;
        CommitRequest::from_raw(raw)
    }
    fn effect(create_result: u32) -> CommitEffect {
        CommitEffect {
            create_result,
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: sizes(),
            namespace_generation: 1,
            security_generation: 1,
            volume_commit_sequence: 5,
        }
    }
    /// Prepare one open and return the engine ready to commit it.
    fn prepared_engine() -> OpenLifecycle {
        let mut eng = OpenLifecycle::new(1);
        eng.prepare(prepared(1, b"a.txt"), result(), 0, tx(100))
            .unwrap();
        eng
    }

    #[test]
    fn a_new_prepare_records_and_returns_the_tx() {
        let mut eng = OpenLifecycle::new(1);
        let got = eng
            .prepare(prepared(1, b"a.txt"), result(), 0, tx(100))
            .expect("new prepare");
        assert_eq!(got.lo, 100);
        assert!(eng.has_prepare(op(1)));
        assert!(eng.retained_prepare_bytes() > 0);
    }

    #[test]
    fn an_identical_replay_returns_the_stored_tx() {
        let mut eng = OpenLifecycle::new(1);
        eng.prepare(prepared(1, b"a.txt"), result(), 0, tx(100))
            .unwrap();
        let bytes_after_first = eng.retained_prepare_bytes();
        // Replay with the SAME op_id + bytes but a DIFFERENT supplied tx.
        let got = eng
            .prepare(prepared(1, b"a.txt"), result(), 0, tx(999))
            .expect("idempotent replay");
        assert_eq!(got.lo, 100, "returns the stored tx, not the supplied 999");
        assert_eq!(
            eng.retained_prepare_bytes(),
            bytes_after_first,
            "a replay does not double-charge"
        );
    }

    #[test]
    fn a_different_bytes_replay_is_a_protocol_fault() {
        let mut eng = OpenLifecycle::new(1);
        eng.prepare(prepared(1, b"a.txt"), result(), 0, tx(100))
            .unwrap();
        assert_eq!(
            eng.prepare(prepared(1, b"b.txt"), result(), 0, tx(101)),
            Err(LifecycleFault::PrepareBytesMismatch)
        );
    }

    #[test]
    fn a_zero_tx_is_rejected() {
        let mut eng = OpenLifecycle::new(1);
        assert_eq!(
            eng.prepare(prepared(1, b"a.txt"), result(), 0, tx(0)),
            Err(LifecycleFault::TransactionIdCollision)
        );
    }

    #[test]
    fn a_tx_collision_across_op_ids_is_rejected() {
        let mut eng = OpenLifecycle::new(1);
        eng.prepare(prepared(1, b"a.txt"), result(), 0, tx(100))
            .unwrap();
        assert_eq!(
            eng.prepare(prepared(2, b"c.txt"), result(), 0, tx(100)),
            Err(LifecycleFault::TransactionIdCollision)
        );
    }

    #[test]
    fn a_commit_creates_a_live_row_and_retires_the_record() {
        let mut eng = prepared_engine();
        let out = eng
            .commit(
                &commit_req(1, 100, 0x33, 1, 1),
                effect(create_result::CREATED),
            )
            .expect("commit");
        assert_ne!(out.provider_open_cookie, 0);
        assert_eq!(out.create_result, create_result::CREATED);
        assert_eq!(out.volume_commit_sequence, 5);
        assert_eq!(eng.row_state(0x33), Some(RowState::Live));
        assert_eq!(eng.live_opens(), 1);
        assert!(!eng.has_prepare(op(1)), "the record is retired");
        assert_eq!(eng.retained_prepare_bytes(), 0, "prepare bytes refunded");
    }

    #[test]
    fn a_commit_for_an_unknown_tx_is_rejected() {
        let mut eng = OpenLifecycle::new(1);
        // `CommittedResult` is not `PartialEq`/`Debug` (its `SizeState` isn't), so
        // the `Ok` side can't be `assert_eq!`d — match the `Err` with `matches!`.
        assert!(matches!(
            eng.commit(
                &commit_req(1, 100, 0x33, 1, 1),
                effect(create_result::OPENED)
            ),
            Err(LifecycleFault::UnknownTransaction)
        ));
    }

    #[test]
    fn a_commit_with_a_wrong_op_id_is_rejected() {
        let mut eng = prepared_engine();
        // tx 100 indexes op 1, but the commit claims op 2.
        assert!(matches!(
            eng.commit(
                &commit_req(2, 100, 0x33, 1, 1),
                effect(create_result::OPENED)
            ),
            Err(LifecycleFault::OpIdMismatch)
        ));
    }

    #[test]
    fn a_commit_with_a_wrong_generation_is_rejected() {
        let mut eng = prepared_engine();
        assert!(matches!(
            eng.commit(
                &commit_req(1, 100, 0x33, 2, 1),
                effect(create_result::OPENED)
            ),
            Err(LifecycleFault::SemanticMismatch)
        ));
    }

    #[test]
    fn open_lifecycle_preflight_rejects_cookie_counter_exhaustion_nonmutatingly() {
        let mut eng = prepared_engine();
        eng.next_cookie = u64::MAX;
        let retained = eng.retained_prepare_bytes();

        assert_eq!(
            eng.preflight_commit(&commit_req(1, 100, 0x33, 1, 1)),
            Err(LifecycleFault::CounterExhausted)
        );
        assert_eq!(eng.next_cookie, u64::MAX);
        assert_eq!(eng.live_opens(), 0);
        assert_eq!(eng.row_state(0x33), None);
        assert_eq!(eng.retained_prepare_bytes(), retained);
        assert!(eng.has_prepare(op(1)));
    }

    #[test]
    fn a_commit_with_an_out_of_registry_create_result_is_rejected() {
        let mut eng = prepared_engine();
        // 4 = EXISTS: a reference constant, never a legal successful wire result.
        assert!(matches!(
            eng.commit(&commit_req(1, 100, 0x33, 1, 1), effect(4)),
            Err(LifecycleFault::IllegalCreateResult)
        ));
    }

    #[test]
    fn an_unknown_tx_wins_over_a_bad_create_result() {
        // A commit with BOTH an unknown tx and an out-of-registry create_result
        // reports UnknownTransaction: the tx index is resolved before the effect
        // is judged (05 §4.7 sequence).
        let mut eng = OpenLifecycle::new(1);
        assert!(matches!(
            eng.commit(&commit_req(1, 100, 0x33, 1, 1), effect(4)),
            Err(LifecycleFault::UnknownTransaction)
        ));
    }

    #[test]
    fn a_commit_onto_an_occupied_kernel_open_id_is_corruption() {
        let mut eng = prepared_engine();
        eng.commit(
            &commit_req(1, 100, 0x33, 1, 1),
            effect(create_result::CREATED),
        )
        .unwrap();
        // A second distinct open reusing kernel_open_id 0x33.
        eng.prepare(prepared(2, b"b.txt"), result(), 0, tx(101))
            .unwrap();
        assert!(matches!(
            eng.commit(
                &commit_req(2, 101, 0x33, 1, 1),
                effect(create_result::OPENED)
            ),
            Err(LifecycleFault::RowCorruption)
        ));
    }

    #[test]
    fn abort_deletes_the_prepare_pair() {
        let mut eng = prepared_engine();
        assert_eq!(eng.abort(tx(100)), Ok(()));
        assert!(!eng.has_prepare(op(1)));
        assert_eq!(eng.retained_prepare_bytes(), 0);
    }

    #[test]
    fn abort_of_an_absent_tx_is_idempotent() {
        let mut eng = OpenLifecycle::new(1);
        assert_eq!(eng.abort(tx(999)), Ok(()));
    }

    #[test]
    fn abort_after_commit_is_idempotent() {
        let mut eng = prepared_engine();
        eng.commit(
            &commit_req(1, 100, 0x33, 1, 1),
            effect(create_result::CREATED),
        )
        .unwrap();
        // commit retired the pair; abort finds joint absence and succeeds.
        assert_eq!(eng.abort(tx(100)), Ok(()));
    }

    /// An engine with one live OPEN row at kernel_open_id 0x33.
    fn committed_engine() -> OpenLifecycle {
        let mut eng = prepared_engine();
        eng.commit(
            &commit_req(1, 100, 0x33, 1, 1),
            effect(create_result::CREATED),
        )
        .unwrap();
        eng
    }

    #[test]
    fn cleanup_moves_live_to_cleaned() {
        let mut eng = committed_engine();
        assert_eq!(eng.cleanup(0x33), Ok(()));
        assert_eq!(eng.row_state(0x33), Some(RowState::Cleaned));
    }

    #[test]
    fn a_cleaned_cleanup_retry_is_idempotent() {
        let mut eng = committed_engine();
        eng.cleanup(0x33).unwrap();
        assert_eq!(eng.cleanup(0x33), Ok(()));
        assert_eq!(eng.row_state(0x33), Some(RowState::Cleaned));
    }

    #[test]
    fn cleanup_of_an_absent_row_is_corruption() {
        let mut eng = OpenLifecycle::new(1);
        assert_eq!(eng.cleanup(0x99), Err(LifecycleFault::RowCorruption));
    }

    #[test]
    fn close_from_cleaned_goes_absent_and_refunds() {
        let mut eng = committed_engine();
        eng.cleanup(0x33).unwrap();
        assert_eq!(eng.close(0x33), Ok(()));
        assert_eq!(eng.row_state(0x33), None);
        assert_eq!(eng.live_opens(), 0, "the retained-open ticket is refunded");
    }

    #[test]
    fn close_of_an_absent_row_is_idempotent() {
        let mut eng = OpenLifecycle::new(1);
        assert_eq!(eng.close(0x99), Ok(()));
    }

    #[test]
    fn close_of_a_live_row_is_corruption() {
        let mut eng = committed_engine();
        // The row is still LIVE (no CLEANUP), so CLOSE is corruption.
        assert_eq!(eng.close(0x33), Err(LifecycleFault::RowCorruption));
        assert_eq!(eng.live_opens(), 1, "a corrupt close refunds nothing");
    }

    #[test]
    fn close_refunds_exactly_once() {
        let mut eng = committed_engine();
        eng.cleanup(0x33).unwrap();
        eng.close(0x33).unwrap();
        // A redundant close on the now-ABSENT row must not underflow the ticket.
        eng.close(0x33).unwrap();
        assert_eq!(eng.live_opens(), 0);
    }

    // The retained-open caps are per-ring 4096 / mount 262144 / global 1048576.
    // Reaching them with real opens is infeasible, so these tests poke the
    // private counters directly (the `tests` submodule can see them) to sit one
    // step below a bound, then assert the next commit is rejected non-mutatingly.

    #[test]
    fn a_full_ring_rejects_commit_nonmutatingly() {
        let mut eng = prepared_engine(); // record op1/tx100, owning_ring 0
        eng.ring_opens.insert(0, MAX_RETAINED_OPENS_PER_RING);
        assert!(matches!(
            eng.commit(
                &commit_req(1, 100, 0x33, 1, 1),
                effect(create_result::CREATED)
            ),
            Err(LifecycleFault::OpenQuota)
        ));
        // Nonmutating: the record survives, no row is created, bytes intact.
        assert!(eng.has_prepare(op(1)));
        assert_eq!(eng.row_state(0x33), None);
        assert!(eng.retained_prepare_bytes() > 0);
    }

    #[test]
    fn a_full_global_rejects_commit() {
        let mut eng = prepared_engine();
        eng.global_opens = MAX_RETAINED_OPENS_GLOBAL;
        assert!(matches!(
            eng.commit(
                &commit_req(1, 100, 0x33, 1, 1),
                effect(create_result::CREATED)
            ),
            Err(LifecycleFault::OpenQuota)
        ));
    }

    #[test]
    fn a_full_mount_rejects_commit() {
        let mut eng = prepared_engine();
        eng.mount_opens = MAX_RETAINED_OPENS_PER_MOUNT; // global/ring still under cap
        assert!(matches!(
            eng.commit(
                &commit_req(1, 100, 0x33, 1, 1),
                effect(create_result::CREATED)
            ),
            Err(LifecycleFault::OpenQuota)
        ));
    }

    #[test]
    fn a_different_ring_still_admits_when_one_is_full() {
        let mut eng = OpenLifecycle::new(1);
        // Prepare on ring 1; saturate ring 0 only.
        eng.prepare(prepared(1, b"a.txt"), result(), 1, tx(100))
            .unwrap();
        eng.ring_opens.insert(0, MAX_RETAINED_OPENS_PER_RING);
        assert!(
            eng.commit(
                &commit_req(1, 100, 0x33, 1, 1),
                effect(create_result::CREATED)
            )
            .is_ok(),
            "ring 1 admits though ring 0 is full"
        );
    }
}
