//! Starknet Sepolia calldata builder for the verified outer aggregate and
//! per-hand settlement path.
//!
//! This module is intentionally thin: it consumes only already-verified
//! artifacts (a [`VerifiedOuterAggregate`] issued by the host verifier and a
//! caller-supplied canonical `SettlementPlan` paired with the authenticated
//! pre-settlement [`TexasPokerTable`]) and produces strict Cairo ABI calldata
//! for the on-chain settlement contract.
//!
//! ## Threat model
//!
//! The on-chain contract deliberately verifies only the outer aggregate
//! commitment, the settlement commitment, replay protection, and zero-sum
//! chip deltas. This module is the off-chain adapter that compiles these
//! values from sources that were *already* proven / authenticated by the
//! native verifier and the table-state root. It never reads fields off an
//! unverified bundle descriptor, and it refuses to invent or rewrite any
//! aggregate / settlement digest.
//!
//! ## Aggregate-digest ABI
//!
//! The Cairo contract stores and emits the aggregate digest as a `(felt252,
//! felt252)` pair to preserve the full 256-bit BLAKE2b / BLAKE3 commitment
//! without truncation. We split the 32-byte digest into a high half
//! (`bytes[0..16]` big-endian) and a low half (`bytes[16..32]` big-endian);
//! each half comfortably fits in `felt252` since the Stark prime is
//! ≈ 2^251 and 2^128 < prime.
//!
//! `settle_hand` takes the digest as a single `felt252` for ABI stability.
//! The host compresses the verified dual-felt digest into the canonical
//! single felt before submitting a `settle_hand` call; the Cairo contract
//! validates equality against the registered halves in storage.

use poker_l1::contracts::texas_poker::settlement::SettlementPlan;
use poker_l1::contracts::texas_poker::types::{EMPTY_PLAYER, Seat, TexasPokerTable};
use starknet_crypto::Felt;

use crate::error::{TexasAirError, TexasAirResult};
use crate::outer_aggregate::VerifiedOuterAggregate;

/// Maximum number of participants per `settle_hand` call (9 seats + treasury).
///
/// The contract uses `Span<ContractAddress>` / `Span<i128>`, so technically the
/// array length is unbounded, but we cap at this size so a malicious or
/// mistaken builder cannot produce an oversized payload that the on-chain
/// step would silently truncate.
pub const MAX_SETTLE_PARTICIPANTS: usize = 10;

/// 32-byte digest split into two 128-bit big-endian halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregateDigestFelts {
    /// High half (`bytes[0..16]`).
    pub hi: Felt,
    /// Low half (`bytes[16..32]`).
    pub lo: Felt,
}

impl AggregateDigestFelts {
    /// Split a 32-byte big-endian digest into dual felts.
    ///
    /// # Errors
    ///
    /// Returns [`TexasAirError::SpecViolation`] if either half does not fit
    /// in 128 bits (cannot happen for a 16-byte slice; the explicit check
    /// guards future refactors).
    pub fn split(bytes: &[u8; 32]) -> TexasAirResult<Self> {
        let mut hi_bytes = [0u8; 16];
        let mut lo_bytes = [0u8; 16];
        hi_bytes.copy_from_slice(&bytes[..16]);
        lo_bytes.copy_from_slice(&bytes[16..]);
        let hi = bytes16_to_felt(&hi_bytes);
        let lo = bytes16_to_felt(&lo_bytes);
        Ok(Self { hi, lo })
    }

    /// Merge two felts back into a 32-byte big-endian digest.
    ///
    /// # Errors
    ///
    /// Returns [`TexasAirError::SpecViolation`] if either felt exceeds the
    /// canonical 128-bit range, indicating corruption or a wrong digest.
    pub fn merge(hi: Felt, lo: Felt) -> TexasAirResult<[u8; 32]> {
        let hi_bytes = felt_to_bytes16(hi)?;
        let lo_bytes = felt_to_bytes16(lo)?;
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&hi_bytes);
        out[16..].copy_from_slice(&lo_bytes);
        Ok(out)
    }

    /// Single-felt projection used by the `settle_hand` ABI (low half).
    #[must_use]
    pub const fn settle_abi_single_felt(self) -> Felt {
        self.lo
    }
}

/// One signed chip delta for the on-chain `i128` ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlayerDelta {
    /// Player address (20 bytes, encoded big-endian into felt252).
    pub address: [u8; 20],
    /// Net chip movement: positive wins, negative loses.
    pub delta: i128,
}

/// Strict calldata DTO for `register_aggregate`.
#[derive(Debug, Clone)]
pub struct RegisterAggregateCalldata {
    aggregate_hi: Felt,
    aggregate_lo: Felt,
    first_hand_id: u64,
    last_hand_id: u64,
    pre_state_hi: Felt,
    pre_state_lo: Felt,
    post_state_hi: Felt,
    post_state_lo: Felt,
    settlement_roots: Vec<Felt>,
}

impl RegisterAggregateCalldata {
    /// Build calldata from one or more host-verified outer aggregates that
    /// together cover `first_hand_id..=last_hand_id`, plus the
    /// caller-prepared settlement commitment list (already Poseidon-derived
    /// from the canonical settlement plan per hand, in hand-id order).
    ///
    /// A single [`VerifiedOuterAggregate`] covers exactly one hand (its
    /// receipt chain enforces single-hand continuity), so a multi-hand
    /// registration supplies one verified aggregate per hand. All supplied
    /// aggregates must share the same aggregate digest and table id, form a
    /// contiguous hand range, and have continuous endpoint state roots.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - `aggregates` is empty or its count does not match the hand span,
    /// - `settlement_roots.len()` does not match the hand span,
    /// - hand ids are not contiguous, or table id / aggregate digest drift,
    /// - the endpoint state roots are discontinuous between aggregates.
    pub fn new(
        aggregates: &[VerifiedOuterAggregate],
        first_hand_id: u32,
        last_hand_id: u32,
        settlement_roots: Vec<Felt>,
    ) -> TexasAirResult<Self> {
        if first_hand_id > last_hand_id {
            return Err(TexasAirError::SpecViolation(format!(
                "register_aggregate: first_hand_id {first_hand_id} > last_hand_id {last_hand_id}"
            )));
        }
        let span = u64::from(last_hand_id) - u64::from(first_hand_id) + 1;
        if settlement_roots.len() as u64 != span {
            return Err(TexasAirError::SpecViolation(format!(
                "register_aggregate: settlement_roots count {} does not match range {span}",
                settlement_roots.len()
            )));
        }
        if aggregates.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "register_aggregate: no verified aggregates supplied".into(),
            ));
        }
        if aggregates.len() as u64 != span {
            return Err(TexasAirError::SpecViolation(format!(
                "register_aggregate: aggregate count {} does not match range {span}",
                aggregates.len()
            )));
        }

        let mut expected_hand = first_hand_id;
        let mut expected_post_root: Option<[u8; 32]> = None;
        let mut first_pre_root: Option<[u8; 32]> = None;
        let mut last_post_root: Option<[u8; 32]> = None;
        let mut last_table_id: Option<u64> = None;
        let mut shared_aggregate_digest: Option<[u8; 32]> = None;

        for (idx, agg) in aggregates.iter().enumerate() {
            let receipts = agg.chain().receipts();
            let first_receipt = receipts.first().ok_or_else(|| {
                TexasAirError::SpecViolation("register_aggregate: empty receipt chain".into())
            })?;
            let last_receipt = receipts.last().expect("non-empty chain validated above");

            if first_receipt.table_id() != last_receipt.table_id() {
                return Err(TexasAirError::SpecViolation(
                    "register_aggregate: chain crosses tables".into(),
                ));
            }
            if let Some(prev_table) = last_table_id {
                if first_receipt.table_id() != prev_table {
                    return Err(TexasAirError::SpecViolation(format!(
                        "register_aggregate: table_id drift at index {idx}"
                    )));
                }
            }
            last_table_id = Some(first_receipt.table_id());

            if first_receipt.hand_id() != expected_hand {
                return Err(TexasAirError::SpecViolation(format!(
                    "register_aggregate: hand mismatch at index {idx} (expected {expected_hand}, got {})",
                    first_receipt.hand_id()
                )));
            }

            if idx == 0 {
                first_pre_root = Some(first_receipt.pre_state_root().bytes());
            }
            if let Some(prev_post) = expected_post_root {
                if first_receipt.pre_state_root().bytes() != prev_post {
                    return Err(TexasAirError::SpecViolation(format!(
                        "register_aggregate: state-root discontinuity at hand {expected_hand}"
                    )));
                }
            }
            expected_post_root = Some(last_receipt.post_state_root().bytes());
            last_post_root = Some(last_receipt.post_state_root().bytes());

            let digest = agg.aggregate_digest();
            if let Some(prev_digest) = shared_aggregate_digest {
                if digest != prev_digest {
                    return Err(TexasAirError::SpecViolation(
                        "register_aggregate: aggregate digest mismatch across hand range".into(),
                    ));
                }
            }
            shared_aggregate_digest = Some(digest);

            expected_hand = expected_hand
                .checked_add(1)
                .ok_or_else(|| TexasAirError::SpecViolation("hand id overflow".into()))?;
        }

        let shared_digest = shared_aggregate_digest.expect("non-empty validated above");
        let first_pre = first_pre_root.expect("non-empty validated above");
        let last_post = last_post_root.expect("non-empty validated above");

        let agg_felts = AggregateDigestFelts::split(&shared_digest)?;
        let pre = AggregateDigestFelts::split(&first_pre)?;
        let post = AggregateDigestFelts::split(&last_post)?;

        Ok(Self {
            aggregate_hi: agg_felts.hi,
            aggregate_lo: agg_felts.lo,
            first_hand_id: u64::from(first_hand_id),
            last_hand_id: u64::from(last_hand_id),
            pre_state_hi: pre.hi,
            pre_state_lo: pre.lo,
            post_state_hi: post.hi,
            post_state_lo: post.lo,
            settlement_roots,
        })
    }

    /// Aggregate digest (high half).
    #[must_use]
    pub const fn aggregate_hi(&self) -> Felt {
        self.aggregate_hi
    }

    /// Aggregate digest (low half).
    #[must_use]
    pub const fn aggregate_lo(&self) -> Felt {
        self.aggregate_lo
    }

    /// First hand in the registration range.
    #[must_use]
    pub const fn first_hand_id(&self) -> u64 {
        self.first_hand_id
    }

    /// Last hand in the registration range.
    #[must_use]
    pub const fn last_hand_id(&self) -> u64 {
        self.last_hand_id
    }

    /// Pre-settlement external state root, split into dual felts.
    #[must_use]
    pub const fn pre_state_root(&self) -> (Felt, Felt) {
        (self.pre_state_hi, self.pre_state_lo)
    }

    /// Post-settlement external state root, split into dual felts.
    #[must_use]
    pub const fn post_state_root(&self) -> (Felt, Felt) {
        (self.post_state_hi, self.post_state_lo)
    }

    /// Per-hand settlement commitment roots.
    #[must_use]
    pub fn settlement_roots(&self) -> &[Felt] {
        &self.settlement_roots
    }

    /// Serialize to strict Cairo ABI calldata:
    /// `(aggregate_digest: (felt252, felt252), first, last,
    /// pre_root: (felt252, felt252), post_root: (felt252, felt252),
    /// settlement_roots: Span<felt252>)`.
    #[must_use]
    pub fn to_felts(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(9 + self.settlement_roots.len());
        out.push(self.aggregate_hi);
        out.push(self.aggregate_lo);
        out.push(Felt::from(self.first_hand_id));
        out.push(Felt::from(self.last_hand_id));
        out.push(self.pre_state_hi);
        out.push(self.pre_state_lo);
        out.push(self.post_state_hi);
        out.push(self.post_state_lo);
        out.push(Felt::from(self.settlement_roots.len()));
        out.extend(self.settlement_roots.iter().copied());
        out
    }
}

/// Strict calldata DTO for `settle_hand`.
#[derive(Debug, Clone)]
pub struct SettleHandCalldata {
    /// Single-felt projection of the registered aggregate digest (low half).
    aggregate_digest: Felt,
    hand_id: u64,
    /// Hand action-log digest (#18 Phase B): absorbed as the settlement
    /// digest's tail word and carried in the settle calldata so the contract
    /// recompute matches the registered root byte-for-byte.
    action_log_digest: Felt,
    players: Vec<Felt>,
    deltas: Vec<i128>,
    /// Poseidon commitment over (hand_id, address, sign, magnitude,
    /// action_log_digest).
    settlement_digest: Felt,
}

impl SettleHandCalldata {
    /// Build calldata for a single `settle_hand` call.
    ///
    /// `verified_aggregate_digest` must be the 32-byte Blake2b/Blake3
    /// aggregate digest from a successfully verified outer aggregate. The
    /// `pre_table` must be the authenticated pre-settlement snapshot, and
    /// `plan` must be the canonical validated settlement plan derived from
    /// the same pre-state and the showdown evidence. `action_log_digest`
    /// (#18 Phase B) is the hand's action-log hash — absorbed as the
    /// settlement digest's tail word.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - `pre_table.hand_id != hand_id`,
    /// - the rake recipient is missing but `plan.rake > 0`,
    /// - the merged participant set is empty, oversized, contains the empty
    ///   address, or duplicates an address,
    /// - deltas are not zero-sum,
    /// - any signed magnitude does not fit in `u64`.
    #[allow(clippy::too_many_lines)]
    pub fn new(
        verified_aggregate_digest: [u8; 32],
        hand_id: u32,
        pre_table: &TexasPokerTable,
        plan: &SettlementPlan,
        rake_recipient: Option<[u8; 20]>,
        action_log_digest: Felt,
    ) -> TexasAirResult<Self> {
        if pre_table.hand_id != hand_id {
            return Err(TexasAirError::SpecViolation(format!(
                "settle_hand: pre_table.hand_id {} != requested {hand_id}",
                pre_table.hand_id
            )));
        }

        let digests = AggregateDigestFelts::split(&verified_aggregate_digest)?;
        let aggregate_digest_single = digests.settle_abi_single_felt();

        // 1. Player deltas from plan.awards and pre_table seat contributions.
        let mut participants: Vec<PlayerDelta> = Vec::with_capacity(MAX_SETTLE_PARTICIPANTS);
        for (seat_index, seat) in pre_table.seats.iter().enumerate() {
            let Some(player_addr) = seat_player_for_settlement(seat) else {
                continue;
            };
            let total_bet = seat.total_bet();
            let award = plan.awards.get(seat_index).copied().unwrap_or(0);
            let delta = signed_delta(award, total_bet)?;
            if delta == 0 {
                continue;
            }
            participants.push(PlayerDelta {
                address: player_addr,
                delta,
            });
        }

        // 2. Rake treasury entry (merged into a player if addresses collide).
        if plan.rake != 0 {
            let treasury = rake_recipient.ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "settle_hand: plan has non-zero rake but no rake recipient provided".into(),
                )
            })?;
            if treasury == EMPTY_PLAYER {
                return Err(TexasAirError::SpecViolation(
                    "settle_hand: rake recipient is the empty player address".into(),
                ));
            }
            let treasury_delta = i128::from(plan.rake);
            if let Some(existing) = participants.iter_mut().find(|p| p.address == treasury) {
                let merged = existing.delta.checked_add(treasury_delta).ok_or_else(|| {
                    TexasAirError::SpecViolation(
                        "settle_hand: merging treasury delta overflows i128".into(),
                    )
                })?;
                existing.delta = merged;
            } else {
                participants.push(PlayerDelta {
                    address: treasury,
                    delta: treasury_delta,
                });
            }
        }

        if participants.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "settle_hand: participant set is empty (no settled players)".into(),
            ));
        }
        if participants.len() > MAX_SETTLE_PARTICIPANTS {
            return Err(TexasAirError::SpecViolation(format!(
                "settle_hand: {} participants exceeds cap {MAX_SETTLE_PARTICIPANTS}",
                participants.len()
            )));
        }

        // 3. Deterministic ordering: sort by address ascending.
        participants.sort_by(|a, b| a.address.cmp(&b.address));

        // 4. Reject duplicate addresses.
        for window in participants.windows(2) {
            if window[0].address == window[1].address {
                return Err(TexasAirError::SpecViolation(
                    "settle_hand: duplicate participant address after treasury merge".into(),
                ));
            }
        }

        // 5. Zero-sum check.
        let mut sum: i128 = 0;
        for p in &participants {
            sum = sum.checked_add(p.delta).ok_or_else(|| {
                TexasAirError::SpecViolation("settle_hand: delta sum overflowed i128".into())
            })?;
        }
        if sum != 0 {
            return Err(TexasAirError::SpecViolation(format!(
                "settle_hand: delta sum {sum} is not zero-sum"
            )));
        }

        // 6. Encode to Cairo ABI felt252 players and i128 deltas.
        let mut players = Vec::with_capacity(participants.len());
        let mut deltas = Vec::with_capacity(participants.len());
        for p in &participants {
            players.push(address_to_felt(p.address)?);
            validate_i128_abi(p.delta)?;
            deltas.push(p.delta);
        }

        let settlement_digest =
            compute_settlement_digest(u64::from(hand_id), &participants, action_log_digest)?;

        Ok(Self {
            aggregate_digest: aggregate_digest_single,
            hand_id: u64::from(hand_id),
            action_log_digest,
            players,
            deltas,
            settlement_digest,
        })
    }

    /// Single-felt projection of the aggregate digest for `settle_hand` ABI.
    #[must_use]
    pub const fn aggregate_digest(&self) -> Felt {
        self.aggregate_digest
    }

    /// Hand id for this settlement call.
    #[must_use]
    pub const fn hand_id(&self) -> u64 {
        self.hand_id
    }

    /// The hand's action-log digest (#18 Phase B settlement digest tail word).
    #[must_use]
    pub const fn action_log_digest(&self) -> Felt {
        self.action_log_digest
    }

    /// Participant addresses (felt252 encoding, big-endian 20-byte).
    #[must_use]
    pub fn players(&self) -> &[Felt] {
        &self.players
    }

    /// Per-player signed deltas in the same order as [`Self::players`].
    #[must_use]
    pub fn deltas(&self) -> &[i128] {
        &self.deltas
    }

    /// The Poseidon settlement commitment this calldata recomputes; the
    /// on-chain contract recomputes the same commitment and rejects mismatches.
    #[must_use]
    pub const fn settlement_digest(&self) -> Felt {
        self.settlement_digest
    }

    /// Serialize to strict Cairo ABI calldata:
    /// `(aggregate_digest: felt252, hand_id: u64, action_log_digest: felt252,
    /// players: Span<ContractAddress>, deltas: Span<i128>)`.
    #[must_use]
    pub fn to_felts(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(5 + self.players.len() * 2);
        out.push(self.aggregate_digest);
        out.push(Felt::from(self.hand_id));
        out.push(self.action_log_digest);
        out.push(Felt::from(self.players.len()));
        for player in &self.players {
            out.push(*player);
        }
        out.push(Felt::from(self.deltas.len()));
        for delta in &self.deltas {
            out.push(i128_to_felt(*delta));
        }
        out
    }
}

/// Extract the player address from a seat.
///
/// Vacant slots return `None`: they have neither a player nor a
/// `total_bet`, so they can never produce a non-zero delta and are simply
/// skipped by the caller.
fn seat_player_for_settlement(seat: &Seat) -> Option<[u8; 20]> {
    match seat {
        Seat::Playing { playing } => Some(playing.occupied.player),
        Seat::Waiting { occupied } => Some(occupied.player),
        Seat::DepartedThisHand { player, .. } => Some(*player),
        Seat::Vacant { .. } => None,
    }
}

/// Compute `award - total_bet` as an `i128`.
///
/// Both inputs are `u64`; the difference of two u64 values always fits in
/// i128, so this cannot overflow.
fn signed_delta(award: u64, total_bet: u64) -> TexasAirResult<i128> {
    if award >= total_bet {
        Ok(i128::from(award - total_bet))
    } else {
        Ok(-i128::from(total_bet - award))
    }
}

/// Reject i128 values whose absolute magnitude exceeds the Cairo `i128`
/// commitment limit (sign + u64 magnitude in the Poseidon encoding).
fn validate_i128_abi(delta: i128) -> TexasAirResult<()> {
    if delta.unsigned_abs() > u64::MAX as u128 {
        return Err(TexasAirError::SpecViolation(format!(
            "settle_hand: delta magnitude {} exceeds u64 ABI bound",
            delta.unsigned_abs()
        )));
    }
    Ok(())
}

/// Encode a player address as a felt252 (big-endian 20 bytes).
fn address_to_felt(addr: [u8; 20]) -> TexasAirResult<Felt> {
    if addr == EMPTY_PLAYER {
        return Err(TexasAirError::SpecViolation(
            "settle_hand: empty player address in participant set".into(),
        ));
    }
    // 20 字节 = 160 bit < P，canonical 恒成立。
    Ok(Felt::from_bytes_be_slice(&addr))
}

/// Encode a signed i128 into the Starknet prime as a felt.
///
/// Negative values become the modular complement `-magnitude`; the contract
/// reads these back into `i128` via the two's-complement felt representation.
fn i128_to_felt(value: i128) -> Felt {
    if value >= 0 {
        let magnitude =
            u64::try_from(value).expect("non-negative delta fits in u64 after validate_i128_abi");
        Felt::from(magnitude)
    } else {
        let magnitude = u64::try_from(value.unsigned_abs())
            .expect("abs delta fits in u64 after validate_i128_abi");
        -Felt::from(magnitude)
    }
}

/// Canonical Cairo-compatible Poseidon settlement commitment.
///
/// The encoding matches `poker_contracts/src/poker_settlement.cairo` /
/// `poker_dual_settlement.cairo::compute_settlement_digest`:
/// `hand_id`, then for each ordered player: `address`, `sign` (1 non-negative,
/// 0 negative), `magnitude` (u64), then the hand's `action_log_digest` tail
/// word (#18 Phase B).
fn compute_settlement_digest(
    hand_id: u64,
    participants: &[PlayerDelta],
    action_log_digest: Felt,
) -> TexasAirResult<Felt> {
    let mut fields: Vec<Felt> = Vec::with_capacity(2 + participants.len() * 3);
    fields.push(Felt::from(hand_id));
    for p in participants {
        fields.push(address_to_felt(p.address)?);
        if p.delta >= 0 {
            fields.push(Felt::from(1_u64));
            let magnitude = u64::try_from(p.delta)
                .expect("non-negative delta fits in u64 after validate_i128_abi");
            fields.push(Felt::from(magnitude));
        } else {
            fields.push(Felt::from(0_u64));
            let magnitude = u64::try_from(p.delta.unsigned_abs())
                .expect("abs delta fits in u64 after validate_i128_abi");
            fields.push(Felt::from(magnitude));
        }
    }
    fields.push(action_log_digest);
    Ok(starknet_crypto::poseidon_hash_many(&fields))
}

/// Convert a 16-byte big-endian slice into a `Felt`.
///
/// A 128-bit value is always a canonical felt252 (Stark prime ≈ 2^251).
fn bytes16_to_felt(bytes: &[u8; 16]) -> Felt {
    Felt::from_bytes_be_slice(bytes)
}

/// Convert a `Felt` back to a 16-byte big-endian slice.
///
/// # Errors
///
/// Returns [`TexasAirError::SpecViolation`] if the felt exceeds the 128-bit
/// canonical range, indicating corruption or a wrong digest.
fn felt_to_bytes16(felt: Felt) -> TexasAirResult<[u8; 16]> {
    let bytes = felt.to_bytes_be();
    if bytes[..16].iter().any(|b| *b != 0) {
        return Err(TexasAirError::SpecViolation(
            "felt_to_bytes16: felt exceeds canonical 128-bit range".into(),
        ));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[16..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_root::StateRoot;
    use crate::texas_canonical::NO_CANONICAL_SEAT;
    use crate::test_support::well_formed_tx_pk_fixture;
    use crate::verified_chain::{VerificationReceipt, VerifiedChain};

    /// 测试用动作日志哈希样例（#18 Phase B 吸收链尾词；值本身不重要，
    /// 重要的是参与 digest 吸收与 calldata 布局）。
    fn action_log_sample() -> Felt {
        Felt::from(0xA11CE_u64)
    }
    use poker_l1::contracts::texas_poker::utils::g1_generator as g1_gen;
    use poker_l1::object_model::ObjectID;
    use poker_l1::contracts::texas_poker::card::{BoardCards, HoleCards};
    use poker_l1::contracts::texas_poker::settlement::{
        SettlementPlan, SettlementPotPlan, SettlementRunoutSchedule, SETTLEMENT_PLAN_VERSION,
        SETTLEMENT_SEATS,
    };
    use poker_l1::contracts::texas_poker::types::{
        DeckState, HandPhase, OccupiedSeat, PlayingSeat, PlayingSeatStatus, TableRules,
    };
    use poker_protocol::crypto::types::ECPoint;

    fn receipt_with_state(
        table_id: u64,
        hand: u32,
        call_seq: u32,
        pre: [u8; 32],
        post: [u8; 32],
    ) -> VerificationReceipt {
        VerificationReceipt::test_only_new(
            table_id,
            hand,
            call_seq,
            StateRoot::from_bytes(pre),
            StateRoot::from_bytes(post),
        )
    }

    fn chain_from(receipts: Vec<VerificationReceipt>) -> VerifiedChain {
        VerifiedChain::test_only_from_receipts(receipts).expect("test chain must validate")
    }

    fn mock_aggregate(chain: VerifiedChain, agg: [u8; 32]) -> VerifiedOuterAggregate {
        VerifiedOuterAggregate::test_only_new(chain, agg)
    }

    fn playing_seat(player: [u8; 20], total_bet: u64) -> Seat {
        Seat::Playing {
            playing: PlayingSeat {
                occupied: OccupiedSeat {
                    player,
                    stack: 1000,
                    pk: ECPoint(g1_gen()),
                    tx_pk: well_formed_tx_pk_fixture(),
                    pending_addon: 0,
                    time_bank_ms: 30_000,
                },
                hand: HoleCards::empty(),
                bet: total_bet,
                total_bet,
                status: PlayingSeatStatus::Active,
            },
        }
    }

    fn vacant_seat() -> Seat {
        Seat::Vacant {
            time_bank_ms: 30_000,
        }
    }

    fn build_test_table(hand_id: u32) -> TexasPokerTable {
        TexasPokerTable {
            id: ObjectID::new([0xAB; 20], 0),
            creator: [0xAA; 20],
            rules: TableRules::new(9, 5, 10),
            seats: [
                playing_seat([0x11; 20], 50),
                playing_seat([0x22; 20], 50),
                vacant_seat(),
                vacant_seat(),
                vacant_seat(),
                vacant_seat(),
                vacant_seat(),
                vacant_seat(),
                vacant_seat(),
            ],
            acted_mask: 0,
            leave_after_hand_mask: 0,
            button: 0,
            last_bb_seat: NO_CANONICAL_SEAT,
            pot: 100,
            community_cards: BoardCards::default(),
            hand_phase: HandPhase::Waiting,
            deck_state: DeckState::default(),
            chip_pool: 100,
            run_it_twice_state: Default::default(),
            hand_id,
            call_seq: 0,
        }
    }

    fn zero_rake_plan(winner_award: u64) -> SettlementPlan {
        SettlementPlan {
            version: SETTLEMENT_PLAN_VERSION,
            schedule: SettlementRunoutSchedule::Single,
            gross_pot: 100,
            rake: 0,
            total_awards: winner_award,
            winner_mask: 1,
            awards: [winner_award, 0, 0, 0, 0, 0, 0, 0, 0],
            pot_count: 0,
            pots: [SettlementPotPlan::inactive(); SETTLEMENT_SEATS],
        }
    }

    #[test]
    fn split_merge_round_trip() {
        let bytes: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let felts = AggregateDigestFelts::split(&bytes).unwrap();
        let merged = AggregateDigestFelts::merge(felts.hi, felts.lo).unwrap();
        assert_eq!(merged, bytes);
    }

    #[test]
    fn split_preserves_high_bits() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[15] = 0xCD;
        let felts = AggregateDigestFelts::split(&bytes).unwrap();
        let merged = AggregateDigestFelts::merge(felts.hi, felts.lo).unwrap();
        assert_eq!(merged, bytes, "high byte must not be silently dropped");
    }

    #[test]
    fn merge_rejects_oversize_felt() {
        let oversized = Felt::from(u128::MAX) + Felt::from(1_u64);
        let err = AggregateDigestFelts::merge(oversized, Felt::ZERO).unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn settle_hand_zero_sum_invariant() {
        let table = build_test_table(7);
        // Seat 0 wins the 100-chip pot: awards[0] = 100 (delta +50), seat 1 loses (delta -50).
        let plan = zero_rake_plan(100);
        let calldata = SettleHandCalldata::new([1u8; 32], 7, &table, &plan, None, action_log_sample()).unwrap();
        let sum: i128 = calldata.deltas().iter().sum();
        assert_eq!(sum, 0);
        // The Poseidon digest must equal the felt computed by the contract:
        // hand_id=7, [addr0, sign=1, mag=50, addr1, sign=0, mag=50,
        // action_log_digest]（#18 Phase B 尾词）。
        let addr0 = address_to_felt([0x11; 20]).unwrap();
        let addr1 = address_to_felt([0x22; 20]).unwrap();
        let expected = starknet_crypto::poseidon_hash_many(&[
            Felt::from(7_u64),
            addr0,
            Felt::from(1_u64),
            Felt::from(50_u64),
            addr1,
            Felt::from(0_u64),
            Felt::from(50_u64),
            action_log_sample(),
        ]);
        assert_eq!(calldata.settlement_digest(), expected);
        assert_eq!(calldata.action_log_digest(), action_log_sample());
    }

    #[test]
    fn settle_hand_rejects_non_zero_sum() {
        let table = build_test_table(7);
        // Awards seat 0 with 200 chips when only 100 were wagered: +150/-50 ≠ 0.
        let plan = zero_rake_plan(200);
        let err = SettleHandCalldata::new([2u8; 32], 7, &table, &plan, None, action_log_sample()).unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn settle_hand_rake_merges_with_player() {
        let table = build_test_table(7);
        let plan = SettlementPlan {
            version: SETTLEMENT_PLAN_VERSION,
            schedule: SettlementRunoutSchedule::Single,
            gross_pot: 100,
            rake: 5,
            total_awards: 95,
            winner_mask: 1,
            awards: [95, 0, 0, 0, 0, 0, 0, 0, 0],
            pot_count: 0,
            pots: [SettlementPotPlan::inactive(); SETTLEMENT_SEATS],
        };
        // Rake recipient equals seat 0 (winner) → must merge.
        let winner_addr = [0x11; 20];
        let calldata =
            SettleHandCalldata::new([3u8; 32], 7, &table, &plan, Some(winner_addr), action_log_sample()).unwrap();
        assert_eq!(calldata.players().len(), 2);
        let sum: i128 = calldata.deltas().iter().sum();
        assert_eq!(sum, 0);
        // Merged delta for the winner: 95 award - 50 bet + 5 rake = +50.
        let winner_felt = address_to_felt([0x11; 20]).unwrap();
        let winner_idx = calldata
            .players()
            .iter()
            .position(|p| *p == winner_felt)
            .expect("winner present");
        assert_eq!(calldata.deltas()[winner_idx], 50);
    }

    #[test]
    fn settle_hand_rejects_missing_rake_recipient() {
        let table = build_test_table(7);
        let plan = SettlementPlan {
            version: SETTLEMENT_PLAN_VERSION,
            schedule: SettlementRunoutSchedule::Single,
            gross_pot: 100,
            rake: 5,
            total_awards: 95,
            winner_mask: 1,
            awards: [95, 0, 0, 0, 0, 0, 0, 0, 0],
            pot_count: 0,
            pots: [SettlementPotPlan::inactive(); SETTLEMENT_SEATS],
        };
        let err = SettleHandCalldata::new([4u8; 32], 7, &table, &plan, None, action_log_sample()).unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn settle_hand_rejects_hand_id_mismatch() {
        let table = build_test_table(7);
        let plan = zero_rake_plan(100);
        let err = SettleHandCalldata::new([5u8; 32], 8, &table, &plan, None, action_log_sample()).unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn settle_hand_felt_layout_matches_contract_abi() {
        let table = build_test_table(7);
        let plan = zero_rake_plan(100);
        let calldata = SettleHandCalldata::new([6u8; 32], 7, &table, &plan, None, action_log_sample()).unwrap();
        let felts = calldata.to_felts();
        // digest + hand_id + action_log + player_len + 2 players + delta_len
        // + 2 deltas = 9（#18 Phase B：action_log 插在 hand_id 之后）。
        assert_eq!(felts.len(), 9);
        assert_eq!(felts[0], calldata.aggregate_digest());
        assert_eq!(felts[1], Felt::from(7_u64));
        assert_eq!(felts[2], action_log_sample(), "action log after hand_id");
        assert_eq!(felts[3], Felt::from(2_u64));
        assert_eq!(felts[6], Felt::from(2_u64));
        // Sorted: [0x11..] < [0x22..], so felts[4] is seat 0, felts[5] is seat 1.
        assert_eq!(felts[4], address_to_felt([0x11; 20]).unwrap());
        assert_eq!(felts[5], address_to_felt([0x22; 20]).unwrap());
        // Deltas: winner +50, loser -50 (modular complement).
        assert_eq!(felts[7], Felt::from(50_u64));
        assert_eq!(felts[8], -Felt::from(50_u64));
    }

    #[test]
    fn register_aggregate_validates_matching_range() {
        let chain_a = chain_from(vec![receipt_with_state(1, 10, 0, [0x10; 32], [0x20; 32])]);
        let chain_b = chain_from(vec![receipt_with_state(1, 11, 0, [0x20; 32], [0x30; 32])]);
        let agg_a = mock_aggregate(chain_a, [0xAA; 32]);
        let agg_b = mock_aggregate(chain_b, [0xAA; 32]);
        let ok = RegisterAggregateCalldata::new(
            &[agg_a, agg_b],
            10,
            11,
            vec![Felt::from(1_u64), Felt::from(2_u64)],
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn register_aggregate_rejects_hand_range_mismatch() {
        let chain_a = chain_from(vec![receipt_with_state(1, 10, 0, [0x10; 32], [0x20; 32])]);
        let chain_b = chain_from(vec![receipt_with_state(1, 11, 0, [0x20; 32], [0x30; 32])]);
        let agg_a = mock_aggregate(chain_a, [0xAA; 32]);
        let agg_b = mock_aggregate(chain_b, [0xAA; 32]);
        // Range asks for hand 11..=12 but aggregates cover 10..=11.
        let err = RegisterAggregateCalldata::new(
            &[agg_a, agg_b],
            11,
            12,
            vec![Felt::from(1_u64), Felt::from(2_u64)],
        )
        .unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn register_aggregate_rejects_digest_drift() {
        let chain_a = chain_from(vec![receipt_with_state(1, 10, 0, [0x10; 32], [0x20; 32])]);
        let chain_b = chain_from(vec![receipt_with_state(1, 11, 0, [0x20; 32], [0x30; 32])]);
        let agg_a = mock_aggregate(chain_a, [0xAA; 32]);
        let agg_b = mock_aggregate(chain_b, [0xBB; 32]);
        let err = RegisterAggregateCalldata::new(
            &[agg_a, agg_b],
            10,
            11,
            vec![Felt::from(1_u64), Felt::from(2_u64)],
        )
        .unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn register_aggregate_rejects_root_discontinuity() {
        let chain_a = chain_from(vec![receipt_with_state(1, 10, 0, [0x10; 32], [0x20; 32])]);
        // Second hand starts from a different root than the first ended with.
        let chain_b = chain_from(vec![receipt_with_state(1, 11, 0, [0x99; 32], [0x30; 32])]);
        let agg_a = mock_aggregate(chain_a, [0xAA; 32]);
        let agg_b = mock_aggregate(chain_b, [0xAA; 32]);
        let err = RegisterAggregateCalldata::new(
            &[agg_a, agg_b],
            10,
            11,
            vec![Felt::from(1_u64), Felt::from(2_u64)],
        )
        .unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn calldata_felt_layout_matches_contract_abi() {
        let chain = chain_from(vec![receipt_with_state(1, 5, 0, [0x01; 32], [0x02; 32])]);
        let agg = mock_aggregate(chain, [0xAA; 32]);
        let c =
            RegisterAggregateCalldata::new(&[agg], 5, 5, vec![Felt::from(42_u64)]).unwrap();
        let felts = c.to_felts();
        // 2 (digest) + 2 (hand range) + 4 (state roots) + 1 (length) + 1 (root) = 10
        assert_eq!(felts.len(), 10);
        assert_eq!(felts[0], c.aggregate_hi());
        assert_eq!(felts[1], c.aggregate_lo());
        assert_eq!(felts[2], Felt::from(5_u64));
        assert_eq!(felts[3], Felt::from(5_u64));
        assert_eq!(felts[8], Felt::from(1_u64));
        assert_eq!(felts[9], Felt::from(42_u64));
    }
}
