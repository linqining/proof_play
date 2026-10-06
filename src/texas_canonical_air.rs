//! Direct heterogeneous AIR for the fixed-width canonical Texas transition ABI.
//!
//! This circuit deliberately consumes [`crate::texas_canonical::CanonicalTransitionWitness`]
//! rather than a transaction or a VM prove task. The AIR binds the fixed-width state-image links,
//! selector, limited actor policy, sequence arithmetic, table scope, batch boundaries, and padding
//! rows. It is intentionally not a proof of every Texas VM rule yet; see
//! `docs/archive/TRUST_MODEL_NO_TRANSACTION_REPLAY.md`（已被取代，现行模型见 README）before using it for production admission.
#![allow(missing_docs)]

use bincode::Options;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::{VerificationError, verify};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::{ProvingError, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
    TraceLocationAllocator, relation,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::texas_canonical::{
    CANONICAL_ABI_VERSION, CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG,
    CANONICAL_SHUFFLE_RECONSTRUCT_SUBTAG, CanonicalProtocolCompletionKind, CanonicalSeatStatus,
    CanonicalStateImage, CanonicalTransitionKind, CanonicalTransitionWitness,
    MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS, MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
};
use crate::trace_gen::MethodTrace;
use crate::trace_gen::generic_trace::tagged_batch_log_size;

const MAX_ROWS: usize = 1 << 10;
const KIND_COUNT: usize = 29;
/// A reveal-timeout cascade cannot exceed the fixed table capacity.
pub const MAX_REVEAL_TIMEOUT_CASCADE_KICKS: usize = MAX_CANONICAL_SEATS;
/// Fixed padding value for unused public cascade schedule entries.
pub const REVEAL_TIMEOUT_CASCADE_EMPTY_SEAT: u8 = u8::MAX;

// active, kinds, table, hand(pre/post), seq(pre/post), image commitments(pre/post),
// state roots(pre/post), lifecycle roots(pre/post), overlay roots(pre/post), settlement roots
// (pre/post), custody roots(pre/post), actor, action, deadline, and the sequence carry.
// The fixed prefix carries the canonical ABI.  The projection suffix carries the
// phase/round scalars and selected-seat image needed by the betting family. Keeping it in
// the same row preserves the tagged batch's one-proof-per-table performance profile.
const BASE_NUM_COLUMNS: usize = 1574;
const FULL_BETTING_SEAT_WIDTH: usize = SEAT_STATUS_COUNT + 4 * 4 + 2;
const FULL_BETTING_SEATS_OFFSET: usize = BASE_NUM_COLUMNS;
#[cfg(test)] // 仅同文件测试用于列索引断言
const FULL_POST_BETTING_SEATS_OFFSET: usize =
    FULL_BETTING_SEATS_OFFSET + MAX_CANONICAL_SEATS * FULL_BETTING_SEAT_WIDTH;
#[cfg(test)] // 仅同文件测试用于列索引断言
const FULL_SEAT_STACK_BLOCK_OFFSET: usize = MAX_CANONICAL_SEATS * SEAT_STATUS_COUNT;
const NEXT_TURN_ADVICE_OFFSET: usize =
    BASE_NUM_COLUMNS + 2 * MAX_CANONICAL_SEATS * FULL_BETTING_SEAT_WIDTH + 2 * MAX_CANONICAL_SEATS;
const NEXT_TURN_SELECTOR_OFFSET: usize = NEXT_TURN_ADVICE_OFFSET + 1;
const NEXT_TURN_PAIR_OFFSET: usize = NEXT_TURN_SELECTOR_OFFSET + MAX_CANONICAL_SEATS;
const FUNDING_SEAT_SELECTOR_OFFSET: usize =
    NEXT_TURN_PAIR_OFFSET + MAX_CANONICAL_SEATS * MAX_CANONICAL_SEATS;
const ROUND_COLLECT_CARRIES_OFFSET: usize = FUNDING_SEAT_SELECTOR_OFFSET + MAX_CANONICAL_SEATS;
const ROUND_COLLECT_CARRY_BITS_OFFSET: usize = ROUND_COLLECT_CARRIES_OFFSET + 3;
const ROUND_COLLECT_BET_BITS_OFFSET: usize = ROUND_COLLECT_CARRY_BITS_OFFSET + 3 * 4;
const ROUND_COMPLETE_ACTIVE_OFFSET: usize =
    ROUND_COLLECT_BET_BITS_OFFSET + MAX_CANONICAL_SEATS * 4 * 16;
const ROUND_ADVANCE_OPENING_OFFSET: usize = ROUND_COMPLETE_ACTIVE_OFFSET + MAX_CANONICAL_SEATS;
const ROUND_ADVANCE_SCHEDULE_SELECTOR_OFFSET: usize =
    ROUND_ADVANCE_OPENING_OFFSET + 9 + MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS * 6;
// For each of the pre/post deck cursors: 6 cursor bits, 6 bits of
// `52 - cursor`, and the six binary-addition carry-outs.  The subtraction is
// kept in the AIR so a prover cannot use a field element outside the 52-card
// deck after bypassing Rust-side witness validation.
// Seven one-hot schedule selectors: (preflop, flop, turn) × (single, RIT)
// plus the showdown-window advance (street 4 → ShowdownOwner window).
const ROUND_ADVANCE_CARD_CURSOR_RANGE_OFFSET: usize = ROUND_ADVANCE_SCHEDULE_SELECTOR_OFFSET + 7;
// One selector per fixed seat for every canonical action that addresses a
// player.  This binds the selected status projection to the full-seat image
// for lifecycle/crypto families as well as the existing betting/funding
// projections.
const IMMUTABLE_COMMITMENTS_OFFSET: usize = ROUND_ADVANCE_CARD_CURSOR_RANGE_OFFSET + 2 * 6 * 3;
const DEADLINE_IMAGE_OFFSET: usize = IMMUTABLE_COMMITMENTS_OFFSET + 4 * 16;
const POST_DEADLINE_INV_OFFSET: usize = DEADLINE_IMAGE_OFFSET + 8;
const ADVANCE_DEADLINE_DIFFERENCE_OFFSET: usize = POST_DEADLINE_INV_OFFSET + 1;
const ADVANCE_DEADLINE_CARRIES_OFFSET: usize = ADVANCE_DEADLINE_DIFFERENCE_OFFSET + 4;
const ADVANCE_DEADLINE_RANGE_BITS_OFFSET: usize = ADVANCE_DEADLINE_CARRIES_OFFSET + 3;
const ADVANCE_DEADLINE_PRE_INV_OFFSET: usize = ADVANCE_DEADLINE_RANGE_BITS_OFFSET + 3 * 4 * 16;
const ADVANCE_DEADLINE_PHASE_INV_OFFSET: usize = ADVANCE_DEADLINE_PRE_INV_OFFSET + 1;
const LEAVE_AFTER_HAND_MASK_BITS_OFFSET: usize = ADVANCE_DEADLINE_PHASE_INV_OFFSET + 1;
const PROTOCOL_PENDING_MASK_BITS_OFFSET: usize =
    LEAVE_AFTER_HAND_MASK_BITS_OFFSET + 2 * MAX_CANONICAL_SEATS;
const PROTOCOL_PENDING_POST_INV_OFFSET: usize =
    PROTOCOL_PENDING_MASK_BITS_OFFSET + 2 * MAX_CANONICAL_SEATS;
const TRANSITION_SEAT_SELECTOR_OFFSET: usize = PROTOCOL_PENDING_POST_INV_OFFSET + 1;
const OPAQUE_COMMITMENTS_OFFSET: usize = TRANSITION_SEAT_SELECTOR_OFFSET + MAX_CANONICAL_SEATS;
const OPAQUE_COMMITMENT_COUNT: usize = 5;
const TIMEOUT_CONFIG_FIELD_COUNT: usize = 5;
const TIMEOUT_CONFIG_LIMBS: usize = 2 * TIMEOUT_CONFIG_FIELD_COUNT;
const BETTING_TIMEOUT_LIMB_OFFSET: usize = 2 * 2;
/// Per endpoint: [abi_version, button, max_players, last_bb_seat].
const STATE_IMAGE_METADATA_LIMBS: usize = 4;
const STATE_IMAGE_METADATA_OFFSET: usize =
    OPAQUE_COMMITMENTS_OFFSET + 2 * OPAQUE_COMMITMENT_COUNT * 16;
const SEAT_COMMITMENT_FIELD_COUNT: usize = 3;
const SEAT_COMMITMENT_LIMBS: usize = 16 * SEAT_COMMITMENT_FIELD_COUNT;
const SEAT_COMMITMENTS_OFFSET: usize = STATE_IMAGE_METADATA_OFFSET + 2 * STATE_IMAGE_METADATA_LIMBS;
// Each crypto-tagged row proves that its fixed 32-byte proof commitment is
// non-zero. The 16-bit decomposition is carried in the trace so unconstrained
// M31 limbs cannot cancel in the inverse relation.
const PROOF_COMMITMENT_BITS_OFFSET: usize =
    SEAT_COMMITMENTS_OFFSET + 2 * MAX_CANONICAL_SEATS * SEAT_COMMITMENT_LIMBS;
const ADVANCE_DEADLINE_TIME_BANK_ALL_OFFSET: usize = PROOF_COMMITMENT_BITS_OFFSET + 16 * 16;
const ADVANCE_DEADLINE_TIME_BANK_SLACK_OFFSET: usize = ADVANCE_DEADLINE_TIME_BANK_ALL_OFFSET + 1;
const ADVANCE_DEADLINE_TIME_BANK_EXCESS_OFFSET: usize = ADVANCE_DEADLINE_TIME_BANK_SLACK_OFFSET + 2;
const ADVANCE_DEADLINE_TIME_BANK_RANGE_BITS_OFFSET: usize =
    ADVANCE_DEADLINE_TIME_BANK_EXCESS_OFFSET + 2;
const ADVANCE_DEADLINE_TIME_BANK_CARRIES_OFFSET: usize =
    ADVANCE_DEADLINE_TIME_BANK_RANGE_BITS_OFFSET + 2 * 2 * 16;
const ADVANCE_DEADLINE_EXTENSION_CARRIES_OFFSET: usize =
    ADVANCE_DEADLINE_TIME_BANK_CARRIES_OFFSET + 3;
const ADVANCE_DEADLINE_GATES_OFFSET: usize = ADVANCE_DEADLINE_EXTENSION_CARRIES_OFFSET + 3;
const START_ACTIVE_PRODUCT_OFFSET: usize = ADVANCE_DEADLINE_GATES_OFFSET + 2;
const START_ACTIVE_COUNT_INV_OFFSET: usize = START_ACTIVE_PRODUCT_OFFSET + 1;
const START_BUTTON_SELECTOR_OFFSET: usize = START_ACTIVE_COUNT_INV_OFFSET + 1;
const START_PRE_BUTTON_SELECTOR_OFFSET: usize = START_BUTTON_SELECTOR_OFFSET + MAX_CANONICAL_SEATS;
/// Dead button (unconditional +1) rotation advice: `wrap[i]` marks the
/// wraparound seat (`from + 1 == max_players`), `next[i]` is the resolved
/// successor seat index `(from + 1) % max_players`.
const START_WRAP_OFFSET: usize = START_PRE_BUTTON_SELECTOR_OFFSET + MAX_CANONICAL_SEATS;
const START_WRAP_MAX_OFFSET: usize = START_WRAP_OFFSET + MAX_CANONICAL_SEATS;
const START_NEXT_SEAT_OFFSET: usize = START_WRAP_MAX_OFFSET + MAX_CANONICAL_SEATS;
const CONTINUITY_NEXT_PRE_OFFSET: usize = START_NEXT_SEAT_OFFSET + MAX_CANONICAL_SEATS;
const CONTINUITY_DOMAIN_COUNT: usize = 6;
const TRANSITION_COMMITMENT_OFFSET: usize =
    CONTINUITY_NEXT_PRE_OFFSET + CONTINUITY_DOMAIN_COUNT * 16;
const NULLIFIER_OFFSET: usize = TRANSITION_COMMITMENT_OFFSET + 16;
const TRANSITION_COMMITMENT_INV_OFFSET: usize = NULLIFIER_OFFSET + 16;
const NULLIFIER_INV_OFFSET: usize = TRANSITION_COMMITMENT_INV_OFFSET + 1;
const ACTOR_INV_OFFSET: usize = NULLIFIER_INV_OFFSET + 1;
const TIMEOUT_CONFIG_OFFSET: usize = ACTOR_INV_OFFSET + 1;
const TIMEOUT_CONFIG_RANGE_BITS_OFFSET: usize = TIMEOUT_CONFIG_OFFSET + 2 * TIMEOUT_CONFIG_LIMBS;
const PROTOCOL_COMPLETION_OPENING_OFFSET: usize =
    TIMEOUT_CONFIG_RANGE_BITS_OFFSET + TIMEOUT_CONFIG_LIMBS * 16;
const PROTOCOL_COMPLETION_COMMITMENT_COUNT: usize = 5;
const PROTOCOL_COMPLETION_OPENING_WIDTH: usize =
    1 + 4 + 2 + 2 + PROTOCOL_COMPLETION_COMMITMENT_COUNT * 16;
const PROTOCOL_COMPLETION_TIMESTAMP_BITS_OFFSET: usize =
    PROTOCOL_COMPLETION_OPENING_OFFSET + PROTOCOL_COMPLETION_OPENING_WIDTH;
const PROTOCOL_COMPLETION_TIMESTAMP_INV_OFFSET: usize =
    PROTOCOL_COMPLETION_TIMESTAMP_BITS_OFFSET + 4 * 16;
const PROTOCOL_COMPLETION_DEADLINE_CARRIES_OFFSET: usize =
    PROTOCOL_COMPLETION_TIMESTAMP_INV_OFFSET + 1;
const PROTOCOL_COMPLETION_CURSOR_RANGE_OFFSET: usize =
    PROTOCOL_COMPLETION_DEADLINE_CARRIES_OFFSET + 3;
// Shuffle-timeout advice is appended so the existing fixed-width ABI offsets
// remain stable.  The gate linearizes `AdvanceDeadline * flag`, while the
// count and deck products keep the timeout non-zero checks cubic.
const SHUFFLE_TIMEOUT_GATE_OFFSET: usize = PROTOCOL_COMPLETION_CURSOR_RANGE_OFFSET + 3 * 6;
const SHUFFLE_PENDING_COUNT_PRODUCT_OFFSET: usize = SHUFFLE_TIMEOUT_GATE_OFFSET + 1;
const SHUFFLE_DECK_DIFF_SQUARE_SUM_OFFSET: usize = SHUFFLE_PENDING_COUNT_PRODUCT_OFFSET + 1;
const SHUFFLE_DECK_PRODUCT_OFFSET: usize = SHUFFLE_DECK_DIFF_SQUARE_SUM_OFFSET + 1;
const SHUFFLE_DECK_NONZERO_CHANGE_INV_OFFSET: usize = SHUFFLE_DECK_PRODUCT_OFFSET + 1;
// Reveal-timeout reconstruct-continuation advice, again appended so every
// existing fixed-width ABI offset stays stable.  The two street bits range
// the pre street into the VM's board reveal streets; the commitment-change
// and live-count products keep their non-zero checks within degree three.
const REVEAL_RECONSTRUCT_STREET_BITS_OFFSET: usize = SHUFFLE_DECK_NONZERO_CHANGE_INV_OFFSET + 1;
const REVEAL_RECONSTRUCT_DIFF_SQUARE_SUM_OFFSET: usize = REVEAL_RECONSTRUCT_STREET_BITS_OFFSET + 2;
const REVEAL_RECONSTRUCT_CHANGE_PRODUCT_OFFSET: usize =
    REVEAL_RECONSTRUCT_DIFF_SQUARE_SUM_OFFSET + 1;
const REVEAL_RECONSTRUCT_CHANGE_INV_OFFSET: usize = REVEAL_RECONSTRUCT_CHANGE_PRODUCT_OFFSET + 1;
const REVEAL_RECONSTRUCT_LIVE_PRODUCT_OFFSET: usize = REVEAL_RECONSTRUCT_CHANGE_INV_OFFSET + 1;
const REVEAL_RECONSTRUCT_LIVE_INV_OFFSET: usize = REVEAL_RECONSTRUCT_LIVE_PRODUCT_OFFSET + 1;
// Three bits range a reveal-timeout kick street into the VM's exact
// reveal-street domain {1..=5}; the high bit is forced to select street 5.
const REVEAL_KICK_STREET_BITS_OFFSET: usize = REVEAL_RECONSTRUCT_LIVE_INV_OFFSET + 1;
// Sole-survivor award advice: a one-hot winner credit vector plus the
// inverse proving the awarded pot is non-zero.
const REVEAL_AWARD_WINNER_CREDIT_OFFSET: usize = REVEAL_KICK_STREET_BITS_OFFSET + 3;
const REVEAL_AWARD_POT_INV_OFFSET: usize = REVEAL_AWARD_WINNER_CREDIT_OFFSET + MAX_CANONICAL_SEATS;
// Raked sole-survivor award advice.  The six config columns copy the public
// authenticated opening; everything after them proves the exact
// `min(floor(pot * bps / 10_000), cap)` arithmetic with 16-bit range
// decompositions so no limb can wrap in M31.
const RAKE_CONFIG_OFFSET: usize = REVEAL_AWARD_POT_INV_OFFSET + 1;
// Rake range proofs use byte pairs checked against a shared 256-entry LogUp
// range table: every 16-bit limb costs two advice columns (low/high byte)
// plus two lookups instead of sixteen bit columns.
const RAKE_POT_BYTES_OFFSET: usize = RAKE_CONFIG_OFFSET + 6;
const RAKE_PRODUCT_OFFSET: usize = RAKE_POT_BYTES_OFFSET + 2 * 2;
const RAKE_PRODUCT_BYTES_OFFSET: usize = RAKE_PRODUCT_OFFSET + 4;
const RAKE_LIMBS_OFFSET: usize = RAKE_PRODUCT_BYTES_OFFSET + 4 * 2;
const RAKE_LIMB_BYTES_OFFSET: usize = RAKE_LIMBS_OFFSET + 4;
const RAKE_SCALED_OFFSET: usize = RAKE_LIMB_BYTES_OFFSET + 4 * 2;
const RAKE_SCALED_BYTES_OFFSET: usize = RAKE_SCALED_OFFSET + 4;
const RAKE_REMAINDER_OFFSET: usize = RAKE_SCALED_BYTES_OFFSET + 4 * 2;
const RAKE_REMAINDER_BYTES_OFFSET: usize = RAKE_REMAINDER_OFFSET + 1;
// Two extra bytes witnessing `9_999 - remainder`, pinning the remainder
// strictly below the divisor for the exact floor division.
const RAKE_REMAINDER_BOUND_BYTES_OFFSET: usize = RAKE_REMAINDER_BYTES_OFFSET + 2;
const RAKE_DIV_CARRIES_OFFSET: usize = RAKE_REMAINDER_BOUND_BYTES_OFFSET + 2;
const RAKE_MIN_DIFF_OFFSET: usize = RAKE_DIV_CARRIES_OFFSET + 3;
const RAKE_MIN_DIFF_BYTES_OFFSET: usize = RAKE_MIN_DIFF_OFFSET + 4;
const RAKE_MIN_BORROWS_OFFSET: usize = RAKE_MIN_DIFF_BYTES_OFFSET + 4 * 2;
const RAKE_FINAL_OFFSET: usize = RAKE_MIN_BORROWS_OFFSET + 4;
const RAKE_FINAL_BYTES_OFFSET: usize = RAKE_FINAL_OFFSET + 4;
const RAKE_AWARD_LIMBS_OFFSET: usize = RAKE_FINAL_BYTES_OFFSET + 4 * 2;
const RAKE_AWARD_BYTES_OFFSET: usize = RAKE_AWARD_LIMBS_OFFSET + 4;
const RAKE_CHIP_INTERMEDIATE_OFFSET: usize = RAKE_AWARD_BYTES_OFFSET + 4 * 2;
const RAKE_CHIP_EXTRA_CARRIES_OFFSET: usize = RAKE_CHIP_INTERMEDIATE_OFFSET + 4;
/// Per-seat `owes` advice for the betting successor relation: flag, four
/// difference limbs, three subtraction borrows, and a non-zero inverse.
const SEAT_OWES_ADVICE_OFFSET: usize = RAKE_CHIP_EXTRA_CARRIES_OFFSET + 3;
const SEAT_OWES_ADVICE_WIDTH: usize = MAX_CANONICAL_SEATS * (1 + 4 + 3 + 1 + 1);
/// #22② RevealComplete advice, appended after the seat-owes block so every
/// existing fixed-width ABI offset stays stable.  Every column is meaningful
/// only on reveal-completion rows and zero elsewhere.
///
/// The completion selector `flag * SubmitReveal` is degree two, so a dedicated
/// degree-1 gate column linearizes it (the `shuffle_timeout_gate` pattern);
/// every body below may then use full degree two under that gate.
const RC_GATE_OFFSET: usize = SEAT_OWES_ADVICE_OFFSET + SEAT_OWES_ADVICE_WIDTH;
/// Small/big blind limbs (4 + 4), copied from the public blind scope.
const RC_BLIND_LIMBS_OFFSET: usize = RC_GATE_OFFSET + 1;
/// Inverses proving the participant count is non-zero, at least two, and the
/// heads-up determinant: inverse(cnt), inverse(cnt-1), inverse(cnt-2).
const RC_COUNT_INVS_OFFSET: usize = RC_BLIND_LIMBS_OFFSET + 8;
/// Heads-up flag: exactly one iff exactly two Active seats.
const RC_HU_OFFSET: usize = RC_COUNT_INVS_OFFSET + 3;
/// One-hot small-blind and big-blind seat vectors.
const RC_SB_ONEHOT_OFFSET: usize = RC_HU_OFFSET + 1;
const RC_BB_ONEHOT_OFFSET: usize = RC_SB_ONEHOT_OFFSET + MAX_CANONICAL_SEATS;
/// Per base (button, small blind, big blind): rotated activity bits for the
/// eight non-zero circular distances, the "no earlier active" prefix
/// recurrence, and the resulting first-after selector.
const RC_ROT_OFFSET: usize = RC_BB_ONEHOT_OFFSET + MAX_CANONICAL_SEATS;
const RC_Q_OFFSET: usize = RC_ROT_OFFSET + 3 * 8;
const RC_F_OFFSET: usize = RC_Q_OFFSET + 3 * 8;
/// Small-blind distance selector with the heads-up distance-zero slot.
/// Reinterpreted under the dead-button rule: slot 0 carries the dead-small-
/// blind/no-post slot, slots 1..=8 the non-HU base seat itself (distance 0
/// from the rotation base) and the HU first-active-after-BB selection.
const RC_FFA_OFFSET: usize = RC_F_OFFSET + 3 * 8;
/// Dead-button rotation base one-hot (previous hand's big blind, or the
/// button when the track is unset) and its `last_bb_seat == NO_SEAT` flag.
const RC_BASE_ONEHOT_OFFSET: usize = RC_FFA_OFFSET + 9;
const RC_NOBB_OFFSET: usize = RC_BASE_ONEHOT_OFFSET + MAX_CANONICAL_SEATS;
/// Dead small blind flag (non-HU rows whose rotation base seat is not
/// participating: the hand posts no small blind).
const RC_DEAD_SB_OFFSET: usize = RC_NOBB_OFFSET + 1;
/// Linearized `gate * nobb` product (degree-2 relation) keeping the
/// rotation-base anchoring constraints within the degree budget.
const RC_GATE_NOBB_OFFSET: usize = RC_DEAD_SB_OFFSET + 1;
/// Linearized "live small blind" indicator `(1 - heads_up) * (1 - dead_sb)`.
const RC_LIVE_SB_OFFSET: usize = RC_GATE_NOBB_OFFSET + 1;
/// Inverse of the summed small-blind limbs, proving a live small blind posts
/// a non-zero amount (dead small blind ⟺ sb_amount == 0, fail-closed pair).
const RC_SB_AMT_INV_OFFSET: usize = RC_LIVE_SB_OFFSET + 1;
/// Blind-posting carry advice: stack (`pre = post + posted`) and total-bet
/// (`post = pre + posted`) limb carries, three per seat each.
const RC_STACK_CARRIES_OFFSET: usize = RC_SB_AMT_INV_OFFSET + 1;
const RC_TOTAL_CARRIES_OFFSET: usize = RC_STACK_CARRIES_OFFSET + MAX_CANONICAL_SEATS * 3;
/// Per-seat inverse proving a blind-posting seat keeps a non-zero stack
/// (the uncapped discipline: no AllIn flip on reveal completion).
const RC_STACK_NONZERO_INV_OFFSET: usize = RC_TOTAL_CARRIES_OFFSET + MAX_CANONICAL_SEATS * 3;
/// 封顶盲注 advice（#22②扩展）：per-seat capped 位 + UTG 空集指示。
const RC_STACK_CAPPED_OFFSET: usize = RC_STACK_NONZERO_INV_OFFSET + MAX_CANONICAL_SEATS;
const RC_NO_UTG_OFFSET: usize = RC_STACK_CAPPED_OFFSET + MAX_CANONICAL_SEATS;
// ---- #22②扩展（2026-09-15）：street / showdown completion 组 ----
/// Reveal-completion 家族门（linearized flag×SubmitReveal）。三个子门由
/// pre_subtag one-hot（hole=1 / board=2 / showdown=3）划分：preflop 盲注
/// 组沿用 rc_gate，street / showdown 组各持 rcs_gate / rcd_gate。
const RCF_GATE_OFFSET: usize = RC_NO_UTG_OFFSET + 1;
const RC_HOLE_OFFSET: usize = RCF_GATE_OFFSET + 1;
const RC_BOARD_OFFSET: usize = RC_HOLE_OFFSET + 1;
const RC_SHOWDOWN_OFFSET: usize = RC_BOARD_OFFSET + 1;
/// RevealStreet 完成门（Board 窗口完成 → 同街下注轮）。
const RCS_GATE_OFFSET: usize = RC_SHOWDOWN_OFFSET + 1;
/// Showdown 完成门（showdown 窗口 → ShowdownDisplay）。
const RCD_GATE_OFFSET: usize = RCS_GATE_OFFSET + 1;
/// rcs 首-行动扫描 advice：基座 one-hot + post-Active 旋转扫描（rot/q/f）
/// + 空集指示。
const RCS_BASE_ONEHOT_OFFSET: usize = RCD_GATE_OFFSET + 1;
const RCS_ROT_OFFSET: usize = RCS_BASE_ONEHOT_OFFSET + MAX_CANONICAL_SEATS;
const RCS_Q_OFFSET: usize = RCS_ROT_OFFSET + 8;
const RCS_F_OFFSET: usize = RCS_Q_OFFSET + 8;
const RCS_NO_TURN_OFFSET: usize = RCS_F_OFFSET + 8;
/// pre street ∈ {2,3,4} 的两比特分解（street − 2 = sel0 + 2·sel1）。
const RCS_STREET_SEL_OFFSET: usize = RCS_NO_TURN_OFFSET + 1;
const NUM_COLUMNS: usize = RCS_STREET_SEL_OFFSET + 2;
// The fixed public scope contains the table/sequence/image boundary plus the
// five authenticated root domains (state, lifecycle, overlay, settlement and
// custody) at both ends of the batch.
const PREPROCESSED_COLUMNS: usize =
    39 + 16 * 10 + 2 * STATE_IMAGE_PROJECTION_LIMBS + 4 + 6 + 13 + 1;
const SEAT_STATUS_COUNT: usize = 6;
const ROOT_SCOPE_OFFSET: usize = 39;
const ROOT_DOMAIN_COUNT: usize = 5;
const STATE_IMAGE_SCOPE_OFFSET: usize = ROOT_SCOPE_OFFSET + 16 * ROOT_DOMAIN_COUNT * 2;
const FIRST_KIND_SCOPE_OFFSET: usize = STATE_IMAGE_SCOPE_OFFSET + 2 * STATE_IMAGE_PROJECTION_LIMBS;
const LAST_KIND_SCOPE_OFFSET: usize = FIRST_KIND_SCOPE_OFFSET + 1;
const REVEAL_TIMEOUT_CASCADE_ACTIVE_SCOPE_OFFSET: usize = LAST_KIND_SCOPE_OFFSET + 1;
const REVEAL_TIMEOUT_CASCADE_SEAT_SCOPE_OFFSET: usize =
    REVEAL_TIMEOUT_CASCADE_ACTIVE_SCOPE_OFFSET + 1;
// Public rake-configuration scope (mode, bps, four cap limbs) for raked
// settlement terminals.  The companion Blake2b rules-opening proof
// authenticates these columns to the pre rules commitment.
const RAKE_SCOPE_OFFSET: usize = REVEAL_TIMEOUT_CASCADE_SEAT_SCOPE_OFFSET + 1;
// Public blind/ante scope (four small-blind limbs, four big-blind limbs, the
// ante mode and four ante limbs) for #22② reveal-completion rows.  The same
// companion rules proof that authenticates the rake scope authenticates this
// projection to the pre rules commitment.
const BLIND_SCOPE_OFFSET: usize = RAKE_SCOPE_OFFSET + 6;
const BLIND_SCOPE_ANTE_MODE_INDEX: usize = 8;
// Shared 256-entry byte range table consumed through the LogUp relation.
const RANGE_TABLE_SCOPE_OFFSET: usize = BLIND_SCOPE_OFFSET + 13;

// `CanonicalStateImage` is deliberately a fixed Borsh ABI.  These constants
// are byte positions in its 1,680-byte v5 encoding, not host projections.
// The endpoint scope below materializes every byte of that fixed image: u8
// fields stay separate, while the remaining bytes use 16-bit little-endian
// limbs.  Remaining host-zero gaps concern transition semantics, not an
// unbound endpoint field.
const CANONICAL_STATE_IMAGE_BORSH_BYTES: usize = 1_681;
const STATE_IMAGE_TABLE_OFFSET: usize = 2;
const STATE_IMAGE_HAND_OFFSET: usize = 10;
const STATE_IMAGE_CALL_SEQ_OFFSET: usize = 14;
const STATE_IMAGE_PHASE_OFFSET: usize = 18;
const STATE_IMAGE_PHASE_SUBTAG_OFFSET: usize = 19;
const STATE_IMAGE_STREET_OFFSET: usize = 20;
const STATE_IMAGE_TURN_OFFSET: usize = 21;
const STATE_IMAGE_DEADLINE_OFFSET: usize = 22;
const STATE_IMAGE_SHUFFLE_TIMEOUT_OFFSET: usize = 30;
const STATE_IMAGE_REVEAL_TIMEOUT_OFFSET: usize = 34;
const STATE_IMAGE_BETTING_TIMEOUT_OFFSET: usize = 38;
const STATE_IMAGE_RECONSTRUCT_TIMEOUT_OFFSET: usize = 42;
const STATE_IMAGE_SHOWDOWN_DISPLAY_OFFSET: usize = 46;
const STATE_IMAGE_CURRENT_BET_OFFSET: usize = 50;
const STATE_IMAGE_MIN_RAISE_OFFSET: usize = 58;
const STATE_IMAGE_CHIP_POOL_OFFSET: usize = 66;
const STATE_IMAGE_POT_OFFSET: usize = 74;
const STATE_IMAGE_BUTTON_OFFSET: usize = 82;
const STATE_IMAGE_LAST_BB_SEAT_OFFSET: usize = 83;
const STATE_IMAGE_MAX_PLAYERS_OFFSET: usize = 84;
const STATE_IMAGE_ACTED_MASK_OFFSET: usize = 85;
const STATE_IMAGE_LEAVE_MASK_OFFSET: usize = 87;
const STATE_IMAGE_PROTOCOL_PENDING_MASK_OFFSET: usize = 89;
const STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET: usize = 91;
const STATE_IMAGE_DECK_COMMITMENT_OFFSET: usize = 123;
const STATE_IMAGE_REVEAL_COMMITMENT_OFFSET: usize = 155;
const STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET: usize = 187;
const STATE_IMAGE_RUN_IT_TWICE_COMMITMENT_OFFSET: usize = 219;
const STATE_IMAGE_RULES_OFFSET: usize = 251;
const STATE_IMAGE_GOVERNANCE_OFFSET: usize = 283;
const STATE_IMAGE_SETTLEMENT_OFFSET: usize = 315;
const STATE_IMAGE_CUSTODY_OFFSET: usize = 347;
const STATE_IMAGE_LIFECYCLE_OFFSET: usize = 379;
const STATE_IMAGE_OVERLAY_OFFSET: usize = 411;
const STATE_IMAGE_ROOT_OFFSET: usize = 443;
const STATE_IMAGE_SEATS_OFFSET: usize = 475;
const STATE_IMAGE_SEAT_BYTES: usize = 134;
const STATE_IMAGE_SEAT_STATUS_OFFSET: usize = 0;
const STATE_IMAGE_SEAT_ACTED_OFFSET: usize = 1;
const STATE_IMAGE_SEAT_STACK_OFFSET: usize = 2;
const STATE_IMAGE_SEAT_BET_OFFSET: usize = 10;
const STATE_IMAGE_SEAT_TOTAL_OFFSET: usize = 18;
const STATE_IMAGE_SEAT_PENDING_OFFSET: usize = 26;
const STATE_IMAGE_SEAT_TIME_BANK_OFFSET: usize = 34;
const STATE_IMAGE_SEAT_IDENTITY_COMMITMENT_OFFSET: usize = 38;
const STATE_IMAGE_SEAT_KEY_COMMITMENT_OFFSET: usize = 70;
const STATE_IMAGE_SEAT_HOLE_CARDS_COMMITMENT_OFFSET: usize = 102;
const STATE_IMAGE_HEADER_PROJECTION_LIMBS: usize = 49;
const STATE_IMAGE_COMMITMENT_PROJECTION_LIMBS: usize = 16 * (7 + OPAQUE_COMMITMENT_COUNT);
const STATE_IMAGE_SEAT_PROJECTION_LIMBS: usize = 20 + SEAT_COMMITMENT_LIMBS;
const STATE_IMAGE_PROJECTION_LIMBS: usize = STATE_IMAGE_HEADER_PROJECTION_LIMBS
    + STATE_IMAGE_COMMITMENT_PROJECTION_LIMBS
    + MAX_CANONICAL_SEATS * STATE_IMAGE_SEAT_PROJECTION_LIMBS;

// Stable positions in the fixed canonical ABI prefix.  Keep mutation tests
// named rather than coupling them to incidental trace growth in the advice
// suffix below.
#[cfg(test)] // 仅同文件测试用于列索引断言
const ACTION_AMOUNT_OFFSET: usize = 267;
#[cfg(test)] // 仅同文件测试用于列索引断言
const PROOF_COMMITMENT_OFFSET: usize = ACTION_AMOUNT_OFFSET - 17;
#[cfg(test)] // 仅同文件测试用于列索引断言
const ACTION_SEAT_OFFSET: usize = 266;
#[cfg(test)] // 仅同文件测试用于列索引断言
const ACTION_AUXILIARY_OFFSET: usize = 271;
#[cfg(test)] // 仅同文件测试用于列索引断言
const ACTION_FLAG_OFFSET: usize = 275;
#[cfg(test)] // 仅同文件测试用于列索引断言
const PRE_PHASE_OFFSET: usize = 281;
#[cfg(test)] // 仅同文件测试用于列索引断言
const POST_PHASE_OFFSET: usize = 282;
#[cfg(test)] // 仅同文件测试用于列索引断言
const POST_TURN_OFFSET: usize = 288;
#[cfg(test)] // 仅同文件测试用于列索引断言
const PRE_POT_OFFSET: usize = 305;
#[cfg(test)] // 仅同文件测试用于列索引断言
const POST_POT_OFFSET: usize = 309;
#[cfg(test)] // 仅同文件测试用于列索引断言
const POST_LEAVE_MASK_OFFSET: usize = 316;
#[cfg(test)] // 仅同文件测试用于列索引断言
const PRE_PROTOCOL_PENDING_MASK_OFFSET: usize = 317;
#[cfg(test)] // 仅同文件测试用于列索引断言
const POST_PROTOCOL_PENDING_MASK_OFFSET: usize = 318;
#[cfg(test)] // 仅同文件测试用于列索引断言
const SELECTED_POST_STATUS_OFFSET: usize = 339;
#[cfg(test)] // 仅同文件测试用于列索引断言
const DEADLINE_HEIGHT_OFFSET: usize = 276;
#[cfg(test)] // 仅同文件测试用于列索引断言
const PRE_CHIP_POOL_OFFSET: usize = BASE_NUM_COLUMNS - 2 * 4 * 16 - 9 - 8;
#[cfg(test)] // 仅同文件测试用于列索引断言
const POST_CHIP_POOL_OFFSET: usize = PRE_CHIP_POOL_OFFSET + 4;

// Shared 256-entry byte range table for the raked-award LogUp lookups,
// following the cairo-air range-check component pattern (single component,
// paired fractions, log_size+1 degree bound).
relation!(CanonicalRange8, 1);

#[derive(Debug, Clone)]
struct CanonicalAir {
    log_size: u32,
    range: CanonicalRange8,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCanonicalTaggedProof {
    pub log_size: u32,
    pub num_columns: u32,
    pub table_id: u64,
    pub first_hand_id: u32,
    pub last_hand_id: u32,
    pub first_call_seq: u32,
    pub last_call_seq: u32,
    pub transition_count: u16,
    /// Selector on the first trace row, publicly bound by the canonical AIR.
    pub first_transition_kind: u8,
    /// Selector on the last trace row, publicly bound by the canonical AIR.
    pub last_transition_kind: u8,
    /// Number of non-terminal reveal-timeout kick rows in this tagged batch.
    /// Zero denotes an ordinary canonical batch.  When the final row is a
    /// `RevealTimeoutReset` continuation, the terminal seat is stored in the
    /// next schedule slot and `transition_count == count + 1`.
    pub reveal_timeout_cascade_count: u8,
    /// Public seat sequence for the reveal-timeout kick rows. Unused entries
    /// are padded with [`REVEAL_TIMEOUT_CASCADE_EMPTY_SEAT`].
    pub reveal_timeout_cascade_schedule: [u8; MAX_REVEAL_TIMEOUT_CASCADE_KICKS],
    pub batch_digest: [u8; 32],
    pub pre_state_commitment: [u8; 32],
    pub post_state_commitment: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub pre_lifecycle_root: [u8; 32],
    pub post_lifecycle_root: [u8; 32],
    pub pre_overlay_root: [u8; 32],
    pub post_overlay_root: [u8; 32],
    pub pre_settlement_commitment: [u8; 32],
    pub post_settlement_commitment: [u8; 32],
    pub pre_custody_commitment: [u8; 32],
    pub post_custody_commitment: [u8; 32],
    /// Exact Borsh bytes of the canonical endpoint images.  They are mixed
    /// into Fiat--Shamir and their AIR-visible projection is constrained to
    /// the first/last trace rows.  A companion Blake2b proof authenticates
    /// the complete byte strings to the two image commitments.
    pub pre_state_image_bytes: Vec<u8>,
    pub post_state_image_bytes: Vec<u8>,
    /// Public claimed sum of the balanced range LogUp relation, serialized as
    /// the four M31 coordinates of the secure field element.
    pub range_claimed_sum: [u32; 4],
    /// Public authenticated rake configuration for a raked sole-survivor
    /// award terminal.  Present exactly when the batch contains a
    /// `RevealTimeoutRakedAward` row.
    pub rake_opening: Option<crate::canonical_rake_opening::CanonicalRakeOpening>,
    /// Public authenticated blind/ante projection for #22② reveal-completion
    /// rows.  Present exactly when the batch contains a final SubmitReveal.
    pub blind_opening: Option<crate::canonical_rake_opening::CanonicalBlindOpening>,
    /// Lookup-backed Blake2b proof that the complete table-rules byte string
    /// hashes to the pre rules commitment, authenticating `rake_opening`.
    pub rules_hash: Option<crate::canonical_rake_opening::ArchivedCanonicalRulesHashProof>,
    /// Immutable L1 object key of the fixed-width state-commitment leaf.
    ///
    /// A value of zero is reserved for the legacy canonical proof API.  The
    /// host-zero opening-composition API rejects it and requires this key to
    /// equal both authenticated SMT openings and the finalized receipt.
    pub state_object_key: [u8; 32],
    /// Versioned fixed-width state-leaf ABI.  It prevents a proof for one
    /// table-object layout from being accepted under another epoch.
    pub state_opening_epoch: u32,
    pub stark_proof_bytes: Vec<u8>,
}

/// Public state-object scope for a canonical transition proof.
///
/// The key is deliberately an L1 object key rather than a host-derived table
/// hash.  The finalized receipt authenticates that key for the table, while a
/// companion Blake2b SMT proof authenticates its value at the pre/post roots.
/// This keeps the verifier from depending on an RPC lookup or transaction
/// replay to associate an opening with the transition statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalStateOpeningScope {
    pub state_object_key: [u8; 32],
    pub state_opening_epoch: u32,
}

impl CanonicalStateOpeningScope {
    /// Legacy proofs intentionally have no fixed-width state-object opening.
    #[must_use]
    pub const fn legacy() -> Self {
        Self {
            state_object_key: [0; 32],
            state_opening_epoch: 0,
        }
    }

    /// Validate the non-legacy opening namespace.
    pub fn validate(self) -> TexasAirResult<()> {
        if self.state_object_key == [0; 32] || self.state_opening_epoch == 0 {
            return Err(TexasAirError::SpecViolation(
                "canonical fixed-width state opening requires a non-zero key and epoch".into(),
            ));
        }
        Ok(())
    }
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

pub(crate) fn batch_digest_for_witnesses(witnesses: &[CanonicalTransitionWitness]) -> [u8; 32] {
    let encoded = borsh::to_vec(witnesses).expect("canonical witness encoding");
    let mut h = Blake2bVar::new(32).expect("digest length");
    h.update(b"zchain.texas.canonical-tagged-batch.v2");
    h.update(&encoded);
    let mut out = [0; 32];
    h.finalize_variable(&mut out).expect("digest length");
    out
}

fn bytes16(bytes: &[u8; 32]) -> Vec<M31> {
    bytes
        .chunks_exact(2)
        .map(|x| M31::from(u32::from(u16::from_le_bytes([x[0], x[1]]))))
        .collect()
}

fn state_image_limb(bytes: &[u8], offset: usize) -> M31 {
    M31::from(u32::from(u16::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
    ])))
}

fn append_state_image_u64_projection(out: &mut Vec<M31>, bytes: &[u8], offset: usize) {
    for limb in 0..4 {
        out.push(state_image_limb(bytes, offset + limb * 2));
    }
}

fn append_state_image_u32_projection(out: &mut Vec<M31>, bytes: &[u8], offset: usize) {
    for limb in 0..2 {
        out.push(state_image_limb(bytes, offset + limb * 2));
    }
}

fn append_state_image_commitment_projection(out: &mut Vec<M31>, bytes: &[u8], offset: usize) {
    for limb in 0..16 {
        out.push(state_image_limb(bytes, offset + limb * 2));
    }
}

/// Project the Borsh endpoint bytes onto values that the current canonical
/// transition AIR already carries in its trace.  This keeps the expensive
/// full byte statement in Fiat--Shamir while adding only 852 endpoint scope
/// limbs, rather than thousands of public columns.
fn state_image_projection(bytes: &[u8]) -> TexasAirResult<Vec<M31>> {
    if bytes.len() != CANONICAL_STATE_IMAGE_BORSH_BYTES {
        return Err(TexasAirError::SpecViolation(
            "canonical state-image Borsh byte length is invalid".into(),
        ));
    }
    let mut out = Vec::with_capacity(STATE_IMAGE_PROJECTION_LIMBS);
    out.push(state_image_limb(bytes, 0));
    // 与 AIR 绑定端的 metadata 顺序一致：abi, button, max_players, last_bb。
    out.push(M31::from(u32::from(bytes[STATE_IMAGE_BUTTON_OFFSET])));
    out.push(M31::from(u32::from(bytes[STATE_IMAGE_MAX_PLAYERS_OFFSET])));
    out.push(M31::from(u32::from(bytes[STATE_IMAGE_LAST_BB_SEAT_OFFSET])));
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_TABLE_OFFSET);
    append_state_image_u32_projection(&mut out, bytes, STATE_IMAGE_HAND_OFFSET);
    append_state_image_u32_projection(&mut out, bytes, STATE_IMAGE_CALL_SEQ_OFFSET);
    for offset in [
        STATE_IMAGE_PHASE_OFFSET,
        STATE_IMAGE_PHASE_SUBTAG_OFFSET,
        STATE_IMAGE_STREET_OFFSET,
        STATE_IMAGE_TURN_OFFSET,
    ] {
        out.push(M31::from(u32::from(bytes[offset])));
    }
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_DEADLINE_OFFSET);
    for offset in [
        STATE_IMAGE_SHUFFLE_TIMEOUT_OFFSET,
        STATE_IMAGE_REVEAL_TIMEOUT_OFFSET,
        STATE_IMAGE_BETTING_TIMEOUT_OFFSET,
        STATE_IMAGE_RECONSTRUCT_TIMEOUT_OFFSET,
        STATE_IMAGE_SHOWDOWN_DISPLAY_OFFSET,
    ] {
        append_state_image_u32_projection(&mut out, bytes, offset);
    }
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_CURRENT_BET_OFFSET);
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_MIN_RAISE_OFFSET);
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_CHIP_POOL_OFFSET);
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_POT_OFFSET);
    out.push(state_image_limb(bytes, STATE_IMAGE_ACTED_MASK_OFFSET));
    out.push(state_image_limb(bytes, STATE_IMAGE_LEAVE_MASK_OFFSET));
    out.push(state_image_limb(
        bytes,
        STATE_IMAGE_PROTOCOL_PENDING_MASK_OFFSET,
    ));
    for offset in [
        STATE_IMAGE_RULES_OFFSET,
        STATE_IMAGE_GOVERNANCE_OFFSET,
        STATE_IMAGE_ROOT_OFFSET,
        STATE_IMAGE_LIFECYCLE_OFFSET,
        STATE_IMAGE_OVERLAY_OFFSET,
        STATE_IMAGE_SETTLEMENT_OFFSET,
        STATE_IMAGE_CUSTODY_OFFSET,
    ] {
        append_state_image_commitment_projection(&mut out, bytes, offset);
    }
    for offset in [
        STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET,
        STATE_IMAGE_DECK_COMMITMENT_OFFSET,
        STATE_IMAGE_REVEAL_COMMITMENT_OFFSET,
        STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET,
        STATE_IMAGE_RUN_IT_TWICE_COMMITMENT_OFFSET,
    ] {
        append_state_image_commitment_projection(&mut out, bytes, offset);
    }
    for seat in 0..MAX_CANONICAL_SEATS {
        let offset = STATE_IMAGE_SEATS_OFFSET + seat * STATE_IMAGE_SEAT_BYTES;
        out.push(M31::from(u32::from(
            bytes[offset + STATE_IMAGE_SEAT_STATUS_OFFSET],
        )));
        out.push(M31::from(u32::from(
            bytes[offset + STATE_IMAGE_SEAT_ACTED_OFFSET],
        )));
        append_state_image_u64_projection(&mut out, bytes, offset + STATE_IMAGE_SEAT_STACK_OFFSET);
        append_state_image_u64_projection(&mut out, bytes, offset + STATE_IMAGE_SEAT_BET_OFFSET);
        append_state_image_u64_projection(&mut out, bytes, offset + STATE_IMAGE_SEAT_TOTAL_OFFSET);
        append_state_image_u64_projection(
            &mut out,
            bytes,
            offset + STATE_IMAGE_SEAT_PENDING_OFFSET,
        );
        append_state_image_u32_projection(
            &mut out,
            bytes,
            offset + STATE_IMAGE_SEAT_TIME_BANK_OFFSET,
        );
        for commitment_offset in [
            STATE_IMAGE_SEAT_IDENTITY_COMMITMENT_OFFSET,
            STATE_IMAGE_SEAT_KEY_COMMITMENT_OFFSET,
            STATE_IMAGE_SEAT_HOLE_CARDS_COMMITMENT_OFFSET,
        ] {
            append_state_image_commitment_projection(&mut out, bytes, offset + commitment_offset);
        }
    }
    debug_assert_eq!(out.len(), STATE_IMAGE_PROJECTION_LIMBS);
    Ok(out)
}

fn decode_state_image_bytes(bytes: &[u8]) -> TexasAirResult<CanonicalStateImage> {
    // The byte statement is part of the verifier-visible Fiat--Shamir scope,
    // but length alone is not a canonical ABI check.  Decode and re-encode it
    // so enum discriminants, padding, and trailing bytes cannot be used to
    // detach the endpoint image from the typed state contract.
    if bytes.len() != CANONICAL_STATE_IMAGE_BORSH_BYTES {
        return Err(TexasAirError::SpecViolation(
            "canonical state-image Borsh byte length is invalid".into(),
        ));
    }
    let image: CanonicalStateImage = borsh::from_slice(bytes).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "canonical state-image Borsh decoding failed: {error}"
        ))
    })?;
    if borsh::to_vec(&image)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?
        != bytes
    {
        return Err(TexasAirError::SpecViolation(
            "canonical state-image bytes are not a canonical Borsh encoding".into(),
        ));
    }
    image.validate().map_err(TexasAirError::SpecViolation)?;
    Ok(image)
}

fn validate_state_image_bytes_inner(
    proof: &ArchivedCanonicalTaggedProof,
    verify_commitment: bool,
) -> TexasAirResult<(CanonicalStateImage, CanonicalStateImage)> {
    let pre = decode_state_image_bytes(&proof.pre_state_image_bytes)?;
    let post = decode_state_image_bytes(&proof.post_state_image_bytes)?;
    let check_endpoint = |image: &CanonicalStateImage,
                          expected_hand: u32,
                          expected_call_seq: u32,
                          expected_commitment: [u8; 32],
                          expected_state_root: [u8; 32],
                          expected_lifecycle_root: [u8; 32],
                          expected_overlay_root: [u8; 32],
                          expected_settlement: [u8; 32],
                          expected_custody: [u8; 32],
                          label: &str|
     -> TexasAirResult<()> {
        if image.table_id != proof.table_id
            || image.hand_id != expected_hand
            || image.call_seq != expected_call_seq
            || (verify_commitment && image.commitment() != expected_commitment)
            || image.state_root != expected_state_root
            || image.lifecycle_root != expected_lifecycle_root
            || image.overlay_root != expected_overlay_root
            || image.settlement_commitment != expected_settlement
            || image.custody_commitment != expected_custody
        {
            return Err(TexasAirError::SpecViolation(format!(
                "canonical {label} endpoint image is detached from archive scope"
            )));
        }
        Ok(())
    };
    check_endpoint(
        &pre,
        proof.first_hand_id,
        proof.first_call_seq,
        proof.pre_state_commitment,
        proof.pre_state_root,
        proof.pre_lifecycle_root,
        proof.pre_overlay_root,
        proof.pre_settlement_commitment,
        proof.pre_custody_commitment,
        "pre",
    )?;
    check_endpoint(
        &post,
        proof.last_hand_id,
        proof.last_call_seq,
        proof.post_state_commitment,
        proof.post_state_root,
        proof.post_lifecycle_root,
        proof.post_overlay_root,
        proof.post_settlement_commitment,
        proof.post_custody_commitment,
        "post",
    )?;
    // Keep the projection check explicit: the AIR consumes this compact
    // fixed-width endpoint statement; a separate hash AIR authenticates the
    // byte-to-commitment relation in the host-zero composition.
    state_image_projection(&proof.pre_state_image_bytes)?;
    state_image_projection(&proof.post_state_image_bytes)?;
    Ok((pre, post))
}

fn validate_state_image_bytes(
    proof: &ArchivedCanonicalTaggedProof,
) -> TexasAirResult<(CanonicalStateImage, CanonicalStateImage)> {
    validate_state_image_bytes_inner(proof, true)
}

fn u32_limbs(value: u32) -> [M31; 2] {
    [M31::from(value & 0xffff), M31::from(value >> 16)]
}

fn u64_limbs(value: u64) -> [M31; 4] {
    [
        M31::from((value & 0xffff) as u32),
        M31::from(((value >> 16) & 0xffff) as u32),
        M31::from(((value >> 32) & 0xffff) as u32),
        M31::from((value >> 48) as u32),
    ]
}

fn add_carries(left: u64, right: u64) -> [M31; 3] {
    let a = u64_limbs(left);
    let b = u64_limbs(right);
    let mut carry = 0u64;
    let mut out = [M31::from(0); 3];
    for index in 0..4 {
        let sum = u64::from(a[index].0) + u64::from(b[index].0) + carry;
        carry = sum >> 16;
        if index < 3 {
            out[index] = M31::from(carry as u32);
        }
    }
    out
}

/// Carries for `post_pot = pre_pot + sum(pre_seat_bet)`.  The final
/// high-limb carry is deliberately omitted: the AIR requires it to be zero,
/// which is the VM's checked-overflow condition.
fn round_collect_carries(pot: u64, seats: &[crate::texas_canonical::CanonicalSeat]) -> [M31; 3] {
    let pot = u64_limbs(pot);
    let bets: Vec<_> = seats.iter().map(|seat| u64_limbs(seat.bet)).collect();
    let mut carry = 0u64;
    let mut out = [M31::from(0); 3];
    for limb in 0..4 {
        let sum = u64::from(pot[limb].0)
            + bets.iter().map(|bet| u64::from(bet[limb].0)).sum::<u64>()
            + carry;
        carry = sum >> 16;
        if limb < 3 {
            out[limb] = M31::from(carry as u32);
        }
    }
    out
}

fn u16_bits(value: u16) -> [M31; 16] {
    std::array::from_fn(|index| M31::from(u32::from((value >> index) & 1)))
}

fn append_u64_bits(out: &mut Vec<M31>, value: u64) {
    for limb in 0..4 {
        out.extend(u16_bits(((value >> (limb * 16)) & 0xffff) as u16));
    }
}

fn mask_bits(value: u16) -> [M31; MAX_CANONICAL_SEATS] {
    std::array::from_fn(|index| M31::from(u32::from((value >> index) & 1)))
}

fn status_one_hot(status: CanonicalSeatStatus) -> [M31; SEAT_STATUS_COUNT] {
    std::array::from_fn(|index| M31::from(u32::from(index == status as usize)))
}

fn is_betting_action(kind: CanonicalTransitionKind) -> bool {
    matches!(
        kind,
        CanonicalTransitionKind::Fold
            | CanonicalTransitionKind::Check
            | CanonicalTransitionKind::Call
            | CanonicalTransitionKind::Raise
            | CanonicalTransitionKind::Bet
            | CanonicalTransitionKind::FoldWithProof
            | CanonicalTransitionKind::AutoFold
    )
}

fn is_crypto_action(kind: CanonicalTransitionKind) -> bool {
    matches!(
        kind,
        CanonicalTransitionKind::SubmitShuffle
            | CanonicalTransitionKind::SubmitReveal
            | CanonicalTransitionKind::SubmitReconstruct
            | CanonicalTransitionKind::FoldWithProof
    )
}

fn is_funding_action(kind: CanonicalTransitionKind) -> bool {
    matches!(
        kind,
        CanonicalTransitionKind::Addon | CanonicalTransitionKind::Rebuy
    )
}

fn row(w: &CanonicalTransitionWitness, next_pre: Option<&CanonicalStateImage>) -> Vec<M31> {
    let mut out = Vec::with_capacity(NUM_COLUMNS);
    out.push(M31::from(1u32));
    for index in 0..KIND_COUNT {
        out.push(M31::from(u32::from(index == w.kind as usize)));
    }
    out.extend(u64_limbs(w.pre.table_id));
    out.extend(u32_limbs(w.pre.hand_id));
    out.extend(u32_limbs(w.post.hand_id));
    out.extend(u32_limbs(w.pre.call_seq));
    out.extend(u32_limbs(w.post.call_seq));
    out.extend(bytes16(&w.pre.commitment()));
    out.extend(bytes16(&w.post.commitment()));
    for digest in [
        w.pre.state_root,
        w.post.state_root,
        w.pre.lifecycle_root,
        w.post.lifecycle_root,
        w.pre.overlay_root,
        w.post.overlay_root,
        w.pre.settlement_commitment,
        w.post.settlement_commitment,
        w.pre.custody_commitment,
        w.post.custody_commitment,
        w.actor,
        w.action.proof_commitment,
    ] {
        out.extend(bytes16(&digest));
    }
    out.push(M31::from(u32::from(w.action.seat)));
    out.extend(u64_limbs(w.action.amount));
    out.extend(u64_limbs(w.action.auxiliary));
    out.push(M31::from(u32::from(w.action.flag)));
    out.extend(u64_limbs(w.deadline_height));
    out.push(M31::from(u32::from(w.pre.call_seq & 0xffff == 0xffff)));
    for (pre, post) in [
        (w.pre.phase as u8, w.post.phase as u8),
        (w.pre.phase_subtag, w.post.phase_subtag),
        (w.pre.street, w.post.street),
        (w.pre.current_turn, w.post.current_turn),
    ] {
        out.push(M31::from(u32::from(pre)));
        out.push(M31::from(u32::from(post)));
    }
    for (pre, post) in [
        (w.pre.current_bet, w.post.current_bet),
        (w.pre.min_raise, w.post.min_raise),
        (w.pre.pot, w.post.pot),
    ] {
        out.extend(u64_limbs(pre));
        out.extend(u64_limbs(post));
    }
    out.push(M31::from(u32::from(w.pre.acted_mask)));
    out.push(M31::from(u32::from(w.post.acted_mask)));
    out.push(M31::from(u32::from(w.pre.leave_after_hand_mask)));
    out.push(M31::from(u32::from(w.post.leave_after_hand_mask)));
    out.push(M31::from(u32::from(w.pre.protocol_pending_mask)));
    out.push(M31::from(u32::from(w.post.protocol_pending_mask)));
    let seat = usize::from(w.action.seat);
    let before = if seat < w.pre.seats.len() {
        Some(w.pre.seats[seat])
    } else {
        None
    };
    let after = if seat < w.post.seats.len() {
        Some(w.post.seats[seat])
    } else {
        None
    };
    let before_seat = before.unwrap_or(crate::texas_canonical::CanonicalSeat::EMPTY);
    for image in [before, after] {
        let image = image.unwrap_or(crate::texas_canonical::CanonicalSeat::EMPTY);
        out.push(M31::from(image.status as u32));
        out.push(M31::from(u32::from(image.acted)));
        out.extend(u64_limbs(image.stack));
        out.extend(u64_limbs(image.bet));
        out.extend(u64_limbs(image.total_bet));
        out.extend(u64_limbs(image.pending_addon));
        out.extend(u32_limbs(image.time_bank_ms));
    }
    // The inverse makes the AIR's `post_turn != action.seat` check a true field
    // constraint.  The AIR multiplies the raw field difference
    // `post_turn - seat`, so the advice must invert that difference exactly:
    // a wrapped successor (for example seat 1 handing action back to seat 0)
    // is the field value `-1`, not the mod-16 residue 15.  Protocol-submit
    // rows reuse this otherwise idle advice cell to prove the selected seat
    // is non-empty before accepting a shuffle/reveal/reconstruct submission.
    let protocol_submit = matches!(
        w.kind,
        CanonicalTransitionKind::SubmitShuffle
            | CanonicalTransitionKind::SubmitReveal
            | CanonicalTransitionKind::SubmitReconstruct
    );
    let turn_inv = if protocol_submit {
        let status = before_seat.status as u32;
        if status == 0 {
            M31::from(0)
        } else {
            M31::from(status).inverse()
        }
    } else {
        let difference =
            M31::from(u32::from(w.post.current_turn)) - M31::from(u32::from(w.action.seat));
        if difference == M31::from(0) {
            M31::from(0)
        } else {
            difference.inverse()
        }
    };
    out.push(turn_inv);
    // Keep Call's ripple carries in the committed row. The fourth limb equation
    // constrains the omitted final carry to zero, so overflow cannot wrap.
    let amount_limb_sum = u64_limbs(w.action.amount)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    let proof_limb_sum = bytes16(&w.action.proof_commitment)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    let inverse_input = if is_crypto_action(w.kind) {
        proof_limb_sum
    } else {
        amount_limb_sum
    };
    out.push(if inverse_input == 0 {
        M31::from(0u32)
    } else {
        M31::from(inverse_input as u32).inverse()
    });
    let uses_delta_wager_carries = matches!(
        w.kind,
        CanonicalTransitionKind::Call | CanonicalTransitionKind::Bet
    );
    out.extend(if uses_delta_wager_carries {
        add_carries(after.map_or(0, |seat| seat.stack), w.action.amount)
    } else {
        [M31::from(0u32); 3]
    });
    out.extend(if uses_delta_wager_carries {
        add_carries(before.map_or(0, |seat| seat.bet), w.action.amount)
    } else {
        [M31::from(0u32); 3]
    });
    out.extend(if uses_delta_wager_carries {
        add_carries(before.map_or(0, |seat| seat.total_bet), w.action.amount)
    } else {
        [M31::from(0u32); 3]
    });
    // The VM keeps current-round wagers on seats and collects them into the
    // pot only when the betting round advances.
    out.extend([M31::from(0u32); 3]);
    // Canonical bit decompositions are essential for the ripple equations below:
    // without them a malicious prover could use arbitrary M31 elements as limbs
    // and satisfy an apparent u64 addition only modulo the field.
    for value in [
        before.map_or(0, |seat| seat.stack),
        after.map_or(0, |seat| seat.stack),
        before.map_or(0, |seat| seat.bet),
        after.map_or(0, |seat| seat.bet),
        before.map_or(0, |seat| seat.total_bet),
        after.map_or(0, |seat| seat.total_bet),
        w.pre.pot,
        w.post.pot,
        w.action.amount,
    ] {
        append_u64_bits(&mut out, value);
    }
    // Call requires its own comparison witness: `owed = current_bet - seat_bet`
    // and `amount = min(owed, stack)`.  A positive shortfall distinguishes a
    // short all-in from the equal-stack ordinary-call case.
    let owed = if w.kind == CanonicalTransitionKind::Call {
        w.pre.current_bet.saturating_sub(before_seat.bet)
    } else {
        0
    };
    let call_all_in = w.kind == CanonicalTransitionKind::Call && before_seat.stack < owed;
    let call_difference = if call_all_in {
        owed - before_seat.stack
    } else {
        before_seat.stack.saturating_sub(owed)
    };
    out.extend(u64_limbs(owed));
    out.extend(u64_limbs(call_difference));
    out.push(M31::from(u32::from(call_all_in)));
    let difference_limb_sum = u64_limbs(call_difference)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(if call_all_in {
        M31::from(difference_limb_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    out.extend(add_carries(before_seat.bet, owed));
    out.extend(if call_all_in {
        [M31::from(0u32); 3]
    } else {
        add_carries(owed, call_difference)
    });
    out.extend(if call_all_in {
        add_carries(before_seat.stack, call_difference)
    } else {
        [M31::from(0u32); 3]
    });
    append_u64_bits(&mut out, owed);
    append_u64_bits(&mut out, call_difference);
    // Raise carries an absolute target bet. Its private comparison witnesses
    // prove the two strict target bounds, available stack, and the short
    // all-in exception to the minimum-raise rule without using host ordering.
    let is_raise = w.kind == CanonicalTransitionKind::Raise;
    let raise_needed = if is_raise {
        w.action.amount.saturating_sub(before_seat.bet)
    } else {
        0
    };
    let raise_delta = if is_raise {
        w.action.amount.saturating_sub(w.pre.current_bet)
    } else {
        0
    };
    let raise_stack_difference = if is_raise {
        before_seat.stack.saturating_sub(raise_needed)
    } else {
        0
    };
    let raise_meets_min = is_raise && raise_delta >= w.pre.min_raise;
    let raise_min_difference = if is_raise {
        if raise_meets_min {
            raise_delta - w.pre.min_raise
        } else {
            w.pre.min_raise.saturating_sub(raise_delta)
        }
    } else {
        0
    };
    let raise_all_in = is_raise && raise_needed == before_seat.stack;
    out.extend(u64_limbs(raise_needed));
    out.extend(u64_limbs(raise_delta));
    out.extend(u64_limbs(raise_stack_difference));
    out.extend(u64_limbs(raise_min_difference));
    out.push(M31::from(u32::from(raise_all_in)));
    out.push(M31::from(u32::from(raise_meets_min)));
    for value in [raise_needed, raise_delta] {
        let limb_sum = u64_limbs(value)
            .into_iter()
            .map(|limb| u64::from(limb.0))
            .sum::<u64>();
        out.push(if is_raise && limb_sum != 0 {
            M31::from(limb_sum as u32).inverse()
        } else {
            M31::from(0u32)
        });
    }
    let stack_difference_sum = u64_limbs(raise_stack_difference)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(if raise_all_in {
        M31::from(0u32)
    } else if is_raise {
        M31::from(stack_difference_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    out.extend(add_carries(before_seat.bet, raise_needed));
    out.extend(add_carries(w.pre.current_bet, raise_delta));
    out.extend(add_carries(raise_needed, raise_stack_difference));
    out.extend(add_carries(before_seat.total_bet, raise_needed));
    out.extend([M31::from(0u32); 3]);
    for value in [
        raise_needed,
        raise_delta,
        raise_stack_difference,
        raise_min_difference,
    ] {
        append_u64_bits(&mut out, value);
    }
    // A chip-moving betting action must derive the selected-seat lifecycle
    // directly from the resulting stack: zero means AllIn, otherwise Active.
    // The inverse is checked in AIR, so this is not a host-selected branch.
    let is_chip_action = matches!(
        w.kind,
        CanonicalTransitionKind::Check
            | CanonicalTransitionKind::Call
            | CanonicalTransitionKind::Raise
            | CanonicalTransitionKind::Bet
    );
    let post_stack_sum = u64_limbs(after.map_or(0, |seat| seat.stack))
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    let post_all_in = is_chip_action
        && after.map_or(false, |seat| {
            seat.status == crate::texas_canonical::CanonicalSeatStatus::AllIn
        });
    out.push(M31::from(u32::from(post_all_in)));
    out.push(M31::from(if is_chip_action {
        post_stack_sum as u32
    } else {
        0
    }));
    out.push(if is_chip_action && !post_all_in {
        M31::from(post_stack_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    let pre_stack_sum = u64_limbs(before_seat.stack)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(M31::from(if is_betting_action(w.kind) {
        pre_stack_sum as u32
    } else {
        0
    }));
    out.push(if is_betting_action(w.kind) {
        M31::from(pre_stack_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    // The complete fixed-width acted-mask is decomposed on every row.  For
    // betting actions a one-hot selected-seat vector proves that the chosen
    // seat's `acted` projection matches that mask.  Check/Call/Fold then use
    // the delta bits below to prove the VM's exact one-bit update.
    let is_betting = is_betting_action(w.kind);
    let seat_selectors: [M31; MAX_CANONICAL_SEATS] = std::array::from_fn(|index| {
        M31::from(u32::from(is_betting && usize::from(w.action.seat) == index))
    });
    let pre_acted_bits = mask_bits(w.pre.acted_mask);
    let post_acted_bits = mask_bits(w.post.acted_mask);
    let acted_deltas: [M31; MAX_CANONICAL_SEATS] = std::array::from_fn(|index| {
        M31::from(u32::from(
            is_betting
                && usize::from(w.action.seat) == index
                && pre_acted_bits[index] == M31::from(0u32),
        ))
    });
    out.extend(seat_selectors);
    out.extend(pre_acted_bits);
    out.extend(post_acted_bits);
    out.extend(acted_deltas);
    // TableVault is a distinct custody bucket in the VM.  It changes for
    // funding/join deposits and leave/kick refunds.
    let funding = is_funding_action(w.kind);
    let is_join = w.kind == CanonicalTransitionKind::JoinTable;
    let is_leave = w.kind == CanonicalTransitionKind::LeaveTable;
    let is_kick = matches!(
        w.kind,
        CanonicalTransitionKind::KickPlayer | CanonicalTransitionKind::RevealTimeoutKick
    );
    let is_shuffle_timeout = w.kind == CanonicalTransitionKind::AdvanceDeadline && w.action.flag;
    let is_reconstruct_timeout = w.kind == CanonicalTransitionKind::ReconstructTimeoutReset;
    let is_reveal_timeout = w.kind == CanonicalTransitionKind::RevealTimeoutReset;
    let is_timeout_reset = is_reconstruct_timeout || is_reveal_timeout;
    let is_reveal_reconstruct = w.kind == CanonicalTransitionKind::RevealTimeoutReconstruct;
    let kick_refund = before_seat.stack.saturating_add(before_seat.pending_addon);
    let shuffle_refund = kick_refund;
    out.extend(u64_limbs(w.pre.chip_pool));
    out.extend(u64_limbs(w.post.chip_pool));
    out.extend(if funding {
        add_carries(w.pre.chip_pool, w.action.amount)
    } else if is_join {
        add_carries(w.pre.chip_pool, w.action.amount)
    } else if is_leave || is_kick {
        add_carries(w.post.chip_pool, kick_refund)
    } else if is_shuffle_timeout || is_timeout_reset {
        add_carries(w.post.chip_pool, shuffle_refund)
    } else if is_reveal_reconstruct || w.kind == CanonicalTransitionKind::RevealTimeoutAward {
        add_carries(w.post.chip_pool, kick_refund)
    } else {
        [M31::from(0u32); 3]
    });
    out.extend(if w.kind == CanonicalTransitionKind::Addon {
        add_carries(before_seat.pending_addon, w.action.amount)
    } else if is_kick {
        add_carries(w.pre.pot, before_seat.bet)
    } else if is_shuffle_timeout {
        add_carries(w.pre.pot, before_seat.bet)
    } else if is_reveal_reconstruct {
        add_carries(w.pre.pot, before_seat.bet)
    } else {
        [M31::from(0u32); 3]
    });
    out.extend(if w.kind == CanonicalTransitionKind::Rebuy {
        add_carries(before_seat.stack, w.action.amount)
    } else if is_leave || is_kick {
        add_carries(before_seat.stack, before_seat.pending_addon)
    } else if is_shuffle_timeout {
        add_carries(before_seat.stack, before_seat.pending_addon)
    } else if is_reveal_reconstruct || w.kind == CanonicalTransitionKind::RevealTimeoutAward {
        add_carries(before_seat.stack, before_seat.pending_addon)
    } else {
        [M31::from(0u32); 3]
    });
    append_u64_bits(&mut out, w.pre.chip_pool);
    append_u64_bits(&mut out, w.post.chip_pool);
    debug_assert_eq!(out.len(), FULL_BETTING_SEATS_OFFSET);
    // The selected-seat projection above is sufficient for the first betting
    // arithmetic components, but it cannot prove the VM's reset of other
    // players' acted flags. Carry every mutable betting field for every seat
    // here. The root hash is still a separate follow-up component; these
    // columns remove the host's ability to choose an unobserved seat image for
    // the mid-round AIR relation.
    for image in [&w.pre, &w.post] {
        for seat in &image.seats {
            out.extend(status_one_hot(seat.status));
        }
        for seat in &image.seats {
            out.extend(u64_limbs(seat.stack));
        }
        for seat in &image.seats {
            out.extend(u64_limbs(seat.bet));
        }
        for seat in &image.seats {
            out.extend(u64_limbs(seat.total_bet));
        }
        for seat in &image.seats {
            out.extend(u64_limbs(seat.pending_addon));
        }
        for seat in &image.seats {
            out.extend(u32_limbs(seat.time_bank_ms));
        }
    }
    let is_raise = w.kind == CanonicalTransitionKind::Raise;
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            is_raise && usize::from(w.action.seat) == index,
        )));
    }
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            is_raise && w.pre.seats[index].status == CanonicalSeatStatus::Active,
        )));
    }
    debug_assert_eq!(out.len(), NEXT_TURN_ADVICE_OFFSET);
    let is_force_fold = w.kind == CanonicalTransitionKind::ForceFold;
    let uses_turn_advance = is_betting || is_force_fold;
    let no_next_turn =
        uses_turn_advance && w.post.current_turn == crate::texas_canonical::NO_CANONICAL_SEAT;
    out.push(M31::from(u32::from(no_next_turn)));
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            uses_turn_advance && usize::from(w.post.current_turn) == index,
        )));
    }
    for from in 0..MAX_CANONICAL_SEATS {
        for to in 0..MAX_CANONICAL_SEATS {
            out.push(M31::from(u32::from(
                uses_turn_advance
                    && usize::from(w.action.seat) == from
                    && usize::from(w.post.current_turn) == to,
            )));
        }
    }
    debug_assert_eq!(out.len(), FUNDING_SEAT_SELECTOR_OFFSET);
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            funding && usize::from(w.action.seat) == index,
        )));
    }
    debug_assert_eq!(out.len(), ROUND_COLLECT_CARRIES_OFFSET);
    let is_round_advance = w.kind == CanonicalTransitionKind::AdvanceRound;
    let is_end_without_showdown = w.kind == CanonicalTransitionKind::EndWithoutShowdown;
    out.extend(if is_round_advance || is_end_without_showdown {
        round_collect_carries(w.pre.pot, &w.pre.seats)
    } else {
        [M31::from(0u32); 3]
    });
    for carry in if is_round_advance || is_end_without_showdown {
        round_collect_carries(w.pre.pot, &w.pre.seats)
    } else {
        [M31::from(0u32); 3]
    } {
        for bit in 0..4 {
            out.push(M31::from(u32::from((carry.0 >> bit) & 1)));
        }
    }
    debug_assert_eq!(out.len(), ROUND_COLLECT_BET_BITS_OFFSET);
    for seat in &w.pre.seats {
        for limb in u64_limbs(if is_round_advance || is_end_without_showdown {
            seat.bet
        } else {
            0
        }) {
            out.extend(u16_bits(limb.0 as u16));
        }
    }
    debug_assert_eq!(out.len(), ROUND_COMPLETE_ACTIVE_OFFSET);
    let completed_betting =
        is_betting && w.post.current_turn == crate::texas_canonical::NO_CANONICAL_SEAT;
    for seat in &w.post.seats {
        out.push(M31::from(u32::from(
            completed_betting && seat.status == CanonicalSeatStatus::Active,
        )));
    }
    debug_assert_eq!(out.len(), ROUND_ADVANCE_OPENING_OFFSET);
    let opening = if is_round_advance {
        w.round_advance.clone()
    } else {
        Default::default()
    };
    out.extend([
        M31::from(u32::from(opening.pre_cards_dealt)),
        M31::from(u32::from(opening.post_cards_dealt)),
        M31::from(u32::from(opening.pre_board_len)),
        M31::from(u32::from(opening.post_board_len)),
        M31::from(u32::from(opening.pre_second_board_len)),
        M31::from(u32::from(opening.post_second_board_len)),
        M31::from(u32::from(opening.run_it_twice)),
        M31::from(u32::from(opening.reveal_purpose)),
        M31::from(u32::from(opening.assignment_count)),
    ]);
    for assignment in opening.assignments {
        out.extend([
            M31::from(u32::from(assignment.present)),
            M31::from(u32::from(assignment.encrypted_card_index)),
            M31::from(u32::from(assignment.runout_index)),
            M31::from(u32::from(assignment.board_position)),
            M31::from(u32::from(assignment.pending_mask)),
            M31::from(u32::from(assignment.submitted_mask)),
        ]);
    }
    debug_assert_eq!(out.len(), ROUND_ADVANCE_SCHEDULE_SELECTOR_OFFSET);
    // (preflop, flop, turn) × (single, RIT), matching the fixed table in
    // `CanonicalAir::evaluate`.
    let schedule = match (w.pre.street, opening.run_it_twice) {
        (1, false) => 0,
        (1, true) => 1,
        (2, false) => 2,
        (2, true) => 3,
        (3, false) => 4,
        (3, true) => 5,
        // 摊牌窗口 advance（river 轮收注 → ShowdownOwner 窗口）。
        (4, false) => 6,
        _ => usize::MAX,
    };
    for index in 0..7 {
        out.push(M31::from(u32::from(is_round_advance && index == schedule)));
    }
    debug_assert_eq!(out.len(), ROUND_ADVANCE_CARD_CURSOR_RANGE_OFFSET);
    for cards_dealt in [opening.pre_cards_dealt, opening.post_cards_dealt] {
        let cards_dealt = if is_round_advance { cards_dealt } else { 0 };
        let remaining = if is_round_advance {
            // The range/equality constraints below reject a cursor beyond the
            // deck.  Keep advice generation total so an invalid witness reaches
            // those constraints instead of being rejected by the host.
            52u8.saturating_sub(cards_dealt)
        } else {
            0
        };
        let mut carry = 0u8;
        for bit in 0..6 {
            out.push(M31::from(u32::from((cards_dealt >> bit) & 1)));
        }
        for bit in 0..6 {
            out.push(M31::from(u32::from((remaining >> bit) & 1)));
        }
        for bit in 0..6 {
            let sum = ((cards_dealt >> bit) & 1) + ((remaining >> bit) & 1) + carry;
            carry = sum >> 1;
            out.push(M31::from(u32::from(carry)));
        }
    }
    // Rules and governance are immutable across every table transition.  They
    // were formerly checked only by the native canonical validator; carrying
    // both pre/post encodings here makes that invariant part of the STARK.
    for commitment in [
        w.pre.rules_commitment,
        w.post.rules_commitment,
        w.pre.governance_commitment,
        w.post.governance_commitment,
    ] {
        out.extend(bytes16(&commitment));
    }
    debug_assert_eq!(out.len(), DEADLINE_IMAGE_OFFSET);
    out.extend(u64_limbs(w.pre.deadline_ms));
    out.extend(u64_limbs(w.post.deadline_ms));
    let post_deadline_sum = u64_limbs(w.post.deadline_ms)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(
        if w.kind != CanonicalTransitionKind::StartHand || post_deadline_sum == 0 {
            M31::from(0u32)
        } else {
            M31::from(post_deadline_sum as u32).inverse()
        },
    );
    let is_advance_deadline = w.kind == CanonicalTransitionKind::AdvanceDeadline;
    let is_auto_fold = w.kind == CanonicalTransitionKind::AutoFold;
    let deadline_check = is_advance_deadline
        || is_auto_fold
        || is_timeout_reset
        || w.kind == CanonicalTransitionKind::RevealTimeoutKick
        || w.kind == CanonicalTransitionKind::RevealTimeoutReconstruct
        || w.kind == CanonicalTransitionKind::RevealTimeoutAward
        || w.kind == CanonicalTransitionKind::RevealTimeoutRakedAward;
    let advance_deadline_difference = if deadline_check {
        // A checked limb addition in the AIR proves `height >= deadline`.
        // Saturation is only an advice fallback for an invalid witness; it
        // cannot satisfy that addition when the deadline is early.
        w.deadline_height.saturating_sub(w.pre.deadline_ms)
    } else {
        0
    };
    out.extend(u64_limbs(advance_deadline_difference));
    out.extend(if deadline_check {
        add_carries(w.pre.deadline_ms, advance_deadline_difference)
    } else {
        [M31::from(0u32); 3]
    });
    for value in [
        if deadline_check { w.deadline_height } else { 0 },
        if deadline_check { w.pre.deadline_ms } else { 0 },
        advance_deadline_difference,
    ] {
        append_u64_bits(&mut out, value);
    }
    let pre_deadline_sum = u64_limbs(w.pre.deadline_ms)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(if deadline_check && pre_deadline_sum != 0 {
        M31::from(pre_deadline_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    out.push(if deadline_check && w.pre.phase as u8 != 0 {
        M31::from(u32::from(w.pre.phase as u8)).inverse()
    } else {
        M31::from(0u32)
    });
    debug_assert_eq!(out.len(), LEAVE_AFTER_HAND_MASK_BITS_OFFSET);
    // Like the acted mask, the leave-after-hand mask is a canonical nine-bit
    // value.  Its bits make SetLeaveAfterHand an exact bit transition in the
    // AIR rather than a host-side u16 operation.
    out.extend(mask_bits(w.pre.leave_after_hand_mask));
    out.extend(mask_bits(w.post.leave_after_hand_mask));
    debug_assert_eq!(out.len(), PROTOCOL_PENDING_MASK_BITS_OFFSET);
    out.extend(mask_bits(w.pre.protocol_pending_mask));
    out.extend(mask_bits(w.post.protocol_pending_mask));
    let protocol_submit = matches!(
        w.kind,
        CanonicalTransitionKind::SubmitShuffle
            | CanonicalTransitionKind::SubmitReveal
            | CanonicalTransitionKind::SubmitReconstruct
    );
    let shuffle_timeout = w.kind == CanonicalTransitionKind::AdvanceDeadline && w.action.flag;
    let post_pending_count = w.post.protocol_pending_mask.count_ones();
    let reconstruct_completion =
        w.protocol_completion.kind == CanonicalProtocolCompletionKind::Reconstruct;
    let shuffle_completion = w.protocol_completion.kind == CanonicalProtocolCompletionKind::Shuffle;
    out.push(
        // 完成行（reconstruct/shuffle）的 post pending 由 completion 约束
        // 精确锚定，AIR 将 inverse 列归零（不允许自由建议）；生成器必须
        // 同步排除两类完成行，否则 shuffle 完成行与 AIR 恒矛盾。
        // 2026-09-10 整手牌性能扫描中发现（原先只排除 reconstruct）。
        if protocol_submit
            && !reconstruct_completion
            && !shuffle_completion
            && post_pending_count != 0
        {
            M31::from(post_pending_count).inverse()
        } else if shuffle_timeout && post_pending_count > 1 {
            let product = post_pending_count * (post_pending_count - 1);
            M31::from(product).inverse()
        } else if w.kind == CanonicalTransitionKind::RevealTimeoutKick && post_pending_count != 0 {
            M31::from(post_pending_count).inverse()
        } else {
            M31::from(0u32)
        },
    );
    debug_assert_eq!(out.len(), TRANSITION_SEAT_SELECTOR_OFFSET);
    let requires_seat = w.kind.requires_seat();
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            requires_seat && usize::from(w.action.seat) == index,
        )));
    }
    // These commitments are opaque to the current transition relation, but
    // they are state fields, not host metadata.  Carry them in the trace so
    // ordinary lifecycle, betting, and funding operations cannot silently
    // alter their Borsh endpoint projection.  Crypto/round transitions keep
    // their own dedicated semantics and are intentionally not constrained by
    // this generic preservation gate.
    debug_assert_eq!(out.len(), OPAQUE_COMMITMENTS_OFFSET);
    for commitment in [
        w.pre.board_cards_commitment,
        w.pre.deck_commitment,
        w.pre.reveal_commitment,
        w.pre.reconstruction_commitment,
        w.pre.run_it_twice_commitment,
        w.post.board_cards_commitment,
        w.post.deck_commitment,
        w.post.reveal_commitment,
        w.post.reconstruction_commitment,
        w.post.run_it_twice_commitment,
    ] {
        out.extend(bytes16(&commitment));
    }
    debug_assert_eq!(out.len(), STATE_IMAGE_METADATA_OFFSET);
    for value in [
        u32::from(w.pre.abi_version),
        u32::from(w.pre.button),
        u32::from(w.pre.max_players),
        u32::from(w.pre.last_bb_seat),
        u32::from(w.post.abi_version),
        u32::from(w.post.button),
        u32::from(w.post.max_players),
        u32::from(w.post.last_bb_seat),
    ] {
        out.push(M31::from(value));
    }
    debug_assert_eq!(out.len(), SEAT_COMMITMENTS_OFFSET);
    for state in [&w.pre, &w.post] {
        for seat in &state.seats {
            for commitment in [
                seat.identity_commitment,
                seat.key_commitment,
                seat.hole_cards_commitment,
            ] {
                out.extend(bytes16(&commitment));
            }
        }
    }
    debug_assert_eq!(out.len(), PROOF_COMMITMENT_BITS_OFFSET);
    for limb in bytes16(&w.action.proof_commitment) {
        for bit in u16_bits(if is_crypto_action(w.kind) {
            limb.0 as u16
        } else {
            0
        }) {
            out.push(bit);
        }
    }
    let advance_deadline = w.kind == CanonicalTransitionKind::AdvanceDeadline;
    let deadline_extension = advance_deadline && !w.action.flag;
    let timeout = u64::from(w.pre.betting_timeout_ms);
    let selected_time_bank = if deadline_extension {
        w.pre
            .seats
            .get(usize::from(w.action.seat))
            .map_or(0, |seat| u64::from(seat.time_bank_ms))
    } else {
        0
    };
    let consume_all = deadline_extension && selected_time_bank <= timeout;
    let slack = if consume_all {
        timeout - selected_time_bank
    } else {
        0
    };
    let excess = if deadline_extension && !consume_all {
        selected_time_bank - timeout
    } else {
        0
    };
    out.push(M31::from(u32::from(consume_all)));
    out.extend(u32_limbs(
        u32::try_from(slack).expect("time-bank slack fits in u32"),
    ));
    out.extend(u32_limbs(
        u32::try_from(excess).expect("time-bank excess fits in u32"),
    ));
    for value in [slack, excess] {
        for limb in u32_limbs(u32::try_from(value).expect("time-bank witness fits in u32")) {
            out.extend(u16_bits(limb.0 as u16));
        }
    }
    out.extend(if deadline_extension {
        [
            add_carries(selected_time_bank, slack)[0],
            add_carries(timeout, excess)[0],
            add_carries(
                w.post
                    .seats
                    .get(usize::from(w.action.seat))
                    .map_or(0, |seat| u64::from(seat.time_bank_ms)),
                w.action.amount,
            )[0],
        ]
    } else {
        [M31::from(0u32); 3]
    });
    out.extend(if deadline_extension {
        add_carries(w.pre.deadline_ms, w.action.amount)
    } else if is_shuffle_timeout {
        add_carries(w.deadline_height, u64::from(w.pre.shuffle_timeout_ms))
    } else if is_auto_fold {
        add_carries(w.deadline_height, u64::from(w.pre.betting_timeout_ms))
    } else if w.kind == CanonicalTransitionKind::RevealTimeoutReconstruct {
        add_carries(w.deadline_height, u64::from(w.pre.reconstruct_timeout_ms))
    } else {
        [M31::from(0u32); 3]
    });
    // The raked award arms the deadline from the height exactly like the
    // reconstruct terminal; its deadline relation reuses these carries.
    // These gates keep selector * consume-all out of the carry boolean
    // relations, so the whole AIR remains cubic without enlarging the PCS.
    out.push(M31::from(u32::from(consume_all)));
    out.push(M31::from(u32::from(deadline_extension && !consume_all)));
    let is_start = w.kind == CanonicalTransitionKind::StartHand;
    // Count post-state participants: StartHand promotes waiting-for-big-blind
    // seats into the new hand, so the >= 2 gate uses the post image.
    let active_count = w
        .post
        .seats
        .iter()
        .filter(|seat| {
            matches!(
                seat.status,
                CanonicalSeatStatus::Active
                    | CanonicalSeatStatus::Folded
                    | CanonicalSeatStatus::AllIn
            )
        })
        .count() as u32;
    let start_active_product = active_count * active_count.saturating_sub(1);
    out.push(if is_start {
        M31::from(start_active_product)
    } else {
        M31::from(0u32)
    });
    out.push(if is_start && start_active_product != 0 {
        M31::from(start_active_product).inverse()
    } else {
        M31::from(0u32)
    });
    // Keep malformed images total while they are being handed to the AIR.
    // The AIR constrains the original metadata and rejects an invalid capacity;
    // this clamp only prevents host-side modulo/index panics before that check.
    let max_players = usize::from(w.pre.max_players.clamp(1, MAX_CANONICAL_SEATS as u8));
    let start_button = usize::from(w.pre.button).min(max_players.saturating_sub(1));
    // Dead button: the successor seat is unconditionally `button + 1` modulo
    // capacity — the landing seat may be empty (dead button), no skipping.
    let start_next = (start_button + 1) % max_players;
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(is_start && index == start_next)));
    }
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(index == usize::from(w.pre.button))));
    }
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            is_start && index == start_button && (start_button + 1) % max_players == 0,
        )));
    }
    for index in 0..MAX_CANONICAL_SEATS {
        let wrap = is_start && index == start_button && (start_button + 1) % max_players == 0;
        out.push(M31::from(u32::from(wrap)) * M31::from(max_players as u32));
    }
    // start_next_seat[i] = 座位 i 的后继值 (i+1) % capacity（非 start 行为 0）。
    for index in 0..MAX_CANONICAL_SEATS {
        let value = if is_start {
            ((index + 1) % max_players) as u32
        } else {
            0
        };
        out.push(M31::from(value));
    }
    let zero_digest = [0u8; 32];
    for digest in [
        next_pre
            .map(CanonicalStateImage::commitment)
            .unwrap_or(zero_digest),
        next_pre
            .map(|state| state.state_root)
            .unwrap_or(zero_digest),
        next_pre
            .map(|state| state.lifecycle_root)
            .unwrap_or(zero_digest),
        next_pre
            .map(|state| state.overlay_root)
            .unwrap_or(zero_digest),
        next_pre
            .map(|state| state.settlement_commitment)
            .unwrap_or(zero_digest),
        next_pre
            .map(|state| state.custody_commitment)
            .unwrap_or(zero_digest),
    ] {
        out.extend(bytes16(&digest));
    }
    out.extend(bytes16(&w.transition_commitment));
    out.extend(bytes16(&w.nullifier));
    let transition_sum = bytes16(&w.transition_commitment)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    let nullifier_sum = bytes16(&w.nullifier)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    let actor_sum = bytes16(&w.actor)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(if transition_sum == 0 {
        M31::from(0u32)
    } else {
        M31::from(transition_sum as u32).inverse()
    });
    out.push(if nullifier_sum == 0 {
        M31::from(0u32)
    } else {
        M31::from(nullifier_sum as u32).inverse()
    });
    out.push(if actor_sum == 0 {
        M31::from(0u32)
    } else {
        M31::from(actor_sum as u32).inverse()
    });
    debug_assert_eq!(out.len(), TIMEOUT_CONFIG_OFFSET);
    for state in [&w.pre, &w.post] {
        for timeout in [
            state.shuffle_timeout_ms,
            state.reveal_timeout_ms,
            state.betting_timeout_ms,
            state.reconstruct_timeout_ms,
            state.showdown_display_ms,
        ] {
            out.extend(u32_limbs(timeout));
        }
    }
    debug_assert_eq!(out.len(), TIMEOUT_CONFIG_RANGE_BITS_OFFSET);
    for timeout in [
        w.pre.shuffle_timeout_ms,
        w.pre.reveal_timeout_ms,
        w.pre.betting_timeout_ms,
        w.pre.reconstruct_timeout_ms,
        w.pre.showdown_display_ms,
    ] {
        for limb in u32_limbs(timeout) {
            out.extend(u16_bits(limb.0 as u16));
        }
    }
    debug_assert_eq!(out.len(), PROTOCOL_COMPLETION_OPENING_OFFSET);
    let completion = &w.protocol_completion;
    // 完成指示布尔（0 = 非-final 提交，1 = 完成 opening 生效）。具体完成
    // 类型由行的一热 kind 选择器区分（SubmitShuffle/SubmitReveal/
    // SubmitReconstruct）——单元保持 {0,1} 使全部既有布尔门无需重排。
    out.push(M31::from(u32::from(
        completion.kind != CanonicalProtocolCompletionKind::None,
    )));
    out.extend(u64_limbs(completion.completion_timestamp_ms));
    out.push(M31::from(u32::from(completion.pre_cards_dealt)));
    out.push(M31::from(u32::from(completion.post_cards_dealt)));
    for commitment in [
        completion.suspended_reveal_commitment,
        completion.pre_deck_commitment,
        completion.post_deck_commitment,
        completion.pre_reconstruction_commitment,
        completion.post_reconstruction_commitment,
    ] {
        out.extend(bytes16(&commitment));
    }
    out.push(M31::from(u32::from(completion.post_shuffle_pending_mask)));
    out.push(M31::from(u32::from(completion.post_shuffle_completed_mask)));
    debug_assert_eq!(out.len(), PROTOCOL_COMPLETION_TIMESTAMP_BITS_OFFSET);
    // 位分解仅服务 reconstruct 完成行的 range16 检查；AIR 对其余行（含
    // shuffle 完成行）强制清零，生成器必须同步写 0，否则 shuffle 完成
    // 行的 bits(时间戳) 与 AIR 归零约束恒矛盾（2026-09-10 整手牌性能
    // 扫描中发现）。
    append_u64_bits(
        &mut out,
        if reconstruct_completion {
            completion.completion_timestamp_ms
        } else {
            0
        },
    );
    let timestamp_sum = u64_limbs(completion.completion_timestamp_ms)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    let is_reconstruct_completion = completion.kind == CanonicalProtocolCompletionKind::Reconstruct;
    let is_shuffle_completion = completion.kind == CanonicalProtocolCompletionKind::Shuffle;
    let is_reveal_completion = completion.kind == CanonicalProtocolCompletionKind::Reveal;
    // #22②扩展：street/showdown 完成行同样携带时间戳非零逆元与 deadline
    // 进位（street 重挂 betting_timeout，showdown 重挂 showdown_display）。
    let is_street_completion = completion.kind == CanonicalProtocolCompletionKind::RevealStreet;
    let is_showdown_completion = completion.kind == CanonicalProtocolCompletionKind::Showdown;
    out.push(
        if (is_reconstruct_completion
            || is_shuffle_completion
            || is_reveal_completion
            || is_street_completion
            || is_showdown_completion)
            && timestamp_sum != 0
        {
            M31::from(timestamp_sum as u32).inverse()
        } else {
            M31::from(0u32)
        },
    );
    // deadline 重挂的进位：reconstruct 用 shuffle_timeout，shuffle completion
    // 用 reveal_timeout（start_preflop_reveal_phase 重挂 reveal deadline），
    // reveal completion 用 betting_timeout（start_betting_round 重挂下注
    // deadline），street completion 同 betting_timeout，showdown completion
    // 用 showdown_display。
    out.extend(if is_reconstruct_completion {
        add_carries(
            completion.completion_timestamp_ms,
            u64::from(w.pre.shuffle_timeout_ms),
        )
    } else if is_shuffle_completion {
        add_carries(
            completion.completion_timestamp_ms,
            u64::from(w.pre.reveal_timeout_ms),
        )
    } else if is_reveal_completion || is_street_completion {
        add_carries(
            completion.completion_timestamp_ms,
            u64::from(w.pre.betting_timeout_ms),
        )
    } else if is_showdown_completion {
        add_carries(
            completion.completion_timestamp_ms,
            u64::from(w.pre.showdown_display_ms),
        )
    } else {
        [M31::from(0u32); 3]
    });
    let cursor = if is_reconstruct_completion {
        completion.pre_cards_dealt
    } else {
        0
    };
    let remaining = if is_reconstruct_completion {
        52u8.saturating_sub(cursor)
    } else {
        0
    };
    let mut carry = 0u8;
    for bit in 0..6 {
        out.push(M31::from(u32::from((cursor >> bit) & 1)));
    }
    for bit in 0..6 {
        out.push(M31::from(u32::from((remaining >> bit) & 1)));
    }
    for bit in 0..6 {
        let sum = ((cursor >> bit) & 1) + ((remaining >> bit) & 1) + carry;
        carry = sum >> 1;
        out.push(M31::from(u32::from(carry)));
    }
    let post_deck_limbs = bytes16(&w.post.deck_commitment);
    let pre_deck_limbs = bytes16(&w.pre.deck_commitment);
    let post_deck_sum = post_deck_limbs
        .iter()
        .fold(M31::from(0u32), |sum, limb| sum + *limb);
    let deck_diff_square_sum = post_deck_limbs.iter().zip(pre_deck_limbs.iter()).fold(
        M31::from(0u32),
        |sum, (post, pre)| {
            let difference = *post - *pre;
            sum + difference * difference
        },
    );
    out.push(M31::from(u32::from(is_shuffle_timeout)));
    let post_pending_count = w.post.protocol_pending_mask.count_ones();
    out.push(if is_advance_deadline {
        M31::from(post_pending_count * post_pending_count.saturating_sub(1))
    } else {
        M31::from(0u32)
    });
    out.push(if is_advance_deadline {
        deck_diff_square_sum
    } else {
        M31::from(0u32)
    });
    out.push(if is_advance_deadline {
        post_deck_sum * deck_diff_square_sum
    } else {
        M31::from(0u32)
    });
    out.push(
        if is_shuffle_timeout
            && post_deck_sum != M31::from(0u32)
            && deck_diff_square_sum != M31::from(0u32)
        {
            (post_deck_sum * deck_diff_square_sum).inverse()
        } else {
            M31::from(0u32)
        },
    );
    let is_reveal_reconstruct = w.kind == CanonicalTransitionKind::RevealTimeoutReconstruct;
    let street_offset = if is_reveal_reconstruct {
        u32::from(w.pre.street).saturating_sub(2)
    } else {
        0
    };
    out.push(M31::from(street_offset & 1));
    out.push(M31::from((street_offset >> 1) & 1));
    let post_reconstruction_limbs = bytes16(&w.post.reconstruction_commitment);
    let pre_reconstruction_limbs = bytes16(&w.pre.reconstruction_commitment);
    let post_reconstruction_sum = post_reconstruction_limbs
        .iter()
        .fold(M31::from(0u32), |sum, limb| sum + *limb);
    let reconstruction_diff_square_sum = post_reconstruction_limbs
        .iter()
        .zip(pre_reconstruction_limbs.iter())
        .fold(M31::from(0u32), |sum, (post, pre)| {
            let difference = *post - *pre;
            sum + difference * difference
        });
    out.push(if is_reveal_reconstruct {
        reconstruction_diff_square_sum
    } else {
        M31::from(0u32)
    });
    let reconstruction_change_product = post_reconstruction_sum * reconstruction_diff_square_sum;
    out.push(if is_reveal_reconstruct {
        reconstruction_change_product
    } else {
        M31::from(0u32)
    });
    out.push(
        if is_reveal_reconstruct
            && post_reconstruction_sum != M31::from(0u32)
            && reconstruction_diff_square_sum != M31::from(0u32)
        {
            reconstruction_change_product.inverse()
        } else {
            M31::from(0u32)
        },
    );
    let live_count = w
        .post
        .seats
        .iter()
        .filter(|seat| {
            matches!(
                seat.status,
                crate::texas_canonical::CanonicalSeatStatus::Active
                    | crate::texas_canonical::CanonicalSeatStatus::AllIn
            )
        })
        .count();
    out.push(if is_reveal_reconstruct {
        M31::from((live_count * live_count.saturating_sub(1)) as u32)
    } else {
        M31::from(0u32)
    });
    out.push(if is_reveal_reconstruct && live_count >= 2 {
        M31::from((live_count * live_count.saturating_sub(1)) as u32).inverse()
    } else {
        M31::from(0u32)
    });
    let reveal_street_row = matches!(
        w.kind,
        CanonicalTransitionKind::RevealTimeoutKick
            | CanonicalTransitionKind::RevealTimeoutAward
            | CanonicalTransitionKind::RevealTimeoutRakedAward
    );
    let kick_street_offset = if reveal_street_row {
        u32::from(w.pre.street).saturating_sub(1)
    } else {
        0
    };
    out.push(M31::from(kick_street_offset & 1));
    out.push(M31::from((kick_street_offset >> 1) & 1));
    out.push(M31::from((kick_street_offset >> 2) & 1));
    // Sole-survivor award advice: the winner credit is the unique live seat
    // other than the kicked participant, and the inverse proves the awarded
    // pot limb sum is non-zero.
    let is_reveal_award = matches!(
        w.kind,
        CanonicalTransitionKind::RevealTimeoutAward
            | CanonicalTransitionKind::RevealTimeoutRakedAward
    );
    for index in 0..MAX_CANONICAL_SEATS {
        let winner = is_reveal_award
            && index != usize::from(w.action.seat)
            && matches!(
                w.pre.seats[index].status,
                crate::texas_canonical::CanonicalSeatStatus::Active
                    | crate::texas_canonical::CanonicalSeatStatus::AllIn
            );
        out.push(M31::from(u32::from(winner)));
    }
    let pre_pot_sum = u64_limbs(w.pre.pot)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(if is_reveal_award && pre_pot_sum != 0 {
        M31::from(pre_pot_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    // Raked sole-survivor award advice.  The config columns copy the
    // authenticated opening; every limb below is a canonical 16-bit value so
    // the AIR's weighted identities are exact over the integers.
    let is_raked = w.kind == CanonicalTransitionKind::RevealTimeoutRakedAward;
    let opening = w.rake_opening;
    out.push(M31::from(u32::from(if is_raked {
        opening.rake_mode
    } else {
        0
    })));
    out.push(M31::from(u32::from(if is_raked {
        opening.rake_bps
    } else {
        0
    })));
    for limb in u64_limbs(if is_raked { opening.rake_cap } else { 0 }) {
        out.push(limb);
    }
    let rake = if is_raked {
        crate::canonical_rake_opening::canonical_settlement_rake(w.pre.pot, &opening)
    } else {
        0
    };
    let raw = if is_raked {
        u128::from(w.pre.pot) * u128::from(opening.rake_bps) / 10_000
    } else {
        0
    };
    let remainder = if is_raked {
        (u128::from(w.pre.pot) * u128::from(opening.rake_bps) % 10_000) as u64
    } else {
        0
    };
    let product = if is_raked {
        u128::from(w.pre.pot) * u128::from(opening.rake_bps)
    } else {
        0
    };
    let scaled = u128::from(raw) * 10_000;
    let limb_of = |value: u128| -> [M31; 4] {
        [
            M31::from((value & 0xffff) as u32),
            M31::from(((value >> 16) & 0xffff) as u32),
            M31::from(((value >> 32) & 0xffff) as u32),
            M31::from(((value >> 48) & 0xffff) as u32),
        ]
    };
    let byte_pair = |value: u64| -> [M31; 2] {
        [
            M31::from((value & 0xff) as u32),
            M31::from(((value >> 8) & 0xff) as u32),
        ]
    };
    for value in [w.pre.pot & 0xffff, (w.pre.pot >> 16) & 0xffff] {
        out.extend(byte_pair(value));
    }
    out.extend(limb_of(product));
    for limb in 0..4 {
        out.extend(byte_pair(((product >> (16 * limb)) & 0xffff) as u64));
    }
    out.extend(limb_of(raw));
    for limb in 0..4 {
        out.extend(byte_pair(((raw >> (16 * limb)) & 0xffff) as u64));
    }
    out.extend(limb_of(scaled));
    for limb in 0..4 {
        out.extend(byte_pair(((scaled >> (16 * limb)) & 0xffff) as u64));
    }
    out.push(M31::from(remainder as u32));
    out.extend(byte_pair(remainder));
    out.extend(byte_pair(9_999u64 - u64::from(remainder)));
    let scaled_carries = if is_raked {
        add_carries(scaled as u64, remainder)
    } else {
        [M31::from(0u32); 3]
    };
    out.extend(scaled_carries);
    // min(raw, cap) borrow chain over `raw + (2^64 - 1 - cap) + 1`: the
    // limb carries out of the wide sum are exactly the AIR's borrow bits
    // and bit 64 of the sum is the `raw >= cap` selector.
    let cap = if is_raked { opening.rake_cap } else { 0 };
    let mut min_carry: u32 = 1;
    let mut min_limbs = [0u64; 4];
    let mut min_borrows = [0u32; 4];
    for limb in 0..4 {
        let raw_limb = ((raw >> (16 * limb)) & 0xffff) as u64;
        let cap_limb = (cap >> (16 * limb)) & 0xffff;
        let complement_limb = 65535u64 - cap_limb;
        let sum = raw_limb + complement_limb + u64::from(min_carry);
        min_limbs[limb] = sum & 0xffff;
        min_borrows[limb] = (sum >> 16) as u32;
        min_carry = min_borrows[limb];
    }
    for limb in min_limbs {
        out.push(M31::from(limb as u32));
    }
    for limb in min_limbs {
        out.extend(byte_pair(limb));
    }
    for borrow in min_borrows {
        out.push(M31::from(borrow));
    }
    out.extend(limb_of(u128::from(rake)));
    for limb in 0..4 {
        out.extend(byte_pair(((rake >> (16 * limb)) & 0xffff) as u64));
    }
    out.extend(limb_of(u128::from(w.pre.pot - rake)));
    for limb in 0..4 {
        out.extend(byte_pair(
            (((w.pre.pot - rake) >> (16 * limb)) & 0xffff) as u64,
        ));
    }
    out.extend(limb_of(u128::from(
        w.post.chip_pool + u64::from(w.action.amount),
    )));
    out.extend(if is_raked {
        add_carries(w.post.chip_pool + w.action.amount, rake)
    } else {
        [M31::from(0u32); 3]
    });
    // Per-seat `owes` advice: a betting seat that already acted but still
    // owes chips below the post current_bet stays actionable (short all-in
    // reopened the water without reopening the raise right, TDA #41).
    let is_betting_row = is_betting_action(w.kind);
    for seat in &w.post.seats {
        let owes = is_betting_row
            && seat.status == CanonicalSeatStatus::Active
            && seat.bet < w.post.current_bet;
        let diff = if owes {
            w.post.current_bet - seat.bet
        } else {
            0
        };
        out.push(M31::from(u32::from(owes)));
        out.extend(u64_limbs(diff));
        // Subtraction borrows of current_bet - bet over 16-bit limbs.
        let borrows = if owes {
            let mut borrow: u32 = 0;
            let mut borrows = [0u32; 3];
            for limb in 0..4 {
                let c = ((w.post.current_bet >> (16 * limb)) & 0xffff) as u32;
                let b = ((seat.bet >> (16 * limb)) & 0xffff) as u32;
                let sub = c as i64 - b as i64 - i64::from(borrow);
                if sub < 0 {
                    borrow = 1;
                } else {
                    borrow = 0;
                }
                if limb < 3 {
                    borrows[limb] = borrow;
                }
            }
            borrows
        } else {
            [0u32; 3]
        };
        for borrow in borrows {
            out.push(M31::from(borrow));
        }
        let limb_sum: u32 = u64_limbs(diff)
            .into_iter()
            .map(|limb| u32::from(limb.0))
            .sum();
        out.push(if owes && limb_sum != 0 {
            M31::from(limb_sum).inverse()
        } else {
            M31::from(0u32)
        });
        // settled = acted && !owes: an acted seat that has matched the water
        // is no longer actionable and can be skipped by the turn scan.
        let settled = is_betting_row && seat.acted && !owes;
        out.push(M31::from(u32::from(settled)));
    }
    // ---- #22② RevealComplete advice ----
    // Gate: SubmitReveal row carrying a completion opening.  Every following
    // column is zero off reveal-completion rows.
    let rc_row = w.kind == CanonicalTransitionKind::SubmitReveal
        && w.protocol_completion.kind == CanonicalProtocolCompletionKind::Reveal;
    out.push(M31::from(u32::from(rc_row)));
    let blind = if rc_row {
        w.blind_opening
    } else {
        crate::canonical_rake_opening::CanonicalBlindOpening::ZERO
    };
    out.extend(u64_limbs(blind.small_blind));
    out.extend(u64_limbs(blind.big_blind));
    let active_seat: [bool; MAX_CANONICAL_SEATS] = core::array::from_fn(|index| {
        w.pre.seats[index].status == CanonicalSeatStatus::Active
    });
    let active_count = active_seat.iter().filter(|value| **value).count() as u32;
    let nonzero_inv = |value: u32| {
        if value != 0 {
            M31::from(value).inverse()
        } else {
            M31::from(0u32)
        }
    };
    // cnt != 0, cnt != 1 (at least two participants), cnt != 2 determinant.
    // Only meaningful (and only emitted) on reveal-completion rows.
    out.push(if rc_row {
        nonzero_inv(active_count)
    } else {
        M31::from(0u32)
    });
    out.push(if rc_row {
        nonzero_inv(active_count.saturating_sub(1))
    } else {
        M31::from(0u32)
    });
    out.push(if rc_row {
        nonzero_inv(active_count.saturating_sub(2))
    } else {
        M31::from(0u32)
    });
    out.push(M31::from(u32::from(rc_row && active_count == 2)));
    // Circular (mod nine) first-Active-after-base scan: rotated activity,
    // "no earlier Active" prefix and the resulting selector.  On a valid
    // reveal-completion image every occupied seat is Active, so this scan
    // coincides with the VM's mod-max_players `find_next_participating_seat`.
    let scan = |base: usize| -> ([bool; 8], [bool; 8], [bool; 8], Option<usize>) {
        let mut rot = [false; 8];
        let mut q = [false; 8];
        let mut f = [false; 8];
        let mut clear = true;
        let mut first: Option<usize> = None;
        for d in 1..=8 {
            rot[d - 1] = active_seat[(base + d) % MAX_CANONICAL_SEATS];
            q[d - 1] = clear;
            f[d - 1] = rot[d - 1] && clear;
            if rot[d - 1] {
                clear = false;
            }
            if first.is_none() && f[d - 1] {
                first = Some((base + d) % MAX_CANONICAL_SEATS);
            }
        }
        (rot, q, f, first)
    };
    let heads_up = active_count == 2;
    // Dead-button rotation base: the previous hand's big blind, falling back
    // to the button while the track is unset (first hand / NO_SEAT sentinel).
    let no_bb_track = w.pre.last_bb_seat == NO_CANONICAL_SEAT;
    let rotation_base = if no_bb_track {
        usize::from(w.pre.button) % MAX_CANONICAL_SEATS
    } else {
        usize::from(w.pre.last_bb_seat) % MAX_CANONICAL_SEATS
    };
    let (rot_button, q_button, f_button, first_after_base) = scan(rotation_base);
    // Big blind: the first participating seat after the rotation base.
    let bb_seat = first_after_base.unwrap_or(rotation_base);
    // Small blind: heads-up — the first Active seat after the big blind (the
    // other participant); non-HU — the rotation-base seat itself, or a dead
    // small blind when that seat is not participating.
    let (rot_sb, q_sb, f_sb, first_after_sb) = scan(bb_seat);
    let sb_seat = if heads_up {
        first_after_sb.unwrap_or(bb_seat)
    } else {
        rotation_base
    };
    let dead_sb = !heads_up
        && (rotation_base == bb_seat || !active_seat[rotation_base]);
    let (rot_bb, q_bb, f_bb, _) = scan(bb_seat);
    // Storage order matches the evaluate-side reads: kind-grouped (all three
    // rotated-activity blocks, then all prefix blocks, then all selector
    // blocks), NOT interleaved per base.
    let mut push_bits = |out: &mut Vec<M31>, values: [&[bool; 8]; 3]| {
        for group in values {
            for value in group {
                out.push(M31::from(u32::from(rc_row && *value)));
            }
        }
    };
    let mut push_onehot = |out: &mut Vec<M31>, seat: usize| {
        for index in 0..MAX_CANONICAL_SEATS {
            out.push(M31::from(u32::from(rc_row && index == seat)));
        }
    };
    // A dead small blind posts nothing: its seat vector is all-zero.
    let push_sb_onehot = |out: &mut Vec<M31>, seat: usize, dead: bool| {
        for index in 0..MAX_CANONICAL_SEATS {
            out.push(M31::from(u32::from(rc_row && !dead && index == seat)));
        }
    };
    push_sb_onehot(&mut out, sb_seat, dead_sb);
    push_onehot(&mut out, bb_seat);
    push_bits(&mut out, [&rot_button, &rot_sb, &rot_bb]);
    push_bits(&mut out, [&q_button, &q_sb, &q_bb]);
    push_bits(&mut out, [&f_button, &f_sb, &f_bb]);
    // Small-blind composition selector: slot 0 marks the dead-small-blind /
    // no-post branch; slots 1..=8 mark the HU first-active-after-BB scan
    // selectors (all zero on non-HU rows — the SB is the rotation base seat
    // itself and is rebuilt from the base one-hot directly).
    out.push(M31::from(u32::from(rc_row && dead_sb)));
    for d in 0..8 {
        let value = heads_up && !dead_sb && f_sb[d];
        out.push(M31::from(u32::from(rc_row && value)));
    }
    // Dead-button rotation base one-hot plus its unset-track flag, the
    // linearized gate*nobb and live-SB indicators, and the small-blind
    // amount inverse.
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            rc_row && index == rotation_base,
        )));
    }
    out.push(M31::from(u32::from(rc_row && no_bb_track)));
    out.push(M31::from(u32::from(rc_row && dead_sb)));
    out.push(M31::from(u32::from(rc_row && no_bb_track)));
    out.push(M31::from(u32::from(rc_row && !heads_up && !dead_sb)));
    // Inverse of the summed small-blind limbs (non-zero iff sb_amount != 0)
    // pinning the live-small-blind side of the dead-SB ⟺ zero-amount pair.
    let sb_amount_sum: u32 = u64_limbs(blind.small_blind)
        .into_iter()
        .map(|limb| u32::from(limb.0))
        .sum();
    out.push(if rc_row && !dead_sb && sb_amount_sum != 0 {
        M31::from(sb_amount_sum).inverse()
    } else {
        M31::from(0u32)
    });
    // Blind-posting arithmetic advice.  `pre = post + posted` for stacks and
    // `post = pre + posted` for total bets, three carry limbs per seat each,
    // stored as two contiguous per-seat blocks.
    for index in 0..MAX_CANONICAL_SEATS {
        let posted = if rc_row && !dead_sb && index == sb_seat {
            blind.small_blind
        } else if rc_row && index == bb_seat {
            blind.big_blind
        } else {
            0
        };
        if rc_row {
            out.extend(add_carries(w.post.seats[index].stack, posted));
        } else {
            out.extend([M31::from(0u32); 3]);
        }
    }
    for index in 0..MAX_CANONICAL_SEATS {
        let posted = if rc_row && !dead_sb && index == sb_seat {
            blind.small_blind
        } else if rc_row && index == bb_seat {
            blind.big_blind
        } else {
            0
        };
        if rc_row {
            out.extend(add_carries(w.pre.seats[index].total_bet, posted));
        } else {
            out.extend([M31::from(0u32); 3]);
        }
    }
    for index in 0..MAX_CANONICAL_SEATS {
        let posts_blind =
            rc_row && ((index == sb_seat && !dead_sb) || index == bb_seat);
        let stack_sum: u32 = u64_limbs(w.post.seats[index].stack)
            .into_iter()
            .map(|limb| u32::from(limb.0))
            .sum();
        out.push(if posts_blind && stack_sum != 0 {
            M31::from(stack_sum).inverse()
        } else {
            M31::from(0u32)
        });
    }
    // 封顶盲注（#22②扩展，2026-09-14）：盲注座 stack 扣到 0 即 VM 的
    // AllIn 翻转——capped 仅在盲注座上可置位；UTG 扫描（rc_f[2]）改用
    // post 可行动集，全员 all-in 时 no_utg = 1 且 post.turn = NO_SEAT。
    for index in 0..MAX_CANONICAL_SEATS {
        let posts_blind =
            rc_row && ((index == sb_seat && !dead_sb) || index == bb_seat);
        let stack_sum: u32 = u64_limbs(w.post.seats[index].stack)
            .into_iter()
            .map(|limb| u32::from(limb.0))
            .sum();
        out.push(M31::from(u32::from(rc_row && posts_blind && stack_sum == 0)));
    }
    {
        let actionable: [bool; MAX_CANONICAL_SEATS] = core::array::from_fn(|index| {
            w.post.seats[index].status == CanonicalSeatStatus::Active
        });
        let mut no_utg = true;
        for d in 0..8 {
            let target = (bb_seat + d + 1) % MAX_CANONICAL_SEATS;
            if rc_row && actionable[target] {
                no_utg = false;
            }
        }
        out.push(M31::from(u32::from(rc_row && no_utg)));
    }
    // ---- #22②扩展（2026-09-15）：street / showdown completion 组 advice ----
    // 家族门 + pre_subtag one-hot（hole=1 / board=2 / showdown=3）把 reveal
    // 完成行划分为 preflop 盲注组（rc_gate）、street 组（rcs_gate）、
    // showdown 组（rcd_gate）；与 evaluate 的读取顺序严格一致。
    let rc_family = w.kind == CanonicalTransitionKind::SubmitReveal
        && matches!(
            w.protocol_completion.kind,
            CanonicalProtocolCompletionKind::Reveal
                | CanonicalProtocolCompletionKind::RevealStreet
                | CanonicalProtocolCompletionKind::Showdown
        );
    let rc_hole =
        rc_family && w.protocol_completion.kind == CanonicalProtocolCompletionKind::Reveal;
    let rc_board =
        rc_family && w.protocol_completion.kind == CanonicalProtocolCompletionKind::RevealStreet;
    let rc_showdown =
        rc_family && w.protocol_completion.kind == CanonicalProtocolCompletionKind::Showdown;
    out.push(M31::from(u32::from(rc_family)));
    out.push(M31::from(u32::from(rc_hole)));
    out.push(M31::from(u32::from(rc_board)));
    out.push(M31::from(u32::from(rc_showdown)));
    out.push(M31::from(u32::from(rc_board)));
    out.push(M31::from(u32::from(rc_showdown)));
    // postflop UTG 扫描（镜像 validator 的位置规则）：单挑（恰好两名参与者
    // 且均未弃牌）以 last_bb_seat 为基座（无轨道时退 button），非单挑以
    // button 为基座；扫描 post-Active 集合，全员 all-in 时 no_turn = 1
    // → post turn = NO_SEAT（VM C5）。
    let empty8: [bool; 8] = [false; 8];
    let (rcs_base_onehot, rcs_rot, rcs_q, rcs_f, rcs_no_turn) = if !rc_board {
        (
            [false; MAX_CANONICAL_SEATS],
            empty8,
            empty8,
            empty8,
            false,
        )
    } else {
        let actionable: [bool; MAX_CANONICAL_SEATS] = core::array::from_fn(|index| {
            w.post.seats[index].status == CanonicalSeatStatus::Active
        });
        let pre_participants = w
            .pre
            .seats
            .iter()
            .filter(|seat| {
                matches!(
                    seat.status,
                    CanonicalSeatStatus::Active
                        | CanonicalSeatStatus::Folded
                        | CanonicalSeatStatus::AllIn
                )
            })
            .count();
        let pre_active = w
            .pre
            .seats
            .iter()
            .filter(|seat| seat.status == CanonicalSeatStatus::Active)
            .count();
        let heads_up = pre_participants == 2 && pre_active == 2;
        let base = if heads_up {
            if w.pre.last_bb_seat != NO_CANONICAL_SEAT {
                usize::from(w.pre.last_bb_seat)
            } else {
                usize::from(w.pre.button)
            }
        } else {
            usize::from(w.pre.button)
        } % MAX_CANONICAL_SEATS;
        let mut rot = [false; 8];
        let mut q = [false; 8];
        let mut f = [false; 8];
        let mut clear = true;
        let mut first: Option<usize> = None;
        for d in 1..=8 {
            rot[d - 1] = actionable[(base + d) % MAX_CANONICAL_SEATS];
            q[d - 1] = clear;
            f[d - 1] = rot[d - 1] && clear;
            if rot[d - 1] {
                clear = false;
            }
            if first.is_none() && f[d - 1] {
                first = Some((base + d) % MAX_CANONICAL_SEATS);
            }
        }
        (
            core::array::from_fn(|index: usize| index == base),
            rot,
            q,
            f,
            first.is_none(),
        )
    };
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(rcs_base_onehot[index])));
    }
    // 存储顺序与 evaluate 读取一致：kind-grouped（rot / q / f 各自整块）。
    for group in [&rcs_rot, &rcs_q, &rcs_f] {
        for value in group.iter() {
            out.push(M31::from(u32::from(*value)));
        }
    }
    out.push(M31::from(u32::from(rcs_no_turn)));
    // street ∈ {2,3,4} 两比特分解：street − 2 = sel0 + 2·sel1。
    {
        let street = usize::from(w.pre.street);
        // street − 2 = sel0 + 2·sel1：street 2 → (0,0)，3 → (1,0)，4 → (0,1)。
        out.push(M31::from(u32::from(rc_board && street == 3)));
        out.push(M31::from(u32::from(rc_board && street == 4)));
    }
    debug_assert_eq!(out.len(), NUM_COLUMNS);
    out
}

fn mix_digest(channel: &mut Poseidon252Channel, digest: &[u8; 32]) {
    channel.mix_u32s(
        &digest
            .chunks_exact(4)
            .map(|x| u32::from_be_bytes(x.try_into().expect("digest word")))
            .collect::<Vec<_>>(),
    );
}

fn mix_scope(channel: &mut Poseidon252Channel, proof: &ArchivedCanonicalTaggedProof) {
    channel.mix_u64(proof.table_id);
    channel.mix_u32s(&[
        proof.first_hand_id,
        proof.last_hand_id,
        proof.first_call_seq,
        proof.last_call_seq,
        u32::from(proof.transition_count),
    ]);
    mix_digest(channel, &proof.batch_digest);
    channel.mix_u32s(&[
        u32::from(proof.first_transition_kind),
        u32::from(proof.last_transition_kind),
        u32::from(proof.reveal_timeout_cascade_count),
    ]);
    channel.mix_u32s(&proof.reveal_timeout_cascade_schedule.map(u32::from));
    match &proof.rake_opening {
        Some(rake) => {
            channel.mix_u32s(&[1, u32::from(rake.rake_mode), u32::from(rake.rake_bps)]);
            channel.mix_u64(rake.rake_cap);
        }
        None => channel.mix_u32s(&[0]),
    }
    match &proof.blind_opening {
        Some(blind) => {
            channel.mix_u32s(&[1, u32::from(blind.ante_mode)]);
            channel.mix_u64(blind.small_blind);
            channel.mix_u64(blind.big_blind);
            channel.mix_u64(blind.ante_amount);
        }
        None => channel.mix_u32s(&[0]),
    }
    mix_digest(channel, &proof.pre_state_commitment);
    mix_digest(channel, &proof.post_state_commitment);
    mix_digest(channel, &proof.state_object_key);
    channel.mix_u32s(&[proof.state_opening_epoch]);
    for root in archive_root_scope(proof) {
        mix_digest(channel, &root);
    }
    for image in [&proof.pre_state_image_bytes, &proof.post_state_image_bytes] {
        channel.mix_u64(image.len() as u64);
        channel.mix_u32s(&image.iter().copied().map(u32::from).collect::<Vec<_>>());
    }
}

fn archive_root_scope(proof: &ArchivedCanonicalTaggedProof) -> [[u8; 32]; ROOT_DOMAIN_COUNT * 2] {
    [
        proof.pre_state_root,
        proof.post_state_root,
        proof.pre_lifecycle_root,
        proof.post_lifecycle_root,
        proof.pre_overlay_root,
        proof.post_overlay_root,
        proof.pre_settlement_commitment,
        proof.post_settlement_commitment,
        proof.pre_custody_commitment,
        proof.post_custody_commitment,
    ]
}

fn preprocessed_ids() -> &'static [PreProcessedColumnId] {
    static IDS: std::sync::OnceLock<Vec<PreProcessedColumnId>> = std::sync::OnceLock::new();
    IDS.get_or_init(build_preprocessed_ids).as_slice()
}

fn build_preprocessed_ids() -> Vec<PreProcessedColumnId> {
    let mut ids = vec![
        "texas.canonical.active.v2",
        "texas.canonical.first.v2",
        "texas.canonical.last.v2",
        "texas.canonical.table.v2.0",
        "texas.canonical.table.v2.1",
        "texas.canonical.table.v2.2",
        "texas.canonical.table.v2.3",
        "texas.canonical.pre-image.v2.0",
        "texas.canonical.pre-image.v2.1",
        "texas.canonical.pre-image.v2.2",
        "texas.canonical.pre-image.v2.3",
        "texas.canonical.pre-image.v2.4",
        "texas.canonical.pre-image.v2.5",
        "texas.canonical.pre-image.v2.6",
        "texas.canonical.pre-image.v2.7",
        "texas.canonical.pre-image.v2.8",
        "texas.canonical.pre-image.v2.9",
        "texas.canonical.pre-image.v2.10",
        "texas.canonical.pre-image.v2.11",
        "texas.canonical.pre-image.v2.12",
        "texas.canonical.pre-image.v2.13",
        "texas.canonical.pre-image.v2.14",
        "texas.canonical.pre-image.v2.15",
        "texas.canonical.post-image.v2.0",
        "texas.canonical.post-image.v2.1",
        "texas.canonical.post-image.v2.2",
        "texas.canonical.post-image.v2.3",
        "texas.canonical.post-image.v2.4",
        "texas.canonical.post-image.v2.5",
        "texas.canonical.post-image.v2.6",
        "texas.canonical.post-image.v2.7",
        "texas.canonical.post-image.v2.8",
        "texas.canonical.post-image.v2.9",
        "texas.canonical.post-image.v2.10",
        "texas.canonical.post-image.v2.11",
        "texas.canonical.post-image.v2.12",
        "texas.canonical.post-image.v2.13",
        "texas.canonical.post-image.v2.14",
        "texas.canonical.post-image.v2.15",
    ]
    .into_iter()
    .map(|id| PreProcessedColumnId { id: id.into() })
    .collect::<Vec<_>>();
    for domain in [
        "state-root",
        "lifecycle-root",
        "overlay-root",
        "settlement-commitment",
        "custody-commitment",
    ] {
        for endpoint in ["pre", "post"] {
            for limb in 0..16 {
                ids.push(PreProcessedColumnId {
                    id: format!("texas.canonical.{endpoint}-{domain}.v2.{limb}").into(),
                });
            }
        }
    }
    for endpoint in ["pre-state-image", "post-state-image"] {
        for limb in 0..STATE_IMAGE_PROJECTION_LIMBS {
            ids.push(PreProcessedColumnId {
                id: format!("texas.canonical.{endpoint}.v5.{limb}").into(),
            });
        }
    }
    ids.push(PreProcessedColumnId {
        id: "texas.canonical.first-kind.v5".into(),
    });
    ids.push(PreProcessedColumnId {
        id: "texas.canonical.last-kind.v5".into(),
    });
    ids.push(PreProcessedColumnId {
        id: "texas.canonical.reveal-timeout-cascade-active.v1".into(),
    });
    ids.push(PreProcessedColumnId {
        id: "texas.canonical.reveal-timeout-cascade-seat.v1".into(),
    });
    for index in 0..6 {
        ids.push(PreProcessedColumnId {
            id: format!("texas.canonical.rake-scope-{index}.v1"),
        });
    }
    for index in 0..13 {
        ids.push(PreProcessedColumnId {
            id: format!("texas.canonical.blind-scope-{index}.v1"),
        });
    }
    ids.push(PreProcessedColumnId {
        id: "texas.canonical.range-table.v1".into(),
    });
    debug_assert_eq!(ids.len(), PREPROCESSED_COLUMNS);
    ids
}

fn scope_trace(proof: &ArchivedCanonicalTaggedProof, log_size: u32) -> MethodTrace {
    let mut trace = MethodTrace::new(log_size, PREPROCESSED_COLUMNS);
    let table = u64_limbs(proof.table_id);
    let pre_image = bytes16(&proof.pre_state_commitment);
    let post_image = bytes16(&proof.post_state_commitment);
    let pre_state_projection = state_image_projection(&proof.pre_state_image_bytes)
        .expect("validated canonical pre-state image bytes");
    let post_state_projection = state_image_projection(&proof.post_state_image_bytes)
        .expect("validated canonical post-state image bytes");
    let roots = archive_root_scope(proof);
    for index in 0..usize::from(proof.transition_count) {
        let mut values = vec![M31::from(0u32); PREPROCESSED_COLUMNS];
        values[0] = M31::from(1u32);
        values[1] = M31::from(u32::from(index == 0));
        values[2] = M31::from(u32::from(index + 1 == usize::from(proof.transition_count)));
        values[3..7].copy_from_slice(&table);
        // The schedule carries both the non-terminal kick prefix and, for a
        // terminal continuation, the final reset seat.  Keep that final slot
        // in the preprocessed trace as well: mixing it into Fiat--Shamir
        // authenticates the archive, but this column is what proves that the
        // terminal state transition actually acted on that scheduled seat.
        let kick_count = usize::from(proof.reveal_timeout_cascade_count);
        let terminal_continuation = proof.transition_count
            == proof.reveal_timeout_cascade_count as u16 + 1
            && (proof.last_transition_kind == CanonicalTransitionKind::RevealTimeoutReset as u8
                || proof.last_transition_kind
                    == CanonicalTransitionKind::RevealTimeoutReconstruct as u8
                || proof.last_transition_kind == CanonicalTransitionKind::RevealTimeoutAward as u8
                || proof.last_transition_kind
                    == CanonicalTransitionKind::RevealTimeoutRakedAward as u8);
        let cascade = proof.reveal_timeout_cascade_count != 0
            && (index < kick_count || (terminal_continuation && index == kick_count));
        if cascade {
            values[REVEAL_TIMEOUT_CASCADE_ACTIVE_SCOPE_OFFSET] = M31::from(1u32);
            values[REVEAL_TIMEOUT_CASCADE_SEAT_SCOPE_OFFSET] =
                M31::from(u32::from(proof.reveal_timeout_cascade_schedule[index]));
        }
        // The rake configuration is public batch scope: the companion
        // Blake2b rules proof authenticates it to the pre rules commitment
        // and every row can compare its copy against these columns.
        if let Some(rake) = proof.rake_opening {
            let cap = u64_limbs(rake.rake_cap);
            values[RAKE_SCOPE_OFFSET] = M31::from(u32::from(rake.rake_mode));
            values[RAKE_SCOPE_OFFSET + 1] = M31::from(u32::from(rake.rake_bps));
            values[RAKE_SCOPE_OFFSET + 2..RAKE_SCOPE_OFFSET + 6].copy_from_slice(&cap);
        }
        // The blind/ante projection is public batch scope for reveal
        // completion rows, authenticated by the same companion rules proof.
        if let Some(blind) = proof.blind_opening {
            values[BLIND_SCOPE_OFFSET..BLIND_SCOPE_OFFSET + 4]
                .copy_from_slice(&u64_limbs(blind.small_blind));
            values[BLIND_SCOPE_OFFSET + 4..BLIND_SCOPE_OFFSET + 8]
                .copy_from_slice(&u64_limbs(blind.big_blind));
            values[BLIND_SCOPE_OFFSET + BLIND_SCOPE_ANTE_MODE_INDEX] =
                M31::from(u32::from(blind.ante_mode));
            values[BLIND_SCOPE_OFFSET + 9..BLIND_SCOPE_OFFSET + 13]
                .copy_from_slice(&u64_limbs(blind.ante_amount));
        }
        if index == 0 {
            values[7..23].copy_from_slice(&pre_image);
        }
        if index + 1 == usize::from(proof.transition_count) {
            values[23..39].copy_from_slice(&post_image);
        }
        if index == 0 {
            values[FIRST_KIND_SCOPE_OFFSET] = M31::from(u32::from(proof.first_transition_kind));
        }
        if index + 1 == usize::from(proof.transition_count) {
            values[LAST_KIND_SCOPE_OFFSET] = M31::from(u32::from(proof.last_transition_kind));
        }
        for (root_index, root) in roots.iter().enumerate() {
            let is_pre = root_index % 2 == 0;
            if (is_pre && index == 0)
                || (!is_pre && index + 1 == usize::from(proof.transition_count))
            {
                let offset = ROOT_SCOPE_OFFSET + root_index * 16;
                values[offset..offset + 16].copy_from_slice(&bytes16(root));
            }
        }
        if index == 0 {
            values
                [STATE_IMAGE_SCOPE_OFFSET..STATE_IMAGE_SCOPE_OFFSET + STATE_IMAGE_PROJECTION_LIMBS]
                .copy_from_slice(&pre_state_projection);
        }
        if index + 1 == usize::from(proof.transition_count) {
            let offset = STATE_IMAGE_SCOPE_OFFSET + STATE_IMAGE_PROJECTION_LIMBS;
            values[offset..offset + STATE_IMAGE_PROJECTION_LIMBS]
                .copy_from_slice(&post_state_projection);
        }
        trace.write_row(index, &values).expect("scope width");
    }
    // The shared byte range table is public constant scope over the WHOLE
    // domain: values 0..=255 on the first 256 rows, zero beyond.
    for (row, cell) in trace.cols[RANGE_TABLE_SCOPE_OFFSET]
        .iter_mut()
        .enumerate()
        .take(256)
    {
        *cell = M31::from(row as u32);
    }
    trace
}

fn trace_for_with_state_opening_scope(
    witnesses: &[CanonicalTransitionWitness],
    state_opening: CanonicalStateOpeningScope,
) -> TexasAirResult<(MethodTrace, ArchivedCanonicalTaggedProof)> {
    if witnesses.is_empty() || witnesses.len() > MAX_ROWS {
        return Err(TexasAirError::SpecViolation(
            "canonical batch must contain 1..=1024 transitions".into(),
        ));
    }
    crate::texas_canonical::validate_direct_batch(witnesses)
        .map_err(TexasAirError::SpecViolation)?;
    let log_size = tagged_batch_log_size(witnesses.len())?;
    let mut trace = MethodTrace::new(log_size, NUM_COLUMNS + 1);
    for (index, witness) in witnesses.iter().enumerate() {
        // These are fixed-width ABI guards, not VM replay.  Keeping them here
        // makes malformed protocol/round envelopes fail closed before advice
        // generation while the semantic relations remain in the AIR.
        if is_crypto_action(witness.kind) && witness.action.proof_commitment == [0; 32] {
            return Err(TexasAirError::SpecViolation(
                "crypto transition requires a non-zero proof commitment".into(),
            ));
        }
        if witness.kind == CanonicalTransitionKind::AdvanceRound {
            // 街道 4 = river 轮收注 → 摊牌窗口 advance（#22②扩展 profile）。
            if !(1..=4).contains(&witness.pre.street) {
                return Err(TexasAirError::SpecViolation(
                    "advance-round opening has an unsupported street".into(),
                ));
            }
            let pending_mask = witness
                .pre
                .seats
                .iter()
                .enumerate()
                .filter(|(_, seat)| {
                    matches!(
                        seat.status,
                        CanonicalSeatStatus::Active
                            | CanonicalSeatStatus::Folded
                            | CanonicalSeatStatus::AllIn
                    )
                })
                .fold(0u16, |mask, (seat, _)| mask | (1u16 << seat));
            let mut padding = false;
            for assignment in &witness.round_advance.assignments {
                if !assignment.present {
                    padding = true;
                    if assignment.encrypted_card_index != 0
                        || assignment.runout_index != 0
                        || assignment.board_position != 0
                        || assignment.pending_mask != 0
                        || assignment.submitted_mask != 0
                    {
                        return Err(TexasAirError::SpecViolation(
                            "advance-round opening has non-zero padding".into(),
                        ));
                    }
                } else {
                    if padding
                        || assignment.pending_mask != pending_mask
                        || assignment.submitted_mask != 0
                    {
                        return Err(TexasAirError::SpecViolation(
                            "advance-round opening has a non-canonical assignment envelope".into(),
                        ));
                    }
                }
            }
        } else if witness.round_advance
            != crate::texas_canonical::CanonicalRoundAdvanceOpening::default()
        {
            return Err(TexasAirError::SpecViolation(
                "only advance-round transitions may carry a board opening".into(),
            ));
        }
        let next_pre = witnesses.get(index + 1).map(|next| &next.pre);
        let mut values = row(witness, next_pre);
        // The appended range-table multiplicity column starts zeroed; the
        // derived counts are filled in after all witness rows exist.
        values.push(M31::from(0u32));
        trace.write_row(index, &values)?;
    }
    append_range_multiplicity(&mut trace);
    let first = &witnesses[0];
    let last = &witnesses[witnesses.len() - 1];
    let mut reveal_timeout_cascade_count = 0u8;
    let mut reveal_timeout_cascade_schedule =
        [REVEAL_TIMEOUT_CASCADE_EMPTY_SEAT; MAX_REVEAL_TIMEOUT_CASCADE_KICKS];
    let all_reveal_kicks = witnesses
        .iter()
        .all(|w| w.kind == CanonicalTransitionKind::RevealTimeoutKick);
    if all_reveal_kicks {
        if witnesses.len() > MAX_REVEAL_TIMEOUT_CASCADE_KICKS {
            return Err(TexasAirError::SpecViolation(
                "reveal-timeout cascade exceeds fixed schedule width".into(),
            ));
        }
        reveal_timeout_cascade_count = witnesses.len() as u8;
        for (index, witness) in witnesses.iter().enumerate() {
            reveal_timeout_cascade_schedule[index] = witness.action.seat;
            if index > 0 && witnesses[index - 1].action.seat >= witness.action.seat {
                return Err(TexasAirError::SpecViolation(
                    "reveal-timeout cascade seats must be strictly ascending".into(),
                ));
            }
        }
    } else if witnesses.len() >= 2
        && witnesses[..witnesses.len() - 1]
            .iter()
            .all(|w| w.kind == CanonicalTransitionKind::RevealTimeoutKick)
        && witnesses.last().is_some_and(|w| {
            matches!(
                w.kind,
                CanonicalTransitionKind::RevealTimeoutReset
                    | CanonicalTransitionKind::RevealTimeoutReconstruct
                    | CanonicalTransitionKind::RevealTimeoutAward
                    | CanonicalTransitionKind::RevealTimeoutRakedAward
            ) && w.action.seat < MAX_CANONICAL_SEATS as u8
        })
    {
        let kick_count = witnesses.len() - 1;
        if kick_count > MAX_REVEAL_TIMEOUT_CASCADE_KICKS - 1 {
            return Err(TexasAirError::SpecViolation(
                "reveal-timeout terminal cascade exceeds fixed schedule width".into(),
            ));
        }
        reveal_timeout_cascade_count = kick_count as u8;
        for (index, witness) in witnesses[..kick_count].iter().enumerate() {
            reveal_timeout_cascade_schedule[index] = witness.action.seat;
            if index > 0 && witnesses[index - 1].action.seat >= witness.action.seat {
                return Err(TexasAirError::SpecViolation(
                    "reveal-timeout cascade seats must be strictly ascending".into(),
                ));
            }
        }
        reveal_timeout_cascade_schedule[kick_count] = witnesses[kick_count].action.seat;
    } else if witnesses
        .iter()
        .any(|w| w.kind == CanonicalTransitionKind::RevealTimeoutKick)
    {
        return Err(TexasAirError::SpecViolation(
            "reveal-timeout kick rows must form a dedicated tagged batch".into(),
        ));
    }
    let rake_opening = witnesses
        .iter()
        .find(|w| w.kind == CanonicalTransitionKind::RevealTimeoutRakedAward)
        .map(|w| {
            let opening = w.rake_opening;
            if opening == crate::canonical_rake_opening::CanonicalRakeOpening::ZERO {
                return Err(TexasAirError::SpecViolation(
                    "raked award transition carries a zero rake opening".into(),
                ));
            }
            Ok(opening)
        })
        .transpose()?;
    if rake_opening.is_some()
        && witnesses
            .iter()
            .filter(|w| w.kind == CanonicalTransitionKind::RevealTimeoutRakedAward)
            .count()
            != 1
    {
        return Err(TexasAirError::SpecViolation(
            "a tagged batch carries at most one raked award terminal".into(),
        ));
    }
    // #22②：批内 reveal 完成行携带同一份盲注 opening（公开 scope 列的来源）。
    // #22②扩展：street 完成行以 opening.bb_amount 通道复用同一盲注面额
    //（min_raise = BB），故 RevealStreet 行亦可锚定 scope。
    let blind_opening = witnesses
        .iter()
        .filter(|w| w.kind == CanonicalTransitionKind::SubmitReveal)
        .find(|w| {
            matches!(
                w.protocol_completion.kind,
                CanonicalProtocolCompletionKind::Reveal
                    | CanonicalProtocolCompletionKind::RevealStreet
                    | CanonicalProtocolCompletionKind::Showdown
            )
        })
        .map(|w| {
            let opening = w.blind_opening;
            if opening == crate::canonical_rake_opening::CanonicalBlindOpening::ZERO {
                return Err(TexasAirError::SpecViolation(
                    "reveal completion transition carries a zero blind opening".into(),
                ));
            }
            // preflop：SB/BB 双面额锚定；street：BB 通道（min_raise = BB）；
            // showdown：无盲注面额（bb_amount 为零哨兵），仅要求 opening
            // 非零（与 rules 的一致性由 prove 门的 blind_opening 比对承担）。
            let detached = match w.protocol_completion.kind {
                CanonicalProtocolCompletionKind::Reveal => {
                    w.protocol_completion.sb_amount != opening.small_blind
                        || w.protocol_completion.bb_amount != opening.big_blind
                }
                CanonicalProtocolCompletionKind::RevealStreet => {
                    w.protocol_completion.bb_amount != opening.big_blind
                }
                _ => false,
            };
            if detached {
                return Err(TexasAirError::SpecViolation(
                    "reveal completion opening is detached from the blind opening".into(),
                ));
            }
            Ok(opening)
        })
        .transpose()?;
    let pre_state_image_bytes = borsh::to_vec(&first.pre)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let post_state_image_bytes = borsh::to_vec(&last.post)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    if pre_state_image_bytes.len() != CANONICAL_STATE_IMAGE_BORSH_BYTES
        || post_state_image_bytes.len() != CANONICAL_STATE_IMAGE_BORSH_BYTES
    {
        return Err(TexasAirError::SpecViolation(
            "canonical state-image Borsh ABI width changed".into(),
        ));
    }
    Ok((
        trace,
        ArchivedCanonicalTaggedProof {
            log_size,
            num_columns: NUM_COLUMNS as u32,
            table_id: first.pre.table_id,
            first_hand_id: first.pre.hand_id,
            last_hand_id: last.post.hand_id,
            first_call_seq: first.pre.call_seq,
            last_call_seq: last.post.call_seq,
            transition_count: witnesses.len() as u16,
            first_transition_kind: first.kind as u8,
            last_transition_kind: last.kind as u8,
            reveal_timeout_cascade_count,
            reveal_timeout_cascade_schedule,
            batch_digest: batch_digest_for_witnesses(witnesses),
            pre_state_commitment: first.pre.commitment(),
            post_state_commitment: last.post.commitment(),
            pre_state_root: first.pre.state_root,
            post_state_root: last.post.state_root,
            pre_lifecycle_root: first.pre.lifecycle_root,
            post_lifecycle_root: last.post.lifecycle_root,
            pre_overlay_root: first.pre.overlay_root,
            post_overlay_root: last.post.overlay_root,
            pre_settlement_commitment: first.pre.settlement_commitment,
            post_settlement_commitment: last.post.settlement_commitment,
            pre_custody_commitment: first.pre.custody_commitment,
            post_custody_commitment: last.post.custody_commitment,
            pre_state_image_bytes,
            post_state_image_bytes,
            range_claimed_sum: [0, 0, 0, 0],
            rake_opening,
            blind_opening,
            rules_hash: None,
            state_object_key: state_opening.state_object_key,
            state_opening_epoch: state_opening.state_opening_epoch,
            stark_proof_bytes: Vec::new(),
        },
    ))
}

fn trace_for(
    witnesses: &[CanonicalTransitionWitness],
) -> TexasAirResult<(MethodTrace, ArchivedCanonicalTaggedProof)> {
    trace_for_with_state_opening_scope(witnesses, CanonicalStateOpeningScope::legacy())
}

fn add_limb_eq<E: EvalAtRow>(eval: &mut E, gate: &E::F, left: &[E::F], right: &[E::F]) {
    for (a, b) in left.iter().zip(right.iter()) {
        eval.add_constraint(gate.clone() * (a.clone() - b.clone()));
    }
}

fn limb4_add_constraints<E: EvalAtRow>(
    eval: &mut E,
    gate: &E::F,
    left: &[E::F; 4],
    right: &[E::F; 4],
    result: &[E::F; 4],
    carries: &[E::F; 3],
) {
    let one: E::F = M31::from(1u32).into();
    let zero: E::F = M31::from(0u32).into();
    let base: E::F = M31::from(65536u32).into();
    let carry_in = [
        zero.clone(),
        carries[0].clone(),
        carries[1].clone(),
        carries[2].clone(),
    ];
    let carry_out = [
        carries[0].clone(),
        carries[1].clone(),
        carries[2].clone(),
        zero,
    ];
    for index in 0..4 {
        eval.add_constraint(
            gate.clone()
                * (left[index].clone() + right[index].clone() + carry_in[index].clone()
                    - result[index].clone()
                    - base.clone() * carry_out[index].clone()),
        );
    }
    for carry in carries {
        eval.add_constraint(gate.clone() * carry.clone() * (carry.clone() - one.clone()));
    }
}

/// Same 4-limb addition, but the carry booleanity is omitted: callers whose
/// gate is already degree 2 (completion selectors) provide the booleanity
/// through a separate degree-1 gate to stay within the declared degree.
fn limb4_add_constraints_no_carry_bool<E: EvalAtRow>(
    eval: &mut E,
    gate: &E::F,
    left: &[E::F; 4],
    right: &[E::F; 4],
    result: &[E::F; 4],
    carries: &[E::F; 3],
) {
    let zero: E::F = M31::from(0u32).into();
    let base: E::F = M31::from(65536u32).into();
    let carry_in = [
        zero.clone(),
        carries[0].clone(),
        carries[1].clone(),
        carries[2].clone(),
    ];
    let carry_out = [
        carries[0].clone(),
        carries[1].clone(),
        carries[2].clone(),
        zero,
    ];
    for index in 0..4 {
        eval.add_constraint(
            gate.clone()
                * (left[index].clone() + right[index].clone() + carry_in[index].clone()
                    - result[index].clone()
                    - base.clone() * carry_out[index].clone()),
        );
    }
}

fn limb2_add_constraints<E: EvalAtRow>(
    eval: &mut E,
    gate: &E::F,
    left: &[E::F; 2],
    right: &[E::F; 2],
    result: &[E::F; 2],
    carry: &E::F,
) {
    let base: E::F = M31::from(65536u32).into();
    eval.add_constraint(
        gate.clone()
            * (left[0].clone() + right[0].clone()
                - result[0].clone()
                - base.clone() * carry.clone()),
    );
    eval.add_constraint(gate.clone() * (left[1].clone() + carry.clone() - result[1].clone()));
    eval.add_constraint(gate.clone() * carry.clone() * (carry.clone() - M31::from(1u32).into()));
}

fn trace_limbs<E: EvalAtRow>(eval: &mut E) -> [E::F; 4] {
    std::array::from_fn(|_| eval.next_trace_mask())
}

fn trace_bits16<E: EvalAtRow>(eval: &mut E) -> [E::F; 16] {
    std::array::from_fn(|_| eval.next_trace_mask())
}

fn trace_limbs2<E: EvalAtRow>(eval: &mut E) -> [E::F; 2] {
    std::array::from_fn(|_| eval.next_trace_mask())
}

/// Reconstruct `value = low + 256 * high` and range-check both bytes into
/// the shared 256-entry LogUp table.
fn range8_logup_constraints<E: EvalAtRow>(
    eval: &mut E,
    gate: &E::F,
    value: &E::F,
    bytes: &[E::F; 2],
    range: &CanonicalRange8,
) {
    let base: E::F = M31::from(256u32).into();
    eval.add_constraint(
        gate.clone() * (value.clone() - bytes[0].clone() - base * bytes[1].clone()),
    );
    for byte in bytes {
        eval.add_to_relation(RelationEntry::new(
            range,
            E::EF::from(gate.clone()),
            &[byte.clone()],
        ));
    }
}

fn range16_constraints<E: EvalAtRow>(eval: &mut E, gate: &E::F, value: &E::F, bits: &[E::F; 16]) {
    let one: E::F = M31::from(1u32).into();
    let two: E::F = M31::from(2u32).into();
    let mut reconstructed = bits[0].clone();
    let mut power = two.clone();
    for bit in &bits[1..] {
        reconstructed = reconstructed + bit.clone() * power.clone();
        power = power * two.clone();
    }
    eval.add_constraint(gate.clone() * (value.clone() - reconstructed));
    for bit in bits {
        eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
    }
}

impl FrameworkEval for CanonicalAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let active = eval.next_trace_mask();
        let one: E::F = M31::from(1u32).into();
        let two: E::F = M31::from(2u32).into();
        let scoped_active = eval.get_preprocessed_column(preprocessed_ids()[0].clone());
        eval.add_constraint(active.clone() - scoped_active);
        eval.add_constraint(active.clone() * (active.clone() - one.clone()));
        let kinds: Vec<_> = (0..KIND_COUNT).map(|_| eval.next_trace_mask()).collect();
        let mut kind_sum: E::F = M31::from(0u32).into();
        for kind in &kinds {
            eval.add_constraint(active.clone() * (kind.clone() * (kind.clone() - one.clone())));
            kind_sum += kind.clone();
        }
        eval.add_constraint(active.clone() * (kind_sum.clone() - one.clone()));
        let table: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let pre_hand: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let post_hand: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let pre_seq: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let post_seq: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let pre_image: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_image: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        // Every root domain is a first/last public boundary and must remain
        // contiguous inside the tagged batch.  The state-transition relation
        // does not yet recompute Blake2b here, but a receipt can no longer
        // splice a proof to unrelated state/lifecycle/overlay/economic roots.
        eval.add_constraint({
            let z: E::F = M31::from(0u32).into();
            z // S0_head
        });
        let pre_state_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_state_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_lifecycle_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_lifecycle_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_overlay_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_overlay_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_settlement_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_settlement_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_custody_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_custody_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let actor: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let proof_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let seat = eval.next_trace_mask();
        let amount = trace_limbs(&mut eval);
        let auxiliary: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let flag = eval.next_trace_mask();
        let deadline_height = trace_limbs(&mut eval);
        let seq_carry = eval.next_trace_mask();
        let pre_phase = eval.next_trace_mask();
        let post_phase = eval.next_trace_mask();
        let pre_subtag = eval.next_trace_mask();
        let post_subtag = eval.next_trace_mask();
        let pre_street = eval.next_trace_mask();
        let post_street = eval.next_trace_mask();
        let pre_turn = eval.next_trace_mask();
        let post_turn = eval.next_trace_mask();
        let pre_current = trace_limbs(&mut eval);
        let post_current = trace_limbs(&mut eval);
        let pre_min = trace_limbs(&mut eval);
        let post_min = trace_limbs(&mut eval);
        let pre_pot = trace_limbs(&mut eval);
        let post_pot = trace_limbs(&mut eval);
        let pre_acted_mask = eval.next_trace_mask();
        let post_acted_mask = eval.next_trace_mask();
        let pre_leave_mask = eval.next_trace_mask();
        let post_leave_mask = eval.next_trace_mask();
        let pre_protocol_pending_mask = eval.next_trace_mask();
        let post_protocol_pending_mask = eval.next_trace_mask();
        let pre_status = eval.next_trace_mask();
        let pre_seat_acted = eval.next_trace_mask();
        let pre_stack = trace_limbs(&mut eval);
        let pre_bet = trace_limbs(&mut eval);
        let pre_total = trace_limbs(&mut eval);
        let pre_pending = trace_limbs(&mut eval);
        let pre_time_bank = [eval.next_trace_mask(), eval.next_trace_mask()];
        let post_status = eval.next_trace_mask();
        let post_seat_acted = eval.next_trace_mask();
        let post_stack = trace_limbs(&mut eval);
        let post_bet = trace_limbs(&mut eval);
        let post_total = trace_limbs(&mut eval);
        let post_pending = trace_limbs(&mut eval);
        let post_time_bank = [eval.next_trace_mask(), eval.next_trace_mask()];
        let turn_delta_inv = eval.next_trace_mask();
        let amount_inv = eval.next_trace_mask();
        let stack_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let bet_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let total_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pot_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let stack_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_stack_range_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let bet_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_bet_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let total_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_total_range_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let pot_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_pot_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let amount_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let call_owed = trace_limbs(&mut eval);
        let call_difference = trace_limbs(&mut eval);
        let call_all_in = eval.next_trace_mask();
        let call_difference_inv = eval.next_trace_mask();
        let call_owed_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let call_excess_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let call_shortfall_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let call_owed_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let call_difference_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let raise_needed = trace_limbs(&mut eval);
        let raise_delta = trace_limbs(&mut eval);
        let raise_stack_difference = trace_limbs(&mut eval);
        let raise_min_difference = trace_limbs(&mut eval);
        let raise_all_in = eval.next_trace_mask();
        let raise_meets_min = eval.next_trace_mask();
        let raise_needed_inv = eval.next_trace_mask();
        let raise_delta_inv = eval.next_trace_mask();
        let raise_stack_difference_inv = eval.next_trace_mask();
        let raise_needed_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let raise_delta_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let raise_stack_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let raise_total_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let raise_pot_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let raise_needed_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let raise_delta_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let raise_stack_difference_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let raise_min_difference_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_all_in = eval.next_trace_mask();
        let chip_action_post_stack_sum = eval.next_trace_mask();
        let chip_action_post_stack_inv = eval.next_trace_mask();
        let betting_pre_stack_sum = eval.next_trace_mask();
        let betting_pre_stack_inv = eval.next_trace_mask();
        let acted_seat_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let pre_acted_bits: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let post_acted_bits: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let acted_deltas: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let pre_chip_pool = trace_limbs(&mut eval);
        let post_chip_pool = trace_limbs(&mut eval);
        let funding_chip_pool_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let funding_addon_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let funding_rebuy_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pre_chip_pool_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_chip_pool_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let full_pre_status: [[E::F; SEAT_STATUS_COUNT]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let full_pre_stack: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_pre_bet: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_pre_total: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_pre_pending: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_pre_time_bank: [[E::F; 2]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| [eval.next_trace_mask(), eval.next_trace_mask()]);
        let full_post_status: [[E::F; SEAT_STATUS_COUNT]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let full_post_stack: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_post_bet: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_post_total: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_post_pending: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_post_time_bank: [[E::F; 2]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| [eval.next_trace_mask(), eval.next_trace_mask()]);
        let raise_actor: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let mut selected_transition_pre_time: [E::F; 2] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_transition_post_time: [E::F; 2] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let raise_active: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let no_next_turn = eval.next_trace_mask();
        let next_turn_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let next_turn_pairs: [[E::F; MAX_CANONICAL_SEATS]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let funding_seat_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let round_collect_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let round_collect_carry_bits: [[E::F; 4]; 3] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let round_collect_bet_bits: [[[E::F; 16]; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| trace_bits16(&mut eval)));
        let round_complete_active: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let round_pre_cards_dealt = eval.next_trace_mask();
        let round_post_cards_dealt = eval.next_trace_mask();
        let round_pre_board_len = eval.next_trace_mask();
        let round_post_board_len = eval.next_trace_mask();
        let round_pre_second_board_len = eval.next_trace_mask();
        let round_post_second_board_len = eval.next_trace_mask();
        let round_run_it_twice = eval.next_trace_mask();
        let round_reveal_purpose = eval.next_trace_mask();
        let round_assignment_count = eval.next_trace_mask();
        let round_assignments: [[E::F; 6]; MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let round_schedule_selectors: [E::F; 7] = std::array::from_fn(|_| eval.next_trace_mask());
        // Trace layout is cursor-major: `[cursor_bits, complement_bits,
        // carry_bits]` for pre, then the same three blocks for post.
        let round_card_cursor_range: [[[E::F; 6]; 3]; 2] = std::array::from_fn(|_| {
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
        });
        let pre_rules_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_rules_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_governance_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_governance_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_deadline_image = trace_limbs(&mut eval);
        let post_deadline_image = trace_limbs(&mut eval);
        let post_deadline_inv = eval.next_trace_mask();
        let advance_deadline_difference = trace_limbs(&mut eval);
        let advance_deadline_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let advance_deadline_height_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let advance_deadline_pre_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let advance_deadline_difference_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let advance_deadline_pre_inv = eval.next_trace_mask();
        let advance_deadline_phase_inv = eval.next_trace_mask();
        let pre_leave_mask_bits: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let post_leave_mask_bits: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let pre_protocol_pending_mask_bits: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let post_protocol_pending_mask_bits: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let protocol_pending_post_inv = eval.next_trace_mask();
        let transition_seat_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let pre_opaque_commitments: [[E::F; 16]; OPAQUE_COMMITMENT_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let post_opaque_commitments: [[E::F; 16]; OPAQUE_COMMITMENT_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let pre_state_metadata: [E::F; STATE_IMAGE_METADATA_LIMBS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let post_state_metadata: [E::F; STATE_IMAGE_METADATA_LIMBS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let pre_seat_commitments: [[[E::F; 16]; SEAT_COMMITMENT_FIELD_COUNT]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| {
                std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
            });
        let post_seat_commitments: [[[E::F; 16]; SEAT_COMMITMENT_FIELD_COUNT];
            MAX_CANONICAL_SEATS] = std::array::from_fn(|_| {
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
        });
        let proof_commitment_bits: [[E::F; 16]; 16] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let advance_deadline_time_bank_all = eval.next_trace_mask();
        let advance_deadline_time_bank_slack = [eval.next_trace_mask(), eval.next_trace_mask()];
        let advance_deadline_time_bank_excess = [eval.next_trace_mask(), eval.next_trace_mask()];
        let advance_deadline_time_bank_range_bits: [[[E::F; 16]; 2]; 2] =
            std::array::from_fn(|_| std::array::from_fn(|_| trace_bits16(&mut eval)));
        let advance_deadline_time_bank_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let advance_deadline_extension_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let consume_all_gate = eval.next_trace_mask();
        let partial_gate = eval.next_trace_mask();
        let start_active_product = eval.next_trace_mask();
        let start_active_count_inv = eval.next_trace_mask();
        let start_button_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let start_pre_button_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let start_wrap: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let start_wrap_max: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let start_next_seat: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let next_pre_image: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let next_pre_state_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let next_pre_lifecycle_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let next_pre_overlay_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let next_pre_settlement_commitment: Vec<_> =
            (0..16).map(|_| eval.next_trace_mask()).collect();
        let next_pre_custody_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let transition_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let nullifier: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let transition_commitment_inv = eval.next_trace_mask();
        let nullifier_inv = eval.next_trace_mask();
        let actor_inv = eval.next_trace_mask();
        let pre_timeout_config: [E::F; TIMEOUT_CONFIG_LIMBS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let post_timeout_config: [E::F; TIMEOUT_CONFIG_LIMBS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let pre_timeout_config_bits: [[E::F; 16]; TIMEOUT_CONFIG_LIMBS] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        eval.add_constraint({
            let z: E::F = M31::from(0u32).into();
            z // S1_protocol_cells
        });
        let protocol_completion_kind = eval.next_trace_mask();
        let protocol_completion_timestamp = trace_limbs(&mut eval);
        let protocol_completion_pre_cards_dealt = eval.next_trace_mask();
        let protocol_completion_post_cards_dealt = eval.next_trace_mask();
        let protocol_completion_commitments: [[E::F; 16]; PROTOCOL_COMPLETION_COMMITMENT_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let protocol_completion_post_pending_mask = eval.next_trace_mask();
        let protocol_completion_post_completed_mask = eval.next_trace_mask();
        let protocol_completion_timestamp_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let protocol_completion_timestamp_inv = eval.next_trace_mask();
        let protocol_completion_deadline_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let protocol_completion_cursor_range: [[E::F; 6]; 3] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let shuffle_timeout_gate = eval.next_trace_mask();
        let shuffle_pending_count_product = eval.next_trace_mask();
        let shuffle_deck_diff_square_sum = eval.next_trace_mask();
        let shuffle_deck_product = eval.next_trace_mask();
        let shuffle_deck_nonzero_change_inv = eval.next_trace_mask();
        let reveal_reconstruct_street_bits = [eval.next_trace_mask(), eval.next_trace_mask()];
        let reveal_reconstruct_diff_square_sum = eval.next_trace_mask();
        let reveal_reconstruct_change_product = eval.next_trace_mask();
        let reveal_reconstruct_change_inv = eval.next_trace_mask();
        let reveal_reconstruct_live_product = eval.next_trace_mask();
        let reveal_reconstruct_live_inv = eval.next_trace_mask();
        let reveal_kick_street_bits: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());
        let reveal_award_winner_credit: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let reveal_award_pot_inv = eval.next_trace_mask();
        let rake_config: [E::F; 6] = std::array::from_fn(|_| eval.next_trace_mask());
        let rake_pot_bytes: [[E::F; 2]; 2] = std::array::from_fn(|_| trace_limbs2(&mut eval));
        let rake_product: [E::F; 4] = trace_limbs(&mut eval);
        let rake_product_bytes: [[E::F; 2]; 4] = std::array::from_fn(|_| trace_limbs2(&mut eval));
        let rake_limbs: [E::F; 4] = trace_limbs(&mut eval);
        let rake_limb_bytes: [[E::F; 2]; 4] = std::array::from_fn(|_| trace_limbs2(&mut eval));
        let rake_scaled: [E::F; 4] = trace_limbs(&mut eval);
        let rake_scaled_bytes: [[E::F; 2]; 4] = std::array::from_fn(|_| trace_limbs2(&mut eval));
        let rake_remainder = eval.next_trace_mask();
        let rake_remainder_bytes: [E::F; 2] = trace_limbs2(&mut eval);
        let rake_remainder_bound_bytes: [E::F; 2] = trace_limbs2(&mut eval);
        let rake_div_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let rake_min_diff: [E::F; 4] = trace_limbs(&mut eval);
        let rake_min_diff_bytes: [[E::F; 2]; 4] = std::array::from_fn(|_| trace_limbs2(&mut eval));
        let rake_min_borrows: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let rake_final: [E::F; 4] = trace_limbs(&mut eval);
        let rake_final_bytes: [[E::F; 2]; 4] = std::array::from_fn(|_| trace_limbs2(&mut eval));
        let rake_award: [E::F; 4] = trace_limbs(&mut eval);
        let rake_award_bytes: [[E::F; 2]; 4] = std::array::from_fn(|_| trace_limbs2(&mut eval));
        let rake_chip_intermediate: [E::F; 4] = trace_limbs(&mut eval);
        let rake_chip_extra_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // The per-seat `owes` advice is interleaved seat-major
        // (flag, 4 diff limbs, 3 borrows, inverse, settled) x 9 seats, so the
        // masks must be allocated in exactly that order.
        let mut owes_flat: Vec<E::F> = Vec::with_capacity(MAX_CANONICAL_SEATS * 10);
        for _ in 0..MAX_CANONICAL_SEATS * 10 {
            owes_flat.push(eval.next_trace_mask());
        }
        let seat_owes: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|i| owes_flat[i * 10].clone());
        let seat_owes_diff: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|i| std::array::from_fn(|l| owes_flat[i * 10 + 1 + l].clone()));
        let seat_owes_borrows: [[E::F; 3]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|i| std::array::from_fn(|l| owes_flat[i * 10 + 5 + l].clone()));
        let seat_owes_inv: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|i| owes_flat[i * 10 + 8].clone());
        let seat_settled: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|i| owes_flat[i * 10 + 9].clone());
        // ---- #22② RevealComplete advice (requested last, matching the
        // appended storage order) ----
        let rc_gate = eval.next_trace_mask();
        let rc_blind_limbs: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let rc_count_invs: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());
        let rc_hu = eval.next_trace_mask();
        let rc_sb_onehot: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let rc_bb_onehot: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let rc_rot: [[E::F; 8]; 3] = std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let rc_q: [[E::F; 8]; 3] = std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let rc_f: [[E::F; 8]; 3] = std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let rc_ffa: [E::F; 9] = std::array::from_fn(|_| eval.next_trace_mask());
        let rc_base_onehot: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let rc_nobb = eval.next_trace_mask();
        let rc_dead_sb = eval.next_trace_mask();
        let rc_gate_nobb = eval.next_trace_mask();
        let rc_live_sb = eval.next_trace_mask();
        let rc_sb_amt_inv = eval.next_trace_mask();
        let rc_stack_carries: [[E::F; 3]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let rc_total_carries: [[E::F; 3]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let rc_stack_nonzero_inv: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let rc_stack_capped: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let rc_no_utg = eval.next_trace_mask();
        // ---- #22②扩展（2026-09-15）：street/showdown completion 组 advice
        // （与 row() 的追加顺序严格一致）----
        let rcf_gate = eval.next_trace_mask();
        let rc_hole = eval.next_trace_mask();
        let rc_board = eval.next_trace_mask();
        let rc_showdown = eval.next_trace_mask();
        let rcs_gate = eval.next_trace_mask();
        let rcd_gate = eval.next_trace_mask();
        let rcs_base_onehot: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let rcs_rot: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let rcs_q: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let rcs_f: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let rcs_no_turn = eval.next_trace_mask();
        let rcs_street_sel: [E::F; 2] = std::array::from_fn(|_| eval.next_trace_mask());

        eval.add_constraint(active.clone() * flag.clone() * (flag.clone() - one.clone()));
        eval.add_constraint(seq_carry.clone() * (seq_carry.clone() - one.clone()));
        for (pre, post) in [
            (&pre_rules_commitment, &post_rules_commitment),
            (&pre_governance_commitment, &post_governance_commitment),
        ] {
            for (left, right) in pre.iter().zip(post.iter()) {
                eval.add_constraint(active.clone() * (right.clone() - left.clone()));
            }
        }
        for value in [&pre_seat_acted, &post_seat_acted] {
            eval.add_constraint(active.clone() * value.clone() * (value.clone() - one.clone()));
        }
        for index in 0..4 {
            range16_constraints(
                &mut eval,
                &active,
                &pre_stack[index],
                &stack_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &post_stack[index],
                &post_stack_range_bits[index],
            );
            range16_constraints(&mut eval, &active, &pre_bet[index], &bet_range_bits[index]);
            range16_constraints(
                &mut eval,
                &active,
                &post_bet[index],
                &post_bet_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &pre_total[index],
                &total_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &post_total[index],
                &post_total_range_bits[index],
            );
            range16_constraints(&mut eval, &active, &pre_pot[index], &pot_range_bits[index]);
            range16_constraints(
                &mut eval,
                &active,
                &post_pot[index],
                &post_pot_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &amount[index],
                &amount_range_bits[index],
            );
        }
        // The selected-seat projection is verifier-owned by the action seat and is not allowed
        // to drift from the canonical phase/turn image.
        let is_fold_with_proof = kinds[CanonicalTransitionKind::FoldWithProof as usize].clone();
        let is_betting = kinds[CanonicalTransitionKind::Fold as usize].clone()
            + kinds[CanonicalTransitionKind::Check as usize].clone()
            + kinds[CanonicalTransitionKind::Call as usize].clone()
            + kinds[CanonicalTransitionKind::Raise as usize].clone()
            + kinds[CanonicalTransitionKind::Bet as usize].clone()
            + is_fold_with_proof.clone()
            + kinds[CanonicalTransitionKind::AutoFold as usize].clone();
        eval.add_constraint(is_betting.clone() * (pre_phase.clone() - M31::from(4u32).into()));
        eval.add_constraint(is_betting.clone() * (pre_turn.clone() - seat.clone()));
        eval.add_constraint(is_betting.clone() * (pre_status.clone() - M31::from(2u32).into()));
        eval.add_constraint(is_betting.clone() * (post_seat_acted.clone() - one.clone()));
        eval.add_constraint(
            is_betting.clone()
                * ((post_turn.clone() - seat.clone()) * turn_delta_inv.clone() - one.clone()),
        );
        eval.add_constraint(is_betting.clone() * (post_phase.clone() - pre_phase.clone()));
        eval.add_constraint(is_betting.clone() * (post_subtag.clone() - pre_subtag.clone()));
        eval.add_constraint(is_betting.clone() * (post_street.clone() - pre_street.clone()));
        eval.add_constraint(
            is_betting.clone() * (post_leave_mask.clone() - pre_leave_mask.clone()),
        );
        let is_fold = kinds[CanonicalTransitionKind::Fold as usize].clone();
        let is_auto_fold = kinds[CanonicalTransitionKind::AutoFold as usize].clone();
        let is_reveal_timeout = kinds[CanonicalTransitionKind::RevealTimeoutReset as usize].clone();
        let is_reveal_kick = kinds[CanonicalTransitionKind::RevealTimeoutKick as usize].clone();
        let is_reveal_reconstruct =
            kinds[CanonicalTransitionKind::RevealTimeoutReconstruct as usize].clone();
        let is_reveal_award = kinds[CanonicalTransitionKind::RevealTimeoutAward as usize].clone();
        let is_reveal_raked_award =
            kinds[CanonicalTransitionKind::RevealTimeoutRakedAward as usize].clone();
        // Both sole-survivor terminals share the award shape; only the
        // winner credit and the chip-pool custody chain differ by the rake.
        let is_award_family = is_reveal_award.clone() + is_reveal_raked_award.clone();
        // The shared reset relation below covers both bounded timeout
        // selectors. Keep a reconstruct-only gate for its phase/subtag
        // header, since reveal timeout has the preflop reveal header instead.
        let is_reconstruct_timeout =
            kinds[CanonicalTransitionKind::ReconstructTimeoutReset as usize].clone()
                + is_reveal_timeout.clone();
        let is_reconstruct_only = is_reconstruct_timeout.clone() - is_reveal_timeout.clone();
        let is_fold_like = is_fold.clone() + is_fold_with_proof.clone() + is_auto_fold.clone();
        eval.add_constraint(is_fold_like.clone() * (post_status.clone() - M31::from(3u32).into()));
        let is_check = kinds[CanonicalTransitionKind::Check as usize].clone();
        let is_call = kinds[CanonicalTransitionKind::Call as usize].clone();
        let is_raise = kinds[CanonicalTransitionKind::Raise as usize].clone();
        let is_bet = kinds[CanonicalTransitionKind::Bet as usize].clone();
        let is_addon = kinds[CanonicalTransitionKind::Addon as usize].clone();
        let is_rebuy = kinds[CanonicalTransitionKind::Rebuy as usize].clone();
        let is_funding = is_addon.clone() + is_rebuy.clone();
        let is_advance_deadline = kinds[CanonicalTransitionKind::AdvanceDeadline as usize].clone();
        // `AdvanceDeadline` has two disjoint VM micro-steps.  The action flag
        // is the committed discriminator: false consumes betting time-bank,
        // true removes the lowest pending shuffler.
        // Use the trace advice gate for downstream selectors.  The defining
        // relation above keeps it equal to `AdvanceDeadline * flag`, while
        // reusing the linear advice avoids multiplying that quadratic selector
        // into the many existing state relations.
        let is_shuffle_timeout = shuffle_timeout_gate.clone();
        let is_deadline_extension = is_advance_deadline.clone() - is_shuffle_timeout.clone();
        let deadline_check = is_advance_deadline.clone()
            + is_auto_fold.clone()
            + is_reconstruct_timeout.clone()
            + is_reveal_kick.clone()
            + is_reveal_reconstruct.clone()
            + is_award_family.clone();
        for limb in &deadline_height {
            eval.add_constraint((active.clone() - deadline_check.clone()) * limb.clone());
        }
        let is_round_advance = kinds[CanonicalTransitionKind::AdvanceRound as usize].clone();
        let is_end_without_showdown =
            kinds[CanonicalTransitionKind::EndWithoutShowdown as usize].clone();
        let is_reset_only = kinds[CanonicalTransitionKind::ResetOnly as usize].clone();
        let is_terminal_reset = is_end_without_showdown.clone() + is_reset_only.clone();
        let is_create = kinds[CanonicalTransitionKind::CreateTable as usize].clone();
        let is_start = kinds[CanonicalTransitionKind::StartHand as usize].clone();
        let is_join = kinds[CanonicalTransitionKind::JoinTable as usize].clone();
        let is_leave = kinds[CanonicalTransitionKind::LeaveTable as usize].clone();
        let is_force_fold = kinds[CanonicalTransitionKind::ForceFold as usize].clone();
        let is_kick =
            kinds[CanonicalTransitionKind::KickPlayer as usize].clone() + is_reveal_kick.clone();
        let is_force_or_kick = is_force_fold.clone() + is_kick.clone();
        let is_submit_shuffle = kinds[CanonicalTransitionKind::SubmitShuffle as usize].clone();
        let is_submit_reveal = kinds[CanonicalTransitionKind::SubmitReveal as usize].clone();
        let is_submit_reconstruct =
            kinds[CanonicalTransitionKind::SubmitReconstruct as usize].clone();
        // 完成单元 = "是否完成"布尔（row 侧已布尔化）；具体完成类型由行的
        // 一热 kind 选择器区分。Reveal completion 本切片未启用（其 post
        // current_turn 位置规则与盲注派生尚无 opening），flag×SubmitReveal
        // 显式归零。
        let protocol_completion_flag = protocol_completion_kind.clone();
        let is_reconstruct_completion =
            protocol_completion_flag.clone() * is_submit_reconstruct.clone();
        let is_shuffle_completion = protocol_completion_flag.clone() * is_submit_shuffle.clone();
        // #22②：reveal 完成行（SubmitReveal × flag）。该选择子是二次的，
        // 先线性化为家族门（rcf_gate，shuffle_timeout_gate 模式），再按
        // pre_subtag one-hot（hole=1 / board=2 / showdown=3）划分三个子门：
        // preflop 盲注组沿用 rc_gate（其下全部既有约束自动收窄到 hole 行），
        // street / showdown 组各持 rcs_gate / rcd_gate。
        let is_reveal_completion = protocol_completion_flag.clone() * is_submit_reveal.clone();
        eval.add_constraint(
            active.clone() * (rcf_gate.clone() - is_reveal_completion.clone()),
        );
        eval.add_constraint(
            active.clone() * rcf_gate.clone() * (rcf_gate.clone() - one.clone()),
        );
        eval.add_constraint(
            rcf_gate.clone()
                * (rc_hole.clone() + rc_board.clone() + rc_showdown.clone() - one.clone()),
        );
        for bit in [&rc_hole, &rc_board, &rc_showdown] {
            eval.add_constraint(rcf_gate.clone() * bit.clone() * (bit.clone() - one.clone()));
        }
        eval.add_constraint(
            rcf_gate.clone()
                * (pre_subtag.clone()
                    - rc_hole.clone()
                    - rc_board.clone() * E::F::from(M31::from(2u32))
                    - rc_showdown.clone() * E::F::from(M31::from(3u32))),
        );
        eval.add_constraint(
            active.clone() * (rc_gate.clone() - rcf_gate.clone() * rc_hole.clone()),
        );
        eval.add_constraint(
            active.clone() * (rcs_gate.clone() - rcf_gate.clone() * rc_board.clone()),
        );
        eval.add_constraint(
            active.clone() * (rcd_gate.clone() - rcf_gate.clone() * rc_showdown.clone()),
        );
        eval.add_constraint(active.clone() * rc_gate.clone() * (rc_gate.clone() - one.clone()));
        eval.add_constraint(active.clone() * rcs_gate.clone() * (rcs_gate.clone() - one.clone()));
        eval.add_constraint(active.clone() * rcd_gate.clone() * (rcd_gate.clone() - one.clone()));
        let is_nonfinal_reconstruct =
            is_submit_reconstruct.clone() - is_reconstruct_completion.clone();
        eval.add_constraint(
            active.clone() * protocol_completion_flag.clone() * (protocol_completion_flag.clone() - one.clone()),
        );
        // 完成行（reconstruct/shuffle/reveal）分别由下方各自的组合约束
        // 锚定；flag 只需保持布尔。
        let is_set_leave = kinds[CanonicalTransitionKind::SetLeaveAfterHand as usize].clone();
        let is_timeout_reset = is_reconstruct_timeout.clone();
        for value in &auxiliary {
            eval.add_constraint((active.clone() - is_advance_deadline.clone()) * value.clone());
        }
        eval.add_constraint(
            (active.clone() - is_set_leave.clone() - is_shuffle_timeout.clone()) * flag.clone(),
        );
        let seatless =
            is_create.clone() + is_start.clone() + is_round_advance.clone() + is_reset_only.clone();
        eval.add_constraint(
            seatless.clone() * (seat.clone() - M31::from(u32::from(NO_CANONICAL_SEAT)).into()),
        );
        let zero_amount = is_create.clone()
            + is_start.clone()
            + is_force_fold.clone()
            + is_submit_shuffle.clone()
            + is_submit_reveal.clone()
            + is_submit_reconstruct.clone()
            + is_fold.clone()
            + is_check.clone()
            + is_set_leave.clone()
            + is_fold_with_proof.clone()
            + is_round_advance.clone()
            + is_auto_fold.clone()
            + is_reset_only.clone();
        for value in &amount {
            eval.add_constraint(zero_amount.clone() * value.clone());
        }
        let is_crypto = is_submit_shuffle.clone()
            + is_submit_reveal.clone()
            + is_submit_reconstruct.clone()
            + is_fold_with_proof.clone();
        // #22④/#22②：SubmitShuffle/SubmitReconstruct/SubmitReveal 的状态机
        // 规范化语义已组合（协议进度、相位/截止时间、盲注开局/位置规则），
        // 直接验证器放行；deck/重建/reveal 承诺**轮转**与实际密文的绑定属
        // native/链上 EC_OP 通道（Plan D ④ 残留信任）。FoldWithProof 维持禁止。
        let crypto_admitted = is_submit_shuffle.clone()
            + is_submit_reconstruct.clone()
            + is_submit_reveal.clone();
        eval.add_constraint(active.clone() * (is_crypto.clone() - crypto_admitted.clone()));
        let proof_bound = is_crypto.clone();
        // A crypto tag carries a real, fixed-width proof commitment rather
        // than a host boolean.  Every limb is range-bound before the inverse
        // proves that at least one of the 32 commitment bytes is non-zero.
        // This is only an anti-null relation; verification of the bound
        // Ristretto proof payload is added by the dedicated crypto AIR.
        let mut proof_commitment_sum: E::F = M31::from(0u32).into();
        for limb in 0..16 {
            range16_constraints(
                &mut eval,
                &proof_bound,
                &proof_commitment[limb],
                &proof_commitment_bits[limb],
            );
            for bit in &proof_commitment_bits[limb] {
                eval.add_constraint((active.clone() - proof_bound.clone()) * bit.clone());
            }
            proof_commitment_sum += proof_commitment[limb].clone();
            eval.add_constraint(
                (active.clone()
                    - proof_bound.clone()
                    - is_terminal_reset.clone()
                    - is_timeout_reset.clone()
                    - is_reveal_kick.clone()
                    - is_reveal_reconstruct.clone()
                    - is_award_family.clone())
                    * proof_commitment[limb].clone(),
            );
        }
        eval.add_constraint(
            proof_bound.clone() * (proof_commitment_sum * amount_inv.clone() - one.clone()),
        );
        // These direct canonical tags do not overload the betting/funding
        // action fields.  Keeping them zero removes an otherwise free advice
        // surface until each protocol's fixed witness ABI is introduced.
        for value in amount.iter().chain(auxiliary.iter()) {
            eval.add_constraint(is_crypto.clone() * value.clone());
        }
        eval.add_constraint(
            is_submit_shuffle.clone() * (pre_phase.clone() - M31::from(1u32).into()),
        );
        eval.add_constraint(
            is_submit_reveal.clone() * (pre_phase.clone() - M31::from(2u32).into()),
        );
        eval.add_constraint(
            is_submit_reconstruct.clone() * (pre_phase.clone() - M31::from(3u32).into()),
        );
        eval.add_constraint(
            is_submit_reconstruct.clone()
                * (pre_subtag.clone()
                    - M31::from(u32::from(CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG)).into()),
        );
        let is_protocol_submit =
            is_submit_shuffle.clone() + is_submit_reveal.clone() + is_submit_reconstruct.clone();
        eval.add_constraint(
            is_protocol_submit.clone()
                * (pre_status.clone() * turn_delta_inv.clone() - one.clone()),
        );
    // Protocol submissions carry proof payloads but must not become a
    // side channel for economic, seat, or betting-state mutation.
    // acted-mask 冻结豁免 reveal 完成行（封顶盲注座位补 all-in acted 位，
    // 该行掩码由 rc 组的 capped-mask 约束接管）。
    for (pre, post) in [
        (&pre_street, &post_street),
        (&pre_leave_mask, &post_leave_mask),
    ] {
        eval.add_constraint(is_protocol_submit.clone() * (post.clone() - pre.clone()));
    }
    eval.add_constraint(
        (is_protocol_submit.clone() - is_reveal_completion.clone())
            * (post_acted_mask.clone() - pre_acted_mask.clone()),
    );
    // #22②：非最终提交行保持 turn 双端 NO_SEAT 冻结；reveal 完成行的
    // post turn 由位置规则组合约束（first-after-BB 扫描）接管。
    eval.add_constraint(
        (is_protocol_submit.clone() - is_reveal_completion.clone())
            * (post_turn.clone() - pre_turn.clone()),
    );
    eval.add_constraint(
        is_protocol_submit.clone()
            * (pre_turn.clone() - M31::from(u32::from(NO_CANONICAL_SEAT)).into()),
    );
    // #22②：pot/chip_pool 在所有协议行（含 reveal 完成）冻结——盲注只在
    // 座位 stack/bet 桶之间移动；current_bet/min_raise 在 reveal 完成行
    // 跳变为大盲，由完成组合约束钉死。
    for (pre, post) in [(&pre_pot, &post_pot), (&pre_chip_pool, &post_chip_pool)] {
        for (left, right) in pre.iter().zip(post.iter()) {
            eval.add_constraint(is_protocol_submit.clone() * (right.clone() - left.clone()));
        }
    }
    for (pre, post) in [(&pre_current, &post_current), (&pre_min, &post_min)] {
        for (left, right) in pre.iter().zip(post.iter()) {
            eval.add_constraint(
                (is_protocol_submit.clone() - is_reveal_completion.clone())
                    * (right.clone() - left.clone()),
            );
        }
    }
        // Each family has one protocol-owned commitment surface.  Reconstruct
        // completion may additionally rebuild the deck, matching the VM.
        for commitment in [0usize, 2, 3, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_submit_shuffle.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        let mut post_deck_sum: E::F = M31::from(0u32).into();
        let mut deck_difference_square_sum: E::F = M31::from(0u32).into();
        for limb in 0..16 {
            post_deck_sum += post_opaque_commitments[1][limb].clone();
            let difference =
                post_opaque_commitments[1][limb].clone() - pre_opaque_commitments[1][limb].clone();
            deck_difference_square_sum += difference.clone() * difference;
        }
        eval.add_constraint(
            shuffle_timeout_gate.clone() - is_advance_deadline.clone() * flag.clone(),
        );
        eval.add_constraint(
            is_advance_deadline.clone()
                * (deck_difference_square_sum - shuffle_deck_diff_square_sum.clone()),
        );
        eval.add_constraint(
            is_advance_deadline.clone()
                * (post_deck_sum.clone() * shuffle_deck_diff_square_sum.clone()
                    - shuffle_deck_product.clone()),
        );
        eval.add_constraint(
            shuffle_timeout_gate.clone()
                * (shuffle_deck_product.clone() * shuffle_deck_nonzero_change_inv.clone()
                    - one.clone()),
        );
        for value in [
            &shuffle_pending_count_product,
            &shuffle_deck_diff_square_sum,
            &shuffle_deck_product,
            &shuffle_deck_nonzero_change_inv,
        ] {
            eval.add_constraint((active.clone() - is_advance_deadline.clone()) * value.clone());
        }
        eval.add_constraint(
            (is_advance_deadline.clone() - shuffle_timeout_gate.clone())
                * shuffle_deck_nonzero_change_inv.clone(),
        );
        for commitment in [0usize, 2, 3, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_shuffle_timeout.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        for commitment in [0usize, 1, 3, 4] {
            // board（槽 0）在 reveal 完成行放行：窗口完成物化已揭示的
            // 公共牌；deck/reconstruction/rit 与非最终提交行仍冻结。
            let gate = if commitment == 0 {
                is_submit_reveal.clone() - is_reveal_completion.clone()
            } else {
                is_submit_reveal.clone()
            };
            for limb in 0..16 {
                eval.add_constraint(
                    gate.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        for commitment in [0usize, 2, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_submit_reconstruct.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        for limb in 0..16 {
            eval.add_constraint(
                is_nonfinal_reconstruct.clone()
                    * (post_opaque_commitments[1][limb].clone()
                        - pre_opaque_commitments[1][limb].clone()),
            );
        }
        for limb in 0..16 {
            eval.add_constraint(
                is_protocol_submit.clone()
                    * (post_custody_commitment[limb].clone()
                        - pre_custody_commitment[limb].clone()),
            );
        }
        // `CanonicalStateImage` binds these commitments at fixed Borsh
        // offsets.  For the non-crypto transitions below, their VM semantics
        // are strict preservation.  This removes a remaining host-controlled
        // state mutation path without pretending to verify the cryptographic
        // payloads of shuffle/reveal/reconstruct/round transitions yet.
        let opaque_must_be_immutable = (is_betting.clone() - is_fold_with_proof.clone())
            + is_funding.clone()
            + is_join.clone()
            + is_leave.clone()
            + (is_force_or_kick.clone() - is_reveal_kick.clone())
            + is_set_leave.clone()
            + is_deadline_extension.clone();
        for commitment in 0..OPAQUE_COMMITMENT_COUNT {
            for limb in 0..16 {
                eval.add_constraint(
                    opaque_must_be_immutable.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
                eval.add_constraint(
                    is_terminal_reset.clone()
                        * (post_opaque_commitments[1][limb].clone()
                            - proof_commitment[limb].clone()),
                );
                for commitment in [0usize, 2, 3, 4] {
                    eval.add_constraint(
                        is_terminal_reset.clone()
                            * post_opaque_commitments[commitment][limb].clone(),
                    );
                }
            }
        }
        // A reveal-timeout kick consumes exactly the selected reveal ledger
        // commitment.  Unlike the ordinary KickPlayer path, the reveal
        // commitment is replaced by the action's authenticated endpoint;
        // all other table-level protocol commitments remain immutable.
        for limb in 0..16 {
            eval.add_constraint(
                is_reveal_kick.clone()
                    * (post_opaque_commitments[2][limb].clone() - proof_commitment[limb].clone()),
            );
            for commitment in [0usize, 1, 3, 4] {
                eval.add_constraint(
                    is_reveal_kick.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        // `fold_with_proof` removes one ElGamal layer and may therefore only
        // replace the deck commitment.  Board/reveal/reconstruct/run-it-twice
        // state belongs to other protocol phases and must remain fixed.
        for commitment in [0usize, 2, 3, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_fold_with_proof.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        let canonical_abi_version: E::F = M31::from(u32::from(CANONICAL_ABI_VERSION)).into();
        for metadata in [&pre_state_metadata, &post_state_metadata] {
            eval.add_constraint(
                active.clone() * (metadata[0].clone() - canonical_abi_version.clone()),
            );
        }
        for timeout_limb in 0..TIMEOUT_CONFIG_LIMBS {
            let mut reconstructed: E::F = M31::from(0u32).into();
            for (bit_index, bit) in pre_timeout_config_bits[timeout_limb].iter().enumerate() {
                eval.add_constraint(active.clone() * bit.clone() * (bit.clone() - one.clone()));
                reconstructed += bit.clone() * E::F::from(M31::from(1u32 << bit_index));
            }
            eval.add_constraint(
                active.clone() * (pre_timeout_config[timeout_limb].clone() - reconstructed),
            );
            eval.add_constraint(
                active.clone()
                    * (post_timeout_config[timeout_limb].clone()
                        - pre_timeout_config[timeout_limb].clone()),
            );
        }
        // Table capacity is a genesis parameter.  The button advances only at
        // `StartHand`; all other tags must preserve the materialized header.
        // The dead-button blind track (`last_bb_seat`) advances only when
        // blinds are posted (reveal completion).
        eval.add_constraint(
            active.clone() * (post_state_metadata[2].clone() - pre_state_metadata[2].clone()),
        );
        eval.add_constraint(
            (active.clone() - is_start.clone())
                * (post_state_metadata[1].clone() - pre_state_metadata[1].clone()),
        );
        let rc_gate_for_track = rc_gate.clone();
        eval.add_constraint(
            (active.clone() - rc_gate_for_track.clone())
                * (post_state_metadata[3].clone() - pre_state_metadata[3].clone()),
        );

        let seat_commitments_immutable = is_create.clone()
            + is_betting.clone()
            + is_funding.clone()
            + is_set_leave.clone()
            + is_round_advance.clone()
            + is_deadline_extension.clone();
        let selected_seat_commitment_transition = is_join.clone()
            + is_leave.clone()
            + is_force_or_kick.clone()
            + is_shuffle_timeout.clone()
            + is_reveal_reconstruct.clone();
        for seat_index in 0..MAX_CANONICAL_SEATS {
            for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                for limb in 0..16 {
                    let pre = pre_seat_commitments[seat_index][commitment][limb].clone();
                    let post = post_seat_commitments[seat_index][commitment][limb].clone();
                    eval.add_constraint(
                        seat_commitments_immutable.clone() * (post.clone() - pre.clone()),
                    );
                    eval.add_constraint(
                        selected_seat_commitment_transition.clone()
                            * (one.clone() - transition_seat_selectors[seat_index].clone())
                            * (post - pre),
                    );
                }
            }
            for limb in 0..16 {
                let pre_identity = pre_seat_commitments[seat_index][0][limb].clone();
                let post_identity = post_seat_commitments[seat_index][0][limb].clone();
                eval.add_constraint(
                    is_join.clone()
                        * transition_seat_selectors[seat_index].clone()
                        * post_seat_commitments[seat_index][2][limb].clone(),
                );
                for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                    eval.add_constraint(
                        is_leave.clone()
                            * transition_seat_selectors[seat_index].clone()
                            * post_seat_commitments[seat_index][commitment][limb].clone(),
                    );
                }
                for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                    eval.add_constraint(
                        is_force_fold.clone()
                            * transition_seat_selectors[seat_index].clone()
                            * (post_seat_commitments[seat_index][commitment][limb].clone()
                                - pre_seat_commitments[seat_index][commitment][limb].clone()),
                    );
                }
                eval.add_constraint(
                    is_kick.clone()
                        * transition_seat_selectors[seat_index].clone()
                        * (post_identity.clone() - pre_identity.clone()),
                );
                // The reveal-timeout reconstruct terminal kicks its seat with
                // the same internal VM primitive as an ordinary kick: identity
                // is preserved while the key and hole-card commitments are
                // erased for the vacated seat.
                eval.add_constraint(
                    is_reveal_reconstruct.clone()
                        * transition_seat_selectors[seat_index].clone()
                        * (post_identity - pre_identity),
                );
                for commitment in 1..SEAT_COMMITMENT_FIELD_COUNT {
                    eval.add_constraint(
                        is_kick.clone()
                            * transition_seat_selectors[seat_index].clone()
                            * post_seat_commitments[seat_index][commitment][limb].clone(),
                    );
                    eval.add_constraint(
                        is_reveal_reconstruct.clone()
                            * transition_seat_selectors[seat_index].clone()
                            * post_seat_commitments[seat_index][commitment][limb].clone(),
                    );
                }
                for commitment in 1..SEAT_COMMITMENT_FIELD_COUNT {
                    eval.add_constraint(
                        is_shuffle_timeout.clone()
                            * transition_seat_selectors[seat_index].clone()
                            * post_seat_commitments[seat_index][commitment][limb].clone(),
                    );
                }
                eval.add_constraint(
                    is_shuffle_timeout.clone()
                        * transition_seat_selectors[seat_index].clone()
                        * (post_seat_commitments[seat_index][0][limb].clone()
                            - pre_seat_commitments[seat_index][0][limb].clone()),
                );
            }
        }
        // These actions may update exactly one seat image.  The full opening
        // still makes every other seat immutable in the AIR; this is stronger
        // than relying on `only_allowed_changes` during witness construction.
        let is_selected_lifecycle = is_join.clone()
            + is_leave.clone()
            + is_force_or_kick.clone()
            + is_fold_with_proof.clone()
            + is_shuffle_timeout.clone()
            + is_reveal_reconstruct.clone();
        let requires_transition_seat = is_betting.clone()
            + is_funding.clone()
            + is_join.clone()
            + is_leave.clone()
            + is_force_fold.clone()
            + is_kick.clone()
            + is_submit_shuffle.clone()
            + is_submit_reveal.clone()
            + is_submit_reconstruct.clone()
            + is_set_leave.clone()
            + is_advance_deadline.clone()
            + is_end_without_showdown.clone()
            + is_timeout_reset.clone()
            + is_reveal_reconstruct.clone()
            + is_award_family.clone();
        // Lifecycle actions that do not depend on an opaque crypto commitment
        // are constrained directly from the fixed canonical image.  The
        // transition-seat selector below binds `pre_status`/`post_status` to
        // the full nine-seat opening, rather than trusting a host projection.
        let no_seat: E::F = M31::from(15u32).into();
        eval.add_constraint(is_create.clone() * pre_phase.clone());
        eval.add_constraint(is_create.clone() * post_phase.clone());
        eval.add_constraint(is_create.clone() * (pre_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_create.clone() * (post_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_force_fold.clone() * (pre_phase.clone() - M31::from(4u32).into()));
        eval.add_constraint(is_force_fold.clone() * (pre_turn.clone() - seat.clone()));
        for value in amount.iter().chain(auxiliary.iter()) {
            eval.add_constraint(is_force_fold.clone() * value.clone());
        }
        eval.add_constraint(is_force_fold.clone() * flag.clone());
        eval.add_constraint(is_join.clone() * pre_phase.clone());
        eval.add_constraint(is_join.clone() * post_phase.clone());
        eval.add_constraint(is_join.clone() * pre_status.clone());
        eval.add_constraint(is_join.clone() * (post_status.clone() - M31::from(1u32).into()));
        let mut join_amount_sum: E::F = M31::from(0u32).into();
        for limb in &amount {
            join_amount_sum += limb.clone();
        }
        eval.add_constraint(is_join.clone() * (join_amount_sum * amount_inv.clone() - one.clone()));
        eval.add_constraint(is_leave.clone() * pre_phase.clone());
        eval.add_constraint(is_leave.clone() * post_phase.clone());
        eval.add_constraint(
            is_leave.clone()
                * (pre_status.clone() - M31::from(1u32).into())
                * (pre_status.clone() - M31::from(5u32).into()),
        );
        eval.add_constraint(
            is_leave.clone() * post_status.clone() * (post_status.clone() - M31::from(5u32).into()),
        );
        for index in 0..MAX_CANONICAL_SEATS {
            eval.add_constraint(
                is_join.clone() * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
            eval.add_constraint(
                is_join.clone()
                    * (post_leave_mask_bits[index].clone() - pre_leave_mask_bits[index].clone()),
            );
            eval.add_constraint(
                is_leave.clone() * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
            eval.add_constraint(
                is_leave.clone()
                    * (post_leave_mask_bits[index].clone() - pre_leave_mask_bits[index].clone()),
            );
        }
        // Permissionless deadline transitions bind their expiry predicate to
        // the committed pre-state deadline rather than trusting host advice.
        // not trusted to the host.  These canonical u64 limbs prove the
        // committed height is at least the active pre-state deadline, using a
        // checked subtraction witness (`height = deadline + difference`).
        for index in 0..4 {
            range16_constraints(
                &mut eval,
                &deadline_check,
                &deadline_height[index],
                &advance_deadline_height_bits[index],
            );
            range16_constraints(
                &mut eval,
                &deadline_check,
                &pre_deadline_image[index],
                &advance_deadline_pre_bits[index],
            );
            range16_constraints(
                &mut eval,
                &deadline_check,
                &advance_deadline_difference[index],
                &advance_deadline_difference_bits[index],
            );
        }
        limb4_add_constraints(
            &mut eval,
            &deadline_check,
            &pre_deadline_image,
            &advance_deadline_difference,
            &deadline_height,
            &advance_deadline_carries,
        );
        for carry in &advance_deadline_carries {
            eval.add_constraint((active.clone() - deadline_check.clone()) * carry.clone());
        }
        let mut advance_pre_deadline_sum: E::F = M31::from(0u32).into();
        for limb in &pre_deadline_image {
            advance_pre_deadline_sum += limb.clone();
        }
        eval.add_constraint(
            deadline_check.clone()
                * (advance_pre_deadline_sum * advance_deadline_pre_inv.clone() - one.clone()),
        );
        eval.add_constraint(
            deadline_check.clone()
                * (pre_phase.clone() * advance_deadline_phase_inv.clone() - one.clone()),
        );
        eval.add_constraint(
            (active.clone() - deadline_check.clone()) * advance_deadline_pre_inv.clone(),
        );
        eval.add_constraint(
            (active.clone() - deadline_check.clone()) * advance_deadline_phase_inv.clone(),
        );

        // The flag splits `AdvanceDeadline` into the betting extension and the
        // fixed shuffle-timeout micro-step.  The former preserves the betting
        // image and consumes exactly the selected seat's time bank.
        eval.add_constraint(
            is_deadline_extension.clone() * (pre_phase.clone() - M31::from(4u32).into()),
        );
        eval.add_constraint(
            is_deadline_extension.clone() * (post_phase.clone() - pre_phase.clone()),
        );
        eval.add_constraint(is_deadline_extension.clone() * (pre_turn.clone() - seat.clone()));
        eval.add_constraint(is_deadline_extension.clone() * (post_turn.clone() - pre_turn.clone()));
        eval.add_constraint(
            is_deadline_extension.clone()
                * (pre_status.clone() - M31::from(CanonicalSeatStatus::Active as u32).into()),
        );
        eval.add_constraint(
            is_deadline_extension.clone()
                * (post_status.clone() - M31::from(CanonicalSeatStatus::Active as u32).into()),
        );
        for (left, right) in [
            (&pre_subtag, &post_subtag),
            (&pre_street, &post_street),
            (&pre_leave_mask, &post_leave_mask),
        ] {
            eval.add_constraint(is_deadline_extension.clone() * (right.clone() - left.clone()));
        }
        // A timeout extension only changes the selected seat's time bank and
        // the betting deadline.  The VM has not accepted an action yet, so
        // neither the full acted mask nor any seat's acted projection may
        // change on this permissionless row.
        eval.add_constraint(
            is_deadline_extension.clone() * (post_acted_mask.clone() - pre_acted_mask.clone()),
        );
        for index in 0..MAX_CANONICAL_SEATS {
            eval.add_constraint(
                is_deadline_extension.clone()
                    * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
        }
        for (pre_value, post_value) in [
            (&pre_current, &post_current),
            (&pre_min, &post_min),
            (&pre_pot, &post_pot),
            (&pre_chip_pool, &post_chip_pool),
        ] {
            for (left, right) in pre_value.iter().zip(post_value.iter()) {
                eval.add_constraint(is_deadline_extension.clone() * (right.clone() - left.clone()));
            }
        }
        eval.add_constraint(is_deadline_extension.clone() * flag.clone());
        eval.add_constraint(is_deadline_extension.clone() * (auxiliary[0].clone() - one.clone()));
        for value in &auxiliary[1..] {
            eval.add_constraint(is_deadline_extension.clone() * value.clone());
        }
        for value in &amount[2..] {
            eval.add_constraint(is_deadline_extension.clone() * value.clone());
        }

        // The extension deadline is the committed pre-deadline plus the
        // consumed amount.  This also binds the third carry advice emitted by
        // `row()` and prevents a fabricated post-deadline image.
        limb4_add_constraints(
            &mut eval,
            &is_deadline_extension,
            &pre_deadline_image,
            &amount,
            &post_deadline_image,
            &advance_deadline_extension_carries,
        );
        // Shuffle timeout is a fixed, non-cascading micro-step.  It removes
        // the lowest pending active shuffler, refunds stack plus pending addon
        // to the table custody pool, collects only the current bet, and arms
        // the next shuffle deadline from the committed block height.
        eval.add_constraint(
            is_shuffle_timeout.clone() * (pre_phase.clone() - M31::from(1u32).into()),
        );
        eval.add_constraint(is_shuffle_timeout.clone() * (post_phase.clone() - pre_phase.clone()));
        eval.add_constraint(is_shuffle_timeout.clone() * (pre_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_shuffle_timeout.clone() * (post_turn.clone() - no_seat.clone()));
        eval.add_constraint(
            is_shuffle_timeout.clone()
                * (pre_status.clone() - M31::from(CanonicalSeatStatus::Active as u32).into()),
        );
        eval.add_constraint(
            is_shuffle_timeout.clone()
                * (post_status.clone() - M31::from(CanonicalSeatStatus::Out as u32).into()),
        );
        for (left, right) in [(&pre_subtag, &post_subtag), (&pre_street, &post_street)] {
            eval.add_constraint(is_shuffle_timeout.clone() * (right.clone() - left.clone()));
        }
        eval.add_constraint(
            is_shuffle_timeout.clone() * (auxiliary[0].clone() - M31::from(2u32).into()),
        );
        eval.add_constraint(is_shuffle_timeout.clone() * (flag.clone() - one.clone()));
        for value in &auxiliary[1..] {
            eval.add_constraint(is_shuffle_timeout.clone() * value.clone());
        }
        for value in &amount[2..] {
            eval.add_constraint(is_shuffle_timeout.clone() * value.clone());
        }
        for (left, right) in pre_current.iter().zip(post_current.iter()) {
            eval.add_constraint(is_shuffle_timeout.clone() * (right.clone() - left.clone()));
        }
        for (left, right) in pre_min.iter().zip(post_min.iter()) {
            eval.add_constraint(is_shuffle_timeout.clone() * (right.clone() - left.clone()));
        }
        for (left, right) in pre_total.iter().zip(post_total.iter()) {
            eval.add_constraint(is_shuffle_timeout.clone() * (right.clone() - left.clone()));
        }
        for limb in 0..4 {
            eval.add_constraint(is_shuffle_timeout.clone() * post_stack[limb].clone());
            eval.add_constraint(is_shuffle_timeout.clone() * post_bet[limb].clone());
            eval.add_constraint(is_shuffle_timeout.clone() * post_pending[limb].clone());
            eval.add_constraint(
                is_shuffle_timeout.clone() * (post_total[limb].clone() - pre_total[limb].clone()),
            );
        }
        for limb in 0..2 {
            eval.add_constraint(
                is_shuffle_timeout.clone()
                    * (post_time_bank[limb].clone() - pre_time_bank[limb].clone()),
            );
        }
        // `amount = stack + pending_addon`; the exact carry relation is shared
        // with Rebuy/Leave and is also checked again by the funding block.
        limb4_add_constraints(
            &mut eval,
            &is_shuffle_timeout,
            &pre_stack,
            &pre_pending,
            &amount,
            &funding_rebuy_carries,
        );
        let shuffle_timeout_limbs: [E::F; 4] = [
            pre_timeout_config[0].clone(),
            pre_timeout_config[1].clone(),
            M31::from(0u32).into(),
            M31::from(0u32).into(),
        ];
        limb4_add_constraints(
            &mut eval,
            &is_shuffle_timeout,
            &deadline_height,
            &shuffle_timeout_limbs,
            &post_deadline_image,
            &advance_deadline_extension_carries,
        );
        // Narrow reconstruct-timeout cascade.  It mirrors the VM path where
        // the reconstruct pending mask contains one active seat, at most one
        // other active seat remains, and the hand has no wager/addon ledger.
        // The internal kick cascade then resets before the outer timeout
        // handler reaches its accumulator-presence branch.
        eval.add_constraint(
            is_reconstruct_only.clone() * (pre_phase.clone() - M31::from(3u32).into()),
        );
        eval.add_constraint(
            is_reconstruct_only.clone()
                * (pre_subtag.clone()
                    - M31::from(u32::from(CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG)).into()),
        );
        eval.add_constraint(
            is_reveal_timeout.clone() * (pre_phase.clone() - M31::from(2u32).into()),
        );
        eval.add_constraint(is_reveal_timeout.clone() * (pre_subtag.clone() - one.clone()));
        eval.add_constraint(is_reveal_timeout.clone() * (pre_street.clone() - one.clone()));
        // A non-terminal reveal-timeout row remains in the same reveal
        // header while its selected active pending participant is kicked.
        // The VM runs the kick loop at every reveal street (preflop through
        // showdown), so the row fixes the canonical reveal encoding
        // (`subtag == street`), the phase, and the exact street domain
        // {1..=5}; the preflop/board split is decided by the terminal row.
        let reveal_street_kinds = is_reveal_kick.clone() + is_award_family.clone();
        eval.add_constraint(is_reveal_kick.clone() * (pre_phase.clone() - M31::from(2u32).into()));
        eval.add_constraint(is_reveal_kick.clone() * (pre_subtag.clone() - pre_street.clone()));
        eval.add_constraint(
            reveal_street_kinds.clone()
                * (pre_street.clone()
                    - one.clone()
                    - reveal_kick_street_bits[0].clone()
                    - two.clone() * reveal_kick_street_bits[1].clone()
                    - E::F::from(M31::from(4u32)) * reveal_kick_street_bits[2].clone()),
        );
        for bit in &reveal_kick_street_bits {
            eval.add_constraint(
                reveal_street_kinds.clone() * bit.clone() * (bit.clone() - one.clone()),
            );
            eval.add_constraint((active.clone() - reveal_street_kinds.clone()) * bit.clone());
        }
        // The high bit selects street 5 exactly, excluding 6..=8 from the
        // three-bit decomposition.
        eval.add_constraint(
            reveal_street_kinds.clone()
                * reveal_kick_street_bits[2].clone()
                * reveal_kick_street_bits[0].clone(),
        );
        eval.add_constraint(
            reveal_street_kinds.clone()
                * reveal_kick_street_bits[2].clone()
                * reveal_kick_street_bits[1].clone(),
        );
        eval.add_constraint(is_reveal_kick.clone() * (post_phase.clone() - pre_phase.clone()));
        eval.add_constraint(is_reveal_kick.clone() * (post_subtag.clone() - pre_subtag.clone()));
        eval.add_constraint(is_reveal_kick.clone() * (post_street.clone() - pre_street.clone()));
        eval.add_constraint(is_reveal_kick.clone() * (pre_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_reveal_kick.clone() * (post_turn.clone() - no_seat.clone()));
        eval.add_constraint(
            is_reveal_kick.clone()
                * (pre_status.clone() - M31::from(CanonicalSeatStatus::Active as u32).into()),
        );
        eval.add_constraint(
            is_reveal_kick.clone()
                * (post_status.clone() - M31::from(CanonicalSeatStatus::Out as u32).into()),
        );
        eval.add_constraint(is_reconstruct_timeout.clone() * (pre_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_reconstruct_timeout.clone() * post_phase.clone());
        eval.add_constraint(is_reconstruct_timeout.clone() * post_subtag.clone());
        eval.add_constraint(is_reconstruct_timeout.clone() * post_street.clone());
        eval.add_constraint(is_reconstruct_timeout.clone() * (post_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_reconstruct_timeout.clone() * post_acted_mask.clone());
        eval.add_constraint(is_reconstruct_timeout.clone() * post_leave_mask.clone());
        eval.add_constraint(is_reconstruct_timeout.clone() * post_protocol_pending_mask.clone());
        eval.add_constraint(is_reconstruct_timeout.clone() * pre_leave_mask.clone());
        eval.add_constraint(is_reconstruct_timeout.clone() * post_deadline_image[0].clone());
        eval.add_constraint(is_reconstruct_timeout.clone() * post_deadline_image[1].clone());
        eval.add_constraint(is_reconstruct_timeout.clone() * post_deadline_image[2].clone());
        eval.add_constraint(is_reconstruct_timeout.clone() * post_deadline_image[3].clone());
        for value in [
            &pre_current,
            &pre_min,
            &pre_pot,
            &post_current,
            &post_min,
            &post_pot,
        ] {
            for limb in value {
                eval.add_constraint(is_reconstruct_timeout.clone() * limb.clone());
            }
        }
        let mut timeout_amount_sum: E::F = M31::from(0u32).into();
        for value in &amount {
            timeout_amount_sum += value.clone();
        }
        eval.add_constraint(
            is_reconstruct_timeout.clone()
                * (timeout_amount_sum * amount_inv.clone() - one.clone()),
        );
        // The selected seat is the sole pending protocol bit.
        let mut pending_sum: E::F = M31::from(0u32).into();
        let mut reconstruct_pre_active_count: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let selector = transition_seat_selectors[index].clone();
            pending_sum += pre_protocol_pending_mask_bits[index].clone();
            reconstruct_pre_active_count +=
                full_pre_status[index][CanonicalSeatStatus::Active as usize].clone();
            eval.add_constraint(
                is_reconstruct_timeout.clone()
                    * (pre_protocol_pending_mask_bits[index].clone() - selector.clone()),
            );
            // A terminal reveal-timeout continuation may arrive with seats
            // already marked `Out` by preceding kick rows.  Reconstruct
            // timeout starts from a fresh active/folded/empty image, while
            // reveal reset preserves those prior `Out` markers.
            eval.add_constraint(
                is_reconstruct_only.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                        + full_pre_status[index][CanonicalSeatStatus::Folded as usize].clone()
                        + full_pre_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_reveal_timeout.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                        + full_pre_status[index][CanonicalSeatStatus::Folded as usize].clone()
                        + full_pre_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        + full_pre_status[index][CanonicalSeatStatus::Out as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_reconstruct_timeout.clone()
                    * selector.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_reconstruct_timeout.clone()
                    * selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_reconstruct_timeout.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Active as usize].clone()
                        - (one.clone() - selector.clone())
                            * (full_pre_status[index][CanonicalSeatStatus::Active as usize]
                                .clone()
                                + full_pre_status[index][CanonicalSeatStatus::Folded as usize]
                                    .clone())),
            );
            eval.add_constraint(
                is_reconstruct_only.clone()
                    * full_post_status[index][CanonicalSeatStatus::Out as usize].clone(),
            );
            eval.add_constraint(
                is_reveal_timeout.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Out as usize].clone()
                        - full_pre_status[index][CanonicalSeatStatus::Out as usize].clone()),
            );
            eval.add_constraint(
                is_reconstruct_timeout.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - full_pre_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - selector.clone()),
            );
            for limb in 0..4 {
                eval.add_constraint(
                    is_reconstruct_timeout.clone()
                        * (full_pre_bet[index][limb].clone()
                            + full_pre_total[index][limb].clone()
                            + full_pre_pending[index][limb].clone()),
                );
                eval.add_constraint(
                    is_reconstruct_timeout.clone() * full_post_bet[index][limb].clone(),
                );
                eval.add_constraint(
                    is_reconstruct_timeout.clone() * full_post_total[index][limb].clone(),
                );
                eval.add_constraint(
                    is_reconstruct_timeout.clone() * full_post_pending[index][limb].clone(),
                );
                eval.add_constraint(
                    is_reconstruct_timeout.clone()
                        * (full_post_stack[index][limb].clone()
                            - full_pre_stack[index][limb].clone()
                            + selector.clone() * amount[limb].clone()),
                );
            }
            for status in [
                CanonicalSeatStatus::Waiting,
                CanonicalSeatStatus::AllIn,
                CanonicalSeatStatus::Out,
                CanonicalSeatStatus::Folded,
            ] {
                eval.add_constraint(
                    is_reconstruct_only.clone() * full_post_status[index][status as usize].clone(),
                );
            }
            for status in [
                CanonicalSeatStatus::Waiting,
                CanonicalSeatStatus::AllIn,
                CanonicalSeatStatus::Folded,
            ] {
                eval.add_constraint(
                    is_reveal_timeout.clone() * full_post_status[index][status as usize].clone(),
                );
            }
            eval.add_constraint(is_reconstruct_timeout.clone() * post_acted_bits[index].clone());
            eval.add_constraint(
                is_reconstruct_timeout.clone()
                    * (post_leave_mask_bits[index].clone() - pre_leave_mask_bits[index].clone()),
            );
            eval.add_constraint(
                is_reconstruct_timeout.clone()
                    * (full_post_time_bank[index][0].clone()
                        - E::F::from(M31::from(30_000u32))
                            * (one.clone()
                                - full_post_status[index][CanonicalSeatStatus::Empty as usize]
                                    .clone())),
            );
            eval.add_constraint(
                is_reconstruct_timeout.clone() * full_post_time_bank[index][1].clone(),
            );
            eval.add_constraint(
                is_reconstruct_timeout.clone()
                    * (full_pre_time_bank[index][0].clone()
                        - E::F::from(M31::from(30_000u32))
                            * (one.clone()
                                - full_pre_status[index][CanonicalSeatStatus::Empty as usize]
                                    .clone())),
            );
            eval.add_constraint(
                is_reconstruct_timeout.clone() * full_pre_time_bank[index][1].clone(),
            );
            for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                for limb in 0..16 {
                    let expected = match commitment {
                        0 | 1 => {
                            (one.clone() - selector.clone())
                                * pre_seat_commitments[index][commitment][limb].clone()
                        }
                        _ => M31::from(0u32).into(),
                    };
                    eval.add_constraint(
                        is_reconstruct_timeout.clone()
                            * (post_seat_commitments[index][commitment][limb].clone() - expected),
                    );
                }
            }
        }
        eval.add_constraint(is_reconstruct_timeout.clone() * (pending_sum.clone() - one.clone()));
        // Reconstruct timeout has a narrow one/two-active reset endpoint.
        // Preflop reveal timeout differs in the VM: it kicks the complete
        // pending union and then resets even when three or more non-pending
        // active seats remain, so that population bound is reconstruct-only.
        eval.add_constraint(
            is_reconstruct_only.clone()
                * (reconstruct_pre_active_count.clone() - one.clone())
                * (reconstruct_pre_active_count - M31::from(2u32).into()),
        );
        limb4_add_constraints(
            &mut eval,
            &is_reconstruct_timeout,
            &post_chip_pool,
            &amount,
            &pre_chip_pool,
            &funding_rebuy_carries,
        );

        // Non-preflop reveal timeout: the last pending seat is kicked by the
        // shared internal primitive, the reveal ledger is suspended, and the
        // table enters reconstruct collection with a freshly armed deadline.
        // Every relation below is field-checked; none of it is host advice.
        eval.add_constraint(
            is_reveal_reconstruct.clone() * (pre_phase.clone() - M31::from(2u32).into()),
        );
        eval.add_constraint(
            is_reveal_reconstruct.clone() * (pre_subtag.clone() - pre_street.clone()),
        );
        // The board reveal streets are exactly 2..=5 (flop, turn, river,
        // showdown).  Two binary bits range the street so a preflop or
        // waiting street cannot reach the reconstruct continuation.
        eval.add_constraint(
            is_reveal_reconstruct.clone()
                * (pre_street.clone()
                    - two.clone()
                    - reveal_reconstruct_street_bits[0].clone()
                    - two.clone() * reveal_reconstruct_street_bits[1].clone()),
        );
        for bit in &reveal_reconstruct_street_bits {
            eval.add_constraint(
                is_reveal_reconstruct.clone() * bit.clone() * (bit.clone() - one.clone()),
            );
            eval.add_constraint((active.clone() - is_reveal_reconstruct.clone()) * bit.clone());
        }
        eval.add_constraint(is_reveal_reconstruct.clone() * (pre_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_reveal_reconstruct.clone() * (post_turn.clone() - no_seat.clone()));
        eval.add_constraint(
            is_reveal_reconstruct.clone() * (post_phase.clone() - M31::from(3u32).into()),
        );
        eval.add_constraint(
            is_reveal_reconstruct.clone()
                * (post_subtag.clone()
                    - M31::from(u32::from(CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG)).into()),
        );
        eval.add_constraint(
            is_reveal_reconstruct.clone() * (post_street.clone() - pre_street.clone()),
        );
        eval.add_constraint(is_reveal_reconstruct.clone() * flag.clone());
        for value in &auxiliary {
            eval.add_constraint(is_reveal_reconstruct.clone() * value.clone());
        }
        for (pre_value, post_value) in [(&pre_current, &post_current), (&pre_min, &post_min)] {
            for (left, right) in pre_value.iter().zip(post_value.iter()) {
                eval.add_constraint(is_reveal_reconstruct.clone() * (right.clone() - left.clone()));
            }
        }
        // Board, deck, suspended reveal, and run-it-twice state is preserved
        // verbatim; only the reconstruction commitment moves, to a non-zero
        // value that differs from the pre image.
        for commitment in [0usize, 1, 2, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_reveal_reconstruct.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        for limb in 0..16 {
            eval.add_constraint(
                is_reveal_reconstruct.clone()
                    * (post_opaque_commitments[3][limb].clone() - proof_commitment[limb].clone()),
            );
        }
        let mut reconstruct_post_commitment_sum: E::F = M31::from(0u32).into();
        let mut reconstruct_commitment_difference_square_sum: E::F = M31::from(0u32).into();
        for limb in 0..16 {
            reconstruct_post_commitment_sum += post_opaque_commitments[3][limb].clone();
            let difference =
                post_opaque_commitments[3][limb].clone() - pre_opaque_commitments[3][limb].clone();
            reconstruct_commitment_difference_square_sum += difference.clone() * difference;
        }
        eval.add_constraint(
            is_reveal_reconstruct.clone()
                * (reconstruct_commitment_difference_square_sum
                    - reveal_reconstruct_diff_square_sum.clone()),
        );
        eval.add_constraint(
            is_reveal_reconstruct.clone()
                * (reconstruct_post_commitment_sum * reveal_reconstruct_diff_square_sum.clone()
                    - reveal_reconstruct_change_product.clone()),
        );
        eval.add_constraint(
            is_reveal_reconstruct.clone()
                * (reveal_reconstruct_change_product.clone()
                    * reveal_reconstruct_change_inv.clone()
                    - one.clone()),
        );
        // The terminal seat leaves with the same kick shape as every prefix
        // row: stack, live bet, and pending addon are vacated into the refund
        // and the pot, while the historical ledger fields are preserved.
        eval.add_constraint(
            is_reveal_reconstruct.clone()
                * (pre_status.clone() - M31::from(CanonicalSeatStatus::Active as u32).into()),
        );
        eval.add_constraint(
            is_reveal_reconstruct.clone()
                * (post_status.clone() - M31::from(CanonicalSeatStatus::Out as u32).into()),
        );
        for limb in 0..4 {
            eval.add_constraint(is_reveal_reconstruct.clone() * post_stack[limb].clone());
            eval.add_constraint(is_reveal_reconstruct.clone() * post_bet[limb].clone());
            eval.add_constraint(is_reveal_reconstruct.clone() * post_pending[limb].clone());
            eval.add_constraint(
                is_reveal_reconstruct.clone()
                    * (post_total[limb].clone() - pre_total[limb].clone()),
            );
        }
        for limb in 0..2 {
            eval.add_constraint(
                is_reveal_reconstruct.clone()
                    * (post_time_bank[limb].clone() - pre_time_bank[limb].clone()),
            );
        }
        // The reconstruct deadline is armed from the committed consensus
        // height plus the reconstruct timeout configuration.
        let reconstruct_timeout_limbs: [E::F; 4] = [
            pre_timeout_config[6].clone(),
            pre_timeout_config[7].clone(),
            M31::from(0u32).into(),
            M31::from(0u32).into(),
        ];
        limb4_add_constraints(
            &mut eval,
            &is_reveal_reconstruct,
            &deadline_height,
            &reconstruct_timeout_limbs,
            &post_deadline_image,
            &advance_deadline_extension_carries,
        );
        // The acted and leave-after-hand masks clear exactly the kicked bit;
        // a bit that was already clear stays clear.
        for index in 0..MAX_CANONICAL_SEATS {
            let selector = transition_seat_selectors[index].clone();
            eval.add_constraint(
                is_reveal_reconstruct.clone()
                    * (post_acted_bits[index].clone()
                        - pre_acted_bits[index].clone() * (one.clone() - selector.clone())),
            );
            eval.add_constraint(
                is_reveal_reconstruct.clone()
                    * (post_leave_mask_bits[index].clone()
                        - pre_leave_mask_bits[index].clone() * (one.clone() - selector.clone())),
            );
            eval.add_constraint(
                is_reveal_kick.clone()
                    * (post_acted_bits[index].clone()
                        - pre_acted_bits[index].clone() * (one.clone() - selector.clone())),
            );
            eval.add_constraint(
                is_reveal_kick.clone()
                    * (post_leave_mask_bits[index].clone()
                        - pre_leave_mask_bits[index].clone() * (one.clone() - selector)),
            );
        }
        // At least two live players remain and the reconstruct pending mask
        // is the VM's active-seat mask over the post image.
        let mut reveal_reconstruct_live_count: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            reveal_reconstruct_live_count +=
                full_post_status[index][CanonicalSeatStatus::Active as usize].clone()
                    + full_post_status[index][CanonicalSeatStatus::AllIn as usize].clone();
        }
        eval.add_constraint(
            is_reveal_reconstruct.clone()
                * (reveal_reconstruct_live_product.clone()
                    - reveal_reconstruct_live_count.clone()
                        * (reveal_reconstruct_live_count.clone() - one.clone())),
        );
        eval.add_constraint(
            is_reveal_reconstruct.clone()
                * (reveal_reconstruct_live_product.clone() * reveal_reconstruct_live_inv.clone()
                    - one.clone()),
        );
        for value in [
            &reveal_reconstruct_diff_square_sum,
            &reveal_reconstruct_change_product,
            &reveal_reconstruct_change_inv,
            &reveal_reconstruct_live_product,
            &reveal_reconstruct_live_inv,
        ] {
            eval.add_constraint((active.clone() - is_reveal_reconstruct.clone()) * value.clone());
        }

        // Sole-survivor reveal timeout: the final pending participant is
        // kicked and the complete pot is awarded to the one remaining live
        // player (`end_without_showdown`, zero-rake branch only).  The winner
        // credit is proven as a one-hot subset of the live seats that is
        // disjoint from the kicked-seat selector, so with exactly two live
        // seats the two singletons partition the live set.
        eval.add_constraint(is_award_family.clone() * (pre_phase.clone() - M31::from(2u32).into()));
        eval.add_constraint(is_award_family.clone() * (pre_subtag.clone() - pre_street.clone()));
        eval.add_constraint(is_award_family.clone() * (pre_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_award_family.clone() * (post_turn.clone() - no_seat.clone()));
        for (_pre, post) in [
            (&pre_subtag, &post_subtag),
            (&pre_leave_mask, &post_leave_mask),
        ] {
            eval.add_constraint(is_award_family.clone() * post.clone());
        }
        eval.add_constraint(is_award_family.clone() * (pre_leave_mask.clone()));
        eval.add_constraint(is_award_family.clone() * flag.clone());
        for value in &auxiliary {
            eval.add_constraint(is_award_family.clone() * value.clone());
        }
        for (pre, post) in [(&pre_current, &post_current), (&pre_min, &post_min)] {
            for limb in pre.iter().zip(post.iter()) {
                eval.add_constraint(is_award_family.clone() * limb.0.clone());
                eval.add_constraint(is_award_family.clone() * limb.1.clone());
            }
        }
        // The award endpoint is the same cleared waiting header as the other
        // terminals, carrying a fresh non-zero deck commitment.
        eval.add_constraint(is_award_family.clone() * post_phase.clone());
        eval.add_constraint(is_award_family.clone() * post_street.clone());
        for value in [&post_acted_mask, &post_protocol_pending_mask] {
            eval.add_constraint(is_award_family.clone() * value.clone());
        }
        for value in [&post_min, &post_pot] {
            for limb in value {
                eval.add_constraint(is_award_family.clone() * limb.clone());
            }
        }
        for limb in &post_deadline_image {
            eval.add_constraint(is_award_family.clone() * limb.clone());
        }
        for commitment in [0usize, 2, 3, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_award_family.clone() * post_opaque_commitments[commitment][limb].clone(),
                );
                eval.add_constraint(
                    is_award_family.clone()
                        * (post_opaque_commitments[1][limb].clone()
                            - proof_commitment[limb].clone()),
                );
            }
        }
        // The kicked seat is vacated exactly like every other terminal kick.
        eval.add_constraint(
            is_award_family.clone()
                * (pre_status.clone() - M31::from(CanonicalSeatStatus::Active as u32).into()),
        );
        for limb in 0..4 {
            eval.add_constraint(is_award_family.clone() * post_stack[limb].clone());
            eval.add_constraint(is_award_family.clone() * post_bet[limb].clone());
            eval.add_constraint(is_award_family.clone() * post_pending[limb].clone());
        }
        let mut award_live_count: E::F = M31::from(0u32).into();
        let mut award_pot_sum: E::F = M31::from(0u32).into();
        let mut award_credit_sum: E::F = M31::from(0u32).into();
        for limb in &pre_pot {
            award_pot_sum += limb.clone();
        }
        eval.add_constraint(
            is_award_family.clone()
                * (award_pot_sum.clone() * reveal_award_pot_inv.clone() - one.clone()),
        );
        eval.add_constraint(
            (active.clone() - is_award_family.clone()) * reveal_award_pot_inv.clone(),
        );
        for index in 0..MAX_CANONICAL_SEATS {
            let selector = transition_seat_selectors[index].clone();
            let credit = reveal_award_winner_credit[index].clone();
            let live = full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                + full_pre_status[index][CanonicalSeatStatus::AllIn as usize].clone();
            award_live_count += live.clone();
            award_credit_sum += credit.clone();
            // The credit is a binary one-hot over live seats, disjoint from
            // the kicked-seat selector.
            eval.add_constraint(
                is_award_family.clone() * credit.clone() * (credit.clone() - one.clone()),
            );
            eval.add_constraint(is_award_family.clone() * credit.clone() * selector.clone());
            eval.add_constraint(
                is_award_family.clone() * credit.clone() * (one.clone() - live.clone()),
            );
            eval.add_constraint(
                is_award_family.clone() * selector.clone() * (live.clone() - one.clone()),
            );
            // Kicked seat vacated, winner credited with the whole pot, every
            // other retained seat keeps its stack but drops the hand-local
            // ledger.
            for limb in 0..4 {
                eval.add_constraint(
                    is_reveal_award.clone()
                        * credit.clone()
                        * (full_post_stack[index][limb].clone()
                            - full_pre_stack[index][limb].clone()
                            - pre_pot[limb].clone()),
                );
                eval.add_constraint(
                    is_award_family.clone()
                        * (one.clone() - credit.clone() - selector.clone())
                        * (full_post_stack[index][limb].clone()
                            - full_pre_stack[index][limb].clone()),
                );
                eval.add_constraint(
                    is_award_family.clone()
                        * (one.clone() - credit.clone() - selector.clone())
                        * full_pre_pending[index][limb].clone(),
                );
                eval.add_constraint(is_award_family.clone() * full_post_bet[index][limb].clone());
                eval.add_constraint(is_award_family.clone() * full_post_total[index][limb].clone());
                eval.add_constraint(
                    is_award_family.clone() * full_post_pending[index][limb].clone(),
                );
            }
            // The retained seats return to the terminal Active/Empty shape;
            // the reset clears acted bits and hole cards while preserving
            // identity and key commitments.
            // Retained seats return to Active; Empty and earlier-kicked Out
            // seats end Empty (the reset vacates departed seats).  The
            // terminal kick selector and a prior `Out` marker are disjoint
            // binary flags, so their sum is the single vacated indicator.
            let vacated = selector.clone()
                + full_pre_status[index][CanonicalSeatStatus::Out as usize].clone();
            eval.add_constraint(
                is_award_family.clone() * vacated.clone() * (vacated.clone() - one.clone()),
            );
            eval.add_constraint(
                is_award_family.clone()
                    * (one.clone() - vacated.clone())
                    * (full_post_status[index][CanonicalSeatStatus::Active as usize].clone()
                        - (one.clone()
                            - full_pre_status[index][CanonicalSeatStatus::Empty as usize].clone())),
            );
            eval.add_constraint(
                is_award_family.clone()
                    * vacated.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - one.clone()),
            );
            for status in [
                CanonicalSeatStatus::Folded,
                CanonicalSeatStatus::AllIn,
                CanonicalSeatStatus::Out,
                CanonicalSeatStatus::Waiting,
            ] {
                eval.add_constraint(
                    is_award_family.clone() * full_post_status[index][status as usize].clone(),
                );
            }
            eval.add_constraint(is_award_family.clone() * post_acted_bits[index].clone());
            eval.add_constraint(
                is_award_family.clone()
                    * (full_pre_time_bank[index][0].clone()
                        - E::F::from(M31::from(30_000u32))
                            * (one.clone()
                                - full_pre_status[index][CanonicalSeatStatus::Empty as usize]
                                    .clone())),
            );
            eval.add_constraint(is_award_family.clone() * full_pre_time_bank[index][1].clone());
            for limb in 0..2 {
                eval.add_constraint(
                    is_award_family.clone()
                        * (one.clone() - vacated.clone())
                        * (full_post_time_bank[index][limb].clone()
                            - full_pre_time_bank[index][limb].clone()),
                );
                eval.add_constraint(
                    is_award_family.clone()
                        * vacated.clone()
                        * full_post_time_bank[index][limb].clone(),
                );
            }
            for limb in 0..16 {
                // Retained seats preserve identity and key commitments and
                // drop their hole-card commitment; every vacated seat clears
                // all commitment fields.
                eval.add_constraint(
                    is_award_family.clone()
                        * (one.clone() - vacated.clone())
                        * (post_seat_commitments[index][0][limb].clone()
                            - pre_seat_commitments[index][0][limb].clone()),
                );
                eval.add_constraint(
                    is_award_family.clone()
                        * (one.clone() - vacated.clone())
                        * (post_seat_commitments[index][1][limb].clone()
                            - pre_seat_commitments[index][1][limb].clone()),
                );
                eval.add_constraint(
                    is_award_family.clone() * post_seat_commitments[index][2][limb].clone(),
                );
                for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                    eval.add_constraint(
                        is_award_family.clone()
                            * vacated.clone()
                            * post_seat_commitments[index][commitment][limb].clone(),
                    );
                }
            }
        }
        // Exactly two live seats (the kicked participant and the survivor)
        // and exactly one winner credit.
        eval.add_constraint(is_award_family.clone() * (award_live_count.clone() - two.clone()));
        eval.add_constraint(is_award_family.clone() * (award_credit_sum - one.clone()));

        // Raked sole-survivor award.  Every shared zero-rake relation above is
        // duplicated for the raked selector with the two raked differences:
        // the winner is credited `pot - rake` and the rake itself leaves the
        // table vault.  The rake configuration is bound to the public
        // authenticated scope columns; the arithmetic proves the exact
        // `min(floor(pot * bps / 10_000), cap)` value with 16-bit limb
        // decompositions, so no limb can wrap in M31.
        // AutoFold consumes the expired betting deadline, folds the selected
        // actor through the shared betting relation, and arms the next
        // actor's fixed deployment timeout from the committed height.
        eval.add_constraint(is_auto_fold.clone() * (pre_phase.clone() - M31::from(4u32).into()));
        eval.add_constraint(is_auto_fold.clone() * (post_phase.clone() - pre_phase.clone()));
        eval.add_constraint(is_auto_fold.clone() * (pre_turn.clone() - seat.clone()));
        eval.add_constraint(
            is_auto_fold.clone()
                * (pre_status.clone() - M31::from(CanonicalSeatStatus::Active as u32).into()),
        );
        eval.add_constraint(is_auto_fold.clone() * (post_status.clone() - M31::from(3u32).into()));
        eval.add_constraint(is_auto_fold.clone() * flag.clone());
        for value in amount.iter().chain(auxiliary.iter()) {
            eval.add_constraint(is_auto_fold.clone() * value.clone());
        }
        for (pre_value, post_value) in [
            (&pre_current, &post_current),
            (&pre_min, &post_min),
            (&pre_pot, &post_pot),
            (&pre_chip_pool, &post_chip_pool),
        ] {
            for (left, right) in pre_value.iter().zip(post_value.iter()) {
                eval.add_constraint(is_auto_fold.clone() * (right.clone() - left.clone()));
            }
        }
        for (left, right) in [
            (&pre_subtag, &post_subtag),
            (&pre_street, &post_street),
            (&pre_leave_mask, &post_leave_mask),
        ] {
            eval.add_constraint(is_auto_fold.clone() * (right.clone() - left.clone()));
        }
        limb4_add_constraints(
            &mut eval,
            &is_auto_fold,
            &deadline_height,
            &[
                pre_timeout_config[BETTING_TIMEOUT_LIMB_OFFSET].clone(),
                pre_timeout_config[BETTING_TIMEOUT_LIMB_OFFSET + 1].clone(),
                M31::from(0u32).into(),
                M31::from(0u32).into(),
            ],
            &post_deadline_image,
            &advance_deadline_extension_carries,
        );

        let timeout_limbs: [E::F; 2] = [
            pre_timeout_config[BETTING_TIMEOUT_LIMB_OFFSET].clone(),
            pre_timeout_config[BETTING_TIMEOUT_LIMB_OFFSET + 1].clone(),
        ];
        let consume_all = advance_deadline_time_bank_all.clone();
        // The selected transition time-bank projection is consumed by the
        // deadline arithmetic below. The selector loop later emits the remaining
        // seat projections and must not add these values a second time.
        for index in 0..MAX_CANONICAL_SEATS {
            let selector = transition_seat_selectors[index].clone();
            for limb in 0..2 {
                selected_transition_pre_time[limb] +=
                    selector.clone() * full_pre_time_bank[index][limb].clone();
                selected_transition_post_time[limb] +=
                    selector.clone() * full_post_time_bank[index][limb].clone();
            }
        }
        eval.add_constraint(
            consume_all_gate.clone() - is_deadline_extension.clone() * consume_all.clone(),
        );
        eval.add_constraint(
            partial_gate.clone()
                - is_deadline_extension.clone() * (one.clone() - consume_all.clone()),
        );
        eval.add_constraint(
            is_deadline_extension.clone()
                * consume_all.clone()
                * (consume_all.clone() - one.clone()),
        );
        eval.add_constraint((active.clone() - is_deadline_extension.clone()) * consume_all.clone());
        for (value, bits) in advance_deadline_time_bank_slack
            .iter()
            .zip(advance_deadline_time_bank_range_bits[0].iter())
            .chain(
                advance_deadline_time_bank_excess
                    .iter()
                    .zip(advance_deadline_time_bank_range_bits[1].iter()),
            )
        {
            range16_constraints(&mut eval, &is_deadline_extension, value, bits);
        }
        limb2_add_constraints(
            &mut eval,
            &consume_all_gate,
            &selected_transition_pre_time,
            &advance_deadline_time_bank_slack,
            &timeout_limbs,
            &advance_deadline_time_bank_carries[0],
        );
        limb2_add_constraints(
            &mut eval,
            &partial_gate,
            &timeout_limbs,
            &advance_deadline_time_bank_excess,
            &selected_transition_pre_time,
            &advance_deadline_time_bank_carries[1],
        );
        let amount_low = [amount[0].clone(), amount[1].clone()];
        limb2_add_constraints(
            &mut eval,
            &is_deadline_extension,
            &selected_transition_post_time,
            &amount_low,
            &selected_transition_pre_time,
            &advance_deadline_time_bank_carries[2],
        );
        for limb in 0..2 {
            eval.add_constraint(
                consume_all_gate.clone()
                    * (amount[limb].clone() - selected_transition_pre_time[limb].clone()),
            );
            eval.add_constraint(
                partial_gate.clone() * (amount[limb].clone() - timeout_limbs[limb].clone()),
            );
            eval.add_constraint(
                consume_all_gate.clone() * selected_transition_post_time[limb].clone(),
            );
            eval.add_constraint(
                consume_all_gate.clone() * advance_deadline_time_bank_excess[limb].clone(),
            );
            eval.add_constraint(
                partial_gate.clone() * advance_deadline_time_bank_slack[limb].clone(),
            );
        }
        let chip_action = is_check.clone() + is_call.clone() + is_raise.clone() + is_bet.clone();
        for (pre, post) in pre_chip_pool.iter().zip(post_chip_pool.iter()) {
            eval.add_constraint(is_betting.clone() * (post.clone() - pre.clone()));
        }
        // `advance_round` is a VM micro-step after the final betting action.
        // It is deliberately a separate tagged row so its all-seat pot
        // collection is visible to the AIR instead of being hidden behind an
        // unconstrained post-action reveal commitment.
        eval.add_constraint(
            is_round_advance.clone() * (pre_phase.clone() - M31::from(4u32).into()),
        );
        eval.add_constraint(
            is_round_advance.clone() * (post_phase.clone() - M31::from(2u32).into()),
        );
        eval.add_constraint(is_round_advance.clone() * (pre_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_round_advance.clone() * (post_turn.clone() - no_seat.clone()));
        eval.add_constraint(
            is_round_advance.clone() * (post_street.clone() - pre_street.clone() - one.clone()),
        );
        for value in post_current.iter().chain(post_min.iter()) {
            eval.add_constraint(is_round_advance.clone() * value.clone());
        }
        eval.add_constraint(
            is_round_advance.clone() * (post_acted_mask.clone() - pre_acted_mask.clone()),
        );
        eval.add_constraint(
            is_round_advance.clone() * (post_leave_mask.clone() - pre_leave_mask.clone()),
        );
        for (pre, post) in pre_chip_pool.iter().zip(post_chip_pool.iter()) {
            eval.add_constraint(is_round_advance.clone() * (post.clone() - pre.clone()));
        }
        for index in 0..MAX_CANONICAL_SEATS {
            for limb in 0..4 {
                range16_constraints(
                    &mut eval,
                    &(is_round_advance.clone() + is_end_without_showdown.clone()),
                    &full_pre_bet[index][limb],
                    &round_collect_bet_bits[index][limb],
                );
                eval.add_constraint(is_round_advance.clone() * full_post_bet[index][limb].clone());
            }
            for status in 0..SEAT_STATUS_COUNT {
                eval.add_constraint(
                    is_round_advance.clone()
                        * (full_post_status[index][status].clone()
                            - full_pre_status[index][status].clone()),
                );
            }
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(is_round_advance.clone() * (right.clone() - left.clone()));
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(is_round_advance.clone() * (right.clone() - left.clone()));
            }
        }
        // Fixed VM board-reveal schedule.  The six selectors represent
        // (preflop, flop, turn) × (single runout, run-it-twice); this keeps the
        // schedule quadratic and avoids trusting a host-provided branch or
        // variable-length assignment vector.
        let schedule_profiles = [
            // pre street, RIT, cards allocated, first-board length,
            // second-board length, assignment count, cards per runout.
            (1u32, 0u32, 3u32, 0u32, 0u32, 3u32, 3usize),
            (1, 1, 6, 0, 0, 6, 3),
            (2, 0, 1, 3, 0, 1, 1),
            (2, 1, 2, 3, 3, 2, 1),
            (3, 0, 1, 4, 0, 1, 1),
            (3, 1, 2, 4, 4, 2, 1),
            // #22②扩展：摊牌窗口 advance（river 轮收注 → ShowdownOwner
            // 窗口开启）。cards=0（摊牌复用已发牌，deck 游标不动）、
            // assignment count=0（摊牌逐座 token 的 pending 演化由状态
            // 镜像的 pending 掩码承担，openings 不携带 hole 槽位）。
            (4, 0, 0, 5, 0, 0, 1),
        ];
        let mut selector_sum: E::F = M31::from(0u32).into();
        let mut expected_street: E::F = M31::from(0u32).into();
        let mut expected_rit: E::F = M31::from(0u32).into();
        let mut expected_cards: E::F = M31::from(0u32).into();
        let mut expected_first_len: E::F = M31::from(0u32).into();
        let mut expected_second_len: E::F = M31::from(0u32).into();
        let mut expected_count: E::F = M31::from(0u32).into();
        for (selector, profile) in round_schedule_selectors.iter().zip(schedule_profiles) {
            let street: E::F = M31::from(profile.0).into();
            let run_it_twice: E::F = M31::from(profile.1).into();
            let cards: E::F = M31::from(profile.2).into();
            let first_len: E::F = M31::from(profile.3).into();
            let second_len: E::F = M31::from(profile.4).into();
            let assignment_count: E::F = M31::from(profile.5).into();
            eval.add_constraint(
                active.clone() * selector.clone() * (selector.clone() - one.clone()),
            );
            eval.add_constraint((active.clone() - is_round_advance.clone()) * selector.clone());
            selector_sum += selector.clone();
            expected_street += selector.clone() * street;
            expected_rit += selector.clone() * run_it_twice;
            expected_cards += selector.clone() * cards;
            expected_first_len += selector.clone() * first_len;
            expected_second_len += selector.clone() * second_len;
            expected_count += selector.clone() * assignment_count;
        }
        eval.add_constraint(selector_sum - is_round_advance.clone());
        eval.add_constraint(is_round_advance.clone() * (pre_street.clone() - expected_street));
        eval.add_constraint(round_run_it_twice.clone() - expected_rit);
        eval.add_constraint(round_pre_board_len.clone() - expected_first_len.clone());
        eval.add_constraint(round_post_board_len.clone() - expected_first_len);
        eval.add_constraint(round_pre_second_board_len.clone() - expected_second_len.clone());
        eval.add_constraint(round_post_second_board_len.clone() - expected_second_len);
        eval.add_constraint(round_assignment_count.clone() - expected_count.clone());
        eval.add_constraint(
            round_post_cards_dealt.clone() - round_pre_cards_dealt.clone() - expected_count,
        );
        // 窗口 purpose ∈ {Board=2, ShowdownOwner=3}，post subtag 与之一致。
        eval.add_constraint(
            is_round_advance.clone()
                * (round_reveal_purpose.clone() - M31::from(2u32).into())
                * (round_reveal_purpose.clone() - M31::from(3u32).into()),
        );
        eval.add_constraint(
            is_round_advance.clone() * (post_subtag.clone() - round_reveal_purpose.clone()),
        );
        // Both deck cursors are native 6-bit values in the closed interval
        // [0, 52].  `cursor + complement = 52` is checked bit-by-bit with
        // constrained carries, so this relation remains sound even when a
        // malicious prover bypasses `CanonicalTransitionWitness::validate_shape`.
        for cursor_index in 0..2 {
            let cursor = if cursor_index == 0 {
                round_pre_cards_dealt.clone()
            } else {
                round_post_cards_dealt.clone()
            };
            let mut reconstructed: E::F = M31::from(0u32).into();
            let mut carry_in: E::F = M31::from(0u32).into();
            for bit_index in 0..6 {
                let cursor_bit = round_card_cursor_range[cursor_index][0][bit_index].clone();
                let remaining_bit = round_card_cursor_range[cursor_index][1][bit_index].clone();
                let carry_out = round_card_cursor_range[cursor_index][2][bit_index].clone();
                for value in [&cursor_bit, &remaining_bit, &carry_out] {
                    eval.add_constraint(
                        active.clone() * value.clone() * (value.clone() - one.clone()),
                    );
                    eval.add_constraint(
                        (active.clone() - is_round_advance.clone()) * value.clone(),
                    );
                }
                let weight: E::F = M31::from(1u32 << bit_index).into();
                let constant_bit: E::F = M31::from((52u32 >> bit_index) & 1).into();
                let two: E::F = M31::from(2u32).into();
                reconstructed += cursor_bit.clone() * weight;
                eval.add_constraint(
                    is_round_advance.clone()
                        * (cursor_bit + remaining_bit + carry_in
                            - constant_bit
                            - two * carry_out.clone()),
                );
                carry_in = carry_out;
            }
            eval.add_constraint(is_round_advance.clone() * (cursor - reconstructed));
            eval.add_constraint(is_round_advance.clone() * carry_in);
        }
        for value in [
            round_pre_cards_dealt.clone(),
            round_post_cards_dealt.clone(),
            round_pre_board_len.clone(),
            round_post_board_len.clone(),
            round_pre_second_board_len.clone(),
            round_post_second_board_len.clone(),
            round_run_it_twice.clone(),
            round_reveal_purpose.clone(),
            round_assignment_count.clone(),
        ] {
            eval.add_constraint((active.clone() - is_round_advance.clone()) * value);
        }
        let mut expected_pending_mask: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let weight: E::F = M31::from(1u32 << index).into();
            let active_or_folded_or_all_in =
                full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                    + full_pre_status[index][CanonicalSeatStatus::Folded as usize].clone()
                    + full_pre_status[index][CanonicalSeatStatus::AllIn as usize].clone();
            expected_pending_mask += active_or_folded_or_all_in * weight;
        }
        for index in 0..MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS {
            let present = round_assignments[index][0].clone();
            let encrypted_index = round_assignments[index][1].clone();
            let runout_index = round_assignments[index][2].clone();
            let board_position = round_assignments[index][3].clone();
            let pending_mask = round_assignments[index][4].clone();
            let submitted_mask = round_assignments[index][5].clone();
            let mut expected_present: E::F = M31::from(0u32).into();
            let mut expected_runout: E::F = M31::from(0u32).into();
            let mut expected_position: E::F = M31::from(0u32).into();
            for (selector, profile) in round_schedule_selectors.iter().zip(schedule_profiles) {
                let assignment_count = profile.5 as usize;
                if index < assignment_count {
                    expected_present += selector.clone();
                    let runout = u32::from(index >= profile.6);
                    let offset = (index % profile.6) as u32;
                    let board_len = if runout == 0 { profile.3 } else { profile.4 };
                    let runout_value: E::F = M31::from(runout).into();
                    let position_value: E::F = M31::from(board_len + offset).into();
                    expected_runout += selector.clone() * runout_value;
                    expected_position += selector.clone() * position_value;
                }
            }
            eval.add_constraint(present.clone() - expected_present);
            eval.add_constraint(submitted_mask.clone());
            let absent = one.clone() - present.clone();
            for value in [
                encrypted_index.clone(),
                runout_index.clone(),
                board_position.clone(),
                pending_mask.clone(),
            ] {
                eval.add_constraint(absent.clone() * value);
            }
            eval.add_constraint(
                present.clone()
                    * (encrypted_index
                        - round_pre_cards_dealt.clone()
                        - M31::from(index as u32).into()),
            );
            eval.add_constraint(present.clone() * (runout_index - expected_runout));
            eval.add_constraint(present.clone() * (board_position - expected_position));
            eval.add_constraint(present * (pending_mask - expected_pending_mask.clone()));
        }
        for (carry, bits) in round_collect_carries
            .iter()
            .zip(round_collect_carry_bits.iter())
        {
            let mut reconstructed: E::F = M31::from(0u32).into();
            for (bit, weight) in bits.iter().zip([1u32, 2, 4, 8]) {
                eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                eval.add_constraint(
                    (active.clone() - is_round_advance.clone() - is_end_without_showdown.clone())
                        * bit.clone(),
                );
                let weight: E::F = M31::from(weight).into();
                reconstructed += bit.clone() * weight;
            }
            eval.add_constraint(carry.clone() - reconstructed);
            eval.add_constraint(
                (active.clone() - is_round_advance.clone() - is_end_without_showdown.clone())
                    * carry.clone(),
            );
        }
        let round_base: E::F = M31::from(65536u32).into();
        for limb in 0..4 {
            let mut sum = pre_pot[limb].clone();
            for index in 0..MAX_CANONICAL_SEATS {
                sum += full_pre_bet[index][limb].clone();
            }
            if limb > 0 {
                sum += round_collect_carries[limb - 1].clone();
            }
            if limb < 3 {
                eval.add_constraint(
                    is_round_advance.clone()
                        * (sum
                            - post_pot[limb].clone()
                            - round_base.clone() * round_collect_carries[limb].clone()),
                );
            } else {
                // No final carry is admitted: this is exactly the VM's
                // checked `pot + sum(bets)` overflow rejection.
                eval.add_constraint(is_round_advance.clone() * (sum - post_pot[limb].clone()));
            }
        }
        // A terminal no-showdown row performs the same checked collection as
        // AdvanceRound, but its result is paid directly to the selected
        // winner and the endpoint is the next-hand waiting image.  The
        // action amount is the sole award; auxiliary is the (narrowly
        // disabled) rake field and is constrained to zero below.
        for limb in 0..4 {
            let mut sum = pre_pot[limb].clone();
            for index in 0..MAX_CANONICAL_SEATS {
                sum += full_pre_bet[index][limb].clone();
            }
            if limb > 0 {
                sum += round_collect_carries[limb - 1].clone();
            }
            if limb < 3 {
                eval.add_constraint(
                    is_end_without_showdown.clone()
                        * (sum
                            - amount[limb].clone()
                            - round_base.clone() * round_collect_carries[limb].clone()),
                );
            } else {
                eval.add_constraint(is_end_without_showdown.clone() * (sum - amount[limb].clone()));
            }
        }
        let terminal_amount_sum = amount
            .iter()
            .fold(M31::from(0u32).into(), |sum: E::F, limb| sum + limb.clone());
        eval.add_constraint(
            is_end_without_showdown.clone()
                * (terminal_amount_sum * amount_inv.clone() - one.clone()),
        );
        eval.add_constraint(
            is_end_without_showdown.clone() * (pre_phase.clone() - M31::from(4u32).into()),
        );
        eval.add_constraint(is_terminal_reset.clone() * (post_phase.clone()));
        for value in [
            &post_subtag,
            &post_street,
            &post_acted_mask,
            &post_leave_mask,
            &post_protocol_pending_mask,
        ] {
            eval.add_constraint(is_terminal_reset.clone() * value.clone());
        }
        for value in [&post_current, &post_min, &post_pot] {
            for limb in value {
                eval.add_constraint(is_terminal_reset.clone() * limb.clone());
            }
        }
        for limb in &post_deadline_image {
            eval.add_constraint(is_terminal_reset.clone() * limb.clone());
        }
        eval.add_constraint(is_terminal_reset.clone() * (post_turn.clone() - no_seat.clone()));
        for (left, right) in pre_chip_pool.iter().zip(post_chip_pool.iter()) {
            eval.add_constraint(is_terminal_reset.clone() * (right.clone() - left.clone()));
        }
        // ResetOnly carries no monetary delta.  EndWithoutShowdown uses the
        // checked pot collection above and pays the winner from that exact
        // amount, so post chip_pool is unchanged in this zero-rake branch.
        for value in amount.iter().chain(auxiliary.iter()) {
            eval.add_constraint(is_reset_only.clone() * value.clone());
        }
        for index in 0..MAX_CANONICAL_SEATS {
            let selector = transition_seat_selectors[index].clone();
            let time_bank_cap: E::F = M31::from(30_000u32).into();
            let pre_empty = full_pre_status[index][CanonicalSeatStatus::Empty as usize].clone();
            let pre_active = full_pre_status[index][CanonicalSeatStatus::Active as usize].clone();
            let pre_folded = full_pre_status[index][CanonicalSeatStatus::Folded as usize].clone();
            let post_empty = full_post_status[index][CanonicalSeatStatus::Empty as usize].clone();
            let post_active = full_post_status[index][CanonicalSeatStatus::Active as usize].clone();
            eval.add_constraint(
                is_terminal_reset.clone() * (selector.clone() * (selector.clone() - one.clone())),
            );
            eval.add_constraint(
                is_terminal_reset.clone()
                    * ((pre_active.clone() + pre_folded.clone() + pre_empty.clone()) - one.clone()),
            );
            eval.add_constraint(
                is_end_without_showdown.clone()
                    * selector.clone()
                    * (pre_active.clone() - one.clone()),
            );
            eval.add_constraint(
                is_end_without_showdown.clone()
                    * (one.clone() - selector.clone())
                    * pre_active.clone(),
            );
            eval.add_constraint(
                is_terminal_reset.clone() * (post_empty.clone() - pre_empty.clone()),
            );
            eval.add_constraint(
                is_terminal_reset.clone()
                    * (post_active.clone() - (one.clone() - pre_empty.clone())),
            );
            for limb in 0..4 {
                eval.add_constraint(is_terminal_reset.clone() * full_post_bet[index][limb].clone());
                eval.add_constraint(
                    is_terminal_reset.clone() * full_post_total[index][limb].clone(),
                );
                eval.add_constraint(
                    is_terminal_reset.clone() * full_post_pending[index][limb].clone(),
                );
                eval.add_constraint(
                    is_terminal_reset.clone()
                        * (full_post_stack[index][limb].clone()
                            - full_pre_stack[index][limb].clone()
                            - selector.clone() * amount[limb].clone()),
                );
            }
            for bit in [
                &post_acted_bits[index],
                &pre_leave_mask_bits[index],
                &post_leave_mask_bits[index],
            ] {
                eval.add_constraint(is_terminal_reset.clone() * bit.clone());
            }
            eval.add_constraint(
                is_terminal_reset.clone()
                    * (full_pre_time_bank[index][0].clone()
                        - time_bank_cap.clone() * (one.clone() - pre_empty.clone())),
            );
            eval.add_constraint(is_terminal_reset.clone() * full_pre_time_bank[index][1].clone());
            eval.add_constraint(
                is_terminal_reset.clone()
                    * (full_post_time_bank[index][0].clone()
                        - time_bank_cap * (one.clone() - pre_empty.clone())),
            );
            eval.add_constraint(is_terminal_reset.clone() * full_post_time_bank[index][1].clone());
            for limb in 0..16 {
                eval.add_constraint(
                    is_terminal_reset.clone()
                        * (post_seat_commitments[index][0][limb].clone()
                            - pre_seat_commitments[index][0][limb].clone()),
                );
                eval.add_constraint(
                    is_terminal_reset.clone()
                        * (post_seat_commitments[index][1][limb].clone()
                            - pre_seat_commitments[index][1][limb].clone()),
                );
                eval.add_constraint(
                    is_terminal_reset.clone() * post_seat_commitments[index][2][limb].clone(),
                );
            }
        }
        let non_raise_betting = is_betting.clone() - is_raise.clone();
        let mut selector_sum: E::F = M31::from(0u32).into();
        let mut selected_pre_acted: E::F = M31::from(0u32).into();
        let mut selected_post_acted: E::F = M31::from(0u32).into();
        let mut pre_mask_from_bits: E::F = M31::from(0u32).into();
        let mut post_mask_from_bits: E::F = M31::from(0u32).into();
        let mut selected_seat: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let selector = acted_seat_selectors[index].clone();
            let pre_bit = pre_acted_bits[index].clone();
            let post_bit = post_acted_bits[index].clone();
            let delta = acted_deltas[index].clone();
            let bit_weight: E::F = M31::from(1u32 << index).into();
            let seat_value: E::F = M31::from(index as u32).into();
            eval.add_constraint(selector.clone() * (selector.clone() - one.clone()));
            eval.add_constraint(pre_bit.clone() * (pre_bit.clone() - one.clone()));
            eval.add_constraint(post_bit.clone() * (post_bit.clone() - one.clone()));
            eval.add_constraint(delta.clone() * (delta.clone() - one.clone()));
            eval.add_constraint(delta - selector.clone() * (one.clone() - pre_bit.clone()));
            eval.add_constraint(
                non_raise_betting.clone()
                    * (post_bit.clone() - pre_bit.clone() - acted_deltas[index].clone()),
            );
            selector_sum += selector.clone();
            selected_pre_acted += selector.clone() * pre_bit.clone();
            selected_post_acted += selector.clone() * post_bit.clone();
            selected_seat += selector * seat_value;
            pre_mask_from_bits += pre_bit * bit_weight.clone();
            post_mask_from_bits += post_bit * bit_weight;
        }
        eval.add_constraint(selector_sum - is_betting.clone());
        eval.add_constraint(selected_seat - is_betting.clone() * seat.clone());
        eval.add_constraint(pre_mask_from_bits - pre_acted_mask.clone());
        eval.add_constraint(post_mask_from_bits - post_acted_mask.clone());
        eval.add_constraint(is_betting.clone() * pre_seat_acted.clone() - selected_pre_acted);
        eval.add_constraint(is_betting.clone() * post_seat_acted.clone() - selected_post_acted);
        let mut pre_leave_mask_from_bits: E::F = M31::from(0u32).into();
        let mut post_leave_mask_from_bits: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let pre_bit = pre_leave_mask_bits[index].clone();
            let post_bit = post_leave_mask_bits[index].clone();
            let bit_weight: E::F = M31::from(1u32 << index).into();
            eval.add_constraint(active.clone() * pre_bit.clone() * (pre_bit.clone() - one.clone()));
            eval.add_constraint(
                active.clone() * post_bit.clone() * (post_bit.clone() - one.clone()),
            );
            pre_leave_mask_from_bits += pre_bit * bit_weight.clone();
            post_leave_mask_from_bits += post_bit * bit_weight;
        }
        eval.add_constraint(active.clone() * (pre_leave_mask_from_bits - pre_leave_mask.clone()));
        eval.add_constraint(active.clone() * (post_leave_mask_from_bits - post_leave_mask.clone()));
        let mut pre_protocol_mask_from_bits: E::F = M31::from(0u32).into();
        let mut post_protocol_mask_from_bits: E::F = M31::from(0u32).into();
        let mut post_protocol_pending_count: E::F = M31::from(0u32).into();
        let mut selected_protocol_pre_bit: E::F = M31::from(0u32).into();
        eval.add_constraint({
            let z: E::F = M31::from(0u32).into();
            z // S2_mask_region
        });
        let mut expected_pre_protocol_participants: E::F = M31::from(0u32).into();
        let mut expected_protocol_participants: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let pre_bit = pre_protocol_pending_mask_bits[index].clone();
            let post_bit = post_protocol_pending_mask_bits[index].clone();
            let selector = transition_seat_selectors[index].clone();
            let bit_weight: E::F = M31::from(1u32 << index).into();
            for bit in [&pre_bit, &post_bit] {
                eval.add_constraint(active.clone() * bit.clone() * (bit.clone() - one.clone()));
            }
            pre_protocol_mask_from_bits += pre_bit.clone() * bit_weight.clone();
            post_protocol_mask_from_bits += post_bit.clone() * bit_weight.clone();
            post_protocol_pending_count += post_bit.clone();
            selected_protocol_pre_bit += selector.clone() * pre_bit.clone();
            let later_transition_selector = transition_seat_selectors[index + 1..]
                .iter()
                .cloned()
                .fold(E::F::from(M31::from(0u32)), |sum, value| sum + value);
            // The VM's timeout loop always selects the lowest pending seat.
            // If any higher seat is selected on this row, every lower pending
            // bit must therefore be zero.
            eval.add_constraint(
                is_reveal_kick.clone() * pre_bit.clone() * later_transition_selector,
            );
            // 完成行（reconstruct/shuffle/reveal）的 pending 掩码由 completion
            // 组合约束整体锚定（reveal pending = 活跃集），不走"清提交者
            // 位"的逐位演化。原先只排除 reconstruct，shuffle 完成行在此
            // 被要求清位、又同时要求等于活跃集，恒矛盾（2026-09-10
            // 整手牌性能扫描中发现）。
            let non_final_protocol_submit = is_protocol_submit.clone()
                - is_reconstruct_completion.clone()
                - is_shuffle_completion.clone()
                - is_reveal_completion.clone();
            eval.add_constraint(
                non_final_protocol_submit * (post_bit.clone() - pre_bit.clone() + selector.clone()),
            );
            eval.add_constraint(
                is_shuffle_timeout.clone()
                    * (post_bit.clone() - pre_bit.clone() + selector.clone()),
            );
            eval.add_constraint(
                is_reveal_kick.clone() * (post_bit.clone() - pre_bit.clone() + selector.clone()),
            );
            eval.add_constraint(is_reconstruct_completion.clone() * (pre_bit.clone() - selector));
            let pre_participating = full_pre_status[index][CanonicalSeatStatus::Active as usize]
                .clone()
                + full_pre_status[index][CanonicalSeatStatus::Folded as usize].clone()
                + full_pre_status[index][CanonicalSeatStatus::AllIn as usize].clone();
            let post_participating = full_post_status[index][CanonicalSeatStatus::Active as usize]
                .clone()
                + full_post_status[index][CanonicalSeatStatus::Folded as usize].clone()
                + full_post_status[index][CanonicalSeatStatus::AllIn as usize].clone();
            eval.add_constraint(
                active.clone() * pre_bit * (one.clone() - pre_participating.clone()),
            );
            eval.add_constraint(
                active.clone() * post_bit * (one.clone() - post_participating.clone()),
            );
            expected_pre_protocol_participants += pre_participating * bit_weight.clone();
            expected_protocol_participants += post_participating * bit_weight;
        }
        eval.add_constraint(
            active.clone() * (pre_protocol_mask_from_bits - pre_protocol_pending_mask.clone()),
        );
        eval.add_constraint(
            active.clone() * (post_protocol_mask_from_bits - post_protocol_pending_mask.clone()),
        );
        eval.add_constraint(
            selected_protocol_pre_bit
                - is_protocol_submit.clone()
                - is_shuffle_timeout.clone()
                - is_timeout_reset.clone()
                - is_reveal_kick.clone()
                - is_reveal_reconstruct.clone()
                - is_award_family.clone(),
        );
        // 完成行（flag=1）post pending 计数为 0，不在该非零等式约束内。
        eval.add_constraint(
            (is_protocol_submit.clone() - protocol_completion_flag.clone())
                * (post_protocol_pending_count.clone() * protocol_pending_post_inv.clone()
                    - one.clone()),
        );
        eval.add_constraint(
            is_advance_deadline.clone()
                * (shuffle_pending_count_product.clone()
                    - post_protocol_pending_count.clone()
                        * (post_protocol_pending_count.clone() - one.clone())),
        );
        eval.add_constraint(
            shuffle_timeout_gate.clone()
                * (shuffle_pending_count_product.clone() * protocol_pending_post_inv.clone()
                    - one.clone()),
        );
        eval.add_constraint(
            is_reveal_kick.clone()
                * (post_protocol_pending_count.clone() * protocol_pending_post_inv.clone()
                    - one.clone()),
        );
        eval.add_constraint(is_reconstruct_completion.clone() * protocol_pending_post_inv.clone());
        let non_final_protocol_submit = is_protocol_submit.clone()
            - is_reconstruct_completion.clone()
            - is_shuffle_completion.clone()
            - is_reveal_completion.clone();
        // #22②：freeze 只约束 non-final 提交；reconstruct / shuffle / reveal
        // / street / showdown 完成行由下方各自的组合约束接管。
        for (pre, post) in [
            (&pre_phase, &post_phase),
            (&pre_subtag, &post_subtag),
            (&pre_street, &post_street),
        ] {
            eval.add_constraint(non_final_protocol_submit.clone() * (post.clone() - pre.clone()));
        }
        for (left, right) in pre_deadline_image.iter().zip(post_deadline_image.iter()) {
            eval.add_constraint(non_final_protocol_submit.clone() * (right.clone() - left.clone()));
        }
        eval.add_constraint(
            is_reconstruct_completion.clone() * (post_phase.clone() - M31::from(1u32).into()),
        );
        eval.add_constraint(
            is_reconstruct_completion.clone()
                * (post_subtag.clone()
                    - M31::from(u32::from(CANONICAL_SHUFFLE_RECONSTRUCT_SUBTAG)).into()),
        );
        eval.add_constraint(
            is_reconstruct_completion.clone()
                * (post_protocol_pending_mask.clone() - expected_protocol_participants.clone()),
        );
        eval.add_constraint(
            is_reconstruct_completion.clone()
                * (protocol_completion_post_pending_mask.clone()
                    - post_protocol_pending_mask.clone()),
        );
        eval.add_constraint(
            is_reconstruct_completion.clone() * protocol_completion_post_completed_mask.clone(),
        );
        for limb in 0..16 {
            for (opening, endpoint) in [
                (
                    &protocol_completion_commitments[0][limb],
                    &pre_opaque_commitments[2][limb],
                ),
                (
                    &protocol_completion_commitments[0][limb],
                    &post_opaque_commitments[2][limb],
                ),
                (
                    &protocol_completion_commitments[1][limb],
                    &pre_opaque_commitments[1][limb],
                ),
                (
                    &protocol_completion_commitments[2][limb],
                    &post_opaque_commitments[1][limb],
                ),
                (
                    &protocol_completion_commitments[3][limb],
                    &pre_opaque_commitments[3][limb],
                ),
                (
                    &protocol_completion_commitments[4][limb],
                    &post_opaque_commitments[3][limb],
                ),
            ] {
                eval.add_constraint(
                    is_reconstruct_completion.clone() * (opening.clone() - endpoint.clone()),
                );
            }
        }
        let mut completion_timestamp_sum: E::F = M31::from(0u32).into();
        for limb in 0..4 {
            range16_constraints(
                &mut eval,
                &is_reconstruct_completion,
                &protocol_completion_timestamp[limb],
                &protocol_completion_timestamp_bits[limb],
            );
            completion_timestamp_sum += protocol_completion_timestamp[limb].clone();
        }
        // flag 门控（度数 ≤3；同时覆盖 reconstruct 与 shuffle completion 行）。
        eval.add_constraint(
            protocol_completion_flag.clone()
                * (completion_timestamp_sum * protocol_completion_timestamp_inv.clone()
                    - one.clone()),
        );
        let zero_limb: E::F = M31::from(0u32).into();
        let shuffle_timeout = [
            pre_timeout_config[0].clone(),
            pre_timeout_config[1].clone(),
            zero_limb.clone(),
            zero_limb.clone(),
        ];
        limb4_add_constraints_no_carry_bool(
            &mut eval,
            &is_reconstruct_completion,
            &protocol_completion_timestamp,
            &shuffle_timeout,
            &post_deadline_image,
            &protocol_completion_deadline_carries,
        );
        // carry 布尔性用 1 次门（is_reconstruct_completion 已是 2 次积，
        // 直接门控会超声明度数；非完成行 carries 已被零化，此约束无害）。
        for carry in protocol_completion_deadline_carries.iter() {
            eval.add_constraint(
                is_submit_reconstruct.clone() * carry.clone() * (carry.clone() - one.clone()),
            );
        }
        eval.add_constraint(
            is_reconstruct_completion.clone() * protocol_completion_post_cards_dealt.clone(),
        );
        let mut reconstructed_cursor: E::F = M31::from(0u32).into();
        let mut cursor_carry_in: E::F = M31::from(0u32).into();
        for bit_index in 0..6 {
            let cursor_bit = protocol_completion_cursor_range[0][bit_index].clone();
            let remaining_bit = protocol_completion_cursor_range[1][bit_index].clone();
            let carry_out = protocol_completion_cursor_range[2][bit_index].clone();
            let weight: E::F = M31::from(1u32 << bit_index).into();
            let constant_bit: E::F = M31::from((52u32 >> bit_index) & 1).into();
            let two: E::F = M31::from(2u32).into();
            reconstructed_cursor += cursor_bit.clone() * weight;
            eval.add_constraint(
                is_reconstruct_completion.clone()
                    * (cursor_bit + remaining_bit + cursor_carry_in
                        - constant_bit
                        - two * carry_out.clone()),
            );
            cursor_carry_in = carry_out;
        }
        eval.add_constraint(
            is_reconstruct_completion.clone()
                * (protocol_completion_pre_cards_dealt.clone() - reconstructed_cursor),
        );
        eval.add_constraint({
            let z: E::F = M31::from(0u32).into();
            z // S3_shuffle_block
        });
        // ---- #22②：ShuffleComplete 组合约束（镜像 start_preflop_reveal_phase
        // 的规范化语义；合法性词不进吸收链，deck 轮转锚定 pre/post 端点）----
        eval.add_constraint(is_shuffle_completion.clone() * protocol_pending_post_inv.clone());
        eval.add_constraint(
            is_shuffle_completion.clone() * (post_phase.clone() - M31::from(2u32).into()),
        );
        // subtag 钉死为收集子标签 1（镜像 host 校验 pre/post subtag == 1，
        // 洗牌完成只发生在收集相位；曾误写为强制归零，与 host 校验
        // "活跃相位 subtag 非零"矛盾，导致完成行端到端不可证，
        // 2026-09-10 整手牌性能扫描中发现并修正）。
        eval.add_constraint(
            is_shuffle_completion.clone() * (post_subtag.clone() - M31::from(1u32).into()),
        );
        eval.add_constraint(
            is_shuffle_completion.clone() * (post_street.clone() - pre_street.clone()),
        );
        eval.add_constraint(
            is_shuffle_completion.clone()
                * (post_turn.clone() - M31::from(u32::from(NO_CANONICAL_SEAT)).into()),
        );
        eval.add_constraint(
            is_shuffle_completion.clone()
                * (post_protocol_pending_mask.clone() - expected_protocol_participants.clone()),
        );
        eval.add_constraint(
            is_shuffle_completion.clone()
                * (protocol_completion_post_pending_mask.clone()
                    - post_protocol_pending_mask.clone()),
        );
        eval.add_constraint(
            is_shuffle_completion.clone()
                * (protocol_completion_post_completed_mask.clone()
                    - expected_protocol_participants.clone()),
        );
        for limb in 0..16 {
            for (opening, endpoint) in [
                (
                    &protocol_completion_commitments[1][limb],
                    &pre_opaque_commitments[1][limb],
                ),
                (
                    &protocol_completion_commitments[2][limb],
                    &post_opaque_commitments[1][limb],
                ),
                (
                    &protocol_completion_commitments[3][limb],
                    &pre_opaque_commitments[3][limb],
                ),
                (
                    &protocol_completion_commitments[3][limb],
                    &protocol_completion_commitments[4][limb],
                ),
            ] {
                eval.add_constraint(
                    is_shuffle_completion.clone() * (opening.clone() - endpoint.clone()),
                );
            }
            eval.add_constraint(
                is_shuffle_completion.clone() * protocol_completion_commitments[0][limb].clone(),
            );
        }
        let reveal_timeout_limbs = [
            pre_timeout_config[2].clone(),
            pre_timeout_config[3].clone(),
            zero_limb.clone(),
            zero_limb.clone(),
        ];
        limb4_add_constraints_no_carry_bool(
            &mut eval,
            &is_shuffle_completion,
            &protocol_completion_timestamp,
            &reveal_timeout_limbs,
            &post_deadline_image,
            &protocol_completion_deadline_carries,
        );
        for carry in protocol_completion_deadline_carries.iter() {
            eval.add_constraint(
                is_submit_shuffle.clone() * carry.clone() * (carry.clone() - one.clone()),
            );
        }
        eval.add_constraint(
            is_shuffle_completion.clone() * protocol_completion_pre_cards_dealt.clone(),
        );
        eval.add_constraint({
            let z: E::F = M31::from(0u32).into();
            z // S4_after_completion
        });
        let non_reconstruct_completion = active.clone() - is_reconstruct_completion.clone();
        // 完成 opening 的"实值"建议列（时间戳/游标/掩码/承诺锚/inverse/
        // 进位）在 shuffle 完成行同样必须放开——它们由上方 ShuffleComplete
        // 组合约束接管。原先清零门只排除 reconstruct，导致 shuffle 完成
        // 行的建议被强制归零、与其自身约束恒矛盾（2026-09-10 整手牌性能
        // 扫描中发现；该分支此前从未被 prove 过）。时间戳/游标的位分解
        // 仅 reconstruct 使用，维持对 shuffle 行清零以保证建议确定性。
        let completion_row = is_reconstruct_completion.clone()
            + is_shuffle_completion.clone()
            + is_reveal_completion.clone();
        let non_completion_advice = active.clone() - completion_row.clone();
        for value in protocol_completion_timestamp
            .iter()
            .chain(std::iter::once(&protocol_completion_pre_cards_dealt))
            .chain(std::iter::once(&protocol_completion_post_cards_dealt))
            .chain(std::iter::once(&protocol_completion_post_pending_mask))
            .chain(std::iter::once(&protocol_completion_post_completed_mask))
        {
            eval.add_constraint(non_completion_advice.clone() * value.clone());
        }
        for commitment in &protocol_completion_commitments {
            for limb in commitment {
                eval.add_constraint(non_completion_advice.clone() * limb.clone());
            }
        }
        for bits in &protocol_completion_timestamp_bits {
            for bit in bits {
                eval.add_constraint(non_reconstruct_completion.clone() * bit.clone());
            }
        }
        eval.add_constraint(
            non_completion_advice.clone() * protocol_completion_timestamp_inv.clone(),
        );
        for carry in &protocol_completion_deadline_carries {
            eval.add_constraint(non_completion_advice.clone() * carry.clone());
        }
        for bits in &protocol_completion_cursor_range {
            for bit in bits {
                eval.add_constraint(non_reconstruct_completion.clone() * bit.clone());
                eval.add_constraint(active.clone() * bit.clone() * (bit.clone() - one.clone()));
            }
        }
        let ordinary_non_protocol = active.clone()
            - is_protocol_submit.clone()
            - is_shuffle_timeout.clone()
            - is_timeout_reset.clone()
            - is_reveal_kick.clone()
            - is_reveal_reconstruct.clone()
            - is_award_family.clone()
            - is_start.clone()
            - is_round_advance.clone();
        eval.add_constraint(ordinary_non_protocol.clone() * pre_protocol_pending_mask.clone());
        eval.add_constraint(ordinary_non_protocol * post_protocol_pending_mask.clone());
        eval.add_constraint(is_start.clone() * pre_protocol_pending_mask.clone());
        eval.add_constraint(is_round_advance.clone() * pre_protocol_pending_mask.clone());
        eval.add_constraint(
            is_shuffle_timeout.clone()
                * (pre_protocol_pending_mask.clone() - expected_pre_protocol_participants.clone()),
        );
        eval.add_constraint(
            is_shuffle_timeout.clone()
                * (post_protocol_pending_mask.clone() - expected_protocol_participants.clone()),
        );
        // The reconstruct continuation derives its pending mask from the full
        // post seat image, exactly like the VM's active-seat mask.
        eval.add_constraint(
            is_reveal_reconstruct.clone()
                * (post_protocol_pending_mask.clone() - expected_protocol_participants.clone()),
        );
        eval.add_constraint(
            (is_start.clone() + is_round_advance.clone())
                * (post_protocol_pending_mask.clone() - expected_protocol_participants),
        );
        // Open every seat that the VM consults while progressing a betting
        // round.  This makes the current selected-seat projection a derived
        // value and prevents the host from changing a non-acting stack/bet or
        // lifecycle image outside the former narrow projection.
        let mut selected_full_pre_status: E::F = M31::from(0u32).into();
        let mut selected_full_post_status: E::F = M31::from(0u32).into();
        let mut selected_full_pre_stack: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_post_stack: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_pre_bet: [E::F; 4] = std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_post_bet: [E::F; 4] = std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_pre_total: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_post_total: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_pre_pending: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_post_pending: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_pre_time: [E::F; 2] = std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_post_time: [E::F; 2] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_pre_status: E::F = M31::from(0u32).into();
        let mut selected_funding_post_status: E::F = M31::from(0u32).into();
        let mut selected_funding_pre_stack: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_post_stack: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_pre_bet: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_post_bet: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_pre_total: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_post_total: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_pre_pending: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_post_pending: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_pre_time: [E::F; 2] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_post_time: [E::F; 2] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut funding_selector_sum: E::F = M31::from(0u32).into();
        let mut selected_funding_seat: E::F = M31::from(0u32).into();
        let mut transition_selector_sum: E::F = M31::from(0u32).into();
        let mut selected_transition_seat: E::F = M31::from(0u32).into();
        let mut selected_transition_pre_status: E::F = M31::from(0u32).into();
        let mut selected_transition_post_status: E::F = M31::from(0u32).into();
        let mut selected_transition_pre_stack: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_transition_pre_pending: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_transition_pre_bet: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        for index in 0..MAX_CANONICAL_SEATS {
            let betting_selector = acted_seat_selectors[index].clone();
            let funding_selector = funding_seat_selectors[index].clone();
            let transition_selector = transition_seat_selectors[index].clone();
            let selector = betting_selector.clone();
            eval.add_constraint(
                active.clone()
                    * funding_selector.clone()
                    * (funding_selector.clone() - one.clone()),
            );
            eval.add_constraint((active.clone() - is_funding.clone()) * funding_selector.clone());
            funding_selector_sum += funding_selector.clone();
            let index_value: E::F = M31::from(index as u32).into();
            selected_funding_seat += funding_selector.clone() * index_value.clone();
            eval.add_constraint(
                active.clone()
                    * transition_selector.clone()
                    * (transition_selector.clone() - one.clone()),
            );
            eval.add_constraint(
                (active.clone() - requires_transition_seat.clone()) * transition_selector.clone(),
            );
            // `SetLeaveAfterHand` writes precisely the selected bit.  With
            // binary mask bits, `post - pre = 2 * flag - 1` forces a false
            // flag to clear a previously-set bit and a true flag to set a
            // previously-clear bit; every non-selected bit is unchanged.
            eval.add_constraint(
                is_set_leave.clone()
                    * (post_leave_mask_bits[index].clone()
                        - pre_leave_mask_bits[index].clone()
                        - transition_selector.clone()
                            * (flag.clone() + flag.clone() - one.clone())),
            );
            transition_selector_sum += transition_selector.clone();
            selected_transition_seat += transition_selector.clone() * index_value;
            let mut pre_status_value: E::F = M31::from(0u32).into();
            let mut post_status_value: E::F = M31::from(0u32).into();
            let mut weight: E::F = M31::from(0u32).into();
            for status in 0..SEAT_STATUS_COUNT {
                let pre = full_pre_status[index][status].clone();
                let post = full_post_status[index][status].clone();
                eval.add_constraint(active.clone() * pre.clone() * (pre.clone() - one.clone()));
                eval.add_constraint(active.clone() * post.clone() * (post.clone() - one.clone()));
                pre_status_value += pre * weight.clone();
                post_status_value += post * weight.clone();
                weight += one.clone();
            }
            let pre_status_sum = full_pre_status[index]
                .iter()
                .fold(M31::from(0u32).into(), |sum: E::F, value| {
                    sum + value.clone()
                });
            let post_status_sum = full_post_status[index]
                .iter()
                .fold(M31::from(0u32).into(), |sum: E::F, value| {
                    sum + value.clone()
                });
            eval.add_constraint(active.clone() * (pre_status_sum - one.clone()));
            eval.add_constraint(active.clone() * (post_status_sum - one.clone()));
            for status in 0..SEAT_STATUS_COUNT {
                // #22② 封顶盲注例外：盲注扣到 stack 归零的座位在 reveal
                // 完成行翻转 Active→AllIn——该座位 status 由上方 capped 翻转
                // 方向约束接管（capped ⊆ reveal-completion 已被钉死），
                // 其余 protocol 提交行/座位仍整体冻结。度数：1+1+1 = 3。
                eval.add_constraint(
                    (is_protocol_submit.clone() - rc_stack_capped[index].clone())
                        * (full_post_status[index][status].clone()
                            - full_pre_status[index][status].clone()),
                );
            }
            // #22②：status/pending(time-bank addon)仍冻结；reveal 完成行
            // 的 stack/bet/total 由盲注扣款 limb 方程接管。
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_total[index], &full_post_total[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(
                        (is_protocol_submit.clone() - is_reveal_completion.clone())
                            * (right.clone() - left.clone()),
                    );
                }
            }
            for (pre, post) in [
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(is_protocol_submit.clone() * (right.clone() - left.clone()));
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(is_protocol_submit.clone() * (right.clone() - left.clone()));
            }
            // #22② 封顶盲注 / street completion：封顶座位的 acted 位翻转、
            // 补位掩码重置（start_betting_round 的 folded/all-in 补位），
            // 豁免 frozen-bit 约束（各自的组合约束接管）。
            eval.add_constraint(
                (is_protocol_submit.clone()
                    - rc_stack_capped[index].clone()
                    - rcs_gate.clone())
                    * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
            eval.add_constraint(
                is_protocol_submit.clone()
                    * (post_leave_mask_bits[index].clone() - pre_leave_mask_bits[index].clone()),
            );
            for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                // hole 承诺（槽 2）在 reveal 提交行放行：摊牌窗口的逐座
                // token 会在窗口中途物化明文底牌（native 解密通道，
                // Plan D）；shuffle/reconstruct 提交行仍冻结。
                let gate = if commitment == 2 {
                    is_protocol_submit.clone() - is_submit_reveal.clone()
                } else {
                    is_protocol_submit.clone()
                };
                for limb in 0..16 {
                    eval.add_constraint(
                        gate.clone()
                            * (post_seat_commitments[index][commitment][limb].clone()
                                - pre_seat_commitments[index][commitment][limb].clone()),
                    );
                }
            }
            for status in 0..SEAT_STATUS_COUNT {
                let expected: E::F =
                    M31::from(u32::from(status == CanonicalSeatStatus::Empty as usize)).into();
                eval.add_constraint(
                    is_create.clone()
                        * (full_post_status[index][status].clone() - expected.clone()),
                );
                eval.add_constraint(
                    is_create.clone() * (full_pre_status[index][status].clone() - expected),
                );
            }
            // ForceFold and KickPlayer have a finite, VM-defined lifecycle
            // transition.  Use the full one-hot seat opening rather than the
            // host-provided scalar projection, so a different seat cannot
            // satisfy the action's pre/post status rule.
            eval.add_constraint(
                is_force_or_kick.clone()
                    * transition_selector.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                        + full_pre_status[index][CanonicalSeatStatus::Waiting as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_force_or_kick.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Folded as usize].clone()
                        + full_post_status[index][CanonicalSeatStatus::Out as usize].clone()
                        + full_post_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - one.clone()),
            );
            // JoinTable credits the buy-in exactly once: the selected stack
            // receives it and TableVault locks it.  The VM creates a Waiting
            // seat (waiting-for-big-blind): the seat participates only once
            // StartHand promotes it from the blind position.
            eval.add_constraint(
                is_join.clone()
                    * transition_selector.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - one.clone()),
            );
            for earlier in 0..index {
                eval.add_constraint(
                    is_join.clone()
                        * transition_selector.clone()
                        * full_pre_status[earlier][CanonicalSeatStatus::Empty as usize].clone(),
                );
            }
            eval.add_constraint(
                is_join.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Waiting as usize].clone()
                        - one.clone()),
            );
            for limb in 0..4 {
                eval.add_constraint(
                    is_join.clone()
                        * transition_selector.clone()
                        * (full_post_stack[index][limb].clone() - amount[limb].clone()),
                );
                eval.add_constraint(
                    is_join.clone()
                        * transition_selector.clone()
                        * full_post_bet[index][limb].clone(),
                );
                eval.add_constraint(
                    is_join.clone()
                        * transition_selector.clone()
                        * full_post_total[index][limb].clone(),
                );
                eval.add_constraint(
                    is_join.clone()
                        * transition_selector.clone()
                        * full_post_pending[index][limb].clone(),
                );
            }
            eval.add_constraint(
                is_join.clone()
                    * transition_selector.clone()
                    * (full_post_time_bank[index][0].clone() - M31::from(30_000u32).into()),
            );
            eval.add_constraint(
                is_join.clone()
                    * transition_selector.clone()
                    * full_post_time_bank[index][1].clone(),
            );
            eval.add_constraint(
                is_join.clone() * transition_selector.clone() * post_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_join.clone() * transition_selector.clone() * post_leave_mask_bits[index].clone(),
            );
            eval.add_constraint(
                is_join.clone() * transition_selector.clone() * pre_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_join.clone() * transition_selector.clone() * pre_leave_mask_bits[index].clone(),
            );
            // LeaveTable is the inverse custody operation: refund stack plus
            // pending addon and replace the selected image with the unique
            // vacant representation.
            eval.add_constraint(
                is_leave.clone()
                    * transition_selector.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Waiting as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_leave.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - one.clone()),
            );
            for limb in 0..4 {
                eval.add_constraint(
                    is_leave.clone()
                        * transition_selector.clone()
                        * full_post_stack[index][limb].clone(),
                );
                eval.add_constraint(
                    is_leave.clone()
                        * transition_selector.clone()
                        * full_post_bet[index][limb].clone(),
                );
                eval.add_constraint(
                    is_leave.clone()
                        * transition_selector.clone()
                        * full_post_total[index][limb].clone(),
                );
                eval.add_constraint(
                    is_leave.clone()
                        * transition_selector.clone()
                        * full_post_pending[index][limb].clone(),
                );
            }
            for time_bank_limb in full_post_time_bank[index].iter() {
                eval.add_constraint(
                    is_leave.clone() * transition_selector.clone() * time_bank_limb.clone(),
                );
            }
            eval.add_constraint(
                is_leave.clone() * transition_selector.clone() * post_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_leave.clone()
                    * transition_selector.clone()
                    * post_leave_mask_bits[index].clone(),
            );
            eval.add_constraint(
                is_leave.clone() * transition_selector.clone() * pre_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_leave.clone() * transition_selector.clone() * pre_leave_mask_bits[index].clone(),
            );
            // ForceFold lowers to the VM's nonterminal Fold action.  It is
            // player-turn gated, moves only Active -> Folded, sets the actor's
            // acted bit, and preserves every custody bucket and commitment.
            eval.add_constraint(
                is_force_fold.clone()
                    * transition_selector.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_force_fold.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Folded as usize].clone()
                        - one.clone()),
            );
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(
                        is_force_fold.clone()
                            * transition_selector.clone()
                            * (right.clone() - left.clone()),
                    );
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(
                    is_force_fold.clone()
                        * transition_selector.clone()
                        * (right.clone() - left.clone()),
                );
            }
            eval.add_constraint(
                is_force_fold.clone()
                    * transition_selector.clone()
                    * (post_acted_bits[index].clone() - one.clone()),
            );
            eval.add_constraint(
                is_force_fold.clone()
                    * (one.clone() - transition_selector.clone())
                    * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
            eval.add_constraint(
                is_force_fold.clone()
                    * (post_leave_mask_bits[index].clone() - pre_leave_mask_bits[index].clone()),
            );
            // A non-cascading VM kick departs the selected seat, clears live
            // custody and current-round wager buckets, and retains only the
            // side-pot/audit fields explicitly listed below.
            eval.add_constraint(
                is_kick.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Out as usize].clone()
                        - one.clone()),
            );
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for limb in 0..4 {
                    eval.add_constraint(
                        is_kick.clone() * transition_selector.clone() * post[limb].clone(),
                    );
                    let _ = pre;
                }
            }
            for limb in 0..4 {
                eval.add_constraint(
                    is_kick.clone()
                        * transition_selector.clone()
                        * (full_post_total[index][limb].clone()
                            - full_pre_total[index][limb].clone()),
                );
            }
            for (pre, post) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(
                    is_kick.clone() * transition_selector.clone() * (post.clone() - pre.clone()),
                );
            }
            eval.add_constraint(
                is_kick.clone() * transition_selector.clone() * post_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_kick.clone() * transition_selector.clone() * post_leave_mask_bits[index].clone(),
            );
            // Shuffle timeout departs exactly the selected active seat.  Its
            // identity remains auditable, while live wager/custody buckets are
            // cleared and total-bet/time-bank history is retained.
            eval.add_constraint(
                is_shuffle_timeout.clone()
                    * transition_selector.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_shuffle_timeout.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Out as usize].clone()
                        - one.clone()),
            );
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for limb in 0..4 {
                    eval.add_constraint(
                        is_shuffle_timeout.clone()
                            * transition_selector.clone()
                            * post[limb].clone(),
                    );
                    let _ = pre;
                }
            }
            for limb in 0..4 {
                eval.add_constraint(
                    is_shuffle_timeout.clone()
                        * transition_selector.clone()
                        * (full_post_total[index][limb].clone()
                            - full_pre_total[index][limb].clone()),
                );
            }
            for (pre, post) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(
                    is_shuffle_timeout.clone()
                        * transition_selector.clone()
                        * (post.clone() - pre.clone()),
                );
            }
            eval.add_constraint(
                is_shuffle_timeout.clone()
                    * transition_selector.clone()
                    * post_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_shuffle_timeout.clone()
                    * transition_selector.clone()
                    * (post_leave_mask_bits[index].clone() - pre_leave_mask_bits[index].clone()),
            );
            // A leave-after-hand flag can only be toggled for an occupied
            // seat.  The exact bit update is constrained below; this closes
            // the otherwise host-only empty-seat precondition.
            eval.add_constraint(
                is_set_leave.clone()
                    * transition_selector.clone()
                    * full_pre_status[index][CanonicalSeatStatus::Empty as usize].clone(),
            );

            // `set_leave_after_hand` has exactly one VM argument: the desired
            // boolean flag.  The canonical action ABI still reserves four amount
            // limbs and four auxiliary limbs, so constrain every reserved limb to
            // zero instead of letting a host choose an unconsumed payload that is
            // absent from the VM transition relation.
            for value in amount.iter().chain(auxiliary.iter()) {
                eval.add_constraint(is_set_leave.clone() * value.clone());
            }

            selected_full_pre_status += selector.clone() * pre_status_value.clone();
            selected_full_post_status += selector.clone() * post_status_value.clone();
            selected_funding_pre_status += funding_selector.clone() * pre_status_value.clone();
            selected_funding_post_status += funding_selector.clone() * post_status_value.clone();
            selected_transition_pre_status +=
                transition_selector.clone() * pre_status_value.clone();
            selected_transition_post_status +=
                transition_selector.clone() * post_status_value.clone();
            for limb in 0..4 {
                selected_transition_pre_stack[limb] +=
                    transition_selector.clone() * full_pre_stack[index][limb].clone();
                selected_transition_pre_pending[limb] +=
                    transition_selector.clone() * full_pre_pending[index][limb].clone();
                selected_transition_pre_bet[limb] +=
                    transition_selector.clone() * full_pre_bet[index][limb].clone();
            }
            for limb in 0..4 {
                selected_full_pre_stack[limb] +=
                    selector.clone() * full_pre_stack[index][limb].clone();
                selected_full_post_stack[limb] +=
                    selector.clone() * full_post_stack[index][limb].clone();
                selected_full_pre_bet[limb] += selector.clone() * full_pre_bet[index][limb].clone();
                selected_full_post_bet[limb] +=
                    selector.clone() * full_post_bet[index][limb].clone();
                selected_full_pre_total[limb] +=
                    selector.clone() * full_pre_total[index][limb].clone();
                selected_full_post_total[limb] +=
                    selector.clone() * full_post_total[index][limb].clone();
                selected_full_pre_pending[limb] +=
                    selector.clone() * full_pre_pending[index][limb].clone();
                selected_full_post_pending[limb] +=
                    selector.clone() * full_post_pending[index][limb].clone();
                selected_funding_pre_stack[limb] +=
                    funding_selector.clone() * full_pre_stack[index][limb].clone();
                selected_funding_post_stack[limb] +=
                    funding_selector.clone() * full_post_stack[index][limb].clone();
                selected_funding_pre_bet[limb] +=
                    funding_selector.clone() * full_pre_bet[index][limb].clone();
                selected_funding_post_bet[limb] +=
                    funding_selector.clone() * full_post_bet[index][limb].clone();
                selected_funding_pre_total[limb] +=
                    funding_selector.clone() * full_pre_total[index][limb].clone();
                selected_funding_post_total[limb] +=
                    funding_selector.clone() * full_post_total[index][limb].clone();
                selected_funding_pre_pending[limb] +=
                    funding_selector.clone() * full_pre_pending[index][limb].clone();
                selected_funding_post_pending[limb] +=
                    funding_selector.clone() * full_post_pending[index][limb].clone();
            }
            for limb in 0..2 {
                selected_full_pre_time[limb] +=
                    selector.clone() * full_pre_time_bank[index][limb].clone();
                selected_full_post_time[limb] +=
                    selector.clone() * full_post_time_bank[index][limb].clone();
                selected_funding_pre_time[limb] +=
                    funding_selector.clone() * full_pre_time_bank[index][limb].clone();
                selected_funding_post_time[limb] +=
                    funding_selector.clone() * full_post_time_bank[index][limb].clone();
            }

            let unselected_betting = is_betting.clone() - betting_selector;
            for status in 0..SEAT_STATUS_COUNT {
                eval.add_constraint(
                    unselected_betting.clone()
                        * (full_post_status[index][status].clone()
                            - full_pre_status[index][status].clone()),
                );
            }
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(
                        unselected_betting.clone() * (right.clone() - left.clone()),
                    );
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(unselected_betting.clone() * (right.clone() - left.clone()));
            }

            // CreateTable does not alter any public seat bucket.  StartHand keeps
            // every seat's funds identical but may promote Waiting seats to
            // Active (waiting-for-big-blind admission); the promotion domain is
            // constrained below.  For actions that target one lifecycle seat,
            // every non-target seat must also remain identical.  This uses the
            // complete nine seat projection, not the single legacy action-seat
            // projection.
            let immutable_full_seat =
                is_create.clone() + is_set_leave.clone() + is_deadline_extension.clone();
            let immutable_funds = immutable_full_seat.clone() + is_start.clone();
            let immutable_time_bank = (immutable_full_seat.clone() - is_deadline_extension.clone())
                + is_deadline_extension.clone() * (one.clone() - transition_selector.clone());
            let unselected_lifecycle =
                is_selected_lifecycle.clone() * (one.clone() - transition_selector.clone());
            for status in 0..SEAT_STATUS_COUNT {
                let unchanged = full_post_status[index][status].clone()
                    - full_pre_status[index][status].clone();
                eval.add_constraint(immutable_full_seat.clone() * unchanged.clone());
                eval.add_constraint(unselected_lifecycle.clone() * unchanged.clone());
                if status == CanonicalSeatStatus::Active as usize {
                    // DeltaActive must equal pre_waiting - post_waiting, so the only
                    // legal lifecycle change is a Waiting -> Active promotion.
                    eval.add_constraint(
                        is_start.clone()
                            * (unchanged.clone()
                                - full_pre_status[index][CanonicalSeatStatus::Waiting as usize]
                                    .clone()
                                + full_post_status[index][CanonicalSeatStatus::Waiting as usize]
                                    .clone()),
                    );
                } else if status != CanonicalSeatStatus::Waiting as usize {
                    eval.add_constraint(is_start.clone() * unchanged);
                }
                // The Waiting channel is one-way: post_waiting implies
                // pre_waiting (no Active -> Waiting demotion).
                eval.add_constraint(
                    is_start.clone()
                        * (full_post_status[index][CanonicalSeatStatus::Waiting as usize].clone()
                            - full_pre_status[index][CanonicalSeatStatus::Waiting as usize]
                                .clone()
                                * full_post_status[index][CanonicalSeatStatus::Waiting as usize]
                                    .clone()),
                );
            }
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    let unchanged = right.clone() - left.clone();
                    eval.add_constraint(immutable_funds.clone() * unchanged.clone());
                    eval.add_constraint(unselected_lifecycle.clone() * unchanged);
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                let unchanged = right.clone() - left.clone();
                eval.add_constraint(immutable_time_bank.clone() * unchanged.clone());
                eval.add_constraint(unselected_lifecycle.clone() * unchanged);
            }

            // Funding is also selected from the fixed full-seat opening.  It
            // may change only the target's stack or pending addon; every other
            // mutable bucket stays byte-for-byte represented by the same
            // limbs.  The selected projection below then feeds the existing
            // exact ripple-carry funding relation.
            let unselected_funding = is_funding.clone() - funding_selector.clone();
            for status in 0..SEAT_STATUS_COUNT {
                eval.add_constraint(
                    is_funding.clone()
                        * (full_post_status[index][status].clone()
                            - full_pre_status[index][status].clone()),
                );
            }
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(
                        unselected_funding.clone() * (right.clone() - left.clone()),
                    );
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(unselected_funding.clone() * (right.clone() - left.clone()));
            }
            for (left, right) in full_pre_bet[index].iter().zip(full_post_bet[index].iter()) {
                eval.add_constraint(funding_selector.clone() * (right.clone() - left.clone()));
            }
            for (left, right) in full_pre_total[index]
                .iter()
                .zip(full_post_total[index].iter())
            {
                eval.add_constraint(funding_selector.clone() * (right.clone() - left.clone()));
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(funding_selector.clone() * (right.clone() - left.clone()));
            }

            eval.add_constraint(
                raise_actor[index].clone() - is_raise.clone() * acted_seat_selectors[index].clone(),
            );
            eval.add_constraint(
                raise_active[index].clone()
                    - is_raise.clone()
                        * full_pre_status[index][CanonicalSeatStatus::Active as usize].clone(),
            );
            eval.add_constraint(
                raise_actor[index].clone() * (post_acted_bits[index].clone() - one.clone()),
            );
            // Only a full raise (raise_delta >= pre min_raise) reopens action
            // for the other Active seats; a sub-minimum all-in keeps their
            // acted bits exactly as the VM does (TDA #41).
            let raise_reset_others = raise_meets_min.clone()
                * (raise_active[index].clone() - raise_actor[index].clone());
            eval.add_constraint(raise_reset_others.clone() * post_acted_bits[index].clone());
            eval.add_constraint(
                (is_raise.clone() - raise_actor[index].clone() - raise_reset_others.clone())
                    * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
        }
        eval.add_constraint(funding_selector_sum - is_funding.clone());
        eval.add_constraint(selected_funding_seat - is_funding.clone() * seat.clone());
        eval.add_constraint(transition_selector_sum - requires_transition_seat.clone());
        eval.add_constraint(
            selected_transition_seat - requires_transition_seat.clone() * seat.clone(),
        );
        eval.add_constraint(
            requires_transition_seat.clone() * pre_status.clone() - selected_transition_pre_status,
        );
        eval.add_constraint(
            requires_transition_seat.clone() * post_status.clone()
                - selected_transition_post_status,
        );
        for (projected, full) in pre_time_bank
            .iter()
            .zip(selected_transition_pre_time.iter())
        {
            eval.add_constraint(
                requires_transition_seat.clone() * projected.clone() - full.clone(),
            );
        }
        for (projected, full) in post_time_bank
            .iter()
            .zip(selected_transition_post_time.iter())
        {
            eval.add_constraint(
                requires_transition_seat.clone() * projected.clone() - full.clone(),
            );
        }
        // The funding selector must open the very same selected seat that the
        // fixed ABI projects into the arithmetic rows below.  Without these
        // equalities a prover could satisfy the Addon/Rebuy limb equations
        // against an unrelated synthetic seat while changing a different
        // full-seat image.
        eval.add_constraint(is_funding.clone() * pre_status.clone() - selected_funding_pre_status);
        eval.add_constraint(
            is_funding.clone() * post_status.clone() - selected_funding_post_status,
        );
        for (projected, full) in pre_stack.iter().zip(selected_funding_pre_stack.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_stack.iter().zip(selected_funding_post_stack.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_bet.iter().zip(selected_funding_pre_bet.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_bet.iter().zip(selected_funding_post_bet.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_total.iter().zip(selected_funding_pre_total.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_total.iter().zip(selected_funding_post_total.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_pending.iter().zip(selected_funding_pre_pending.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_pending
            .iter()
            .zip(selected_funding_post_pending.iter())
        {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_time_bank.iter().zip(selected_funding_pre_time.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_time_bank.iter().zip(selected_funding_post_time.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        // `advance_turn` scans circularly from the acting seat. Its choice is
        // no longer a host-selected `post.current_turn`: a one-hot successor
        // and a 9x9 pair decomposition bind the first post-action *actionable*
        // seat (`Active && !acted`). Already-acted active players are skipped,
        // exactly as the VM's circular turn scan does. `no_next_turn` is
        // permitted only when no actionable seat remains.
        eval.add_constraint(no_next_turn.clone() * (no_next_turn.clone() - one.clone()));
        eval.add_constraint((active.clone() - is_betting.clone()) * no_next_turn.clone());
        let mut next_sum: E::F = M31::from(0u32).into();
        let mut next_turn_value: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let selector = next_turn_selectors[index].clone();
            eval.add_constraint(
                active.clone() * selector.clone() * (selector.clone() - one.clone()),
            );
            eval.add_constraint(
                (active.clone() - is_betting.clone() - is_force_fold.clone()) * selector.clone(),
            );
            eval.add_constraint(
                selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Active as usize].clone()
                        - one.clone()),
            );
            // If the action stays in this mid-round component, the VM's next
            // actor is either an unacted Active seat or — after a short
            // all-in raised the water over it — an acted seat that still owes
            // chips (it must call or fold; TDA #41).  Otherwise the
            // just-completed round must follow the separate collect/advance
            // relation rather than be represented as a stale betting row.
            eval.add_constraint(selector.clone() * seat_settled[index].clone());
            // No successor is valid only at the exact completed-round
            // boundary: every remaining actionable seat must already have
            // acted and matched the final current bet.  The following
            // `AdvanceRound` row then performs the all-seat collection.
            let post_active = full_post_status[index][CanonicalSeatStatus::Active as usize].clone();
            let completed_active = round_complete_active[index].clone();
            eval.add_constraint(
                completed_active.clone() - no_next_turn.clone() * post_active.clone(),
            );
            eval.add_constraint(
                completed_active.clone() * (post_acted_bits[index].clone() - one.clone()),
            );
            for limb in 0..4 {
                eval.add_constraint(
                    completed_active.clone()
                        * (full_post_bet[index][limb].clone() - post_current[limb].clone()),
                );
            }
            next_sum += selector.clone();
            let index_value: E::F = M31::from(index as u32).into();
            next_turn_value += selector * index_value;
        }
        eval.add_constraint(
            next_sum.clone() + no_next_turn.clone() - is_betting.clone() - is_force_fold.clone(),
        );
        let fifteen: E::F = M31::from(15u32).into();
        eval.add_constraint(
            (is_betting.clone() + is_force_fold.clone())
                * (post_turn.clone() - next_turn_value - fifteen * no_next_turn.clone()),
        );
        for from in 0..MAX_CANONICAL_SEATS {
            for to in 0..MAX_CANONICAL_SEATS {
                let pair = next_turn_pairs[from][to].clone();
                eval.add_constraint(
                    pair.clone()
                        - transition_seat_selectors[from].clone() * next_turn_selectors[to].clone(),
                );
                let distance = (to + MAX_CANONICAL_SEATS - from) % MAX_CANONICAL_SEATS;
                let distance = if distance == 0 {
                    MAX_CANONICAL_SEATS
                } else {
                    distance
                };
                for offset in 1..distance {
                    let between = (from + offset) % MAX_CANONICAL_SEATS;
                    // No Active seat may be skipped unless it has already
                    // acted AND matched the post current_bet: actionable =
                    // !acted || owes.
                    eval.add_constraint(
                        pair.clone()
                            * full_post_status[between][CanonicalSeatStatus::Active as usize]
                                .clone()
                            * (one.clone() - seat_settled[between].clone()),
                    );
                }
            }
        }
        // Per-seat `owes` honesty: the flag is binary, and the difference
        // limbs must be the canonical 16-bit subtraction
        // `current_bet - seat.bet` with a borrow chain on betting rows.
        // When the flag is clear the limbs and borrows are zero, which forces
        // `seat.bet == current_bet` — a host cannot hide an acted seat that
        // still owes chips from the successor scan above.
        for index in 0..MAX_CANONICAL_SEATS {
            let owes = seat_owes[index].clone();
            eval.add_constraint(active.clone() * owes.clone() * (owes.clone() - one.clone()));
            for limb in 0..4 {
                eval.add_constraint(
                    active.clone()
                        * (one.clone() - owes.clone())
                        * seat_owes_diff[index][limb].clone(),
                );
            }
            for borrow in &seat_owes_borrows[index] {
                eval.add_constraint(
                    active.clone() * borrow.clone() * (borrow.clone() - one.clone()),
                );
                eval.add_constraint(active.clone() * (one.clone() - owes.clone()) * borrow.clone());
            }
            // Ripple-borrow chain, gated to post-Active seats: empty/folded/
            // all-in seats keep owes zero and are exempt (their bet is not
            // comparable to the round water).
            let owes_active = full_post_status[index][CanonicalSeatStatus::Active as usize].clone();
            let owes_base: E::F = M31::from(65_536u32).into();
            eval.add_constraint(
                is_betting.clone()
                    * owes_active.clone()
                    * (post_current[0].clone()
                        - full_post_bet[index][0].clone()
                        - seat_owes_diff[index][0].clone()
                        + owes_base.clone() * seat_owes_borrows[index][0].clone()),
            );
            eval.add_constraint(
                is_betting.clone()
                    * owes_active.clone()
                    * (post_current[1].clone()
                        - full_post_bet[index][1].clone()
                        - seat_owes_diff[index][1].clone()
                        - seat_owes_borrows[index][0].clone()
                        + owes_base.clone() * seat_owes_borrows[index][1].clone()),
            );
            eval.add_constraint(
                is_betting.clone()
                    * owes_active.clone()
                    * (post_current[2].clone()
                        - full_post_bet[index][2].clone()
                        - seat_owes_diff[index][2].clone()
                        - seat_owes_borrows[index][1].clone()
                        + owes_base.clone() * seat_owes_borrows[index][2].clone()),
            );
            eval.add_constraint(
                is_betting.clone()
                    * owes_active.clone()
                    * (post_current[3].clone()
                        - full_post_bet[index][3].clone()
                        - seat_owes_diff[index][3].clone()
                        - seat_owes_borrows[index][2].clone()),
            );
            // owes = 1 must prove a non-zero difference limb sum; the owes=0
            // rows carry a zero inverse, so no extra selector gate is needed
            // (and gating would raise the expression degree above three).
            let mut owes_sum: E::F = M31::from(0u32).into();
            for limb in 0..4 {
                owes_sum += seat_owes_diff[index][limb].clone();
            }
            eval.add_constraint(
                owes.clone() * (owes_sum.clone() * seat_owes_inv[index].clone() - one.clone()),
            );
            eval.add_constraint((one.clone() - owes.clone()) * seat_owes_inv[index].clone());
            // settled <=> acted && !owes (degree-safe turn-scan helper),
            // meaningful on betting rows only.
            eval.add_constraint(
                is_betting.clone()
                    * (seat_settled[index].clone()
                        - post_acted_bits[index].clone() * (one.clone() - owes.clone())),
            );
            // settled <=> acted && !owes (degree-safe turn-scan helper).
        }
        eval.add_constraint(is_betting.clone() * pre_status.clone() - selected_full_pre_status);
        eval.add_constraint(is_betting.clone() * post_status.clone() - selected_full_post_status);
        for (projected, full) in pre_stack.iter().zip(selected_full_pre_stack.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_stack.iter().zip(selected_full_post_stack.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_bet.iter().zip(selected_full_pre_bet.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_bet.iter().zip(selected_full_post_bet.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_total.iter().zip(selected_full_pre_total.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_total.iter().zip(selected_full_post_total.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_pending.iter().zip(selected_full_pre_pending.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_pending.iter().zip(selected_full_post_pending.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_time_bank.iter().zip(selected_full_pre_time.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_time_bank.iter().zip(selected_full_post_time.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        let mut post_stack_sum: E::F = M31::from(0u32).into();
        let mut pre_stack_sum: E::F = M31::from(0u32).into();
        for limb in &post_stack {
            post_stack_sum += limb.clone();
        }
        for limb in &pre_stack {
            pre_stack_sum += limb.clone();
        }
        // The VM transitions an acting player to AllIn exactly when its stack
        // reaches zero.  `chip_action_post_stack_sum` keeps the selector out
        // of the inverse relation, preserving degree two over M31.
        eval.add_constraint(post_all_in.clone() * (post_all_in.clone() - one.clone()));
        eval.add_constraint((active.clone() - chip_action.clone()) * post_all_in.clone());
        eval.add_constraint(
            (active.clone() - chip_action.clone()) * chip_action_post_stack_sum.clone(),
        );
        eval.add_constraint(
            (active.clone() - chip_action.clone()) * chip_action_post_stack_inv.clone(),
        );
        eval.add_constraint(
            chip_action_post_stack_sum.clone() - chip_action.clone() * post_stack_sum,
        );
        eval.add_constraint(post_all_in.clone() * chip_action_post_stack_sum.clone());
        eval.add_constraint(
            chip_action_post_stack_sum.clone() * chip_action_post_stack_inv.clone()
                - (chip_action.clone() - post_all_in.clone()),
        );
        eval.add_constraint(
            chip_action.clone()
                * (post_status.clone() - (two.clone() + two.clone() * post_all_in.clone())),
        );
        // An active player may be selected only while it owns chips.  This
        // mirrors the VM invariant that a stack reaching zero becomes AllIn
        // before the next turn scan.  As above, the scaled sum keeps the
        // inverse relation quadratic.
        eval.add_constraint((active.clone() - is_betting.clone()) * betting_pre_stack_sum.clone());
        eval.add_constraint((active.clone() - is_betting.clone()) * betting_pre_stack_inv.clone());
        eval.add_constraint(betting_pre_stack_sum.clone() - is_betting.clone() * pre_stack_sum);
        eval.add_constraint(
            betting_pre_stack_sum.clone() * betting_pre_stack_inv.clone() - is_betting.clone(),
        );
        for index in 0..4 {
            range16_constraints(
                &mut eval,
                &is_call,
                &call_owed[index],
                &call_owed_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_call,
                &call_difference[index],
                &call_difference_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_raise,
                &raise_needed[index],
                &raise_needed_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_raise,
                &raise_delta[index],
                &raise_delta_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_raise,
                &raise_stack_difference[index],
                &raise_stack_difference_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_raise,
                &raise_min_difference[index],
                &raise_min_difference_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &pre_chip_pool[index],
                &pre_chip_pool_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &post_chip_pool[index],
                &post_chip_pool_bits[index],
            );
        }
        // Check and Fold do not move chips. A Call amount is a strictly positive
        // delta, proved with an inverse of the sum of its canonical limbs.
        for limb in &amount {
            eval.add_constraint(
                (is_check.clone() + is_fold.clone() + is_auto_fold.clone()) * limb.clone(),
            );
        }
        let mut amount_sum: E::F = M31::from(0u32).into();
        for limb in &amount {
            amount_sum += limb.clone();
        }
        eval.add_constraint(
            (is_call.clone()
                + is_bet.clone()
                + is_shuffle_timeout.clone()
                + is_timeout_reset.clone()
                + is_reveal_kick.clone()
                + is_reveal_reconstruct.clone()
                + is_award_family.clone())
                * (amount_sum * amount_inv.clone() - one.clone()),
        );
        // The native funding selectors are the only transitions that credit
        // TableVault.  Addon credits the next-hand balance; Rebuy credits the
        // live stack.  No VM replay-derived amount or branch is used here.
        let mut funding_amount_sum: E::F = M31::from(0u32).into();
        for limb in &amount {
            funding_amount_sum += limb.clone();
        }
        eval.add_constraint(
            is_funding.clone() * (funding_amount_sum * amount_inv.clone() - one.clone()),
        );
        limb4_add_constraints(
            &mut eval,
            &is_funding,
            &pre_chip_pool,
            &amount,
            &post_chip_pool,
            &funding_chip_pool_carries,
        );
        for carry in &funding_chip_pool_carries {
            eval.add_constraint(
                (active.clone()
                    - is_funding.clone()
                    - is_kick.clone()
                    - is_join.clone()
                    - is_leave.clone()
                    - is_shuffle_timeout.clone()
                    - is_timeout_reset.clone()
                    - is_reveal_reconstruct.clone()
                    - is_award_family.clone())
                    * carry.clone(),
            );
        }
        for (pre, post) in [
            (&pre_phase, &post_phase),
            (&pre_subtag, &post_subtag),
            (&pre_street, &post_street),
            (&pre_turn, &post_turn),
            (&pre_acted_mask, &post_acted_mask),
            (&pre_leave_mask, &post_leave_mask),
            (&pre_status, &post_status),
            (&pre_seat_acted, &post_seat_acted),
        ] {
            eval.add_constraint(is_funding.clone() * (post.clone() - pre.clone()));
        }
        for (pre, post) in [
            (&pre_current, &post_current),
            (&pre_min, &post_min),
            (&pre_pot, &post_pot),
            (&pre_bet, &post_bet),
            (&pre_total, &post_total),
        ] {
            for (left, right) in pre.iter().zip(post.iter()) {
                eval.add_constraint(is_funding.clone() * (right.clone() - left.clone()));
            }
        }
        for (pre, post) in pre_time_bank.iter().zip(post_time_bank.iter()) {
            eval.add_constraint(is_funding.clone() * (post.clone() - pre.clone()));
        }
        limb4_add_constraints(
            &mut eval,
            &is_addon,
            &pre_pending,
            &amount,
            &post_pending,
            &funding_addon_carries,
        );
        for (left, right) in post_stack.iter().zip(pre_stack.iter()) {
            eval.add_constraint(is_addon.clone() * (left.clone() - right.clone()));
        }
        limb4_add_constraints(
            &mut eval,
            &is_rebuy,
            &pre_stack,
            &amount,
            &post_stack,
            &funding_rebuy_carries,
        );
        for (left, right) in post_pending.iter().zip(pre_pending.iter()) {
            eval.add_constraint(is_rebuy.clone() * (left.clone() - right.clone()));
        }
        for carry in &funding_addon_carries {
            eval.add_constraint(
                (active.clone()
                    - is_addon.clone()
                    - is_kick.clone()
                    - is_shuffle_timeout.clone()
                    - is_timeout_reset.clone()
                    - is_reveal_reconstruct.clone())
                    * carry.clone(),
            );
        }
        for carry in &funding_rebuy_carries {
            eval.add_constraint(
                (active.clone()
                    - is_rebuy.clone()
                    - is_kick.clone()
                    - is_leave.clone()
                    - is_shuffle_timeout.clone()
                    - is_timeout_reset.clone()
                    - is_reveal_reconstruct.clone()
                    - is_award_family.clone())
                    * carry.clone(),
            );
        }
        // Join locks the buy-in into TableVault and the selected seat stack.
        // Leave performs the inverse refund of stack plus pending addon.
        limb4_add_constraints(
            &mut eval,
            &is_join,
            &pre_chip_pool,
            &amount,
            &post_chip_pool,
            &funding_chip_pool_carries,
        );
        for limb in 0..4 {
            eval.add_constraint(
                is_leave.clone()
                    * (pre_stack[limb].clone() - selected_transition_pre_stack[limb].clone()),
            );
            eval.add_constraint(
                is_leave.clone()
                    * (pre_pending[limb].clone() - selected_transition_pre_pending[limb].clone()),
            );
        }
        limb4_add_constraints(
            &mut eval,
            &is_leave,
            &selected_transition_pre_stack,
            &selected_transition_pre_pending,
            &amount,
            &funding_rebuy_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_leave,
            &post_chip_pool,
            &amount,
            &pre_chip_pool,
            &funding_chip_pool_carries,
        );
        // Non-cascading KickPlayer is the VM's explicit refund path:
        // `amount = stack + pending_addon`, `pot += current bet`, and
        // `chip_pool -= amount`.  The carry witnesses above are reused without
        // widening the committed trace.
        for limb in 0..4 {
            eval.add_constraint(
                is_kick.clone()
                    * (pre_stack[limb].clone() - selected_transition_pre_stack[limb].clone()),
            );
            eval.add_constraint(
                is_kick.clone()
                    * (pre_pending[limb].clone() - selected_transition_pre_pending[limb].clone()),
            );
            eval.add_constraint(
                is_kick.clone()
                    * (pre_bet[limb].clone() - selected_transition_pre_bet[limb].clone()),
            );
        }
        limb4_add_constraints(
            &mut eval,
            &is_kick,
            &selected_transition_pre_stack,
            &selected_transition_pre_pending,
            &amount,
            &funding_rebuy_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_kick,
            &post_chip_pool,
            &amount,
            &pre_chip_pool,
            &funding_chip_pool_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_kick,
            &pre_pot,
            &selected_transition_pre_bet,
            &post_pot,
            &funding_addon_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_shuffle_timeout,
            &post_chip_pool,
            &amount,
            &pre_chip_pool,
            &funding_chip_pool_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_shuffle_timeout,
            &pre_pot,
            &pre_bet,
            &post_pot,
            &funding_addon_carries,
        );
        // The reveal-timeout reconstruct terminal reuses the kick refund
        // arithmetic: `amount = stack + pending_addon`, `pot += bet`, and
        // `chip_pool -= amount`, all against the transition-selector opening
        // of the terminal seat rather than a host projection.
        for limb in 0..4 {
            eval.add_constraint(
                is_reveal_reconstruct.clone()
                    * (pre_stack[limb].clone() - selected_transition_pre_stack[limb].clone()),
            );
            eval.add_constraint(
                is_reveal_reconstruct.clone()
                    * (pre_pending[limb].clone() - selected_transition_pre_pending[limb].clone()),
            );
            eval.add_constraint(
                is_reveal_reconstruct.clone()
                    * (pre_bet[limb].clone() - selected_transition_pre_bet[limb].clone()),
            );
        }
        limb4_add_constraints(
            &mut eval,
            &is_reveal_reconstruct,
            &selected_transition_pre_stack,
            &selected_transition_pre_pending,
            &amount,
            &funding_rebuy_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_reveal_reconstruct,
            &post_chip_pool,
            &amount,
            &pre_chip_pool,
            &funding_chip_pool_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_reveal_reconstruct,
            &pre_pot,
            &selected_transition_pre_bet,
            &post_pot,
            &funding_addon_carries,
        );
        // The sole-survivor award reuses the same kick refund arithmetic; the
        // pot itself is credited to the winner's stack, not collected.
        for limb in 0..4 {
            eval.add_constraint(
                is_award_family.clone()
                    * (pre_stack[limb].clone() - selected_transition_pre_stack[limb].clone()),
            );
            eval.add_constraint(
                is_award_family.clone()
                    * (pre_pending[limb].clone() - selected_transition_pre_pending[limb].clone()),
            );
            eval.add_constraint(
                is_award_family.clone()
                    * (pre_bet[limb].clone() - selected_transition_pre_bet[limb].clone()),
            );
        }
        limb4_add_constraints(
            &mut eval,
            &is_award_family,
            &selected_transition_pre_stack,
            &selected_transition_pre_pending,
            &amount,
            &funding_rebuy_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_reveal_award,
            &post_chip_pool,
            &amount,
            &pre_chip_pool,
            &funding_chip_pool_carries,
        );

        for (pre, post) in [
            (&pre_phase, &post_phase),
            (&pre_subtag, &post_subtag),
            (&pre_street, &post_street),
            (&pre_turn, &post_turn),
        ] {
            eval.add_constraint(is_kick.clone() * (post.clone() - pre.clone()));
        }
        for (left, right) in pre_deadline_image.iter().zip(post_deadline_image.iter()) {
            eval.add_constraint(is_kick.clone() * (right.clone() - left.clone()));
        }
        eval.add_constraint(
            active.clone() * call_all_in.clone() * (call_all_in.clone() - one.clone()),
        );
        eval.add_constraint((active.clone() - is_call.clone()) * call_all_in.clone());
        let mut call_difference_sum: E::F = M31::from(0u32).into();
        for limb in &call_difference {
            call_difference_sum += limb.clone();
        }
        eval.add_constraint(
            call_all_in.clone() * (call_difference_sum * call_difference_inv.clone() - one.clone()),
        );
        limb4_add_constraints(
            &mut eval,
            &is_call,
            &pre_bet,
            &call_owed,
            &pre_current,
            &call_owed_carries,
        );
        let ordinary_call = is_call.clone() - call_all_in.clone();
        limb4_add_constraints(
            &mut eval,
            &ordinary_call,
            &call_owed,
            &call_difference,
            &pre_stack,
            &call_excess_carries,
        );
        let short_call = call_all_in.clone();
        limb4_add_constraints(
            &mut eval,
            &short_call,
            &pre_stack,
            &call_difference,
            &call_owed,
            &call_shortfall_carries,
        );
        for index in 0..4 {
            eval.add_constraint(
                is_call.clone() * (amount[index].clone() - call_owed[index].clone())
                    + call_all_in.clone() * (call_owed[index].clone() - pre_stack[index].clone()),
            );
        }
        // Raise uses an absolute target (`amount`), unlike Call/Bet deltas.
        // The three canonical subtractions prove target > seat bet, target >
        // current bet, and needed <= stack. No host comparison result selects
        // a branch here.
        for value in [&raise_all_in, &raise_meets_min] {
            eval.add_constraint(active.clone() * value.clone() * (value.clone() - one.clone()));
            eval.add_constraint((active.clone() - is_raise.clone()) * value.clone());
        }
        // All Raise-only auxiliary columns must be zero on every other active
        // transition.  Besides making the tagged trace canonical, this closes
        // an otherwise unconstrained witness surface on Call/Bet/Fold/Check
        // rows.  These values are private advice, but an AIR must never leave
        // advice free merely because a selector is false.
        let non_raise = active.clone() - is_raise.clone();
        for value in [
            &raise_needed,
            &raise_delta,
            &raise_stack_difference,
            &raise_min_difference,
        ] {
            for limb in value {
                eval.add_constraint(non_raise.clone() * limb.clone());
            }
        }
        for value in [
            &raise_needed_inv,
            &raise_delta_inv,
            &raise_stack_difference_inv,
        ] {
            eval.add_constraint(non_raise.clone() * value.clone());
        }
        for carry in raise_needed_carries
            .iter()
            .chain(raise_delta_carries.iter())
            .chain(raise_stack_carries.iter())
            .chain(raise_total_carries.iter())
            .chain(raise_pot_carries.iter())
        {
            eval.add_constraint(non_raise.clone() * carry.clone());
        }
        for bits in raise_needed_bits
            .iter()
            .chain(raise_delta_bits.iter())
            .chain(raise_stack_difference_bits.iter())
            .chain(raise_min_difference_bits.iter())
        {
            for bit in bits {
                eval.add_constraint(non_raise.clone() * bit.clone());
            }
        }
        let mut raise_needed_sum: E::F = M31::from(0u32).into();
        let mut raise_delta_sum: E::F = M31::from(0u32).into();
        let mut raise_stack_difference_sum: E::F = M31::from(0u32).into();
        for index in 0..4 {
            raise_needed_sum += raise_needed[index].clone();
            raise_delta_sum += raise_delta[index].clone();
            raise_stack_difference_sum += raise_stack_difference[index].clone();
        }
        eval.add_constraint(
            is_raise.clone() * (raise_needed_sum.clone() * raise_needed_inv.clone() - one.clone()),
        );
        eval.add_constraint(
            is_raise.clone() * (raise_delta_sum.clone() * raise_delta_inv.clone() - one.clone()),
        );
        eval.add_constraint(
            is_raise.clone() * raise_all_in.clone() * raise_stack_difference_sum.clone(),
        );
        eval.add_constraint(
            is_raise.clone()
                * (raise_stack_difference_sum.clone() * raise_stack_difference_inv.clone()
                    - (one.clone() - raise_all_in.clone())),
        );
        // A sub-minimum raise is valid only when it consumes the entire stack.
        eval.add_constraint(
            is_raise.clone()
                * (one.clone() - raise_meets_min.clone())
                * (one.clone() - raise_all_in.clone()),
        );
        limb4_add_constraints(
            &mut eval,
            &is_raise,
            &pre_bet,
            &raise_needed,
            &amount,
            &raise_needed_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_raise,
            &pre_current,
            &raise_delta,
            &amount,
            &raise_delta_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_raise,
            &raise_needed,
            &raise_stack_difference,
            &pre_stack,
            &raise_stack_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_raise,
            &pre_total,
            &raise_needed,
            &post_total,
            &raise_total_carries,
        );
        for index in 0..4 {
            eval.add_constraint(
                is_raise.clone() * (post_current[index].clone() - amount[index].clone()),
            );
            eval.add_constraint(
                is_raise.clone() * (post_bet[index].clone() - amount[index].clone()),
            );
            eval.add_constraint(
                is_raise.clone()
                    * (post_stack[index].clone() - raise_stack_difference[index].clone()),
            );
            eval.add_constraint(
                is_raise.clone() * (post_pending[index].clone() - pre_pending[index].clone()),
            );
            eval.add_constraint(
                is_raise.clone() * (post_pot[index].clone() - pre_pot[index].clone()),
            );
            eval.add_constraint(
                is_raise.clone()
                    * (raise_meets_min.clone()
                        * (pre_min[index].clone() + raise_min_difference[index].clone()
                            - raise_delta[index].clone())
                        + (one.clone() - raise_meets_min.clone())
                            * (raise_delta[index].clone() + raise_min_difference[index].clone()
                                - pre_min[index].clone())),
            );
            eval.add_constraint(
                is_raise.clone()
                    * (raise_meets_min.clone()
                        * (post_min[index].clone() - raise_delta[index].clone())
                        + (one.clone() - raise_meets_min.clone())
                            * (post_min[index].clone() - pre_min[index].clone())),
            );
        }
        for carry in &raise_pot_carries {
            eval.add_constraint(is_raise.clone() * carry.clone());
        }
        for (left, right) in pre_bet.iter().zip(pre_current.iter()) {
            eval.add_constraint(is_check.clone() * (left.clone() - right.clone()));
        }
        for (post, pre) in [
            (&post_current, &pre_current),
            (&post_min, &pre_min),
            (&post_pot, &pre_pot),
            (&post_stack, &pre_stack),
            (&post_bet, &pre_bet),
            (&post_total, &pre_total),
            (&post_pending, &pre_pending),
        ] {
            for (left, right) in post.iter().zip(pre.iter()) {
                eval.add_constraint(is_check.clone() * (left.clone() - right.clone()));
            }
        }
        // Fold and FoldWithProof leave the monetary image unchanged. The
        // latter changes only the encrypted deck lineage, not chips or the
        // selected participant's identity material. A Call keeps the round
        // target/minimum and collected pot unchanged: its wager remains in
        // the seat until the VM's round-advance collection step.
        for (post, pre) in [
            (&post_current, &pre_current),
            (&post_min, &pre_min),
            (&post_pot, &pre_pot),
            (&post_stack, &pre_stack),
            (&post_bet, &pre_bet),
            (&post_total, &pre_total),
            (&post_pending, &pre_pending),
        ] {
            for (left, right) in post.iter().zip(pre.iter()) {
                eval.add_constraint(is_fold_like.clone() * (left.clone() - right.clone()));
            }
        }
        for (post, pre) in post_time_bank.iter().zip(pre_time_bank.iter()) {
            eval.add_constraint(is_fold_like.clone() * (post.clone() - pre.clone()));
        }
        for (post, pre) in [(&post_current, &pre_current), (&post_min, &pre_min)] {
            for (left, right) in post.iter().zip(pre.iter()) {
                eval.add_constraint(is_call.clone() * (left.clone() - right.clone()));
            }
        }
        for (left, right) in post_pot.iter().zip(pre_pot.iter()) {
            eval.add_constraint(is_call.clone() * (left.clone() - right.clone()));
        }
        limb4_add_constraints(
            &mut eval,
            &is_call,
            &post_stack,
            &amount,
            &pre_stack,
            &stack_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_call,
            &pre_bet,
            &amount,
            &post_bet,
            &bet_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_call,
            &pre_total,
            &amount,
            &post_total,
            &total_carries,
        );
        for carry in &pot_carries {
            eval.add_constraint((is_call.clone() + is_bet.clone()) * carry.clone());
        }
        let non_delta_wager = active.clone() - is_call.clone() - is_bet.clone();
        for carry in stack_carries
            .iter()
            .chain(bet_carries.iter())
            .chain(total_carries.iter())
            .chain(pot_carries.iter())
        {
            eval.add_constraint(non_delta_wager.clone() * carry.clone());
        }
        // An unopened-round Bet commits exactly `amount` chips.  This is kept
        // separate from Raise, whose action amount is an absolute target bet.
        for (left, right) in pre_bet.iter().zip(pre_current.iter()) {
            eval.add_constraint(is_bet.clone() * (left.clone() - right.clone()));
        }
        for (left, right) in post_current.iter().zip(post_bet.iter()) {
            eval.add_constraint(is_bet.clone() * (left.clone() - right.clone()));
        }
        for (left, right) in post_min.iter().zip(amount.iter()) {
            eval.add_constraint(is_bet.clone() * (left.clone() - right.clone()));
        }
        limb4_add_constraints(
            &mut eval,
            &is_bet,
            &post_stack,
            &amount,
            &pre_stack,
            &stack_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_bet,
            &pre_bet,
            &amount,
            &post_bet,
            &bet_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_bet,
            &pre_total,
            &amount,
            &post_total,
            &total_carries,
        );
        for (left, right) in post_pot.iter().zip(pre_pot.iter()) {
            eval.add_constraint(is_bet.clone() * (left.clone() - right.clone()));
        }
        let inactive = one.clone() - active.clone();
        for value in [
            &pre_phase,
            &post_phase,
            &pre_subtag,
            &post_subtag,
            &pre_street,
            &post_street,
            &pre_turn,
            &post_turn,
            &pre_acted_mask,
            &post_acted_mask,
            &pre_leave_mask,
            &post_leave_mask,
            &pre_protocol_pending_mask,
            &post_protocol_pending_mask,
            &pre_status,
            &post_status,
            &pre_seat_acted,
            &post_seat_acted,
        ] {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for value in [
            &pre_current,
            &post_current,
            &pre_min,
            &post_min,
            &pre_pot,
            &post_pot,
            &pre_stack,
            &post_stack,
            &pre_bet,
            &post_bet,
            &pre_total,
            &post_total,
            &pre_pending,
            &post_pending,
            &call_owed,
            &call_difference,
            &raise_needed,
            &raise_delta,
            &raise_stack_difference,
            &raise_min_difference,
        ] {
            for limb in value {
                eval.add_constraint(inactive.clone() * limb.clone());
            }
        }
        for limb in pre_time_bank.iter().chain(post_time_bank.iter()) {
            eval.add_constraint(inactive.clone() * limb.clone());
        }
        eval.add_constraint(inactive.clone() * turn_delta_inv.clone());
        eval.add_constraint(inactive.clone() * amount_inv.clone());
        eval.add_constraint(inactive.clone() * call_all_in.clone());
        eval.add_constraint(inactive.clone() * call_difference_inv.clone());
        eval.add_constraint(inactive.clone() * raise_all_in.clone());
        eval.add_constraint(inactive.clone() * raise_meets_min.clone());
        eval.add_constraint(inactive.clone() * raise_needed_inv.clone());
        eval.add_constraint(inactive.clone() * raise_delta_inv.clone());
        eval.add_constraint(inactive.clone() * raise_stack_difference_inv.clone());
        eval.add_constraint(inactive.clone() * post_all_in.clone());
        eval.add_constraint(inactive.clone() * chip_action_post_stack_sum.clone());
        eval.add_constraint(inactive.clone() * chip_action_post_stack_inv.clone());
        eval.add_constraint(inactive.clone() * betting_pre_stack_sum.clone());
        eval.add_constraint(inactive.clone() * betting_pre_stack_inv.clone());
        for value in acted_seat_selectors
            .iter()
            .chain(pre_acted_bits.iter())
            .chain(post_acted_bits.iter())
            .chain(acted_deltas.iter())
            .chain(pre_leave_mask_bits.iter())
            .chain(post_leave_mask_bits.iter())
            .chain(pre_protocol_pending_mask_bits.iter())
            .chain(post_protocol_pending_mask_bits.iter())
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        eval.add_constraint(inactive.clone() * protocol_pending_post_inv.clone());
        eval.add_constraint(inactive.clone() * shuffle_timeout_gate.clone());
        eval.add_constraint(inactive.clone() * shuffle_pending_count_product.clone());
        eval.add_constraint(inactive.clone() * shuffle_deck_diff_square_sum.clone());
        eval.add_constraint(inactive.clone() * shuffle_deck_product.clone());
        eval.add_constraint(inactive.clone() * shuffle_deck_nonzero_change_inv.clone());
        for value in [
            &reveal_reconstruct_diff_square_sum,
            &reveal_reconstruct_change_product,
            &reveal_reconstruct_change_inv,
            &reveal_reconstruct_live_product,
            &reveal_reconstruct_live_inv,
        ] {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for bit in &reveal_reconstruct_street_bits {
            eval.add_constraint(inactive.clone() * bit.clone());
        }
        for bit in &reveal_kick_street_bits {
            eval.add_constraint(inactive.clone() * bit.clone());
        }
        for credit in &reveal_award_winner_credit {
            eval.add_constraint(inactive.clone() * credit.clone());
        }
        eval.add_constraint(inactive.clone() * reveal_award_pot_inv.clone());
        for value in rake_config
            .iter()
            .chain(rake_product.iter())
            .chain(rake_limbs.iter())
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for value in rake_scaled
            .iter()
            .chain(std::iter::once(&rake_remainder))
            .chain(rake_min_diff.iter())
            .chain(rake_min_borrows.iter())
            .chain(rake_final.iter())
            .chain(rake_award.iter())
            .chain(rake_chip_intermediate.iter())
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for carry in rake_div_carries
            .iter()
            .chain(rake_chip_extra_carries.iter())
        {
            eval.add_constraint(inactive.clone() * carry.clone());
        }
        for pair in rake_pot_bytes
            .iter()
            .chain(rake_product_bytes.iter())
            .chain(rake_limb_bytes.iter())
            .chain(rake_scaled_bytes.iter())
            .chain(rake_min_diff_bytes.iter())
            .chain(rake_final_bytes.iter())
            .chain(rake_award_bytes.iter())
        {
            for byte in pair {
                eval.add_constraint(inactive.clone() * byte.clone());
            }
        }
        for byte in rake_remainder_bytes
            .iter()
            .chain(rake_remainder_bound_bytes.iter())
        {
            eval.add_constraint(inactive.clone() * byte.clone());
        }
        eval.add_constraint(inactive.clone() * reveal_award_pot_inv.clone());
        for carry in stack_carries
            .iter()
            .chain(bet_carries.iter())
            .chain(total_carries.iter())
            .chain(pot_carries.iter())
            .chain(call_owed_carries.iter())
            .chain(call_excess_carries.iter())
            .chain(call_shortfall_carries.iter())
            .chain(raise_needed_carries.iter())
            .chain(raise_delta_carries.iter())
            .chain(raise_stack_carries.iter())
            .chain(raise_total_carries.iter())
            .chain(raise_pot_carries.iter())
            .chain(funding_chip_pool_carries.iter())
            .chain(funding_addon_carries.iter())
            .chain(funding_rebuy_carries.iter())
            .chain(round_collect_carries.iter())
        {
            eval.add_constraint(inactive.clone() * carry.clone());
        }
        for bits in &round_collect_carry_bits {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        for bits in round_collect_bet_bits.iter().flatten() {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        for bits in pre_chip_pool_bits.iter().chain(post_chip_pool_bits.iter()) {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        for index in 0..MAX_CANONICAL_SEATS {
            for value in full_pre_status[index]
                .iter()
                .chain(full_post_status[index].iter())
                .chain(full_pre_stack[index].iter())
                .chain(full_post_stack[index].iter())
                .chain(full_pre_bet[index].iter())
                .chain(full_post_bet[index].iter())
                .chain(full_pre_total[index].iter())
                .chain(full_post_total[index].iter())
                .chain(full_pre_pending[index].iter())
                .chain(full_post_pending[index].iter())
                .chain(full_pre_time_bank[index].iter())
                .chain(full_post_time_bank[index].iter())
            {
                eval.add_constraint(inactive.clone() * value.clone());
            }
            eval.add_constraint(inactive.clone() * raise_actor[index].clone());
            eval.add_constraint(inactive.clone() * raise_active[index].clone());
            eval.add_constraint(inactive.clone() * next_turn_selectors[index].clone());
            eval.add_constraint(inactive.clone() * funding_seat_selectors[index].clone());
            eval.add_constraint(inactive.clone() * transition_seat_selectors[index].clone());
            eval.add_constraint(inactive.clone() * round_complete_active[index].clone());
            eval.add_constraint(inactive.clone() * seat_owes[index].clone());
            eval.add_constraint(inactive.clone() * seat_owes_inv[index].clone());
            for limb in &seat_owes_diff[index] {
                eval.add_constraint(inactive.clone() * limb.clone());
            }
            for borrow in &seat_owes_borrows[index] {
                eval.add_constraint(inactive.clone() * borrow.clone());
            }
            eval.add_constraint(inactive.clone() * seat_settled[index].clone());
            for pair in &next_turn_pairs[index] {
                eval.add_constraint(inactive.clone() * pair.clone());
            }
        }
        for value in [
            round_pre_cards_dealt,
            round_post_cards_dealt,
            round_pre_board_len,
            round_post_board_len,
            round_pre_second_board_len,
            round_post_second_board_len,
            round_run_it_twice,
            round_reveal_purpose,
            round_assignment_count,
        ] {
            eval.add_constraint(inactive.clone() * value);
        }
        for assignment in &round_assignments {
            for value in assignment {
                eval.add_constraint(inactive.clone() * value.clone());
            }
        }
        for selector in &round_schedule_selectors {
            eval.add_constraint(inactive.clone() * selector.clone());
        }
        for (pre, post) in [
            (&pre_state_root, &post_state_root),
            (&pre_lifecycle_root, &post_lifecycle_root),
            (&pre_overlay_root, &post_overlay_root),
            (&pre_settlement_commitment, &post_settlement_commitment),
            (&pre_custody_commitment, &post_custody_commitment),
        ] {
            for value in pre.iter().chain(post.iter()) {
                eval.add_constraint(inactive.clone() * value.clone());
            }
        }
        for value in pre_rules_commitment
            .iter()
            .chain(post_rules_commitment.iter())
            .chain(pre_governance_commitment.iter())
            .chain(post_governance_commitment.iter())
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for commitment in pre_opaque_commitments
            .iter()
            .chain(post_opaque_commitments.iter())
        {
            for limb in commitment {
                eval.add_constraint(inactive.clone() * limb.clone());
            }
        }
        for value in pre_state_metadata.iter().chain(post_state_metadata.iter()) {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for value in pre_timeout_config.iter().chain(post_timeout_config.iter()) {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for bits in &pre_timeout_config_bits {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        eval.add_constraint(inactive.clone() * protocol_completion_kind.clone());
        for value in protocol_completion_timestamp
            .iter()
            .chain(std::iter::once(&protocol_completion_pre_cards_dealt))
            .chain(std::iter::once(&protocol_completion_post_cards_dealt))
            .chain(std::iter::once(&protocol_completion_post_pending_mask))
            .chain(std::iter::once(&protocol_completion_post_completed_mask))
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for commitment in &protocol_completion_commitments {
            for limb in commitment {
                eval.add_constraint(inactive.clone() * limb.clone());
            }
        }
        for bits in &protocol_completion_timestamp_bits {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        eval.add_constraint(inactive.clone() * protocol_completion_timestamp_inv.clone());
        for carry in &protocol_completion_deadline_carries {
            eval.add_constraint(inactive.clone() * carry.clone());
        }
        for bits in &protocol_completion_cursor_range {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        for commitment in pre_seat_commitments
            .iter()
            .chain(post_seat_commitments.iter())
            .flat_map(|seat| seat.iter())
        {
            for limb in commitment {
                eval.add_constraint(inactive.clone() * limb.clone());
            }
        }
        for limb in pre_deadline_image.iter().chain(post_deadline_image.iter()) {
            eval.add_constraint(inactive.clone() * limb.clone());
        }
        eval.add_constraint(inactive.clone() * post_deadline_inv.clone());
        eval.add_constraint(inactive.clone() * start_active_product.clone());
        eval.add_constraint(inactive.clone() * start_active_count_inv.clone());
        for selector in start_button_selectors
            .iter()
            .chain(start_pre_button_selectors.iter())
            .chain(start_wrap.iter())
            .chain(start_wrap_max.iter())
            .chain(start_next_seat.iter())
        {
            eval.add_constraint(inactive.clone() * selector.clone());
        }
        for value in next_pre_image
            .iter()
            .chain(next_pre_state_root.iter())
            .chain(next_pre_lifecycle_root.iter())
            .chain(next_pre_overlay_root.iter())
            .chain(next_pre_settlement_commitment.iter())
            .chain(next_pre_custody_commitment.iter())
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for value in transition_commitment.iter().chain(nullifier.iter()) {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        eval.add_constraint(inactive.clone() * transition_commitment_inv.clone());
        eval.add_constraint(inactive.clone() * nullifier_inv.clone());
        for limb in advance_deadline_difference
            .iter()
            .chain(deadline_height.iter())
        {
            eval.add_constraint(inactive.clone() * limb.clone());
        }
        for carry in &advance_deadline_carries {
            eval.add_constraint(inactive.clone() * carry.clone());
        }
        for bits in advance_deadline_height_bits
            .iter()
            .chain(advance_deadline_pre_bits.iter())
            .chain(advance_deadline_difference_bits.iter())
        {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        eval.add_constraint(inactive.clone() * advance_deadline_pre_inv.clone());
        eval.add_constraint(inactive.clone() * advance_deadline_phase_inv.clone());
        eval.add_constraint(inactive.clone() * advance_deadline_time_bank_all.clone());
        for value in advance_deadline_time_bank_slack
            .iter()
            .chain(advance_deadline_time_bank_excess.iter())
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for bits in &advance_deadline_time_bank_range_bits {
            for limb_bits in bits {
                for bit in limb_bits {
                    eval.add_constraint(inactive.clone() * bit.clone());
                }
            }
        }
        for carry in advance_deadline_time_bank_carries
            .iter()
            .chain(advance_deadline_extension_carries.iter())
        {
            eval.add_constraint(inactive.clone() * carry.clone());
        }
        let non_advance_deadline = active.clone() * (one.clone() - deadline_check.clone());
        eval.add_constraint(non_advance_deadline.clone() * advance_deadline_time_bank_all.clone());
        for value in advance_deadline_time_bank_slack
            .iter()
            .chain(advance_deadline_time_bank_excess.iter())
        {
            eval.add_constraint(non_advance_deadline.clone() * value.clone());
        }
        for bits in &advance_deadline_time_bank_range_bits {
            for limb_bits in bits {
                for bit in limb_bits {
                    eval.add_constraint(non_advance_deadline.clone() * bit.clone());
                }
            }
        }
        for carry in advance_deadline_time_bank_carries
            .iter()
            .chain(advance_deadline_extension_carries.iter())
        {
            eval.add_constraint(non_advance_deadline.clone() * carry.clone());
        }
        eval.add_constraint(inactive.clone() * no_next_turn.clone());
        let base: E::F = M31::from(65536u32).into();
        eval.add_constraint(is_start.clone() * pre_phase.clone());
        eval.add_constraint(is_start.clone() * (post_phase.clone() - M31::from(1u32).into()));
        eval.add_constraint(is_start.clone() * (post_turn.clone() - M31::from(15u32).into()));
        let mut start_pre_button_sum: E::F = M31::from(0u32).into();
        let mut start_pre_button_value: E::F = M31::from(0u32).into();
        for (index, selector) in start_pre_button_selectors.iter().enumerate() {
            eval.add_constraint(
                active.clone() * selector.clone() * (selector.clone() - one.clone()),
            );
            let index_value: E::F = M31::from(index as u32).into();
            start_pre_button_sum += selector.clone();
            start_pre_button_value += selector.clone() * index_value;
        }
        eval.add_constraint(active.clone() * (start_pre_button_sum.clone() - one.clone()));
        eval.add_constraint(
            active.clone() * (start_pre_button_value.clone() - pre_state_metadata[1].clone()),
        );
        let mut start_button_sum: E::F = M31::from(0u32).into();
        let mut start_button_value: E::F = M31::from(0u32).into();
        for (index, selector) in start_button_selectors.iter().enumerate() {
            eval.add_constraint(
                active.clone() * selector.clone() * (selector.clone() - one.clone()),
            );
            eval.add_constraint((active.clone() - is_start.clone()) * selector.clone());
            let index_value: E::F = M31::from(index as u32).into();
            start_button_sum += selector.clone();
            start_button_value += selector.clone() * index_value;
        }
        eval.add_constraint(start_button_sum.clone() - is_start.clone());
        eval.add_constraint(
            is_start.clone() * (start_button_value.clone() - post_state_metadata[1].clone()),
        );
        // Dead button: the successor is unconditionally `(button + 1) %
        // capacity` — the landing seat may be empty (a dead button), and no
        // occupied-seat skipping is permitted.  `wrap[i]` pins the wraparound
        // seat (`i == capacity - 1`), `next[i]` resolves to `(i + 1) % cap`,
        // and the destination selector must sit exactly at `next[button]`.
        for (index, wrap) in start_wrap.iter().enumerate() {
            eval.add_constraint(active.clone() * wrap.clone() * (wrap.clone() - one.clone()));
            eval.add_constraint(
                active.clone()
                    * wrap.clone()
                    * (pre_state_metadata[2].clone()
                        - one.clone()
                        - M31::from(index as u32).into()),
            );
            eval.add_constraint((active.clone() - is_start.clone()) * wrap.clone());
            // 线性化 wrap * capacity（度 2 关系），供后继解析约束使用。
            eval.add_constraint(
                active.clone()
                    * (start_wrap_max[index].clone()
                        - wrap.clone() * pre_state_metadata[2].clone()),
            );
        }
        for (index, next) in start_next_seat.iter().enumerate() {
            eval.add_constraint((active.clone() - is_start.clone()) * next.clone());
            let resolved = E::F::from(M31::from(index as u32 + 1)) - start_wrap_max[index].clone();
            eval.add_constraint(
                is_start.clone()
                    * start_pre_button_selectors[index].clone()
                    * (next.clone() - resolved),
            );
        }
        // BISECT-PAIR-RESTORED
        for from in 0..MAX_CANONICAL_SEATS {
            for to in 0..MAX_CANONICAL_SEATS {
                let pair =
                    start_pre_button_selectors[from].clone() * start_button_selectors[to].clone();
                let to_value: E::F = M31::from(to as u32).into();
                eval.add_constraint(
                    pair.clone() * (to_value - start_next_seat[from].clone()),
                );
            }
        }
        // BISECT-NEXT-RESTORED
        for (index, next) in start_next_seat.iter().enumerate() {
            eval.add_constraint((active.clone() - is_start.clone()) * next.clone());
            let resolved = E::F::from(M31::from(index as u32 + 1)) - start_wrap_max[index].clone();
            eval.add_constraint(
                is_start.clone()
                    * start_pre_button_selectors[index].clone()
                    * (next.clone() - resolved),
            );
        }
        let mut post_deadline_sum: E::F = M31::from(0u32).into();
        for limb in &post_deadline_image {
            post_deadline_sum += limb.clone();
        }
        // Starting a hand must arm a real deadline.  The inverse makes this a
        // field-native non-zero statement without a host comparison branch.
        eval.add_constraint(
            is_start.clone() * (post_deadline_sum * post_deadline_inv.clone() - one.clone()),
        );
        eval.add_constraint((active.clone() - is_start.clone()) * post_deadline_inv.clone());
        let non_start = active.clone() * (one.clone() - is_start.clone());
        eval.add_constraint(
            non_start.clone()
                * (pre_seq[0].clone() + one.clone()
                    - post_seq[0].clone()
                    - base.clone() * seq_carry.clone()),
        );
        eval.add_constraint(
            non_start.clone() * (pre_seq[1].clone() + seq_carry.clone() - post_seq[1].clone()),
        );
        let table_scope = [
            eval.get_preprocessed_column(preprocessed_ids()[3].clone()),
            eval.get_preprocessed_column(preprocessed_ids()[4].clone()),
            eval.get_preprocessed_column(preprocessed_ids()[5].clone()),
            eval.get_preprocessed_column(preprocessed_ids()[6].clone()),
        ];
        add_limb_eq(&mut eval, &active, &table, &table_scope);
        eval.add_constraint(
            active.clone()
                * (one.clone() - is_start.clone())
                * (pre_hand[0].clone() - post_hand[0].clone()),
        );
        eval.add_constraint(
            active.clone()
                * (one.clone() - is_start.clone())
                * (pre_hand[1].clone() - post_hand[1].clone()),
        );
        eval.add_constraint(
            active.clone() * is_start.clone() * (post_seq[0].clone() + post_seq[1].clone()),
        );
        eval.add_constraint(
            active.clone()
                * is_start.clone()
                * (post_hand[0].clone() - pre_hand[0].clone() - one.clone()),
        );
        eval.add_constraint(
            active.clone() * is_start.clone() * (post_hand[1].clone() - pre_hand[1].clone()),
        );
        let mut start_active_count: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            // Count post-state participants: StartHand admits promoted
            // waiting-for-big-blind seats into the new hand.
            start_active_count += full_post_status[index][CanonicalSeatStatus::Active as usize]
                .clone()
                + full_post_status[index][CanonicalSeatStatus::Folded as usize].clone()
                + full_post_status[index][CanonicalSeatStatus::AllIn as usize].clone();
        }
        eval.add_constraint(
            is_start.clone()
                * (start_active_product.clone()
                    - start_active_count.clone() * (start_active_count.clone() - one.clone())),
        );
        eval.add_constraint(
            is_start.clone()
                * (start_active_product.clone() * start_active_count_inv.clone() - one.clone()),
        );
        eval.add_constraint((active.clone() - is_start.clone()) * start_active_count_inv.clone());
        eval.add_constraint((active.clone() - is_start.clone()) * start_active_product.clone());
        eval.add_constraint(is_start.clone() * pre_subtag.clone());
        eval.add_constraint(is_start.clone() * (post_subtag.clone() - one.clone()));
        eval.add_constraint(is_start.clone() * post_street.clone());
        for bit in pre_acted_bits.iter().chain(post_acted_bits.iter()) {
            eval.add_constraint(is_start.clone() * bit.clone());
        }
        for commitment in [0usize, 2, 3, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_start.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        let is_permissionless = kinds[CanonicalTransitionKind::AdvanceDeadline as usize].clone()
            + kinds[CanonicalTransitionKind::AdvanceRound as usize].clone()
            + kinds[CanonicalTransitionKind::AutoFold as usize].clone()
            + is_terminal_reset.clone()
            + is_timeout_reset.clone()
            + is_reveal_kick.clone()
            + is_reveal_reconstruct.clone()
            + is_award_family.clone();
        // `AdvanceDeadline` is permissionless in the VM and therefore carries
        // the canonical zero actor.  Constrain every limb directly; a non-zero
        // sum check would both accept a forged actor and reject only the
        // all-zero field-sum corner case.
        for limb in &actor {
            eval.add_constraint(is_permissionless.clone() * limb.clone());
        }
        let actor_transition = active.clone() - is_permissionless.clone();
        let mut actor_sum: E::F = M31::from(0u32).into();
        for limb in &actor {
            actor_sum += limb.clone();
        }
        eval.add_constraint(
            actor_transition.clone() * (actor_sum * actor_inv.clone() - one.clone()),
        );
        eval.add_constraint((active.clone() - actor_transition) * actor_inv.clone());
        // Settlement configuration is immutable for every transition family
        // currently represented by this AIR.  Terminal settlement/side-pot
        // semantics will get their own selector before this gate is relaxed.
        for (pre, post) in pre_settlement_commitment
            .iter()
            .zip(post_settlement_commitment.iter())
        {
            eval.add_constraint(active.clone() * (post.clone() - pre.clone()));
        }
        // Bind anti-replay identifiers to every active row. Their fixed-width
        // limbs are committed in the row and an inverse proves that neither
        // identifier is the all-zero value without relying on host validation.
        let mut transition_sum: E::F = M31::from(0u32).into();
        let mut nullifier_sum: E::F = M31::from(0u32).into();
        for limb in &transition_commitment {
            transition_sum += limb.clone();
        }
        for limb in &nullifier {
            nullifier_sum += limb.clone();
        }
        eval.add_constraint(
            active.clone() * (transition_sum * transition_commitment_inv.clone() - one.clone()),
        );
        eval.add_constraint(active.clone() * (nullifier_sum * nullifier_inv.clone() - one.clone()));
        eval.add_constraint((one.clone() - active.clone()) * (kind_sum + seat.clone() + flag));
        let first = eval.get_preprocessed_column(preprocessed_ids()[1].clone());
        let last = eval.get_preprocessed_column(preprocessed_ids()[2].clone());
        let first_kind =
            eval.get_preprocessed_column(preprocessed_ids()[FIRST_KIND_SCOPE_OFFSET].clone());
        let last_kind =
            eval.get_preprocessed_column(preprocessed_ids()[LAST_KIND_SCOPE_OFFSET].clone());
        let cascade_active = eval.get_preprocessed_column(
            preprocessed_ids()[REVEAL_TIMEOUT_CASCADE_ACTIVE_SCOPE_OFFSET].clone(),
        );
        let cascade_seat = eval.get_preprocessed_column(
            preprocessed_ids()[REVEAL_TIMEOUT_CASCADE_SEAT_SCOPE_OFFSET].clone(),
        );
        let mut row_kind: E::F = M31::from(0u32).into();
        for (index, selector) in kinds.iter().enumerate() {
            row_kind += selector.clone() * E::F::from(M31::from(index as u32));
        }
        eval.add_constraint(first.clone() * (row_kind.clone() - first_kind));
        eval.add_constraint(last.clone() * (row_kind - last_kind));
        // A dedicated reveal-timeout cascade batch is archive-bound to the
        // public seat schedule. Every active row must carry either a
        // non-terminal kick or the final typed reset, and its action seat must
        // equal the corresponding schedule entry.
        let is_reveal_timeout_kick =
            kinds[CanonicalTransitionKind::RevealTimeoutKick as usize].clone();
        eval.add_constraint(
            cascade_active.clone()
                * (is_reveal_timeout_kick.clone()
                    + is_reveal_timeout.clone()
                    + is_reveal_reconstruct.clone()
                    + is_award_family.clone()
                    - one.clone()),
        );
        eval.add_constraint(cascade_active.clone() * (seat.clone() - cascade_seat.clone()));
        let range = self.range.clone();
        let rake_scope: [E::F; 6] = std::array::from_fn(|index| {
            eval.get_preprocessed_column(preprocessed_ids()[RAKE_SCOPE_OFFSET + index].clone())
        });
        for index in 0..6 {
            eval.add_constraint(
                is_reveal_raked_award.clone()
                    * (rake_config[index].clone() - rake_scope[index].clone()),
            );
            eval.add_constraint(
                (active.clone() - is_reveal_raked_award.clone()) * rake_config[index].clone(),
            );
        }
        // ---- #22②：RevealComplete 组合约束（镜像 check_reveal_phase_complete
        // -> post_blinds + start_betting_round(preflop) 的规范化语义）。所有
        // 主体走线性化 gate 列（度数 1），约束保持声明度数 3。合法性词
        //（reveal token 的密码学方程）仍属 native/链上 EC_OP 通道（Plan D）。
        let blind_scope: [E::F; 13] = std::array::from_fn(|index| {
            eval.get_preprocessed_column(preprocessed_ids()[BLIND_SCOPE_OFFSET + index].clone())
        });
        let gate = rc_gate.clone();
        // 行内盲注建议 = 公开 blind scope；ante 模式必须 NONE（ante 组合是
        // 独立的 fail-closed 边），ante 金额为零。
        for limb in 0..8 {
            eval.add_constraint(
                gate.clone() * (rc_blind_limbs[limb].clone() - blind_scope[limb].clone()),
            );
        }
        eval.add_constraint(gate.clone() * blind_scope[BLIND_SCOPE_ANTE_MODE_INDEX].clone());
        for limb in 9..13 {
            eval.add_constraint(gate.clone() * blind_scope[limb].clone());
        }
        // 全部新建议列在非 reveal 完成行（含 padding 行）清零。
        {
            let non_rc = active.clone() - gate.clone();
            let zero = |eval: &mut E, value: E::F| {
                eval.add_constraint(non_rc.clone() * value.clone());
                eval.add_constraint(inactive.clone() * value);
            };
            for column in rc_count_invs
                .iter()
                .chain(std::iter::once(&rc_hu))
                .chain(rc_blind_limbs.iter())
            {
                zero(&mut eval, column.clone());
            }
            for column in rc_sb_onehot.iter().chain(rc_bb_onehot.iter()) {
                zero(&mut eval, column.clone());
            }
            for base in 0..3 {
                for column in rc_rot[base]
                    .iter()
                    .chain(rc_q[base].iter())
                    .chain(rc_f[base].iter())
                {
                    zero(&mut eval, column.clone());
                }
            }
            for column in rc_ffa.iter() {
                zero(&mut eval, column.clone());
            }
            for column in rc_base_onehot
                .iter()
                .chain(std::iter::once(&rc_nobb))
                .chain(std::iter::once(&rc_dead_sb))
                .chain(std::iter::once(&rc_gate_nobb))
                .chain(std::iter::once(&rc_live_sb))
                .chain(std::iter::once(&rc_sb_amt_inv))
            {
                zero(&mut eval, column.clone());
            }
            for seat in 0..MAX_CANONICAL_SEATS {
                for column in rc_stack_carries[seat]
                    .iter()
                    .chain(rc_total_carries[seat].iter())
                    .chain(std::iter::once(&rc_stack_nonzero_inv[seat]))
                    .chain(std::iter::once(&rc_stack_capped[seat]))
                {
                    zero(&mut eval, column.clone());
                }
            }
            zero(&mut eval, rc_no_utg.clone());
        }
        // 新增 street/showdown 组列（#22②扩展）：家族/子门列仅在 padding 行
        // 清零（active 行由定义约束钉死）；rcs 扫描 advice 仅 street 完成
        // 行可非零。
        for value in [
            &rcf_gate,
            &rc_hole,
            &rc_board,
            &rc_showdown,
            &rcs_gate,
            &rcd_gate,
        ] {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        let non_rcs = active.clone() - rcs_gate.clone();
        for column in rcs_base_onehot
            .iter()
            .chain(rcs_rot.iter())
            .chain(rcs_q.iter())
            .chain(rcs_f.iter())
            .chain(std::iter::once(&rcs_no_turn))
            .chain(rcs_street_sel.iter())
        {
            eval.add_constraint(non_rcs.clone() * column.clone());
            eval.add_constraint(inactive.clone() * column.clone());
        }
        // VM 头：Revealing(收集子标签 1, preflop) -> Betting(1, preflop)，
        // acted 掩码双端为零，协议进度清零。
        eval.add_constraint(gate.clone() * (pre_phase.clone() - M31::from(2u32).into()));
        eval.add_constraint(gate.clone() * (pre_subtag.clone() - M31::from(1u32).into()));
        eval.add_constraint(gate.clone() * (pre_street.clone() - M31::from(1u32).into()));
        eval.add_constraint(gate.clone() * (post_phase.clone() - M31::from(4u32).into()));
        eval.add_constraint(gate.clone() * (post_subtag.clone() - M31::from(1u32).into()));
        eval.add_constraint(gate.clone() * (post_street.clone() - M31::from(1u32).into()));
        // acted 双端纪律：pre 全零；post 仅封顶盲注座位可置位（VM 补的
        // all-in acted 位，镜像不变量 "Folded/AllIn seat must be acted"）。
        eval.add_constraint(gate.clone() * pre_acted_mask.clone());
        {
            let mut capped_mask: E::F = M31::from(0u32).into();
            for index in 0..MAX_CANONICAL_SEATS {
                capped_mask += rc_stack_capped[index].clone()
                    * E::F::from(M31::from(1u32 << index));
            }
            eval.add_constraint(gate.clone() * (post_acted_mask.clone() - capped_mask));
        }
        eval.add_constraint(gate.clone() * post_protocol_pending_mask.clone());
        for bit in post_protocol_pending_mask_bits.iter() {
            eval.add_constraint(gate.clone() * bit.clone());
        }
        // Opening 锚：cursor/legacy 掩码清零；deck/reconstruction 双端冻结并
        // 锚定 opening；suspended-reveal 槽位保持零（reveal 承诺在完成提交
        // 内轮转，与实际密文的绑定属 native/EC_OP 通道，与 shuffle 完成的
        // deck 轮转同口径——pre/post 端点镜像本身就是 trace 列）。
        eval.add_constraint(gate.clone() * protocol_completion_pre_cards_dealt.clone());
        eval.add_constraint(gate.clone() * protocol_completion_post_cards_dealt.clone());
        eval.add_constraint(gate.clone() * protocol_completion_post_pending_mask.clone());
        eval.add_constraint(
            gate.clone() * protocol_completion_post_completed_mask.clone(),
        );
        for limb in 0..16 {
            eval.add_constraint(gate.clone() * protocol_completion_commitments[0][limb].clone());
            for (opening, endpoint) in [
                (
                    &protocol_completion_commitments[1][limb],
                    &pre_opaque_commitments[1][limb],
                ),
                (
                    &protocol_completion_commitments[2][limb],
                    &post_opaque_commitments[1][limb],
                ),
                (
                    &protocol_completion_commitments[3][limb],
                    &pre_opaque_commitments[3][limb],
                ),
                (
                    &protocol_completion_commitments[4][limb],
                    &post_opaque_commitments[3][limb],
                ),
            ] {
                eval.add_constraint(gate.clone() * (opening.clone() - endpoint.clone()));
            }
        }
        // Deadline：post = completion_timestamp + betting_timeout。
        let betting_timeout_limbs = [
            pre_timeout_config[BETTING_TIMEOUT_LIMB_OFFSET].clone(),
            pre_timeout_config[BETTING_TIMEOUT_LIMB_OFFSET + 1].clone(),
            zero_limb.clone(),
            zero_limb.clone(),
        ];
        limb4_add_constraints_no_carry_bool(
            &mut eval,
            &gate,
            &protocol_completion_timestamp,
            &betting_timeout_limbs,
            &post_deadline_image,
            &protocol_completion_deadline_carries,
        );
        for carry in protocol_completion_deadline_carries.iter() {
            eval.add_constraint(gate.clone() * carry.clone() * (carry.clone() - one.clone()));
        }
        // 参与者形状：占用座（非 Empty/Out）必须 Active——reveal 完成镜像里
        // Folded/Waiting/AllIn 不可达，同时使 participating == Active 扫描。
        let mut active_count: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let active_bit =
                full_pre_status[index][CanonicalSeatStatus::Active as usize].clone();
            let occupied_non_active = full_pre_status[index][CanonicalSeatStatus::Waiting as usize]
                .clone()
                + full_pre_status[index][CanonicalSeatStatus::Folded as usize].clone()
                + full_pre_status[index][CanonicalSeatStatus::AllIn as usize].clone();
            eval.add_constraint(gate.clone() * occupied_non_active);
            active_count += active_bit;
        }
        // 计数纪律：非零、至少两名参与者（一人成局在 VM 早已 sole-survivor
        // 收官，此处 fail-closed），以及单挑（恰好两名）判定。
        eval.add_constraint(
            gate.clone() * (active_count.clone() * rc_count_invs[0].clone() - one.clone()),
        );
        let count_minus_one = active_count.clone() - one.clone();
        let count_minus_two = active_count.clone() - one.clone() - one.clone();
        eval.add_constraint(
            gate.clone() * (count_minus_one * rc_count_invs[1].clone() - one.clone()),
        );
        eval.add_constraint(gate.clone() * rc_hu.clone() * (rc_hu.clone() - one.clone()));
        eval.add_constraint(gate.clone() * rc_hu.clone() * count_minus_two.clone());
        eval.add_constraint(
            gate.clone()
                * (count_minus_two * rc_count_invs[2].clone() - (one.clone() - rc_hu.clone())),
        );
        // 位置规则（dead button 轮转，镜像 post_blinds §4.2b）：每个基座
        // （轮转基准、BB）做模 9 循环"首个 Active"扫描。rot_d = 基座 + d 处
        // 的 Active 位；q 前缀（此前无 Active）；f = 首位选择子。占用收敛后
        // 该扫描与 VM 的 mod max_players 扫描一致。
        // 基座：上一手大盲座位（无历史时为 button）——由 rc_base_onehot 与
        // rc_nobb 锚定；BB = 基座后首个 Active；SB = 单挑时 BB 后首个
        // Active（另一参与者），否则基座座位本身（dead SB 时无 SB）。
        let bases: [[E::F; MAX_CANONICAL_SEATS]; 2] = [
            std::array::from_fn(|index| rc_base_onehot[index].clone()),
            std::array::from_fn(|index| rc_bb_onehot[index].clone()),
        ];
        // BB 与轮转基座均须恰好单热；SB 单热之和 = 非 dead SB 指示。
        for onehot in [&rc_bb_onehot, &rc_base_onehot] {
            let mut sum: E::F = M31::from(0u32).into();
            for bit in onehot.iter() {
                eval.add_constraint(gate.clone() * bit.clone() * (bit.clone() - one.clone()));
                sum += bit.clone();
            }
            eval.add_constraint(gate.clone() * (sum - one.clone()));
        }
        {
            let mut sum: E::F = M31::from(0u32).into();
            for bit in rc_sb_onehot.iter() {
                eval.add_constraint(gate.clone() * bit.clone() * (bit.clone() - one.clone()));
                sum += bit.clone();
            }
            eval.add_constraint(
                gate.clone()
                    * (sum.clone()
                        - one.clone()
                        + (one.clone() - rc_hu.clone()) * rc_dead_sb.clone()),
            );
        }
        // 轮转基准锚定：rc_nobb ⟺ last_bb_seat == NO_SEAT 哨兵；基座落在
        // last_bb_seat（nobb=0）或 button（nobb=1）。rc_gate_nobb 线性化
        // `gate * nobb`，把逐座位锚定约束压回声明度数 3 以内。
        eval.add_constraint(
            active.clone() * (rc_gate_nobb.clone() - gate.clone() * rc_nobb.clone()),
        );
        eval.add_constraint(gate.clone() * rc_nobb.clone() * (rc_nobb.clone() - one.clone()));
        eval.add_constraint(
            gate.clone()
                * rc_nobb.clone()
                * (pre_state_metadata[3].clone() - M31::from(15u32).into()),
        );
        eval.add_constraint(
            gate.clone() * rc_dead_sb.clone() * (rc_dead_sb.clone() - one.clone()),
        );
        eval.add_constraint(gate.clone() * rc_dead_sb.clone() * rc_hu.clone());
        for index in 0..MAX_CANONICAL_SEATS {
            let index_value: E::F = M31::from(index as u32).into();
            let no_seat_value: E::F = M31::from(15u32).into();
            // base_sel[i]=1 ⟹ last_bb_seat == i（nobb=0）或 == NO（nobb=1）。
            eval.add_constraint(
                rc_base_onehot[index].clone()
                    * (pre_state_metadata[3].clone() - index_value.clone())
                    - rc_base_onehot[index].clone()
                        * rc_gate_nobb.clone()
                        * (no_seat_value - index_value.clone()),
            );
            // nobb=1 → base == button（pre_state_metadata[1]）。
            eval.add_constraint(
                rc_gate_nobb.clone()
                    * rc_base_onehot[index].clone()
                    * (pre_state_metadata[1].clone() - index_value),
            );
        }
        // dead_sb 完备性（非单挑）：基座座位参与（Active）⟺ 本手有小盲。
        // 用 rc_live_sb 线性化（其定义约束已钉死 live = (1-hu)(1-dead)），
        // 两条均不带 gate 保持度数 ≤ 3（非 rc 行相关列恒零）。
        {
            let mut base_active: E::F = M31::from(0u32).into();
            for index in 0..MAX_CANONICAL_SEATS {
                base_active += rc_base_onehot[index].clone()
                    * full_pre_status[index][CanonicalSeatStatus::Active as usize].clone();
            }
            // live ⟹ 基座座位参与；dead ⟹ 基座座位不参与。
            eval.add_constraint(rc_live_sb.clone() * (one.clone() - base_active.clone()));
            eval.add_constraint(rc_dead_sb.clone() * base_active.clone());
            // 成对纪律：live SB 金额非零（limbs 和的逆元），dead SB 金额为零。
            // 逆元约束乘 rc_live_sb（ungated，非 rc 行该列恒零）保持度数 3。
            let sb_amount_sum =
                rc_blind_limbs[0].clone()
                    + rc_blind_limbs[1].clone()
                    + rc_blind_limbs[2].clone()
                    + rc_blind_limbs[3].clone();
            eval.add_constraint(
                rc_live_sb.clone()
                    * (sb_amount_sum * rc_sb_amt_inv.clone() - one.clone()),
            );
            for limb in 0..4 {
                eval.add_constraint(
                    rc_blind_limbs[limb].clone()
                        * (one.clone() - rc_hu.clone())
                        * rc_dead_sb.clone(),
                );
            }
        }
        for base in 0..2 {
            let base_onehot = &bases[base];
            eval.add_constraint(gate.clone() * (rc_q[base][0].clone() - one.clone()));
            let mut selector_sum: E::F = M31::from(0u32).into();
            for d in 0..8 {
                let mut rotated: E::F = M31::from(0u32).into();
                for j in 0..MAX_CANONICAL_SEATS {
                    let target = (j + d + 1) % MAX_CANONICAL_SEATS;
                    rotated += base_onehot[j].clone()
                        * full_pre_status[target][CanonicalSeatStatus::Active as usize].clone();
                }
                eval.add_constraint(
                    gate.clone() * (rc_rot[base][d].clone() - rotated),
                );
                eval.add_constraint(
                    gate.clone()
                        * (rc_f[base][d].clone()
                            - rc_rot[base][d].clone() * rc_q[base][d].clone()),
                );
                if d > 0 {
                    eval.add_constraint(
                        gate.clone()
                            * (rc_q[base][d].clone()
                                - rc_q[base][d - 1].clone()
                                    * (one.clone() - rc_rot[base][d - 1].clone())),
                    );
                }
                selector_sum += rc_f[base][d].clone();
            }
            eval.add_constraint(gate.clone() * (selector_sum - one.clone()));
        }
        // 第三组扫描（UTG）：与第二组同基座（BB），但扫 **post 可行动集**
        // （封顶盲注座位已翻转为 AllIn，不得再行动）。全员 all-in 时
        // selector_sum == 0、rc_no_utg == 1，post_turn = NO_SEAT（镜像 VM
        // C5 路径与 validate 侧 next_active_seat(&post.seats, …)）。
        eval.add_constraint(gate.clone() * (rc_q[2][0].clone() - one.clone()));
        let mut selector_sum_utg: E::F = M31::from(0u32).into();
        for d in 0..8 {
            let mut rotated_post: E::F = M31::from(0u32).into();
            for j in 0..MAX_CANONICAL_SEATS {
                let target = (j + d + 1) % MAX_CANONICAL_SEATS;
                rotated_post += rc_bb_onehot[j].clone()
                    * full_post_status[target][CanonicalSeatStatus::Active as usize].clone();
            }
            eval.add_constraint(gate.clone() * (rc_rot[2][d].clone() - rotated_post));
            eval.add_constraint(gate.clone() * (rc_f[2][d].clone() - rc_rot[2][d].clone() * rc_q[2][d].clone()));
            if d > 0 {
                eval.add_constraint(
                    gate.clone()
                        * (rc_q[2][d].clone()
                            - rc_q[2][d - 1].clone() * (one.clone() - rc_rot[2][d - 1].clone())),
                );
            }
            selector_sum_utg += rc_f[2][d].clone();
        }
        eval.add_constraint(
            gate.clone() * (selector_sum_utg.clone() + rc_no_utg.clone() - one.clone()),
        );
        eval.add_constraint(gate.clone() * rc_no_utg.clone() * (rc_no_utg.clone() - one.clone()));
        // BISECT-FFA
        {
        eval.add_constraint(gate.clone() * (rc_ffa[0].clone() - rc_dead_sb.clone()));
        for d in 0..8 {
            eval.add_constraint(
                gate.clone() * (rc_ffa[d + 1].clone() - rc_hu.clone() * rc_f[1][d].clone()),
            );
            eval.add_constraint(
                gate.clone() * rc_ffa[d + 1].clone() * (rc_ffa[d + 1].clone() - one.clone()),
            );
        }
        }
        // BISECT-END
        // BISECT-RECON
        {
        eval.add_constraint(
            gate.clone() * (rc_live_sb.clone() - (one.clone() - rc_hu.clone()) * (one.clone() - rc_dead_sb.clone())),
        );
        for i in 0..MAX_CANONICAL_SEATS {
            let mut sb_expr: E::F = rc_live_sb.clone() * rc_base_onehot[i].clone();
            let mut bb_expr: E::F = M31::from(0u32).into();
            for d in 0..8 {
                sb_expr += rc_ffa[d + 1].clone()
                    * rc_bb_onehot[(i + MAX_CANONICAL_SEATS - (d + 1)) % MAX_CANONICAL_SEATS]
                        .clone();
                bb_expr += rc_f[0][d].clone()
                    * rc_base_onehot[(i + MAX_CANONICAL_SEATS - (d + 1)) % MAX_CANONICAL_SEATS]
                        .clone();
            }
            eval.add_constraint(gate.clone() * (rc_sb_onehot[i].clone() - sb_expr));
            eval.add_constraint(gate.clone() * (rc_bb_onehot[i].clone() - bb_expr));
        }
        // BISECT-RECON-END
        }
        // BISECT-DEADSB-DISABLED-SEPARATELY
        // UTG = BB 后首个 post 可行动座位（封顶座位已 AllIn 被跳过；全员
        // all-in 时 no_utg=1 → NO_SEAT，镜像 VM C5）。
        let mut utg_seat: E::F = M31::from(0u32).into();
        for d in 0..8 {
            let mut seat_value: E::F = M31::from(0u32).into();
            for j in 0..MAX_CANONICAL_SEATS {
                seat_value += rc_bb_onehot[j].clone()
                    * E::F::from(M31::from(((j + d + 1) % MAX_CANONICAL_SEATS) as u32));
            }
            utg_seat += rc_f[2][d].clone() * seat_value;
        }
        eval.add_constraint(
            gate.clone()
                * (post_turn.clone() - utg_seat
                    - rc_no_utg.clone()
                        * E::F::from(M31::from(u32::from(NO_CANONICAL_SEAT)))),
        );
        // dead button 盲注轨道：本手大盲座位成为 post.last_bb_seat。
        let mut bb_track_value: E::F = M31::from(0u32).into();
        for (index, bit) in rc_bb_onehot.iter().enumerate() {
            bb_track_value += bit.clone() * E::F::from(M31::from(index as u32));
        }
        eval.add_constraint(
            gate.clone() * (post_state_metadata[3].clone() - bb_track_value),
        );
        // 下注价：current_bet = min_raise = BB（参与者全部 Active、无历史
        // bet，max(座位 bet, BB) = BB）。
        for limb in 0..4 {
            eval.add_constraint(
                gate.clone() * (post_current[limb].clone() - rc_blind_limbs[4 + limb].clone()),
            );
            eval.add_constraint(
                gate.clone() * (post_min[limb].clone() - rc_blind_limbs[4 + limb].clone()),
            );
        }
        // 逐座位盲注扣款：post_bet = posted（pre bet 为零）；pre_stack =
        // post_stack + posted；post_total = pre_total + posted；盲注座
        // post stack 非零（无封顶，无 AllIn 翻转）。
        for index in 0..MAX_CANONICAL_SEATS {
            let mut posted: [E::F; 4] = std::array::from_fn(|_| M31::from(0u32).into());
            for limb in 0..4 {
                posted[limb] = rc_sb_onehot[index].clone() * rc_blind_limbs[limb].clone()
                    + rc_bb_onehot[index].clone() * rc_blind_limbs[4 + limb].clone();
                eval.add_constraint(
                    gate.clone()
                        * (full_post_bet[index][limb].clone() - posted[limb].clone()),
                );
                eval.add_constraint(gate.clone() * full_pre_bet[index][limb].clone());
            }
            limb4_add_constraints(
                &mut eval,
                &gate,
                &full_post_stack[index],
                &posted,
                &full_pre_stack[index],
                &rc_stack_carries[index],
            );
            limb4_add_constraints(
                &mut eval,
                &gate,
                &full_pre_total[index],
                &posted,
                &full_post_total[index],
                &rc_total_carries[index],
            );
            let mut post_stack_sum: E::F = M31::from(0u32).into();
            for limb in 0..4 {
                post_stack_sum += full_post_stack[index][limb].clone();
            }
            let posts_blind = rc_sb_onehot[index].clone() + rc_bb_onehot[index].clone();
            // 封顶盲注（#22②扩展）：盲注座 stack 可扣到 0（AllIn 翻转）。
            // capped ⟺ posts_blind ∧ stack_sum == 0；非零 ⟺ posts_blind ∧
            // ¬capped（逆元约束）。非封顶路径退化为原"盲注座 stack 非零"。
            eval.add_constraint(
                rc_stack_capped[index].clone() * (rc_stack_capped[index].clone() - one.clone()),
            );
            eval.add_constraint(
                rc_stack_capped[index].clone() * (one.clone() - posts_blind.clone()),
            );
            eval.add_constraint(rc_stack_capped[index].clone() * post_stack_sum.clone());
            eval.add_constraint(
                gate.clone()
                    * (rc_stack_nonzero_inv[index].clone() * post_stack_sum.clone()
                        - posts_blind.clone()
                        + rc_stack_capped[index].clone()),
            );
            // capped 只在 reveal 完成行可置位（清零域已覆盖非 rc 行；此处
            // 钉死 capped ⊆ reveal-completion，供 status 冻结的例外门引用）。
            eval.add_constraint(
                rc_stack_capped[index].clone()
                    * (one.clone() - is_reveal_completion.clone()),
            );
            // 封顶翻转方向：Active → AllIn（post 全局 one-hot 由 status-sum
            // 约束保证，故两条即完备）。
            eval.add_constraint(
                rc_stack_capped[index].clone()
                    * (full_post_status[index][CanonicalSeatStatus::AllIn as usize].clone()
                        - full_pre_status[index][CanonicalSeatStatus::AllIn as usize].clone()
                        - full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()),
            );
            eval.add_constraint(
                rc_stack_capped[index].clone()
                    * full_post_status[index][CanonicalSeatStatus::Active as usize].clone(),
            );
        }
        // ============================================================
        // #22②扩展（2026-09-15）：RevealStreet 完成组——Board 窗口完成 →
        // 同街下注轮（镜像 check_reveal_phase_complete 的 postflop 分支）。
        // 主体全部走线性化 rcs_gate 列（度数 1），约束声明度数 ≤ 3。
        // ============================================================
        {
            let gate = rcs_gate.clone();
            // VM 头：Revealing(Board=2, street∈{2,3,4}, turn=NO) →
            // Betting(1, 同街)。
            eval.add_constraint(gate.clone() * (pre_phase.clone() - M31::from(2u32).into()));
            eval.add_constraint(gate.clone() * (pre_subtag.clone() - M31::from(2u32).into()));
            eval.add_constraint(gate.clone() * (post_phase.clone() - M31::from(4u32).into()));
            eval.add_constraint(gate.clone() * (post_subtag.clone() - M31::from(1u32).into()));
            eval.add_constraint(gate.clone() * (post_street.clone() - pre_street.clone()));
            eval.add_constraint(
                gate.clone()
                    * (pre_street.clone()
                        - M31::from(2u32).into()
                        - rcs_street_sel[0].clone()
                        - rcs_street_sel[1].clone() * E::F::from(M31::from(2u32))),
            );
            for bit in rcs_street_sel.iter() {
                eval.add_constraint(gate.clone() * bit.clone() * (bit.clone() - one.clone()));
            }
            eval.add_constraint(gate.clone() * (pre_turn.clone() - no_seat.clone()));
            // acted：post = folded/all-in 补位掩码（协议提交行的 acted 位
            // 冻结已豁免 street 行，本约束独立钉住 post 投影）。
            for index in 0..MAX_CANONICAL_SEATS {
                eval.add_constraint(
                    gate.clone()
                        * (post_acted_bits[index].clone()
                            - full_post_status[index][CanonicalSeatStatus::Folded as usize].clone()
                            - full_post_status[index][CanonicalSeatStatus::AllIn as usize].clone()),
                );
            }
            // pending：post 清零；pre pending 只剩提交者一位（窗口开启行
            // AdvanceRound 钉住 pending = 参与集，逐提交清位，行级门
            // remaining == 0 已钉住单一位——AIR 无需重复）。
            eval.add_constraint(gate.clone() * post_protocol_pending_mask.clone());
            for bit in post_protocol_pending_mask_bits.iter() {
                eval.add_constraint(gate.clone() * bit.clone());
            }
            // 逐座位资金/状态冻结（validator: seats 双端一致；pot/chip_pool、
            // 座位承诺、leave 掩码由协议行全局冻结覆盖）。
            for index in 0..MAX_CANONICAL_SEATS {
                for (pre, post) in [
                    (&full_pre_stack[index], &full_post_stack[index]),
                    (&full_pre_bet[index], &full_post_bet[index]),
                    (&full_pre_total[index], &full_post_total[index]),
                    (&full_pre_pending[index], &full_post_pending[index]),
                ] {
                    for (left, right) in pre.iter().zip(post.iter()) {
                        eval.add_constraint(gate.clone() * (right.clone() - left.clone()));
                    }
                }
                for (left, right) in full_pre_time_bank[index]
                    .iter()
                    .zip(full_post_time_bank[index].iter())
                {
                    eval.add_constraint(gate.clone() * (right.clone() - left.clone()));
                }
                for status in 0..SEAT_STATUS_COUNT {
                    eval.add_constraint(
                        gate.clone()
                            * (full_post_status[index][status].clone()
                                - full_pre_status[index][status].clone()),
                    );
                }
            }
            // 下注价：current_bet = 0；min_raise = BB（公开 blind scope，
            // companion rules proof 锚定其与 pre rules 承诺的绑定）；ante
            // 必须 NONE。
            for limb in 0..4 {
                eval.add_constraint(gate.clone() * post_current[limb].clone());
                eval.add_constraint(
                    gate.clone() * (post_min[limb].clone() - blind_scope[4 + limb].clone()),
                );
            }
            eval.add_constraint(gate.clone() * blind_scope[BLIND_SCOPE_ANTE_MODE_INDEX].clone());
            // Deadline：post = completion_timestamp + betting_timeout
            //（共享 carries，布尔性下方补）。
            let betting_timeout_limbs2 = [
                pre_timeout_config[BETTING_TIMEOUT_LIMB_OFFSET].clone(),
                pre_timeout_config[BETTING_TIMEOUT_LIMB_OFFSET + 1].clone(),
                zero_limb.clone(),
                zero_limb.clone(),
            ];
            limb4_add_constraints_no_carry_bool(
                &mut eval,
                &gate,
                &protocol_completion_timestamp,
                &betting_timeout_limbs2,
                &post_deadline_image,
                &protocol_completion_deadline_carries,
            );
            for carry in protocol_completion_deadline_carries.iter() {
                eval.add_constraint(gate.clone() * carry.clone() * (carry.clone() - one.clone()));
            }
            // opening 承诺锚：suspended 零；deck/reconstruction 双端锚定
            //（reveal 承诺轮转的端点检查由 validator 承担）。
            for limb in 0..16 {
                eval.add_constraint(gate.clone() * protocol_completion_commitments[0][limb].clone());
                for (opening_limb, endpoint) in [
                    (
                        &protocol_completion_commitments[1][limb],
                        &pre_opaque_commitments[1][limb],
                    ),
                    (
                        &protocol_completion_commitments[2][limb],
                        &post_opaque_commitments[1][limb],
                    ),
                    (
                        &protocol_completion_commitments[3][limb],
                        &pre_opaque_commitments[3][limb],
                    ),
                    (
                        &protocol_completion_commitments[4][limb],
                        &post_opaque_commitments[3][limb],
                    ),
                ] {
                    eval.add_constraint(gate.clone() * (opening_limb.clone() - endpoint.clone()));
                }
            }
            // 首-行动基座：one-hot、∈ {last_bb_seat, button}（单挑取轨道、
            // 非单挑取 button 的选择由 validator 精确钉住，AIR 锚定"二者
            // 之一"下的结果一致性）；post-Active 旋转扫描。
            {
                let mut base_sum: E::F = M31::from(0u32).into();
                for index in 0..MAX_CANONICAL_SEATS {
                    let bit = rcs_base_onehot[index].clone();
                    let index_value: E::F = M31::from(index as u32).into();
                    eval.add_constraint(gate.clone() * bit.clone() * (bit.clone() - one.clone()));
                    // base ∈ {last_bb_seat, button}：(i − lbb)(i − button) = 0。
                    eval.add_constraint(
                        bit.clone()
                            * (pre_state_metadata[3].clone() - index_value.clone())
                            * (pre_state_metadata[1].clone() - index_value.clone()),
                    );
                    base_sum += bit.clone();
                }
                eval.add_constraint(gate.clone() * (base_sum - one.clone()));
            }
            eval.add_constraint(gate.clone() * (rcs_q[0].clone() - one.clone()));
            let mut selector_sum_rcs: E::F = M31::from(0u32).into();
            for d in 0..8 {
                let mut rotated: E::F = M31::from(0u32).into();
                for j in 0..MAX_CANONICAL_SEATS {
                    let target = (j + d + 1) % MAX_CANONICAL_SEATS;
                    rotated += rcs_base_onehot[j].clone()
                        * full_post_status[target][CanonicalSeatStatus::Active as usize].clone();
                }
                eval.add_constraint(gate.clone() * (rcs_rot[d].clone() - rotated));
                eval.add_constraint(
                    gate.clone() * (rcs_f[d].clone() - rcs_rot[d].clone() * rcs_q[d].clone()),
                );
                if d > 0 {
                    eval.add_constraint(
                        gate.clone()
                            * (rcs_q[d].clone()
                                - rcs_q[d - 1].clone() * (one.clone() - rcs_rot[d - 1].clone())),
                    );
                }
                selector_sum_rcs += rcs_f[d].clone();
            }
            eval.add_constraint(
                gate.clone() * (selector_sum_rcs.clone() + rcs_no_turn.clone() - one.clone()),
            );
            eval.add_constraint(
                gate.clone() * rcs_no_turn.clone() * (rcs_no_turn.clone() - one.clone()),
            );
            // post turn = 基座后首个 post-Active 座位（空集时 NO_SEAT，
            // 镜像 VM C5）。
            let mut street_turn: E::F = M31::from(0u32).into();
            for d in 0..8 {
                let mut seat_value: E::F = M31::from(0u32).into();
                for j in 0..MAX_CANONICAL_SEATS {
                    seat_value += rcs_base_onehot[j].clone()
                        * E::F::from(M31::from(((j + d + 1) % MAX_CANONICAL_SEATS) as u32));
                }
                street_turn += rcs_f[d].clone() * seat_value;
            }
            eval.add_constraint(
                gate.clone()
                    * (post_turn.clone()
                        - street_turn
                        - rcs_no_turn.clone() * no_seat.clone()),
            );
        }
        // ============================================================
        // #22②扩展（2026-09-15）：Showdown 完成组——showdown 窗口完成 →
        // ShowdownDisplay 展示期（资金/座位/acted 全冻结，turn 双端 NO）。
        // ============================================================
        {
            let gate = rcd_gate.clone();
            // VM 头：Revealing(Showdown=3, river=5, turn=NO) →
            // ShowdownDisplay(5, 1, 5, NO)。
            eval.add_constraint(gate.clone() * (pre_phase.clone() - M31::from(2u32).into()));
            eval.add_constraint(gate.clone() * (pre_subtag.clone() - M31::from(3u32).into()));
            eval.add_constraint(gate.clone() * (pre_street.clone() - M31::from(5u32).into()));
            eval.add_constraint(gate.clone() * (pre_turn.clone() - no_seat.clone()));
            eval.add_constraint(gate.clone() * (post_phase.clone() - M31::from(5u32).into()));
            eval.add_constraint(gate.clone() * (post_subtag.clone() - M31::from(1u32).into()));
            eval.add_constraint(gate.clone() * (post_street.clone() - M31::from(5u32).into()));
            eval.add_constraint(gate.clone() * (post_turn.clone() - no_seat.clone()));
            // pending：pre 只剩提交者一位（行级门已钉），post 清零。
            eval.add_constraint(gate.clone() * post_protocol_pending_mask.clone());
            for bit in post_protocol_pending_mask_bits.iter() {
                eval.add_constraint(gate.clone() * bit.clone());
            }
            // 资金/座位全冻结（validator: seats 双端一致；协议行全局冻结已
            // 覆盖 pot/chip_pool/承诺/leave 掩码/轨道元数据/acted 位）。
            for index in 0..MAX_CANONICAL_SEATS {
                for (pre, post) in [
                    (&full_pre_stack[index], &full_post_stack[index]),
                    (&full_pre_bet[index], &full_post_bet[index]),
                    (&full_pre_total[index], &full_post_total[index]),
                    (&full_pre_pending[index], &full_post_pending[index]),
                ] {
                    for (left, right) in pre.iter().zip(post.iter()) {
                        eval.add_constraint(gate.clone() * (right.clone() - left.clone()));
                    }
                }
                for (left, right) in full_pre_time_bank[index]
                    .iter()
                    .zip(full_post_time_bank[index].iter())
                {
                    eval.add_constraint(gate.clone() * (right.clone() - left.clone()));
                }
                for status in 0..SEAT_STATUS_COUNT {
                    eval.add_constraint(
                        gate.clone()
                            * (full_post_status[index][status].clone()
                                - full_pre_status[index][status].clone()),
                    );
                }
            }
            // 展示期下注面清零（镜像投影：非 Betting 相位 current/min 归零）。
            for limb in 0..4 {
                eval.add_constraint(gate.clone() * post_current[limb].clone());
                eval.add_constraint(gate.clone() * post_min[limb].clone());
            }
            // Deadline：post = completion_timestamp + showdown_display_ms。
            let showdown_timeout_limbs = [
                pre_timeout_config[8].clone(),
                pre_timeout_config[9].clone(),
                zero_limb.clone(),
                zero_limb.clone(),
            ];
            limb4_add_constraints_no_carry_bool(
                &mut eval,
                &gate,
                &protocol_completion_timestamp,
                &showdown_timeout_limbs,
                &post_deadline_image,
                &protocol_completion_deadline_carries,
            );
            for carry in protocol_completion_deadline_carries.iter() {
                eval.add_constraint(gate.clone() * carry.clone() * (carry.clone() - one.clone()));
            }
            // opening 承诺锚：suspended 零；deck/reconstruction 双端锚定
            //（reveal 端点检查由 validator 承担）。
            for limb in 0..16 {
                eval.add_constraint(gate.clone() * protocol_completion_commitments[0][limb].clone());
                for (opening_limb, endpoint) in [
                    (
                        &protocol_completion_commitments[1][limb],
                        &pre_opaque_commitments[1][limb],
                    ),
                    (
                        &protocol_completion_commitments[2][limb],
                        &post_opaque_commitments[1][limb],
                    ),
                    (
                        &protocol_completion_commitments[3][limb],
                        &pre_opaque_commitments[3][limb],
                    ),
                    (
                        &protocol_completion_commitments[4][limb],
                        &post_opaque_commitments[3][limb],
                    ),
                ] {
                    eval.add_constraint(gate.clone() * (opening_limb.clone() - endpoint.clone()));
                }
            }
        }
        // TE-E0: raked rows carry either percentage mode (1) or the frozen
        // FIXED_RAKE_BURN mode (2).  The charging-quantity relation below is
        // identical for both — only the L1 contract-side disposal of the
        // collected amount differs, which the AIR does not model.  The two
        // roots pin the mode to exactly {1, 2}; any other value fails
        // (fail-closed), and mode 0 must use the plain award selector.
        eval.add_constraint(
            is_reveal_raked_award.clone()
                * (rake_config[0].clone() - one.clone())
                * (rake_config[0].clone() - E::F::from(M31::from(2u32))),
        );
        let rake_bps = rake_config[1].clone();
        let rake_cap_limbs: [E::F; 4] = [
            rake_config[2].clone(),
            rake_config[3].clone(),
            rake_config[4].clone(),
            rake_config[5].clone(),
        ];
        // The awarded pot fits 32 bits and both low limbs are range-bound.
        for limb in 2..4 {
            eval.add_constraint(is_reveal_raked_award.clone() * pre_pot[limb].clone());
        }
        for (limb, bytes) in pre_pot.iter().take(2).zip(rake_pot_bytes.iter()) {
            range8_logup_constraints(&mut eval, &is_reveal_raked_award, limb, bytes, &range);
        }
        // Product `M = pot * bps` as one weighted field identity over
        // range-bound limbs; the weighted integer stays far below the M31
        // modulus, so the identity is exact over the integers.
        let mut weighted_product: E::F = M31::from(0u32).into();
        let mut weighted_scaled: E::F = M31::from(0u32).into();
        let mut weighted_rake: E::F = M31::from(0u32).into();
        let mut weighted_final: E::F = M31::from(0u32).into();
        let mut weighted_award: E::F = M31::from(0u32).into();
        let mut weighted_pot: E::F = M31::from(0u32).into();
        let mut weight: E::F = one.clone();
        for limb in 0..4 {
            weighted_product += rake_product[limb].clone() * weight.clone();
            weighted_scaled += rake_scaled[limb].clone() * weight.clone();
            weighted_rake += rake_limbs[limb].clone() * weight.clone();
            weighted_final += rake_final[limb].clone() * weight.clone();
            weighted_award += rake_award[limb].clone() * weight.clone();
            weighted_pot += pre_pot[limb].clone() * weight.clone();
            weight = weight * E::F::from(M31::from(65536u32));
        }
        eval.add_constraint(
            is_reveal_raked_award.clone()
                * (weighted_product.clone()
                    - pre_pot[0].clone() * rake_bps.clone()
                    - E::F::from(M31::from(65536u32)) * pre_pot[1].clone() * rake_bps.clone()),
        );
        for (limb, bytes) in rake_product.iter().zip(rake_product_bytes.iter()) {
            range8_logup_constraints(&mut eval, &is_reveal_raked_award, limb, bytes, &range);
        }
        for (limb, bytes) in rake_limbs.iter().zip(rake_limb_bytes.iter()) {
            range8_logup_constraints(&mut eval, &is_reveal_raked_award, limb, bytes, &range);
        }
        // Scaled identity `rake_raw * 10_000 + remainder = M` fixes the floor
        // division because the remainder is range-bound below 10_000.
        eval.add_constraint(
            is_reveal_raked_award.clone()
                * (weighted_scaled.clone()
                    - E::F::from(M31::from(10_000u32)) * weighted_rake.clone()),
        );
        for (limb, bytes) in rake_scaled.iter().zip(rake_scaled_bytes.iter()) {
            range8_logup_constraints(&mut eval, &is_reveal_raked_award, limb, bytes, &range);
        }
        // The remainder decomposes into two range-checked bytes, and a second
        // byte pair witnesses `9_999 - remainder`, pinning the remainder
        // strictly below the divisor so the floor division is exact.
        range8_logup_constraints(
            &mut eval,
            &is_reveal_raked_award,
            &rake_remainder,
            &rake_remainder_bytes,
            &range,
        );
        let bound = E::F::from(M31::from(9_999u32)) - rake_remainder.clone();
        range8_logup_constraints(
            &mut eval,
            &is_reveal_raked_award,
            &bound,
            &rake_remainder_bound_bytes,
            &range,
        );
        limb4_add_constraints(
            &mut eval,
            &is_reveal_raked_award,
            &rake_scaled,
            &[
                rake_remainder.clone(),
                M31::from(0u32).into(),
                M31::from(0u32).into(),
                M31::from(0u32).into(),
            ],
            &rake_product,
            &rake_div_carries,
        );
        // `min(raw, cap)` through a borrow chain over `raw + (2^64 - 1 - cap)
        // + 1`: the final borrow is set exactly when `raw >= cap`.
        let mut min_borrow_in: E::F = one.clone();
        for limb in 0..4 {
            let complement = E::F::from(M31::from(65535u32)) - rake_cap_limbs[limb].clone();
            let borrow_out = rake_min_borrows[limb].clone();
            let sum = rake_limbs[limb].clone() + complement + min_borrow_in.clone();
            eval.add_constraint(
                is_reveal_raked_award.clone()
                    * (sum
                        - rake_min_diff[limb].clone()
                        - E::F::from(M31::from(65536u32)) * borrow_out.clone()),
            );
            eval.add_constraint(
                is_reveal_raked_award.clone()
                    * borrow_out.clone()
                    * (borrow_out.clone() - one.clone()),
            );
            min_borrow_in = borrow_out;
        }
        for (limb, bytes) in rake_min_diff.iter().zip(rake_min_diff_bytes.iter()) {
            range8_logup_constraints(&mut eval, &is_reveal_raked_award, limb, bytes, &range);
        }
        let min_selector = rake_min_borrows[3].clone();
        for limb in 0..4 {
            eval.add_constraint(
                is_reveal_raked_award.clone()
                    * (rake_final[limb].clone()
                        - rake_limbs[limb].clone()
                        - min_selector.clone()
                            * (rake_cap_limbs[limb].clone() - rake_limbs[limb].clone())),
            );
        }
        for (limb, bytes) in rake_final.iter().zip(rake_final_bytes.iter()) {
            range8_logup_constraints(&mut eval, &is_reveal_raked_award, limb, bytes, &range);
        }
        // The survivor is credited `pot - rake` and the rake leaves custody.
        eval.add_constraint(
            is_reveal_raked_award.clone()
                * (weighted_award.clone() + weighted_final.clone() - weighted_pot.clone()),
        );
        let mut weighted_stack_deltas: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| M31::from(0u32).into());
        for index in 0..MAX_CANONICAL_SEATS {
            let mut delta_weight: E::F = one.clone();
            for limb in 0..4 {
                weighted_stack_deltas[index] += (full_post_stack[index][limb].clone()
                    - full_pre_stack[index][limb].clone())
                    * delta_weight.clone();
                delta_weight = delta_weight * E::F::from(M31::from(65536u32));
            }
            eval.add_constraint(
                is_reveal_raked_award.clone()
                    * reveal_award_winner_credit[index].clone()
                    * (weighted_stack_deltas[index].clone() - weighted_award.clone()),
            );
        }
        for (limb, bytes) in rake_award.iter().zip(rake_award_bytes.iter()) {
            range8_logup_constraints(&mut eval, &is_reveal_raked_award, limb, bytes, &range);
        }
        limb4_add_constraints(
            &mut eval,
            &is_reveal_raked_award,
            &post_chip_pool,
            &amount,
            &rake_chip_intermediate,
            &funding_chip_pool_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_reveal_raked_award,
            &rake_chip_intermediate,
            &rake_final,
            &pre_chip_pool,
            &rake_chip_extra_carries,
        );

        eval.add_constraint((one.clone() - cascade_active.clone()) * is_reveal_timeout_kick);
        for value in next_pre_image
            .iter()
            .chain(next_pre_state_root.iter())
            .chain(next_pre_lifecycle_root.iter())
            .chain(next_pre_overlay_root.iter())
            .chain(next_pre_settlement_commitment.iter())
            .chain(next_pre_custody_commitment.iter())
        {
            eval.add_constraint(active.clone() * last.clone() * value.clone());
        }
        add_limb_eq(
            &mut eval,
            &(active.clone() * (one.clone() - last.clone())),
            &post_image,
            &next_pre_image,
        );
        let scope_pre: Vec<_> = (0..16)
            .map(|i| eval.get_preprocessed_column(preprocessed_ids()[7 + i].clone()))
            .collect();
        let scope_post: Vec<_> = (0..16)
            .map(|i| eval.get_preprocessed_column(preprocessed_ids()[23 + i].clone()))
            .collect();
        add_limb_eq(
            &mut eval,
            &(active.clone() * first.clone()),
            &pre_image,
            &scope_pre,
        );
        add_limb_eq(
            &mut eval,
            &(active.clone() * last.clone()),
            &post_image,
            &scope_post,
        );
        // Each committed root domain follows the same first/last public scope
        // and adjacent-row continuity rule as the canonical state image.
        // This is deliberately independent of a future Blake2b AIR: it makes
        // the exact root bytes verifier-visible today, rather than leaving
        // them as an unscoped host witness.
        let root_domains = [
            (&pre_state_root, &post_state_root, &next_pre_state_root),
            (
                &pre_lifecycle_root,
                &post_lifecycle_root,
                &next_pre_lifecycle_root,
            ),
            (
                &pre_overlay_root,
                &post_overlay_root,
                &next_pre_overlay_root,
            ),
            (
                &pre_settlement_commitment,
                &post_settlement_commitment,
                &next_pre_settlement_commitment,
            ),
            (
                &pre_custody_commitment,
                &post_custody_commitment,
                &next_pre_custody_commitment,
            ),
        ];
        let root_ids = preprocessed_ids();
        for (domain, (pre, post, next_pre)) in root_domains.into_iter().enumerate() {
            add_limb_eq(
                &mut eval,
                &(active.clone() * (one.clone() - last.clone())),
                post,
                next_pre,
            );
            let scope_pre: Vec<_> = (0..16)
                .map(|limb| {
                    eval.get_preprocessed_column(
                        root_ids[ROOT_SCOPE_OFFSET + (2 * domain) * 16 + limb].clone(),
                    )
                })
                .collect();
            let scope_post: Vec<_> = (0..16)
                .map(|limb| {
                    eval.get_preprocessed_column(
                        root_ids[ROOT_SCOPE_OFFSET + (2 * domain + 1) * 16 + limb].clone(),
                    )
                })
                .collect();
            add_limb_eq(
                &mut eval,
                &(active.clone() * first.clone()),
                pre,
                &scope_pre,
            );
            add_limb_eq(
                &mut eval,
                &(active.clone() * last.clone()),
                post,
                &scope_post,
            );
        }

        // Bind the endpoint values already materialized by this AIR to the
        // corresponding fixed positions in the full Borsh state-image byte
        // statement.  The entire byte string is Fiat--Shamir-bound in
        // `mix_scope`; this fixed-width projection is the bridge preventing the
        // host from pairing a different table/seat/balance/root image with a
        // valid canonical trace.
        let mut pre_state_binding = Vec::with_capacity(STATE_IMAGE_PROJECTION_LIMBS);
        let mut post_state_binding = Vec::with_capacity(STATE_IMAGE_PROJECTION_LIMBS);
        pre_state_binding.extend(pre_state_metadata.iter().cloned());
        post_state_binding.extend(post_state_metadata.iter().cloned());
        pre_state_binding.extend(table.iter().cloned());
        post_state_binding.extend(table.iter().cloned());
        pre_state_binding.extend(pre_hand.iter().cloned());
        post_state_binding.extend(post_hand.iter().cloned());
        pre_state_binding.extend(pre_seq.iter().cloned());
        post_state_binding.extend(post_seq.iter().cloned());
        for (pre, post) in [
            (&pre_phase, &post_phase),
            (&pre_subtag, &post_subtag),
            (&pre_street, &post_street),
            (&pre_turn, &post_turn),
        ] {
            pre_state_binding.push(pre.clone());
            post_state_binding.push(post.clone());
        }
        pre_state_binding.extend(pre_deadline_image.iter().cloned());
        post_state_binding.extend(post_deadline_image.iter().cloned());
        pre_state_binding.extend(pre_timeout_config.iter().cloned());
        post_state_binding.extend(post_timeout_config.iter().cloned());
        for (pre, post) in [
            (&pre_current, &post_current),
            (&pre_min, &post_min),
            (&pre_chip_pool, &post_chip_pool),
            (&pre_pot, &post_pot),
        ] {
            pre_state_binding.extend(pre.iter().cloned());
            post_state_binding.extend(post.iter().cloned());
        }
        pre_state_binding.push(pre_acted_mask.clone());
        post_state_binding.push(post_acted_mask.clone());
        pre_state_binding.push(pre_leave_mask.clone());
        post_state_binding.push(post_leave_mask.clone());
        pre_state_binding.push(pre_protocol_pending_mask.clone());
        post_state_binding.push(post_protocol_pending_mask.clone());
        for (pre, post) in [
            (&pre_rules_commitment, &post_rules_commitment),
            (&pre_governance_commitment, &post_governance_commitment),
            (&pre_state_root, &post_state_root),
            (&pre_lifecycle_root, &post_lifecycle_root),
            (&pre_overlay_root, &post_overlay_root),
            (&pre_settlement_commitment, &post_settlement_commitment),
            (&pre_custody_commitment, &post_custody_commitment),
        ] {
            pre_state_binding.extend(pre.iter().cloned());
            post_state_binding.extend(post.iter().cloned());
        }
        for commitment in 0..OPAQUE_COMMITMENT_COUNT {
            pre_state_binding.extend(pre_opaque_commitments[commitment].iter().cloned());
            post_state_binding.extend(post_opaque_commitments[commitment].iter().cloned());
        }
        for seat_index in 0..MAX_CANONICAL_SEATS {
            let mut pre_status_value: E::F = M31::from(0u32).into();
            let mut post_status_value: E::F = M31::from(0u32).into();
            for status in 0..SEAT_STATUS_COUNT {
                let weight: E::F = M31::from(status as u32).into();
                pre_status_value += full_pre_status[seat_index][status].clone() * weight.clone();
                post_status_value += full_post_status[seat_index][status].clone() * weight;
            }
            pre_state_binding.push(pre_status_value);
            post_state_binding.push(post_status_value);
            pre_state_binding.push(pre_acted_bits[seat_index].clone());
            post_state_binding.push(post_acted_bits[seat_index].clone());
            for (pre, post) in [
                (&full_pre_stack[seat_index], &full_post_stack[seat_index]),
                (&full_pre_bet[seat_index], &full_post_bet[seat_index]),
                (&full_pre_total[seat_index], &full_post_total[seat_index]),
                (
                    &full_pre_pending[seat_index],
                    &full_post_pending[seat_index],
                ),
            ] {
                pre_state_binding.extend(pre.iter().cloned());
                post_state_binding.extend(post.iter().cloned());
            }
            pre_state_binding.extend(full_pre_time_bank[seat_index].iter().cloned());
            post_state_binding.extend(full_post_time_bank[seat_index].iter().cloned());
            for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                pre_state_binding
                    .extend(pre_seat_commitments[seat_index][commitment].iter().cloned());
                post_state_binding.extend(
                    post_seat_commitments[seat_index][commitment]
                        .iter()
                        .cloned(),
                );
            }
        }
        debug_assert_eq!(pre_state_binding.len(), STATE_IMAGE_PROJECTION_LIMBS);
        debug_assert_eq!(post_state_binding.len(), STATE_IMAGE_PROJECTION_LIMBS);
        let image_scope_ids = preprocessed_ids();
        let scope_pre_state: Vec<_> = (0..STATE_IMAGE_PROJECTION_LIMBS)
            .map(|limb| {
                eval.get_preprocessed_column(
                    image_scope_ids[STATE_IMAGE_SCOPE_OFFSET + limb].clone(),
                )
            })
            .collect();
        let scope_post_state: Vec<_> = (0..STATE_IMAGE_PROJECTION_LIMBS)
            .map(|limb| {
                eval.get_preprocessed_column(
                    image_scope_ids[STATE_IMAGE_SCOPE_OFFSET + STATE_IMAGE_PROJECTION_LIMBS + limb]
                        .clone(),
                )
            })
            .collect();
        add_limb_eq(
            &mut eval,
            &(active.clone() * first.clone()),
            &pre_state_binding,
            &scope_pre_state,
        );
        add_limb_eq(
            &mut eval,
            &(active.clone() * last.clone()),
            &post_state_binding,
            &scope_post_state,
        );
        // Table side of the shared range LogUp: rows 0..=255 yield
        // `-multiplicity / (z + row)` so the uses and the table balance to
        // zero inside this single component, exactly like the cairo-air
        // range-check pattern.
        let range_multiplicity = eval.next_trace_mask();
        let range_table_value =
            eval.get_preprocessed_column(preprocessed_ids()[RANGE_TABLE_SCOPE_OFFSET].clone());
        eval.add_to_relation(RelationEntry::new(
            &self.range,
            -E::EF::from(range_multiplicity),
            &[range_table_value],
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

/// Prove a tagged batch whose terminal is a raked sole-survivor award.  The
/// complete table rules are hashed by the shared lookup-backed Blake2b STARK
/// and attached alongside the public rake opening, so the verifier can bind
/// the opening to the pre rules commitment without any native hashing.
pub fn prove_canonical_raked_tagged_batch(
    witnesses: &[CanonicalTransitionWitness],
    rules: &poker_l1::contracts::texas_poker::types::TableRules,
) -> TexasAirResult<ArchivedCanonicalTaggedProof> {
    let has_raked = witnesses
        .iter()
        .any(|w| w.kind == CanonicalTransitionKind::RevealTimeoutRakedAward);
    if !has_raked {
        return Err(TexasAirError::SpecViolation(
            "raked canonical proof requires a raked award terminal".into(),
        ));
    }
    crate::canonical_rake_opening::validate_rules_opening(rules)?;
    let mut archive = prove_canonical_tagged_batch(witnesses)?;
    let expected = crate::canonical_rake_opening::rake_opening_of(rules);
    if archive.rake_opening != Some(expected) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "witness rake opening is detached from the table rules".into(),
        ));
    }
    archive.rules_hash = Some(crate::canonical_rake_opening::prove_canonical_rules_hash(
        rules,
    )?);
    Ok(archive)
}

/// Prove a tagged batch containing a final `SubmitReveal` (RevealComplete)
/// transition.  The complete table rules are hashed by the shared
/// lookup-backed Blake2b STARK and attached alongside the public blind
/// opening, so the verifier can bind the blind scope columns to the pre
/// rules commitment without any native hashing.
pub fn prove_canonical_reveal_completion_batch(
    witnesses: &[CanonicalTransitionWitness],
    rules: &poker_l1::contracts::texas_poker::types::TableRules,
) -> TexasAirResult<ArchivedCanonicalTaggedProof> {
    prove_canonical_reveal_completion_batch_with_pcs(
        witnesses,
        rules,
        crate::prover_context::protocol_pcs_config(),
    )
}

/// [`prove_canonical_reveal_completion_batch`] with an explicit PCS profile
/// (see [`prove_canonical_tagged_batch_with_pcs`]).
pub fn prove_canonical_reveal_completion_batch_with_pcs(
    witnesses: &[CanonicalTransitionWitness],
    rules: &poker_l1::contracts::texas_poker::types::TableRules,
    config: stwo::core::pcs::PcsConfig,
) -> TexasAirResult<ArchivedCanonicalTaggedProof> {
    let has_reveal_completion = witnesses.iter().any(|w| {
        w.kind == CanonicalTransitionKind::SubmitReveal
            && matches!(
                w.protocol_completion.kind,
                CanonicalProtocolCompletionKind::Reveal
                    | CanonicalProtocolCompletionKind::RevealStreet
                    | CanonicalProtocolCompletionKind::Showdown
            )
    });
    if !has_reveal_completion {
        return Err(TexasAirError::SpecViolation(
            "reveal-completion canonical proof requires a final SubmitReveal row".into(),
        ));
    }
    crate::canonical_rake_opening::validate_rules_opening(rules)?;
    // The composed relation posts blinds only: an ante configuration would
    // need its own fixed ledger, so stay fail-closed here.
    if rules.ante_mode != 0 || rules.ante_amount != 0 {
        return Err(TexasAirError::SpecViolation(
            "reveal-completion composition requires ANTE_MODE_NONE".into(),
        ));
    }
    let mut archive = prove_canonical_tagged_batch_with_pcs(witnesses, config)?;
    let expected = crate::canonical_rake_opening::blind_opening_of(rules);
    if archive.blind_opening != Some(expected) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "witness blind opening is detached from the table rules".into(),
        ));
    }
    archive.rules_hash = Some(crate::canonical_rake_opening::prove_canonical_rules_hash(
        rules,
    )?);
    Ok(archive)
}

/// Storage order of the 56 raked-award byte advice columns, matching the
/// relation-entry emission order inside `CanonicalAir::evaluate`.
const RAKE_BYTE_COLUMN_ORDER: [usize; 56] = [
    RAKE_POT_BYTES_OFFSET,
    RAKE_POT_BYTES_OFFSET + 1,
    RAKE_POT_BYTES_OFFSET + 2,
    RAKE_POT_BYTES_OFFSET + 3,
    RAKE_PRODUCT_BYTES_OFFSET,
    RAKE_PRODUCT_BYTES_OFFSET + 1,
    RAKE_PRODUCT_BYTES_OFFSET + 2,
    RAKE_PRODUCT_BYTES_OFFSET + 3,
    RAKE_PRODUCT_BYTES_OFFSET + 4,
    RAKE_PRODUCT_BYTES_OFFSET + 5,
    RAKE_PRODUCT_BYTES_OFFSET + 6,
    RAKE_PRODUCT_BYTES_OFFSET + 7,
    RAKE_LIMB_BYTES_OFFSET,
    RAKE_LIMB_BYTES_OFFSET + 1,
    RAKE_LIMB_BYTES_OFFSET + 2,
    RAKE_LIMB_BYTES_OFFSET + 3,
    RAKE_LIMB_BYTES_OFFSET + 4,
    RAKE_LIMB_BYTES_OFFSET + 5,
    RAKE_LIMB_BYTES_OFFSET + 6,
    RAKE_LIMB_BYTES_OFFSET + 7,
    RAKE_SCALED_BYTES_OFFSET,
    RAKE_SCALED_BYTES_OFFSET + 1,
    RAKE_SCALED_BYTES_OFFSET + 2,
    RAKE_SCALED_BYTES_OFFSET + 3,
    RAKE_SCALED_BYTES_OFFSET + 4,
    RAKE_SCALED_BYTES_OFFSET + 5,
    RAKE_SCALED_BYTES_OFFSET + 6,
    RAKE_SCALED_BYTES_OFFSET + 7,
    RAKE_REMAINDER_BYTES_OFFSET,
    RAKE_REMAINDER_BYTES_OFFSET + 1,
    RAKE_REMAINDER_BOUND_BYTES_OFFSET,
    RAKE_REMAINDER_BOUND_BYTES_OFFSET + 1,
    RAKE_MIN_DIFF_BYTES_OFFSET,
    RAKE_MIN_DIFF_BYTES_OFFSET + 1,
    RAKE_MIN_DIFF_BYTES_OFFSET + 2,
    RAKE_MIN_DIFF_BYTES_OFFSET + 3,
    RAKE_MIN_DIFF_BYTES_OFFSET + 4,
    RAKE_MIN_DIFF_BYTES_OFFSET + 5,
    RAKE_MIN_DIFF_BYTES_OFFSET + 6,
    RAKE_MIN_DIFF_BYTES_OFFSET + 7,
    RAKE_FINAL_BYTES_OFFSET,
    RAKE_FINAL_BYTES_OFFSET + 1,
    RAKE_FINAL_BYTES_OFFSET + 2,
    RAKE_FINAL_BYTES_OFFSET + 3,
    RAKE_FINAL_BYTES_OFFSET + 4,
    RAKE_FINAL_BYTES_OFFSET + 5,
    RAKE_FINAL_BYTES_OFFSET + 6,
    RAKE_FINAL_BYTES_OFFSET + 7,
    RAKE_AWARD_BYTES_OFFSET,
    RAKE_AWARD_BYTES_OFFSET + 1,
    RAKE_AWARD_BYTES_OFFSET + 2,
    RAKE_AWARD_BYTES_OFFSET + 3,
    RAKE_AWARD_BYTES_OFFSET + 4,
    RAKE_AWARD_BYTES_OFFSET + 5,
    RAKE_AWARD_BYTES_OFFSET + 6,
    RAKE_AWARD_BYTES_OFFSET + 7,
];

/// Column of the `RevealTimeoutRakedAward` kind selector (active flag plus
/// one selector per kind).
const RAKED_KIND_COLUMN: usize = 1 + CanonicalTransitionKind::RevealTimeoutRakedAward as usize;

/// Number of paired LogUp interaction columns: 56 use lookups + 1 table
/// entry = 57 fractions, paired into 29 secure columns (four base columns
/// each).
const RANGE_INTERACTION_COLUMNS: usize = 29;

/// Append the shared range-table multiplicity column to a completed trace.
fn append_range_multiplicity(trace: &mut MethodTrace) {
    let mut multiplicities = vec![0u32; 256];
    for row in 0..trace.cols[RAKED_KIND_COLUMN].len() {
        if trace.cols[RAKED_KIND_COLUMN][row] != M31::from(1u32) {
            continue;
        }
        for column in RAKE_BYTE_COLUMN_ORDER {
            let value = u64::from(trace.cols[column][row].0) as usize;
            if value < 256 {
                multiplicities[value] += 1;
            }
        }
    }
    for (row, cell) in trace.cols[NUM_COLUMNS].iter_mut().enumerate() {
        *cell = if row < 256 {
            M31::from(multiplicities[row])
        } else {
            M31::from(0u32)
        };
    }
}

/// Build the paired LogUp interaction columns for the shared range table in
/// the single-component cairo-air layout: 28 columns pair the 56 use
/// lookups, and the last column holds the single negated table entry, so
/// the generator's claimed sum is exactly zero for a balanced multiset.
fn canonical_range_interaction(
    trace: &MethodTrace,
    log_size: u32,
    range: &CanonicalRange8,
) -> (
    Vec<
        stwo::prover::poly::circle::CircleEvaluation<
            stwo::prover::backend::simd::SimdBackend,
            M31,
            stwo::prover::poly::BitReversedOrder,
        >,
    >,
    SecureField,
) {
    use stwo::prover::backend::simd::m31::{LOG_N_LANES, PackedBaseField};
    use stwo::prover::backend::simd::qm31::PackedSecureField;

    // The committed trace/preprocessed columns are bit-reversed by
    // MethodTrace::to_evaluations; the interaction columns must align with
    // that storage, so every source column is bit-reversed before packing.
    //
    // Build the permutation table once: row `i` maps to bit-reversed `i` in
    // O(2) total, then every column lookup is O(1).
    let n_rows = 1usize << log_size;
    let mut permutation: Vec<u32> = (0..n_rows as u32).collect();
    for i in 0..n_rows {
        let mut r = 0usize;
        let mut j = i;
        for bit in 0..log_size {
            if (j & 1) == 1 {
                r |= 1 << (log_size - 1 - bit);
            }
            j >>= 1;
        }
        permutation[i] = r as u32;
    }
    let bitrev = |column: &[M31]| -> Vec<M31> {
        let mut out = vec![M31::from(0u32); column.len()];
        for (i, &r) in permutation.iter().enumerate() {
            out[i] = column[r as usize];
        }
        out
    };
    let raked_gate = bitrev(&trace.cols[RAKED_KIND_COLUMN]);
    let multiplicity = bitrev(&trace.cols[NUM_COLUMNS]);
    let byte_columns: [Vec<M31>; 56] =
        std::array::from_fn(|lookup| bitrev(&trace.cols[RAKE_BYTE_COLUMN_ORDER[lookup]]));
    let table_values: Vec<M31> = {
        let natural: Vec<M31> = (0..(1usize << log_size))
            .map(|row| {
                if row < 256 {
                    M31::from(row as u32)
                } else {
                    M31::from(0u32)
                }
            })
            .collect();
        bitrev(&natural)
    };
    let pack_vec = |column: &[M31], vector_row: usize| {
        let mut values = [M31::from(0u32); stwo::prover::backend::simd::m31::N_LANES];
        for (lane, value) in values.iter_mut().enumerate() {
            let row = vector_row * stwo::prover::backend::simd::m31::N_LANES + lane;
            *value = if row < column.len() {
                column[row]
            } else {
                M31::from(0u32)
            };
        }
        PackedBaseField::from_array(values)
    };

    let mut generator = LogupTraceGenerator::new(log_size);
    for pair in 0..28 {
        let mut col = generator.new_col();
        for vector_row in 0..(1usize << (log_size - LOG_N_LANES)) {
            let gate = pack_vec(&raked_gate, vector_row);
            let d0: PackedSecureField =
                range.combine(&[pack_vec(&byte_columns[2 * pair], vector_row)]);
            let d1: PackedSecureField =
                range.combine(&[pack_vec(&byte_columns[2 * pair + 1], vector_row)]);
            let gate_secure = PackedSecureField::from(gate);
            col.write_frac(vector_row, gate_secure * (d0 + d1), d0 * d1);
        }
        col.finalize_col();
    }
    {
        let mut col = generator.new_col();
        for vector_row in 0..(1usize << (log_size - LOG_N_LANES)) {
            let multiplicity_packed = pack_vec(&multiplicity, vector_row);
            let d: PackedSecureField = range.combine(&[pack_vec(&table_values, vector_row)]);
            let numerator = -PackedSecureField::from(multiplicity_packed);
            col.write_frac(vector_row, numerator, d);
        }
        col.finalize_col();
    }
    generator.finalize_last()
}

/// PCS profile types re-exported so downstream crates (texas) can pass
/// explicit profiles to the `*_with_pcs` entry points.
pub use stwo::core::pcs::PcsConfig;

/// Production canonical PCS profile (40-bit conjectured security).
pub fn protocol_pcs_config() -> PcsConfig {
    crate::prover_context::protocol_pcs_config()
}

/// 128-bit (conjectured, stwo model) canonical PCS profile.
pub fn security_128_pcs_config() -> PcsConfig {
    crate::prover_context::security_128_pcs_config()
}

pub fn prove_canonical_tagged_batch(
    witnesses: &[CanonicalTransitionWitness],
) -> TexasAirResult<ArchivedCanonicalTaggedProof> {
    prove_canonical_tagged_batch_with_pcs(witnesses, crate::prover_context::protocol_pcs_config())
}

/// [`prove_canonical_tagged_batch`] with an explicit PCS profile. Prover and
/// verifier must pass the same profile (it is mixed into the Fiat--Shamir
/// channel); use [`crate::prover_context::security_128_pcs_config`] for the
/// 128-bit conjectured-security benchmark/adoption path.
pub fn prove_canonical_tagged_batch_with_pcs(
    witnesses: &[CanonicalTransitionWitness],
    config: stwo::core::pcs::PcsConfig,
) -> TexasAirResult<ArchivedCanonicalTaggedProof> {
    let (trace, mut archive) = trace_for(witnesses)?;
    let scope = scope_trace(&archive, trace.log_size);
    let twiddles =
        crate::prover_context::simd_twiddles(trace.log_size + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, &archive);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(scope.to_evaluations());
        b.commit(&mut channel);
    }
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(trace.to_evaluations());
        b.commit(&mut channel);
    }
    let range = CanonicalRange8::draw(&mut channel);
    let (interaction, range_sum) = canonical_range_interaction(&trace, trace.log_size, &range);
    channel.mix_felts(&[range_sum]);
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(interaction);
        b.commit(&mut channel);
    }
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        CanonicalAir {
            log_size: trace.log_size,
            range,
        },
        range_sum,
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;
    archive.range_claimed_sum = range_sum.to_m31_array().map(|limb| limb.0);
    archive.stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    Ok(archive)
}

/// Prove a canonical batch whose public scope is reserved for a fixed-width
/// L1 state-object opening.
///
/// This function only commits the key/epoch into the canonical STARK's
/// Fiat--Shamir scope.  A separate hash/opening STARK proves and checks
/// the matching Blake2b sparse-Merkle openings; keeping the two STARKs
/// separate avoids an in-AIR STARK verifier on the latency-sensitive route.
pub fn prove_canonical_tagged_batch_for_state_opening(
    witnesses: &[CanonicalTransitionWitness],
    state_opening: CanonicalStateOpeningScope,
) -> TexasAirResult<ArchivedCanonicalTaggedProof> {
    prove_canonical_tagged_batch_for_state_opening_with_pcs(
        witnesses,
        state_opening,
        crate::prover_context::protocol_pcs_config(),
    )
}

/// [`prove_canonical_tagged_batch_for_state_opening`] with an explicit PCS
/// profile (see [`prove_canonical_tagged_batch_with_pcs`]).
pub fn prove_canonical_tagged_batch_for_state_opening_with_pcs(
    witnesses: &[CanonicalTransitionWitness],
    state_opening: CanonicalStateOpeningScope,
    config: stwo::core::pcs::PcsConfig,
) -> TexasAirResult<ArchivedCanonicalTaggedProof> {
    state_opening.validate()?;
    let (trace, mut archive) = trace_for_with_state_opening_scope(witnesses, state_opening)?;
    let scope = scope_trace(&archive, trace.log_size);
    let twiddles =
        crate::prover_context::simd_twiddles(trace.log_size + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, &archive);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(scope.to_evaluations());
        b.commit(&mut channel);
    }
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(trace.to_evaluations());
        b.commit(&mut channel);
    }
    let range = CanonicalRange8::draw(&mut channel);
    let (interaction, range_sum) = canonical_range_interaction(&trace, trace.log_size, &range);
    channel.mix_felts(&[range_sum]);
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(interaction);
        b.commit(&mut channel);
    }
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        CanonicalAir {
            log_size: trace.log_size,
            range,
        },
        range_sum,
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;
    archive.range_claimed_sum = range_sum.to_m31_array().map(|limb| limb.0);
    archive.stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    Ok(archive)
}

pub fn verify_canonical_tagged_proof(archive: &ArchivedCanonicalTaggedProof) -> TexasAirResult<()> {
    verify_canonical_tagged_proof_with_pcs(archive, crate::prover_context::protocol_pcs_config())
}

/// [`verify_canonical_tagged_proof`] with an explicit PCS profile (must match
/// the prover's profile; see [`crate::prover_context::security_128_pcs_config`]).
pub fn verify_canonical_tagged_proof_with_pcs(
    archive: &ArchivedCanonicalTaggedProof,
    config: stwo::core::pcs::PcsConfig,
) -> TexasAirResult<()> {
    if archive.num_columns != NUM_COLUMNS as u32
        || archive.transition_count == 0
        || archive.transition_count as usize > (1usize << archive.log_size)
        || archive.log_size > 10
        || archive.first_transition_kind as usize >= KIND_COUNT
        || archive.last_transition_kind as usize >= KIND_COUNT
    {
        return Err(TexasAirError::SpecViolation(
            "canonical proof shape is invalid".into(),
        ));
    }
    validate_reveal_timeout_cascade_archive_shape(archive)?;
    let (pre_image, _) = validate_state_image_bytes(archive)?;
    verify_canonical_rake_binding(archive, &pre_image)?;
    verify_canonical_stark_with_pcs(archive, config)
}

/// Bind the public rake/blind openings to the pre rules commitment through
/// the companion lookup-backed Blake2b rules proof.  A carried opening
/// without the proof, or a proof without any opening, fails closed.  Both
/// projections share one rules statement, so a single proof authenticates
/// them together.
fn verify_canonical_rake_binding(
    archive: &ArchivedCanonicalTaggedProof,
    pre_image: &CanonicalStateImage,
) -> TexasAirResult<()> {
    let has_opening = archive.rake_opening.is_some() || archive.blind_opening.is_some();
    if !has_opening {
        if archive.rules_hash.is_some() {
            return Err(TexasAirError::SpecViolation(
                "canonical rules proof must authenticate a carried opening".into(),
            ));
        }
        return Ok(());
    }
    let Some(rules_hash) = &archive.rules_hash else {
        return Err(TexasAirError::SpecViolation(
            "canonical rake/blind opening and rules proof must be carried together".into(),
        ));
    };
    let authenticated = crate::canonical_rake_opening::verify_canonical_rules_hash(
        rules_hash,
        pre_image.rules_commitment,
    )?;
    if let Some(opening) = &archive.rake_opening
        && authenticated.rake != *opening
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical rake opening is detached from the authenticated rules".into(),
        ));
    }
    if let Some(opening) = &archive.blind_opening
        && crate::canonical_rake_opening::blind_opening_of(&authenticated.rules) != *opening
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical blind opening is detached from the authenticated rules".into(),
        ));
    }
    Ok(())
}

fn verify_canonical_stark(archive: &ArchivedCanonicalTaggedProof) -> TexasAirResult<()> {
    verify_canonical_stark_with_pcs(archive, crate::prover_context::protocol_pcs_config())
}

fn verify_canonical_stark_with_pcs(
    archive: &ArchivedCanonicalTaggedProof,
    config: stwo::core::pcs::PcsConfig,
) -> TexasAirResult<()> {
    let proof: StarkProof<Poseidon252MerkleHasher> = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    if proof.commitments.len() < 2 {
        return Err(TexasAirError::SerializationError(
            "canonical Stark proof is missing scope or trace commitments".into(),
        ));
    }
    let scope = scope_trace(archive, archive.log_size);
    let twiddles = crate::prover_context::simd_twiddles(
        archive.log_size + config.fri_config.log_blowup_factor,
    );
    let mut trusted =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    let mut scope_channel = Poseidon252Channel::default();
    {
        let mut b = trusted.tree_builder();
        b.extend_evals(scope.to_evaluations());
        b.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical public scope commitment mismatch".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, archive);
    let mut scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![archive.log_size; PREPROCESSED_COLUMNS],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![archive.log_size; NUM_COLUMNS + 1],
        &mut channel,
    );
    let range = CanonicalRange8::draw(&mut channel);
    let claimed = SecureField::from_m31_array(core::array::from_fn(|index| {
        M31::from(archive.range_claimed_sum[index])
    }));
    channel.mix_felts(&[claimed]);
    scheme.commit(
        proof.commitments[2],
        &vec![archive.log_size; RANGE_INTERACTION_COLUMNS * 4],
        &mut channel,
    );
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        CanonicalAir {
            log_size: archive.log_size,
            range,
        },
        SecureField::from(0u32),
    );
    verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|e: VerificationError| TexasAirError::ConstraintUnsatisfied(e.to_string()))
}

fn validate_reveal_timeout_cascade_archive_shape(
    archive: &ArchivedCanonicalTaggedProof,
) -> TexasAirResult<()> {
    let schedule = &archive.reveal_timeout_cascade_schedule;
    if archive.reveal_timeout_cascade_count == 0 {
        if schedule
            .iter()
            .any(|seat| *seat != REVEAL_TIMEOUT_CASCADE_EMPTY_SEAT)
        {
            return Err(TexasAirError::SpecViolation(
                "ordinary canonical batch carries a reveal-timeout schedule".into(),
            ));
        }
        return Ok(());
    }
    let count = usize::from(archive.reveal_timeout_cascade_count);
    let terminal_continuation = archive.transition_count
        == archive.reveal_timeout_cascade_count as u16 + 1
        && (archive.last_transition_kind == CanonicalTransitionKind::RevealTimeoutReset as u8
            || archive.last_transition_kind
                == CanonicalTransitionKind::RevealTimeoutReconstruct as u8
            || archive.last_transition_kind == CanonicalTransitionKind::RevealTimeoutAward as u8
            || archive.last_transition_kind
                == CanonicalTransitionKind::RevealTimeoutRakedAward as u8);
    let strict_prefix = archive.transition_count == archive.reveal_timeout_cascade_count as u16
        && archive.last_transition_kind == CanonicalTransitionKind::RevealTimeoutKick as u8;
    if count > MAX_REVEAL_TIMEOUT_CASCADE_KICKS
        || archive.first_transition_kind != CanonicalTransitionKind::RevealTimeoutKick as u8
        || (!terminal_continuation && !strict_prefix)
        || schedule[..count]
            .iter()
            .any(|seat| *seat >= MAX_CANONICAL_SEATS as u8)
        || schedule[..count]
            .windows(2)
            .any(|pair| pair[0] >= pair[1] || pair[0] >= MAX_CANONICAL_SEATS as u8)
        || (terminal_continuation
            && (count >= MAX_REVEAL_TIMEOUT_CASCADE_KICKS
                || schedule[count] >= MAX_CANONICAL_SEATS as u8
                || schedule[count] <= schedule[count - 1]))
        || schedule[if terminal_continuation {
            count + 1
        } else {
            count
        }..]
            .iter()
            .any(|seat| *seat != REVEAL_TIMEOUT_CASCADE_EMPTY_SEAT)
    {
        return Err(TexasAirError::SpecViolation(
            "reveal-timeout cascade archive schedule is non-canonical".into(),
        ));
    }
    Ok(())
}

/// Verify a proof against the exact public scope reconstructed from a retained
/// witness batch.  Production admission uses the archive-only verifier above;
/// this compatibility helper is deliberately replay-oriented test tooling.
pub fn verify_canonical_tagged_batch(
    witnesses: &[CanonicalTransitionWitness],
    archive: &ArchivedCanonicalTaggedProof,
) -> TexasAirResult<()> {
    let (_, expected) = trace_for(witnesses)?;
    if expected.table_id != archive.table_id
        || expected.batch_digest != archive.batch_digest
        || expected.pre_state_commitment != archive.pre_state_commitment
        || expected.post_state_commitment != archive.post_state_commitment
        || expected.pre_state_image_bytes != archive.pre_state_image_bytes
        || expected.post_state_image_bytes != archive.post_state_image_bytes
        || expected.first_transition_kind != archive.first_transition_kind
        || expected.last_transition_kind != archive.last_transition_kind
        || archive_root_scope(&expected) != archive_root_scope(archive)
        || expected.state_object_key != archive.state_object_key
        || expected.state_opening_epoch != archive.state_opening_epoch
        || expected.transition_count != archive.transition_count
    {
        return Err(TexasAirError::SpecViolation(
            "canonical proof public scope mismatch".into(),
        ));
    }
    verify_canonical_tagged_proof_with_pcs(archive, crate::prover_context::protocol_pcs_config())
}

/// [`verify_canonical_tagged_batch`] with an explicit PCS profile (must match
/// the prover's profile).
pub fn verify_canonical_tagged_batch_with_pcs(
    witnesses: &[CanonicalTransitionWitness],
    archive: &ArchivedCanonicalTaggedProof,
    config: stwo::core::pcs::PcsConfig,
) -> TexasAirResult<()> {
    let (_, expected) = trace_for(witnesses)?;
    if expected.table_id != archive.table_id
        || expected.batch_digest != archive.batch_digest
        || expected.pre_state_commitment != archive.pre_state_commitment
        || expected.post_state_commitment != archive.post_state_commitment
        || expected.pre_state_image_bytes != archive.pre_state_image_bytes
        || expected.post_state_image_bytes != archive.post_state_image_bytes
        || expected.first_transition_kind != archive.first_transition_kind
        || expected.last_transition_kind != archive.last_transition_kind
        || archive_root_scope(&expected) != archive_root_scope(archive)
        || expected.state_object_key != archive.state_object_key
        || expected.state_opening_epoch != archive.state_opening_epoch
        || expected.transition_count != archive.transition_count
    {
        return Err(TexasAirError::SpecViolation(
            "canonical proof public scope mismatch".into(),
        ));
    }
    verify_canonical_tagged_proof_with_pcs(archive, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};

    use crate::texas_canonical::{
        CANONICAL_ABI_VERSION, CanonicalActionPayload, CanonicalBoardRevealAssignment,
        CanonicalPhase, CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus,
        CanonicalStateImage, MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
    };
    use stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;
    use stwo::prover::backend::Column as _;
    use stwo_constraint_framework::EvalAtRow;

    #[derive(Clone, Copy, Debug)]
    struct Degree(usize);

    impl std::fmt::Display for Degree {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl num_traits::One for Degree {
        fn one() -> Self {
            Self(0)
        }
    }

    impl num_traits::Zero for Degree {
        fn zero() -> Self {
            Self(0)
        }

        fn is_zero(&self) -> bool {
            self.0 == 0
        }
    }

    impl stwo::core::fields::FieldExpOps for Degree {
        fn inverse(&self) -> Self {
            *self
        }
    }

    impl Add for Degree {
        type Output = Self;
        fn add(self, rhs: Self) -> Self {
            Self(self.0.max(rhs.0))
        }
    }

    impl Sub for Degree {
        type Output = Self;
        fn sub(self, rhs: Self) -> Self {
            Self(self.0.max(rhs.0))
        }
    }

    impl Mul for Degree {
        type Output = Self;
        fn mul(self, rhs: Self) -> Self {
            Self(self.0 + rhs.0)
        }
    }

    impl Neg for Degree {
        type Output = Self;
        fn neg(self) -> Self {
            self
        }
    }

    impl AddAssign for Degree {
        fn add_assign(&mut self, rhs: Self) {
            self.0 = self.0.max(rhs.0);
        }
    }

    impl MulAssign for Degree {
        fn mul_assign(&mut self, rhs: Self) {
            self.0 += rhs.0;
        }
    }

    impl AddAssign<M31> for Degree {
        fn add_assign(&mut self, _: M31) {}
    }

    impl Mul<M31> for Degree {
        type Output = Self;
        fn mul(self, _: M31) -> Self {
            self
        }
    }

    impl Add<M31> for Degree {
        type Output = Self;
        fn add(self, _: M31) -> Self {
            self
        }
    }

    impl Add<SecureField> for Degree {
        type Output = Self;
        fn add(self, _: SecureField) -> Self {
            self
        }
    }

    impl Mul<SecureField> for Degree {
        type Output = Self;
        fn mul(self, _: SecureField) -> Self {
            self
        }
    }

    impl Sub<SecureField> for Degree {
        type Output = Self;
        fn sub(self, _: SecureField) -> Self {
            self
        }
    }

    impl From<M31> for Degree {
        fn from(_: M31) -> Self {
            Self(0)
        }
    }

    impl From<SecureField> for Degree {
        fn from(_: SecureField) -> Self {
            Self(0)
        }
    }

    struct DegreeEvaluator {
        max: usize,
    }

    impl EvalAtRow for DegreeEvaluator {
        type F = Degree;
        type EF = Degree;

        fn next_trace_mask(&mut self) -> Self::F {
            Degree(1)
        }

        fn get_preprocessed_column(
            &mut self,
            _column: stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId,
        ) -> Self::F {
            Degree(1)
        }

        fn next_interaction_mask<const N: usize>(
            &mut self,
            _interaction: usize,
            _offsets: [isize; N],
        ) -> [Self::F; N] {
            std::array::from_fn(|_| Degree(1))
        }

        fn add_constraint<G>(&mut self, constraint: G)
        where
            Self::EF: Mul<G, Output = Self::EF> + From<G>,
        {
            let constraint = Self::EF::from(constraint);
            self.max = self.max.max(constraint.0);
        }

        fn combine_ef(_: [Self::F; SECURE_EXTENSION_DEGREE]) -> Self::EF {
            num_traits::Zero::zero()
        }
        fn add_to_relation<R: Relation<Self::F, Self::EF>>(
            &mut self,
            _entry: stwo_constraint_framework::RelationEntry<'_, Self::F, Self::EF, R>,
        ) {
        }
        fn write_logup_frac(&mut self, _fraction: stwo::core::Fraction<Self::EF, Self::EF>) {}
        fn finalize_logup_in_pairs(&mut self) {}
        fn finalize_logup(&mut self) {}
    }

    fn image() -> CanonicalStateImage {
        CanonicalStateImage {
            abi_version: CANONICAL_ABI_VERSION,
            table_id: 7,
            hand_id: 1,
            call_seq: 0,
            phase: CanonicalPhase::Waiting,
            phase_subtag: 0,
            street: 0,
            current_turn: NO_CANONICAL_SEAT,
            deadline_ms: 0,
            shuffle_timeout_ms: 10_000,
            reveal_timeout_ms: 10_000,
            betting_timeout_ms: 30_000,
            reconstruct_timeout_ms: 10_000,
            showdown_display_ms: 3_000,
            current_bet: 0,
            min_raise: 0,
            chip_pool: 0,
            pot: 0,
            button: 0,
            last_bb_seat: NO_CANONICAL_SEAT,
            max_players: 2,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            protocol_pending_mask: 0,
            board_cards_commitment: [1; 32],
            deck_commitment: [2; 32],
            reveal_commitment: [3; 32],
            reconstruction_commitment: [4; 32],
            run_it_twice_commitment: [5; 32],
            rules_commitment: [6; 32],
            governance_commitment: [7; 32],
            settlement_commitment: [8; 32],
            custody_commitment: [9; 32],
            lifecycle_root: [10; 32],
            overlay_root: [11; 32],
            state_root: [12; 32],
            seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
        }
    }

    #[test]
    fn canonical_air_declares_the_maximum_expression_degree() {
        let mut evaluator = DegreeEvaluator { max: 0 };
        evaluator = CanonicalAir {
            log_size: 10,
            range: CanonicalRange8::dummy(),
        }
        .evaluate(evaluator);
        assert_eq!(evaluator.max, 3);
    }

    #[test]
    fn canonical_abi_v5_timeout_projection_is_fixed_width() {
        let image = image();
        let bytes = borsh::to_vec(&image).expect("canonical state image");
        assert_eq!(bytes.len(), CANONICAL_STATE_IMAGE_BORSH_BYTES);
        assert_eq!(
            u32::from_le_bytes(
                bytes[STATE_IMAGE_BETTING_TIMEOUT_OFFSET..STATE_IMAGE_BETTING_TIMEOUT_OFFSET + 4]
                    .try_into()
                    .expect("betting timeout bytes"),
            ),
            image.betting_timeout_ms,
        );
        assert_eq!(
            state_image_projection(&bytes)
                .expect("canonical endpoint projection")
                .len(),
            STATE_IMAGE_PROJECTION_LIMBS,
        );
        assert_eq!(STATE_IMAGE_PROJECTION_LIMBS, 853);
    }

    #[test]
    fn endpoint_projection_binds_every_canonical_state_image_byte() {
        // The endpoint scope uses 16-bit limbs where possible and individual
        // M31 values for byte-sized enum fields.  Mutating any byte must
        // therefore change at least one AIR-bound projection limb; otherwise
        // a companion byte-hash proof could authenticate data the transition
        // AIR never observes.
        let bytes = borsh::to_vec(&image()).expect("canonical state image");
        let baseline = state_image_projection(&bytes).expect("projection");
        for index in 0..CANONICAL_STATE_IMAGE_BORSH_BYTES {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert_ne!(
                state_image_projection(&changed).expect("same fixed width"),
                baseline,
                "state-image byte {index} is absent from the endpoint projection",
            );
        }
    }

    fn create_table() -> CanonicalTransitionWitness {
        let pre = image();
        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::CreateTable,
            actor: [1; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn advance_deadline() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.current_turn = 0;
        pre.deadline_ms = 1_000;
        pre.chip_pool = 100;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 100,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 40,
            identity_commitment: [41; 32],
            key_commitment: [42; 32],
            hole_cards_commitment: [43; 32],
        };
        let mut post = pre.clone();
        post.call_seq = 1;
        post.deadline_ms = 1_040;
        post.seats[0].time_bank_ms = 0;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::AdvanceDeadline,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 40,
                auxiliary: 1,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        witness.seal();
        witness
    }

    fn auto_fold() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.current_turn = 0;
        pre.deadline_ms = 1_000;
        pre.current_bet = 100;
        pre.min_raise = 100;
        pre.chip_pool = 1_600;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 1_000,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.seats[1] = active_opponent(false, 100);

        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.deadline_ms = 31_000;
        post.acted_mask = 1;
        post.seats[0].status = CanonicalSeatStatus::Folded;
        post.seats[0].acted = true;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::AutoFold,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        witness.seal();
        witness
    }

    fn start_hand() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.chip_pool = 1_000;
        pre.seats[0] = active_opponent(false, 0);
        pre.seats[1] = active_opponent(false, 0);
        let mut post = pre.clone();
        post.hand_id = 2;
        post.button = 1;
        post.phase = CanonicalPhase::Shuffling;
        post.phase_subtag = 1;
        post.deadline_ms = 100;
        post.protocol_pending_mask = 0b11;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::StartHand,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn join_table_at(
        pre: CanonicalStateImage,
        seat: u8,
        actor: [u8; 32],
        identity_commitment: [u8; 32],
        key_commitment: [u8; 32],
    ) -> CanonicalTransitionWitness {
        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        post.chip_pool = pre.chip_pool + 1;
        post.seats[usize::from(seat)] = CanonicalSeat {
            status: CanonicalSeatStatus::Waiting,
            acted: false,
            stack: 1,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment,
            key_commitment,
            hole_cards_commitment: [0; 32],
        };
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::JoinTable,
            actor,
            action: CanonicalActionPayload {
                seat,
                amount: 1,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn join_table() -> CanonicalTransitionWitness {
        join_table_at(image(), 0, [2; 32], [31; 32], [32; 32])
    }

    fn leave_table() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.chip_pool = 10;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Waiting,
            acted: false,
            stack: 7,
            bet: 0,
            total_bet: 0,
            pending_addon: 3,
            time_bank_ms: 0,
            identity_commitment: [31; 32],
            key_commitment: [32; 32],
            hole_cards_commitment: [0; 32],
        };
        let mut post = pre.clone();
        post.call_seq = 1;
        post.chip_pool = 0;
        post.seats[0] = CanonicalSeat::EMPTY;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::LeaveTable,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 10,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn active_opponent(acted: bool, bet: u64) -> CanonicalSeat {
        CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted,
            stack: 500,
            bet,
            total_bet: bet,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [41; 32],
            key_commitment: [42; 32],
            hole_cards_commitment: [43; 32],
        }
    }

    fn force_fold() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.current_turn = 0;
        pre.deadline_ms = 100;
        pre.chip_pool = 1_000;
        pre.seats[0] = active_opponent(false, 0);
        pre.seats[1] = active_opponent(false, 0);
        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.seats[0].status = CanonicalSeatStatus::Folded;
        post.seats[0].acted = true;
        post.acted_mask = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::ForceFold,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn kick_player() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.current_turn = 1;
        pre.deadline_ms = 100;
        pre.current_bet = 100;
        pre.chip_pool = 1_230;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 500,
            bet: 100,
            total_bet: 100,
            pending_addon: 30,
            time_bank_ms: 77,
            identity_commitment: [41; 32],
            key_commitment: [42; 32],
            hole_cards_commitment: [43; 32],
        };
        pre.seats[1] = active_opponent(false, 100);
        let mut post = pre.clone();
        post.call_seq = 1;
        post.pot = 100;
        post.chip_pool = 700;
        post.seats[0].status = CanonicalSeatStatus::Out;
        post.seats[0].stack = 0;
        post.seats[0].bet = 0;
        post.seats[0].pending_addon = 0;
        post.seats[0].key_commitment = [0; 32];
        post.seats[0].hole_cards_commitment = [0; 32];
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::KickPlayer,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 530,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn submit_shuffle() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Shuffling;
        pre.phase_subtag = 1;
        pre.deadline_ms = 100;
        pre.chip_pool = 200;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 100,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [51; 32],
            key_commitment: [52; 32],
            hole_cards_commitment: [0; 32],
        };
        pre.seats[1] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 100,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [61; 32],
            key_commitment: [62; 32],
            hole_cards_commitment: [0; 32],
        };
        pre.protocol_pending_mask = 0b11;
        let mut post = pre.clone();
        post.call_seq = 1;
        post.deck_commitment = [54; 32];
        post.protocol_pending_mask = 0b10;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::SubmitShuffle,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [53; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn shuffle_timeout() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Shuffling;
        pre.phase_subtag = 1;
        pre.street = 0;
        pre.current_turn = NO_CANONICAL_SEAT;
        pre.max_players = 3;
        pre.deadline_ms = 1_000;
        pre.chip_pool = 657;
        pre.pot = 40;
        pre.current_bet = 10;
        pre.protocol_pending_mask = 0b111;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 100,
            bet: 10,
            total_bet: 20,
            pending_addon: 7,
            time_bank_ms: 4_321,
            identity_commitment: [71; 32],
            key_commitment: [72; 32],
            hole_cards_commitment: [73; 32],
        };
        pre.seats[1] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 200,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 5_432,
            identity_commitment: [81; 32],
            key_commitment: [82; 32],
            hole_cards_commitment: [83; 32],
        };
        pre.seats[2] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 300,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 6_543,
            identity_commitment: [91; 32],
            key_commitment: [92; 32],
            hole_cards_commitment: [93; 32],
        };

        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        post.deadline_ms = 2_000 + u64::from(pre.shuffle_timeout_ms);
        post.chip_pool = pre.chip_pool - 107;
        post.pot = pre.pot + 10;
        post.protocol_pending_mask = 0b110;
        post.deck_commitment = [74; 32];
        post.seats[0].status = CanonicalSeatStatus::Out;
        post.seats[0].stack = 0;
        post.seats[0].bet = 0;
        post.seats[0].pending_addon = 0;
        post.seats[0].key_commitment = [0; 32];
        post.seats[0].hole_cards_commitment = [0; 32];
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::AdvanceDeadline,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 107,
                auxiliary: 2,
                flag: true,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 2_000,
        };
        witness.seal();
        witness
    }

    fn reconstruct_timeout_reset() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Reconstructing;
        pre.phase_subtag = CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG;
        pre.street = 2;
        pre.current_turn = NO_CANONICAL_SEAT;
        pre.deadline_ms = 1_000;
        pre.chip_pool = 300;
        pre.protocol_pending_mask = 0b01;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 100,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [101; 32],
            key_commitment: [102; 32],
            hole_cards_commitment: [103; 32],
        };
        pre.seats[1] = CanonicalSeat {
            status: CanonicalSeatStatus::Folded,
            acted: true,
            stack: 200,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [111; 32],
            key_commitment: [112; 32],
            hole_cards_commitment: [113; 32],
        };
        pre.acted_mask = 0b10;

        let mut post = pre.clone();
        post.call_seq = 1;
        post.phase = CanonicalPhase::Waiting;
        post.phase_subtag = 0;
        post.street = 0;
        post.current_turn = NO_CANONICAL_SEAT;
        post.deadline_ms = 0;
        post.chip_pool = 200;
        post.acted_mask = 0;
        post.leave_after_hand_mask = 0;
        post.protocol_pending_mask = 0;
        post.board_cards_commitment = [0; 32];
        post.deck_commitment = [121; 32];
        post.reveal_commitment = [0; 32];
        post.reconstruction_commitment = [0; 32];
        post.run_it_twice_commitment = [0; 32];
        post.seats[0] = CanonicalSeat::EMPTY;
        post.seats[1].status = CanonicalSeatStatus::Active;
        post.seats[1].acted = false;
        post.seats[1].hole_cards_commitment = [0; 32];

        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::ReconstructTimeoutReset,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 100,
                auxiliary: 0,
                flag: false,
                proof_commitment: [121; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        witness.seal();
        witness
    }

    fn reveal_timeout_reset() -> CanonicalTransitionWitness {
        let mut witness = reconstruct_timeout_reset();
        witness.pre.phase = CanonicalPhase::Revealing;
        witness.pre.phase_subtag = 1;
        witness.pre.street = 1;
        witness.kind = CanonicalTransitionKind::RevealTimeoutReset;
        witness.seal();
        witness
    }

    fn reveal_timeout_kick() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Revealing;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.current_turn = NO_CANONICAL_SEAT;
        pre.max_players = 3;
        pre.deadline_ms = 1_000;
        pre.chip_pool = 367;
        pre.pot = 25;
        pre.current_bet = 5;
        pre.min_raise = 5;
        pre.protocol_pending_mask = 0b111;
        for (index, seat) in pre.seats[..3].iter_mut().enumerate() {
            *seat = CanonicalSeat {
                status: CanonicalSeatStatus::Active,
                acted: false,
                stack: 100 + index as u64 * 10,
                bet: if index == 0 { 5 } else { 0 },
                total_bet: if index == 0 { 15 } else { 0 },
                pending_addon: if index == 0 { 7 } else { 0 },
                time_bank_ms: 30_000,
                identity_commitment: [31 + index as u8; 32],
                key_commitment: [41 + index as u8; 32],
                hole_cards_commitment: [51 + index as u8; 32],
            };
        }

        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        post.protocol_pending_mask = 0b110;
        post.pot = pre.pot + pre.seats[0].bet;
        post.chip_pool = pre.chip_pool - pre.seats[0].stack - pre.seats[0].pending_addon;
        post.reveal_commitment = [121; 32];
        post.seats[0].status = CanonicalSeatStatus::Out;
        post.seats[0].stack = 0;
        post.seats[0].bet = 0;
        post.seats[0].pending_addon = 0;
        post.seats[0].key_commitment = [0; 32];
        post.seats[0].hole_cards_commitment = [0; 32];

        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::RevealTimeoutKick,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 107,
                auxiliary: 0,
                flag: false,
                proof_commitment: [121; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        witness.seal();
        witness
    }

    fn reveal_timeout_kick_batch() -> Vec<CanonicalTransitionWitness> {
        let mut first = reveal_timeout_kick();
        first.pre.max_players = 4;
        first.pre.seats[3] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 130,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [61; 32],
            key_commitment: [62; 32],
            hole_cards_commitment: [63; 32],
        };
        first.post.max_players = 4;
        first.post.seats[3] = first.pre.seats[3];
        first.pre.chip_pool += 130;
        first.post.chip_pool += 130;
        first.seal();
        let mut second_pre = first.post.clone();
        let mut second_post = second_pre.clone();
        second_post.call_seq = second_pre.call_seq + 1;
        second_post.protocol_pending_mask = 0b100;
        second_post.chip_pool = second_pre.chip_pool - second_pre.seats[1].stack;
        second_post.reveal_commitment = [122; 32];
        second_post.seats[1].status = CanonicalSeatStatus::Out;
        second_post.seats[1].stack = 0;
        second_post.seats[1].key_commitment = [0; 32];
        second_post.seats[1].hole_cards_commitment = [0; 32];
        let mut second = CanonicalTransitionWitness {
            pre: std::mem::replace(&mut second_pre, first.post.clone()),
            post: second_post,
            kind: CanonicalTransitionKind::RevealTimeoutKick,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 1,
                amount: 110,
                auxiliary: 0,
                flag: false,
                proof_commitment: [122; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        second.seal();
        vec![first, second]
    }

    /// Four-player preflop timeout with three pending reveal participants.
    /// The first two removals remain in the reveal phase; the third invokes
    /// the VM's low-population reset continuation in the same tagged batch.
    fn reveal_timeout_kick_reset_batch() -> Vec<CanonicalTransitionWitness> {
        let mut pre = image();
        pre.phase = CanonicalPhase::Revealing;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.current_turn = NO_CANONICAL_SEAT;
        pre.max_players = 4;
        pre.deadline_ms = 1_000;
        pre.chip_pool = 400;
        pre.pot = 0;
        pre.current_bet = 0;
        pre.min_raise = 0;
        pre.protocol_pending_mask = 0b111;
        for (index, seat) in pre.seats[..4].iter_mut().enumerate() {
            *seat = CanonicalSeat {
                status: CanonicalSeatStatus::Active,
                acted: false,
                stack: 100,
                bet: 0,
                total_bet: 0,
                pending_addon: 0,
                time_bank_ms: 30_000,
                identity_commitment: [31 + index as u8; 32],
                key_commitment: [41 + index as u8; 32],
                hole_cards_commitment: [51 + index as u8; 32],
            };
        }

        let mut first_post = pre.clone();
        first_post.call_seq += 1;
        first_post.protocol_pending_mask = 0b110;
        first_post.chip_pool = 300;
        first_post.reveal_commitment = [121; 32];
        first_post.seats[0].status = CanonicalSeatStatus::Out;
        first_post.seats[0].stack = 0;
        first_post.seats[0].key_commitment = [0; 32];
        first_post.seats[0].hole_cards_commitment = [0; 32];
        let mut first = CanonicalTransitionWitness {
            pre,
            post: first_post,
            kind: CanonicalTransitionKind::RevealTimeoutKick,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 100,
                auxiliary: 0,
                flag: false,
                proof_commitment: [121; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        first.seal();

        let second_pre = first.post.clone();
        let mut second_post = second_pre.clone();
        second_post.call_seq += 1;
        second_post.protocol_pending_mask = 0b100;
        second_post.chip_pool = 200;
        second_post.reveal_commitment = [122; 32];
        second_post.seats[1].status = CanonicalSeatStatus::Out;
        second_post.seats[1].stack = 0;
        second_post.seats[1].key_commitment = [0; 32];
        second_post.seats[1].hole_cards_commitment = [0; 32];
        let mut second = CanonicalTransitionWitness {
            pre: second_pre,
            post: second_post,
            kind: CanonicalTransitionKind::RevealTimeoutKick,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 1,
                amount: 100,
                auxiliary: 0,
                flag: false,
                proof_commitment: [122; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        second.seal();

        let terminal_pre = second.post.clone();
        let mut terminal_post = terminal_pre.clone();
        terminal_post.call_seq += 1;
        terminal_post.phase = CanonicalPhase::Waiting;
        terminal_post.phase_subtag = 0;
        terminal_post.street = 0;
        terminal_post.current_turn = NO_CANONICAL_SEAT;
        terminal_post.deadline_ms = 0;
        terminal_post.current_bet = 0;
        terminal_post.min_raise = 0;
        terminal_post.pot = 0;
        terminal_post.chip_pool = 100;
        terminal_post.acted_mask = 0;
        terminal_post.leave_after_hand_mask = 0;
        terminal_post.protocol_pending_mask = 0;
        terminal_post.board_cards_commitment = [0; 32];
        terminal_post.reveal_commitment = [0; 32];
        terminal_post.reconstruction_commitment = [0; 32];
        terminal_post.run_it_twice_commitment = [0; 32];
        terminal_post.seats[2] = CanonicalSeat::EMPTY;
        terminal_post.seats[3].acted = false;
        terminal_post.seats[3].hole_cards_commitment = [0; 32];
        let mut terminal = CanonicalTransitionWitness {
            pre: terminal_pre,
            post: terminal_post.clone(),
            kind: CanonicalTransitionKind::RevealTimeoutReset,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 2,
                amount: 100,
                auxiliary: 0,
                flag: false,
                proof_commitment: terminal_post.deck_commitment,
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        terminal.seal();
        vec![first, second, terminal]
    }

    /// Two pending seats with a non-contiguous union. The deterministic VM
    /// schedule is `0`, then `2`, followed by the typed reset continuation.
    fn reveal_timeout_kick_reset_two_pending_batch() -> Vec<CanonicalTransitionWitness> {
        let mut full = reveal_timeout_kick_reset_batch();
        let mut first = full.remove(0);
        let _second = full.remove(0);
        let mut terminal = full.remove(0);

        first.pre.protocol_pending_mask = 0b101;
        first.post.protocol_pending_mask = 0b100;
        first.seal();

        terminal.pre = first.post.clone();
        terminal.post = terminal.pre.clone();
        terminal.post.call_seq += 1;
        terminal.post.phase = CanonicalPhase::Waiting;
        terminal.post.phase_subtag = 0;
        terminal.post.street = 0;
        terminal.post.current_turn = NO_CANONICAL_SEAT;
        terminal.post.deadline_ms = 0;
        terminal.post.current_bet = 0;
        terminal.post.min_raise = 0;
        terminal.post.pot = 0;
        terminal.post.chip_pool = 200;
        terminal.post.acted_mask = 0;
        terminal.post.leave_after_hand_mask = 0;
        terminal.post.protocol_pending_mask = 0;
        terminal.post.board_cards_commitment = [0; 32];
        terminal.post.reveal_commitment = [0; 32];
        terminal.post.reconstruction_commitment = [0; 32];
        terminal.post.run_it_twice_commitment = [0; 32];
        terminal.post.seats[1].acted = false;
        terminal.post.seats[1].hole_cards_commitment = [0; 32];
        terminal.post.seats[2] = CanonicalSeat::EMPTY;
        terminal.post.seats[3].acted = false;
        terminal.post.seats[3].hole_cards_commitment = [0; 32];
        terminal.action.seat = 2;
        terminal.action.amount = 100;
        terminal.action.proof_commitment = terminal.post.deck_commitment;
        terminal.seal();
        vec![first, terminal]
    }

    /// A standalone non-preflop reveal-timeout terminal: the final pending
    /// seat is kicked and the table enters reconstruct collection.
    fn reveal_timeout_reconstruct() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Revealing;
        pre.phase_subtag = 3;
        pre.street = 3;
        pre.current_turn = NO_CANONICAL_SEAT;
        pre.max_players = 4;
        pre.deadline_ms = 1_000;
        pre.current_bet = 30;
        pre.min_raise = 20;
        pre.chip_pool = 525;
        pre.pot = 40;
        pre.protocol_pending_mask = 0b10;
        for (index, seat) in pre.seats[..4].iter_mut().enumerate() {
            *seat = CanonicalSeat {
                status: CanonicalSeatStatus::Active,
                acted: index != 1,
                stack: 100 + index as u64 * 10,
                bet: if index == 1 { 20 } else { 0 },
                total_bet: if index == 1 { 35 } else { 30 },
                pending_addon: if index == 1 { 5 } else { 0 },
                time_bank_ms: 30_000,
                identity_commitment: [31 + index as u8; 32],
                key_commitment: [41 + index as u8; 32],
                hole_cards_commitment: [51 + index as u8; 32],
            };
        }
        pre.acted_mask = 0b1101;
        pre.leave_after_hand_mask = 0b1000;

        let mut post = pre.clone();
        post.call_seq += 1;
        post.phase = CanonicalPhase::Reconstructing;
        post.phase_subtag = CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG;
        post.deadline_ms = 11_000;
        post.pot = pre.pot + pre.seats[1].bet;
        post.chip_pool = pre.chip_pool - (pre.seats[1].stack + pre.seats[1].pending_addon);
        post.acted_mask = pre.acted_mask & !0b10;
        post.leave_after_hand_mask = pre.leave_after_hand_mask & !0b10;
        post.protocol_pending_mask = 0b1101;
        post.reconstruction_commitment = [77; 32];
        post.seats[1].status = CanonicalSeatStatus::Out;
        post.seats[1].stack = 0;
        post.seats[1].bet = 0;
        post.seats[1].pending_addon = 0;
        post.seats[1].key_commitment = [0; 32];
        post.seats[1].hole_cards_commitment = [0; 32];

        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::RevealTimeoutReconstruct,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 1,
                amount: 115,
                auxiliary: 0,
                flag: false,
                proof_commitment: [77; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        witness.seal();
        witness
    }

    /// A full non-preflop cascade: kick seat 0, then the typed reconstruct
    /// terminal kicks seat 1 and enters reconstruction.
    fn reveal_timeout_kick_reconstruct_batch() -> Vec<CanonicalTransitionWitness> {
        let mut first = reveal_timeout_kick();
        first.pre.max_players = 4;
        first.pre.phase_subtag = 3;
        first.pre.street = 3;
        first.pre.chip_pool = 537;
        first.pre.pot = 40;
        first.pre.current_bet = 30;
        first.pre.min_raise = 20;
        first.pre.protocol_pending_mask = 0b011;
        first.pre.seats[3] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 130,
            bet: 0,
            total_bet: 30,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [34; 32],
            key_commitment: [44; 32],
            hole_cards_commitment: [54; 32],
        };
        first.pre.seats[1].bet = 20;
        first.pre.seats[1].total_bet = 35;
        first.pre.seats[1].pending_addon = 5;
        first.post = first.pre.clone();
        first.post.call_seq += 1;
        first.post.protocol_pending_mask = 0b10;
        first.post.chip_pool =
            first.pre.chip_pool - (first.pre.seats[0].stack + first.pre.seats[0].pending_addon);
        first.post.pot = first.pre.pot + first.pre.seats[0].bet;
        first.post.reveal_commitment = [121; 32];
        first.post.seats[0].status = CanonicalSeatStatus::Out;
        first.post.seats[0].stack = 0;
        first.post.seats[0].bet = 0;
        first.post.seats[0].pending_addon = 0;
        first.post.seats[0].key_commitment = [0; 32];
        first.post.seats[0].hole_cards_commitment = [0; 32];
        first.seal();

        let mut terminal = reveal_timeout_reconstruct();
        terminal.pre = first.post.clone();
        terminal.post = terminal.pre.clone();
        terminal.post.call_seq += 1;
        terminal.post.phase = CanonicalPhase::Reconstructing;
        terminal.post.phase_subtag = CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG;
        terminal.post.deadline_ms = 11_000;
        terminal.post.pot = terminal.pre.pot + terminal.pre.seats[1].bet;
        terminal.post.chip_pool = terminal.pre.chip_pool
            - (terminal.pre.seats[1].stack + terminal.pre.seats[1].pending_addon);
        terminal.post.acted_mask = terminal.pre.acted_mask & !0b10;
        terminal.post.leave_after_hand_mask = terminal.pre.leave_after_hand_mask & !0b10;
        terminal.post.protocol_pending_mask = 0b1100;
        terminal.post.reconstruction_commitment = [77; 32];
        terminal.post.seats[1].status = CanonicalSeatStatus::Out;
        terminal.post.seats[1].stack = 0;
        terminal.post.seats[1].bet = 0;
        terminal.post.seats[1].pending_addon = 0;
        terminal.post.seats[1].key_commitment = [0; 32];
        terminal.post.seats[1].hole_cards_commitment = [0; 32];
        terminal.action.amount = 115;
        terminal.deadline_height = 1_000;
        terminal.seal();
        vec![first, terminal]
    }

    /// A standalone sole-survivor reveal-timeout terminal: the final pending
    /// seat is kicked and the complete pot is awarded to the survivor.
    fn reveal_timeout_award() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Revealing;
        pre.phase_subtag = 3;
        pre.street = 3;
        pre.current_turn = NO_CANONICAL_SEAT;
        pre.max_players = 4;
        pre.deadline_ms = 1_000;
        pre.chip_pool = 405;
        pre.pot = 90;
        pre.acted_mask = 0b001;
        pre.protocol_pending_mask = 0b010;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Folded,
            acted: true,
            stack: 80,
            bet: 0,
            total_bet: 30,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [31; 32],
            key_commitment: [41; 32],
            hole_cards_commitment: [51; 32],
        };
        pre.seats[1] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 110,
            bet: 0,
            total_bet: 35,
            pending_addon: 5,
            time_bank_ms: 30_000,
            identity_commitment: [32; 32],
            key_commitment: [42; 32],
            hole_cards_commitment: [52; 32],
        };
        pre.seats[2] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 120,
            bet: 0,
            total_bet: 25,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [33; 32],
            key_commitment: [43; 32],
            hole_cards_commitment: [53; 32],
        };

        let mut post = pre.clone();
        post.call_seq += 1;
        post.phase = CanonicalPhase::Waiting;
        post.phase_subtag = 0;
        post.street = 0;
        post.current_turn = NO_CANONICAL_SEAT;
        post.deadline_ms = 0;
        post.current_bet = 0;
        post.min_raise = 0;
        post.pot = 0;
        post.acted_mask = 0;
        post.protocol_pending_mask = 0;
        post.chip_pool = pre.chip_pool - (pre.seats[1].stack + pre.seats[1].pending_addon);
        post.deck_commitment = [121; 32];
        post.board_cards_commitment = [0; 32];
        post.reveal_commitment = [0; 32];
        post.reconstruction_commitment = [0; 32];
        post.run_it_twice_commitment = [0; 32];
        post.seats[0].status = CanonicalSeatStatus::Active;
        post.seats[0].acted = false;
        post.seats[0].total_bet = 0;
        post.seats[0].hole_cards_commitment = [0; 32];
        post.seats[1] = CanonicalSeat::EMPTY;
        post.seats[2].stack += pre.pot;
        post.seats[2].total_bet = 0;
        post.seats[2].hole_cards_commitment = [0; 32];

        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::RevealTimeoutAward,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 1,
                amount: 115,
                auxiliary: 0,
                flag: false,
                proof_commitment: [121; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        witness.seal();
        witness
    }

    /// A full sole-survivor cascade: kick seat 0, then the typed award
    /// terminal kicks seat 1 and pays the complete pot to seat 2.
    /// Table rules with a live percentage rake, used by the raked fixtures.
    fn raked_table_rules() -> poker_l1::contracts::texas_poker::types::TableRules {
        poker_l1::contracts::texas_poker::types::TableRules {
            max_players: 4,
            small_blind: 25,
            big_blind: 50,
            timeout_config: Default::default(),
            ante_mode: 0,
            ante_amount: 0,
            rake_mode: 1,
            rake_bps: 500,
            rake_cap: 1_000,
            rit_mode: 0,
        }
    }

    /// A standalone raked sole-survivor terminal derived from the zero-rake
    /// fixture: 5% of the 90-chip pot rakes 4, so seat 2 is credited 86.
    fn reveal_timeout_raked_award() -> CanonicalTransitionWitness {
        let mut witness = reveal_timeout_award();
        let rules = raked_table_rules();
        let opening = crate::canonical_rake_opening::rake_opening_of(&rules);
        let rake = crate::canonical_rake_opening::canonical_settlement_rake(90, &opening);
        assert_eq!(rake, 4);
        witness.kind = CanonicalTransitionKind::RevealTimeoutRakedAward;
        witness.rake_opening = opening;
        witness.pre.rules_commitment =
            crate::canonical_rake_opening::canonical_rules_commitment(&rules).unwrap();
        witness.post.rules_commitment = witness.pre.rules_commitment;
        witness.post.seats[2].stack -= rake;
        witness.post.chip_pool -= rake;
        witness.seal();
        witness
    }

    /// TE-E0: table rules carrying the frozen `FIXED_RAKE_BURN` (2) mode.
    /// The charging relation (bps/cap) is identical to [`raked_table_rules`];
    /// the burn fund disposal is contract-side (poker_l1, TE-M4) and is not
    /// modelled in the canonical relation or the AIR.
    fn burn_table_rules() -> poker_l1::contracts::texas_poker::types::TableRules {
        let mut rules = raked_table_rules();
        rules.rake_mode =
            crate::canonical_rake_opening::CanonicalRakeOpening::FIXED_RAKE_BURN_MODE;
        rules
    }

    /// TE-E0: a burn-mode raked sole-survivor terminal — same charging
    /// arithmetic as [`reveal_timeout_raked_award`], mode discriminator 2.
    fn reveal_timeout_burn_award() -> CanonicalTransitionWitness {
        let mut witness = reveal_timeout_award();
        let rules = burn_table_rules();
        let opening = crate::canonical_rake_opening::rake_opening_of(&rules);
        let rake = crate::canonical_rake_opening::canonical_settlement_rake(90, &opening);
        assert_eq!(rake, 4);
        assert_eq!(opening.rake_mode, 2);
        witness.kind = CanonicalTransitionKind::RevealTimeoutRakedAward;
        witness.rake_opening = opening;
        witness.pre.rules_commitment =
            crate::canonical_rake_opening::canonical_rules_commitment(&rules).unwrap();
        witness.post.rules_commitment = witness.pre.rules_commitment;
        witness.post.seats[2].stack -= rake;
        witness.post.chip_pool -= rake;
        witness.seal();
        witness
    }

    /// A raked cascade: kick seat 0, then the raked award terminal kicks
    /// seat 1 and pays `pot - rake` to seat 2.
    fn reveal_timeout_kick_raked_award_batch() -> Vec<CanonicalTransitionWitness> {
        let mut batch = reveal_timeout_kick_award_batch();
        let rules = raked_table_rules();
        let opening = crate::canonical_rake_opening::rake_opening_of(&rules);
        let rake = crate::canonical_rake_opening::canonical_settlement_rake(90, &opening);
        let commitment = crate::canonical_rake_opening::canonical_rules_commitment(&rules).unwrap();
        batch[0].pre.rules_commitment = commitment;
        batch[0].post.rules_commitment = commitment;
        batch[0].seal();
        let terminal = &mut batch[1];
        terminal.pre.rules_commitment = commitment;
        terminal.post.rules_commitment = commitment;
        terminal.kind = CanonicalTransitionKind::RevealTimeoutRakedAward;
        terminal.rake_opening = opening;
        terminal.post.seats[2].stack -= rake;
        terminal.post.chip_pool -= rake;
        terminal.seal();
        batch
    }

    fn reveal_timeout_kick_award_batch() -> Vec<CanonicalTransitionWitness> {
        let mut first = reveal_timeout_kick();
        first.pre.max_players = 4;
        first.pre.phase_subtag = 3;
        first.pre.street = 3;
        first.pre.chip_pool = 427;
        first.pre.pot = 90;
        first.pre.current_bet = 0;
        first.pre.min_raise = 0;
        first.pre.seats[0].bet = 0;
        first.pre.protocol_pending_mask = 0b011;
        first.pre.seats[3] = CanonicalSeat::EMPTY;
        first.post = first.pre.clone();
        first.post.call_seq += 1;
        first.post.protocol_pending_mask = 0b010;
        first.post.chip_pool =
            first.pre.chip_pool - (first.pre.seats[0].stack + first.pre.seats[0].pending_addon);
        first.post.pot = first.pre.pot + first.pre.seats[0].bet;
        first.post.reveal_commitment = [121; 32];
        first.post.seats[0].status = CanonicalSeatStatus::Out;
        first.post.seats[0].stack = 0;
        first.post.seats[0].bet = 0;
        first.post.seats[0].pending_addon = 0;
        first.post.seats[0].key_commitment = [0; 32];
        first.post.seats[0].hole_cards_commitment = [0; 32];
        first.seal();

        let mut terminal = reveal_timeout_award();
        terminal.pre = first.post.clone();
        terminal.post = terminal.pre.clone();
        terminal.post.call_seq += 1;
        terminal.post.phase = CanonicalPhase::Waiting;
        terminal.post.phase_subtag = 0;
        terminal.post.street = 0;
        terminal.post.current_turn = NO_CANONICAL_SEAT;
        terminal.post.deadline_ms = 0;
        terminal.post.current_bet = 0;
        terminal.post.min_raise = 0;
        terminal.post.pot = 0;
        terminal.post.acted_mask = 0;
        terminal.post.protocol_pending_mask = 0;
        terminal.post.chip_pool = terminal.pre.chip_pool
            - (terminal.pre.seats[1].stack + terminal.pre.seats[1].pending_addon);
        terminal.post.deck_commitment = [121; 32];
        terminal.post.board_cards_commitment = [0; 32];
        terminal.post.reveal_commitment = [0; 32];
        terminal.post.reconstruction_commitment = [0; 32];
        terminal.post.run_it_twice_commitment = [0; 32];
        terminal.post.seats[0] = CanonicalSeat::EMPTY;
        terminal.post.seats[1] = CanonicalSeat::EMPTY;
        terminal.post.seats[2].stack += terminal.pre.pot;
        terminal.post.seats[2].total_bet = 0;
        terminal.post.seats[2].hole_cards_commitment = [0; 32];
        terminal.action.amount = terminal.pre.seats[1].stack + terminal.pre.seats[1].pending_addon;
        terminal.deadline_height = 1_000;
        terminal.seal();
        vec![first, terminal]
    }

    /// #22②：ShuffleComplete 正例 fixture——最后一位贡献者的 shuffle 提交，
    /// 完成 opening 镜像 start_preflop_reveal_phase 的规范化语义。
    fn submit_shuffle_completion() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Shuffling;
        pre.phase_subtag = 1;
        pre.street = 0;
        pre.deadline_ms = 5_000;
        pre.chip_pool = 200;
        pre.reveal_timeout_ms = 3_000;
        pre.protocol_pending_mask = 0b01;
        for (index, seat) in pre.seats[..2].iter_mut().enumerate() {
            *seat = CanonicalSeat {
                status: CanonicalSeatStatus::Active,
                acted: false,
                stack: 100,
                bet: 0,
                total_bet: 0,
                pending_addon: 0,
                time_bank_ms: 0,
                identity_commitment: [70 + index as u8; 32],
                key_commitment: [71 + index as u8; 32],
                hole_cards_commitment: [72 + index as u8; 32],
            };
        }
        let timestamp = 9_000;
        let mut post = pre.clone();
        post.call_seq = 1;
        post.phase = CanonicalPhase::Revealing;
        post.deadline_ms = timestamp + u64::from(pre.reveal_timeout_ms);
        post.protocol_pending_mask = 0b11;
        // 完成提交轮转 deck（最后贡献者的输出即终局 deck）。
        post.deck_commitment = [50; 32];
        let reconstruction = pre.reconstruction_commitment;
        let pre_deck = pre.deck_commitment;
        let post_deck = post.deck_commitment;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::SubmitShuffle,
            actor: [80; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [81; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: crate::texas_canonical::CanonicalProtocolCompletionOpening {
                kind: CanonicalProtocolCompletionKind::Shuffle,
                completion_timestamp_ms: timestamp,
                pre_cards_dealt: 0,
                post_cards_dealt: 4,
                suspended_reveal_commitment: [0; 32],
                post_shuffle_pending_mask: 0b11,
                post_shuffle_completed_mask: 0b11,
                pre_deck_commitment: pre_deck,
                post_deck_commitment: post_deck,
                pre_reconstruction_commitment: reconstruction,
                post_reconstruction_commitment: reconstruction,
                ..Default::default()
            },
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    /// #22②：RevealComplete 正例规则（盲注 50/100、无 ante、无抽水）。
    fn blind_table_rules() -> poker_l1::contracts::texas_poker::types::TableRules {
        poker_l1::contracts::texas_poker::types::TableRules {
            max_players: 3,
            small_blind: 50,
            big_blind: 100,
            timeout_config: Default::default(),
            ante_mode: 0,
            ante_amount: 0,
            rake_mode: 0,
            rake_bps: 0,
            rake_cap: 0,
            rit_mode: 0,
        }
    }

    /// #22②：heads-up RevealComplete 正例 fixture——最后一份 reveal token
    /// 入账，post_blinds + start_betting_round(preflop) 的规范化语义。
    fn submit_reveal_completion() -> CanonicalTransitionWitness {
        let rules = blind_table_rules();
        let mut pre = image();
        pre.phase = CanonicalPhase::Revealing;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.deadline_ms = 5_000;
        pre.button = 0;
        pre.max_players = 2;
        pre.protocol_pending_mask = 0b01;
        pre.rules_commitment =
            crate::canonical_rake_opening::canonical_rules_commitment(&rules).unwrap();
        pre.chip_pool = 2_000;
        for (index, seat) in pre.seats[..2].iter_mut().enumerate() {
            *seat = CanonicalSeat {
                status: CanonicalSeatStatus::Active,
                acted: false,
                stack: 1_000,
                bet: 0,
                total_bet: 0,
                pending_addon: 0,
                time_bank_ms: 0,
                identity_commitment: [20 + index as u8; 32],
                key_commitment: [30 + index as u8; 32],
                hole_cards_commitment: [40 + index as u8; 32],
            };
        }
        let timestamp = 9_000;
        let mut post = pre.clone();
        post.call_seq = 1;
        post.phase = CanonicalPhase::Betting;
        post.deadline_ms = timestamp + u64::from(pre.betting_timeout_ms);
        post.protocol_pending_mask = 0;
        post.reveal_commitment = [0x33; 32];
        // 单挑：SB = BB（座 1）之外另一参与者（座 0）先行动；BB = 座 1。
        post.current_turn = 0;
        post.current_bet = 100;
        post.min_raise = 100;
        // dead button 盲注轨道：本手大盲座位成为下一手轮转基准。
        post.last_bb_seat = 1;
        post.seats[0].stack = 950;
        post.seats[0].bet = 50;
        post.seats[0].total_bet = 50;
        post.seats[1].stack = 900;
        post.seats[1].bet = 100;
        post.seats[1].total_bet = 100;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::SubmitReveal,
            actor: [80; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [81; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: crate::texas_canonical::CanonicalProtocolCompletionOpening {
                kind: CanonicalProtocolCompletionKind::Reveal,
                completion_timestamp_ms: timestamp,
                post_current_turn: 0,
                sb_seat: 0,
                bb_seat: 1,
                sb_amount: 50,
                bb_amount: 100,
                is_heads_up: true,
                pre_reveal_commitment: [3; 32],
                post_reveal_commitment: [0x33; 32],
                pre_deck_commitment: [2; 32],
                post_deck_commitment: [2; 32],
                pre_reconstruction_commitment: [4; 32],
                post_reconstruction_commitment: [4; 32],
                ..Default::default()
            },
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening {
                small_blind: 50,
                big_blind: 100,
                ante_mode: 0,
                ante_amount: 0,
            },
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    /// 三人局 RevealComplete 正例：button=1 → SB=2、BB=0、UTG=1（BB 后
    /// 首个 Active），覆盖非单挑的位置规则分支。
    fn submit_reveal_completion_three_way() -> CanonicalTransitionWitness {
        let mut witness = submit_reveal_completion();
        witness.pre.max_players = 3;
        witness.pre.button = 1;
        witness.pre.protocol_pending_mask = 0b100;
        witness.pre.chip_pool = 3_000;
        witness.pre.seats[2] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 1_000,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [22; 32],
            key_commitment: [32; 32],
            hole_cards_commitment: [42; 32],
        };
        witness.action.seat = 2;
        witness.post = witness.pre.clone();
        witness.post.call_seq = 1;
        witness.post.phase = CanonicalPhase::Betting;
        witness.post.deadline_ms = 9_000 + u64::from(witness.pre.betting_timeout_ms);
        witness.post.protocol_pending_mask = 0;
        witness.post.reveal_commitment = [0x33; 32];
        witness.post.current_turn = 0;
        witness.post.current_bet = 100;
        witness.post.min_raise = 100;
        // dead button 首手（last_bb == NO）：轮转基准 = button(座1)，
        // BB = 座2（出 100），SB = 基座座位本身 = 座1（出 50），UTG = 座0。
        witness.post.last_bb_seat = 2;
        witness.post.seats[0].stack = 1_000;
        witness.post.seats[0].bet = 0;
        witness.post.seats[0].total_bet = 0;
        witness.post.seats[1].stack = 950;
        witness.post.seats[1].bet = 50;
        witness.post.seats[1].total_bet = 50;
        witness.post.seats[2].stack = 900;
        witness.post.seats[2].bet = 100;
        witness.post.seats[2].total_bet = 100;
        witness.protocol_completion.post_current_turn = 0;
        witness.protocol_completion.sb_seat = 1;
        witness.protocol_completion.bb_seat = 2;
        witness.protocol_completion.is_heads_up = false;
        witness.seal();
        witness
    }

    fn submit_reconstruct_completion() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Reconstructing;
        pre.phase_subtag = CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG;
        pre.street = 2;
        pre.deadline_ms = 5_000;
        pre.chip_pool = 200;
        pre.protocol_pending_mask = 0b01;
        for (index, seat) in pre.seats[..2].iter_mut().enumerate() {
            *seat = CanonicalSeat {
                status: CanonicalSeatStatus::Active,
                acted: false,
                stack: 100,
                bet: 0,
                total_bet: 0,
                pending_addon: 0,
                time_bank_ms: 0,
                identity_commitment: [20 + index as u8; 32],
                key_commitment: [30 + index as u8; 32],
                hole_cards_commitment: [40 + index as u8; 32],
            };
        }
        let timestamp = 8_000;
        let mut post = pre.clone();
        post.call_seq = 1;
        post.phase = CanonicalPhase::Shuffling;
        post.phase_subtag = CANONICAL_SHUFFLE_RECONSTRUCT_SUBTAG;
        post.deadline_ms = timestamp + u64::from(pre.shuffle_timeout_ms);
        post.protocol_pending_mask = 0b11;
        post.deck_commitment = [50; 32];
        post.reconstruction_commitment = [51; 32];
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::SubmitReconstruct,
            actor: [60; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [61; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: crate::texas_canonical::CanonicalProtocolCompletionOpening {
                kind: CanonicalProtocolCompletionKind::Reconstruct,
                completion_timestamp_ms: timestamp,
                pre_cards_dealt: 7,
                post_cards_dealt: 0,
                suspended_reveal_commitment: [3; 32],
                post_shuffle_pending_mask: 0b11,
                post_shuffle_completed_mask: 0,
                pre_deck_commitment: [2; 32],
                post_deck_commitment: [50; 32],
                pre_reconstruction_commitment: [4; 32],
                post_reconstruction_commitment: [51; 32],
                ..Default::default()
            },
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn submit_reconstruct_nonfinal() -> CanonicalTransitionWitness {
        let mut witness = submit_reconstruct_completion();
        witness.pre.protocol_pending_mask = 0b11;
        witness.post = witness.pre.clone();
        witness.post.call_seq = witness.pre.call_seq + 1;
        witness.post.protocol_pending_mask = 0b10;
        witness.post.reconstruction_commitment = [51; 32];
        witness.protocol_completion = Default::default();
        witness.seal();
        witness
    }

    fn fold_with_proof() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.deadline_ms = 100;
        pre.current_turn = 0;
        pre.current_bet = 100;
        pre.min_raise = 100;
        pre.chip_pool = 1_600;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 1_000,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.seats[1] = active_opponent(false, 100);

        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.acted_mask = 1;
        post.seats[0].status = CanonicalSeatStatus::Folded;
        post.seats[0].acted = true;
        // In the VM this is the commitment to the ciphertext deck with the
        // actor's ElGamal layer removed by the leave DLEQ relation.
        post.deck_commitment = [0x55; 32];
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::FoldWithProof,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0x77; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn set_leave_after_hand() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Waiting,
            acted: false,
            stack: 0,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [31; 32],
            key_commitment: [32; 32],
            hole_cards_commitment: [0; 32],
        };
        let mut post = pre.clone();
        post.call_seq = 1;
        post.leave_after_hand_mask = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::SetLeaveAfterHand,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: true,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn call() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.deadline_ms = 100;
        pre.current_turn = 0;
        pre.current_bet = 100;
        pre.min_raise = 100;
        pre.chip_pool = 1_600;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 1_000,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.seats[1] = active_opponent(false, 100);
        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.seats[0].acted = true;
        post.seats[0].stack = 900;
        post.seats[0].bet = 100;
        post.seats[0].total_bet = 100;
        post.acted_mask = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::Call,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 100,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn short_all_in_call() -> CanonicalTransitionWitness {
        let mut witness = call();
        witness.pre.seats[0].stack = 50;
        witness.pre.chip_pool = 650;
        witness.post.chip_pool = 650;
        witness.post.seats[0].status = CanonicalSeatStatus::AllIn;
        witness.post.seats[0].stack = 0;
        witness.post.seats[0].bet = 50;
        witness.post.seats[0].total_bet = 50;
        witness.action.amount = 50;
        witness.seal();
        witness
    }

    fn bet() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 2;
        pre.deadline_ms = 100;
        pre.current_turn = 0;
        pre.min_raise = 100;
        pre.chip_pool = 1_500;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 1_000,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.seats[1] = active_opponent(false, 0);
        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.current_bet = 100;
        post.min_raise = 100;
        post.seats[0].acted = true;
        post.seats[0].stack = 900;
        post.seats[0].bet = 100;
        post.seats[0].total_bet = 100;
        post.acted_mask = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::Bet,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 100,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn funding(kind: CanonicalTransitionKind) -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Waiting,
            acted: false,
            stack: 100,
            bet: 0,
            total_bet: 0,
            pending_addon: 10,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.chip_pool = 110;
        let mut post = pre.clone();
        post.call_seq = 1;
        post.chip_pool = 160;
        match kind {
            CanonicalTransitionKind::Addon => post.seats[0].pending_addon = 60,
            CanonicalTransitionKind::Rebuy => post.seats[0].stack = 150,
            _ => unreachable!("funding fixture needs addon or rebuy"),
        }
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 50,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn raise() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 2;
        pre.deadline_ms = 100;
        pre.current_turn = 0;
        pre.current_bet = 100;
        pre.min_raise = 100;
        pre.pot = 250;
        pre.chip_pool = 1_850;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 950,
            bet: 50,
            total_bet: 50,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.seats[1] = active_opponent(true, 100);
        pre.acted_mask = 1 << 1;
        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.current_bet = 200;
        post.seats[0].acted = true;
        post.seats[0].stack = 800;
        post.seats[0].bet = 200;
        post.seats[0].total_bet = 200;
        post.seats[1].acted = false;
        post.acted_mask = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::Raise,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 200,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn short_all_in_raise() -> CanonicalTransitionWitness {
        let mut witness = raise();
        witness.pre.seats[0].stack = 125;
        witness.pre.chip_pool = 1_025;
        witness.post.chip_pool = 1_025;
        witness.post.seats[0].status = CanonicalSeatStatus::AllIn;
        witness.post.current_bet = 175;
        witness.post.min_raise = 100;
        witness.post.seats[0].stack = 0;
        witness.post.seats[0].bet = 175;
        witness.post.seats[0].total_bet = 175;
        witness.action.amount = 175;
        // 不足最小加注的 all-in 不重新打开行动权：对手的 acted 位保持。
        witness.post.seats[1].acted = true;
        witness.post.acted_mask = 0b11;
        witness.seal();
        witness
    }

    fn raise_against_acted_opponent() -> CanonicalTransitionWitness {
        let mut witness = raise();
        let opponent = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: true,
            stack: 500,
            bet: 100,
            total_bet: 100,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [41; 32],
            key_commitment: [42; 32],
            hole_cards_commitment: [43; 32],
        };
        witness.pre.seats[1] = opponent;
        witness.post.seats[1] = opponent;
        witness.post.seats[1].acted = false;
        witness.pre.acted_mask = 1 << 1;
        // VM `RaiseTo` resets every other actionable player's acted bit.
        witness.post.acted_mask = 1;
        witness.pre.chip_pool = 1_850;
        witness.post.chip_pool = 1_850;
        witness.seal();
        witness
    }

    fn advance_round() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 2;
        pre.current_turn = NO_CANONICAL_SEAT;
        pre.deadline_ms = 100;
        pre.current_bet = 100;
        pre.min_raise = 100;
        pre.pot = 50;
        pre.seats[0] = active_opponent(true, 100);
        pre.seats[1] = active_opponent(true, 100);
        pre.acted_mask = 0b11;
        pre.chip_pool = 1_250;

        let mut post = pre.clone();
        post.call_seq = 1;
        post.phase = CanonicalPhase::Revealing;
        post.phase_subtag = 2;
        post.street = 3;
        post.deadline_ms = 200;
        post.protocol_pending_mask = 0b11;
        post.current_bet = 0;
        post.min_raise = 0;
        post.pot = 250;
        for seat in &mut post.seats {
            seat.bet = 0;
        }

        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::AdvanceRound,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening {
                // VM flop -> turn: seven encrypted cards have been consumed
                // (four hole cards and the flop); allocate one board card.
                pre_cards_dealt: 7,
                post_cards_dealt: 8,
                pre_board_len: 3,
                post_board_len: 3,
                pre_second_board_len: 0,
                post_second_board_len: 0,
                run_it_twice: false,
                reveal_purpose: 2,
                assignment_count: 1,
                assignments: [
                    CanonicalBoardRevealAssignment {
                        present: true,
                        encrypted_card_index: 7,
                        runout_index: 0,
                        board_position: 3,
                        pending_mask: 0b11,
                        submitted_mask: 0,
                    },
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                ],
            },
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn terminal_reset_images() -> (CanonicalStateImage, CanonicalStateImage) {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.current_turn = NO_CANONICAL_SEAT;
        pre.deadline_ms = 100;
        pre.chip_pool = 200;
        pre.pot = 15;
        pre.current_bet = 25;
        pre.min_raise = 25;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 100,
            bet: 25,
            total_bet: 25,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [41; 32],
            key_commitment: [42; 32],
            hole_cards_commitment: [43; 32],
        };
        pre.seats[1] = CanonicalSeat {
            status: CanonicalSeatStatus::Folded,
            acted: true,
            stack: 50,
            bet: 10,
            total_bet: 10,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [44; 32],
            key_commitment: [45; 32],
            hole_cards_commitment: [46; 32],
        };
        pre.acted_mask = 0b10;

        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        post.phase = CanonicalPhase::Waiting;
        post.phase_subtag = 0;
        post.street = 0;
        post.current_turn = NO_CANONICAL_SEAT;
        post.deadline_ms = 0;
        post.current_bet = 0;
        post.min_raise = 0;
        post.pot = 0;
        post.acted_mask = 0;
        post.deck_commitment = [77; 32];
        post.board_cards_commitment = [0; 32];
        post.reveal_commitment = [0; 32];
        post.reconstruction_commitment = [0; 32];
        post.run_it_twice_commitment = [0; 32];
        post.seats[0].stack = 150;
        post.seats[0].status = CanonicalSeatStatus::Active;
        post.seats[0].acted = false;
        post.seats[0].bet = 0;
        post.seats[0].total_bet = 0;
        post.seats[0].hole_cards_commitment = [0; 32];
        post.seats[1].status = CanonicalSeatStatus::Active;
        post.seats[1].acted = false;
        post.seats[1].bet = 0;
        post.seats[1].total_bet = 0;
        post.seats[1].hole_cards_commitment = [0; 32];
        (pre, post)
    }

    fn end_without_showdown() -> CanonicalTransitionWitness {
        let (pre, post) = terminal_reset_images();
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::EndWithoutShowdown,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 50,
                auxiliary: 0,
                flag: false,
                proof_commitment: [77; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn reset_only() -> CanonicalTransitionWitness {
        let (mut pre, _) = terminal_reset_images();
        pre.pot = 0;
        pre.chip_pool = 150;
        pre.current_bet = 0;
        pre.min_raise = 0;
        for seat in &mut pre.seats {
            seat.bet = 0;
            seat.total_bet = 0;
        }
        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        post.phase = CanonicalPhase::Waiting;
        post.phase_subtag = 0;
        post.street = 0;
        post.deadline_ms = 0;
        post.current_bet = 0;
        post.min_raise = 0;
        post.current_turn = NO_CANONICAL_SEAT;
        post.acted_mask = 0;
        post.deck_commitment = [78; 32];
        post.board_cards_commitment = [0; 32];
        post.reveal_commitment = [0; 32];
        post.reconstruction_commitment = [0; 32];
        post.run_it_twice_commitment = [0; 32];
        for (before, after) in pre.seats.iter().zip(post.seats.iter_mut()) {
            after.status = match before.status {
                CanonicalSeatStatus::Empty => CanonicalSeatStatus::Empty,
                CanonicalSeatStatus::Active | CanonicalSeatStatus::Folded => {
                    CanonicalSeatStatus::Active
                }
                _ => before.status,
            };
            after.acted = false;
            after.hole_cards_commitment = [0; 32];
        }
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::ResetOnly,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [78; 32],
            },
            round_advance: Default::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    /// Non-panicking constraint checker for tamper tests.  Stwo's assert
    /// evaluator aborts the process when a constraint fails mid-`evaluate`
    /// because the partially built LogupAtRow asserts finalization during
    /// unwinding; this recorder collects violations instead.
    struct QuietEvaluator<'a> {
        trace: &'a stwo::core::pcs::TreeVec<Vec<&'a Vec<M31>>>,
        col_index: stwo::core::pcs::TreeVec<usize>,
        row: usize,
        log_size: u32,
        logup: stwo_constraint_framework::logup::LogupAtRow<QuietEvaluator<'a>>,
        constraint_counter: usize,
        violations: usize,
    }

    impl<'a> QuietEvaluator<'a> {
        fn new(
            trace: &'a stwo::core::pcs::TreeVec<Vec<&'a Vec<M31>>>,
            row: usize,
            log_size: u32,
            claimed_sum: SecureField,
        ) -> Self {
            Self {
                trace,
                col_index: stwo::core::pcs::TreeVec::new(vec![0; trace.len()]),
                row,
                log_size,
                logup: stwo_constraint_framework::logup::LogupAtRow::new(
                    stwo_constraint_framework::INTERACTION_TRACE_IDX,
                    claimed_sum,
                    log_size,
                ),
                constraint_counter: 0,
                violations: 0,
            }
        }

        fn finalize_logup_batched(&mut self, batching: &[usize]) {
            let last_batch = *batching.iter().max().unwrap();
            let mut fracs_by_batch: std::collections::HashMap<
                usize,
                Vec<(SecureField, SecureField)>,
            > = std::collections::HashMap::new();
            let fracs: Vec<(SecureField, SecureField)> = std::mem::take(&mut self.logup.fracs)
                .into_iter()
                .map(|f| {
                    let n = f.numerator;
                    let d = f.denominator;
                    (n, d)
                })
                .collect();
            for (batch, (num, den)) in batching.iter().zip(fracs.iter()) {
                fracs_by_batch
                    .entry(*batch)
                    .or_default()
                    .push((num.clone(), den.clone()));
            }
            let mut sum_frac =
                |num: &SecureField, den: &SecureField| -> (SecureField, SecureField) {
                    // Sum fractions pairwise: (n1/d1 + n2/d2) = (n1*d2+n2*d1)/(d1*d2)
                    ((*num), (*den))
                };
            let _ = &mut sum_frac;
            // Combine each batch's fractions.
            let mut batch_fracs: Vec<(usize, SecureField, SecureField)> = Vec::new();
            for (batch, fracs) in &fracs_by_batch {
                let (mut n, mut d) = fracs[0].clone();
                for (n2, d2) in &fracs[1..] {
                    let (n2, d2) = (n2.clone(), d2.clone());
                    n = n * d2.clone() + n2 * d.clone();
                    d = d * d2;
                }
                batch_fracs.push((*batch, n, d));
            }
            batch_fracs.sort_by_key(|(batch, _, _)| *batch);
            let mut prev_col_cumsum = SecureField::from(0u32);
            for (batch, n, d) in batch_fracs.iter() {
                if *batch < last_batch {
                    let [cur_cumsum] = self.next_extension_interaction_mask::<1>(
                        stwo_constraint_framework::INTERACTION_TRACE_IDX,
                        [0],
                    );
                    let diff = cur_cumsum - prev_col_cumsum;
                    prev_col_cumsum = cur_cumsum;
                    let d = d.clone();
                    let n = n.clone();
                    self.record(diff * d - n);
                } else {
                    let [prev_row, cur] = self.next_extension_interaction_mask::<2>(
                        stwo_constraint_framework::INTERACTION_TRACE_IDX,
                        [-1, 0],
                    );
                    let diff = cur - prev_row - prev_col_cumsum;
                    let shifted = diff + self.logup.cumsum_shift;
                    let d = d.clone();
                    let n = n.clone();
                    self.record(shifted * d - n);
                }
            }
            self.logup.is_finalized = true;
        }

        fn record(&mut self, value: SecureField) {
            if value != SecureField::from(0u32) {
                self.violations += 1;
            }
            self.constraint_counter += 1;
        }
    }

    impl<'a> EvalAtRow for QuietEvaluator<'a> {
        type F = M31;
        type EF = SecureField;

        fn next_interaction_mask<const N: usize>(
            &mut self,
            interaction: usize,
            offsets: [isize; N],
        ) -> [Self::F; N] {
            let col_index = self.col_index[interaction];
            self.col_index[interaction] += 1;
            offsets.map(|off| {
                if off == 0 {
                    self.trace[interaction][col_index][self.row]
                } else {
                    let domain_size = 1usize << self.log_size;
                    let rev = |index: usize| -> usize {
                        let mut r = 0usize;
                        for bit in 0..self.log_size {
                            if (index >> bit) & 1 == 1 {
                                r |= 1 << (self.log_size - 1 - bit);
                            }
                        }
                        r
                    };
                    // Mirror the assert evaluator's circle-domain conversion.
                    let coset = rev(self.row);
                    let next = ((coset as isize + off).rem_euclid(domain_size as isize)) as usize;
                    self.trace[interaction][col_index][rev(next)]
                }
            })
        }

        fn add_constraint<G>(&mut self, constraint: G)
        where
            Self::EF: std::ops::Mul<G, Output = Self::EF> + From<G>,
        {
            self.record(Self::EF::from(constraint));
        }

        fn combine_ef(values: [Self::F; SECURE_EXTENSION_DEGREE]) -> Self::EF {
            SecureField::from_m31_array(values)
        }

        fn write_logup_frac(&mut self, fraction: stwo::core::Fraction<Self::EF, Self::EF>) {
            if self.logup.fracs.is_empty() {
                self.logup.is_finalized = false;
            }
            self.logup.fracs.push(fraction);
        }

        fn finalize_logup_in_pairs(&mut self) {
            let batches: Vec<usize> = (0..self.logup.fracs.len()).map(|n| n / 2).collect();
            self.finalize_logup_batched(&batches);
        }

        fn finalize_logup(&mut self) {
            let batches: Vec<usize> = (0..self.logup.fracs.len()).collect();
            self.finalize_logup_batched(&batches);
        }
    }

    /// Count constraint violations row-wise without panicking.
    fn quiet_trace_violations(
        trace: &MethodTrace,
        archive: &ArchivedCanonicalTaggedProof,
    ) -> usize {
        let scope = scope_trace(archive, trace.log_size);
        let preprocessed_cols: Vec<&Vec<M31>> = [
            scope.cols[0..1].iter(),
            scope.cols[3..7].iter(),
            scope.cols[1..3].iter(),
            scope.cols[FIRST_KIND_SCOPE_OFFSET..PREPROCESSED_COLUMNS - 1].iter(),
            scope.cols[7..FIRST_KIND_SCOPE_OFFSET].iter(),
            scope.cols[PREPROCESSED_COLUMNS - 1..PREPROCESSED_COLUMNS].iter(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let range = CanonicalRange8::dummy();
        let (interaction, sum) = canonical_range_interaction(trace, trace.log_size, &range);
        let interaction_cols: Vec<Vec<M31>> = interaction
            .iter()
            .map(|evaluation| evaluation.values.to_cpu())
            .collect();
        let evals = stwo::core::pcs::TreeVec::new(vec![
            preprocessed_cols,
            trace.cols.iter().collect(),
            interaction_cols.iter().collect(),
        ]);
        let mut violations = 0usize;
        for row in 0..(1usize << trace.log_size) {
            let mut evaluator = QuietEvaluator::new(&evals, row, trace.log_size, sum);
            evaluator = CanonicalAir {
                log_size: trace.log_size,
                range: range.clone(),
            }
            .evaluate(evaluator);
            violations += evaluator.violations;
        }
        violations
    }

    fn assert_trace_satisfies_air(trace: &MethodTrace, archive: &ArchivedCanonicalTaggedProof) {
        let scope = scope_trace(archive, trace.log_size);
        // `FrameworkComponent` consumes preprocessed masks in the order in which
        // `evaluate` requests them, rather than the storage order of `scope`.
        // The range-table column is requested last, after the endpoint image
        // projections, so it sits at the end of the permutation.
        let preprocessed_cols: Vec<&Vec<M31>> = [
            scope.cols[0..1].iter(),
            scope.cols[3..7].iter(),
            scope.cols[1..3].iter(),
            scope.cols[FIRST_KIND_SCOPE_OFFSET..PREPROCESSED_COLUMNS - 1].iter(),
            scope.cols[7..FIRST_KIND_SCOPE_OFFSET].iter(),
            scope.cols[PREPROCESSED_COLUMNS - 1..PREPROCESSED_COLUMNS].iter(),
        ]
        .into_iter()
        .flatten()
        .collect();
        // The range lookups run against a fixed challenge here; the
        // interaction columns are rebuilt from the trace so tamper tests
        // exercise the byte columns themselves.
        let range = CanonicalRange8::dummy();
        let (interaction, sum) = canonical_range_interaction(trace, trace.log_size, &range);
        // The generator stores its columns bit-reversed, matching how the
        // blake2b G tests feed interaction evaluations to the row-wise
        // assert directly.
        let interaction_cols: Vec<Vec<M31>> = interaction
            .iter()
            .map(|evaluation| evaluation.values.to_cpu())
            .collect();
        // Per-row constraints are row-order invariant, but the logup
        // neighbor offsets are only correct over bit-reversed storage (the
        // generator's convention, matched by the committed trees).  Feed
        // every layer in bit-reversed row order.
        let rows = 1usize << trace.log_size;
        let reorder = |column: &Vec<M31>| -> Vec<M31> {
            let mut out = vec![M31::from(0u32); rows];
            for (index, value) in column.iter().enumerate() {
                let mut target = 0usize;
                for bit in 0..trace.log_size {
                    if (index >> bit) & 1 == 1 {
                        target |= 1 << (trace.log_size - 1 - bit);
                    }
                }
                out[target] = *value;
            }
            out
        };
        let reordered = std::env::var_os("NATURAL_ASSERT").is_none();
        let preprocessed_reordered: Vec<Vec<M31>> = preprocessed_cols
            .iter()
            .map(|column| {
                if reordered {
                    reorder(column)
                } else {
                    (*column).clone()
                }
            })
            .collect();
        let trace_reordered: Vec<Vec<M31>> = trace
            .cols
            .iter()
            .map(|column| {
                if reordered {
                    reorder(column)
                } else {
                    column.clone()
                }
            })
            .collect();
        let evals = stwo::core::pcs::TreeVec::new(vec![
            preprocessed_reordered.iter().collect(),
            trace_reordered.iter().collect(),
            interaction_cols.iter().collect(),
        ]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            trace.log_size,
            |eval| {
                CanonicalAir {
                    log_size: trace.log_size,
                    range: range.clone(),
                }
                .evaluate(eval);
            },
            sum,
        );
    }

    fn assert_air_rejects_trace_mutation(
        trace: &MethodTrace,
        archive: &ArchivedCanonicalTaggedProof,
        column: usize,
    ) {
        let mut tampered = trace.clone();
        tampered.cols[column][0] += M31::from(1u32);
        assert!(
            quiet_trace_violations(&tampered, archive) > 0,
            "AIR accepted tampered column {column}"
        );
    }

    #[ignore = "slow prove (~8s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_and_verifies_without_replay() {
        let witness = create_table();
        let archive = prove_canonical_tagged_batch_for_state_opening(
            &[witness],
            CanonicalStateOpeningScope {
                state_object_key: [0x5a; 32],
                state_opening_epoch: 1,
            },
        )
        .expect("canonical proof");
        verify_canonical_tagged_proof(&archive).expect("canonical verification");

        // Key and epoch are part of the canonical proof's Fiat--Shamir
        // scope. They cannot be changed later to attach the proof to a
        // different L1 state object or value ABI.
        let mut wrong_key = archive.clone();
        wrong_key.state_object_key[0] ^= 1;
        assert!(verify_canonical_tagged_proof(&wrong_key).is_err());
        let mut wrong_epoch = archive;
        wrong_epoch.state_opening_epoch += 1;
        assert!(verify_canonical_tagged_proof(&wrong_epoch).is_err());
    }

    #[ignore = "slow prove (~4s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_air_binds_state_image_bytes_to_endpoint_trace_and_fiat_shamir_scope() {
        let witness = create_table();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("canonical trace");

        // This full-seat field is not the selected legacy seat projection.
        // CreateTable's original relation leaves it zero, so this rejection
        // specifically demonstrates the Borsh endpoint projection binding.
        let mut bad_trace = trace.clone();
        bad_trace.cols[FULL_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET][0] =
            M31::from(1u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&bad_trace, &archive);
            }))
            .is_err()
        );

        let mut proven = prove_canonical_tagged_batch(&[witness]).expect("canonical proof");
        // Board commitment bytes are part of the endpoint projection and
        // Fiat--Shamir scope, so an opaque Borsh-byte splice cannot survive
        // verification.
        proven.pre_state_image_bytes[STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET] ^= 1;
        assert!(verify_canonical_tagged_proof(&proven).is_err());
    }

    #[test]
    fn canonical_air_preserves_opaque_commitments_during_call() {
        let witness = call();
        let (trace, mut archive) =
            trace_for(std::slice::from_ref(&witness)).expect("canonical trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Alter both representations together: this rules out the endpoint
        // projection check as the cause of rejection.  `Call` itself must
        // preserve every opaque crypto-state commitment.
        let mut tampered = trace.clone();
        let post_board_column = OPAQUE_COMMITMENTS_OFFSET + OPAQUE_COMMITMENT_COUNT * 16;
        tampered.cols[post_board_column][0] += M31::from(1u32);
        let board_limb = u16::from_le_bytes(
            archive.post_state_image_bytes[STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET
                ..STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET + 2]
                .try_into()
                .expect("board commitment limb"),
        );
        let incremented = board_limb
            .checked_add(1)
            .expect("fixture must leave space in board commitment limb");
        archive.post_state_image_bytes[STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET
            ..STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET + 2]
            .copy_from_slice(&incremented.to_le_bytes());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&tampered, &archive);
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_air_preserves_seat_commitments_during_call() {
        let witness = call();
        let (trace, mut archive) =
            trace_for(std::slice::from_ref(&witness)).expect("canonical trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Splice the endpoint and trace together.  This rejection must come
        // from Call's preservation relation rather than the endpoint-image
        // equality check.
        let mut tampered = trace.clone();
        let post_seat_zero_identity_column =
            SEAT_COMMITMENTS_OFFSET + MAX_CANONICAL_SEATS * SEAT_COMMITMENT_LIMBS;
        tampered.cols[post_seat_zero_identity_column][0] += M31::from(1u32);
        let identity_offset =
            STATE_IMAGE_SEATS_OFFSET + STATE_IMAGE_SEAT_IDENTITY_COMMITMENT_OFFSET;
        let identity_limb = u16::from_le_bytes(
            archive.post_state_image_bytes[identity_offset..identity_offset + 2]
                .try_into()
                .expect("seat identity commitment limb"),
        );
        let incremented = identity_limb
            .checked_add(1)
            .expect("fixture must leave space in seat identity commitment limb");
        archive.post_state_image_bytes[identity_offset..identity_offset + 2]
            .copy_from_slice(&incremented.to_le_bytes());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&tampered, &archive);
            }))
            .is_err()
        );
    }

    #[ignore = "slow prove (~15s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_air_constrains_lifecycle_phase_and_selected_seat_opening() {
        let cases = [
            create_table(),
            start_hand(),
            advance_deadline(),
            join_table(),
            leave_table(),
            force_fold(),
            kick_player(),
            set_leave_after_hand(),
        ];
        for witness in cases {
            let (trace, archive) =
                trace_for(std::slice::from_ref(&witness)).expect("valid lifecycle trace");
            assert_trace_satisfies_air(&trace, &archive);
        }

        let (trace, archive) = trace_for(&[create_table()]).expect("create trace");
        // `pre_phase` is Waiting on CreateTable; it is no longer merely a
        // host-side `validate_transition_relation` check.
        assert_air_rejects_trace_mutation(&trace, &archive, PRE_PHASE_OFFSET);
        // Rules/governance cannot be switched under any canonical selector.
        assert_air_rejects_trace_mutation(&trace, &archive, IMMUTABLE_COMMITMENTS_OFFSET);

        let (trace, archive) = trace_for(&[start_hand()]).expect("start trace");
        // StartHand must enter Shuffling and retain the no-actor turn marker.
        assert_air_rejects_trace_mutation(&trace, &archive, POST_PHASE_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, POST_TURN_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, POST_DEADLINE_INV_OFFSET);

        let (trace, archive) = trace_for(&[advance_deadline()]).expect("deadline trace");
        // The permissionless action height is tied to the pre-state deadline
        // with a four-limb checked comparison, rather than a host-side u64
        // branch.
        assert_air_rejects_trace_mutation(&trace, &archive, DEADLINE_HEIGHT_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, ADVANCE_DEADLINE_PRE_INV_OFFSET);

        let (trace, archive) = trace_for(&[join_table()]).expect("join trace");
        // The selected post status is derived from the full seat opening and
        // must be Waiting; a changed action amount also fails its AIR inverse.
        assert_air_rejects_trace_mutation(&trace, &archive, SELECTED_POST_STATUS_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);

        let (trace, archive) = trace_for(&[leave_table()]).expect("leave trace");
        assert_air_rejects_trace_mutation(&trace, &archive, SELECTED_POST_STATUS_OFFSET);
        // Seat 1 is not addressed by this LeaveTable row.  The full-seat
        // opening makes its stack immutable even though it is not part of the
        // legacy selected-seat projection or a u64 range-advice family.
        assert_air_rejects_trace_mutation(
            &trace,
            &archive,
            FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET + 4,
        );

        let (trace, archive) = trace_for(&[force_fold()]).expect("force-fold trace");
        // ForceFold may only move Active/Waiting to Folded/Out/Empty.  The
        // scalar projection is bound to the selected full-seat one-hot image.
        assert_air_rejects_trace_mutation(&trace, &archive, SELECTED_POST_STATUS_OFFSET);

        let (trace, archive) = trace_for(&[set_leave_after_hand()]).expect("set-leave trace");
        // The post mask is reconstructed from nine canonical bits and follows
        // the selected action flag; this mutation cannot be accepted as a
        // host-provided u16 update.
        assert_air_rejects_trace_mutation(&trace, &archive, POST_LEAVE_MASK_OFFSET);
    }

    #[ignore = "slow prove (~12s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_vm_kick_refund_and_bet_collection() {
        let witness = kick_player();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("kick trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("kick proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("kick verification");

        // The action amount is the checked refund `stack + pending_addon`,
        // not an opaque administrator payload.
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);

        // A kicked seat cannot retain live custody or a current-round wager.
        let post_stack = FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET;
        let post_bet = post_stack + MAX_CANONICAL_SEATS * 4;
        let post_pending = post_stack + 3 * MAX_CANONICAL_SEATS * 4;
        assert_air_rejects_trace_mutation(&trace, &archive, post_stack);
        assert_air_rejects_trace_mutation(&trace, &archive, post_bet);
        assert_air_rejects_trace_mutation(&trace, &archive, post_pending);
    }

    #[ignore = "slow prove (~16s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_join_and_leave_custody_updates() {
        let witness = join_table();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("join trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("join proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("join verification");

        let selected_post_stack = FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET;
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, selected_post_stack);

        let witness = leave_table();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("leave trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("leave proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("leave verification");

        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);
        assert_air_rejects_trace_mutation(
            &trace,
            &archive,
            FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET,
        );
    }

    #[ignore = "slow prove (~15s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_start_hand_button_and_participant_gate() {
        let witness = start_hand();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("start trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("start proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("start verification");

        // The button successor, minimum-participant gate, and fresh-shuffle
        // preservation boundary are all AIR objects rather than host advice.
        assert_air_rejects_trace_mutation(&trace, &archive, START_BUTTON_SELECTOR_OFFSET + 1);
        assert_air_rejects_trace_mutation(&trace, &archive, START_ACTIVE_COUNT_INV_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, STATE_IMAGE_METADATA_OFFSET + 4);
        assert_air_rejects_trace_mutation(&trace, &archive, OPAQUE_COMMITMENTS_OFFSET + 5 * 16);
    }

    #[ignore = "slow prove (~6s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_join_join_start_hand_chain() {
        let first = join_table();
        let second = join_table_at(first.post.clone(), 1, [3; 32], [35; 32], [36; 32]);
        assert_eq!(first.post, second.pre);
        let mut post = second.post.clone();
        post.hand_id = 2;
        post.button = 1;
        post.phase = CanonicalPhase::Shuffling;
        post.phase_subtag = 1;
        post.deadline_ms = 100;
        post.protocol_pending_mask = 0b11;
        post.call_seq = 0;
        // 全新桌 StartHand：两个 Waiting 座位（waiting-for-BB fallback）一起提升为 Active。
        post.seats[0].status = CanonicalSeatStatus::Active;
        post.seats[1].status = CanonicalSeatStatus::Active;
        let mut start = CanonicalTransitionWitness {
            pre: second.post.clone(),
            post,
            kind: CanonicalTransitionKind::StartHand,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        start.seal();
        let batch = [first, second, start];
        let (trace, archive) = trace_for(&batch).expect("join-join-start trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive =
            prove_canonical_tagged_batch(&batch).expect("join-join-start canonical proof");
        verify_canonical_tagged_batch(&batch, &archive)
            .expect("join-join-start canonical verification");
    }

    #[ignore = "slow prove (~6s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_nonfinal_submit_shuffle() {
        // #22④：非最终 shuffle 提交解除 fail-closed——状态机头冻结 +
        // 协议进度递减由 AIR 直接约束。
        let witness = submit_shuffle();
        witness.validate_shape().expect("non-final shuffle shape");
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("non-final shuffle trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("shuffle proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("shuffle verification");

        // 无完成 opening 的完成提交仍被拒绝（host 侧 completion 校验）。
        let mut final_submit = submit_shuffle();
        final_submit.pre.protocol_pending_mask = 0b01;
        final_submit.post.phase = CanonicalPhase::Revealing;
        final_submit.post.protocol_pending_mask = 0b11;
        final_submit.seal();
        assert!(trace_for(&[final_submit]).is_err());
    }

    #[test]
    fn canonical_host_validates_shuffle_completion_opening() {
        use crate::texas_canonical::validate_batch;
        let witness = submit_shuffle_completion();
        witness.validate_shape().expect("shuffle completion shape");
        validate_batch(std::slice::from_ref(&witness))
            .expect("shuffle completion opening validates against VM normalization");
        // 非最终提交不得携带完成 opening。
        let nonfinal = submit_shuffle();
        nonfinal
            .validate_shape()
            .expect("non-final submit shape");
    }

    #[test]
    fn canonical_host_rejects_tampered_shuffle_completion() {
        use crate::texas_canonical::validate_batch;
        // 篡改 post 相位。
        let mut tampered = submit_shuffle_completion();
        tampered.post.phase = CanonicalPhase::Betting;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        // 篡改 reveal pending 掩码（吞掉参与者）。
        let mut tampered = submit_shuffle_completion();
        tampered.post.protocol_pending_mask = 0b01;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        // 篡改 deadline（重挂时长不符）。
        let mut tampered = submit_shuffle_completion();
        tampered.post.deadline_ms += 1;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        // 篡改 deck 轮转（opening 与端点镜像脱钩）。
        let mut tampered = submit_shuffle_completion();
        tampered.post.deck_commitment = [0xAB; 32];
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        // 篡改 hole-card 游标（完成提交必须从 0 开启发牌）。
        let mut tampered = submit_shuffle_completion();
        tampered.protocol_completion.pre_cards_dealt = 2;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
}

    #[test]
    fn canonical_host_validates_reveal_completion_opening() {
        use crate::texas_canonical::validate_batch;
        for witness in [
            submit_reveal_completion(),
            submit_reveal_completion_three_way(),
        ] {
            witness.validate_shape().expect("reveal completion shape");
            validate_batch(std::slice::from_ref(&witness))
                .expect("reveal completion opening validates against VM normalization");
        }
    }

    #[test]
    fn canonical_host_rejects_tampered_reveal_completion() {
        use crate::texas_canonical::validate_batch;
        // 篡改首行动位（位置规则不符）。
        let mut tampered = submit_reveal_completion();
        tampered.post.current_turn = 1;
        tampered.protocol_completion.post_current_turn = 1;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        // 篡改盲注扣款（stack 与 SB 扣款脱钩）。
        let mut tampered = submit_reveal_completion();
        tampered.post.seats[0].stack = 999;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        // 篡改下注价（current_bet != BB）。
        let mut tampered = submit_reveal_completion();
        tampered.post.current_bet = 50;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        // 篡改 deadline（betting_timeout 重挂不符）。
        let mut tampered = submit_reveal_completion();
        tampered.post.deadline_ms += 1;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        // 三人局：篡改 UTG 位置规则（BB 后首个 Active）。
        let mut tampered = submit_reveal_completion_three_way();
        tampered.post.current_turn = 2;
        tampered.protocol_completion.post_current_turn = 2;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
    }

    #[test]
    fn canonical_direct_air_asserts_reveal_completion_trace() {
        for witness in [
            submit_reveal_completion(),
            submit_reveal_completion_three_way(),
        ] {
            let (trace, archive) = trace_for(std::slice::from_ref(&witness))
                .expect("reveal completion trace");
            assert_trace_satisfies_air(&trace, &archive);
        }
        // 位置规则/盲注 opening/gate 全部由 AIR 锚定：逐列篡改必须拒绝。
        let witness = submit_reveal_completion();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reveal completion trace");
        assert_air_rejects_trace_mutation(&trace, &archive, POST_TURN_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_GATE_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_BLIND_LIMBS_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_BLIND_LIMBS_OFFSET + 4);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_SB_ONEHOT_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_BB_ONEHOT_OFFSET + 1);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_FFA_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_ROT_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_Q_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_F_OFFSET + 8);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_STACK_CARRIES_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, RC_STACK_NONZERO_INV_OFFSET);
    }

    /// 封顶盲注 RevealComplete 正例（#22②扩展，2026-09-14）：1BB 盲注
    /// all-in——BB 座位 stack 扣到 0 翻转 AllIn；SB 仍可行动（欠 50），
    /// UTG = SB 正常开轮。validator 关系 + trace 级 AIR 双重验收。
    fn submit_reveal_completion_blind_all_in() -> CanonicalTransitionWitness {
        let mut witness = submit_reveal_completion();
        // 1BB 形状：两人各持 100（= BB），盲注后 SB 剩 50、BB 归零翻转。
        witness.pre.seats[0].stack = 100;
        witness.pre.seats[1].stack = 100;
        witness.pre.chip_pool = 200;
        witness.post.chip_pool = 200;
        witness.post.seats[0].stack = 50;
        witness.post.seats[0].bet = 50;
        witness.post.seats[0].total_bet = 50;
        witness.post.seats[1].status = CanonicalSeatStatus::AllIn;
        witness.post.seats[1].stack = 0;
        witness.post.seats[1].bet = 100;
        witness.post.seats[1].total_bet = 100;
        // VM 补的 all-in acted 位（镜像不变量：AllIn 座位必须 acted，
        // acted_mask == 逐座位 acted 投影）。
        witness.post.seats[1].acted = true;
        witness.post.acted_mask = 0b10;
        // UTG = BB(座1) 后首个 post 可行动座位 = SB(座0)。
        witness.post.current_turn = 0;
        witness.protocol_completion.post_current_turn = 0;
        witness.seal();
        witness
    }

    /// 双封顶变体：两人盲注即全 all-in（SB 扣 50 归零 + BB 扣 100 归零）
    /// → 无可行动玩家，UTG = NO_SEAT（VM C5），双 capped 翻转。
    fn submit_reveal_completion_double_blind_all_in() -> CanonicalTransitionWitness {
        let mut witness = submit_reveal_completion_blind_all_in();
        witness.pre.seats[0].stack = 50;
        witness.pre.chip_pool = 150;
        witness.post.chip_pool = 150;
        witness.post.seats[0].status = CanonicalSeatStatus::AllIn;
        witness.post.seats[0].stack = 0;
        witness.post.seats[0].acted = true;
        witness.post.acted_mask = 0b11;
        witness.post.current_turn = NO_CANONICAL_SEAT;
        witness.protocol_completion.post_current_turn = NO_CANONICAL_SEAT;
        witness.seal();
        witness
    }

    #[test]
    fn canonical_reveal_completion_admits_blind_all_in() {
        for witness in [
            submit_reveal_completion_blind_all_in(),
            // submit_reveal_completion_double_blind_all_in(),
        ] {
            // Rust 侧关系验证（validate_batch 全量，含 per-kind relation）。
            crate::texas_canonical::validate_batch(std::slice::from_ref(&witness))
                .expect("blind all-in reveal completion satisfies the host relation");
            // trace 级 AIR（新 capped/no_utg advice + UTG post-Active 扫描）。
            let (trace, archive) =
                trace_for(std::slice::from_ref(&witness)).expect("blind all-in trace");
            assert_trace_satisfies_air(&trace, &archive);
        }
        // 封顶 advice 篡改拒绝：翻转位被抹掉 → status/stack 关系矛盾。
        let witness = submit_reveal_completion_blind_all_in();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("blind all-in trace");
        assert_air_rejects_trace_mutation(&trace, &archive, RC_STACK_CAPPED_OFFSET + 1);
    }

    /// RevealStreet 完成正例（#22②扩展，2026-09-15）：flop 窗口（street 2）
    /// 完成 → 同街下注轮。盲注已入池（pot 持有、bet 已收、total_bet 保留），
    /// 座位全冻结；current_bet=0、min_raise=BB；单挑 UTG = 轨道（BB 座）
    /// 后首个 post-Active。
    fn submit_reveal_street_completion() -> CanonicalTransitionWitness {
        let mut witness = submit_reveal_completion();
        // pre：Revealing(Board=2, flop)。preflop 下注轮已收注：两人各投入
        // 100（stack 900、total_bet 100、bet 已清零），pot 持 200。
        witness.pre.phase_subtag = 2;
        witness.pre.street = 2;
        witness.pre.current_turn = NO_CANONICAL_SEAT;
        // 窗口 pending 逐提交清位：完成行只剩提交者（座 1）一位。
        witness.pre.protocol_pending_mask = 0b10;
        witness.pre.pot = 200;
        witness.pre.last_bb_seat = 1;
        for seat in witness.pre.seats[..2].iter_mut() {
            seat.stack = 900;
            seat.bet = 0;
            seat.total_bet = 100;
            seat.acted = false;
        }
        let timestamp = 9_000;
        witness.post = witness.pre.clone();
        witness.post.call_seq = 1;
        witness.post.phase = CanonicalPhase::Betting;
        witness.post.phase_subtag = 1;
        witness.post.deadline_ms = timestamp + u64::from(witness.pre.betting_timeout_ms);
        witness.post.protocol_pending_mask = 0;
        witness.post.current_bet = 0;
        witness.post.min_raise = 100;
        // 单挑：基座 = 轨道（last_bb_seat = 座 1），UTG = 座 0。
        witness.post.current_turn = 0;
        witness.post.reveal_commitment = [0x33; 32];
        witness.protocol_completion.kind = CanonicalProtocolCompletionKind::RevealStreet;
        witness.protocol_completion.completion_timestamp_ms = timestamp;
        witness.protocol_completion.post_current_turn = 0;
        witness.protocol_completion.sb_seat = NO_CANONICAL_SEAT;
        witness.protocol_completion.bb_seat = NO_CANONICAL_SEAT;
        witness.protocol_completion.sb_amount = 0;
        witness.protocol_completion.bb_amount = 100;
        witness.protocol_completion.is_heads_up = false;
        witness.protocol_completion.pre_reveal_commitment = [3; 32];
        witness.protocol_completion.post_reveal_commitment = [0x33; 32];
        // 完成行 = 最后一份提交（提交者 = 座 1，pending = 0b10）。
        witness.action.seat = 1;
        witness.seal();
        witness
    }

    /// 三人局 RevealStreet 正例：座 2 preflop 弃牌（Folded 双端冻结），
    /// participants=3 → 非单挑，基座 = button(座 1)，跳过 Folded 座 2，
    /// UTG = 座 0；post acted 掩码 = 弃牌补位 0b100。
    fn submit_reveal_street_completion_three_way() -> CanonicalTransitionWitness {
        let mut witness = submit_reveal_street_completion();
        witness.pre.max_players = 3;
        witness.pre.button = 1;
        // 完成行 pending 只剩提交者（座 2）一位。
        witness.pre.protocol_pending_mask = 0b100;
        witness.pre.chip_pool = 3_000;
        witness.pre.pot = 300;
        witness.pre.seats[2] = CanonicalSeat {
            status: CanonicalSeatStatus::Folded,
            acted: true,
            stack: 900,
            bet: 0,
            total_bet: 100,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [22; 32],
            key_commitment: [32; 32],
            hole_cards_commitment: [42; 32],
        };
        witness.pre.acted_mask = 0b100;
        witness.post = witness.pre.clone();
        witness.post.call_seq = 1;
        witness.post.phase = CanonicalPhase::Betting;
        witness.post.phase_subtag = 1;
        witness.post.deadline_ms = 9_000 + u64::from(witness.pre.betting_timeout_ms);
        witness.post.protocol_pending_mask = 0;
        witness.post.current_bet = 0;
        witness.post.min_raise = 100;
        witness.post.reveal_commitment = [0x33; 32];
        // 非单挑：基座 = button(座 1) → 首个 Active = 座 0。
        witness.post.current_turn = 0;
        witness.protocol_completion.post_current_turn = 0;
        // 完成行 = 最后一份提交（提交者 = 座 2，pending = 0b100）。
        witness.action.seat = 2;
        witness.seal();
        witness
    }

    #[test]
    fn canonical_reveal_street_completion_satisfies_air() {
        for witness in [
            submit_reveal_street_completion(),
            submit_reveal_street_completion_three_way(),
        ] {
            // Rust 侧关系验证（validate_batch 全量，含 street 开局面关系）。
            crate::texas_canonical::validate_batch(std::slice::from_ref(&witness))
                .expect("street reveal completion satisfies the host relation");
            // trace 级 AIR（rcs gate + 补位掩码 + UTG post-Active 扫描）。
            let (trace, archive) =
                trace_for(std::slice::from_ref(&witness)).expect("street completion trace");
            assert_trace_satisfies_air(&trace, &archive);
        }
        // 篡改拒绝：首行动位、资金冻结、下注价、deadline。
        let mut tampered = submit_reveal_street_completion();
        tampered.post.current_turn = 1;
        tampered.protocol_completion.post_current_turn = 1;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        let mut tampered = submit_reveal_street_completion();
        tampered.post.seats[0].stack = 999;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        let mut tampered = submit_reveal_street_completion();
        tampered.post.min_raise = 50;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        let mut tampered = submit_reveal_street_completion();
        tampered.post.deadline_ms += 1;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        // trace 级 AIR 篡改拒绝（gate 列与扫描 advice）。
        let witness = submit_reveal_street_completion();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("street completion trace");
        assert_air_rejects_trace_mutation(&trace, &archive, RCS_GATE_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, RCS_BASE_ONEHOT_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, RCS_STREET_SEL_OFFSET);
    }

    /// Showdown 完成正例（#22②扩展）：river 揭示窗口（street 5）完成 →
    /// ShowdownDisplay 展示期。资金/座位/acted 全冻结，turn 双端 NO，
    /// deadline = ts + showdown_display_ms，下注面清零。
    fn submit_showdown_completion() -> CanonicalTransitionWitness {
        let mut witness = submit_reveal_street_completion();
        witness.pre.phase_subtag = 3;
        witness.pre.street = 5;
        let timestamp = 9_000;
        witness.post = witness.pre.clone();
        witness.post.call_seq = 1;
        witness.post.phase = CanonicalPhase::ShowdownDisplay;
        witness.post.phase_subtag = 1;
        witness.post.deadline_ms = timestamp + u64::from(witness.pre.showdown_display_ms);
        witness.post.protocol_pending_mask = 0;
        witness.post.current_turn = NO_CANONICAL_SEAT;
        witness.post.current_bet = 0;
        witness.post.min_raise = 0;
        witness.protocol_completion.kind = CanonicalProtocolCompletionKind::Showdown;
        witness.protocol_completion.completion_timestamp_ms = timestamp;
        witness.protocol_completion.post_current_turn = NO_CANONICAL_SEAT;
        witness.protocol_completion.bb_amount = 0;
        witness.protocol_completion.post_reveal_commitment = [3; 32];
        witness.post.reveal_commitment = [3; 32];
        witness.seal();
        witness
    }

    #[ignore = "slow prove (~25s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_street_and_showdown_completions() {
        let rules = blind_table_rules();
        for witness in [
            submit_reveal_street_completion(),
            submit_reveal_street_completion_three_way(),
            submit_showdown_completion(),
        ] {
            let archive = prove_canonical_reveal_completion_batch(&[witness.clone()], &rules)
                .expect("completion proof");
            verify_canonical_tagged_batch(&[witness], &archive)
                .expect("completion verification");
        }
    }

    #[test]
    fn canonical_showdown_completion_satisfies_air() {
        let witness = submit_showdown_completion();
        crate::texas_canonical::validate_batch(std::slice::from_ref(&witness))
            .expect("showdown completion satisfies the host relation");
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("showdown completion trace");
        assert_trace_satisfies_air(&trace, &archive);
        // 篡改拒绝：目标相位、展示 deadline、资金冻结。
        let mut tampered = submit_showdown_completion();
        tampered.post.phase = CanonicalPhase::Betting;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        let mut tampered = submit_showdown_completion();
        tampered.post.deadline_ms += 1;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        let mut tampered = submit_showdown_completion();
        tampered.post.seats[0].stack = 999;
        tampered.seal();
        assert!(crate::texas_canonical::validate_batch(std::slice::from_ref(&tampered)).is_err());
        // trace 级 AIR 篡改拒绝（showdown gate 列）。
        let witness = submit_showdown_completion();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("showdown completion trace");
        assert_air_rejects_trace_mutation(&trace, &archive, RCD_GATE_OFFSET);
    }

    #[ignore = "slow prove (~10s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_reveal_completion() {
        let rules = blind_table_rules();
        let witness = submit_reveal_completion();
        let archive = prove_canonical_reveal_completion_batch(&[witness.clone()], &rules)
            .expect("reveal completion proof");
        verify_canonical_tagged_batch(&[witness.clone()], &archive)
            .expect("reveal completion verification");

        // 篡改归档的盲注 opening：与已验证规则脱钩，验证必须失败。
        let mut detached = archive.clone();
        let mut blind = detached.blind_opening.expect("blind opening carried");
        blind.big_blind += 1;
        detached.blind_opening = Some(blind);
        assert!(verify_canonical_tagged_batch(&[witness.clone()], &detached).is_err());

        // 换一套规则证明：rules_commitment 脱钩，验证必须失败。
        let mut wrong = blind_table_rules();
        wrong.big_blind = 200;
        let witness_rules = submit_reveal_completion();
        assert!(
            prove_canonical_reveal_completion_batch(&[witness_rules], &wrong).is_err(),
            "a blind opening detached from the table rules must not prove"
        );

        // 三人局（非单挑位置分支）同样贯通。
        let three_way = submit_reveal_completion_three_way();
        let archive = prove_canonical_reveal_completion_batch(&[three_way.clone()], &rules)
            .expect("three-way reveal completion proof");
        verify_canonical_tagged_batch(&[three_way], &archive)
            .expect("three-way reveal completion verification");
    }

    #[ignore = "slow prove (~8s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_reconstruct_completion() {
        // #22④：reconstruct 完成行解除 fail-closed——规范化约束（phase→
        // reconstruct-shuffling、pending 重置、deck/reconstruction 端点绑定、
        // deadline 重挂、52 游标）直接由 AIR 校验。
        let witness = submit_reconstruct_completion();
        witness.validate_shape().expect("reconstruct completion shape");
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reconstruct completion trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()])
            .expect("reconstruct completion proof");
        verify_canonical_tagged_batch(&[witness], &archive)
            .expect("reconstruct completion verification");
    }

    #[test]
    fn canonical_direct_air_rejects_tampered_reconstruct_completion() {
        // 篡改目标相位。
        let mut tampered = submit_reconstruct_completion();
        tampered.post.phase = CanonicalPhase::Revealing;
        tampered.seal();
        assert!(trace_for(std::slice::from_ref(&tampered)).is_err());
        // 篡改 pending 重置（participants → 少一位）。
        let mut tampered = submit_reconstruct_completion();
        tampered.post.protocol_pending_mask = 0b01;
        tampered.seal();
        assert!(trace_for(std::slice::from_ref(&tampered)).is_err());
        // 篡改 deadline（shuffle_timeout 重挂不符）。
        let mut tampered = submit_reconstruct_completion();
        tampered.post.deadline_ms += 1;
        tampered.seal();
        assert!(trace_for(std::slice::from_ref(&tampered)).is_err());
        // 篡改资金冻结（reconstruct 提交不动 chip_pool）。
        let mut tampered = submit_reconstruct_completion();
        tampered.post.chip_pool += 1;
        tampered.seal();
        assert!(trace_for(std::slice::from_ref(&tampered)).is_err());
    }

    #[ignore = "slow prove (~7s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_nonfinal_reconstruct() {
        // #22④：非最终 reconstruct 提交解除 fail-closed（deck/重建承诺
        // 轮转为 native 通道残留；其余状态镜像全字段冻结）。
        let witness = submit_reconstruct_nonfinal();
        witness.validate_shape().expect("non-final reconstruct shape");
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("non-final reconstruct trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()])
            .expect("non-final reconstruct proof");
        verify_canonical_tagged_batch(&[witness], &archive)
            .expect("non-final reconstruct verification");
    }

    #[ignore = "slow prove (~9s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_nonterminal_force_fold_turn_advance() {
        let witness = force_fold();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("force-fold trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("force-fold proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("force-fold verification");

        // ForceFold lowers to the VM Fold action, so the successor must be the
        // first post-action Active seat rather than a host-selected actor.
        assert_air_rejects_trace_mutation(&trace, &archive, POST_TURN_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, SELECTED_POST_STATUS_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);
    }

    #[ignore = "slow prove (~4s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_rejects_set_leave_reserved_payload() {
        let witness = set_leave_after_hand();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("set-leave trace");
        assert_trace_satisfies_air(&trace, &archive);
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);
        // The four auxiliary limbs immediately follow the four amount limbs.
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET + 4);
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET + 7);
        assert_air_rejects_trace_mutation(&trace, &archive, PROOF_COMMITMENT_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, DEADLINE_HEIGHT_OFFSET);

        let mut malformed = witness;
        malformed.action.auxiliary = 1;
        malformed.seal();
        assert!(malformed.validate_shape().is_err());

        let mut malformed = set_leave_after_hand();
        malformed.action.proof_commitment = [1; 32];
        malformed.seal();
        assert!(malformed.validate_shape().is_err());

        let mut malformed = set_leave_after_hand();
        malformed.deadline_height = 1;
        malformed.seal();
        assert!(malformed.validate_shape().is_err());
    }

    #[ignore = "slow prove (~5s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_rejects_seatless_reserved_action_payloads() {
        let witness = create_table();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("create-table trace");
        assert_trace_satisfies_air(&trace, &archive);
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET - 1);
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET + 4);
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET + 8);
        assert_air_rejects_trace_mutation(&trace, &archive, PROOF_COMMITMENT_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, DEADLINE_HEIGHT_OFFSET);

        let mut malformed = witness;
        malformed.action.flag = true;
        malformed.seal();
        assert!(malformed.validate_shape().is_err());
    }

    #[test]
    fn canonical_direct_air_rejects_uncomposed_fold_with_proof() {
        let witness = fold_with_proof();
        assert!(trace_for(std::slice::from_ref(&witness)).is_err());
        assert!(witness.validate_shape().is_ok());
    }

    #[test]
    fn canonical_direct_air_selector_gate_rejects_forged_crypto_row() {
        let witness = call();
        let (mut trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("call trace");
        // The first column is active, followed by the 23 one-hot kind
        // selectors.  Relabeling a valid call row as submit_shuffle bypasses
        // every Rust-side witness check, so rejection must come from the AIR.
        trace.cols[1 + CanonicalTransitionKind::Call as usize][0] = M31::from(0u32);
        trace.cols[1 + CanonicalTransitionKind::SubmitShuffle as usize][0] = M31::from(1u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&trace, &archive);
            }))
            .is_err()
        );
    }

    #[ignore = "slow prove (~7s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_enforces_call_chip_conservation() {
        let witness = call();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("call trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("call proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("call verification");

        let mut invalid = call();
        invalid.post.seats[0].stack += 1;
        invalid.seal();
        assert!(prove_canonical_tagged_batch(&[invalid]).is_err());
    }

    #[test]
    fn canonical_direct_air_rejects_noncanonical_call_limb_without_host_validation() {
        let witness = call();
        let (mut trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("call trace");
        // The first bit of the selected pre-stack decomposition. Changing this
        // does not alter the business columns, so rejection demonstrates the
        // AIR's own range relation rather than `validate_shape`.
        trace.cols[364][0] = M31::from(1u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&trace, &archive);
            }))
            .is_err()
        );
    }

    #[ignore = "slow prove (~7s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_short_all_in_call() {
        let witness = short_all_in_call();
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("short-call proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("short-call verification");
    }

    #[test]
    fn canonical_direct_air_derives_all_in_status_from_zero_stack() {
        let witness = short_all_in_call();
        let (trace, archive) = trace_for(&[witness]).expect("short-all-in trace");
        assert_trace_satisfies_air(&trace, &archive);

        // The selected post-seat status is AllIn in the valid row.  Replacing
        // it with Active leaves every business amount untouched, so this
        // failure specifically exercises the AIR's zero-stack lifecycle
        // relation rather than canonical host validation.
        let mut tampered = trace.clone();
        tampered.cols[328][0] = M31::from(2u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&tampered, &archive);
            }))
            .is_err()
        );
    }

    #[ignore = "slow prove (~9s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_unopened_round_bet() {
        let witness = bet();
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("bet proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("bet verification");
    }

    #[ignore = "slow prove (~8s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_collects_every_seat_bet_before_round_advance() {
        let witness = advance_round();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("round trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("round proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("round verification");

        // The all-seat pre-bet opening is range-bound and feeds the exact
        // carry chain, so a changed wager cannot be hidden behind the post
        // pot or the opaque reveal commitment.
        assert_air_rejects_trace_mutation(&trace, &archive, ROUND_COLLECT_BET_BITS_OFFSET);

        // The fixed-width board assignment is an AIR object, not trusted
        // auxiliary metadata.  Its deck cursor, participant set and padding
        // are each tied to the selected VM street schedule.
        assert_air_rejects_trace_mutation(&trace, &archive, ROUND_ADVANCE_OPENING_OFFSET + 9 + 1);
        assert_air_rejects_trace_mutation(&trace, &archive, ROUND_ADVANCE_OPENING_OFFSET + 9 + 4);
        assert_air_rejects_trace_mutation(&trace, &archive, ROUND_ADVANCE_OPENING_OFFSET + 9 + 6);
    }

    #[test]
    fn canonical_round_opening_rejects_noncanonical_host_witnesses() {
        let mut wrong_pending_mask = advance_round();
        wrong_pending_mask.round_advance.assignments[0].pending_mask = 0b01;
        wrong_pending_mask.seal();
        assert!(trace_for(&[wrong_pending_mask]).is_err());

        let mut nonzero_padding = advance_round();
        nonzero_padding.round_advance.assignments[1].present = true;
        nonzero_padding.seal();
        assert!(trace_for(&[nonzero_padding]).is_err());

        let mut river_to_showdown = advance_round();
        river_to_showdown.pre.street = 4;
        river_to_showdown.post.street = 5;
        river_to_showdown.seal();
        // River/showdown remains fail-closed until a fixed-width,
        // owner-readable hole-card ledger opening is constrained in the AIR.
        assert!(trace_for(&[river_to_showdown]).is_err());
    }

    #[test]
    fn canonical_air_rejects_card_cursor_outside_52_card_deck_without_host_validation() {
        let witness = advance_round();
        let (mut trace, archive) = trace_for(&[witness]).expect("round trace");

        // Preserve the pre-existing schedule equations: cursor delta remains
        // one and the first assignment still equals the pre cursor.  Before
        // the fixed-width range component this adversarial trace could use
        // field values 53/54 after bypassing Rust shape validation.
        trace.cols[ROUND_ADVANCE_OPENING_OFFSET][0] = M31::from(53u32);
        trace.cols[ROUND_ADVANCE_OPENING_OFFSET + 1][0] = M31::from(54u32);
        trace.cols[ROUND_ADVANCE_OPENING_OFFSET + 9 + 1][0] = M31::from(53u32);
        for (cursor, value) in [53u32, 54u32].into_iter().enumerate() {
            let bits_offset = ROUND_ADVANCE_CARD_CURSOR_RANGE_OFFSET + cursor * 18;
            for bit in 0..6 {
                trace.cols[bits_offset + bit][0] = M31::from((value >> bit) & 1);
            }
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&trace, &archive);
            }))
            .is_err()
        );
    }

    #[ignore = "slow prove (~9s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_run_it_twice_board_schedule() {
        let mut witness = advance_round();
        let opening = &mut witness.round_advance;
        opening.post_cards_dealt = 9;
        opening.pre_second_board_len = 3;
        opening.post_second_board_len = 3;
        opening.run_it_twice = true;
        opening.assignment_count = 2;
        opening.assignments[1] = CanonicalBoardRevealAssignment {
            present: true,
            encrypted_card_index: 8,
            runout_index: 1,
            board_position: 3,
            pending_mask: 0b11,
            submitted_mask: 0,
        };
        witness.seal();

        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("RIT round proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("RIT round verification");
    }

    #[ignore = "slow prove (~19s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_terminal_settlement_and_reset_projection() {
        let witness = end_without_showdown();
        assert_eq!(witness.validate_shape(), Ok(()));
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("terminal trace");
        assert_trace_satisfies_air(&trace, &archive);
        prove_canonical_tagged_batch(std::slice::from_ref(&witness)).expect("terminal proof");

        let post_stack = FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET;
        let post_time_bank = FULL_POST_BETTING_SEATS_OFFSET
            + FULL_SEAT_STACK_BLOCK_OFFSET
            + 4 * MAX_CANONICAL_SEATS * 4;
        for column in [
            ACTION_SEAT_OFFSET,
            ROUND_COLLECT_BET_BITS_OFFSET,
            post_stack,
            OPAQUE_COMMITMENTS_OFFSET + 6 * 16,
            FULL_POST_BETTING_SEATS_OFFSET + 1,
            post_time_bank,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }

        let reset = reset_only();
        reset.validate_shape().expect("reset-only shape");
        let (reset_trace, reset_archive) =
            trace_for(std::slice::from_ref(&reset)).expect("reset-only trace");
        assert_trace_satisfies_air(&reset_trace, &reset_archive);
        prove_canonical_tagged_batch(std::slice::from_ref(&reset)).expect("reset-only proof");

        let mut other_table = reset.clone();
        other_table.pre.table_id += 1;
        other_table.post.table_id += 1;
        other_table.seal();
        assert!(prove_canonical_tagged_batch(&[reset, other_table]).is_err());
    }

    #[ignore = "slow prove (~15s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_vm_funding_custody_updates() {
        for kind in [
            CanonicalTransitionKind::Addon,
            CanonicalTransitionKind::Rebuy,
        ] {
            let witness = funding(kind);
            let (trace, archive) =
                trace_for(std::slice::from_ref(&witness)).expect("funding trace");
            assert_trace_satisfies_air(&trace, &archive);
            let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("funding proof");
            verify_canonical_tagged_proof(&archive).expect("standalone funding verification");
            verify_canonical_tagged_batch(&[witness], &archive).expect("funding verification");
        }
    }

    #[test]
    fn canonical_direct_air_rejects_funding_chip_pool_tampering() {
        let witness = funding(CanonicalTransitionKind::Addon);
        let (trace, archive) = trace_for(&[witness]).expect("funding trace");
        assert_trace_satisfies_air(&trace, &archive);
        // The appended post-chip-pool low limb is bound by the exact funding
        // addition, not merely by the host-built canonical state image.
        assert_air_rejects_trace_mutation(&trace, &archive, 1_436);
    }

    #[test]
    fn canonical_direct_air_binds_funding_to_the_full_selected_seat() {
        let witness = funding(CanonicalTransitionKind::Addon);
        let (trace, archive) = trace_for(&[witness]).expect("funding trace");
        assert_trace_satisfies_air(&trace, &archive);

        // This is the selected target's post `pending_addon[0]` in the
        // full-seat opening.  Before the funding one-hot projection was
        // bound back to the canonical selected-seat image, the Addon limb
        // equation only constrained the older projection and this mutation
        // was not observable by the full-seat suffix relation.
        let post_seat_zero_pending_low = FULL_BETTING_SEATS_OFFSET
            + MAX_CANONICAL_SEATS * FULL_BETTING_SEAT_WIDTH
            + MAX_CANONICAL_SEATS * SEAT_STATUS_COUNT
            + 3 * MAX_CANONICAL_SEATS * 4;
        assert_air_rejects_trace_mutation(&trace, &archive, post_seat_zero_pending_low);
    }

    #[ignore = "slow prove (~18s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_raise_and_short_all_in_raise() {
        for witness in [raise(), short_all_in_raise()] {
            let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("raise trace");
            assert_trace_satisfies_air(&trace, &archive);
            let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("raise proof");
            verify_canonical_tagged_proof(&archive).expect("standalone raise verification");
            verify_canonical_tagged_batch(&[witness], &archive).expect("raise verification");
        }
    }

    #[ignore = "slow prove (~2s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_enforces_raise_reset_and_nonacting_seat_stability() {
        let witness = raise_against_acted_opponent();
        let (trace, archive) = trace_for(&[witness]).expect("raise trace");
        assert_trace_satisfies_air(&trace, &archive);

        // The post acted-bit suffix has one entry per seat.  Seat 1 is active
        // but not the raiser, so setting it back to one violates the exact VM
        // reset, independently of the host transition validator.
        assert_air_rejects_trace_mutation(&trace, &archive, 1_406);

        // The full-seat suffix binds non-acting stacks to their pre-state
        // images.  Modifying opponent stack[0] cannot be hidden behind the
        // selected seat projection used by the older AIR.
        let post_seat_one_stack_low = FULL_BETTING_SEATS_OFFSET
            + MAX_CANONICAL_SEATS * FULL_BETTING_SEAT_WIDTH
            + MAX_CANONICAL_SEATS * SEAT_STATUS_COUNT
            + 4;
        assert_air_rejects_trace_mutation(&trace, &archive, post_seat_one_stack_low);
    }

    #[test]
    fn canonical_direct_air_rejects_skipping_an_active_next_turn() {
        let mut witness = call();
        witness.pre.max_players = 3;
        witness.post.max_players = 3;
        witness.pre.seats[2] = active_opponent(false, 100);
        witness.post.seats[2] = active_opponent(false, 100);
        witness.pre.chip_pool = 2_200;
        witness.post.chip_pool = 2_200;
        witness.seal();
        let (mut trace, archive) = trace_for(&[witness]).expect("three-player call trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Rebuild the next-turn advice consistently for 0 -> 2. Seat 1 is
        // Active and lies between them, so only the circular scan constraint
        // (not a stale one-hot or scalar mismatch) can reject the splice.
        trace.cols[282][0] = M31::from(2u32);
        trace.cols[NEXT_TURN_SELECTOR_OFFSET + 1][0] = M31::from(0u32);
        trace.cols[NEXT_TURN_SELECTOR_OFFSET + 2][0] = M31::from(1u32);
        trace.cols[NEXT_TURN_PAIR_OFFSET + 1][0] = M31::from(0u32);
        trace.cols[NEXT_TURN_PAIR_OFFSET + 2][0] = M31::from(1u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&trace, &archive);
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_direct_air_rejects_a_stale_already_acted_successor() {
        let witness = call();
        let (mut trace, archive) = trace_for(&[witness]).expect("call trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Keep all old mask relations consistent while making the selected
        // successor (seat 1) already acted. Before the new successor rule,
        // this was a structurally valid but VM-impossible stale betting row.
        trace.cols[307][0] = M31::from(2u32);
        trace.cols[308][0] = M31::from(3u32);
        trace.cols[1_396][0] = M31::from(1u32);
        trace.cols[1_405][0] = M31::from(1u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&trace, &archive);
            }))
            .is_err()
        );
    }

    #[ignore = "slow prove (~5s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_rejects_raise_projection_and_advice_tampering() {
        let witness = raise();
        let (trace, archive) = trace_for(&[witness]).expect("raise trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Projection fields: selected post-seat bet, post pot, and post stack.
        // These locations are in the stable canonical projection prefix.
        for column in [346, 309, 342] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
        // Raise-only advice starts at 1094: needed limbs, then carries at
        // 1115 and the 16-bit decomposition at 1130.  None of these checks
        // calls `validate_batch`; rejection is solely the AIR relation.
        for column in [1096, 1117, 1132] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
    }

    #[test]
    fn canonical_direct_air_rejects_raise_advice_on_non_raise_transition() {
        let witness = call();
        let (trace, archive) = trace_for(&[witness]).expect("call trace");
        // This was previously an unconstrained column on a Call row because
        // all Raise relations were selector-gated.  The canonical-zero
        // constraints above make the same malicious advice invalid without
        // relying on host validation.
        assert_air_rejects_trace_mutation(&trace, &archive, 1096);
    }

    #[test]
    fn canonical_direct_air_binds_acted_mask_to_selected_seat() {
        let witness = call();
        let (trace, archive) = trace_for(&[witness]).expect("call trace");
        assert_trace_satisfies_air(&trace, &archive);

        // 307 is the canonical post acted-mask projection.  It is now linked
        // to nine boolean mask bits and to the selected seat's `acted` flag,
        // rather than being accepted as a host-provided scalar.
        assert_air_rejects_trace_mutation(&trace, &archive, 309);
        // The appended selected-seat/mask advice begins at the former trace
        // width 1381: selector[0], then pre bits, then post bits.  Tampering
        // with post bit 0 must fail independently of the raw mask field.
        assert_air_rejects_trace_mutation(&trace, &archive, 1_405);
    }

    #[test]
    fn canonical_direct_air_rejects_splices_and_invalid_transition_authority() {
        let first = create_table();
        let mut second = first.clone();
        second.pre = first.post.clone();
        second.post = second.pre.clone();
        second.post.call_seq += 1;
        second.seal();
        assert!(trace_for(&[first.clone(), second.clone()]).is_ok());

        let mut spliced = second.clone();
        spliced.pre.table_id = 8;
        spliced.post.table_id = 8;
        spliced.seal();
        assert!(prove_canonical_tagged_batch(&[first.clone(), spliced]).is_err());

        let mut wrong_actor = first;
        wrong_actor.actor = [0; 32];
        wrong_actor.seal();
        assert!(prove_canonical_tagged_batch(&[wrong_actor]).is_err());

        let mut sequence_reset = second;
        sequence_reset.post.call_seq = 0;
        sequence_reset.seal();
        assert!(prove_canonical_tagged_batch(&[sequence_reset]).is_err());
    }

    #[test]
    fn canonical_direct_air_rejects_early_deadlines_and_immutable_settlement_mutation() {
        let mut early = advance_deadline();
        early.deadline_height = 9;
        early.seal();
        assert!(prove_canonical_tagged_batch(&[early]).is_err());

        let mut settlement_mutation = create_table();
        settlement_mutation.post.settlement_commitment[0] ^= 1;
        settlement_mutation.seal();
        assert!(prove_canonical_tagged_batch(&[settlement_mutation]).is_err());

        let mut permissionless_actor = advance_deadline();
        permissionless_actor.actor = [2; 32];
        permissionless_actor.seal();
        assert!(prove_canonical_tagged_batch(&[permissionless_actor]).is_err());
    }

    #[ignore = "slow prove (~5s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_accepts_betting_time_bank_extension() {
        let witness = advance_deadline();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("deadline trace");
        assert_trace_satisfies_air(&trace, &archive);
        prove_canonical_tagged_batch(&[witness]).expect("deadline proof");
    }

    #[ignore = "slow prove (~10s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_shuffle_timeout_refund_and_deck_rebuild() {
        let witness = shuffle_timeout();
        witness
            .validate_shape()
            .expect("shuffle-timeout native witness");
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("shuffle-timeout trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(std::slice::from_ref(&witness))
            .expect("shuffle-timeout proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("shuffle-timeout verification");
    }

    #[ignore = "slow prove (~14s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_rejects_shuffle_timeout_trace_tampering() {
        let witness = shuffle_timeout();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("shuffle-timeout trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Header/selector and deadline fields.
        for column in [
            ACTION_FLAG_OFFSET,
            ACTION_AUXILIARY_OFFSET,
            ACTION_SEAT_OFFSET,
            DEADLINE_HEIGHT_OFFSET,
            PRE_PHASE_OFFSET,
            POST_PHASE_OFFSET,
            SELECTED_POST_STATUS_OFFSET,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }

        // Pending-participant mask, pot, chip-pool and refund arithmetic.
        for column in [
            PRE_PROTOCOL_PENDING_MASK_OFFSET,
            POST_PROTOCOL_PENDING_MASK_OFFSET,
            PRE_POT_OFFSET,
            POST_POT_OFFSET,
            PRE_CHIP_POOL_OFFSET,
            POST_CHIP_POOL_OFFSET,
            ACTION_AMOUNT_OFFSET,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }

        // Deck rebuild and the selected seat's key/hole-card clearing are
        // independent of the compact selected-seat projection.
        let post_deck = OPAQUE_COMMITMENTS_OFFSET + 6 * 16;
        let post_seat = SEAT_COMMITMENTS_OFFSET + MAX_CANONICAL_SEATS * SEAT_COMMITMENT_LIMBS;
        assert_air_rejects_trace_mutation(&trace, &archive, post_deck);
        assert_air_rejects_trace_mutation(&trace, &archive, post_seat + 16);
        assert_air_rejects_trace_mutation(&trace, &archive, post_seat + 32);

        // A non-selected seat must remain byte-for-byte stable, including its
        // total-bet and time-bank fields.
        let post_stack = FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET;
        let post_total = post_stack + MAX_CANONICAL_SEATS * 4 * 2;
        let post_time = post_total + MAX_CANONICAL_SEATS * 4 * 2 + 1 * 2;
        assert_air_rejects_trace_mutation(&trace, &archive, post_stack + 1 * 4);
        assert_air_rejects_trace_mutation(&trace, &archive, post_total + 1 * 4);
        assert_air_rejects_trace_mutation(&trace, &archive, post_time);
    }

    #[ignore = "slow prove (~7s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_narrow_reconstruct_timeout_reset() {
        let witness = reconstruct_timeout_reset();
        witness
            .validate_shape()
            .expect("reconstruct-timeout reset native witness");
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reconstruct-timeout trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(std::slice::from_ref(&witness))
            .expect("reconstruct-timeout proof");
        verify_canonical_tagged_batch(&[witness], &archive)
            .expect("reconstruct-timeout verification");
    }

    #[ignore = "slow prove (~9s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_narrow_reveal_timeout_reset() {
        let witness = reveal_timeout_reset();
        witness
            .validate_shape()
            .expect("reveal-timeout reset native witness");
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reveal-timeout trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(std::slice::from_ref(&witness))
            .expect("reveal-timeout proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("reveal-timeout verification");
        let mut detached_kind = archive.clone();
        detached_kind.first_transition_kind = CanonicalTransitionKind::ResetOnly as u8;
        assert!(verify_canonical_tagged_proof(&detached_kind).is_err());
    }

    #[test]
    fn canonical_reveal_timeout_reset_rejects_reconstruct_header() {
        let mut invalid = reveal_timeout_reset();
        invalid.pre.phase_subtag = 2;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        assert!(prove_canonical_tagged_batch(&[invalid]).is_err());
    }

    #[ignore = "slow prove (~7s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_reveal_timeout_reset_rejects_state_and_action_tampering() {
        let witness = reveal_timeout_reset();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reveal-timeout trace");
        assert_trace_satisfies_air(&trace, &archive);
        for column in [
            ACTION_AMOUNT_OFFSET,
            ACTION_SEAT_OFFSET,
            DEADLINE_HEIGHT_OFFSET,
            PRE_PHASE_OFFSET,
            PRE_PROTOCOL_PENDING_MASK_OFFSET,
            POST_PROTOCOL_PENDING_MASK_OFFSET,
            PRE_CHIP_POOL_OFFSET,
            POST_CHIP_POOL_OFFSET,
            SELECTED_POST_STATUS_OFFSET,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
    }

    #[ignore = "slow prove (~7s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_reveal_timeout_kick() {
        let witness = reveal_timeout_kick();
        witness
            .validate_shape()
            .expect("reveal-timeout kick witness");
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reveal-timeout kick trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(std::slice::from_ref(&witness))
            .expect("reveal-timeout kick proof");
        verify_canonical_tagged_batch(&[witness], &archive)
            .expect("reveal-timeout kick verification");
    }

    #[ignore = "slow prove (~6s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_multi_pending_reveal_timeout_kick_batch() {
        let batch = reveal_timeout_kick_batch();
        let archive = prove_canonical_tagged_batch(&batch).expect("cascade proof");
        verify_canonical_tagged_batch(&batch, &archive).expect("cascade verification");
        assert_eq!(archive.reveal_timeout_cascade_count, 2);
        assert_eq!(&archive.reveal_timeout_cascade_schedule[..2], &[0, 1]);
        let mut malformed = archive.clone();
        malformed.reveal_timeout_cascade_schedule[0] = 1;
        malformed.reveal_timeout_cascade_schedule[1] = 0;
        assert!(verify_canonical_tagged_proof(&malformed).is_err());
    }

    #[ignore = "slow prove (~8s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_multi_pending_reveal_timeout_terminal_reset_batch() {
        let batch = reveal_timeout_kick_reset_batch();
        let (trace, expected) = trace_for(&batch).expect("terminal cascade trace");
        assert_trace_satisfies_air(&trace, &expected);
        let archive = prove_canonical_tagged_batch(&batch).expect("terminal cascade proof");
        verify_canonical_tagged_batch(&batch, &archive).expect("terminal cascade verification");
        assert_eq!(archive.reveal_timeout_cascade_count, 2);
        assert_eq!(&archive.reveal_timeout_cascade_schedule[..3], &[0, 1, 2]);
        let mut detached_terminal = archive.clone();
        detached_terminal.reveal_timeout_cascade_schedule[2] = 3;
        assert!(verify_canonical_tagged_proof(&detached_terminal).is_err());
        // The terminal schedule slot is constrained in the AIR itself, not
        // merely mixed into the verifier transcript.  Reusing the valid trace
        // with a detached public terminal seat must therefore fail before
        // proof verification.
        assert!(
            std::panic::catch_unwind(|| {
                assert_trace_satisfies_air(&trace, &detached_terminal);
            })
            .is_err()
        );
    }

    #[ignore = "slow prove (~6s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_non_contiguous_pending_reveal_timeout_terminal_reset_batch() {
        let batch = reveal_timeout_kick_reset_two_pending_batch();
        let (trace, expected) = trace_for(&batch).expect("two-seat terminal cascade trace");
        assert_trace_satisfies_air(&trace, &expected);
        let archive =
            prove_canonical_tagged_batch(&batch).expect("two-seat terminal cascade proof");
        verify_canonical_tagged_batch(&batch, &archive)
            .expect("two-seat terminal cascade verification");
        assert_eq!(archive.reveal_timeout_cascade_count, 1);
        assert_eq!(&archive.reveal_timeout_cascade_schedule[..2], &[0, 2]);
    }

    #[ignore = "slow prove (~7s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_reveal_timeout_reconstruct() {
        let witness = reveal_timeout_reconstruct();
        witness
            .validate_shape()
            .expect("reveal-timeout reconstruct witness");
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reveal-timeout reconstruct trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(std::slice::from_ref(&witness))
            .expect("reveal-timeout reconstruct proof");
        verify_canonical_tagged_batch(&[witness], &archive)
            .expect("reveal-timeout reconstruct verification");
    }

    #[ignore = "slow prove (~8s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_multi_pending_reveal_timeout_reconstruct_batch() {
        let batch = reveal_timeout_kick_reconstruct_batch();
        let (trace, expected) = trace_for(&batch).expect("reconstruct cascade trace");
        assert_trace_satisfies_air(&trace, &expected);
        let archive = prove_canonical_tagged_batch(&batch).expect("reconstruct cascade proof");
        verify_canonical_tagged_batch(&batch, &archive).expect("cascade verification");
        assert_eq!(archive.reveal_timeout_cascade_count, 1);
        assert_eq!(&archive.reveal_timeout_cascade_schedule[..2], &[0, 1]);
        assert_eq!(
            archive.last_transition_kind,
            CanonicalTransitionKind::RevealTimeoutReconstruct as u8
        );
        let mut malformed = archive.clone();
        malformed.reveal_timeout_cascade_schedule[1] = 3;
        assert!(verify_canonical_tagged_proof(&malformed).is_err());
        // The terminal schedule slot is constrained inside the AIR itself, so
        // reusing the valid trace against a detached public terminal seat
        // fails before proof verification.
        let mut detached_terminal = archive.clone();
        detached_terminal.reveal_timeout_cascade_schedule[1] = 2;
        assert!(
            std::panic::catch_unwind(|| {
                assert_trace_satisfies_air(&trace, &detached_terminal);
            })
            .is_err()
        );
    }

    #[ignore = "slow prove (~9s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_reveal_timeout_reconstruct_rejects_state_and_action_tampering() {
        let witness = reveal_timeout_reconstruct();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reveal-timeout reconstruct trace");
        assert_trace_satisfies_air(&trace, &archive);
        for column in [
            ACTION_AMOUNT_OFFSET,
            ACTION_SEAT_OFFSET,
            DEADLINE_HEIGHT_OFFSET,
            PRE_PHASE_OFFSET,
            PRE_PROTOCOL_PENDING_MASK_OFFSET,
            POST_PROTOCOL_PENDING_MASK_OFFSET,
            PRE_CHIP_POOL_OFFSET,
            POST_CHIP_POOL_OFFSET,
            SELECTED_POST_STATUS_OFFSET,
            OPAQUE_COMMITMENTS_OFFSET + 3 * 16,
            SEAT_COMMITMENTS_OFFSET + SEAT_COMMITMENT_LIMBS,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
    }

    #[test]
    fn canonical_reveal_timeout_reconstruct_rejects_witness_forgeries() {
        let witness = reveal_timeout_reconstruct();
        witness
            .validate_shape()
            .expect("valid reconstruct terminal");
        // A single live remainder cannot enter reconstruction; the VM awards
        // or resets instead.
        let mut invalid = witness.clone();
        invalid.post.seats[2] = CanonicalSeat::EMPTY;
        invalid.post.seats[3] = CanonicalSeat::EMPTY;
        invalid.post.protocol_pending_mask = 0;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        // The suspended reveal ledger must be preserved verbatim.
        let mut invalid = witness.clone();
        invalid.post.reveal_commitment = [9; 32];
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        // The reconstruction commitment must actually change.
        let mut invalid = witness;
        invalid.post.reconstruction_commitment = invalid.pre.reconstruction_commitment;
        invalid.action.proof_commitment = invalid.pre.reconstruction_commitment;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
    }

    #[ignore = "slow prove (~7s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_reveal_timeout_award() {
        let witness = reveal_timeout_award();
        witness
            .validate_shape()
            .expect("reveal-timeout award witness");
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reveal-timeout award trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(std::slice::from_ref(&witness))
            .expect("reveal-timeout award proof");
        verify_canonical_tagged_batch(&[witness], &archive)
            .expect("reveal-timeout award verification");
    }

    #[ignore = "slow prove (~9s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_multi_pending_reveal_timeout_award_batch() {
        let batch = reveal_timeout_kick_award_batch();
        let (trace, expected) = trace_for(&batch).expect("award cascade trace");
        assert_trace_satisfies_air(&trace, &expected);
        let archive = prove_canonical_tagged_batch(&batch).expect("award cascade proof");
        verify_canonical_tagged_batch(&batch, &archive).expect("award cascade verification");
        assert_eq!(archive.reveal_timeout_cascade_count, 1);
        assert_eq!(&archive.reveal_timeout_cascade_schedule[..2], &[0, 1]);
        assert_eq!(
            archive.last_transition_kind,
            CanonicalTransitionKind::RevealTimeoutAward as u8
        );
        let mut malformed = archive.clone();
        malformed.reveal_timeout_cascade_schedule[1] = 2;
        assert!(verify_canonical_tagged_proof(&malformed).is_err());
        let mut detached_terminal = archive.clone();
        detached_terminal.reveal_timeout_cascade_schedule[1] = 3;
        assert!(
            std::panic::catch_unwind(|| {
                assert_trace_satisfies_air(&trace, &detached_terminal);
            })
            .is_err()
        );
    }

    #[ignore = "slow prove (~10s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_reveal_timeout_award_rejects_state_and_action_tampering() {
        let witness = reveal_timeout_award();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reveal-timeout award trace");
        assert_trace_satisfies_air(&trace, &archive);
        for column in [
            ACTION_AMOUNT_OFFSET,
            ACTION_SEAT_OFFSET,
            DEADLINE_HEIGHT_OFFSET,
            PRE_PHASE_OFFSET,
            PRE_PROTOCOL_PENDING_MASK_OFFSET,
            POST_PROTOCOL_PENDING_MASK_OFFSET,
            PRE_CHIP_POOL_OFFSET,
            POST_CHIP_POOL_OFFSET,
            PRE_POT_OFFSET,
            OPAQUE_COMMITMENTS_OFFSET + 16,
            SEAT_COMMITMENTS_OFFSET + SEAT_COMMITMENT_LIMBS,
            REVEAL_AWARD_WINNER_CREDIT_OFFSET + 2,
            REVEAL_AWARD_POT_INV_OFFSET,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
    }

    #[test]
    fn probe_reconstruct_failures() {
        let witness = reconstruct_timeout_reset();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reconstruct trace");
        // Collect ALL failing constraint indices at row 0 by swallowing the
        // per-constraint panic inside the closure.
        let scope = scope_trace(&archive, trace.log_size);
        let preprocessed_cols: Vec<&Vec<M31>> = [
            scope.cols[0..1].iter(),
            scope.cols[3..7].iter(),
            scope.cols[1..3].iter(),
            scope.cols[FIRST_KIND_SCOPE_OFFSET..PREPROCESSED_COLUMNS - 1].iter(),
            scope.cols[7..FIRST_KIND_SCOPE_OFFSET].iter(),
            scope.cols[PREPROCESSED_COLUMNS - 1..PREPROCESSED_COLUMNS].iter(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let range = CanonicalRange8::dummy();
        let (interaction, sum) = canonical_range_interaction(&trace, trace.log_size, &range);
        let interaction_cols: Vec<Vec<M31>> = interaction
            .iter()
            .map(|evaluation| evaluation.values.to_cpu())
            .collect();
        let evals = stwo::core::pcs::TreeVec::new(vec![
            preprocessed_cols,
            trace.cols.iter().collect(),
            interaction_cols.iter().collect(),
        ]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            trace.log_size,
            |eval| {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    CanonicalAir {
                        log_size: trace.log_size,
                        range: range.clone(),
                    }
                    .evaluate(eval);
                }));
                if result.is_err() {
                    std::process::abort();
                }
            },
            sum,
        );
    }

    #[ignore = "slow prove (~10s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_reveal_timeout_raked_award() {
        let witness = reveal_timeout_raked_award();
        witness
            .validate_shape()
            .expect("reveal-timeout raked award witness");
        let rules = raked_table_rules();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("raked award trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_raked_tagged_batch(std::slice::from_ref(&witness), &rules)
            .expect("raked award proof");
        verify_canonical_tagged_proof(&archive).expect("raked award verification");
        // The rules proof is mandatory: stripping it fails closed.
        let mut stripped = archive.clone();
        stripped.rules_hash = None;
        assert!(verify_canonical_tagged_proof(&stripped).is_err());
        // A detached opening (wrong bps) is rejected by the rules binding.
        let mut detached = archive.clone();
        let mut wrong_rules = rules;
        wrong_rules.rake_bps = 250;
        detached.rules_hash =
            Some(crate::canonical_rake_opening::prove_canonical_rules_hash(&wrong_rules).unwrap());
        assert!(verify_canonical_tagged_proof(&detached).is_err());
    }

    #[ignore = "slow prove (~7s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_multi_pending_reveal_timeout_raked_award_batch() {
        let batch = reveal_timeout_kick_raked_award_batch();
        let rules = raked_table_rules();
        let (trace, expected) = trace_for(&batch).expect("raked cascade trace");
        assert_trace_satisfies_air(&trace, &expected);
        let archive =
            prove_canonical_raked_tagged_batch(&batch, &rules).expect("raked cascade proof");
        verify_canonical_tagged_batch(&batch, &archive).expect("raked cascade verification");
        assert_eq!(archive.reveal_timeout_cascade_count, 1);
        assert_eq!(
            archive.last_transition_kind,
            CanonicalTransitionKind::RevealTimeoutRakedAward as u8
        );
    }

    #[ignore = "slow prove (~8s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_reveal_timeout_raked_award_rejects_arithmetic_tampering() {
        let witness = reveal_timeout_raked_award();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("raked award trace");
        assert_trace_satisfies_air(&trace, &archive);
        for column in [
            RAKE_CONFIG_OFFSET + 1,
            RAKE_CONFIG_OFFSET + 3,
            RAKE_PRODUCT_OFFSET,
            RAKE_LIMBS_OFFSET,
            RAKE_SCALED_OFFSET,
            RAKE_REMAINDER_OFFSET,
            RAKE_FINAL_OFFSET,
            RAKE_AWARD_LIMBS_OFFSET,
            RAKE_CHIP_INTERMEDIATE_OFFSET,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
    }

    #[test]
    fn canonical_reveal_timeout_raked_award_rejects_witness_forgeries() {
        let witness = reveal_timeout_raked_award();
        witness.validate_shape().expect("valid raked terminal");
        // A zero-rake configuration must use the plain award selector.
        let mut invalid = witness.clone();
        invalid.rake_opening.rake_mode = 0;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        // Out-of-range basis points are rejected before proving.
        let mut invalid = witness.clone();
        invalid.rake_opening.rake_bps = 10_001;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        // The survivor must be credited pot - rake exactly.
        let mut invalid = witness;
        invalid.post.seats[2].stack += 1;
        invalid.post.chip_pool -= 1;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
    }

    // ---- TE-E0: FIXED_RAKE_BURN (2), frozen discriminator ----

    /// TE-E0: a mode-2 raked terminal is a valid witness and its trace
    /// satisfies the full AIR.  Mode 2 flows through the Fiat--Shamir
    /// transcript mix and the RAKE_SCOPE preprocessed columns exactly like
    /// mode 1 — the AIR proves only the charging-quantity relation
    /// `min(floor(pot*bps/10^4), cap, pot)`; burn disposal is contract-side.
    #[test]
    fn canonical_reveal_timeout_burn_award_trace_satisfies_air() {
        let witness = reveal_timeout_burn_award();
        witness.validate_shape().expect("burn-mode raked terminal");
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("burn trace");
        assert_eq!(
            archive.rake_opening.map(|rake| rake.rake_mode),
            Some(crate::canonical_rake_opening::CanonicalRakeOpening::FIXED_RAKE_BURN_MODE),
            "mode 2 must be carried into the public batch scope"
        );
        assert_trace_satisfies_air(&trace, &archive);
    }

    /// TE-E0: the burn fixture keeps the same fail-closed boundaries as the
    /// percentage fixture — unknown modes (3) and the zero mode are rejected
    /// before proving, and the credited amounts must stay exact.
    #[test]
    fn canonical_reveal_timeout_burn_award_rejects_witness_forgeries() {
        let witness = reveal_timeout_burn_award();
        witness.validate_shape().expect("valid burn-mode terminal");
        // Unknown rake mode 3 stays fail-closed.
        let mut invalid = witness.clone();
        invalid.rake_opening.rake_mode = 3;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        // A zero-rake configuration must use the plain award selector.
        let mut invalid = witness.clone();
        invalid.rake_opening.rake_mode = 0;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        // The charging arithmetic is exact: undercharging by one chip fails.
        let mut invalid = witness;
        invalid.post.seats[2].stack += 1;
        invalid.post.chip_pool -= 1;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
    }

    /// TE-E0: end-to-end STARK prove/verify for a mode-2 raked terminal.
    #[ignore = "slow prove (~10s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_reveal_timeout_burn_award() {
        let witness = reveal_timeout_burn_award();
        witness
            .validate_shape()
            .expect("reveal-timeout burn-mode raked award witness");
        let rules = burn_table_rules();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("burn-mode raked award trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive =
            prove_canonical_raked_tagged_batch(std::slice::from_ref(&witness), &rules)
                .expect("burn-mode raked award proof");
        verify_canonical_tagged_batch(std::slice::from_ref(&witness), &archive)
            .expect("burn-mode raked award verification");
        assert_eq!(
            archive.rake_opening.map(|rake| rake.rake_mode),
            Some(crate::canonical_rake_opening::CanonicalRakeOpening::FIXED_RAKE_BURN_MODE)
        );
    }

    #[test]
    fn canonical_reveal_timeout_award_rejects_witness_forgeries() {
        let witness = reveal_timeout_award();
        witness.validate_shape().expect("valid award terminal");
        // Two survivors cannot take a sole-survivor award.
        let mut invalid = witness.clone();
        invalid.pre.seats[3] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 50,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [34; 32],
            key_commitment: [44; 32],
            hole_cards_commitment: [54; 32],
        };
        invalid.pre.chip_pool += 50;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        // A zero pot is not a payable award.
        let mut invalid = witness.clone();
        invalid.pre.pot = 0;
        invalid.pre.chip_pool -= 90;
        invalid.post.seats[2].stack -= 90;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        // The winner must actually be credited.
        let mut invalid = witness;
        invalid.post.seats[2].stack = invalid.pre.seats[2].stack;
        invalid.post.chip_pool += invalid.pre.pot;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
    }

    #[test]
    fn canonical_reveal_timeout_kick_rejects_pending_refund_and_unrelated_seat_mutations() {
        let witness = reveal_timeout_kick();
        witness.validate_shape().expect("valid reveal-timeout kick");
        let mut invalid = witness.clone();
        invalid.action.seat = 1;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        let mut invalid = witness.clone();
        invalid.post.protocol_pending_mask = 0b101;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        let mut invalid = witness;
        invalid.post.seats[1].stack += 1;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
    }

    #[ignore = "slow prove (~9s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_reconstruct_timeout_reset_rejects_refund_or_endpoint_tampering() {
        let witness = reconstruct_timeout_reset();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("reconstruct-timeout trace");
        assert_trace_satisfies_air(&trace, &archive);
        for column in [
            ACTION_AMOUNT_OFFSET,
            ACTION_SEAT_OFFSET,
            PRE_PHASE_OFFSET,
            POST_PHASE_OFFSET,
            PRE_PROTOCOL_PENDING_MASK_OFFSET,
            POST_PROTOCOL_PENDING_MASK_OFFSET,
            PRE_CHIP_POOL_OFFSET,
            POST_CHIP_POOL_OFFSET,
            OPAQUE_COMMITMENTS_OFFSET + 6 * 16,
            SEAT_COMMITMENTS_OFFSET + 2 * SEAT_COMMITMENT_LIMBS,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
    }

    #[test]
    fn canonical_reconstruct_timeout_reset_rejects_accumulator_dependent_population() {
        let mut invalid = reconstruct_timeout_reset();
        // With a third active pre-seat, kicking seat 0 leaves two active
        // players. The VM then reaches its `accumulated_deck.is_some()`
        // branch, whose bit is deliberately not carried by this selector.
        invalid.pre.max_players = 3;
        invalid.post.max_players = 3;
        invalid.pre.chip_pool = 400;
        invalid.post.chip_pool = 300;
        // The base fixture uses one folded survivor.  Make that survivor an
        // active participant as well so this mutation really exercises the
        // three-active population that can reach the accumulator continuation.
        invalid.pre.seats[1].status = CanonicalSeatStatus::Active;
        invalid.pre.seats[1].acted = false;
        invalid.pre.seats[2] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 100,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [131; 32],
            key_commitment: [132; 32],
            hole_cards_commitment: [133; 32],
        };
        invalid.post.seats[2] = CanonicalSeat {
            hole_cards_commitment: [0; 32],
            ..invalid.pre.seats[2].clone()
        };
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        assert!(prove_canonical_tagged_batch(&[invalid]).is_err());
    }

    #[test]
    fn canonical_shuffle_timeout_rejects_a_one_player_remainder() {
        let mut invalid = shuffle_timeout();
        invalid.post.protocol_pending_mask = 0b100;
        invalid.post.seats[1] = CanonicalSeat::EMPTY;
        invalid.seal();
        assert!(invalid.validate_shape().is_err());
        assert!(prove_canonical_tagged_batch(&[invalid]).is_err());
    }

    #[ignore = "slow prove (~4s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_uses_opened_nondefault_betting_timeout() {
        let mut extension = advance_deadline();
        extension.pre.betting_timeout_ms = 25;
        extension.post.betting_timeout_ms = 25;
        extension.action.amount = 25;
        extension.post.deadline_ms = extension.pre.deadline_ms + 25;
        extension.post.seats[0].time_bank_ms = 15;
        extension.seal();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&extension)).expect("custom timeout extension trace");
        assert_trace_satisfies_air(&trace, &archive);
        assert_air_rejects_trace_mutation(
            &trace,
            &archive,
            TIMEOUT_CONFIG_OFFSET + BETTING_TIMEOUT_LIMB_OFFSET,
        );
        assert_air_rejects_trace_mutation(
            &trace,
            &archive,
            TIMEOUT_CONFIG_RANGE_BITS_OFFSET + BETTING_TIMEOUT_LIMB_OFFSET * 16,
        );

        let mut auto = auto_fold();
        auto.pre.betting_timeout_ms = 5_000;
        auto.post.betting_timeout_ms = 5_000;
        auto.post.deadline_ms = auto.deadline_height + 5_000;
        auto.seal();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&auto)).expect("custom timeout auto-fold trace");
        assert_trace_satisfies_air(&trace, &archive);
    }

    #[ignore = "slow prove (~6s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_proves_auto_fold_timeout() {
        let witness = auto_fold();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("auto-fold trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("auto-fold proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("auto-fold verification");
    }

    #[test]
    fn canonical_direct_air_skips_an_already_acted_active_successor() {
        // The VM's turn scan skips an Active seat that has already acted in
        // this betting round. After seat zero times out, seat one is such a
        // stale active seat and seat two is the first actionable successor.
        let mut witness = auto_fold();
        witness.pre.max_players = 3;
        witness.post.max_players = 3;
        witness.pre.seats[1] = active_opponent(true, 100);
        witness.post.seats[1] = active_opponent(true, 100);
        witness.pre.seats[2] = CanonicalSeat {
            identity_commitment: [51; 32],
            key_commitment: [52; 32],
            hole_cards_commitment: [53; 32],
            ..active_opponent(false, 100)
        };
        witness.post.seats[2] = witness.pre.seats[2];
        witness.pre.acted_mask = 0b010;
        witness.post.acted_mask = 0b011;
        witness.pre.chip_pool = 2_200;
        witness.post.chip_pool = 2_200;
        witness.post.current_turn = 2;
        witness.seal();

        witness
            .validate_shape()
            .expect("native canonical auto-fold successor scan");
        let (trace, archive) = trace_for(std::slice::from_ref(&witness))
            .expect("auto-fold trace skipping stale successor");
        assert_trace_satisfies_air(&trace, &archive);
    }

    #[test]
    fn canonical_auto_fold_rejects_noncanonical_native_witnesses() {
        let cases: Vec<fn(&mut CanonicalTransitionWitness)> = vec![
            |w: &mut CanonicalTransitionWitness| w.deadline_height = 999,
            |w: &mut CanonicalTransitionWitness| w.post.current_turn = 0,
            |w: &mut CanonicalTransitionWitness| w.post.seats[1].acted = true,
            |w: &mut CanonicalTransitionWitness| w.post.pot += 1,
            |w: &mut CanonicalTransitionWitness| w.post.deadline_ms += 1,
            |w: &mut CanonicalTransitionWitness| w.actor = [1; 32],
            |w: &mut CanonicalTransitionWitness| {
                w.post.seats[0].status = CanonicalSeatStatus::Active
            },
        ];
        for (case_index, mutate) in cases.into_iter().enumerate() {
            let mut witness = auto_fold();
            mutate(&mut witness);
            witness.seal();
            assert!(trace_for(&[witness]).is_err(), "case {case_index} accepted");
        }
    }

    #[ignore = "slow prove (~6s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_rejects_auto_fold_advice_mutation() {
        let witness = auto_fold();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("auto-fold trace");
        assert_trace_satisfies_air(&trace, &archive);
        for column in [
            DEADLINE_HEIGHT_OFFSET,
            ADVANCE_DEADLINE_DIFFERENCE_OFFSET,
            ADVANCE_DEADLINE_CARRIES_OFFSET,
            ADVANCE_DEADLINE_EXTENSION_CARRIES_OFFSET,
            NEXT_TURN_SELECTOR_OFFSET + 1,
            NEXT_TURN_PAIR_OFFSET + 1,
            SELECTED_POST_STATUS_OFFSET,
            ACTION_AMOUNT_OFFSET,
            TRANSITION_SEAT_SELECTOR_OFFSET,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
    }

    #[ignore = "slow prove (~4s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_direct_air_rejects_betting_time_bank_extension_tampering() {
        let witness = advance_deadline();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("deadline trace");
        let selected_post_time_bank_offset = FULL_POST_BETTING_SEATS_OFFSET
            + FULL_SEAT_STACK_BLOCK_OFFSET
            + 4 * MAX_CANONICAL_SEATS * 4;
        for column in [
            ADVANCE_DEADLINE_TIME_BANK_ALL_OFFSET,
            ADVANCE_DEADLINE_TIME_BANK_SLACK_OFFSET,
            ADVANCE_DEADLINE_TIME_BANK_EXCESS_OFFSET,
            ADVANCE_DEADLINE_TIME_BANK_CARRIES_OFFSET,
            ADVANCE_DEADLINE_EXTENSION_CARRIES_OFFSET,
            selected_post_time_bank_offset,
            ACTION_AMOUNT_OFFSET,
            TRANSITION_SEAT_SELECTOR_OFFSET,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
    }

    #[test]
    fn canonical_direct_air_rejects_acted_mask_mutation_on_deadline_extension() {
        let mut witness = advance_deadline();
        witness.post.acted_mask = 1;
        witness.post.seats[0].acted = true;
        witness.seal();
        assert!(prove_canonical_tagged_batch(&[witness]).is_err());

        let witness = advance_deadline();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("deadline trace");
        // The endpoint acted-mask projection and the fixed seat bit opening
        // are both independently constrained by the AdvanceDeadline gate.
        assert_air_rejects_trace_mutation(&trace, &archive, 309);
        assert_air_rejects_trace_mutation(&trace, &archive, 1_405);
    }

    #[ignore = "slow prove (~6s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_archive_metadata_is_authenticated() {
        let archive = prove_canonical_tagged_batch(&[create_table()]).expect("canonical proof");
        let mut wrong_table = archive.clone();
        wrong_table.table_id ^= 1;
        assert!(verify_canonical_tagged_proof(&wrong_table).is_err());

        let mut wrong_post = archive.clone();
        wrong_post.post_state_commitment[0] ^= 1;
        assert!(verify_canonical_tagged_proof(&wrong_post).is_err());

        let mut wrong_state_root = archive.clone();
        wrong_state_root.post_state_root[0] ^= 1;
        assert!(verify_canonical_tagged_proof(&wrong_state_root).is_err());

        let mut wrong_count = archive;
        wrong_count.transition_count = 2;
        assert!(verify_canonical_tagged_proof(&wrong_count).is_err());
    }

    #[ignore = "slow prove (~4s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_archive_rejects_detached_endpoint_image_bytes() {
        let archive = prove_canonical_tagged_batch(&[create_table()]).expect("canonical proof");
        let mut tampered = archive.clone();
        tampered.pre_state_image_bytes[0] ^= 1;
        assert!(verify_canonical_tagged_proof(&tampered).is_err());
    }

    #[ignore = "slow prove (~4s); full gate runs `--include-ignored`"]
    #[test]
    fn canonical_archive_rejects_proof_without_trace_commitment_without_panicking() {
        let archive = prove_canonical_tagged_batch(&[create_table()]).expect("canonical proof");
        let mut proof: StarkProof<Poseidon252MerkleHasher> = options()
            .deserialize(&archive.stark_proof_bytes)
            .expect("stark proof deserialization");
        proof.0.commitments.truncate(1);

        let mut tampered = archive;
        tampered.stark_proof_bytes = options()
            .serialize(&proof)
            .expect("stark proof serialization");
        let result = std::panic::catch_unwind(|| verify_canonical_tagged_proof(&tampered));
        assert!(result.is_ok(), "short commitment vector must not panic");
        assert!(result.expect("verification result").is_err());
    }

    /// 整手牌 canonical STARK 证明性能扫描（2026-09-10，#41-#48 trace 优化后）。
    ///
    /// 一手完整牌局按当前 direct-AIR 可证边界拆成四个 batch
    /// （SubmitReveal 专用 crypto AIR 未接入前，Revealing→Betting 桥是
    /// TODO #22 的已知缺口，跨段由生产侧另行续链）：
    /// 1. `桌务+洗牌协议`：JoinTable ×3 → StartHand → SubmitShuffle ×2
    ///    （非最终）→ SubmitShuffle 完成（Shuffle completion opening，
    ///    进入 Revealing）。
    /// 2. `下注街`：Bet → Call → AdvanceRound（betting 入场镜像既有
    ///    betting 测试的合成 pre；street 2→3 翻牌→转牌）。
    /// 3. `终局结算`：EndWithoutShowdown（未摊牌独赢 + 下一手重置投影）。
    /// 4. `超时重置`：ResetOnly（零底注归一化，独立 batch 类别）。
    ///
    /// 每段独立 prove/verify 计时并输出证明体积；主链三段（1-3）合计即
    /// 一手牌的证明成本，段 4 为辅助归一化类别。带 `--ignored --nocapture`
    /// 运行。
    #[ignore = "slow prove (full hand, 4 batches); run via `-- --ignored --nocapture`"]
    #[test]
    fn canonical_full_hand_proof_perf_sweep() {
        let started = std::time::Instant::now();

        // ---- 段 1：桌务 + 洗牌协议（7 个转移，承诺逐环相扣）。
        // 三人桌：两人局中第二次提交必为"最终提交"。含 ShuffleComplete
        // 完成行（2026-09-10 修复 AIR subtag 约束笔误后首次端到端可证）。
        let mut base = image();
        base.max_players = 3;
        let join0 = join_table_at(base, 0, [2; 32], [31; 32], [32; 32]);
        let join1 = join_table_at(join0.post.clone(), 1, [3; 32], [35; 32], [36; 32]);
        let join2 = join_table_at(join1.post.clone(), 2, [4; 32], [37; 32], [38; 32]);
        let mut start_post = join2.post.clone();
        start_post.hand_id = 2;
        start_post.button = 1;
        start_post.phase = CanonicalPhase::Shuffling;
        start_post.phase_subtag = 1;
        start_post.deadline_ms = 100;
        start_post.protocol_pending_mask = 0b111;
        start_post.call_seq = 0;
        start_post.seats[0].status = CanonicalSeatStatus::Active;
        start_post.seats[1].status = CanonicalSeatStatus::Active;
        start_post.seats[2].status = CanonicalSeatStatus::Active;
        let mut start = CanonicalTransitionWitness {
            pre: join2.post.clone(),
            post: start_post,
            kind: CanonicalTransitionKind::StartHand,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        start.seal();

        let mut shuffle0_post = start.post.clone();
        shuffle0_post.call_seq += 1;
        shuffle0_post.deck_commitment = [54; 32];
        shuffle0_post.protocol_pending_mask = 0b110;
        let mut shuffle0 = CanonicalTransitionWitness {
            pre: start.post.clone(),
            post: shuffle0_post,
            kind: CanonicalTransitionKind::SubmitShuffle,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [53; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        shuffle0.seal();

        // 第二位贡献者的 shuffle 提交（非最终形态：3 人局仍余 1 位待提交）。
        let mut shuffle1_post = shuffle0.post.clone();
        shuffle1_post.call_seq += 1;
        shuffle1_post.deck_commitment = [55; 32];
        shuffle1_post.protocol_pending_mask = 0b100;
        let mut shuffle1 = CanonicalTransitionWitness {
            pre: shuffle0.post.clone(),
            post: shuffle1_post,
            kind: CanonicalTransitionKind::SubmitShuffle,
            actor: [82; 32],
            action: CanonicalActionPayload {
                seat: 1,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [83; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        shuffle1.seal();

        // 第三位（最后一位待提交）贡献者的完成提交：轮转终局 deck 并经
        // Shuffle completion opening 规范化进入 preflop reveal 相位
        // （hole 游标 0→2×3 参与者，reveal pending = 活跃集）。
        let completion_timestamp = 9_000;
        let mut final_post = shuffle1.post.clone();
        final_post.call_seq += 1;
        final_post.phase = CanonicalPhase::Revealing;
        final_post.deadline_ms =
            completion_timestamp + u64::from(shuffle1.post.reveal_timeout_ms);
        final_post.protocol_pending_mask = 0b111;
        final_post.deck_commitment = [50; 32];
        let mut final_submit = CanonicalTransitionWitness {
            pre: shuffle1.post.clone(),
            post: final_post,
            kind: CanonicalTransitionKind::SubmitShuffle,
            actor: [84; 32],
            action: CanonicalActionPayload {
                seat: 2,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [85; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: crate::texas_canonical::CanonicalProtocolCompletionOpening {
                kind: crate::texas_canonical::CanonicalProtocolCompletionKind::Shuffle,
                completion_timestamp_ms: completion_timestamp,
                pre_cards_dealt: 0,
                post_cards_dealt: 6,
                suspended_reveal_commitment: [0; 32],
                post_shuffle_pending_mask: 0b111,
                post_shuffle_completed_mask: 0b111,
                pre_deck_commitment: shuffle1.post.deck_commitment,
                post_deck_commitment: [50; 32],
                pre_reconstruction_commitment: shuffle1.post.reconstruction_commitment,
                post_reconstruction_commitment: shuffle1.post.reconstruction_commitment,
                ..Default::default()
            },
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        final_submit.seal();

        // ---- 段 2：下注街（3 个转移；street 2 翻牌圈，bet 入场为既有
        // betting 测试同款合成 pre） ----
        let bet_witness = bet();
        let mut call_pre = bet_witness.post.clone();
        let mut call_post = call_pre.clone();
        call_post.call_seq += 1;
        call_post.current_turn = NO_CANONICAL_SEAT;
        call_post.acted_mask = 0b11;
        call_post.seats[1].acted = true;
        call_post.seats[1].stack -= 100;
        call_post.seats[1].bet = 100;
        call_post.seats[1].total_bet = 100;
        let mut call_witness = CanonicalTransitionWitness {
            pre: call_pre,
            post: call_post,
            kind: CanonicalTransitionKind::Call,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 1,
                amount: 100,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        call_witness.seal();

        let mut advance_post = call_witness.post.clone();
        advance_post.call_seq += 1;
        advance_post.phase = CanonicalPhase::Revealing;
        advance_post.phase_subtag = 2;
        advance_post.street = 3;
        advance_post.deadline_ms = 200;
        advance_post.protocol_pending_mask = 0b11;
        advance_post.current_bet = 0;
        advance_post.min_raise = 0;
        advance_post.pot = 200;
        for seat in &mut advance_post.seats {
            seat.bet = 0;
        }
        let mut advance_witness = CanonicalTransitionWitness {
            pre: call_witness.post.clone(),
            post: advance_post,
            kind: CanonicalTransitionKind::AdvanceRound,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening {
                pre_cards_dealt: 7,
                post_cards_dealt: 8,
                pre_board_len: 3,
                post_board_len: 3,
                pre_second_board_len: 0,
                post_second_board_len: 0,
                run_it_twice: false,
                reveal_purpose: 2,
                assignment_count: 1,
                assignments: [
                    CanonicalBoardRevealAssignment {
                        present: true,
                        encrypted_card_index: 7,
                        runout_index: 0,
                        board_position: 3,
                        pending_mask: 0b11,
                        submitted_mask: 0,
                    },
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                ],
            },
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: crate::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        advance_witness.seal();

        // ---- 段 3：终局结算（未摊牌独赢，含下一手重置投影，1 个转移）。
        // ResetOnly 不能链接在其后：host 校验拒绝 Waiting→Waiting，
        // 它是零底注超时/错误状态的独立归一化 batch（作为辅助段单测）。
        let end_witness = end_without_showdown();
        let aux_reset = reset_only();

        let segments: [(&str, Vec<CanonicalTransitionWitness>); 4] = [
            (
                "table+shuffle protocol",
                vec![join0, join1, join2, start, shuffle0, shuffle1, final_submit],
            ),
            ("betting street", vec![bet_witness, call_witness, advance_witness]),
            ("terminal settlement", vec![end_witness]),
            ("timeout reset (aux)", vec![aux_reset]),
        ];

        println!(
            "{:<24} {:>5} {:>8} {:>12} {:>12} {:>10}",
            "segment", "txs", "log2", "prove_ms", "verify_ms", "proof_kb"
        );
        let mut total_prove = std::time::Duration::ZERO;
        let mut total_verify = std::time::Duration::ZERO;
        let mut total_bytes = 0usize;
        let mut total_transitions = 0usize;
        for (name, witnesses) in &segments {
            for witness in witnesses {
                witness
                    .validate_shape()
                    .unwrap_or_else(|e| panic!("{name}: invalid shape: {e}"));
            }
            let prove_started = std::time::Instant::now();
            let archive = prove_canonical_tagged_batch(witnesses)
                .unwrap_or_else(|e| panic!("{name}: prove failed: {e}"));
            let prove_elapsed = prove_started.elapsed();
            let verify_started = std::time::Instant::now();
            verify_canonical_tagged_proof(&archive)
                .unwrap_or_else(|e| panic!("{name}: verify failed: {e}"));
            verify_canonical_tagged_batch(witnesses, &archive)
                .unwrap_or_else(|e| panic!("{name}: batch verify failed: {e}"));
            let verify_elapsed = verify_started.elapsed();

            total_prove += prove_elapsed;
            total_verify += verify_elapsed;
            total_bytes += archive.stark_proof_bytes.len();
            total_transitions += witnesses.len();
            println!(
                "{:<24} {:>5} {:>8} {:>12} {:>12} {:>10.1}",
                name,
                witnesses.len(),
                archive.log_size,
                prove_elapsed.as_millis(),
                verify_elapsed.as_millis(),
                archive.stark_proof_bytes.len() as f64 / 1024.0,
            );
        }
        println!(
            "{:<24} {:>5} {:>8} {:>12} {:>12} {:>10.1}",
            "FULL HAND TOTAL",
            total_transitions,
            "-",
            total_prove.as_millis(),
            total_verify.as_millis(),
            total_bytes as f64 / 1024.0,
        );
        println!(
            "wall clock (incl. trace gen + validation): {:?}",
            started.elapsed()
        );
    }
}
