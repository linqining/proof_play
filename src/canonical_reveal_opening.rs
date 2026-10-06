//! Fixed-width authenticated opening for the VM reveal-assignment ledger.
//!
//! `CanonicalStateImage::protocol_pending_mask` is only the union projection
//! used by the transition AIR.  The VM derives it from every
//! `RevealAssignment.pending_mask`; this module authenticates that ledger
//! before a timeout cascade is allowed to consume the projection.
#![allow(missing_docs)]

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::{ArchivedHashProof, HashStatement, HashProofProvider as _};
use crate::trace_gen::MethodTrace;

pub const CANONICAL_REVEAL_OPENING_MAGIC: [u8; 4] = *b"ZR4A";
pub const CANONICAL_REVEAL_OPENING_VERSION: u8 = 3;
/// Two hole-card assignments per seat is the largest fixed reveal batch
/// (9 seats × 2 cards).  Board reveals use a smaller prefix of this array.
pub const MAX_CANONICAL_REVEAL_ASSIGNMENTS: usize = 2 * 9;
/// Upper bound for the transport envelope.  The fixed ledger itself is small;
/// the bound mainly prevents an attacker from allocating an unbounded lookup
/// proof payload during archive decoding.
pub const MAX_CANONICAL_REVEAL_OPENING_BYTES: usize = 16 * 1024 * 1024;
const REVEAL_OPENING_DOMAIN: &[u8] = b"zchain.texas.canonical-reveal-opening.v3";
// The structural gadget uses a compact fixed domain; all non-zero
// checks are expressed with dedicated inverse advice columns.
const PENDING_UNION_AIR_LOG_SIZE: u32 = 5;
const PENDING_UNION_AIR_SEAT_BITS: usize = 9;
pub const REVEAL_TIMEOUT_SCHEDULE_EMPTY: u8 = u8::MAX;
const REVEAL_ASSIGNMENT_FIELDS: usize = 9;
const PENDING_UNION_AIR_SCOPE_COLUMNS: usize =
    4 + MAX_CANONICAL_REVEAL_ASSIGNMENTS * REVEAL_ASSIGNMENT_FIELDS + PENDING_UNION_AIR_SEAT_BITS;
// The first block mirrors the full fixed-width ledger.  Everything after it
// is witness-only range, OR, and ordering advice constrained below.
const PENDING_UNION_AIR_TRACE_COLUMNS: usize = MAX_CANONICAL_REVEAL_ASSIGNMENTS
    * REVEAL_ASSIGNMENT_FIELDS
    + MAX_CANONICAL_REVEAL_ASSIGNMENTS
    + MAX_CANONICAL_REVEAL_ASSIGNMENTS * PENDING_UNION_AIR_SEAT_BITS * 2
    + PENDING_UNION_AIR_SEAT_BITS
    + PENDING_UNION_AIR_SEAT_BITS
    + MAX_CANONICAL_REVEAL_ASSIGNMENTS * PENDING_UNION_AIR_SEAT_BITS
    + MAX_CANONICAL_REVEAL_ASSIGNMENTS * 6
    + MAX_CANONICAL_REVEAL_ASSIGNMENTS
    + MAX_CANONICAL_REVEAL_ASSIGNMENTS * 4
    + MAX_CANONICAL_REVEAL_ASSIGNMENTS * 3
    + (MAX_CANONICAL_REVEAL_ASSIGNMENTS - 1) * 5
    + (MAX_CANONICAL_REVEAL_ASSIGNMENTS - 1)
    + MAX_CANONICAL_REVEAL_ASSIGNMENTS * (MAX_CANONICAL_REVEAL_ASSIGNMENTS - 1) / 2;
const PENDING_UNION_AIR_DOMAIN: &[u8] = b"zchain.texas.canonical-reveal-pending-union-air.v2";

fn pending_union_twiddle_log_size(config: &stwo::core::pcs::PcsConfig) -> u32 {
    PENDING_UNION_AIR_LOG_SIZE + config.fri_config.log_blowup_factor
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCanonicalRevealPendingUnionProof {
    /// Seat-indexed canonical kick schedule.  Slot `i` is `i` exactly when
    /// bit `i` is pending; otherwise it is the fixed empty sentinel.
    pub kick_schedule: [u8; PENDING_UNION_AIR_SEAT_BITS],
    pub stark_proof_bytes: Vec<u8>,
}

fn reveal_timeout_kick_schedule(
    opening: &CanonicalRevealLedgerOpening,
) -> [u8; PENDING_UNION_AIR_SEAT_BITS] {
    std::array::from_fn(|seat| {
        if opening.pending_union & (1u16 << seat) != 0 {
            seat as u8
        } else {
            REVEAL_TIMEOUT_SCHEDULE_EMPTY
        }
    })
}

fn pending_union_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

fn pending_union_ids() -> &'static [PreProcessedColumnId] {
    static IDS: std::sync::OnceLock<Vec<PreProcessedColumnId>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| {
        (0..PENDING_UNION_AIR_SCOPE_COLUMNS)
            .map(|index| PreProcessedColumnId {
                id: format!("canonical.reveal.pending-union.v1.{index}").into(),
            })
            .collect()
    })
}

fn pending_union_scope(
    opening: &CanonicalRevealLedgerOpening,
    schedule: &[u8; PENDING_UNION_AIR_SEAT_BITS],
) -> MethodTrace {
    let mut row = Vec::with_capacity(PENDING_UNION_AIR_SCOPE_COLUMNS);
    row.extend([
        M31::from(u32::from(opening.phase)),
        M31::from(u32::from(opening.street)),
        M31::from(u32::from(opening.assignment_count)),
        M31::from(u32::from(opening.pending_union)),
    ]);
    for assignment in &opening.assignments {
        row.push(M31::from(u32::from(assignment.present)));
        row.push(M31::from(u32::from(assignment.encrypted_card_index)));
        row.push(M31::from(u32::from(assignment.target_kind)));
        row.push(M31::from(u32::from(assignment.target_seat)));
        row.push(M31::from(u32::from(assignment.target_slot)));
        row.push(M31::from(u32::from(assignment.runout_index)));
        row.push(M31::from(u32::from(assignment.board_position)));
        row.push(M31::from(u32::from(assignment.pending_mask)));
        row.push(M31::from(u32::from(assignment.submitted_mask)));
    }
    row.extend(
        schedule
            .iter()
            .copied()
            .map(|seat| M31::from(u32::from(seat))),
    );
    let mut trace = MethodTrace::new(PENDING_UNION_AIR_LOG_SIZE, PENDING_UNION_AIR_SCOPE_COLUMNS);
    for index in 0..(1 << PENDING_UNION_AIR_LOG_SIZE) {
        trace
            .write_row(index, &row)
            .expect("fixed pending-union scope width");
    }
    trace
}

fn pending_union_trace(
    opening: &CanonicalRevealLedgerOpening,
    schedule: &[u8; PENDING_UNION_AIR_SEAT_BITS],
) -> MethodTrace {
    let mut row = Vec::with_capacity(PENDING_UNION_AIR_TRACE_COLUMNS);
    for assignment in &opening.assignments {
        row.push(M31::from(u32::from(assignment.present)));
        row.push(M31::from(u32::from(assignment.encrypted_card_index)));
        row.push(M31::from(u32::from(assignment.target_kind)));
        row.push(M31::from(u32::from(assignment.target_seat)));
        row.push(M31::from(u32::from(assignment.target_slot)));
        row.push(M31::from(u32::from(assignment.runout_index)));
        row.push(M31::from(u32::from(assignment.board_position)));
        row.push(M31::from(u32::from(assignment.pending_mask)));
        row.push(M31::from(u32::from(assignment.submitted_mask)));
    }
    for assignment in &opening.assignments {
        let target_key = if assignment.present {
            if assignment.target_kind == 0 {
                assignment.target_seat * 2 + assignment.target_slot
            } else {
                18 + assignment.runout_index * 5 + assignment.board_position
            }
        } else {
            0
        };
        row.push(M31::from(u32::from(target_key)));
    }
    for assignment in &opening.assignments {
        for seat in 0..PENDING_UNION_AIR_SEAT_BITS {
            row.push(M31::from(u32::from((assignment.pending_mask >> seat) & 1)));
        }
    }
    for assignment in &opening.assignments {
        for seat in 0..PENDING_UNION_AIR_SEAT_BITS {
            row.push(M31::from(u32::from(
                (assignment.submitted_mask >> seat) & 1,
            )));
        }
    }
    for seat in 0..PENDING_UNION_AIR_SEAT_BITS {
        row.push(M31::from(u32::from((opening.pending_union >> seat) & 1)));
    }
    // Fixed schedule slots are seat-indexed.  This is exactly the VM's
    // `seat_mask_to_indices` order, with no host-selected permutation.
    for seat in 0..PENDING_UNION_AIR_SEAT_BITS {
        row.push(M31::from(u32::from(schedule[seat])));
    }
    for seat in 0..PENDING_UNION_AIR_SEAT_BITS {
        let mut running = 0u16;
        for assignment in &opening.assignments {
            running |= (assignment.pending_mask >> seat) & 1;
            row.push(M31::from(u32::from(running)));
        }
    }
    for assignment in &opening.assignments {
        for bit in 0..6 {
            row.push(M31::from(u32::from(
                (assignment.encrypted_card_index >> bit) & 1,
            )));
        }
    }
    for assignment in &opening.assignments {
        row.push(M31::from(u32::from(
            ((assignment.encrypted_card_index >> 5) & 1)
                * ((assignment.encrypted_card_index >> 4) & 1),
        )));
    }
    for assignment in &opening.assignments {
        for bit in 0..4 {
            row.push(M31::from(u32::from((assignment.target_seat >> bit) & 1)));
        }
    }
    for assignment in &opening.assignments {
        for bit in 0..3 {
            row.push(M31::from(u32::from((assignment.board_position >> bit) & 1)));
        }
    }
    for pair in opening.assignments.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        let key = |assignment: &CanonicalRevealAssignmentOpening| -> u8 {
            if assignment.target_kind == 0 {
                assignment.target_seat * 2 + assignment.target_slot
            } else {
                18 + assignment.runout_index * 5 + assignment.board_position
            }
        };
        let difference = if current.present {
            key(current) - key(previous)
        } else {
            0
        };
        for bit in 0..5 {
            row.push(M31::from(u32::from((difference >> bit) & 1)));
        }
    }
    for pair in opening.assignments.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        let key = |assignment: &CanonicalRevealAssignmentOpening| -> u8 {
            if assignment.target_kind == 0 {
                assignment.target_seat * 2 + assignment.target_slot
            } else {
                18 + assignment.runout_index * 5 + assignment.board_position
            }
        };
        let difference = if current.present {
            u32::from(key(current) - key(previous))
        } else {
            0
        };
        row.push(if difference == 0 {
            M31::from(0u32)
        } else {
            M31::from(difference).inverse()
        });
    }
    for later in 1..MAX_CANONICAL_REVEAL_ASSIGNMENTS {
        for earlier in 0..later {
            let difference = i32::from(opening.assignments[later].encrypted_card_index)
                - i32::from(opening.assignments[earlier].encrypted_card_index);
            row.push(if opening.assignments[later].present {
                M31::from(difference).inverse()
            } else {
                M31::from(0u32)
            });
        }
    }
    debug_assert_eq!(row.len(), PENDING_UNION_AIR_TRACE_COLUMNS);
    let mut trace = MethodTrace::new(PENDING_UNION_AIR_LOG_SIZE, PENDING_UNION_AIR_TRACE_COLUMNS);
    for index in 0..(1 << PENDING_UNION_AIR_LOG_SIZE) {
        trace
            .write_row(index, &row)
            .expect("fixed pending-union trace width");
    }
    trace
}

#[derive(Clone, Copy)]
struct CanonicalRevealPendingUnionAir;

impl FrameworkEval for CanonicalRevealPendingUnionAir {
    fn log_size(&self) -> u32 {
        PENDING_UNION_AIR_LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        PENDING_UNION_AIR_LOG_SIZE + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = M31::from(1u32).into();
        let _phase = eval.get_preprocessed_column(pending_union_ids()[0].clone());
        let _street = eval.get_preprocessed_column(pending_union_ids()[1].clone());
        let count = eval.get_preprocessed_column(pending_union_ids()[2].clone());
        let union = eval.get_preprocessed_column(pending_union_ids()[3].clone());
        let mut present: Vec<E::F> = Vec::with_capacity(MAX_CANONICAL_REVEAL_ASSIGNMENTS);
        let mut cards: Vec<E::F> = Vec::with_capacity(MAX_CANONICAL_REVEAL_ASSIGNMENTS);
        let mut kinds: Vec<E::F> = Vec::with_capacity(MAX_CANONICAL_REVEAL_ASSIGNMENTS);
        let mut seats: Vec<E::F> = Vec::with_capacity(MAX_CANONICAL_REVEAL_ASSIGNMENTS);
        let mut slots: Vec<E::F> = Vec::with_capacity(MAX_CANONICAL_REVEAL_ASSIGNMENTS);
        let mut runouts: Vec<E::F> = Vec::with_capacity(MAX_CANONICAL_REVEAL_ASSIGNMENTS);
        let mut boards: Vec<E::F> = Vec::with_capacity(MAX_CANONICAL_REVEAL_ASSIGNMENTS);
        let mut pending_masks: Vec<E::F> = Vec::with_capacity(MAX_CANONICAL_REVEAL_ASSIGNMENTS);
        let mut submitted_masks: Vec<E::F> = Vec::with_capacity(MAX_CANONICAL_REVEAL_ASSIGNMENTS);
        for index in 0..MAX_CANONICAL_REVEAL_ASSIGNMENTS {
            let trace_present = eval.next_trace_mask();
            let trace_card = eval.next_trace_mask();
            let trace_kind = eval.next_trace_mask();
            let trace_seat = eval.next_trace_mask();
            let trace_slot = eval.next_trace_mask();
            let trace_runout = eval.next_trace_mask();
            let trace_board = eval.next_trace_mask();
            let trace_pending = eval.next_trace_mask();
            let trace_submitted = eval.next_trace_mask();
            let ids = pending_union_ids();
            let scope = 4 + REVEAL_ASSIGNMENT_FIELDS * index;
            let trace_values = [
                trace_present.clone(),
                trace_card.clone(),
                trace_kind.clone(),
                trace_seat.clone(),
                trace_slot.clone(),
                trace_runout.clone(),
                trace_board.clone(),
                trace_pending.clone(),
                trace_submitted.clone(),
            ];
            for (offset, value) in trace_values.into_iter().enumerate() {
                let scope_value = eval.get_preprocessed_column(ids[scope + offset].clone());
                eval.add_constraint(value - scope_value);
            }
            eval.add_constraint(trace_present.clone() * (trace_present.clone() - one.clone()));
            if index > 0 {
                eval.add_constraint(
                    trace_present.clone() * (one.clone() - present[index - 1].clone()),
                );
            }
            present.push(trace_present);
            cards.push(trace_card);
            kinds.push(trace_kind);
            seats.push(trace_seat);
            slots.push(trace_slot);
            runouts.push(trace_runout);
            boards.push(trace_board);
            pending_masks.push(trace_pending);
            submitted_masks.push(trace_submitted);
        }
        let target_keys: Vec<E::F> = (0..MAX_CANONICAL_REVEAL_ASSIGNMENTS)
            .map(|_| eval.next_trace_mask())
            .collect();
        let pending_bits: [[E::F; PENDING_UNION_AIR_SEAT_BITS]; MAX_CANONICAL_REVEAL_ASSIGNMENTS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let submitted_bits: [[E::F; PENDING_UNION_AIR_SEAT_BITS];
            MAX_CANONICAL_REVEAL_ASSIGNMENTS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let union_bits: [E::F; PENDING_UNION_AIR_SEAT_BITS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let schedule_seat: [E::F; PENDING_UNION_AIR_SEAT_BITS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let running: [[E::F; MAX_CANONICAL_REVEAL_ASSIGNMENTS]; PENDING_UNION_AIR_SEAT_BITS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let card_bits: [[E::F; 6]; MAX_CANONICAL_REVEAL_ASSIGNMENTS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let card_high_products: [E::F; MAX_CANONICAL_REVEAL_ASSIGNMENTS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let seat_bits: [[E::F; 4]; MAX_CANONICAL_REVEAL_ASSIGNMENTS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let board_bits: [[E::F; 3]; MAX_CANONICAL_REVEAL_ASSIGNMENTS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let target_difference_bits: [[E::F; 5]; MAX_CANONICAL_REVEAL_ASSIGNMENTS - 1] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let target_difference_inverse: [E::F; MAX_CANONICAL_REVEAL_ASSIGNMENTS - 1] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let mut card_difference_inverse: Vec<E::F> = Vec::with_capacity(
            MAX_CANONICAL_REVEAL_ASSIGNMENTS * (MAX_CANONICAL_REVEAL_ASSIGNMENTS - 1) / 2,
        );
        for later in 1..MAX_CANONICAL_REVEAL_ASSIGNMENTS {
            for _ in 0..later {
                card_difference_inverse.push(eval.next_trace_mask());
            }
        }

        let mut present_sum: E::F = M31::from(0u32).into();
        for value in &present {
            present_sum += value.clone();
        }
        eval.add_constraint(present_sum - count);
        let mut union_reconstructed: E::F = M31::from(0u32).into();
        for seat in 0..PENDING_UNION_AIR_SEAT_BITS {
            let schedule_scope =
                4 + MAX_CANONICAL_REVEAL_ASSIGNMENTS * REVEAL_ASSIGNMENT_FIELDS + seat;
            let schedule_scope_value =
                eval.get_preprocessed_column(pending_union_ids()[schedule_scope].clone());
            eval.add_constraint(schedule_seat[seat].clone() - schedule_scope_value);
            eval.add_constraint(
                schedule_seat[seat].clone()
                    - (E::F::from(M31::from(seat as u32)) * union_bits[seat].clone()
                        + E::F::from(M31::from(u32::from(REVEAL_TIMEOUT_SCHEDULE_EMPTY)))
                            * (one.clone() - union_bits[seat].clone())),
            );
            let weight: E::F = M31::from(1u32 << seat).into();
            eval.add_constraint(
                union_bits[seat].clone() * (union_bits[seat].clone() - one.clone()),
            );
            union_reconstructed += union_bits[seat].clone() * weight.clone();
            for assignment in 0..MAX_CANONICAL_REVEAL_ASSIGNMENTS {
                let bit = pending_bits[assignment][seat].clone();
                eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                eval.add_constraint((one.clone() - present[assignment].clone()) * bit.clone());
                let submitted = submitted_bits[assignment][seat].clone();
                eval.add_constraint(submitted.clone() * (submitted.clone() - one.clone()));
                eval.add_constraint(
                    (one.clone() - present[assignment].clone()) * submitted.clone(),
                );
                eval.add_constraint(bit.clone() * submitted);
                if assignment == 0 {
                    eval.add_constraint(running[seat][assignment].clone() - bit);
                } else {
                    let prior = running[seat][assignment - 1].clone();
                    eval.add_constraint(
                        running[seat][assignment].clone()
                            - (prior.clone() + bit.clone() - prior * bit),
                    );
                }
                eval.add_constraint(
                    running[seat][assignment].clone()
                        * (running[seat][assignment].clone() - one.clone()),
                );
            }
            eval.add_constraint(
                union_bits[seat].clone()
                    - running[seat][MAX_CANONICAL_REVEAL_ASSIGNMENTS - 1].clone(),
            );
        }
        // Reconstruct every assignment mask from its nine boolean bits.
        for assignment in 0..MAX_CANONICAL_REVEAL_ASSIGNMENTS {
            let mut pending_reconstructed: E::F = M31::from(0u32).into();
            let mut submitted_reconstructed: E::F = M31::from(0u32).into();
            for seat in 0..PENDING_UNION_AIR_SEAT_BITS {
                pending_reconstructed +=
                    pending_bits[assignment][seat].clone() * E::F::from(M31::from(1u32 << seat));
                submitted_reconstructed +=
                    submitted_bits[assignment][seat].clone() * E::F::from(M31::from(1u32 << seat));
            }
            eval.add_constraint(pending_masks[assignment].clone() - pending_reconstructed);
            eval.add_constraint(submitted_masks[assignment].clone() - submitted_reconstructed);
        }
        eval.add_constraint(union - union_reconstructed);

        for assignment in 0..MAX_CANONICAL_REVEAL_ASSIGNMENTS {
            let present_value = present[assignment].clone();
            let kind = kinds[assignment].clone();
            let slot = slots[assignment].clone();
            let runout = runouts[assignment].clone();
            eval.add_constraint(kind.clone() * (kind.clone() - one.clone()));
            eval.add_constraint(slot.clone() * (slot.clone() - one.clone()));
            eval.add_constraint(runout.clone() * (runout.clone() - one.clone()));
            for value in [
                cards[assignment].clone(),
                kind.clone(),
                seats[assignment].clone(),
                slot.clone(),
                runout.clone(),
                boards[assignment].clone(),
                pending_masks[assignment].clone(),
                submitted_masks[assignment].clone(),
            ] {
                eval.add_constraint((one.clone() - present_value.clone()) * value);
            }
            let mut card_reconstructed: E::F = M31::from(0u32).into();
            for bit in 0..6 {
                let value = card_bits[assignment][bit].clone();
                eval.add_constraint(value.clone() * (value.clone() - one.clone()));
                card_reconstructed += value * E::F::from(M31::from(1u32 << bit));
            }
            eval.add_constraint(cards[assignment].clone() - card_reconstructed);
            // A six-bit card value is below 52 iff its high two bits do not
            // select 52..63: 110100..111111 are excluded.
            eval.add_constraint(
                card_high_products[assignment].clone()
                    - card_bits[assignment][5].clone() * card_bits[assignment][4].clone(),
            );
            eval.add_constraint(
                card_high_products[assignment].clone()
                    * (card_bits[assignment][3].clone() + card_bits[assignment][2].clone()),
            );
            let mut seat_reconstructed: E::F = M31::from(0u32).into();
            for bit in 0..4 {
                let value = seat_bits[assignment][bit].clone();
                eval.add_constraint(value.clone() * (value.clone() - one.clone()));
                seat_reconstructed += value * E::F::from(M31::from(1u32 << bit));
            }
            eval.add_constraint(seats[assignment].clone() - seat_reconstructed);
            eval.add_constraint(
                seat_bits[assignment][3].clone()
                    * (seat_bits[assignment][2].clone()
                        + seat_bits[assignment][1].clone()
                        + seat_bits[assignment][0].clone()),
            );
            let mut board_reconstructed: E::F = M31::from(0u32).into();
            for bit in 0..3 {
                let value = board_bits[assignment][bit].clone();
                eval.add_constraint(value.clone() * (value.clone() - one.clone()));
                board_reconstructed += value * E::F::from(M31::from(1u32 << bit));
            }
            eval.add_constraint(boards[assignment].clone() - board_reconstructed);
            eval.add_constraint(
                board_bits[assignment][2].clone()
                    * (board_bits[assignment][1].clone() + board_bits[assignment][0].clone()),
            );
            // Hole and board targets own disjoint fields, so no ignored host
            // metadata can be smuggled through their typed padding.
            eval.add_constraint((one.clone() - kind.clone()) * runout.clone());
            eval.add_constraint((one.clone() - kind.clone()) * boards[assignment].clone());
            eval.add_constraint(kind.clone() * seats[assignment].clone());
            eval.add_constraint(kind.clone() * slot);
        }
        for later in 1..MAX_CANONICAL_REVEAL_ASSIGNMENTS {
            let prior = later - 1;
            let target_key = |index: usize| {
                (one.clone() - kinds[index].clone())
                    * (seats[index].clone() * E::F::from(M31::from(2u32)) + slots[index].clone())
                    + kinds[index].clone()
                        * (E::F::from(M31::from(18u32))
                            + runouts[index].clone() * E::F::from(M31::from(5u32))
                            + boards[index].clone())
            };
            let mut difference: E::F = M31::from(0u32).into();
            for bit in 0..5 {
                let value = target_difference_bits[prior][bit].clone();
                eval.add_constraint(value.clone() * (value.clone() - one.clone()));
                difference += value * E::F::from(M31::from(1u32 << bit));
            }
            eval.add_constraint(
                present[later].clone()
                    * (difference.clone()
                        - (target_keys[later].clone() - target_keys[prior].clone())),
            );
            eval.add_constraint(target_keys[later].clone() - target_key(later));
            eval.add_constraint(
                difference * target_difference_inverse[prior].clone() - present[later].clone(),
            );
        }
        let mut inverse_index = 0;
        for later in 1..MAX_CANONICAL_REVEAL_ASSIGNMENTS {
            for earlier in 0..later {
                eval.add_constraint(
                    (cards[later].clone() - cards[earlier].clone())
                        * card_difference_inverse[inverse_index].clone()
                        - present[later].clone(),
                );
                inverse_index += 1;
            }
        }
        eval
    }
}

fn mix_pending_union_scope(
    channel: &mut impl Channel,
    opening: &CanonicalRevealLedgerOpening,
    schedule: &[u8; PENDING_UNION_AIR_SEAT_BITS],
) {
    let bytes = borsh::to_vec(opening).expect("canonical reveal opening is serializable");
    channel.mix_u32s(&[u32::from(CANONICAL_REVEAL_OPENING_VERSION)]);
    channel.mix_u32s(&bytes.into_iter().map(u32::from).collect::<Vec<_>>());
    channel.mix_u32s(
        &PENDING_UNION_AIR_DOMAIN
            .iter()
            .copied()
            .map(u32::from)
            .collect::<Vec<_>>(),
    );
    channel.mix_u32s(
        &schedule
            .iter()
            .map(|value| u32::from(*value))
            .collect::<Vec<_>>(),
    );
}

pub fn prove_canonical_reveal_pending_union(
    opening: &CanonicalRevealLedgerOpening,
) -> TexasAirResult<ArchivedCanonicalRevealPendingUnionProof> {
    opening.validate()?;
    let schedule = reveal_timeout_kick_schedule(opening);
    let trace = pending_union_trace(opening, &schedule);
    let scope = pending_union_scope(opening, &schedule);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles = crate::prover_context::simd_twiddles(pending_union_twiddle_log_size(&config));
    let mut channel = Poseidon252Channel::default();
    mix_pending_union_scope(&mut channel, opening, &schedule);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut builder = scheme.tree_builder();
        builder.extend_evals(scope.to_evaluations());
        builder.commit(&mut channel);
    }
    {
        let mut builder = scheme.tree_builder();
        builder.extend_evals(trace.to_evaluations());
        builder.commit(&mut channel);
    }
    let ids = pending_union_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        CanonicalRevealPendingUnionAir,
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    Ok(ArchivedCanonicalRevealPendingUnionProof {
        kick_schedule: schedule,
        stark_proof_bytes: pending_union_options()
            .serialize(&proof)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?,
    })
}

pub fn verify_canonical_reveal_pending_union(
    opening: &CanonicalRevealLedgerOpening,
    archive: &ArchivedCanonicalRevealPendingUnionProof,
) -> TexasAirResult<()> {
    let schedule = reveal_timeout_kick_schedule(opening);
    if archive.kick_schedule != schedule {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal timeout kick schedule is detached from pending union".into(),
        ));
    }
    let proof: StarkProof<Poseidon252MerkleHasher> = pending_union_options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    if proof.commitments.len() < 2 {
        return Err(TexasAirError::SerializationError(
            "reveal pending-union proof is missing scope or trace commitment".into(),
        ));
    }
    let scope = pending_union_scope(opening, &schedule);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles = crate::prover_context::simd_twiddles(pending_union_twiddle_log_size(&config));
    let mut trusted =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    let mut scope_channel = Poseidon252Channel::default();
    {
        let mut builder = trusted.tree_builder();
        builder.extend_evals(scope.to_evaluations());
        builder.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal pending-union public scope commitment mismatch".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_pending_union_scope(&mut channel, opening, &schedule);
    let mut scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![PENDING_UNION_AIR_LOG_SIZE; PENDING_UNION_AIR_SCOPE_COLUMNS],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![PENDING_UNION_AIR_LOG_SIZE; PENDING_UNION_AIR_TRACE_COLUMNS],
        &mut channel,
    );
    let ids = pending_union_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        CanonicalRevealPendingUnionAir,
        SecureField::from(0u32),
    );
    verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalRevealAssignmentOpening {
    pub present: bool,
    pub encrypted_card_index: u8,
    /// `0 = hole`, `1 = board`.
    pub target_kind: u8,
    pub target_seat: u8,
    pub target_slot: u8,
    pub runout_index: u8,
    pub board_position: u8,
    pub pending_mask: u16,
    pub submitted_mask: u16,
}

impl CanonicalRevealAssignmentOpening {
    pub const EMPTY: Self = Self {
        present: false,
        encrypted_card_index: 0,
        target_kind: 0,
        target_seat: 0,
        target_slot: 0,
        runout_index: 0,
        board_position: 0,
        pending_mask: 0,
        submitted_mask: 0,
    };

    fn validate(&self) -> TexasAirResult<()> {
        if !self.present {
            if *self != Self::EMPTY {
                return Err(TexasAirError::SpecViolation(
                    "empty reveal opening entry is not canonical zero".into(),
                ));
            }
            return Ok(());
        }
        if self.encrypted_card_index >= 52
            || self.target_kind > 1
            || self.target_seat >= 9
            || self.pending_mask & !0x01ff != 0
            || self.submitted_mask & !0x01ff != 0
            || self.pending_mask & self.submitted_mask != 0
        {
            return Err(TexasAirError::SpecViolation(
                "reveal opening assignment is outside the fixed seat/card domain".into(),
            ));
        }
        if (self.target_kind == 0 && self.target_slot >= 2)
            || (self.target_kind == 1 && (self.runout_index >= 2 || self.board_position >= 5))
        {
            return Err(TexasAirError::SpecViolation(
                "reveal opening assignment target is outside its typed domain".into(),
            ));
        }
        // Typed targets have a single canonical representation: fields owned
        // by the other target variant are zero padding, never host-selected
        // metadata that is ignored by the VM.
        if (self.target_kind == 0 && (self.runout_index != 0 || self.board_position != 0))
            || (self.target_kind == 1 && (self.target_seat != 0 || self.target_slot != 0))
        {
            return Err(TexasAirError::SpecViolation(
                "reveal opening assignment contains non-zero typed padding".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalRevealLedgerOpening {
    pub phase: u8,
    pub street: u8,
    pub assignment_count: u8,
    pub pending_union: u16,
    pub assignments: [CanonicalRevealAssignmentOpening; MAX_CANONICAL_REVEAL_ASSIGNMENTS],
}

impl CanonicalRevealLedgerOpening {
    pub fn validate(&self) -> TexasAirResult<()> {
        if self.assignment_count as usize > MAX_CANONICAL_REVEAL_ASSIGNMENTS
            || self.phase == 0
            || self.street == 0
            || self.pending_union & !0x01ff != 0
        {
            return Err(TexasAirError::SpecViolation(
                "reveal ledger opening header is outside the fixed domain".into(),
            ));
        }
        let mut union = 0u16;
        let mut prior_target = None;
        let mut seen_encrypted_card = [false; 52];
        for (index, assignment) in self.assignments.iter().enumerate() {
            let occupied = index < self.assignment_count as usize;
            if assignment.present != occupied {
                return Err(TexasAirError::SpecViolation(
                    "reveal ledger assignments are not contiguous".into(),
                ));
            }
            assignment.validate()?;
            if occupied {
                let target = if assignment.target_kind == 0 {
                    (0, assignment.target_seat, assignment.target_slot)
                } else {
                    (1, assignment.runout_index, assignment.board_position)
                };
                if prior_target.is_some_and(|prior| prior >= target) {
                    return Err(TexasAirError::SpecViolation(
                        "reveal ledger targets are not in canonical order".into(),
                    ));
                }
                if seen_encrypted_card[usize::from(assignment.encrypted_card_index)] {
                    return Err(TexasAirError::SpecViolation(
                        "reveal ledger repeats an encrypted card index".into(),
                    ));
                }
                prior_target = Some(target);
                seen_encrypted_card[usize::from(assignment.encrypted_card_index)] = true;
                union |= assignment.pending_mask;
            }
        }
        if union != self.pending_union {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "reveal ledger pending union is detached from assignments".into(),
            ));
        }
        Ok(())
    }

    /// Bind the fixed ledger header to the canonical pre-state projection.
    /// This is intentionally a separate check from structural validation: the
    /// same wire opening can be structurally valid but belong to another hand
    /// or another reveal phase.
    pub fn validate_for_pre_state(
        &self,
        pre: &crate::texas_canonical::CanonicalStateImage,
    ) -> TexasAirResult<()> {
        if pre.phase != crate::texas_canonical::CanonicalPhase::Revealing
            || self.phase != pre.phase_subtag
            || self.street != pre.street
            || self.pending_union != pre.protocol_pending_mask
            || self.pending_union == 0
            || self.assignment_count == 0
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "reveal ledger opening is detached from the canonical revealing pre-state".into(),
            ));
        }

        Ok(())
    }

    pub fn message(&self) -> TexasAirResult<Vec<u8>> {
        self.validate()?;
        Ok(self.message_unchecked())
    }

    /// Canonical hash preimage for a decoded fixed-width ledger.  Structural
    /// validity is established by `CanonicalRevealPendingUnionAir` in the
    /// verifier path; callers that construct a new statement must use
    /// [`Self::message`] or the prover entrypoint, both of which run the
    /// inexpensive host-side hygiene check first.
    fn message_unchecked(&self) -> Vec<u8> {
        let mut bytes = REVEAL_OPENING_DOMAIN.to_vec();
        bytes.extend_from_slice(&borsh::to_vec(self).expect("fixed reveal ledger serializes"));
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCanonicalRevealLedgerOpening {
    pub magic: [u8; 4],
    pub version: u8,
    pub opening: CanonicalRevealLedgerOpening,
    pub pending_union: ArchivedCanonicalRevealPendingUnionProof,
    /// BLAKE3 (flock chain) statement authenticating the fixed ledger bytes.
    pub hash: ArchivedHashProof,
}

impl ArchivedCanonicalRevealLedgerOpening {
    /// Validate the canonical envelope shape and its authenticated preimage.
    /// Cryptographic verification is intentionally separate and is performed
    /// by [`verify_canonical_reveal_ledger_opening`].
    pub fn validate(&self) -> TexasAirResult<()> {
        if self.magic != CANONICAL_REVEAL_OPENING_MAGIC
            || self.version != CANONICAL_REVEAL_OPENING_VERSION
        {
            return Err(TexasAirError::SpecViolation(
                "reveal ledger opening magic/version mismatch".into(),
            ));
        }
        let message = self.opening.message_unchecked();
        let statements = self.hash.statements();
        let [statement] = statements.as_slice() else {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "reveal ledger opening hash proof must cover exactly one statement".into(),
            ));
        };
        if statement.message != message {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "reveal ledger opening hash preimage is detached from the opening".into(),
            ));
        }
        Ok(())
    }

    /// Strict canonical Borsh encoding.
    pub fn to_bytes(&self) -> TexasAirResult<Vec<u8>> {
        self.validate()?;
        let bytes = borsh::to_vec(self).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "reveal ledger opening Borsh encoding failed: {error}"
            ))
        })?;
        if bytes.len() > MAX_CANONICAL_REVEAL_OPENING_BYTES {
            return Err(TexasAirError::SerializationError(
                "reveal ledger opening exceeds size limit".into(),
            ));
        }
        Ok(bytes)
    }

    /// Strict canonical Borsh decoding with trailing-byte rejection.
    pub fn from_bytes(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_REVEAL_OPENING_BYTES {
            return Err(TexasAirError::SerializationError(
                "invalid reveal ledger opening length".into(),
            ));
        }
        let archive = Self::try_from_slice(bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "reveal ledger opening Borsh decoding failed: {error}"
            ))
        })?;
        archive.validate()?;
        Ok(archive)
    }
}

pub fn prove_canonical_reveal_ledger_opening(
    opening: CanonicalRevealLedgerOpening,
) -> TexasAirResult<ArchivedCanonicalRevealLedgerOpening> {
    // Prover-side hygiene only.  Verification below relies on the fixed-width
    // AIR rather than replaying this routine on untrusted archive data.
    opening.validate()?;
    let message = opening.message()?;
    let statement = HashStatement::new(
        message.clone(),
        crate::blake3_flock::blake3_chain_digest(&message),
    );
    Ok(ArchivedCanonicalRevealLedgerOpening {
        magic: CANONICAL_REVEAL_OPENING_MAGIC,
        version: CANONICAL_REVEAL_OPENING_VERSION,
        pending_union: prove_canonical_reveal_pending_union(&opening)?,
        opening,
        hash: crate::blake3_flock::FlockProvider.prove_statements(&[statement])?,
    })
}

pub fn verify_canonical_reveal_ledger_opening(
    archive: &ArchivedCanonicalRevealLedgerOpening,
    expected_reveal_commitment: [u8; 32],
) -> TexasAirResult<()> {
    archive.validate()?;
    verify_canonical_reveal_pending_union(&archive.opening, &archive.pending_union)?;
    let statements = archive.hash.statements();
    let [statement] = statements.as_slice() else {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal ledger opening hash proof must cover exactly one statement".into(),
        ));
    };
    if statement.digest != expected_reveal_commitment {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal ledger opening is detached from the state reveal commitment".into(),
        ));
    }
    crate::blake3_flock::FlockProvider.verify_proof(&archive.hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opening() -> CanonicalRevealLedgerOpening {
        let mut assignments =
            [CanonicalRevealAssignmentOpening::EMPTY; MAX_CANONICAL_REVEAL_ASSIGNMENTS];
        assignments[0] = CanonicalRevealAssignmentOpening {
            present: true,
            encrypted_card_index: 0,
            target_kind: 0,
            target_seat: 1,
            target_slot: 0,
            runout_index: 0,
            board_position: 0,
            pending_mask: 1,
            submitted_mask: 0,
        };
        CanonicalRevealLedgerOpening {
            phase: 1,
            street: 1,
            assignment_count: 1,
            pending_union: 1,
            assignments,
        }
    }

    fn empty_pending_union_proof() -> ArchivedCanonicalRevealPendingUnionProof {
        ArchivedCanonicalRevealPendingUnionProof {
            kick_schedule: [REVEAL_TIMEOUT_SCHEDULE_EMPTY; PENDING_UNION_AIR_SEAT_BITS],
            stark_proof_bytes: Vec::new(),
        }
    }

    #[test]
    fn pending_union_is_derived_not_host_advice() {
        let mut value = opening();
        value.pending_union = 2;
        assert!(value.validate().is_err());
    }

    #[ignore = "slow prove (~4s); full gate runs `--include-ignored`"]
    #[test]
    fn pending_union_air_binds_all_assignment_masks_and_padding() {
        let value = opening();
        let archive = prove_canonical_reveal_pending_union(&value).expect("pending-union proof");
        verify_canonical_reveal_pending_union(&value, &archive).expect("pending-union verify");
        assert_eq!(archive.kick_schedule[0], 0);
        assert_eq!(archive.kick_schedule[1], REVEAL_TIMEOUT_SCHEDULE_EMPTY);

        let mut relabeled = value.clone();
        relabeled.assignments[1].present = true;
        relabeled.assignments[1].pending_mask = 1;
        assert!(verify_canonical_reveal_pending_union(&relabeled, &archive).is_err());
        let mut schedule_splice = archive.clone();
        schedule_splice.kick_schedule[0] = REVEAL_TIMEOUT_SCHEDULE_EMPTY;
        assert!(verify_canonical_reveal_pending_union(&value, &schedule_splice).is_err());
    }

    #[ignore = "slow prove (~3s); full gate runs `--include-ignored`"]
    #[test]
    fn pending_union_air_rejects_structural_archive_mutations() {
        let mut value = opening();
        value.assignment_count = 2;
        value.pending_union = 0b11;
        value.assignments[1] = CanonicalRevealAssignmentOpening {
            present: true,
            encrypted_card_index: 1,
            target_kind: 0,
            target_seat: 1,
            target_slot: 1,
            runout_index: 0,
            board_position: 0,
            pending_mask: 0b10,
            submitted_mask: 0,
        };
        let archive = prove_canonical_reveal_pending_union(&value).expect("valid ledger proof");

        let mut duplicate_card = value.clone();
        duplicate_card.assignments[1].encrypted_card_index = 0;
        assert!(verify_canonical_reveal_pending_union(&duplicate_card, &archive).is_err());

        let mut swapped_target = value.clone();
        swapped_target.assignments[1].target_slot = 0;
        assert!(verify_canonical_reveal_pending_union(&swapped_target, &archive).is_err());

        let mut out_of_range_card = value.clone();
        out_of_range_card.assignments[0].encrypted_card_index = 52;
        assert!(verify_canonical_reveal_pending_union(&out_of_range_card, &archive).is_err());

        let mut overlapping_masks = value.clone();
        overlapping_masks.assignments[1].pending_mask = 0b01;
        assert!(verify_canonical_reveal_pending_union(&overlapping_masks, &archive).is_err());
    }

    #[test]
    fn opening_rejects_detached_state_commitment_before_stark_verify() {
        let value = opening();
        let archive = ArchivedCanonicalRevealLedgerOpening {
            magic: CANONICAL_REVEAL_OPENING_MAGIC,
            version: CANONICAL_REVEAL_OPENING_VERSION,
            pending_union: empty_pending_union_proof(),
            hash: ArchivedHashProof::Flock(crate::blake3_flock::ArchivedFlockHashesProof {
                statements: vec![HashStatement::new(value.message().unwrap(), [9; 32])],
                chains: Vec::new(),
                merkles: Vec::new(),
            }),
            opening: value,
        };
        assert!(verify_canonical_reveal_ledger_opening(&archive, [8; 32]).is_err());
    }

    #[test]
    fn archive_wire_roundtrip_is_canonical_and_rejects_trailing_bytes() {
        let value = opening();
        let archive = ArchivedCanonicalRevealLedgerOpening {
            magic: CANONICAL_REVEAL_OPENING_MAGIC,
            version: CANONICAL_REVEAL_OPENING_VERSION,
            pending_union: empty_pending_union_proof(),
            hash: ArchivedHashProof::Flock(crate::blake3_flock::ArchivedFlockHashesProof {
                statements: vec![HashStatement::new(value.message().unwrap(), [0; 32])],
                chains: Vec::new(),
                merkles: Vec::new(),
            }),
            opening: value,
        };
        let bytes = archive.to_bytes().expect("canonical wire encoding");
        assert_eq!(
            ArchivedCanonicalRevealLedgerOpening::from_bytes(&bytes).unwrap(),
            archive
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ArchivedCanonicalRevealLedgerOpening::from_bytes(&trailing).is_err());
    }

    #[test]
    fn archive_wire_rejects_header_splice() {
        let value = opening();
        let mut archive = ArchivedCanonicalRevealLedgerOpening {
            magic: CANONICAL_REVEAL_OPENING_MAGIC,
            version: CANONICAL_REVEAL_OPENING_VERSION,
            pending_union: empty_pending_union_proof(),
            hash: ArchivedHashProof::Flock(crate::blake3_flock::ArchivedFlockHashesProof {
                statements: vec![HashStatement::new(value.message().unwrap(), [0; 32])],
                chains: Vec::new(),
                merkles: Vec::new(),
            }),
            opening: value,
        };
        archive.magic = *b"BAD!";
        assert!(archive.to_bytes().is_err());
    }

    #[test]
    fn typed_target_padding_is_not_ignored() {
        let mut value = opening();
        value.assignments[0].runout_index = 1;
        assert!(value.validate().is_err());
        value.assignments[0].runout_index = 0;
        value.assignments[0].target_kind = 1;
        value.assignments[0].target_slot = 1;
        assert!(value.validate().is_err());
    }

    #[test]
    fn ledger_rejects_duplicate_cards_and_noncanonical_target_order() {
        let mut value = opening();
        value.assignment_count = 2;
        value.assignments[1] = CanonicalRevealAssignmentOpening {
            present: true,
            encrypted_card_index: 0,
            target_kind: 0,
            target_seat: 1,
            target_slot: 1,
            runout_index: 0,
            board_position: 0,
            pending_mask: 0,
            submitted_mask: 1,
        };
        assert!(value.validate().is_err());

        value.assignments[1].encrypted_card_index = 1;
        value.assignments[1].target_slot = 0;
        assert!(value.validate().is_err());
    }
}
