//! Poseidon2 over M31: transcript-chain segment (Path A Flock-elimination).
//!
//! Parameters follow the Circle STARKs instantiation (eprint 2024/278):
//! state `t = 16`, 8 external rounds (4+4) and 14 internal rounds, S-box
//! `x^5` (3 native multiplications — `x^3`/`x^7` are **not** permutations
//! on M31 because 3²·7 | 2^31−2), external matrix `circ(2·M4, M4, M4, M4)`
//! implemented with additions only, internal matrix `diag(2^{i+1}) + sum`.
//! With rate/capacity 8/8 the capacity is 8·31 = 248 bits ⇒ 124-bit
//! classical collision security (see eprint 2024/1635); digests must
//! serialize at least 8 state elements.
//!
//! Performance shape (measured 2026-08): one permutation occupies 158
//! columns × one row (8 instances per row, SIMD lanes in parallel), with
//! no limbs, carries, or range checks — M31-native by construction.
//!
//! Chain semantics (2026-08-28, soundness wiring): a chain step is
//! `state ← permute(state + words)` with the 8 rate-lane words public
//! (scope columns, pinned through the statement digest).  Per-step states
//! are chained by the LogUp multiset argument — every instance publishes
//! `(+1, state_j)` and `(−1, state_{j+1})`, and every chain adds the
//! boundary pair `(−1, scope initial)` / `(+1, scope digest)` gated by a
//! one-hot selector column, so the total fraction sum telescopes to
//! exactly zero and the multiset equality pins each chain's first state
//! to the scope initial and its terminal state to the scope digest —
//! the same balanced-table pattern the ladder range stripes use.
//! Round constants are deterministically generated below (splitmix-style
//! PRG, fixed seed); production must regenerate them (and re-check the
//! internal matrix coefficients) per the Poseidon2 paper's
//! nothing-up-my-sleeve procedure — the stwo reference example carries
//! the same TODOs.

#![allow(missing_docs)]

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkEval, RelationEntry, relation,
};

use num_traits::One;

// ---------------------------------------------------------------------------
// Parameters (Circle STARKs Poseidon2-M31 instantiation).
// ---------------------------------------------------------------------------

pub const N_STATE: usize = 16;
/// Rate lanes: message words absorbed before each permutation.
pub const N_RATE_LANES: usize = 8;
pub const N_PARTIAL_ROUNDS: usize = 14;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;
/// Instances (whole permutations) unrolled per trace row.
pub const N_INSTANCES_PER_ROW: usize = 8;

const M31_P: u64 = (1 << 31) - 1;

/// Deterministic round constants (splitmix64 chain, fixed public seed).
/// See the module docs for the production regeneration note.
const fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Reduce a u64 into M31 via Mersenne folding.
const fn to_m31_bits(value: u64) -> u32 {
    let folded = (value & M31_P) + (value >> 31);
    let folded = (folded & M31_P) + (folded >> 31);
    (folded % M31_P) as u32
}

const fn generate_constants() -> ([[u32; N_STATE]; FULL_ROUNDS], [u32; N_PARTIAL_ROUNDS]) {
    let mut state = 0x5053_4549_444F_4E32_u64; // "POSEIDON2"
    let mut external = [[0u32; N_STATE]; FULL_ROUNDS];
    let mut round = 0;
    while round < FULL_ROUNDS {
        let mut i = 0;
        while i < N_STATE {
            state = splitmix64(state);
            external[round][i] = to_m31_bits(state);
            i += 1;
        }
        round += 1;
    }
    let mut internal = [0u32; N_PARTIAL_ROUNDS];
    let mut round = 0;
    while round < N_PARTIAL_ROUNDS {
        state = splitmix64(state);
        internal[round] = to_m31_bits(state);
        round += 1;
    }
    (external, internal)
}

pub const EXTERNAL_ROUND_CONSTS: [[u32; N_STATE]; FULL_ROUNDS] = generate_constants().0;
pub const INTERNAL_ROUND_CONSTS: [u32; N_PARTIAL_ROUNDS] = generate_constants().1;

// ---------------------------------------------------------------------------
// Round functions, generic over the field so the witness generator and the
// AIR constraints share one implementation.
// ---------------------------------------------------------------------------

pub trait Poseidon2Field:
    Clone + std::ops::AddAssign + std::ops::Mul<M31, Output = Self>
{
}
impl<T> Poseidon2Field for T where T: Clone + std::ops::AddAssign + std::ops::Mul<M31, Output = T> {}

/// `x^5` — three native field multiplications.
pub fn pow5<F: Poseidon2Field + std::ops::Mul<Output = F>>(x: &F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x.clone()
}

/// The M4 matrix of Poseidon2 §5.1: additions and doublings only.
fn apply_m4<F: Poseidon2Field + std::ops::Add<Output = F>>(x: [F; 4]) -> [F; 4] {
    let t0 = x[0].clone() + x[1].clone();
    let t02 = t0.clone() + t0.clone();
    let t1 = x[2].clone() + x[3].clone();
    let t12 = t1.clone() + t1.clone();
    let t2 = x[1].clone() + x[1].clone() + t1;
    let t3 = x[3].clone() + x[3].clone() + t0;
    let t4 = t12.clone() + t12.clone() + t3.clone();
    let t5 = t02.clone() + t02.clone() + t2.clone();
    let t6 = t3 + t5.clone();
    let t7 = t2 + t4.clone();
    [t6, t5, t7, t4]
}

/// External round matrix `circ(2·M4, M4, M4, M4)` (Poseidon2 §5.1).
fn apply_external_round_matrix<
    F: Poseidon2Field + std::ops::Add<Output = F> + std::ops::Sub<Output = F>,
>(
    state: &mut [F; N_STATE],
) {
    for i in 0..4 {
        [state[4 * i], state[4 * i + 1], state[4 * i + 2], state[4 * i + 3]] = apply_m4([
            state[4 * i].clone(),
            state[4 * i + 1].clone(),
            state[4 * i + 2].clone(),
            state[4 * i + 3].clone(),
        ]);
    }
    for j in 0..4 {
        let s = state[j].clone() + state[j + 4].clone() + state[j + 8].clone() + state[j + 12].clone();
        for i in 0..4 {
            state[4 * i + j] += s.clone();
        }
    }
}

/// Internal round matrix: `x_i ← 2^{i+1}·x_i + Σ x` (Poseidon2 §5.2 shape;
/// the stwo reference example carries the same coefficient TODO).
fn apply_internal_round_matrix<F: Poseidon2Field + std::ops::Add<Output = F>>(
    state: &mut [F; N_STATE],
) {
    let sum = state[1..]
        .iter()
        .cloned()
        .fold(state[0].clone(), |acc, s| acc + s);
    state.iter_mut().enumerate().for_each(|(i, s)| {
        *s = s.clone() * M31::from_u32_unchecked(1 << (i + 1)) + sum.clone();
    });
}

/// One full Poseidon2 permutation over M31 (native witness path).
pub fn permute(state: &mut [M31; N_STATE]) {
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] += M31::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]);
        }
        apply_external_round_matrix(state);
        *state = std::array::from_fn(|i| pow5(&state[i]));
    }
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] += M31::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]);
        apply_internal_round_matrix(state);
        state[0] = pow5(&state[0]);
    }
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] +=
                M31::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i]);
        }
        apply_external_round_matrix(state);
        *state = std::array::from_fn(|i| pow5(&state[i]));
    }
}

/// One chain step: absorb the public rate words, then permute.
pub fn absorb_and_permute(state: &mut [M31; N_STATE], words: &[u32; N_RATE_LANES]) {
    for (lane, word) in words.iter().enumerate() {
        state[lane] += M31::from_u32_unchecked(*word);
    }
    permute(state);
}

// ---------------------------------------------------------------------------
// LogUp relation and AIR.
// ---------------------------------------------------------------------------

relation!(Poseidon2State, N_STATE);

/// One transcript-chain batch statement: every chain starts at a public
/// initial state and applies `chain_length` absorb-and-permute steps; the
/// terminal state is the chain digest (scope-pinned by the segment).
///
/// The absorbed words are public and travel chain-major:
/// `absorbed_words[c * chain_length + j]` is step `j` of chain `c`.
/// Padding steps (and padding instances beyond the chain slots) absorb
/// the all-zero word vector.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Poseidon2ChainSpec {
    /// Public initial states, one per chain.
    pub initial_states: Vec<[u32; N_STATE]>,
    /// Public absorbed rate words per step, chain-major
    /// (`chains × chain_length` entries).
    pub absorbed_words: Vec<[u32; N_RATE_LANES]>,
    /// Uniform chain length in absorb-and-permute steps.
    pub chain_length: u32,
}

impl Poseidon2ChainSpec {
    /// Validate the shape: at least one chain, `chain_length ≥ 1`, and the
    /// words schedule sized `chains × chain_length`.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.initial_states.is_empty() {
            return Err("poseidon2 chain spec carries no chains");
        }
        if self.chain_length == 0 {
            return Err("poseidon2 chain length is zero");
        }
        let expected = self.initial_states.len() * self.chain_length as usize;
        if self.absorbed_words.len() != expected {
            return Err("poseidon2 absorbed-words schedule is detached from the chain set");
        }
        Ok(())
    }

    fn words(&self, chain: usize, step: usize) -> [u32; N_RATE_LANES] {
        self.absorbed_words[chain * self.chain_length as usize + step]
    }

    /// Native chain evaluation: the terminal state of every chain.
    pub fn digests(&self) -> Vec<[u32; N_STATE]> {
        self.initial_states
            .iter()
            .enumerate()
            .map(|(chain, initial)| {
                let mut state: [M31; N_STATE] =
                    std::array::from_fn(|i| M31::from_u32_unchecked(initial[i]));
                for step in 0..self.chain_length as usize {
                    absorb_and_permute(&mut state, &self.words(chain, step));
                }
                std::array::from_fn(|i| state[i].0)
            })
            .collect()
    }
}

/// AIR of the permutation batch: each row carries
/// [`N_INSTANCES_PER_ROW`] whole permutations (442 columns each).  Every
/// instance absorbs its public rate words into the pre-permutation state
/// (scope columns), and the LogUp relation publishes every
/// `(pre-absorption state, post-permutation state)` pair plus, per chain,
/// the boundary pair `(−selector, scope initial)` / `(+selector, scope
/// digest)` with a one-hot selector firing on row 0 — the total fraction
/// sum telescopes to zero exactly.
#[derive(Clone)]
pub struct Poseidon2Air {
    log_size: u32,
    chains: usize,
    lookup_elements: Poseidon2State,
    /// Preprocessed scope-column identities in consumption order: the
    /// words block (rep-major, `N_RATE_LANES` per instance slot) followed
    /// by the per-chain blocks `[initial (16), digest (16), select_initial,
    /// select_digest]`.  `get_preprocessed_column` consumes the
    /// preprocessed tree sequentially, so this order is the scope layout.
    scope_ids: Vec<PreProcessedColumnId>,
}

impl FrameworkEval for Poseidon2Air {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut scope_cursor = 0usize;
        let next_scope = |cursor: &mut usize| {
            let id = self.scope_ids[*cursor].clone();
            *cursor += 1;
            id
        };
        for _ in 0..N_INSTANCES_PER_ROW {
            let mut state: [_; N_STATE] = std::array::from_fn(|_| eval.next_trace_mask());
            let initial_state: [_; N_STATE] = state.clone();

            // Absorb the instance's public rate words (scope columns,
            // rep-major: the words of the instance living in this slot).
            let words: [_; N_RATE_LANES] =
                std::array::from_fn(|_| eval.get_preprocessed_column(next_scope(&mut scope_cursor)));
            for (lane, word) in words.iter().enumerate() {
                state[lane] += word.clone();
            }

            let pow5_split = |eval: &mut E, x: E::F| -> E::F {
                let x2 = x.clone() * x.clone();
                let m2 = eval.next_trace_mask();
                eval.add_constraint(x2.clone() - m2.clone());
                let x4 = m2.clone() * m2.clone();
                let m4 = eval.next_trace_mask();
                eval.add_constraint(x4 - m4.clone());
                let x5 = m4.clone() * x;
                let m5 = eval.next_trace_mask();
                eval.add_constraint(x5 - m5.clone());
                m5
            };

            let full_round = |eval: &mut E, state: &mut [E::F; N_STATE], round: usize| {
                for (i, s) in state.iter_mut().enumerate() {
                    let constant =
                        E::F::from(M31::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]));
                    *s += constant;
                }
                apply_external_round_matrix(state);
                *state = std::array::from_fn(|i| pow5_split(eval, state[i].clone()));
            };

            for round in 0..N_HALF_FULL_ROUNDS {
                full_round(&mut eval, &mut state, round);
            }
            for round in 0..N_PARTIAL_ROUNDS {
                let constant = E::F::from(M31::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]));
                state[0] += constant;
                apply_internal_round_matrix(&mut state);
                state[0] = pow5_split(&mut eval, state[0].clone());
            }
            for round in 0..N_HALF_FULL_ROUNDS {
                full_round(&mut eval, &mut state, round + N_HALF_FULL_ROUNDS);
            }

            eval.add_to_relation(RelationEntry::new(
                &self.lookup_elements,
                E::EF::one(),
                &initial_state,
            ));
            eval.add_to_relation(RelationEntry::new(&self.lookup_elements, -E::EF::one(), &state));
        }
        // Chain boundaries: per chain, the scope initial is a yield and
        // the scope digest is a use, each gated by a one-hot selector so
        // the pair fires exactly once across the trace (row 0).  With the
        // per-instance (+state_j, −state_{j+1}) entries this balances the
        // LogUp sum to zero and pins both boundary tuples.
        for _ in 0..self.chains {
            let initial: [_; N_STATE] =
                std::array::from_fn(|_| eval.get_preprocessed_column(next_scope(&mut scope_cursor)));
            let digest: [_; N_STATE] =
                std::array::from_fn(|_| eval.get_preprocessed_column(next_scope(&mut scope_cursor)));
            let select_initial = eval.get_preprocessed_column(next_scope(&mut scope_cursor));
            let select_digest = eval.get_preprocessed_column(next_scope(&mut scope_cursor));
            eval.add_to_relation(RelationEntry::new(
                &self.lookup_elements,
                -E::EF::from(select_initial),
                &initial,
            ));
            eval.add_to_relation(RelationEntry::new(
                &self.lookup_elements,
                E::EF::from(select_digest),
                &digest,
            ));
        }
        eval.finalize_logup_in_pairs();
        eval
    }
}

