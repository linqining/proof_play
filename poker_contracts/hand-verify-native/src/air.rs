//! The native Stwo statement AIR for hand_verify (form-① architecture).
//!
//! ## What the AIR attests
//!
//! One row per statement, canonically laid out: the first `n_own` rows are
//! ownership statements, then `n_reveal` reveal rows, then `n_leave` leave
//! rows, then `n_recon` reconstruct rows; the remainder is padding. The AIR
//! constrains, with row-local constraints plus cyclic accumulators:
//!
//! 1. selector well-formedness: the four kind selectors are boolean and
//!    mutually exclusive;
//! 2. binding: on every active row the committed `hand_binding` limbs equal
//!    the claim's limbs (padding rows carry zeros);
//! 3. counts: cyclic accumulators prove `Σ is_<kind> = n_<kind>` against the
//!    claim — the classic free-rotation trick
//!    (`acc_next = acc + sel − count/N`) avoids boundary markers entirely;
//! 4. the full claim (hand_binding limbs, digests, counts) is mixed into the
//!    Fiat–Shamir channel *before* any commit/draw, binding the proof to the
//!    claim bytes.
//!
//! ## What the AIR deliberately does NOT attest
//!
//! The EC residual results (identity checks) are verified host-side by
//! [`crate::handbatch::verify_hand`] *before* proving; they enter only as
//! digests bound via the channel. That is the form-① trust boundary: the
//! proof is O(1)-verifiable evidence that "the sequencer claimed this exact
//! hand batch statement", not transferable cryptographic evidence that the
//! EC verification is correct. See README.
//!
//! Trace columns (17): `is_own, is_rev, is_leave, is_recon`, one accumulator
//! per kind, `hb_limb0..8` (9 × 28-bit limbs cover the full felt252 range).

use num_bigint::BigUint;
use stwo::core::fields::m31::{BaseField, M31};
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, ORIGINAL_TRACE_IDX};
use starknet_crypto::Felt;

/// Felt ↔ BigUint — the claim's hand binding is a wire word; limb splitting
/// is integer work on BigUint.
fn felt_to_biguint(f: Felt) -> BigUint {
    BigUint::from_bytes_be(&f.to_bytes_be())
}

fn biguint_to_felt(v: &BigUint) -> Option<Felt> {
    let bytes = v.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    // types-core from_bytes_be 无失败路径，canonical 用字节往返判定
    // （语义同旧 ff 库的 Result 路径）。
    let felt = Felt::from_bytes_be(&buf);
    (felt.to_bytes_be() == buf).then_some(felt)
}

/// Number of 28-bit limbs representing a felt252 in the trace.
pub const N_LIMBS: usize = 9;
/// Number of statement kinds (ownership, reveal, leave, reconstruct).
pub const N_KINDS: usize = 4;
/// Total trace columns.
pub const N_COLUMNS: usize = 2 * N_KINDS + N_LIMBS;

/// Bit width of one limb. 9 × 28 = 252 ≥ 251 covers every felt252, and each
/// limb is an M31-safe value.
pub const LIMB_BITS: u32 = 28;

/// Split a felt into 9 little-endian 28-bit limbs.
pub fn felt_limbs(f: Felt) -> [M31; N_LIMBS] {
    let v = felt_to_biguint(f);
    let mask = BigUint::from((1u128 << LIMB_BITS) - 1);
    let mut limbs = [M31::from_u32_unchecked(0); N_LIMBS];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let shifted = (&v >> (i as u32 * LIMB_BITS)) & &mask;
        let val = u32::try_from(shifted).expect("limb < 2^28");
        *limb = M31::from_u32_unchecked(val);
    }
    limbs
}

/// Recombine limbs into a felt (verifier-side consistency helper;
/// exercised by the limb round-trip test).
#[allow(dead_code)]
pub fn limbs_to_felt(limbs: &[M31; N_LIMBS]) -> Felt {
    let mut v = BigUint::from(0u32);
    for limb in limbs.iter().rev() {
        v = (v << LIMB_BITS) | BigUint::from(limb.0);
    }
    biguint_to_felt(&v).expect("limb recombination < P")
}

/// Per-kind statement counts of the canonical layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindCounts {
    pub n_own: u32,
    pub n_reveal: u32,
    pub n_leave: u32,
    pub n_recon: u32,
}

impl KindCounts {
    pub fn total(&self) -> u32 {
        self.n_own + self.n_reveal + self.n_leave + self.n_recon
    }

    fn as_array(&self) -> [u32; N_KINDS] {
        [self.n_own, self.n_reveal, self.n_leave, self.n_recon]
    }
}

/// The public statement a hand-batch proof stands for. Both prover and
/// verifier construct the component from this; it is also mixed into the
/// Fiat–Shamir channel pre-commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandBatchClaim {
    pub hand_binding: Felt,
    /// `poseidon` over the full payload (`handbatch::payload_digest`).
    pub payload_digest: Felt,
    pub counts: KindCounts,
    pub log_size: u32,
    /// Program hash of the form-② EC attestation (the Cairo hand_verify
    /// executable proven via the EC_OP builtin — EC in trace). `ZERO` marks
    /// pure form-① (no EC attestation half). Mixed into the channel like
    /// every other claim field.
    pub cairo_program_hash: Felt,
}

impl HandBatchClaim {
    /// Smallest power-of-two row count fitting the canonical layout.
    pub fn log_size_for(counts: KindCounts) -> u32 {
        let rows = counts.total().max(1) as usize;
        rows.next_power_of_two().ilog2().max(3)
    }

    pub fn new(
        hand_binding: Felt,
        payload_digest: Felt,
        counts: KindCounts,
        cairo_program_hash: Felt,
    ) -> Self {
        Self {
            hand_binding,
            payload_digest,
            counts,
            log_size: Self::log_size_for(counts),
            cairo_program_hash,
        }
    }

    /// Fiat–Shamir binding: every claim field enters the channel as u32
    /// words (same encoding discipline as the main project's public inputs).
    pub fn mix_into<C: stwo::core::channel::Channel>(&self, channel: &mut C) {
        let mut words: Vec<u32> = Vec::with_capacity(32);
        for felt in [self.hand_binding, self.payload_digest, self.cairo_program_hash] {
            words.extend(felt.to_bytes_be().chunks_exact(4).map(|c| {
                u32::from_be_bytes([c[0], c[1], c[2], c[3]])
            }));
        }
        words.extend_from_slice(&self.counts.as_array());
        words.push(self.log_size);
        channel.mix_u32s(&words);
    }

    fn hb_limbs(&self) -> [BaseField; N_LIMBS] {
        felt_limbs(self.hand_binding)
    }
}

/// The statement-table evaluator.
#[derive(Clone)]
pub struct HandBatchEval {
    log_size: u32,
    kind_counts: [BaseField; N_KINDS],
    inv_total: BaseField,
    hb_limbs: [BaseField; N_LIMBS],
}

impl HandBatchEval {
    pub fn new(claim: &HandBatchClaim) -> Self {
        let total = BaseField::from_u32_unchecked(1 << claim.log_size);
        Self {
            log_size: claim.log_size,
            kind_counts: claim
                .counts
                .as_array()
                .map(BaseField::from_u32_unchecked),
            inv_total: total.inverse(),
            hb_limbs: claim.hb_limbs(),
        }
    }
}

impl FrameworkEval for HandBatchEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Column order: 4 kind selectors, 4 accumulators, 9 binding limbs.
        let sel: [_; N_KINDS] = std::array::from_fn(|_| eval.next_trace_mask());
        let acc: [_; N_KINDS] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let hb: [_; N_LIMBS] = std::array::from_fn(|_| eval.next_trace_mask());

        // 1. boolean selectors, pairwise mutually exclusive.
        for i in 0..N_KINDS {
            eval.add_constraint(sel[i].clone() * sel[i].clone() - sel[i].clone());
        }
        for i in 0..N_KINDS {
            for j in (i + 1)..N_KINDS {
                eval.add_constraint(sel[i].clone() * sel[j].clone());
            }
        }

        // 2. active rows must carry exactly the claimed binding limbs;
        //    padding rows carry zeros.
        let mut active = sel[0].clone();
        for s in &sel[1..] {
            active = active + s.clone();
        }
        for (limb, expected) in hb.iter().zip(self.hb_limbs.iter()) {
            let expected: E::F = (*expected).into();
            eval.add_constraint(limb.clone() - expected * active.clone());
        }

        // 3. cyclic count accumulators (free-rotation trick), one per kind.
        for k in 0..N_KINDS {
            let [acc_cur, acc_next] = acc[k].clone();
            let bias: E::F = (self.kind_counts[k] * self.inv_total).into();
            eval.add_constraint(acc_next - acc_cur - sel[k].clone() + bias);
        }

        eval
    }
}

/// Logical (coset-natural) row `i` → storage index in the bit-reversed
/// circle-domain order the evaluation columns expect. Same mapping the Stwo
/// `state_machine` example uses for sequential traces; without it the
/// offset-1 accumulator constraints read the wrong neighbour rows.
fn storage_index(i: usize, log_size: u32) -> usize {
    const fn coset_index_to_circle_domain_index(coset_index: usize, log_domain_size: u32) -> usize {
        if coset_index % 2 == 0 {
            coset_index / 2
        } else {
            ((2 << log_domain_size) - coset_index) / 2
        }
    }
    const fn bit_reverse_index(i: usize, log_size: u32) -> usize {
        if log_size == 0 {
            return i;
        }
        i.reverse_bits() >> (usize::BITS - log_size)
    }
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

/// Build the canonical trace columns for a claim (prover side).
///
/// Rows follow the canonical layout (own → reveal → leave → recon → padding).
/// Values are written in bit-reversed circle-domain order so the offset-1
/// accumulator constraints chain consecutive logical rows.
pub fn build_trace(claim: &HandBatchClaim) -> Vec<Vec<BaseField>> {
    let rows = 1usize << claim.log_size;
    assert!(
        rows >= claim.counts.total() as usize,
        "log_size too small"
    );

    let hb = felt_limbs(claim.hand_binding);
    let zero = BaseField::from_u32_unchecked(0);
    let one = BaseField::from_u32_unchecked(1);
    let mut logical = vec![vec![zero; rows]; N_COLUMNS];

    // Cyclic accumulator state: acc_{i+1} = acc_i + sel_i − count/N.
    let inv_total = BaseField::from_u32_unchecked(1 << claim.log_size).inverse();
    let kind_steps: [BaseField; N_KINDS] = std::array::from_fn(|k| {
        BaseField::from_u32_unchecked(claim.counts.as_array()[k]) * inv_total
    });

    let mut accs = [zero; N_KINDS];
    for row in 0..rows {
        let idx = row as u32;
        let counts = claim.counts.as_array();
        let kind = if idx < counts[0] {
            Some(0)
        } else if idx < counts[0] + counts[1] {
            Some(1)
        } else if idx < counts[0] + counts[1] + counts[2] {
            Some(2)
        } else if idx < claim.counts.total() {
            Some(3)
        } else {
            None
        };

        if let Some(k) = kind {
            logical[k][row] = one;
            for (c, limb) in hb.iter().enumerate() {
                logical[2 * N_KINDS + c][row] = *limb;
            }
        }
        for k in 0..N_KINDS {
            logical[N_KINDS + k][row] = accs[k];
        }
        for k in 0..N_KINDS {
            let sel = if Some(k) == kind { one } else { zero };
            accs[k] = accs[k] + sel - kind_steps[k];
        }
    }
    // Cyclic closure: after a full cycle every accumulator must be back at
    // its row-0 value (0). If not, the trace does not satisfy the AIR.
    for (k, acc) in accs.iter().enumerate() {
        assert_eq!(*acc, zero, "kind {k} count violates the AIR");
    }

    // Permute logical rows into bit-reversed circle-domain storage order.
    let mut cols = vec![vec![zero; rows]; N_COLUMNS];
    for (i, _) in logical[0].iter().enumerate() {
        let s = storage_index(i, claim.log_size);
        for (c, column) in logical.iter().enumerate() {
            cols[c][s] = column[i];
        }
    }
    cols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limbs_roundtrip() {
        let f = Felt::from_hex("0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(limbs_to_felt(&felt_limbs(f)), f);
        let zero = Felt::from(0u32);
        assert_eq!(limbs_to_felt(&felt_limbs(zero)), zero);
        let max_small = Felt::from(u64::MAX);
        assert_eq!(limbs_to_felt(&felt_limbs(max_small)), max_small);
    }

    #[test]
    fn storage_index_is_a_permutation() {
        for log in 3..=8 {
            let n = 1usize << log;
            let mut seen = vec![false; n];
            for i in 0..n {
                let s = storage_index(i, log);
                assert!(s < n);
                assert!(!seen[s], "duplicate storage index at log {log}");
                seen[s] = true;
            }
        }
    }
}
