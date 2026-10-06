//! Native form-② leaf kernel: felt252 modular multiplication as a direct
//! program-logic AIR (no Cairo VM, no instruction trace).
//!
//! One trace row proves ONE statement `a·b = q·P + r` with `q, r ≥ 0`,
//! `r < 2^252`, over the Stark curve modulus
//! `P = 2^251 + 17·2^192 + 1`. The trace rows are the multiplication's own
//! limb algebra — there is no interpreter between the constraint and the
//! math.
//!
//! ## Encoding
//!
//! * `a`, `b`, `r` — 28 limbs × 9 bits, each limb decomposed into 9 boolean
//!   columns (range check; no lookup tables needed).
//! * `q` — 251 boolean bits. Because `P` is sparse
//!   (`q·P = q·2^251 + 17·q·2^192 + q`), the `q·P` term enters the position
//!   equations as *linear* combinations of q-bits — no q-limb convolution.
//! * `carry_off` — 56 signed schoolbook carries biased by `2^13` and bounded
//!   to `|carry| < 2^13` via 14 boolean bits.
//!
//! ## Soundness
//!
//! Per 9-bit position `k` (bit window `[9k, 9k+9)`), the constraint
//! `Σ_{i+j=k} a_i·b_j + cin_k − (q·P + r)_k − 512·carry_k = 0` holds in M31.
//! Every term is a bounded integer (`|LHS| < 2^27 ≪ 2^31 − 1`), so the field
//! identity implies the integer identity; the carry chain telescopes the
//! positions into `a·b = q·P + r` exactly, with `cin_0 = 0` and the final
//! carry constrained to zero. Boolean constraints bound every decomposition.
//!
//! Scope notes: `r` is proven `< 2^252` — the mod *relation*; a full
//! canonicality check (`r < P`) adds one borrow chain and is deferred. The
//! EC group-law layer (point double/add rows over this kernel) is the next
//! increment of the native form-② stack.

use num_bigint::BigUint;
use starknet_crypto::Felt;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::curve::{biguint_to_felt, felt_to_biguint};

/// Stark curve modulus as `BigUint` — the kernel's reduction target.
pub fn modulus_p() -> BigUint {
    // P = 2^251 + 17·2^192 + 1
    (BigUint::from(1u32) << 251) + (BigUint::from(17u32) << 192) + BigUint::from(1u32)
}

pub const N_LIMBS: usize = 28; // 28 × 9 = 252
pub const LIMB_BITS: usize = 9;
pub const N_Q_BITS: usize = 252; // q can reach 2^251.004 — 251 bits would truncate
pub const N_POSITIONS: usize = 56; // (28 + 28) limbs of 9 bits cover 504 ≥ 502
pub const CARRY_BIAS: u32 = 1 << 13;
pub const CARRY_BITS: usize = 14;

// Column layout (order must match `FeltMulEval::evaluate` reads and the
// trace generator exactly).
const A_LIMBS: usize = 0;
const B_LIMBS: usize = A_LIMBS + N_LIMBS;
const R_LIMBS: usize = B_LIMBS + N_LIMBS;
const A_BITS: usize = R_LIMBS + N_LIMBS;
const B_BITS: usize = A_BITS + N_LIMBS * LIMB_BITS;
const R_BITS: usize = B_BITS + N_LIMBS * LIMB_BITS;
const Q_BITS: usize = R_BITS + N_LIMBS * LIMB_BITS;
const CARRY_OFF: usize = Q_BITS + N_Q_BITS;
const CARRY_BITS_BASE: usize = CARRY_OFF + N_POSITIONS;
pub const N_COLUMNS: usize = CARRY_BITS_BASE + N_POSITIONS * CARRY_BITS;

const LIMB_WEIGHTS: [u32; LIMB_BITS] = [1, 2, 4, 8, 16, 32, 64, 128, 256];

fn m31(v: u32) -> BaseField {
    BaseField::from_u32_unchecked(v)
}

/// A proved multiplication statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeltMulStatement {
    pub a: Felt,
    pub b: Felt,
    pub r: Felt,
}

/// Little-endian boolean decomposition of `v` into `bits` M31 columns.
fn bool_bits(v: &BigUint, bits: usize) -> Vec<BaseField> {
    // BigUint::to_bytes_be returns the MINIMAL byte string — index from the
    // LSB end and treat everything above the string as zero.
    let bytes = v.to_bytes_be();
    let mut out = Vec::with_capacity(bits);
    for j in 0..bits {
        let from_lsb = j / 8;
        let bit = if from_lsb < bytes.len() {
            (bytes[bytes.len() - 1 - from_lsb] >> (j % 8)) & 1
        } else {
            0
        };
        out.push(BaseField::from_u32_unchecked(bit as u32));
    }
    out
}

fn limb_of(v: &BigUint, i: usize) -> BaseField {
    let mask = BigUint::from((1u32 << LIMB_BITS) - 1u32);
    let shifted = (v >> (i * LIMB_BITS)) & mask;
    BaseField::from_u32_unchecked(u32::try_from(shifted).expect("9-bit limb"))
}

fn q_bits_of(q: &BigUint) -> [BaseField; N_Q_BITS] {
    let mut bits = [BaseField::from_u32_unchecked(0); N_Q_BITS];
    for (j, bit) in bool_bits(q, N_Q_BITS).into_iter().enumerate() {
        bits[j] = bit;
    }
    bits
}

/// Exact integer evaluation of position `k` of `q·P + r`:
/// the value of bits `[9k, 9k+9)` of `q·P + r`, given the bit witnesses.
fn position_target(
    q_bits: &[BaseField; N_Q_BITS],
    r_limbs: &[BaseField; N_LIMBS],
    k: usize,
) -> i64 {
    let qbit = |idx: i64| -> i64 {
        if idx < 0 || idx >= N_Q_BITS as i64 {
            0
        } else {
            q_bits[idx as usize].0 as i64
        }
    };
    let mut t: i64 = 0;
    if k < N_LIMBS {
        t += r_limbs[k].0 as i64;
    }
    for e in 0..LIMB_BITS as i64 {
        // q·2^251: q-bit (9k + e − 251) at weight 2^e.
        t += qbit(9 * k as i64 + e - (N_Q_BITS as i64 - 1)) * (1i64 << e);
        // q·1: q-bit (9k + e) at weight 2^e.
        t += qbit(9 * k as i64 + e) * (1i64 << e);
    }
    // 17·q·2^192: q-bit m lands in this window when
    // 9k ≤ 192+m ≤ 9k+8 → m = 9k+e−192 at weight 17·2^e.
    for e in 0..LIMB_BITS as i64 {
        t += 17 * qbit(9 * k as i64 + e - 192) * (1i64 << e);
    }
    t
}

/// Per-row witness (all M31-safe integers).
pub struct FeltMulRow {
    columns: Vec<BaseField>,
}

/// Compute the witness row for one statement `a·b = q·P + r`.
///
/// `stmt.r` is the CLAIMED result — the kernel verifies it, it does not
/// recompute it. A claimed `r` with `a·b − q·P − r ≠ 0` for every `q`
/// yields an unsatisfiable row (prove fails).
pub fn gen_row(stmt: &FeltMulStatement) -> Result<FeltMulRow, String> {
    let big_a = felt_to_biguint(stmt.a);
    let big_b = felt_to_biguint(stmt.b);
    let big_p = modulus_p();
    let product = &big_a * &big_b;
    let big_r = felt_to_biguint(stmt.r);
    // q = (a·b − r) / P — exact only when the claimed r is congruent.
    if &product % &big_p != &big_r % &big_p {
        return Err("claimed r is not congruent to a·b mod P".into());
    }
    let q = (&product - &big_r) / &big_p;
    let q_bits = q_bits_of(&q);

    let mut cols = vec![BaseField::from_u32_unchecked(0); N_COLUMNS];
    let mut a_limbs = [BaseField::from_u32_unchecked(0); N_LIMBS];
    let mut b_limbs = [BaseField::from_u32_unchecked(0); N_LIMBS];
    let mut r_limbs = [BaseField::from_u32_unchecked(0); N_LIMBS];
    for i in 0..N_LIMBS {
        a_limbs[i] = limb_of(&big_a, i);
        b_limbs[i] = limb_of(&big_b, i);
        r_limbs[i] = limb_of(&big_r, i);
        cols[A_LIMBS + i] = a_limbs[i];
        cols[B_LIMBS + i] = b_limbs[i];
        cols[R_LIMBS + i] = r_limbs[i];
    }
    for (j, bit) in bool_bits(&big_a, N_LIMBS * LIMB_BITS).into_iter().enumerate() {
        cols[A_BITS + j] = bit;
    }
    for (j, bit) in bool_bits(&big_b, N_LIMBS * LIMB_BITS).into_iter().enumerate() {
        cols[B_BITS + j] = bit;
    }
    for (j, bit) in bool_bits(&big_r, N_LIMBS * LIMB_BITS).into_iter().enumerate() {
        cols[R_BITS + j] = bit;
    }
    for (j, bit) in q_bits.iter().enumerate() {
        cols[Q_BITS + j] = *bit;
    }

    // Schoolbook carry chain over exact integers, LSB first.
    let mut carry: i64 = 0;
    for k in 0..N_POSITIONS {
        let mut sum: i64 = carry;
        for i in 0..=k.min(N_LIMBS - 1) {
            if k - i < N_LIMBS {
                sum += a_limbs[i].0 as i64 * b_limbs[k - i].0 as i64;
            }
        }
        let t = position_target(&q_bits, &r_limbs, k);
        let value = sum - t;
        debug_assert_eq!(value % 512, 0, "position {k} not 512-aligned");
        carry = value / 512;
        let biased = carry + CARRY_BIAS as i64;
        debug_assert!(
            biased >= 0 && biased < (1 << CARRY_BITS),
            "carry out of biased range at position {k}: {carry}"
        );
        let biased_u32 = u32::try_from(biased)
            .map_err(|_| format!("carry out of biased range at position {k}: {carry}"))?;
        cols[CARRY_OFF + k] = BaseField::from_u32_unchecked(biased_u32);
        for j in 0..CARRY_BITS {
            let bit = (biased_u32 >> j) & 1;
            cols[CARRY_BITS_BASE + k * CARRY_BITS + j] = BaseField::from_u32_unchecked(bit);
        }
    }
    if carry != 0 {
        return Err(format!("final carry must vanish, got {carry}"));
    }

    Ok(FeltMulRow { columns: cols })
}

impl FeltMulRow {
    pub fn columns(&self) -> &[BaseField] {
        &self.columns
    }
}

/// The evaluator: one row = one multiplication statement.
#[derive(Clone)]
pub struct FeltMulEval {
    pub log_size: u32,
}

impl FeltMulEval {
    pub fn new(log_size: u32) -> Self {
        Self { log_size }
    }
}

impl FrameworkEval for FeltMulEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let c = |v: u32| -> E::F { m31(v).into() };

        let a_limbs: [_; N_LIMBS] = std::array::from_fn(|_| eval.next_trace_mask());
        let b_limbs: [_; N_LIMBS] = std::array::from_fn(|_| eval.next_trace_mask());
        let r_limbs: [_; N_LIMBS] = std::array::from_fn(|_| eval.next_trace_mask());
        let a_bits: [_; N_LIMBS * LIMB_BITS] = std::array::from_fn(|_| eval.next_trace_mask());
        let b_bits: [_; N_LIMBS * LIMB_BITS] = std::array::from_fn(|_| eval.next_trace_mask());
        let r_bits: [_; N_LIMBS * LIMB_BITS] = std::array::from_fn(|_| eval.next_trace_mask());
        let q_bits: [_; N_Q_BITS] = std::array::from_fn(|_| eval.next_trace_mask());
        let carry_off: [_; N_POSITIONS] = std::array::from_fn(|_| eval.next_trace_mask());
        let carry_bits: [_; N_POSITIONS * CARRY_BITS] =
            std::array::from_fn(|_| eval.next_trace_mask());

        // 1. Booleanity of every decomposition bit.
        for bit in a_bits
            .iter()
            .chain(b_bits.iter())
            .chain(r_bits.iter())
            .chain(q_bits.iter())
            .chain(carry_bits.iter())
        {
            eval.add_constraint(bit.clone() * bit.clone() - bit.clone());
        }

        // 2. Limb = Σ bit·2^j within each 9-bit limb.
        for i in 0..N_LIMBS {
            let mut acc_a: E::F = c(0);
            let mut acc_b: E::F = c(0);
            let mut acc_r: E::F = c(0);
            for (j, &w) in LIMB_WEIGHTS.iter().enumerate() {
                acc_a = acc_a + a_bits[i * LIMB_BITS + j].clone() * c(w);
                acc_b = acc_b + b_bits[i * LIMB_BITS + j].clone() * c(w);
                acc_r = acc_r + r_bits[i * LIMB_BITS + j].clone() * c(w);
            }
            eval.add_constraint(a_limbs[i].clone() - acc_a);
            eval.add_constraint(b_limbs[i].clone() - acc_b);
            eval.add_constraint(r_limbs[i].clone() - acc_r);
        }

        // 3. Carry decomposition: carry_off = carry_bits value + bias.
        for k in 0..N_POSITIONS {
            let mut acc: E::F = c(0);
            for j in 0..CARRY_BITS {
                acc = acc + carry_bits[k * CARRY_BITS + j].clone() * c(1u32 << j);
            }
            // carry_off IS the bit-encoded biased value (bias compensated in
            // the position equations via +512·bias).
            eval.add_constraint(carry_off[k].clone() - acc);
        }

        // 4. Position equations:
        //    Σ_{i+j=k} a_i·b_j + cin_k − (q·P + r)_k − 512·carry_k = 0,
        //    cin_0 = 0, and the final carry vanishes.
        for k in 0..N_POSITIONS {
            let mut eq: E::F = c(0);
            for i in 0..=k.min(N_LIMBS - 1) {
                if k - i < N_LIMBS {
                    eq = eq + a_limbs[i].clone() * b_limbs[k - i].clone();
                }
            }
            if k > 0 {
                eq = eq + carry_off[k - 1].clone() - c(CARRY_BIAS);
            }
            if k < N_LIMBS {
                eq = eq - r_limbs[k].clone();
            }
            // q·1: q-bit idx (= 9k+e) at weight 2^e (idx < 252);
            // q·2^251: q-bit (idx − 251) at weight 2^e (idx ≥ 251).
            for e in 0..LIMB_BITS {
                let idx = 9 * k + e;
                if idx < N_Q_BITS {
                    eq = eq - q_bits[idx].clone() * c(1u32 << e);
                }
                if idx >= N_Q_BITS - 1 && idx - (N_Q_BITS - 1) < N_Q_BITS {
                    eq = eq - q_bits[idx - (N_Q_BITS - 1)].clone() * c(1u32 << e);
                }
            }
            // 17·q·2^192: q-bit m lands in this window when
            // 9k ≤ 192+m ≤ 9k+8 → m = 9k+e−192 at weight 17·2^e.
            for e in 0..LIMB_BITS {
                let idx = 9 * k + e;
                if idx >= 192 && idx - 192 < N_Q_BITS {
                    eq = eq - q_bits[idx - 192].clone() * c(17u32 * (1u32 << e));
                }
            }
            if k == N_POSITIONS - 1 {
                // Final carry vanishes; carry_off is pure bias.
                eq = eq - carry_off[k].clone() + c(CARRY_BIAS);
            } else {
                // 512·carry_k = 512·(carry_off[k] − bias): the +512·bias
                // compensates the biased encoding.
                eq = eq - carry_off[k].clone() * c(512u32) + c(512u32 * CARRY_BIAS);
            }
            eval.add_constraint(eq);
        }

        eval
    }
}

/// Pure-integer verification of a witness row against its statement —
/// mirrors the position equations exactly (debug aid, also used by tests to
/// isolate witness bugs from constraint-transcription bugs).
pub fn check_row_integers(row: &FeltMulRow, stmt: &FeltMulStatement) -> Result<(), String> {
    let cols = row.columns();
    let get = |base: usize, i: usize| cols[base + i].0 as i64;
    let big_a = felt_to_biguint(stmt.a);
    let big_b = felt_to_biguint(stmt.b);
    let mut carry: i64 = 0;
    for k in 0..N_POSITIONS {
        let mut sum: i64 = carry;
        for i in 0..=k.min(N_LIMBS - 1) {
            if k - i < N_LIMBS {
                sum += get(A_LIMBS, i) * get(B_LIMBS, k - i);
            }
        }
        // (q·P + r) position target, recomputed from the claimed q, r.
        let big_r = felt_to_biguint(stmt.r);
        let q = ((&big_a * &big_b) - &big_r) / modulus_p();
        let q_bits = q_bits_of(&q);
        let qbit = |idx: i64| -> i64 {
            if idx < 0 || idx >= N_Q_BITS as i64 {
                0
            } else {
                q_bits[idx as usize].0 as i64
            }
        };
        let mut t: i64 = 0;
        if k < N_LIMBS {
            t += get(R_LIMBS, k);
        }
        let dbg_bits = std::env::var("FMUL_DEBUG").is_ok() && k == 0;
        let mut dbg_terms: Vec<(i64, i64, i64)> = Vec::new();
        for e in 0..LIMB_BITS as i64 {
            let idx = 9 * k as i64 + e;
            let t251 = qbit(idx - (N_Q_BITS as i64 - 1)) * (1i64 << e);
            let q1 = qbit(idx) * (1i64 << e);
            let t17 = if idx >= 192 && (idx as usize) - 192 < N_Q_BITS {
                17 * qbit(idx - 192) * (1i64 << e)
            } else {
                0
            };
            if dbg_bits {
                eprintln!("  k=0 e={e}: idx={idx} q1={q1} w={}", 1i64 << e);
            }
            if dbg_bits {
                dbg_terms.push((idx, q1, t251 + t17));
            }
            t += t251;
            t += q1;
            t += t17;
        }
        if dbg_bits {
            eprintln!("k=0 q1+q251+17 terms: {dbg_terms:?} -> t-r = {}", t - get(R_LIMBS, k));
        }
        sum -= t;
        let carry_val = get(CARRY_OFF, k) - CARRY_BIAS as i64;
        if std::env::var("FMUL_DEBUG").is_ok() && k < 2 {
            eprintln!(
                "k={k}: t={t} sum={sum} carry_val={carry_val} r_limb={} q01={:?}",
                get(R_LIMBS, k),
                (0..9).map(|e| qbit(e)).collect::<Vec<_>>(),
            );
        }
        if k == N_POSITIONS - 1 {
            if carry_val != 0 {
                return Err(format!("final carry {carry_val}"));
            }
        } else {
            let residual = sum - 512 * carry_val;
            if residual != 0 {
                return Err(format!(
                    "position {k}: sum={sum} t={t} carry={carry_val} residual={residual}"
                ));
            }
        }
        carry = carry_val;
    }
    Ok(())
}

/// Host oracle: `r = a·b mod P` — the value an honest prover supplies.
pub fn felt_mul_mod_p(a: Felt, b: Felt) -> Felt {
    biguint_to_felt(&(felt_to_biguint(a) * felt_to_biguint(b) % modulus_p()))
        .expect("product mod P < P")
}

// ============================================================
// Prove / verify wiring (mirrors `crate::prove`, single component,
// no interaction phase — all range checks are boolean).
// ============================================================

use stwo::core::channel::Poseidon252Channel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::verify;
use stwo::core::air::Component;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column as _};
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::prove;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

/// Claim of a felt-mul batch: the row count is the only public parameter —
/// every row's (a, b, r) is committed witness, and the statement each row
/// attests is transported alongside the proof by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeltMulClaim {
    pub log_size: u32,
}

impl FeltMulClaim {
    pub fn new(log_size: u32) -> Self {
        Self { log_size }
    }

    pub fn mix_into<C: stwo::core::channel::Channel>(&self, channel: &mut C) {
        channel.mix_u32s(&[self.log_size, 0xFE17_0001]);
    }
}

#[derive(Clone)]
pub struct FeltMulProof {
    pub claim: FeltMulClaim,
    pub stark_proof: StarkProof<Poseidon252MerkleHasher>,
}

/// Padding row (constraint-satisfying): a witness of "0 · 0 = 0" with the
/// carry bias baked in.
fn padding_row() -> Vec<BaseField> {
    // carry = 0: carry_off = bias, and the bits encode the biased value.
    let mut cols = vec![BaseField::from_u32_unchecked(0); N_COLUMNS];
    for k in 0..N_POSITIONS {
        cols[CARRY_OFF + k] = m31(CARRY_BIAS);
        for j in 0..CARRY_BITS {
            let bit = (CARRY_BIAS >> j) & 1;
            cols[CARRY_BITS_BASE + k * CARRY_BITS + j] = m31(bit);
        }
    }
    cols
}

/// Prove a batch of multiplication statements. `log_size` must fit
/// `statements.len()`; spare rows are constraint-valid padding.
pub fn prove_felt_muls(
    statements: &[FeltMulStatement],
    log_size: u32,
) -> Result<FeltMulProof, String> {
    assert!(
        statements.len() <= (1usize << log_size),
        "log_size too small for batch"
    );
    let mut rows = Vec::with_capacity(statements.len());
    for stmt in statements {
        rows.push(gen_row(stmt)?);
    }
    let claim = FeltMulClaim::new(log_size);
    let config = crate::prove::protocol_pcs_config();
    let blowup_log = config.fri_config.log_blowup_factor;
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + blowup_log).half_coset(),
    );

    let mut channel = Poseidon252Channel::default();
    claim.mix_into(&mut channel);
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);

    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }
    {
        let n_rows = 1usize << log_size;
        let domain = CanonicCoset::new(log_size).circle_domain();
        let mut evals = Vec::with_capacity(N_COLUMNS);
        for c in 0..N_COLUMNS {
            let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);
            for (row_idx, row) in rows.iter().enumerate() {
                col.set(row_idx, row.columns()[c]);
            }
            if statements.len() < n_rows {
                let pad = padding_row();
                for row_idx in statements.len()..n_rows {
                    col.set(row_idx, pad[c]);
                }
            }
            evals.push(CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(domain, col));
        }
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(evals);
        tree_builder.commit(&mut channel);
    }

    let mut allocator = TraceLocationAllocator::default();
    let component =
        FrameworkComponent::new(&mut allocator, FeltMulEval::new(log_size), SecureField::from(0u32));
    let stark_proof = prove(&[&component], &mut channel, commitment_scheme)
        .map_err(|e| format!("stwo prove error: {e}"))?;
    Ok(FeltMulProof { claim, stark_proof })
}

/// Verify a felt-mul batch proof against the expected claim.
pub fn verify_felt_muls(
    expected_claim: &FeltMulClaim,
    proof: &FeltMulProof,
) -> Result<(), String> {
    if proof.claim != *expected_claim {
        return Err("claim mismatch".into());
    }
    let config = crate::prove::protocol_pcs_config();
    let mut channel = Poseidon252Channel::default();
    expected_claim.mix_into(&mut channel);
    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    commitment_scheme.commit(proof.stark_proof.commitments[0], &[], &mut channel);
    let component = FrameworkComponent::new(
        &mut TraceLocationAllocator::default(),
        FeltMulEval::new(expected_claim.log_size),
        SecureField::from(0u32),
    );
    let sizes = component.trace_log_degree_bounds();
    commitment_scheme.commit(proof.stark_proof.commitments[1], &sizes[1], &mut channel);
    verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        proof.stark_proof.clone(),
    )
    .map_err(|e| format!("stwo verify error: {e}"))
}

/// Deterministic statement pair for tests/bench.
pub fn sample_statement(seed: u64) -> FeltMulStatement {
    let a = starknet_crypto::poseidon_hash_many(&[Felt::from(seed)]);
    let b = starknet_crypto::poseidon_hash_many(&[Felt::from(seed + 1)]);
    FeltMulStatement { a, b, r: felt_mul_mod_p(a, b) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_checker_loop() {
        let stmt = sample_statement(0);
        let row = gen_row(&stmt).expect("witness");
        let cols = row.columns();
        let get = |base: usize, i: usize| cols[base + i].0 as i64;
        let big_a = felt_to_biguint(stmt.a);
        let big_b = felt_to_biguint(stmt.b);
        let big_r = felt_to_biguint(stmt.r);
        let q = ((&big_a * &big_b) - &big_r) / modulus_p();
        let q_bits = q_bits_of(&q);
        let qbit = |idx: i64| -> i64 {
            if idx < 0 || idx >= N_Q_BITS as i64 {
                0
            } else {
                q_bits[idx as usize].0 as i64
            }
        };
        let mut t: i64 = get(R_LIMBS, 0);
        for e in 0..LIMB_BITS as i64 {
            let idx = 9 * 0 + e;
            let a = qbit(idx - (N_Q_BITS as i64 - 1));
            let b = qbit(idx);
            println!("e={e}: idx={idx} q251={a} q1={b} w={}", 1i64 << e);
            t += a * (1i64 << e) + b;
        }
        println!("t after loop = {t} (r was {})", get(R_LIMBS, 0));
        let sum = get(A_LIMBS, 0) * get(B_LIMBS, 0);
        let carry = get(CARRY_OFF, 0) - CARRY_BIAS as i64;
        println!("conv={sum} 512*carry={} residual={}", 512 * carry, sum - t - 512 * carry);
    }


    #[test]
    fn probe_position_zero() {
        let stmt = sample_statement(0);
        let a = felt_to_biguint(stmt.a);
        let b = felt_to_biguint(stmt.b);
        let r = felt_to_biguint(stmt.r);
        let p = modulus_p();
        let prod = &a * &b;
        let q = (&prod - &r) / &p;
        println!(
            "a0={} b0={} r0={} q0={} carry_expected={}",
            (&a % 512u32).to_str_radix(10),
            (&b % 512u32).to_str_radix(10),
            (&r % 512u32).to_str_radix(10),
            (&q % 512u32).to_str_radix(10),
            (((&a % 512u32) * (&b % 512u32) + 512u32 * 8192u32 - (&r % 512u32) - (&q % 512u32)) / 512u32).to_str_radix(10),
        );
        let row = gen_row(&stmt).expect("witness");
        println!(
            "row: a0={} b0={} r0={} carry_off={} qbits0..9={:?}",
            row.columns()[A_LIMBS].0,
            row.columns()[B_LIMBS].0,
            row.columns()[R_LIMBS].0,
            row.columns()[CARRY_OFF].0,
            (0..9).map(|e| row.columns()[Q_BITS + e].0).collect::<Vec<_>>(),
        );
    }




    /// Host oracle must agree with an independent felt-multiplication check:
    /// (a·b)·P⁻¹-style sanity via re-multiplication is overkill; instead pin
    /// algebraic laws that any wrong reduction would break.
    #[test]
    fn oracle_algebraic_laws() {
        // Generator-derived constants — no hand-typed hex to get wrong.
        let g = crate::curve::Point::generator();
        let a = g.mul(Felt::from(2u32)).to_affine().unwrap().0;
        let b = g.mul(Felt::from(3u32)).to_affine().unwrap().0;
        let ab = felt_mul_mod_p(a, b);
        // (a+b)·b = a·b + b·b (mod P) — linear distributivity check.
        let p = modulus_p();
        let sum_big = (felt_to_biguint(a) + felt_to_biguint(b)) % &p;
        let sum = biguint_to_felt(&sum_big).unwrap();
        let lhs = felt_mul_mod_p(sum, b);
        let bb = felt_mul_mod_p(b, b);
        let rhs_big = (felt_to_biguint(ab) + felt_to_biguint(bb)) % &p;
        let rhs = biguint_to_felt(&rhs_big).unwrap();
        assert_eq!(lhs, rhs);
    }

    /// Pure-integer re-check of every position equation on a generated row —
    /// isolates witness bugs from constraint-transcription bugs.
    #[test]
    fn witness_satisfies_position_equations() {
        let stmt = sample_statement(9);
        let row = gen_row(&stmt).expect("witness gen");
        let cols = row.columns();
        let get = |base: usize, i: usize| cols[base + i].0 as i64;
        let mut carry: i64 = 0;
        for k in 0..N_POSITIONS {
            let mut lhs: i64 = carry;
            for i in 0..=k.min(N_LIMBS - 1) {
                if k - i < N_LIMBS {
                    lhs += get(A_LIMBS, i) * get(B_LIMBS, k - i);
                }
            }
            let mut t: i64 = 0;
            if k < N_LIMBS {
                t += get(R_LIMBS, k);
            }
            for e in 0..LIMB_BITS {
                let idx = 9 * k + e;
                if idx < N_Q_BITS {
                    t += get(Q_BITS, idx) * (1i64 << e);
                }
                if idx + 1 >= N_Q_BITS && idx + 1 - N_Q_BITS < N_Q_BITS {
                    t += get(Q_BITS, idx + 1 - N_Q_BITS) * (1i64 << e);
                }
                if idx >= 192 && idx - 192 < N_Q_BITS {
                    t += get(Q_BITS, idx - 192) * 17 * (1i64 << e);
                }
            }
            lhs -= t;
            let carry_val = get(CARRY_OFF, k) - CARRY_BIAS as i64;
            if k == N_POSITIONS - 1 {
                assert_eq!(carry_val, 0, "final carry must vanish");
            } else {
                assert_eq!(lhs - 512 * carry_val, 0, "position {k} residual");
            }
            carry = carry_val;
        }
    }

    /// Diagnostic: which constraint index fails on the honest trace?
    /// Constraint order: booleanity (1792), limb consistency (84),
    /// carry decomposition (56), then position equations (56, by k).
    #[test]
    fn constraints_hold_on_honest_trace() {
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::AssertEvaluator;

        let log = 4;
        let stmts: Vec<_> = (0..4).map(sample_statement).collect();
        let mut rows = Vec::new();
        for stmt in &stmts {
            rows.push(gen_row(stmt).expect("witness").columns().to_vec());
        }
        let n_rows = 1usize << log;
        while rows.len() < n_rows {
            rows.push(padding_row());
        }
        let mut columns: Vec<Vec<BaseField>> = vec![vec![BaseField::from_u32_unchecked(0); n_rows]; N_COLUMNS];
        for (i, row) in rows.iter().enumerate() {
            for c in 0..N_COLUMNS {
                columns[c][i] = row[c];
            }
        }
        let col_refs: Vec<&Vec<BaseField>> = columns.iter().collect();
        let evals = TreeVec::new(vec![vec![], col_refs]);
        eprintln!(
            "row0 pos0: a0={} b0={} r0={} q0..8={:?} conv={} carry_off0={}",
            columns[A_LIMBS][0].0, columns[B_LIMBS][0].0, columns[R_LIMBS][0].0,
            (0..9).map(|e| columns[Q_BITS + e][0].0).collect::<Vec<_>>(),
            columns[A_LIMBS][0].0 * columns[B_LIMBS][0].0,
            columns[CARRY_OFF][0].0,
        );
        eprintln!(
            "row0 carry_off[0..3] = {:?}, bits[0..14] = {:?}",
            (0..3).map(|k| columns[CARRY_OFF + k][0].0).collect::<Vec<_>>(),
            (0..14).map(|j| columns[CARRY_BITS_BASE + j][0].0).collect::<Vec<_>>(),
        );
        for row in 0..n_rows {
            let evaluator = AssertEvaluator::new(&evals, row, log, starknet_felt_zero());
            FeltMulEval::new(log).evaluate(evaluator);
        }
    }

    fn starknet_felt_zero() -> stwo::core::fields::qm31::SecureField {
        stwo::core::fields::qm31::SecureField::from(0u32)
    }

    /// Find every seed whose witness violates the integer identity —
    /// exposes edge cases the single-seed check misses.
    #[test]
    fn scan_seed_edges() {
        let mut bad = Vec::new();
        for seed in 0..300u64 {
            let stmt = sample_statement(seed);
            let row = match gen_row(&stmt) {
                Ok(r) => r,
                Err(e) => {
                    bad.push((seed, format!("gen: {e}")));
                    continue;
                }
            };
            if let Err(e) = check_row_integers(&row, &stmt) {
                if seed < 2 {
                    let big_a = felt_to_biguint(stmt.a);
                    let big_b = felt_to_biguint(stmt.b);
                    let big_r = felt_to_biguint(stmt.r);
                    let q = ((&big_a * &big_b) - &big_r) / modulus_p();
                    eprintln!(
                        "seed {seed}: checker qbits[0..9]={:?} q hex={}",
                        (0..9)
                            .map(|i| q_bits_of(&q)[i].0)
                            .collect::<Vec<_>>(),
                        q.to_str_radix(16)
                    );
                }
                bad.push((seed, e));
            }
        }
        assert!(bad.is_empty(), "edge-case seeds: {bad:?}");
    }

    /// Honest prove → verify round trip (release only per repo discipline).
    #[test]
    #[cfg(not(debug_assertions))]
    fn honest_batch_prove_verify() {
        let stmts: Vec<_> = (0..4).map(sample_statement).collect();
        let proof = prove_felt_muls(&stmts, 4).expect("prove");
        verify_felt_muls(&FeltMulClaim::new(4), &proof).expect("verify");
    }

    /// A tampered claimed result must be rejected — the kernel verifies r,
    /// it does not recompute it, so no proof exists for a wrong r.
    #[test]
    #[cfg(not(debug_assertions))]
    fn tampered_result_rejected() {
        let mut stmts: Vec<_> = (0..4).map(sample_statement).collect();
        stmts[2].r = stmts[2].r + Felt::from(512u32); // bump limb 1
        assert!(
            prove_felt_muls(&stmts, 4).is_err(),
            "tampered result must not prove"
        );
    }
}
