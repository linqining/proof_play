//! Poseidon252 chain AIR, v2 — the cairo-air-style component decomposition
//! (see `git 历史（原 docs/plan-poseidon252-v2.md）`).
//!
//! Instead of one monolithic component, the chain statement is proven by five
//! components, each with a single log size:
//!
//! - [`ChainAir`] (chain log): the linking component.  It holds every
//!   per-round *value* limb and proves the linear structure — absorb,
//!   partial-round gate, mix linear combinations and borrow chains, position
//!   recursion, boundaries and the anchor.  The nonlinear algebra
//!   (squaring, cubing, modular reduction) is delegated through LogUp link
//!   tuples to the coprocessors below, mirroring how cairo-air links
//!   `poseidon_full_round_chain` to `cube_252`.
//! - [`MulAir`] (mul log): schoolbook coprocessor `a(32) × b(16) = c(48)`.
//! - [`ReduceAir`] (reduce log): modular coprocessor `x(48) = z(16) + q(32)·P`.
//! - [`RangeTableAir`] ×2: the 2^16 / 2^12 lookup tables.
//!
//! The state chain multiset `(state ‖ pos) → (zm ‖ pos_next)` with the
//! init/void boundaries is carried over verbatim from the verified v1
//! design.  Gadget rows come from [`crate::poseidon252_air`]'s
//! `build_chain_trace` (same arithmetic pass), padded with enabler-zero
//! rows to each component's own power-of-two domain.
//!
//! # Byte-scope binding (host-hash-free verification)
//!
//! The verification path recomputes no Poseidon permutation.  Three
//! mechanisms replace the former host recomputation:
//!
//! 1. **Input scope by root equality** — the preprocessed tree carries only
//!    public-byte-derived columns (position/flag/round-key/absorbed-word
//!    selectors and the initial state, plus the canonical range tables and
//!    the deterministic enabler columns).  The verifier rebuilds the entire
//!    expected tree from the public spec and requires the committed root to
//!    match, pinning every schedule value the ChainAir reads.
//! 2. **Anchor by Fiat–Shamir + constants** — the claimed anchor bytes are
//!    mixed into the transcript before any commitment, and the ChainAir
//!    pins its final boundary against the anchor's limb constants.
//! 3. **Derived values as witnesses** — the void tuple (terminal state of
//!    the padding walk over `n_pad` full zero-absorb permutations plus the
//!    truncated leftover rounds) rides in the witness tree and is forced by
//!    the multiset chain, not by preprocessed trust.
//!
//! 历史：#22⑤ 的 `zchain.string.v2` 名字承诺封装（prove/verify
//! name_commitment_v2）曾在本模块，随展示名出共识（poker_l1 v34）整体移除；
//! chain-spec 机制保留给状态根 Poseidon252 化（#42）复用。

#![allow(missing_docs)]

use starknet_crypto::Felt;
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, PackedBaseField};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{ComponentProver, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use num_traits::{One, Zero};

use bincode::Options as _;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
    TraceLocationAllocator, relation,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::poseidon252_air as native;
use native::{L, MulRow, ReduceRow};

// ===========================================================================
// Relations and preprocessed ids
// ===========================================================================

relation!(V2Range16, 1);
relation!(V2Range12, 1);
relation!(V2State, 49);
relation!(V2MulLink, 96);
relation!(V2RedLink, 96);
const _: () = assert!(native::STATE_TUPLE == 49, "state tuple arity");
const _: () = assert!(native::MUL_TUPLE == 96, "mul tuple arity");
const _: () = assert!(native::REDUCE_TUPLE == 96, "reduce tuple arity");

/// Input-side scope columns: position/flag/keys/words/selectors/init —
/// everything a verifier can rebuild from the public spec bytes.  The
/// derived void/anchor blocks are excluded (they are witness/eval-constant
/// data, the very values the STARK establishes).
pub const PUBLIC_SCOPE_COLUMNS: usize = native::S_VOID;

/// Indices into the shared preprocessed tree.
pub const PP_TABLE16: usize = PUBLIC_SCOPE_COLUMNS;
pub const PP_TABLE12: usize = PUBLIC_SCOPE_COLUMNS + 1;
pub const PP_MUL_ENABLER: usize = PUBLIC_SCOPE_COLUMNS + 2;
pub const PP_RED_ENABLER: usize = PUBLIC_SCOPE_COLUMNS + 3;

fn v2_preprocessed_ids() -> Vec<PreProcessedColumnId> {
    let mut ids: Vec<PreProcessedColumnId> = (0..PUBLIC_SCOPE_COLUMNS)
        .map(|index| PreProcessedColumnId {
            id: format!("poseidon252.v2.scope.{index}").into(),
        })
        .collect();
    ids.push(PreProcessedColumnId { id: "poseidon252.v2.table16".into() });
    ids.push(PreProcessedColumnId { id: "poseidon252.v2.table12".into() });
    ids.push(PreProcessedColumnId { id: "poseidon252.v2.mul.enabler".into() });
    ids.push(PreProcessedColumnId { id: "poseidon252.v2.red.enabler".into() });
    ids
}

// ===========================================================================
// Chain component column layout (explicit v1 index list — no interleaving)
// ===========================================================================

/// v1 witness columns committed by the chain component, in read order.
pub(crate) fn chain_witness_indices() -> Vec<usize> {
    use native::*;
    let mut idx: Vec<usize> = (W_STATE_IN..W_STATE_IN + 3 * L).collect();
    for lane in 0..3 {
        idx.extend(w_abs_out(lane)..w_abs_out(lane) + L);
        idx.extend(w_abs_carry(lane)..w_abs_carry(lane) + L);
    }
    for lane in 0..2 {
        idx.extend(w_sq(lane)..w_sq(lane) + 2 * L);
    }
    idx.extend(w_sq(2)..w_sq(2) + 2 * L); // lane-2 square == its x2
    for lane in 0..2 {
        idx.extend(w_x2(lane)..w_x2(lane) + 2 * L);
    }
    for lane in 0..3 {
        idx.extend(w_x3(lane)..w_x3(lane) + 3 * L);
    }
    for lane in 0..3 {
        idx.extend(w_q(lane)..w_q(lane) + 2 * L);
    }
    for lane in 0..3 {
        idx.extend(w_z(lane)..w_z(lane) + L);
    }
    // lanes 0/1 only: the ungated lane has no p columns (p2 aliases z2).
    for lane in 0..2 {
        idx.extend(w_p(lane)..w_p(lane) + L);
    }
    idx.extend(w_t()..w_t() + L);
    // tc follows t contiguously in the v1 layout.
    idx.extend(w_t() + L..w_t() + 2 * L);
    // mix lane 0: d, dc, v, vc, qm, zm (no u/uc/bw/rc — those moved or are
    // structural zeros).
    idx.extend(w_mix_d(0)..w_mix_d(0) + L);
    idx.extend(w_mix_dc(0)..w_mix_dc(0) + L);
    idx.extend(w_mix_v(0)..w_mix_v(0) + L);
    idx.extend(w_mix_vc(0)..w_mix_vc(0) + L);
    idx.push(w_mix_qm(0));
    idx.extend(w_mix_zm(0)..w_mix_zm(0) + L);
    // mix lanes 1/2: d, dc, u, uc, v, bw, qm, zm (vc is zero, rc moved).
    for lane in 1..3 {
        idx.extend(w_mix_d(lane)..w_mix_d(lane) + L);
        idx.extend(w_mix_dc(lane)..w_mix_dc(lane) + L);
        idx.extend(w_mix_u(lane)..w_mix_u(lane) + L);
        idx.extend(w_mix_uc(lane)..w_mix_uc(lane) + L);
        idx.extend(w_mix_v(lane)..w_mix_v(lane) + L);
        idx.extend(w_mix_bw(lane)..w_mix_bw(lane) + L);
        idx.push(w_mix_qm(lane));
        idx.extend(w_mix_zm(lane)..w_mix_zm(lane) + L);
    }
    idx.push(W_POS_NEXT);
    idx.push(W_IS_WRAP);
    idx
}

// Segment offsets inside the chain witness read order.
const CH_STATE_IN: usize = 0;
const CH_ABS: usize = CH_STATE_IN + 3 * L;
const CH_SQ01: usize = CH_ABS + 6 * L;
const CH_X2_2: usize = CH_SQ01 + 4 * L;
const CH_X201: usize = CH_X2_2 + 2 * L;
const CH_X3: usize = CH_X201 + 4 * L;
const CH_Q: usize = CH_X3 + 9 * L;
const CH_Z: usize = CH_Q + 6 * L;
const CH_P: usize = CH_Z + 3 * L; // lanes 0/1 only (2L)
const CH_T: usize = CH_P + 2 * L;
// lane 0: d, dc, v, vc, qm, zm (5L + 1); lanes 1/2: d, dc, u, uc, v, bw,
// qm, zm (7L + 1).
const MIX0_WIDTH_V2: usize = 5 * L + 1;
const MIX12_WIDTH_V2: usize = 7 * L + 1;
const CH_MIX0: usize = CH_T + 2 * L;
const CH_MIX1: usize = CH_MIX0 + MIX0_WIDTH_V2;
const CH_MIX2: usize = CH_MIX1 + MIX12_WIDTH_V2;
const CH_POS_NEXT: usize = CH_MIX2 + MIX12_WIDTH_V2;
const CH_IS_WRAP: usize = CH_POS_NEXT + 1;
pub const CHAIN_WITNESS_COLUMNS: usize = CH_IS_WRAP + 1;

// Per-lane offsets inside the mix segments (v2 compressed layout).
const MIX_D: usize = 0;
const MIX_DC: usize = L;
const MIX_U: usize = 2 * L;
const MIX_UC: usize = 3 * L;
const MIX_V0: usize = 2 * L; // lane 0
const MIX_VC0: usize = 3 * L; // lane 0 carry
const MIX_V: usize = 4 * L; // lanes 1/2
const MIX_BW: usize = 5 * L; // lanes 1/2
const MIX_QM0: usize = 4 * L; // lane 0
const MIX_ZM0: usize = 4 * L + 1;
const MIX12_QM: usize = 6 * L; // lanes 1/2
const MIX12_ZM: usize = 6 * L + 1;

#[inline]
fn mix_v_off(lane: usize) -> usize {
    if lane == 0 { MIX_V0 } else { MIX_V }
}
#[inline]
fn mix_qm_off(lane: usize) -> usize {
    if lane == 0 { MIX_QM0 } else { MIX12_QM }
}
#[inline]
fn mix_zm_off(lane: usize) -> usize {
    if lane == 0 { MIX_ZM0 } else { MIX12_ZM }
}

/// Fixed LogUp entry layout of the chain component (per row).
const CH_ENTRIES_STATE: usize = 4;
const CH_ENTRIES_SQUARE: usize = 3;
const CH_ENTRIES_CUBE: usize = 3;
const CH_ENTRIES_CRED: usize = 3;
const CH_ENTRIES_MRED: usize = 3;
const CH_ENTRIES_RANGE: usize = 4 * L; // t (16) + d lanes (48)
const CH_ENTRIES: usize = CH_ENTRIES_STATE
    + CH_ENTRIES_SQUARE
    + CH_ENTRIES_CUBE
    + CH_ENTRIES_CRED
    + CH_ENTRIES_MRED
    + CH_ENTRIES_RANGE;
pub const CHAIN_FRACTION_COLUMNS: usize = CH_ENTRIES.div_ceil(2);

/// Fixed LogUp entry layout of the coprocessors.
const MUL_ENTRIES: usize = 1 + native::MUL_TUPLE; // link + a/b/c limbs
pub const MUL_FRACTION_COLUMNS: usize = MUL_ENTRIES.div_ceil(2);
const RED_ENTRIES: usize = 2 + native::REDUCE_TUPLE; // link + x/z/q limbs + bound12
pub const REDUCE_FRACTION_COLUMNS: usize = RED_ENTRIES.div_ceil(2);

// ===========================================================================
// ChainAir
// ===========================================================================

#[derive(Clone)]
pub struct ChainAir {
    log_size: u32,
    range16: V2Range16,
    state: V2State,
    mul_link: V2MulLink,
    red_link: V2RedLink,
    /// The public anchor limbs (from the claimed anchor bytes).  The final
    /// boundary pins the chain's terminal state against these constants, so
    /// the STARK itself — not a host recomputation — ties the proof to the
    /// claimed value.
    anchor: [[M31; native::L]; 3],
}

impl FrameworkEval for ChainAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let m = |v: u32| E::F::from(M31::from(v));
        let zero = m(0);
        let one = m(1);
        let base = m(1 << 16);
        
        // ---- preprocessed (v1 scope order) ----
        let ids = v2_ids();
        let pos = eval.get_preprocessed_column(ids[native::S_POS].clone());
        let is_full = eval.get_preprocessed_column(ids[native::S_IS_FULL].clone());
        let mut k: Vec<Vec<E::F>> = Vec::with_capacity(3);
        for lane in 0..3 {
            let mut lane_keys = Vec::with_capacity(L);
            for i in 0..L {
                lane_keys
                    .push(eval.get_preprocessed_column(ids[native::S_K + lane * L + i].clone()));
            }
            k.push(lane_keys);
        }
        let mut w: Vec<Vec<E::F>> = Vec::with_capacity(2);
        for lane in 0..2 {
            let mut lane_words = Vec::with_capacity(L);
            for i in 0..L {
                lane_words
                    .push(eval.get_preprocessed_column(ids[native::S_W + lane * L + i].clone()));
            }
            w.push(lane_words);
        }
        let mut sel: Vec<E::F> = Vec::with_capacity(3);
        for s in 0..3 {
            sel.push(eval.get_preprocessed_column(ids[native::S_SEL + s].clone()));
        }
        let mut init = Vec::with_capacity(native::STATE_TUPLE);
        for i in 0..3 * L {
            init.push(eval.get_preprocessed_column(ids[native::S_INIT + i].clone()));
        }
        init.push(eval.get_preprocessed_column(ids[native::S_INIT + 3 * L].clone()));
        let anchor_limbs: Vec<E::F> = self
            .anchor
            .iter()
            .flat_map(|lane| lane.iter())
            .map(|&limb| E::F::from(limb))
            .collect();

        // ---- witness (chain read order) ----
        macro_rules! read_vec {
            ($n:expr) => {{
                let mut v = Vec::with_capacity($n);
                for _ in 0..$n {
                    v.push(eval.next_trace_mask());
                }
                v
            }};
        }
        let state_in_flat = read_vec!(3 * L);
        let abs_flat = read_vec!(6 * L);
        let sq01_flat = read_vec!(4 * L);
        let x2_2_flat = read_vec!(2 * L);
        let x201_flat = read_vec!(4 * L);
        let x3_flat = read_vec!(9 * L);
        let q_flat = read_vec!(6 * L);
        let z_flat = read_vec!(3 * L);
        let p01_flat = read_vec!(2 * L);
        let t_flat = read_vec!(L);
        let tc = read_vec!(L);
        let mix0 = read_vec!(MIX0_WIDTH_V2);
        let mix1 = read_vec!(MIX12_WIDTH_V2);
        let mix2 = read_vec!(MIX12_WIDTH_V2);
        let pos_next = eval.next_trace_mask();
        let is_wrap = eval.next_trace_mask();
        // The void tuple (state ‖ void_pos) is derived data — the terminal
        // state of the padding permutation — so it rides in the witness
        // tree, read last, after every other chain column.
        let void_t = read_vec!(native::STATE_TUPLE);

        let lane_of = |flat: &[E::F], lane: usize, width: usize| -> Vec<E::F> {
            flat[lane * width..(lane + 1) * width].to_vec()
        };
        let mut state_in = Vec::with_capacity(3);
        for lane in 0..3 {
            state_in.push(lane_of(&state_in_flat, lane, L));
        }
        let mut abs_out = Vec::with_capacity(3);
        let mut abs_carry = Vec::with_capacity(3);
        for lane in 0..3 {
            abs_out.push(lane_of(&abs_flat, 2 * lane, L));
            abs_carry.push(lane_of(&abs_flat, 2 * lane + 1, L));
        }
        let mut sq = Vec::with_capacity(3);
        for lane in 0..2 {
            sq.push(lane_of(&sq01_flat, lane, 2 * L));
        }
        sq.push(x2_2_flat.clone()); // lane 2: square == x2
        let mut x2 = Vec::with_capacity(3);
        for lane in 0..2 {
            x2.push(lane_of(&x201_flat, lane, 2 * L));
        }
        x2.push(x2_2_flat);
        let mut x3 = Vec::with_capacity(3);
        for lane in 0..3 {
            x3.push(lane_of(&x3_flat, lane, 3 * L));
        }
        let mut qc_cols = Vec::with_capacity(3);
        for lane in 0..3 {
            qc_cols.push(lane_of(&q_flat, lane, 2 * L));
        }
        let mut z = Vec::with_capacity(3);
        for lane in 0..3 {
            z.push(lane_of(&z_flat, lane, L));
        }
        let mut p = Vec::with_capacity(3);
        for lane in 0..2 {
            p.push(lane_of(&p01_flat, lane, L));
        }
        p.push(z[2].clone()); // ungated lane: p2 aliases z2
        let t = t_flat;
        let mix = [mix0, mix1, mix2];

        // =================================================================
        // Constraints (linear / gated / boundary only — algebra is delegated)
        // =================================================================

        // ---- absorb + round constant: s_c = state_in + w + k ----
        for lane in 0..3 {
            for i in 0..L {
                let absorbed = if lane == 2 { zero.clone() } else { w[lane][i].clone() };
                let mut acc = state_in[lane][i].clone() + absorbed + k[lane][i].clone();
                if i > 0 {
                    acc = acc + abs_carry[lane][i - 1].clone();
                }
                let rhs = abs_out[lane][i].clone() + base.clone() * abs_carry[lane][i].clone();
                eval.add_constraint(acc - rhs);
            }
            eval.add_constraint(abs_carry[lane][L - 1].clone());
        }

        // ---- gate: x2 = is_full · sq (lanes 0/1) ----
        for lane in 0..2 {
            for i in 0..2 * L {
                eval.add_constraint(
                    x2[lane][i].clone() - is_full.clone() * sq[lane][i].clone(),
                );
            }
        }

        // ---- gated post-sbox value: p = is_full·z + (1−is_full)·s_c ----
        for lane in 0..2 {
            for i in 0..L {
                let gated = p[lane][i].clone()
                    - is_full.clone() * z[lane][i].clone()
                    - (one.clone() - is_full.clone()) * abs_out[lane][i].clone();
                eval.add_constraint(gated);
            }
        }

        // ---- mix: t = p0 + p1 + p2 ----
        for i in 0..L {
            let mut acc = p[0][i].clone() + p[1][i].clone() + z[2][i].clone();
            if i > 0 {
                acc = acc + tc[i - 1].clone();
            }
            let rhs = t[i].clone() + base.clone() * tc[i].clone();
            eval.add_constraint(acc - rhs);
        }
        eval.add_constraint(tc[L - 1].clone());

        // ---- mix lanes ----
        let p4 = native::p_multiple(4);
        let p6 = native::p_multiple(6);
        let p16 = native::P_LIMBS;
        for lane in 0..3 {
            let (d, dc): (Vec<E::F>, Vec<E::F>) = (
                (0..L).map(|i| mix[lane][MIX_D + i].clone()).collect(),
                (0..L).map(|i| mix[lane][MIX_DC + i].clone()).collect(),
            );
            let u = |i: usize| -> E::F {
                if lane == 0 {
                    t[i].clone()
                } else {
                    mix[lane][MIX_U + i].clone()
                }
            };
            let uc = |i: usize| -> E::F {
                if lane == 0 {
                    tc[i].clone()
                } else {
                    mix[lane][MIX_UC + i].clone()
                }
            };
            let v = |i: usize| -> E::F { mix[lane][mix_v_off(lane) + i].clone() };
            let vc = |i: usize| -> E::F { mix[lane][MIX_VC0 + i].clone() };
            let bw = |i: usize| -> E::F { mix[lane][MIX_BW + i].clone() };
            let qm = || -> E::F { mix[lane][mix_qm_off(lane)].clone() };
            let zm = |i: usize| -> E::F { mix[lane][mix_zm_off(lane) + i].clone() };

            // d = coeff · source
            let coeff: u32 = if lane == 2 { 3 } else { 2 };
            let source = |i: usize| -> E::F {
                if lane < 2 {
                    p[lane][i].clone()
                } else {
                    z[2][i].clone()
                }
            };
            for i in 0..L {
                let mut acc = source(i) * m(coeff);
                if i > 0 {
                    acc = acc + dc[i - 1].clone();
                }
                let rhs = d[i].clone() + base.clone() * dc[i].clone();
                eval.add_constraint(acc - rhs);
            }
            eval.add_constraint(dc[L - 1].clone());

            if lane == 0 {
                // v = d + t
                for i in 0..L {
                    let mut acc = d[i].clone() + t[i].clone();
                    if i > 0 {
                        acc = acc + vc(i - 1);
                    }
                    let rhs = v(i) + base.clone() * vc(i);
                    eval.add_constraint(acc - rhs);
                }
                eval.add_constraint(vc(L - 1));
            } else {
                // u = t + m·P
                let multiple = if lane == 1 { &p4 } else { &p6 };
                for i in 0..L {
                    let mut acc = t[i].clone() + m(multiple[i] as u32);
                    if i > 0 {
                        acc = acc + uc(i - 1);
                    }
                    let rhs = u(i) + base.clone() * uc(i);
                    eval.add_constraint(acc - rhs);
                }
                eval.add_constraint(uc(L - 1));
                // v = u − d (borrow chain)
                for i in 0..L {
                    let mut acc = u(i) - d[i].clone();
                    if i > 0 {
                        acc = acc - bw(i - 1);
                    }
                    acc = acc + base.clone() * bw(i);
                    eval.add_constraint(acc - v(i));
                }
                eval.add_constraint(bw(L - 1));
            }
            let _ = (p16, qm, zm);
        }

        // ---- round position recurrence ----
        let rec = pos_next.clone() - pos.clone() - one.clone()
            + m(native::ROUND_COUNT as u32) * is_wrap.clone();
        eval.add_constraint(rec);
        eval.add_constraint(is_wrap.clone() * (is_wrap.clone() - one.clone()));

        // ---- boundary pinning ----
        let mut in_tuple: Vec<E::F> = Vec::with_capacity(native::STATE_TUPLE);
        for lane in 0..3 {
            in_tuple.extend(state_in[lane].iter().cloned());
        }
        in_tuple.push(pos.clone());
        let mut out_tuple: Vec<E::F> = Vec::with_capacity(native::STATE_TUPLE);
        for lane in 0..3 {
            let off = mix_zm_off(lane);
            out_tuple.extend((0..L).map(|i| mix[lane][off + i].clone()));
        }
        out_tuple.push(pos_next.clone());
        for i in 0..3 * L {
            eval.add_constraint(sel[0].clone() * (in_tuple[i].clone() - init[i].clone()));
            eval.add_constraint(
                sel[2].clone() * (out_tuple[i].clone() - anchor_limbs[i].clone()),
            );
        }

        // ---- LogUp entries (fixed order, algebraic multiplicities) ----
        // 1..4: state chain (verbatim from the verified v1 design).
        eval.add_to_relation(RelationEntry::new(&self.state, -E::EF::one(), &in_tuple));
        eval.add_to_relation(RelationEntry::new(&self.state, E::EF::one(), &out_tuple));
        eval.add_to_relation(RelationEntry::new(&self.state, E::EF::from(sel[0].clone()), &init));
        eval.add_to_relation(RelationEntry::new(&self.state, -E::EF::from(sel[1].clone()), &void_t));

        // 5..7: square links (a = s_c ‖ 0¹⁶, b = s_c, c = sq ‖ 0¹⁶).
        let is_full_ef = E::EF::from(is_full.clone());
        let one_ef = E::EF::one();
        for lane in 0..3 {
            let mult = if lane == 2 { one_ef.clone() } else { is_full_ef.clone() };
            let mut coords: Vec<E::F> = Vec::with_capacity(native::MUL_TUPLE);
            for i in 0..2 * L {
                coords.push(if i < L { abs_out[lane][i].clone() } else { zero.clone() });
            }
            coords.extend(abs_out[lane].iter().cloned());
            for i in 0..3 * L {
                coords.push(if i < 2 * L { sq[lane][i].clone() } else { zero.clone() });
            }
            eval.add_to_relation(RelationEntry::new(&self.mul_link, mult.clone(), &coords));
        }
        // 8..10: cube links (a = x2, b = s_c, c = x3).
        for lane in 0..3 {
            let mult = if lane == 2 { one_ef.clone() } else { is_full_ef.clone() };
            let mut coords: Vec<E::F> = Vec::with_capacity(native::MUL_TUPLE);
            coords.extend(x2[lane].iter().cloned());
            coords.extend(abs_out[lane].iter().cloned());
            coords.extend(x3[lane].iter().cloned());
            eval.add_to_relation(RelationEntry::new(&self.mul_link, mult.clone(), &coords));
        }
        // 11..13: cube-reduce links (x = x3, z, q).
        for lane in 0..3 {
            let mult = if lane == 2 { one_ef.clone() } else { is_full_ef.clone() };
            let mut coords: Vec<E::F> = Vec::with_capacity(native::REDUCE_TUPLE);
            coords.extend(x3[lane].iter().cloned());
            coords.extend(z[lane].iter().cloned());
            coords.extend(qc_cols[lane].iter().cloned());
            eval.add_to_relation(RelationEntry::new(&self.red_link, mult.clone(), &coords));
        }
        // 14..16: mix-reduce links (x = v ‖ 0³², z = zm, q = qm ‖ 0³¹).
        for lane in 0..3 {
            let v_off = mix_v_off(lane);
            let qm_off = mix_qm_off(lane);
            let zm_off = mix_zm_off(lane);
            let mut coords: Vec<E::F> = Vec::with_capacity(native::REDUCE_TUPLE);
            for i in 0..3 * L {
                coords.push(if i < L { mix[lane][v_off + i].clone() } else { zero.clone() });
            }
            coords.extend((0..L).map(|i| mix[lane][zm_off + i].clone()));
            for i in 0..2 * L {
                coords.push(if i == 0 { mix[lane][qm_off].clone() } else { zero.clone() });
            }
            eval.add_to_relation(RelationEntry::new(&self.red_link, one_ef.clone(), &coords));
        }
        // 17..80: chain-owned range16 limbs: t then d lanes.
        for i in 0..L {
            eval.add_to_relation(RelationEntry::new(
                &self.range16,
                E::EF::one(),
                &[t[i].clone()],
            ));
        }
        for lane in 0..3 {
            for i in 0..L {
                eval.add_to_relation(RelationEntry::new(
                    &self.range16,
                    E::EF::one(),
                    &[mix[lane][MIX_D + i].clone()],
                ));
            }
        }

        eval.finalize_logup_in_pairs();
        eval
    }
}

fn v2_ids() -> Vec<PreProcessedColumnId> {
    use std::sync::OnceLock;
    static IDS: OnceLock<Vec<PreProcessedColumnId>> = OnceLock::new();
    IDS.get_or_init(v2_preprocessed_ids).clone()
}

// ===========================================================================
// MulAir — a(32) × b(16) = c(48) coprocessor
// ===========================================================================

#[derive(Clone)]
pub struct MulAir {
    log_size: u32,
    range16: V2Range16,
    link: V2MulLink,
}

impl MulAir {
    fn enabler<E: EvalAtRow>(&self, eval: &mut E) -> E::F {
        eval.get_preprocessed_column(v2_ids()[PP_MUL_ENABLER].clone())
    }
}

impl FrameworkEval for MulAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let m = |v: u32| E::F::from(M31::from(v));
        let zero = m(0);
        let base = m(1 << 16);
        let enabler = self.enabler(&mut eval);

        let mut a = Vec::with_capacity(native::MUL_A_LIMBS);
        for _ in 0..native::MUL_A_LIMBS {
            a.push(eval.next_trace_mask());
        }
        let mut b = Vec::with_capacity(native::MUL_B_LIMBS);
        for _ in 0..native::MUL_B_LIMBS {
            b.push(eval.next_trace_mask());
        }
        let mut c = Vec::with_capacity(native::MUL_C_LIMBS);
        for _ in 0..native::MUL_C_LIMBS {
            c.push(eval.next_trace_mask());
        }
        let mut carry = Vec::with_capacity(native::GADGET_CARRY_LIMBS);
        for _ in 0..native::GADGET_CARRY_LIMBS {
            carry.push(eval.next_trace_mask());
        }

        // convolution: c = a · b over the integers.
        for kk in 0..native::MUL_C_LIMBS {
            let mut term = if kk == 0 { zero.clone() } else { carry[kk - 1].clone() };
            for i in 0..native::MUL_A_LIMBS.min(kk + 1) {
                let j = kk - i;
                if j < native::MUL_B_LIMBS {
                    term = term + a[i].clone() * b[j].clone();
                }
            }
            if kk < native::MUL_C_LIMBS - 1 {
                let rhs = c[kk].clone() + base.clone() * carry[kk].clone();
                eval.add_constraint(term - rhs);
            } else {
                eval.add_constraint(c[kk].clone() - term);
            }
        }

        // link tuple with multiplicity −enabler (padding rows vanish).
        let mut coords: Vec<E::F> = Vec::with_capacity(native::MUL_TUPLE);
        coords.extend(a.iter().cloned());
        coords.extend(b.iter().cloned());
        coords.extend(c.iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            &self.link,
            -E::EF::from(enabler.clone()),
            &coords,
        ));
        for value in coords.iter().take(native::MUL_TUPLE) {
            eval.add_to_relation(RelationEntry::new(
                &self.range16,
                E::EF::one(),
                &[value.clone()],
            ));
        }
        eval.finalize_logup_in_pairs();
        eval
    }
}

// ===========================================================================
// ReduceAir — x(48) = z(16) + q(32)·P coprocessor
// ===========================================================================

#[derive(Clone)]
pub struct ReduceAir {
    log_size: u32,
    range16: V2Range16,
    range12: V2Range12,
    link: V2RedLink,
}

impl ReduceAir {
    fn enabler<E: EvalAtRow>(&self, eval: &mut E) -> E::F {
        eval.get_preprocessed_column(v2_ids()[PP_RED_ENABLER].clone())
    }
}

impl FrameworkEval for ReduceAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let m = |v: u32| E::F::from(M31::from(v));
        let zero = m(0);
        let base = m(1 << 16);
        let p16 = native::P_LIMBS;
        let enabler = self.enabler(&mut eval);

        let mut x = Vec::with_capacity(native::RED_X_LIMBS);
        for _ in 0..native::RED_X_LIMBS {
            x.push(eval.next_trace_mask());
        }
        let mut z = Vec::with_capacity(L);
        for _ in 0..L {
            z.push(eval.next_trace_mask());
        }
        let mut q = Vec::with_capacity(native::RED_Q_LIMBS);
        for _ in 0..native::RED_Q_LIMBS {
            q.push(eval.next_trace_mask());
        }
        let mut carry = Vec::with_capacity(native::GADGET_CARRY_LIMBS);
        for _ in 0..native::GADGET_CARRY_LIMBS {
            carry.push(eval.next_trace_mask());
        }

        // x = z + q·P limb-wise.
        for kk in 0..native::RED_X_LIMBS {
            let mut term = if kk == 0 { zero.clone() } else { carry[kk - 1].clone() };
            if kk < L {
                term = term + z[kk].clone();
            }
            for i in 0..native::RED_Q_LIMBS.min(kk + 1) {
                let j = kk - i;
                if j < L {
                    term = term + q[i].clone() * m(p16[j] as u32);
                }
            }
            if kk < native::RED_X_LIMBS - 1 {
                let rhs = x[kk].clone() + base.clone() * carry[kk].clone();
                eval.add_constraint(term - rhs);
            } else {
                eval.add_constraint(x[kk].clone() - term);
            }
        }

        let mut coords: Vec<E::F> = Vec::with_capacity(native::REDUCE_TUPLE);
        coords.extend(x.iter().cloned());
        coords.extend(z.iter().cloned());
        coords.extend(q.iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            &self.link,
            -E::EF::from(enabler.clone()),
            &coords,
        ));
        for value in coords.iter().take(native::REDUCE_TUPLE) {
            eval.add_to_relation(RelationEntry::new(
                &self.range16,
                E::EF::one(),
                &[value.clone()],
            ));
        }
        // top limb of the reduced value stays below 2^12 (value < 2^252).
        eval.add_to_relation(RelationEntry::new(
            &self.range12,
            E::EF::one(),
            &[z[L - 1].clone()],
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

// ===========================================================================
// Range tables
// ===========================================================================

#[derive(Clone)]
pub struct RangeTableAir {
    log_size: u32,
    column: usize,
    range16: V2Range16,
    range12: V2Range12,
}

impl RangeTableAir {
    pub fn table16(log_size: u32, range16: V2Range16, range12: V2Range12) -> Self {
        Self { log_size, column: PP_TABLE16, range16, range12 }
    }
    pub fn table12(log_size: u32, range16: V2Range16, range12: V2Range12) -> Self {
        Self { log_size, column: PP_TABLE12, range16, range12 }
    }
}

impl FrameworkEval for RangeTableAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let value = eval.get_preprocessed_column(v2_ids()[self.column].clone());
        let multiplicity = eval.next_trace_mask();
        if self.column == PP_TABLE16 {
            eval.add_to_relation(RelationEntry::new(
                &self.range16,
                -E::EF::from(multiplicity),
                &[value],
            ));
        } else {
            eval.add_to_relation(RelationEntry::new(
                &self.range12,
                -E::EF::from(multiplicity),
                &[value],
            ));
        }
        eval.finalize_logup_in_pairs();
        eval
    }
}

// ===========================================================================
// Honest traces for the coprocessors
// ===========================================================================

/// Padded witness columns of the mul coprocessor: a, b, c, carry, plus the
/// preprocessed enabler column.
pub(crate) fn mul_columns(rows: &[MulRow], log: u32) -> (Vec<Vec<M31>>, Vec<M31>) {
    let n = 1usize << log;
    let mut cols = vec![vec![M31::from(0u32); n]; native::MUL_A_LIMBS + native::MUL_B_LIMBS + native::MUL_C_LIMBS + native::GADGET_CARRY_LIMBS];
    let mut enabler = vec![M31::from(0u32); n];
    let (la, lb) = (native::MUL_A_LIMBS, native::MUL_B_LIMBS);
    let lc = native::MUL_C_LIMBS;
    for (row, mr) in rows.iter().enumerate() {
        for i in 0..la {
            cols[i][row] = M31::from(mr.a[i] as u32);
        }
        for i in 0..lb {
            cols[la + i][row] = M31::from(mr.b[i] as u32);
        }
        for i in 0..lc {
            cols[la + lb + i][row] = M31::from(mr.c[i] as u32);
        }
        for i in 0..native::GADGET_CARRY_LIMBS {
            cols[la + lb + lc + i][row] = M31::from(mr.carry[i]);
        }
        enabler[row] = M31::from(1u32);
    }
    (cols, enabler)
}

/// Padded witness columns of the reduce coprocessor: x, z, q, carry, plus
/// the preprocessed enabler column.
pub(crate) fn reduce_columns(rows: &[ReduceRow], log: u32) -> (Vec<Vec<M31>>, Vec<M31>) {
    let n = 1usize << log;
    let mut cols = vec![vec![M31::from(0u32); n]; native::RED_X_LIMBS + L + native::RED_Q_LIMBS + native::GADGET_CARRY_LIMBS];
    let mut enabler = vec![M31::from(0u32); n];
    let (lx, lz) = (native::RED_X_LIMBS, L);
    let lq = native::RED_Q_LIMBS;
    for (row, rr) in rows.iter().enumerate() {
        for i in 0..lx {
            cols[i][row] = M31::from(rr.x[i] as u32);
        }
        for i in 0..lz {
            cols[lx + i][row] = M31::from(rr.z[i] as u32);
        }
        for i in 0..lq {
            cols[lx + lz + i][row] = M31::from(rr.q[i] as u32);
        }
        for i in 0..native::GADGET_CARRY_LIMBS {
            cols[lx + lz + lq + i][row] = M31::from(rr.carry[i]);
        }
        enabler[row] = M31::from(1u32);
    }
    (cols, enabler)
}

// ===========================================================================
// Interaction traces
// ===========================================================================

type PackedEval = CircleEvaluation<SimdBackend, M31, BitReversedOrder>;

/// The one tested pairing formula (v1's fixed numerator/denominator
/// accumulation, mirroring the official `write_frac(d0 + d1, d0·d1)`).
fn paired_logup(
    log_size: u32,
    n_entries: usize,
    entry: impl Fn(usize, usize) -> (PackedSecureField, PackedSecureField),
) -> (Vec<PackedEval>, SecureField) {
    let vec_rows = 1usize << (log_size - LOG_N_LANES);
    let mut lgen = LogupTraceGenerator::new(log_size);
    for batch in 0..n_entries.div_ceil(2) {
        let mut col = lgen.new_col();
        for vec_row in 0..vec_rows {
            let mut num_acc: Option<PackedSecureField> = None;
            let mut den_acc: Option<PackedSecureField> = None;
            for entry_index in [batch * 2, batch * 2 + 1] {
                if entry_index >= n_entries {
                    continue;
                }
                let (mult, denom) = entry(entry_index, vec_row);
                num_acc = Some(match num_acc {
                    None => mult,
                    Some(prev) => prev * denom.clone() + mult * den_acc.clone().unwrap(),
                });
                den_acc = Some(match den_acc {
                    None => denom,
                    Some(prev) => prev * denom,
                });
            }
            col.write_frac(
                vec_row,
                num_acc.unwrap_or_else(PackedSecureField::zero),
                den_acc.unwrap_or_else(PackedSecureField::one),
            );
        }
        col.finalize_col();
    }
    lgen.finalize_last()
}

fn pk(cols: &[BaseColumn], col: usize, vec_row: usize) -> PackedBaseField {
    cols[col].data[vec_row]
}

/// Chain interaction trace.  Entry order mirrors `ChainAir::evaluate`.
pub(crate) fn chain_interaction_trace(
    chain_cols: &[BaseColumn],
    scope_cols: &[BaseColumn],
    log_size: u32,
    range16: &V2Range16,
    range12: &V2Range12,
    state: &V2State,
    mul_link: &V2MulLink,
    red_link: &V2RedLink,
) -> (Vec<PackedEval>, SecureField) {
    let ch = |col: usize, vr: usize| pk(chain_cols, col, vr);
    let sc = |col: usize, vr: usize| pk(scope_cols, col, vr);

    let entries: Vec<Box<dyn Fn(usize) -> (PackedSecureField, PackedSecureField) + '_>> = vec![
        // 0: StateIn
        Box::new(|vr| {
            let mut coords = Vec::with_capacity(native::STATE_TUPLE);
            for lane in 0..3 {
                for i in 0..L {
                    coords.push(ch(CH_STATE_IN + lane * L + i, vr));
                }
            }
            coords.push(sc(native::S_POS, vr));
            (-PackedSecureField::one(), state.combine(&coords))
        }),
        // 1: StateOut
        Box::new(|vr| {
            let mut coords = Vec::with_capacity(native::STATE_TUPLE);
            for lane in 0..3 {
                let base = if lane == 0 { CH_MIX0 } else { CH_MIX1 + (lane - 1) * MIX12_WIDTH_V2 };
                let off = base + mix_zm_off(lane);
                for i in 0..L {
                    coords.push(ch(off + i, vr));
                }
            }
            coords.push(ch(CH_POS_NEXT, vr));
            (PackedSecureField::one(), state.combine(&coords))
        }),
        // 2: Init
        Box::new(|vr| {
            let coords: Vec<PackedBaseField> =
                (0..native::STATE_TUPLE).map(|i| sc(native::S_INIT + i, vr)).collect();
            (
                PackedSecureField::from(sc(native::S_SEL, vr)),
                state.combine(&coords),
            )
        }),
        // 3: Void
        Box::new(|vr| {
            let coords: Vec<PackedBaseField> =
                (0..native::STATE_TUPLE).map(|i| sc(native::S_VOID + i, vr)).collect();
            (
                -PackedSecureField::from(sc(native::S_SEL + 1, vr)),
                state.combine(&coords),
            )
        }),
    ];

    // square/cube/cube-reduce links per lane; multiplicities: lane 2 always,
    // lanes 0/1 gated by is_full.
    let mut all_entries: Vec<Box<dyn Fn(usize) -> (PackedSecureField, PackedSecureField) + '_>> =
        entries;
    let abs_lane = |lane: usize| CH_ABS + lane * 2 * L;
    let sq_lane = |lane: usize| if lane < 2 { CH_SQ01 + lane * 2 * L } else { CH_X2_2 };
    let x2_lane = |lane: usize| if lane < 2 { CH_X201 + lane * 2 * L } else { CH_X2_2 };
    let x3_lane = |lane: usize| CH_X3 + lane * 3 * L;
    let q_lane = |lane: usize| CH_Q + lane * 2 * L;
    let z_lane = |lane: usize| CH_Z + lane * L;
    let mix_lane = |lane: usize| if lane == 0 { CH_MIX0 } else { CH_MIX1 + (lane - 1) * MIX12_WIDTH_V2 };

    for lane in 0..3 {
        // square link
        let la = abs_lane(lane);
        let ls = sq_lane(lane);
        all_entries.push(Box::new(move |vr: usize| {
            let mut coords = Vec::with_capacity(native::MUL_TUPLE);
            for i in 0..2 * L {
                coords.push(if i < L { ch(la + i, vr) } else { PackedBaseField::zero() });
            }
            for i in 0..L {
                coords.push(ch(la + i, vr));
            }
            for i in 0..3 * L {
                coords.push(if i < 2 * L { ch(ls + i, vr) } else { PackedBaseField::zero() });
            }
            let mult = if lane == 2 {
                PackedSecureField::one()
            } else {
                PackedSecureField::from(sc(native::S_IS_FULL, vr))
            };
            (mult, mul_link.combine(&coords))
        }));
    }
    for lane in 0..3 {
        // cube link
        let lx2 = x2_lane(lane);
        let la = abs_lane(lane);
        let lx3 = x3_lane(lane);
        all_entries.push(Box::new(move |vr: usize| {
            let mut coords = Vec::with_capacity(native::MUL_TUPLE);
            for i in 0..2 * L {
                coords.push(ch(lx2 + i, vr));
            }
            for i in 0..L {
                coords.push(ch(la + i, vr));
            }
            for i in 0..3 * L {
                coords.push(ch(lx3 + i, vr));
            }
            let mult = if lane == 2 {
                PackedSecureField::one()
            } else {
                PackedSecureField::from(sc(native::S_IS_FULL, vr))
            };
            (mult, mul_link.combine(&coords))
        }));
    }
    for lane in 0..3 {
        // cube-reduce link
        let lx3 = x3_lane(lane);
        let lz = z_lane(lane);
        let lq = q_lane(lane);
        all_entries.push(Box::new(move |vr: usize| {
            let mut coords = Vec::with_capacity(native::REDUCE_TUPLE);
            for i in 0..3 * L {
                coords.push(ch(lx3 + i, vr));
            }
            for i in 0..L {
                coords.push(ch(lz + i, vr));
            }
            for i in 0..2 * L {
                coords.push(ch(lq + i, vr));
            }
            let mult = if lane == 2 {
                PackedSecureField::one()
            } else {
                PackedSecureField::from(sc(native::S_IS_FULL, vr))
            };
            (mult, red_link.combine(&coords))
        }));
    }
    for lane in 0..3 {
        // mix-reduce link
        let lm = mix_lane(lane);
        let qm_off = mix_qm_off(lane);
        let zm_off = mix_zm_off(lane);
        all_entries.push(Box::new(move |vr: usize| {
            let mut coords = Vec::with_capacity(native::REDUCE_TUPLE);
            for i in 0..3 * L {
                coords.push(if i < L {
                    ch(lm + mix_v_off(lane) + i, vr)
                } else {
                    PackedBaseField::zero()
                });
            }
            for i in 0..L {
                coords.push(ch(lm + zm_off + i, vr));
            }
            for i in 0..2 * L {
                coords.push(if i == 0 {
                    ch(lm + qm_off, vr)
                } else {
                    PackedBaseField::zero()
                });
            }
            (PackedSecureField::one(), red_link.combine(&coords))
        }));
    }
    // chain-owned range16 limbs: t then d lanes.
    for i in 0..L {
        all_entries.push(Box::new(move |vr: usize| {
            (PackedSecureField::one(), range16.combine(&[ch(CH_T + i, vr)]))
        }));
    }
    for lane in 0..3 {
        let lm = mix_lane(lane);
        for i in 0..L {
            all_entries.push(Box::new(move |vr: usize| {
                (PackedSecureField::one(), range16.combine(&[ch(lm + MIX_D + i, vr)]))
            }));
        }
    }
    let _ = range12; // the chain owns no 2^12 entries

    assert_eq!(all_entries.len(), CH_ENTRIES);
    let n = all_entries.len();
    paired_logup(log_size, n, move |entry_index, vec_row| {
        all_entries[entry_index](vec_row)
    })
}

/// Mul coprocessor interaction trace (link + a/b/c range entries).
pub(crate) fn mul_interaction_trace(
    cols: &[BaseColumn],
    enabler: &BaseColumn,
    log_size: u32,
    range16: &V2Range16,
    link: &V2MulLink,
) -> (Vec<PackedEval>, SecureField) {
    let (la, lb) = (native::MUL_A_LIMBS, native::MUL_B_LIMBS);
    let lc = native::MUL_C_LIMBS;
    let mut entries: Vec<Box<dyn Fn(usize) -> (PackedSecureField, PackedSecureField) + '_>> =
        Vec::with_capacity(MUL_ENTRIES);
    entries.push(Box::new(|vr: usize| {
        let mut coords = Vec::with_capacity(native::MUL_TUPLE);
        for i in 0..la {
            coords.push(pk(cols, i, vr));
        }
        for i in 0..lb {
            coords.push(pk(cols, la + i, vr));
        }
        for i in 0..lc {
            coords.push(pk(cols, la + lb + i, vr));
        }
        (
            -PackedSecureField::from(enabler.data[vr]),
            link.combine(&coords),
        )
    }));
    for i in 0..native::MUL_TUPLE {
        entries.push(Box::new(move |vr: usize| {
            (
                PackedSecureField::one(),
                range16.combine(&[pk(cols, i, vr)]),
            )
        }));
    }
    let n = entries.len();
    paired_logup(log_size, n, move |e, vr| entries[e](vr))
}

/// Reduce coprocessor interaction trace (link + x/z/q range entries + z-top
/// 2^12 bound).
pub(crate) fn reduce_interaction_trace(
    cols: &[BaseColumn],
    enabler: &BaseColumn,
    log_size: u32,
    range16: &V2Range16,
    range12: &V2Range12,
    link: &V2RedLink,
) -> (Vec<PackedEval>, SecureField) {
    let (lx, lz) = (native::RED_X_LIMBS, L);
    let lq = native::RED_Q_LIMBS;
    let mut entries: Vec<Box<dyn Fn(usize) -> (PackedSecureField, PackedSecureField) + '_>> =
        Vec::with_capacity(RED_ENTRIES);
    entries.push(Box::new(|vr: usize| {
        let mut coords = Vec::with_capacity(native::REDUCE_TUPLE);
        for i in 0..lx {
            coords.push(pk(cols, i, vr));
        }
        for i in 0..lz {
            coords.push(pk(cols, lx + i, vr));
        }
        for i in 0..lq {
            coords.push(pk(cols, lx + lz + i, vr));
        }
        (
            -PackedSecureField::from(enabler.data[vr]),
            link.combine(&coords),
        )
    }));
    for i in 0..native::REDUCE_TUPLE {
        entries.push(Box::new(move |vr: usize| {
            (
                PackedSecureField::one(),
                range16.combine(&[pk(cols, i, vr)]),
            )
        }));
    }
    entries.push(Box::new(move |vr: usize| {
        (
            PackedSecureField::one(),
            range12.combine(&[pk(cols, lx + L - 1, vr)]),
        )
    }));
    let n = entries.len();
    paired_logup(log_size, n, move |e, vr| entries[e](vr))
}

fn table_interaction_trace(
    table_log: u32,
    value_column: &BaseColumn,
    multiplicities: &[u32],
    use_range16: bool,
    range16: &V2Range16,
    range12: &V2Range12,
) -> (Vec<PackedEval>, SecureField) {
    let mut mult_values: Vec<M31> = multiplicities.iter().map(|&v| M31::from(v)).collect();
    bit_reverse_coset_to_circle_domain_order(&mut mult_values);
    let mult = BaseColumn::from_iter(mult_values);
    paired_logup(table_log, 1, |_, vr| {
        let denom = if use_range16 {
            range16.combine(&[value_column.data[vr]])
        } else {
            range12.combine(&[value_column.data[vr]])
        };
        (-PackedSecureField::from(mult.data[vr]), denom)
    })
}

// ===========================================================================
// Prove / verify drivers
// ===========================================================================

fn v2_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(0, 1, 30, 1),
        lifting_log_size: None,
    }
}

fn column_eval(
    log_size: u32,
    column: &[M31],
) -> CircleEvaluation<SimdBackend, M31, BitReversedOrder> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    CircleEvaluation::new(domain, BaseColumn::from_iter(column.iter().copied()))
}

fn range_table_values(log: u32) -> Vec<M31> {
    let mut values: Vec<M31> = (0..1usize << log).map(|i| M31::from(i as u32)).collect();
    bit_reverse_coset_to_circle_domain_order(&mut values);
    values
}

fn mix_digest(channel: &mut Poseidon252Channel, digest: &[u8; 32]) {
    channel.mix_u32s(
        &digest
            .chunks_exact(4)
            .map(|x| u32::from_be_bytes(x.try_into().expect("digest word")))
            .collect::<Vec<_>>(),
    );
}

fn range_tables_digest() -> [u8; 32] {
    // The fixed table statement: (2^16, 2^12) identity tables.
    crate::blake3_flock::blake3_chain_digest(&16u32.to_le_bytes())
}

fn secure_to_words(value: SecureField) -> [u32; 8] {
    let arr = value.to_m31_array();
    let mut words = [0u32; 8];
    for (i, m) in arr.iter().enumerate() {
        words[2 * i] = m.0 & 0xffff;
        words[2 * i + 1] = m.0 >> 16;
    }
    words
}

fn words_to_secure(words: &[u32; 8]) -> SecureField {
    let arr = [
        M31::from(words[0] | (words[1] << 16)),
        M31::from(words[2] | (words[3] << 16)),
        M31::from(words[4] | (words[5] << 16)),
        M31::from(words[6] | (words[7] << 16)),
    ];
    SecureField::from_m31_array(arr)
}

#[derive(borsh::BorshDeserialize, borsh::BorshSerialize, Clone)]
pub struct ArchivedPoseidon252V2Proof {
    pub spec: native::Poseidon252ChainSpec,
    pub log_size: u32,
    pub mul_log: u32,
    pub reduce_log: u32,
    pub claimed_anchor: [[u8; 32]; 3],
    pub logup_sums: [[u32; 8]; 5],
    pub stark_proof_bytes: Vec<u8>,
}

/// Decompose the claimed anchor bytes into the M31 limb constants the
/// ChainAir pins its final boundary against.
fn claimed_anchor_limbs(
    claimed: &[[u8; 32]; 3],
) -> TexasAirResult<[[M31; native::L]; 3]> {
    let mut out = [[M31::from(0u32); native::L]; 3];
    for (lane, bytes) in claimed.iter().enumerate() {
        // types-core from_bytes_be 无失败路径，canonical 用字节往返判定
        // （语义同旧 0.6 ff Result 路径：≥ P 拒绝）。
        let felt = crate::state_root::felt_from_canonical_bytes(bytes).ok_or(
            TexasAirError::ConstraintUnsatisfied(
                "v2 claimed anchor carries a non-canonical felt".into(),
            ),
        )?;
        let limbs = native::felt_to_limbs(&felt);
        for (i, &limb) in limbs.iter().enumerate() {
            out[lane][i] = M31::from(limb as u32);
        }
    }
    Ok(out)
}

/// Rebuild the full expected preprocessed tree from public data alone and
/// return its root: the input-side scope schedule from the spec bytes, the
/// two canonical range tables, and the two coprocessor enabler columns
/// derived from the deterministic row counts.  The prover commits exactly
/// this tree, so a root match pins every preprocessed column the ChainAir
/// reads to the public byte scope.
fn v2_expected_preprocessed_root(
    spec: &native::Poseidon252ChainSpec,
    mul_log: u32,
    reduce_log: u32,
) -> TexasAirResult<<Poseidon252MerkleHasher as MerkleHasherLifted>::Hash> {
    let log_size = spec.layout().log_size;
    let (mul_rows, red_rows) = native::coprocessor_row_counts(spec);

    let mut scope = native::public_scope_columns(spec)?;
    for col in scope.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    let mut mul_en = vec![M31::from(0u32); 1usize << mul_log];
    for row in mul_en.iter_mut().take(mul_rows) {
        *row = M31::from(1u32);
    }
    let mut red_en = vec![M31::from(0u32); 1usize << reduce_log];
    for row in red_en.iter_mut().take(red_rows) {
        *row = M31::from(1u32);
    }
    bit_reverse_coset_to_circle_domain_order(&mut mul_en);
    bit_reverse_coset_to_circle_domain_order(&mut red_en);

    let max_log = native::TABLE16_LOG
        .max(log_size)
        .max(mul_log)
        .max(reduce_log);
    let config = v2_pcs_config();
    let twiddles = crate::prover_context::simd_twiddles(
        max_log + 1 + config.fri_config.log_blowup_factor,
    );

    let mut throwaway = Poseidon252Channel::default();
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();
    {
        let mut tree = scheme.tree_builder();
        for col in &scope {
            tree.extend_evals(vec![column_eval(log_size, col)]);
        }
        tree.extend_evals(vec![column_eval(
            native::TABLE16_LOG,
            &range_table_values(native::TABLE16_LOG),
        )]);
        tree.extend_evals(vec![column_eval(
            native::TABLE12_LOG,
            &range_table_values(native::TABLE12_LOG),
        )]);
        tree.extend_evals(vec![column_eval(mul_log, &mul_en)]);
        tree.extend_evals(vec![column_eval(reduce_log, &red_en)]);
        tree.commit(&mut throwaway);
    }
    Ok(scheme.roots()[0])
}

/// Prove the chain statement with the v2 component decomposition.
pub fn prove_poseidon252_chain_v2(
    spec: &native::Poseidon252ChainSpec,
) -> TexasAirResult<ArchivedPoseidon252V2Proof> {
    spec.validate()?;
    let mut trace = native::build_chain_trace(spec)?;
    let log_size = trace.log_size;
    let mul_log = trace.mul_log;
    let reduce_log = trace.reduce_log;

    // Assemble every committed column in tree order, then convert once.
    // The chain witness block ends with the void tuple (derived data, read
    // last by the eval), which used to live in the preprocessed tree.
    let chain_indices = chain_witness_indices();
    let mut chain_cols: Vec<Vec<M31>> =
        chain_indices.iter().map(|&c| trace.witness[c].clone()).collect();
    chain_cols.extend(
        trace.scope[native::S_VOID..native::S_VOID + native::STATE_TUPLE]
            .iter()
            .cloned(),
    );
    for col in chain_cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    let (mut mul_cols, mul_enabler) = mul_columns(&trace.mul_rows, mul_log);
    let (mut red_cols, red_enabler) = reduce_columns(&trace.reduce_rows, reduce_log);
    for col in mul_cols.iter_mut().chain(red_cols.iter_mut()) {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    for col in trace.scope.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    let mut mul_en_col = mul_enabler;
    let mut red_en_col = red_enabler;
    bit_reverse_coset_to_circle_domain_order(&mut mul_en_col);
    bit_reverse_coset_to_circle_domain_order(&mut red_en_col);

    // Range-table multiplicities: chain + coprocessor contributions.
    let mut mult16 = vec![0u32; 1 << 16];
    let mut mult12 = vec![0u32; 1 << 12];
    for row in 0..(1usize << log_size) {
        // t limbs (16) then the three mix d limbs (16 each).
        for i in 0..L {
            mult16[trace.witness[native::w_t() + i][row].0 as usize] += 1;
        }
        for lane in 0..3 {
            for i in 0..L {
                mult16[trace.witness[native::w_mix_d(lane) + i][row].0 as usize] += 1;
            }
        }
    }
    for mr in &trace.mul_rows {
        for limb in mr.a.iter().chain(&mr.b).chain(&mr.c) {
            mult16[*limb as usize] += 1;
        }
    }
    for rr in &trace.reduce_rows {
        for limb in rr.x.iter().chain(&rr.z).chain(&rr.q) {
            mult16[*limb as usize] += 1;
        }
        mult12[rr.z[L - 1] as usize] += 1;
    }
    // padding rows of the coprocessors feed zero limbs into the 2^16 table.
    let mul_pad = (1usize << mul_log) - trace.mul_rows.len();
    let red_pad = (1usize << reduce_log) - trace.reduce_rows.len();
    mult16[0] += native::MUL_TUPLE as u32 * mul_pad as u32;
    mult16[0] += native::REDUCE_TUPLE as u32 * red_pad as u32;
    mult12[0] += red_pad as u32;
    let mut mult16_col: Vec<M31> = mult16.iter().map(|&v| M31::from(v)).collect();
    let mut mult12_col: Vec<M31> = mult12.iter().map(|&v| M31::from(v)).collect();
    bit_reverse_coset_to_circle_domain_order(&mut mult16_col);
    bit_reverse_coset_to_circle_domain_order(&mut mult12_col);

    let max_log = native::TABLE16_LOG.max(log_size).max(mul_log).max(reduce_log);
    let config = v2_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(max_log + 1 + config.fri_config.log_blowup_factor);

    let claimed_anchor: [[u8; 32]; 3] = spec
        .anchor_state()
        .iter()
        .map(|f| f.to_bytes_be())
        .collect::<Vec<_>>()
        .try_into()
        .expect("3 felts");
    let anchor: [[M31; native::L]; 3] = std::array::from_fn(|lane| {
        let felt = Felt::from_bytes_be(&claimed_anchor[lane]);
        let limbs = native::felt_to_limbs(&felt);
        std::array::from_fn(|i| M31::from(limbs[i] as u32))
    });

    let mut channel = Poseidon252Channel::default();
    mix_digest(&mut channel, &spec.statement_digest());
    mix_digest(&mut channel, &range_tables_digest());
    // Bind the claimed anchor bytes into the Fiat–Shamir transcript before
    // any commitment: the STARK's pinned constants and the public claim then
    // live on the same challenge path.
    for lane in &claimed_anchor {
        mix_digest(&mut channel, lane);
    }

    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    {
        let mut tree = scheme.tree_builder();
        for col in trace.scope[..PUBLIC_SCOPE_COLUMNS].iter() {
            tree.extend_evals(vec![column_eval(log_size, col)]);
        }
        tree.extend_evals(vec![column_eval(native::TABLE16_LOG, &range_table_values(native::TABLE16_LOG))]);
        tree.extend_evals(vec![column_eval(native::TABLE12_LOG, &range_table_values(native::TABLE12_LOG))]);
        tree.extend_evals(vec![column_eval(mul_log, &mul_en_col)]);
        tree.extend_evals(vec![column_eval(reduce_log, &red_en_col)]);
        tree.commit(&mut channel);
    }
    {
        // Span order must follow component creation order: chain, mul,
        // reduce, then the two table multiplicities.
        let mut tree = scheme.tree_builder();
        for col in &chain_cols {
            tree.extend_evals(vec![column_eval(log_size, col)]);
        }
        for col in &mul_cols {
            tree.extend_evals(vec![column_eval(mul_log, col)]);
        }
        for col in &red_cols {
            tree.extend_evals(vec![column_eval(reduce_log, col)]);
        }
        tree.extend_evals(vec![column_eval(native::TABLE16_LOG, &mult16_col)]);
        tree.extend_evals(vec![column_eval(native::TABLE12_LOG, &mult12_col)]);
        tree.commit(&mut channel);
    }

    let range16 = V2Range16::draw(&mut channel);
    let range12 = V2Range12::draw(&mut channel);
    let state = V2State::draw(&mut channel);
    let mul_link = V2MulLink::draw(&mut channel);
    let red_link = V2RedLink::draw(&mut channel);

    let chain_base: Vec<BaseColumn> = chain_cols.iter().map(|c| BaseColumn::from_iter(c.iter().copied())).collect();
    let scope_base: Vec<BaseColumn> = trace.scope.iter().map(|c| BaseColumn::from_iter(c.iter().copied())).collect();
    let mul_base: Vec<BaseColumn> = mul_cols.iter().map(|c| BaseColumn::from_iter(c.iter().copied())).collect();
    let red_base: Vec<BaseColumn> = red_cols.iter().map(|c| BaseColumn::from_iter(c.iter().copied())).collect();
    let mul_en_base = BaseColumn::from_iter(mul_en_col.iter().copied());
    let red_en_base = BaseColumn::from_iter(red_en_col.iter().copied());
    let t16_value = BaseColumn::from_iter(range_table_values(native::TABLE16_LOG).iter().copied());
    let t12_value = BaseColumn::from_iter(range_table_values(native::TABLE12_LOG).iter().copied());

    let (chain_i, chain_sum) = chain_interaction_trace(
        &chain_base, &scope_base, log_size, &range16, &range12, &state, &mul_link, &red_link,
    );
    let (mul_i, mul_sum) =
        mul_interaction_trace(&mul_base, &mul_en_base, mul_log, &range16, &mul_link);
    let (red_i, red_sum) =
        reduce_interaction_trace(&red_base, &red_en_base, reduce_log, &range16, &range12, &red_link);
    let (t16_i, t16_sum) = table_interaction_trace(
        native::TABLE16_LOG, &t16_value, &mult16, true, &range16, &range12,
    );
    let (t12_i, t12_sum) = table_interaction_trace(
        native::TABLE12_LOG, &t12_value, &mult12, false, &range16, &range12,
    );
    assert_eq!(
        chain_sum + mul_sum + red_sum + t16_sum + t12_sum,
        SecureField::from(0u32),
        "v2 logup balance across components"
    );
    channel.mix_felts(&[chain_sum, mul_sum, red_sum, t16_sum, t12_sum]);
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(
            chain_i
                .into_iter()
                .chain(mul_i)
                .chain(red_i)
                .chain(t16_i)
                .chain(t12_i)
                .collect::<Vec<_>>(),
        );
        tree.commit(&mut channel);
    }

    let ids = v2_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let components: Vec<Box<dyn ComponentProver<SimdBackend>>> = vec![
        Box::new(FrameworkComponent::new(
            &mut allocator,
            ChainAir {
                log_size,
                range16: range16.clone(),
                state: state.clone(),
                mul_link: mul_link.clone(),
                red_link: red_link.clone(),
                anchor,
            },
            chain_sum,
        )),
        Box::new(FrameworkComponent::new(
            &mut allocator,
            MulAir {
                log_size: mul_log,
                range16: range16.clone(),
                link: mul_link.clone(),
            },
            mul_sum,
        )),
        Box::new(FrameworkComponent::new(
            &mut allocator,
            ReduceAir {
                log_size: reduce_log,
                range16: range16.clone(),
                range12: range12.clone(),
                link: red_link.clone(),
            },
            red_sum,
        )),
        Box::new(FrameworkComponent::new(
            &mut allocator,
            RangeTableAir::table16(native::TABLE16_LOG, range16.clone(), range12.clone()),
            t16_sum,
        )),
        Box::new(FrameworkComponent::new(
            &mut allocator,
            RangeTableAir::table12(native::TABLE12_LOG, range16, range12),
            t12_sum,
        )),
    ];
    let proof = prove(
        &components.iter().map(|c| c.as_ref() as &dyn ComponentProver<SimdBackend>).collect::<Vec<_>>(),
        &mut channel,
        scheme,
    )
    .map_err(|e| TexasAirError::SpecViolation(format!("poseidon252 v2 prove failed: {e:?}")))?;

    Ok(ArchivedPoseidon252V2Proof {
        spec: spec.clone(),
        log_size,
        mul_log,
        reduce_log,
        claimed_anchor,
        logup_sums: [
            secure_to_words(chain_sum),
            secure_to_words(mul_sum),
            secure_to_words(red_sum),
            secure_to_words(t16_sum),
            secure_to_words(t12_sum),
        ],
        stark_proof_bytes: bincode::options()
            .with_fixint_encoding()
            .with_limit(1024 * 1024 * 1024)
            .serialize(&proof)
            .map_err(|e| TexasAirError::SerializationError(e.to_string()))?,
    })
}

/// Verify a v2 chain proof against the public spec.
pub fn verify_poseidon252_chain_v2(
    archive: &ArchivedPoseidon252V2Proof,
) -> TexasAirResult<()> {
    archive.spec.validate()?;
    let layout = archive.spec.layout();
    if layout.log_size != archive.log_size {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "v2 log size detached from the spec layout".into(),
        ));
    }
    // No host Poseidon recomputation on this path: the anchor is pinned by
    // the STARK's final-boundary constants, the claimed bytes are mixed into
    // the Fiat–Shamir transcript before any commitment, and the whole input
    // scope (keys, absorbed words, selectors, initial state) is pinned by the
    // expected-preprocessed-root comparison below.
    let (expected_mul, expected_red) = native::coprocessor_row_counts(&archive.spec);
    if archive.mul_log != expected_mul.next_power_of_two().max(2).ilog2()
        || archive.reduce_log != expected_red.next_power_of_two().max(2).ilog2()
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "v2 coprocessor layouts detached from the spec".into(),
        ));
    }
    for lane in archive.claimed_anchor.iter() {
        if crate::state_root::felt_from_canonical_bytes(lane).is_none() {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "v2 claimed anchor carries a non-canonical felt".into(),
            ));
        }
    }

    let log_size = archive.log_size;
    let mul_log = archive.mul_log;
    let reduce_log = archive.reduce_log;
    let config = v2_pcs_config();
    let proof: StarkProof<Poseidon252MerkleHasher> = bincode::options()
        .with_fixint_encoding()
        .with_limit(1024 * 1024 * 1024)
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;

    let mut channel = Poseidon252Channel::default();
    mix_digest(&mut channel, &archive.spec.statement_digest());
    mix_digest(&mut channel, &range_tables_digest());
    for lane in &archive.claimed_anchor {
        mix_digest(&mut channel, lane);
    }

    // Byte-scope binding: rebuild the entire expected preprocessed tree from
    // public data (the input-side scope schedule, both range tables, both
    // enabler columns) and require the committed root to match.  From here
    // on, every scope column the ChainAir reads is public-byte-derived.
    let expected_root =
        v2_expected_preprocessed_root(&archive.spec, archive.mul_log, archive.reduce_log)?;
    if expected_root != proof.commitments[0] {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "v2 preprocessed tree detached from the public byte scope".into(),
        ));
    }

    let mut verifier = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    let mut pre_sizes = vec![log_size; PUBLIC_SCOPE_COLUMNS];
    pre_sizes.push(native::TABLE16_LOG);
    pre_sizes.push(native::TABLE12_LOG);
    pre_sizes.push(mul_log);
    pre_sizes.push(reduce_log);
    verifier.commit(proof.commitments[0], &pre_sizes, &mut channel);

    // Channel order mirrors the prover: preprocessed, witness, relations,
    // sums, interaction.
    let chain_cols = chain_witness_indices().len();
    let mul_witness = native::MUL_A_LIMBS + native::MUL_B_LIMBS + native::MUL_C_LIMBS
        + native::GADGET_CARRY_LIMBS;
    let red_witness = native::RED_X_LIMBS + L + native::RED_Q_LIMBS + native::GADGET_CARRY_LIMBS;
    let mut wit_sizes = vec![log_size; chain_cols + native::STATE_TUPLE];
    wit_sizes.extend(vec![mul_log; mul_witness]);
    wit_sizes.extend(vec![reduce_log; red_witness]);
    wit_sizes.push(native::TABLE16_LOG);
    wit_sizes.push(native::TABLE12_LOG);
    verifier.commit(proof.commitments[1], &wit_sizes, &mut channel);

    let range16 = V2Range16::draw(&mut channel);
    let range12 = V2Range12::draw(&mut channel);
    let state = V2State::draw(&mut channel);
    let mul_link = V2MulLink::draw(&mut channel);
    let red_link = V2RedLink::draw(&mut channel);

    let sums: Vec<SecureField> =
        archive.logup_sums.iter().map(|w| words_to_secure(w)).collect();
    if sums.iter().fold(SecureField::from(0u32), |a, b| a + *b) != SecureField::from(0u32) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "v2 logup sums do not balance".into(),
        ));
    }
    channel.mix_felts(&sums);

    let mut int_sizes = vec![log_size; CHAIN_FRACTION_COLUMNS * 4];
    int_sizes.extend(vec![mul_log; MUL_FRACTION_COLUMNS * 4]);
    int_sizes.extend(vec![reduce_log; REDUCE_FRACTION_COLUMNS * 4]);
    int_sizes.extend(vec![native::TABLE16_LOG; 4]);
    int_sizes.extend(vec![native::TABLE12_LOG; 4]);
    verifier.commit(proof.commitments[2], &int_sizes, &mut channel);

    let ids = v2_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let components: Vec<Box<dyn stwo::core::air::Component>> = vec![
        Box::new(FrameworkComponent::new(
            &mut allocator,
            ChainAir {
                log_size,
                range16: range16.clone(),
                state: state.clone(),
                mul_link: mul_link.clone(),
                red_link: red_link.clone(),
                anchor: claimed_anchor_limbs(&archive.claimed_anchor)?,
            },
            sums[0],
        )),
        Box::new(FrameworkComponent::new(
            &mut allocator,
            MulAir {
                log_size: mul_log,
                range16: range16.clone(),
                link: mul_link.clone(),
            },
            sums[1],
        )),
        Box::new(FrameworkComponent::new(
            &mut allocator,
            ReduceAir {
                log_size: reduce_log,
                range16: range16.clone(),
                range12: range12.clone(),
                link: red_link.clone(),
            },
            sums[2],
        )),
        Box::new(FrameworkComponent::new(
            &mut allocator,
            RangeTableAir::table16(native::TABLE16_LOG, range16.clone(), range12.clone()),
            sums[3],
        )),
        Box::new(FrameworkComponent::new(
            &mut allocator,
            RangeTableAir::table12(native::TABLE12_LOG, range16, range12),
            sums[4],
        )),
    ];
    verify(
        &components.iter().map(|c| c.as_ref() as &dyn stwo::core::air::Component).collect::<Vec<_>>(),
        &mut channel,
        &mut verifier,
        proof,
    )
    .map_err(|e| {
        TexasAirError::ConstraintUnsatisfied(format!("poseidon252 v2 verification failed: {e:?}"))
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn small_spec() -> native::Poseidon252ChainSpec {
        let message = [Felt::from(7u64), Felt::from(9u64)];
        native::Poseidon252ChainSpec::hash_many(&message)
    }

    #[test]
    fn chain_witness_layout_matches_segments() {
        let idx = chain_witness_indices();
        assert_eq!(idx.len(), CHAIN_WITNESS_COLUMNS);
        // spot-check segment starts against the v1 accessors.
        assert_eq!(idx[CH_STATE_IN], native::W_STATE_IN);
        assert_eq!(idx[CH_ABS], native::w_abs_out(0));
        assert_eq!(idx[CH_SQ01], native::w_sq(0));
        assert_eq!(idx[CH_X2_2], native::w_sq(2));
        assert_eq!(idx[CH_X201], native::w_x2(0));
        assert_eq!(idx[CH_X3], native::w_x3(0));
        assert_eq!(idx[CH_Q], native::w_q(0));
        assert_eq!(idx[CH_Z], native::w_z(0));
        assert_eq!(idx[CH_P], native::w_p(0));
        assert_eq!(idx[CH_T], native::w_t());
        assert_eq!(idx[CH_MIX0], native::w_mix_d(0));
        assert_eq!(idx[CH_MIX1], native::w_mix_d(1));
        assert_eq!(idx[CH_MIX2], native::w_mix_d(2));
        assert_eq!(idx[CH_POS_NEXT], native::W_POS_NEXT);
        assert_eq!(idx[CH_IS_WRAP], native::W_IS_WRAP);
    }

    #[test]
    fn v2_rowcheck() {
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;
        use stwo_constraint_framework::PREPROCESSED_TRACE_IDX;
        let spec = small_spec();
        let mut trace = native::build_chain_trace(&spec).unwrap();
        let log_size = trace.log_size;
        let mul_log = trace.mul_log;
        let reduce_log = trace.reduce_log;

        for col in trace.scope.iter_mut().chain(trace.witness.iter_mut()) {
            bit_reverse_coset_to_circle_domain_order(col);
        }
        let chain_indices = chain_witness_indices();
        let chain_cols: Vec<Vec<M31>> =
            chain_indices.iter().map(|&c| trace.witness[c].clone()).collect();
        let (mul_cols, mul_en) = mul_columns(&trace.mul_rows, mul_log);
        let (red_cols, red_en) = reduce_columns(&trace.reduce_rows, reduce_log);

        let mut mult16 = vec![0u32; 1 << 16];
        let mut mult12 = vec![0u32; 1 << 12];
        for row in 0..(1usize << log_size) {
            for i in 0..L {
                mult16[trace.witness[native::w_t() + i][row].0 as usize] += 1;
            }
            for lane in 0..3 {
                for i in 0..L {
                    mult16[trace.witness[native::w_mix_d(lane) + i][row].0 as usize] += 1;
                }
            }
        }
        for mr in &trace.mul_rows {
            for limb in mr.a.iter().chain(&mr.b).chain(&mr.c) {
                mult16[*limb as usize] += 1;
            }
        }
        for rr in &trace.reduce_rows {
            for limb in rr.x.iter().chain(&rr.z).chain(&rr.q) {
                mult16[*limb as usize] += 1;
            }
            mult12[rr.z[L - 1] as usize] += 1;
        }
        let mul_pad = (1usize << mul_log) - trace.mul_rows.len();
        let red_pad = (1usize << reduce_log) - trace.reduce_rows.len();
        mult16[0] += native::MUL_TUPLE as u32 * mul_pad as u32;
        mult16[0] += native::REDUCE_TUPLE as u32 * red_pad as u32;
        mult12[0] += red_pad as u32;
        let mut mult16_col: Vec<M31> = mult16.iter().map(|&v| M31::from(v)).collect();
        let mut mult12_col: Vec<M31> = mult12.iter().map(|&v| M31::from(v)).collect();
        bit_reverse_coset_to_circle_domain_order(&mut mult16_col);
        bit_reverse_coset_to_circle_domain_order(&mut mult12_col);

        let mut channel = Poseidon252Channel::default();
        let r16 = V2Range16::draw(&mut channel);
        let r12 = V2Range12::draw(&mut channel);
        let st = V2State::draw(&mut channel);
        let ml = V2MulLink::draw(&mut channel);
        let rl = V2RedLink::draw(&mut channel);

        let chain_base: Vec<BaseColumn> = chain_cols.iter().map(|c| BaseColumn::from_iter(c.iter().copied())).collect();
        let scope_base: Vec<BaseColumn> = trace.scope.iter().map(|c| BaseColumn::from_iter(c.iter().copied())).collect();
        let mul_base: Vec<BaseColumn> = mul_cols.iter().map(|c| BaseColumn::from_iter(c.iter().copied())).collect();
        let red_base: Vec<BaseColumn> = red_cols.iter().map(|c| BaseColumn::from_iter(c.iter().copied())).collect();
        let mul_en_base = BaseColumn::from_iter(mul_en.iter().copied());
        let red_en_base = BaseColumn::from_iter(red_en.iter().copied());
        let t16_value = BaseColumn::from_iter(range_table_values(native::TABLE16_LOG).iter().copied());
        let t12_value = BaseColumn::from_iter(range_table_values(native::TABLE12_LOG).iter().copied());

        let (chain_i, chain_sum) = chain_interaction_trace(&chain_base, &scope_base, log_size, &r16, &r12, &st, &ml, &rl);
        let (mul_i, mul_sum) = mul_interaction_trace(&mul_base, &mul_en_base, mul_log, &r16, &ml);
        let (red_i, red_sum) = reduce_interaction_trace(&red_base, &red_en_base, reduce_log, &r16, &r12, &rl);
        let (t16_i, t16_sum) = table_interaction_trace(native::TABLE16_LOG, &t16_value, &mult16, true, &r16, &r12);
        let (t12_i, t12_sum) = table_interaction_trace(native::TABLE12_LOG, &t12_value, &mult12, false, &r16, &r12);
        assert_eq!(chain_sum + mul_sum + red_sum + t16_sum + t12_sum, SecureField::from(0u32));

        let unpack = |evals: &Vec<PackedEval>| -> Vec<Vec<M31>> {
            let mut cols = vec![Vec::new(); 4];
            for e in evals {
                for (i, packed) in e.data.iter().enumerate() {
                    let lanes = packed.to_array();
                    for c in 0..4 {
                        if i == 0 {
                            cols[c] = Vec::with_capacity(1 << e.domain.log_size());
                        }
                        cols[c].extend(lanes.iter().map(|l| if c == 0 { *l } else { *l }));
                    }
                }
            }
            // restructure: evals are (frac_col, coord) pairs — evals[k*4+c]
            let _ = &mut cols;
            let mut out: Vec<Vec<M31>> = Vec::new();
            for e in evals {
                let mut v = Vec::with_capacity(1 << e.domain.log_size());
                for packed in e.data.iter() {
                    v.extend(packed.to_array());
                }
                out.push(v);
            }
            out
        };
        let chain_flat = unpack(&chain_i);
        let mul_flat = unpack(&mul_i);
        let red_flat = unpack(&red_i);
        let t16_flat = unpack(&t16_i);
        let t12_flat = unpack(&t12_i);

        // trees in span order (preprocessed = public scope prefix only)
        let preprocessed: Vec<Vec<M31>> = trace.scope[..PUBLIC_SCOPE_COLUMNS]
            .iter()
            .cloned()
            .chain([range_table_values(native::TABLE16_LOG)])
            .chain([range_table_values(native::TABLE12_LOG)])
            .chain([mul_en.clone()])
            .chain([red_en.clone()])
            .collect();
        let witness: Vec<Vec<M31>> = chain_cols
            .iter()
            .cloned()
            .chain(trace.scope[native::S_VOID..native::S_VOID + native::STATE_TUPLE].iter().cloned())
            .chain(mul_cols.iter().cloned())
            .chain(red_cols.iter().cloned())
            .chain([mult16_col.clone()])
            .chain([mult12_col.clone()])
            .collect();
        let interaction: Vec<Vec<M31>> = chain_flat
            .into_iter()
            .chain(mul_flat)
            .chain(red_flat)
            .chain(t16_flat)
            .chain(t12_flat)
            .collect();

        let tree_refs = TreeVec::new(vec![
            preprocessed.iter().collect::<Vec<_>>(),
            witness.iter().collect::<Vec<_>>(),
            interaction.iter().collect::<Vec<_>>(),
        ]);

        let ids = v2_ids();
        let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
        let components: Vec<(&'static str, u32, Box<dyn std::any::Any>)> = Vec::new();
        let _ = &components;
        macro_rules! check {
            ($name:expr, $air:expr, $sum:expr, $log:expr) => {{
                let air = $air;
                let component = FrameworkComponent::new(&mut allocator, air.clone(), $sum);
                let mut component_trace: TreeVec<Vec<Vec<M31>>> = tree_refs
                    .sub_tree(&component.trace_locations())
                    .map_cols(|column| (*column).clone());
                component_trace[PREPROCESSED_TRACE_IDX] = component
                    .preprocessed_column_indices()
                    .iter()
                    .map(|idx| tree_refs[PREPROCESSED_TRACE_IDX][*idx].clone())
                    .collect();
                let component_refs = TreeVec::new(vec![
                    component_trace[0].iter().collect(),
                    component_trace[1].iter().collect(),
                    component_trace[2].iter().collect(),
                ]);
                let _ = &component;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    assert_constraints_on_trace(
                        &component_refs,
                        $log,
                        |evaluator| {
                            FrameworkEval::evaluate(&air, evaluator);
                        },
                        $sum,
                    );
                }));
                println!("component {}: {}", $name, if result.is_ok() { "OK" } else { "FAILED" });
            }};
        }
        let anchor = claimed_anchor_limbs(
            &spec.anchor_state().iter().map(|f| f.to_bytes_be()).collect::<Vec<_>>().try_into().unwrap(),
        )
        .unwrap();
        check!("chain", ChainAir { log_size, range16: r16.clone(), state: st.clone(), mul_link: ml.clone(), red_link: rl.clone(), anchor }, chain_sum, log_size);
        check!("mul", MulAir { log_size: mul_log, range16: r16.clone(), link: ml.clone() }, mul_sum, mul_log);
        check!("red", ReduceAir { log_size: reduce_log, range16: r16.clone(), range12: r12.clone(), link: rl.clone() }, red_sum, reduce_log);
        check!("t16", RangeTableAir::table16(native::TABLE16_LOG, r16.clone(), r12.clone()), t16_sum, native::TABLE16_LOG);
        check!("t12", RangeTableAir::table12(native::TABLE12_LOG, r16.clone(), r12.clone()), t12_sum, native::TABLE12_LOG);
    }

#[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn v2_proof_roundtrip() {
        let spec = small_spec();
        let archive = prove_poseidon252_chain_v2(&spec).expect("prove");
        verify_poseidon252_chain_v2(&archive).expect("verify");
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn v2_rejects_tampered_anchor() {
        let spec = small_spec();
        let mut archive = prove_poseidon252_chain_v2(&spec).expect("prove");
        archive.claimed_anchor[0][0] ^= 1;
        assert!(verify_poseidon252_chain_v2(&archive).is_err());
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn v2_rejects_tampered_message() {
        let spec = small_spec();
        let mut archive = prove_poseidon252_chain_v2(&spec).expect("prove");
        archive.spec.message[0][31] ^= 1;
        assert!(verify_poseidon252_chain_v2(&archive).is_err());
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn v2_rejects_swapped_order() {
        let a = native::Poseidon252ChainSpec::hash_many(&[
            Felt::from(7u64),
            Felt::from(9u64),
        ]);
        let b = native::Poseidon252ChainSpec::hash_many(&[
            Felt::from(9u64),
            Felt::from(7u64),
        ]);
        let archive = prove_poseidon252_chain_v2(&a).expect("prove");
        let mut forged = archive;
        forged.spec = b;
        assert!(verify_poseidon252_chain_v2(&forged).is_err());
    }

    // =========================================================================
    // 性能扫描(#41/#42 决策支撑,2026-09-10)
    //
    // 度量 poseidon252_v2 在"整表 canonical preimage"规模下的 prove/verify
    // 成本,并按 felt 数扫描伸缩曲线,用于裁决:
    // - #42(状态根切 Poseidon252)在真实规模下的证明代价;
    // - #41(preimage 定长化/材料出热态)每缩减一半 felts 能省多少。
    // 运行:
    //   cargo test -p poker_texas_air --release --lib v2_perf_sweep \
    //     -- --include-ignored --nocapture
    // =========================================================================

    /// 9 人桌中局 fixture(空牌组):近似 #41 落地后"轻热态"的 preimage 规模。
    fn realistic_table_fixture()
    -> (poker_l1::contracts::texas_poker::types::TexasPokerTable, Vec<Felt>) {
        use poker_l1::contracts::texas_poker::types::TexasPokerTable;
        let mut table = TexasPokerTable::new(
            poker_l1::object_model::ObjectID::new([0xAB; 20], 9),
            [0xCD; 20],
            9,
            50,
            100,
        );
        table.hand_id = 42;
        table.call_seq = 7;
        table.pot = 123_456;
        for seat_index in 0..9usize {
            let seat = &mut table.seats[seat_index];
            crate::test_support::set_player(seat, [0x20 + seat_index as u8; 20]);
            crate::test_support::set_stack(seat, 100_000 + 1_000 * seat_index as u64);
            crate::test_support::set_bet(seat, 100 + 50 * seat_index as u64);
            crate::test_support::set_total_bet(seat, 300 + 50 * seat_index as u64);
        }
        let preimage =
            crate::state_root::table_state_preimage(&table).expect("fixture table must encode");
        (table, preimage)
    }

    #[test]
#[ignore = "perf sweep (~1-3 min at --release); run with --include-ignored --nocapture"]
    fn v2_perf_sweep_scaling_curve() {
        use std::time::Instant;

        // ---- 用例集:small 基线 → 448 felts(≈当前生产热态含满牌组规模)----
        let (table, real_preimage) = realistic_table_fixture();
        let mut cases: Vec<(String, Vec<Felt>)> = vec![(
            "small".into(),
            vec![Felt::from(7u64), Felt::from(9u64)],
        )];
        for &felt_count in &[16usize, 64, 192, 448] {
            cases.push((
                format!("synthetic_{felt_count}f"),
                (0..felt_count)
                    .map(|i| Felt::from(i as u64 * 0x9E37_79B9 + 1))
                    .collect(),
            ));
        }
        cases.push((format!("table9_real_{}f", real_preimage.len()), real_preimage));

        // ---- host 对照:当前 BLAKE3 热根的宿主耗时(µs 级)----
        let host_start = Instant::now();
        let host_root = crate::state_root::compute_state_root(&table);
        println!(
            "[host] blake3 compute_state_root: {:8.1} µs ({})",
            host_start.elapsed().as_secs_f64() * 1e6,
            if host_root.is_ok() { "ok" } else { "err" },
        );

        println!(
            "{:<20} {:>6} {:>6} {:>4} {:>6} {:>8} {:>8} {:>10} {:>10} {:>9}",
            "case", "felts", "perms", "log", "rows", "mul_log", "red_log", "prove_ms",
            "verify_ms", "proof_kb"
        );
        for (name, message) in &cases {
            let spec = native::Poseidon252ChainSpec::hash_many(message);
            let perms = spec.n_real_perms();

            let prove_start = Instant::now();
            let archive = prove_poseidon252_chain_v2(&spec)
                .unwrap_or_else(|e| panic!("{name}: prove failed: {e}"));
            let prove_ms = prove_start.elapsed().as_secs_f64() * 1e3;

            let verify_start = Instant::now();
            verify_poseidon252_chain_v2(&archive)
                .unwrap_or_else(|e| panic!("{name}: verify failed: {e}"));
            let verify_ms = verify_start.elapsed().as_secs_f64() * 1e3;

            println!(
                "{:<20} {:>6} {:>6} {:>5}({:>5}) {:>8} {:>8} {:>10.1} {:>10.1} {:>9.1}",
                name,
                message.len(),
                perms,
                archive.log_size,
                1usize << archive.log_size,
                archive.mul_log,
                archive.reduce_log,
                prove_ms,
                verify_ms,
                archive.stark_proof_bytes.len() as f64 / 1024.0,
            );
        }
    }
}
