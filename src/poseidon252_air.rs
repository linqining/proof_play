//! Poseidon252 (Starknet Hades-3) chain statement — native layer.
//!
//! This half of the state-root recomputation engine (#22⑤) carries the
//! *computation*: the exact Starknet Poseidon permutation behind
//! `starknet_crypto::poseidon_hash_many` (round keys derived from the raw
//! parameter table and unit-tested against the library), the 16-bit limb
//! big-integer layer, the chain statement spec with its deterministic
//! pow-2 layout, and the honest witness builder.
//!
//! The AIR components, interaction traces, and the prove/verify drivers live
//! in the v2 component decomposition ([`crate::poseidon252_v2`]).
//!
//! # What this module proves (with its component half)
//!
//! One STARK proves a full `poseidon_hash_many` sponge run: starting from
//! the committed initial state, the trace absorbs the committed message
//! pairs and applies the exact Starknet Poseidon permutation after every
//! pair, and the terminal full state is pinned to the committed anchor
//! scope.  The prover's only freedom is the 16-bit limb representation of
//! each 252-bit field element; the computed field elements are fully
//! determined, so an accepting proof certifies `anchor = sponge(initial,
//! words)` — state-root recomputation inside the AIR, matching the native
//! anchor that both sides recompute with the library hash.
//!
//! # Round structure (mirrors `starknet_crypto::poseidon_permute_comp`)
//!
//! α = 3, t = 3, 8 full rounds + 83 partial rounds, compressed round keys
//! (partial-round constants pre-moved through the mix):
//!
//! ```text
//! full round:    s_j += K[3r+j] (j=0,1,2);  s_j = s_j³;  mix
//! partial round: s_2 += K[12+r];             s_2 = s_2³;  mix
//! mix: t = s0+s1+s2; s0 = t+2·s0; s1 = t−2·s1; s2 = t−3·s2
//! ```

#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use starknet_crypto::Felt;

use crate::error::{TexasAirError, TexasAirResult};

// ===========================================================================
// Round keys and the native permutation
// ===========================================================================

pub const N_FULL_ROUNDS: usize = 8;
pub const N_PARTIAL_ROUNDS: usize = 83;
/// Rounds per permutation (8 full + 83 partial).
pub const ROUND_COUNT: usize = N_FULL_ROUNDS + N_PARTIAL_ROUNDS;
/// Compressed round-key entries: 4·3 + 83 + 4·3.
pub const COMPRESSED_KEY_COUNT: usize =
    3 * (N_FULL_ROUNDS / 2) + N_PARTIAL_ROUNDS + 3 * (N_FULL_ROUNDS / 2);

/// The compressed round-key schedule, derived once from the raw parameter
/// table with the exact constant-compression `starknet-crypto-codegen`
/// applies.  Index layout: `[0..12]` head full rounds (3 per round),
/// `[12..95]` partial rounds (lane 2 only), `[95..107]` tail full rounds
/// (the first of which carries the accumulated partial-round image).
pub fn compressed_round_keys() -> &'static [Felt; COMPRESSED_KEY_COUNT] {
    static KEYS: std::sync::OnceLock<[Felt; COMPRESSED_KEY_COUNT]> =
        std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let raw: [[Felt; 3]; ROUND_COUNT] = crate::poseidon252_round_keys::RAW_ROUND_KEYS
            .each_ref()
            .map(|row| {
                row.each_ref()
                    .map(|v| Felt::from_dec_str(v).expect("round key decimal string"))
            });

        let mut out = Vec::with_capacity(COMPRESSED_KEY_COUNT);
        for row in raw.iter().take(N_FULL_ROUNDS / 2) {
            out.extend_from_slice(row);
        }

        // Partial rounds: the lane-2 constant plus the accumulated image of
        // every previous partial constant under the mix, with lane 2 reset
        // after each emission (it is consumed by the s-box).
        let mut acc = [Felt::ZERO; 3];
        for row in raw.iter().skip(N_FULL_ROUNDS / 2).take(N_PARTIAL_ROUNDS) {
            acc[0] += row[0];
            acc[1] += row[1];
            acc[2] += row[2];
            out.push(acc[2]);
            acc[2] = Felt::ZERO;
            mix(&mut acc);
        }

        // First of the tail full rounds carries the accumulated image.
        let tail_base = N_FULL_ROUNDS / 2 + N_PARTIAL_ROUNDS;
        acc[0] += raw[tail_base][0];
        acc[1] += raw[tail_base][1];
        acc[2] += raw[tail_base][2];
        out.extend_from_slice(&acc);
        for row in raw.iter().skip(tail_base + 1) {
            out.extend_from_slice(row);
        }

        out.try_into().expect("compressed key count")
    })
}

/// Optimized mix: `t = s0+s1+s2; s0 = t+2·s0; s1 = t−2·s1; s2 = t−3·s2`.
pub fn mix(state: &mut [Felt; 3]) {
    let t = state[0] + state[1] + state[2];
    state[0] = t + state[0].double();
    state[1] = t - state[1].double();
    state[2] = t - Felt::THREE * state[2];
}

fn cube(x: Felt) -> Felt {
    x * x * x
}

/// Whether round `pos` is a full round (all three lanes nonlinear).
pub fn is_full_round(pos: usize) -> bool {
    let head = N_FULL_ROUNDS / 2;
    pos < head || pos >= head + N_PARTIAL_ROUNDS
}

/// The compressed-key index of round `pos` (3-wide for full rounds, the
/// lane-2 entry otherwise).
fn round_key_index(pos: usize) -> usize {
    let head = N_FULL_ROUNDS / 2;
    if pos < head {
        3 * pos
    } else if pos < head + N_PARTIAL_ROUNDS {
        3 * head + (pos - head)
    } else {
        3 * head + N_PARTIAL_ROUNDS + 3 * (pos - head - N_PARTIAL_ROUNDS)
    }
}

/// One Hades round, bit-exact with `starknet_crypto`'s `round_comp`.
pub fn apply_round(state: &mut [Felt; 3], pos: usize) {
    let keys = compressed_round_keys();
    let idx = round_key_index(pos);
    if is_full_round(pos) {
        state[0] += keys[idx];
        state[1] += keys[idx + 1];
        state[2] += keys[idx + 2];
        state[0] = cube(state[0]);
        state[1] = cube(state[1]);
        state[2] = cube(state[2]);
    } else {
        state[2] += keys[idx];
        state[2] = cube(state[2]);
    }
    mix(state);
}

/// The Starknet Poseidon permutation, bit-exact with
/// `starknet_crypto::poseidon_permute_comp` (unit-tested).
pub fn permute_comp(state: &mut [Felt; 3]) {
    for pos in 0..ROUND_COUNT {
        apply_round(state, pos);
    }
}

/// The absorb schedule of `poseidon_hash_many`: `n` message felts become
/// `(n + 2) / 2` permutations; the tail pair is `(last, 1)` for an odd
/// message and `(1, 0)` for an even one.
pub fn absorb_schedule(msg: &[Felt]) -> Vec<[Felt; 2]> {
    let n = msg.len();
    let perms = (n + 2) / 2;
    let mut pairs = Vec::with_capacity(perms);
    for i in 0..perms {
        match (msg.get(2 * i).copied(), msg.get(2 * i + 1).copied()) {
            (Some(a), Some(b)) => pairs.push([a, b]),
            (Some(a), None) => pairs.push([a, Felt::ONE]),
            (None, None) => pairs.push([Felt::ONE, Felt::ZERO]),
            (None, Some(_)) => unreachable!("odd index cannot be present without even"),
        }
    }
    pairs
}

/// Native sponge over an absorb schedule (mirror of
/// `starknet_crypto::poseidon_hash_many` semantics).
pub fn sponge(pairs: &[[Felt; 2]]) -> [Felt; 3] {
    let mut state = [Felt::ZERO; 3];
    for pair in pairs {
        state[0] += pair[0];
        state[1] += pair[1];
        permute_comp(&mut state);
    }
    state
}

// ===========================================================================
// 16-bit limb layer (native witness arithmetic)
// ===========================================================================

pub const LIMBS: usize = 16;

/// felt252 ↔ 16 little-endian 16-bit limbs.
pub fn felt_to_limbs(f: &Felt) -> [u16; LIMBS] {
    let bytes = f.to_bytes_be();
    let mut limbs = [0u16; LIMBS];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = u16::from_be_bytes([bytes[30 - 2 * i], bytes[31 - 2 * i]]);
    }
    limbs
}

pub fn limbs_to_felt(limbs: &[u16; LIMBS]) -> Felt {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let [hi, lo] = limb.to_be_bytes();
        bytes[30 - 2 * i] = hi;
        bytes[31 - 2 * i] = lo;
    }
    // 语义与旧 0.6 ff Result 路径一致：≥ P 的 limb 向量必须 fail-loud
    // （types-core 的 from_bytes_be 会静默归约，这里显式守住 canonical）。
    let felt = Felt::from_bytes_be(&bytes);
    assert_eq!(felt.to_bytes_be(), bytes, "limb vector must be a canonical felt252");
    felt
}

/// Stark prime as 16-bit LE limbs: `2^251 + 17·2^192 + 1`.
pub const P_LIMBS: [u16; LIMBS] = {
    let mut limbs = [0u16; LIMBS];
    limbs[0] = 1;
    limbs[12] = 17;
    limbs[15] = 1 << 11;
    limbs
};

/// `m·P` as 16-bit LE limbs (m ≤ 6 keeps the result below 2^256).
pub const fn p_multiple(m: u64) -> [u16; LIMBS] {
    let mut out = [0u16; LIMBS];
    let mut carry = 0u64;
    let mut i = 0;
    while i < LIMBS {
        let v = m * P_LIMBS[i] as u64 + carry;
        out[i] = (v & 0xffff) as u16;
        carry = v >> 16;
        i += 1;
    }
    out
}

/// Big-uint helpers over LE u16 limbs (witness side only).
mod bigu {
    pub fn cmp(a: &[u16], b: &[u16]) -> std::cmp::Ordering {
        let n = a.len().max(b.len());
        for i in (0..n).rev() {
            let x = a.get(i).copied().unwrap_or(0);
            let y = b.get(i).copied().unwrap_or(0);
            match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    }

    pub fn sub(a: &[u16], b: &[u16]) -> Vec<u16> {
        debug_assert!(cmp(a, b) != std::cmp::Ordering::Less);
        let mut out = vec![0u16; a.len()];
        let mut borrow = 0i32;
        for (i, slot) in out.iter_mut().enumerate() {
            let diff = a[i] as i32 - b.get(i).copied().unwrap_or(0) as i32 - borrow;
            if diff < 0 {
                *slot = (diff + (1 << 16)) as u16;
                borrow = 1;
            } else {
                *slot = diff as u16;
                borrow = 0;
            }
        }
        debug_assert_eq!(borrow, 0);
        out
    }

    /// Binary long division: `y = q·p + r` with `r < p`.
    pub fn div_rem(y: &[u16], p: &[u16]) -> (Vec<u16>, Vec<u16>) {
        assert!(!p.iter().all(|&x| x == 0));
        let bits = y.len() * 16;
        let mut q = vec![0u16; y.len()];
        let mut r = vec![0u16; p.len() + 1];
        for i in (0..bits).rev() {
            let mut carry = 0u16;
            for limb in r.iter_mut() {
                let next = *limb >> 15;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            if (y[i / 16] >> (i % 16)) & 1 == 1 {
                r[0] |= 1;
            }
            if cmp(&r, p) != std::cmp::Ordering::Less {
                r = sub(&r, p);
                q[i / 16] |= 1 << (i % 16);
            }
        }
        (q, r)
    }
}

/// Carry-add `Σ coeff_j · x_j` into `n` limbs; the final carry is pinned to
/// zero (all callers hold their value bounds below 2^256).
pub(crate) fn add_witness(n: usize, terms: &[(u64, &[u16])]) -> (Vec<u16>, Vec<u32>) {
    let mut out = vec![0u16; n];
    let mut carry = vec![0u32; n];
    let mut c = 0u64;
    for i in 0..n {
        let mut t = c;
        for (coeff, value) in terms {
            t += coeff * value[i] as u64;
        }
        out[i] = (t & 0xffff) as u16;
        c = t >> 16;
        carry[i] = c as u32;
    }
    carry[n - 1] = 0;
    (out, carry)
}

/// Borrow-subtract `u − p` (u ≥ p): `(out, b_1..b_n)` with `b_n = 0`.
pub(crate) fn sub_witness(u: &[u16], p: &[u16]) -> (Vec<u16>, Vec<u16>) {
    let n = u.len();
    let mut out = vec![0u16; n];
    let mut bw = vec![0u16; n];
    let mut borrow = 0u16;
    for i in 0..n {
        let diff = u[i] as i32 - p[i] as i32 - borrow as i32;
        if diff < 0 {
            out[i] = (diff + (1 << 16)) as u16;
            borrow = 1;
        } else {
            out[i] = diff as u16;
            borrow = 0;
        }
        bw[i] = borrow;
    }
    debug_assert_eq!(bw[n - 1], 0);
    (out, bw)
}

/// Schoolbook mul producing exactly `n_out` limbs (`n_out − 1` carries; the
/// top output limb equals the last carry).  `n_out` must cover the product.
pub(crate) fn mul_witness(a: &[u16], b: &[u16], n_out: usize) -> (Vec<u16>, Vec<u32>) {
    let mut acc = vec![0u64; n_out];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            if i + j < n_out {
                acc[i + j] += x as u64 * y as u64;
            }
        }
    }
    let mut out = vec![0u16; n_out];
    let mut carries = vec![0u32; n_out - 1];
    let mut c = 0u64;
    for k in 0..n_out - 1 {
        let t = acc[k] + c;
        out[k] = (t & 0xffff) as u16;
        c = t >> 16;
        carries[k] = c as u32;
    }
    out[n_out - 1] = c as u16;
    (out, carries)
}

/// Witness side of `y = z + q·P` (y has 48 limbs → q 32, z 16) plus the
/// reduction carry chain (47 columns, the final carry implicitly zero).
fn reduce48_with_carries(y: &[u16]) -> (Vec<u16>, Vec<u16>, Vec<u32>) {
    let (q, z) = bigu::div_rem(y, &P_LIMBS);
    assert!(
        q.iter().skip(32).all(|&limb| limb == 0),
        "s-box reduction quotient exceeded 32 limbs"
    );
    let q = &q[..32];
    let z: [u16; LIMBS] = z[..LIMBS].try_into().expect("remainder fits 16 limbs");
    let mut carries = vec![0u32; 3 * LIMBS - 1];
    let mut c = 0u64;
    for k in 0..3 * LIMBS - 1 {
        let mut t = c;
        if k < LIMBS {
            t += z[k] as u64;
        }
        for i in 0..=k.min(31) {
            let j = k - i;
            if j < LIMBS {
                t += q[i] as u64 * P_LIMBS[j] as u64;
            }
        }
        // t = x3_k + 2^16·c  (x3 limbs are the inputs)
        c = (t - y[k] as u64) >> 16;
        carries[k] = c as u32;
    }
    // Limb 47 has no quotient/product terms beyond the carry: the sum
    // i + j = 47 is empty for i < 32, j < 16, so the top limb of x3 must
    // equal the final carry exactly.
    debug_assert_eq!(carries[3 * LIMBS - 2] as u64, y[3 * LIMBS - 1] as u64);
    (q.to_vec(), z.to_vec(), carries)
}

/// Witness side of `v = zm + qm·P` (v has 16 limbs) plus the reduction
/// carry chain (`rc[k] = carry out of limb k`, rc[15] pinned zero).
fn reduce16_with_carries(v: &[u16]) -> (u16, [u16; LIMBS], Vec<u32>) {
    let (q, z) = bigu::div_rem(v, &P_LIMBS);
    debug_assert!(
        q.iter().skip(1).all(|&limb| limb == 0),
        "mix value must stay below 2·P"
    );
    let qm = q[0];
    let zm: [u16; LIMBS] = z[..LIMBS].try_into().expect("remainder fits 16 limbs");
    let mut rc = vec![0u32; LIMBS];
    let mut carry = 0u32;
    for k in 0..LIMBS {
        let t = zm[k] as u32 + qm as u32 * P_LIMBS[k] as u32 + carry;
        debug_assert_eq!((t & 0xffff) as u16, v[k], "reduce16 limb mismatch");
        carry = t >> 16;
        rc[k] = carry;
    }
    rc[LIMBS - 1] = 0;
    (qm, zm, rc)
}

// ===========================================================================
// Chain spec
// ===========================================================================

/// Minimum trace size (SIMD-friendly floor).
pub const LOG_SIZE_FLOOR: u32 = 8;

/// One provable Poseidon252 sponge run: initial state plus the felt message
/// schedule; layout (padding, leftover, log size) derives deterministically.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Poseidon252ChainSpec {
    pub initial_state: [[u8; 32]; 3],
    pub message: Vec<[u8; 32]>,
}

impl Poseidon252ChainSpec {
    pub fn from_message(initial_state: [&Felt; 3], message: &[Felt]) -> Self {
        Self {
            initial_state: initial_state.each_ref().map(|f| f.to_bytes_be()),
            message: message.iter().map(|f| f.to_bytes_be()).collect(),
        }
    }

    /// The canonical `poseidon_hash_many` statement: zero initial state.
    pub fn hash_many(message: &[Felt]) -> Self {
        Self::from_message([
            &Felt::ZERO,
            &Felt::ZERO,
            &Felt::ZERO,
        ], message)
    }

    pub fn validate(&self) -> Result<(), TexasAirError> {
        if self.message.len() > 4096 {
            return Err(TexasAirError::SpecViolation(
                "poseidon252 chain message is unreasonably long".into(),
            ));
        }
        for felt in self.initial_state.iter().chain(self.message.iter()) {
            if crate::state_root::felt_from_canonical_bytes(felt).is_none() {
                return Err(TexasAirError::SpecViolation(
                    "poseidon252 chain carries a non-canonical felt".into(),
                ));
            }
        }
        Ok(())
    }

    fn initial_limbs(&self) -> [[u16; LIMBS]; 3] {
        self.initial_state.each_ref().map(|f| {
            felt_to_limbs(&Felt::from_bytes_be(f))
        })
    }

    fn message_felts(&self) -> Vec<Felt> {
        self.message
            .iter()
            .map(|f| Felt::from_bytes_be(f))
            .collect()
    }

    /// The `(n + 2) / 2` absorb pairs, including the `poseidon_hash_many`
    /// tail.
    pub fn absorb_pairs(&self) -> Vec<[Felt; 2]> {
        absorb_schedule(&self.message_felts())
    }

    /// Real permutations: one per absorb pair.
    pub fn n_real_perms(&self) -> usize {
        self.absorb_pairs().len()
    }

    /// The native anchor: full terminal sponge state.
    pub fn anchor_state(&self) -> [Felt; 3] {
        sponge(&self.absorb_pairs())
    }

    /// Statement digest mixed into the Fiat–Shamir channel before any
    /// commitment.
    pub fn statement_digest(&self) -> [u8; 32] {
        let bytes = borsh::to_vec(self).expect("chain spec is serializable");
        crate::blake3_flock::blake3_chain_digest(&bytes)
    }

    /// Deterministic proof layout.
    pub fn layout(&self) -> ChainLayout {
        let n_real = self.n_real_perms();
        let min_rows = ROUND_COUNT * n_real + 1;
        let log_size = (min_rows.max(1usize << LOG_SIZE_FLOOR) - 1)
            .next_power_of_two()
            .ilog2()
            .max(LOG_SIZE_FLOOR);
        let rows = 1usize << log_size;
        let n_pad = (rows - ROUND_COUNT * n_real) / ROUND_COUNT;
        let leftover = rows - ROUND_COUNT * (n_real + n_pad);
        ChainLayout {
            log_size,
            rows,
            n_real,
            n_pad,
            leftover,
        }
    }
}

/// Deterministic proof layout of a chain statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainLayout {
    pub log_size: u32,
    pub rows: usize,
    pub n_real: usize,
    pub n_pad: usize,
    /// Rows of the truncated final identity permutation (always ≥ 1: 91 is
    /// odd and never divides a power of two).
    pub leftover: usize,
}

// ===========================================================================
// Column layout (shared with the AIR component half)
// ===========================================================================

pub(crate) const L: usize = LIMBS;
/// Limbs of a full state (3 felts) plus the round-position lane.
pub const STATE_TUPLE: usize = 3 * L + 1;

// --- scope (preprocessed) columns ---
pub(crate) const S_POS: usize = 0;
pub(crate) const S_IS_FULL: usize = S_POS + 1;
pub(crate) const S_K: usize = S_IS_FULL + 1; // 3 × 16 limb columns
pub(crate) const S_W: usize = S_K + 3 * L; // 2 × 16
pub(crate) const S_SEL: usize = S_W + 2 * L; // sel_init, sel_void, sel_final
pub(crate) const S_INIT: usize = S_SEL + 3; // initial state ‖ pos = 0
pub(crate) const S_VOID: usize = S_INIT + 3 * L + 1; // void state ‖ void_pos
pub(crate) const S_ANCHOR: usize = S_VOID + 3 * L + 1; // anchor state limbs
pub const SCOPE_COLUMNS: usize = S_ANCHOR + 3 * L;
/// Shared preprocessed tree: chain scope + 2^16 table + 2^12 table columns.
pub const PREPROCESSED_COLUMNS: usize = SCOPE_COLUMNS + 2;
pub(crate) const TABLE16_LOG: u32 = 16;
pub(crate) const TABLE12_LOG: u32 = 12;

// --- witness columns ---
pub(crate) const W_STATE_IN: usize = 0; // 3 × 16
const W_ABS: usize = W_STATE_IN + 3 * L; // per lane: out 16 + carry 16
const W_SBOX0: usize = W_ABS + 6 * L;
/// gated lane: sq(32) sqc(31) x2(32) x2c(31) x3(48) x3c(47) q(32) qc(47)
///             z(16) p(16)
pub(crate) const GATED_LANE: usize = 2 * L
    + (2 * L - 1)
    + 2 * L
    + (2 * L - 1)
    + 3 * L
    + (3 * L - 1)
    + 2 * L
    + (3 * L - 1)
    + L
    + L;
/// ungated lane: x2(32) x2c(31) x3(48) x3c(47) q(32) qc(47) z(16)
pub(crate) const UNGATED_LANE: usize = 2 * L
    + (2 * L - 1)
    + 3 * L
    + (3 * L - 1)
    + 2 * L
    + (3 * L - 1)
    + L;
const W_SBOX1: usize = W_SBOX0 + GATED_LANE;
const W_SBOX2: usize = W_SBOX1 + GATED_LANE;
const W_T: usize = W_SBOX2 + UNGATED_LANE; // t(16) + tc(16)
pub(crate) const W_MIX0: usize = W_T + 2 * L;
/// lane 0 mix: d(16) dc(16) v(16) vc(16) rc(16) qm(1) zm(16)
pub(crate) const MIX0_WIDTH: usize = 6 * L + 1;
/// lanes 1/2: d(16) dc(16) u(16) uc(16) v(16) vc(16) rc(16) bw(16) qm(1) zm(16)
pub(crate) const MIX12_WIDTH: usize = 9 * L + 1;
const W_MIX1: usize = W_MIX0 + MIX0_WIDTH;
const W_MIX2: usize = W_MIX1 + MIX12_WIDTH;
pub(crate) const W_POS_NEXT: usize = W_MIX2 + MIX12_WIDTH;
pub(crate) const W_IS_WRAP: usize = W_POS_NEXT + 1;
pub const WITNESS_COLUMNS: usize = W_IS_WRAP + 1;

pub(crate) const fn w_abs_out(lane: usize) -> usize {
    W_ABS + lane * 2 * L
}
pub(crate) const fn w_abs_carry(lane: usize) -> usize {
    w_abs_out(lane) + L
}
pub(crate) const fn w_sq(lane: usize) -> usize {
    W_SBOX0 + lane * GATED_LANE
}
pub(crate) const fn w_sqc(lane: usize) -> usize {
    w_sq(lane) + 2 * L
}
pub(crate) const fn w_x2(lane: usize) -> usize {
    if lane < 2 {
        w_sqc(lane) + (2 * L - 1)
    } else {
        W_SBOX2
    }
}
pub(crate) const fn w_x2c(lane: usize) -> usize {
    w_x2(lane) + 2 * L
}
pub(crate) const fn w_x3(lane: usize) -> usize {
    w_x2c(lane) + (2 * L - 1)
}
pub(crate) const fn w_x3c(lane: usize) -> usize {
    w_x3(lane) + 3 * L
}
pub(crate) const fn w_q(lane: usize) -> usize {
    w_x3c(lane) + (3 * L - 1)
}
pub(crate) const fn w_qc(lane: usize) -> usize {
    w_q(lane) + 2 * L
}
pub(crate) const fn w_z(lane: usize) -> usize {
    w_qc(lane) + (3 * L - 1)
}
pub(crate) const fn w_p(lane: usize) -> usize {
    w_z(lane) + L
}
pub(crate) const fn w_t() -> usize {
    W_T
}
pub(crate) const fn w_mix(lane: usize) -> usize {
    match lane {
        0 => W_MIX0,
        1 => W_MIX1,
        _ => W_MIX2,
    }
}
pub(crate) const fn w_mix_d(lane: usize) -> usize {
    w_mix(lane)
}
pub(crate) const fn w_mix_dc(lane: usize) -> usize {
    w_mix_d(lane) + L
}
pub(crate) const fn w_mix_u(lane: usize) -> usize {
    w_mix_dc(lane) + L
}
pub(crate) const fn w_mix_uc(lane: usize) -> usize {
    w_mix_u(lane) + L
}
pub(crate) const fn w_mix_v(lane: usize) -> usize {
    if lane == 0 {
        w_mix_dc(lane) + L
    } else {
        w_mix_uc(lane) + L
    }
}
pub(crate) const fn w_mix_vc(lane: usize) -> usize {
    w_mix_v(lane) + L
}
pub(crate) const fn w_mix_rc(lane: usize) -> usize {
    w_mix_vc(lane) + L
}
pub(crate) const fn w_mix_bw(lane: usize) -> usize {
    w_mix_rc(lane) + L
}
pub(crate) const fn w_mix_qm(lane: usize) -> usize {
    if lane == 0 {
        w_mix_rc(lane) + L
    } else {
        w_mix_bw(lane) + L
    }
}
pub(crate) const fn w_mix_zm(lane: usize) -> usize {
    w_mix_qm(lane) + 1
}

// ===========================================================================
// Range-checked columns and relation entries (fixed per-row order)
// ===========================================================================

/// Every 2^16-range-checked witness column, in eval/entry order.
pub(crate) fn range_use_columns() -> &'static Vec<usize> {
    static COLS: std::sync::OnceLock<Vec<usize>> = std::sync::OnceLock::new();
    COLS.get_or_init(|| {
        let mut cols = Vec::new();
        for lane in 0..3 {
            cols.extend(w_abs_out(lane)..w_abs_out(lane) + L);
        }
        // carry columns (sqc/x2c/x3c/qc/rc) are intentionally NOT
        // range-checked: every carry chain ends in a pinned-zero or
        // top-limb-equals-carry equation, which bounds them by induction.
        for lane in 0..2 {
            cols.extend(w_sq(lane)..w_sq(lane) + 2 * L);
            cols.extend(w_x2(lane)..w_x2(lane) + 2 * L);
            cols.extend(w_x3(lane)..w_x3(lane) + 3 * L);
            cols.extend(w_q(lane)..w_q(lane) + 2 * L);
            cols.extend(w_z(lane)..w_z(lane) + L);
            cols.extend(w_p(lane)..w_p(lane) + L);
        }
        cols.extend(w_x2(2)..w_x2(2) + 2 * L);
        cols.extend(w_x3(2)..w_x3(2) + 3 * L);
        cols.extend(w_q(2)..w_q(2) + 2 * L);
        cols.extend(w_z(2)..w_z(2) + L);
        cols.extend(w_t()..w_t() + L);
        for lane in 0..3 {
            cols.extend(w_mix_d(lane)..w_mix_d(lane) + L);
            cols.extend(w_mix_v(lane)..w_mix_v(lane) + L);
            cols.push(w_mix_qm(lane));
            cols.extend(w_mix_zm(lane)..w_mix_zm(lane) + L);
        }
        cols
    })
}

/// Columns whose top limb must stay below 2^252: the three s-box outputs
/// and the three mix outputs.
pub(crate) fn bound12_columns() -> &'static Vec<usize> {
    static COLS: std::sync::OnceLock<Vec<usize>> = std::sync::OnceLock::new();
    COLS.get_or_init(|| {
        let mut cols: Vec<usize> = (0..3).map(|lane| w_z(lane) + L - 1).collect();
        cols.extend((0..3).map(|lane| w_mix_zm(lane) + L - 1));
        cols
    })
}

/// LogUp relation entries per row, in eval order (the interaction-trace
/// generator pairs the same sequence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    /// 2^16 range use of one witness limb column.
    Range16(usize),
    /// 2^12 bound use of one top-limb column.
    Range12(usize),
    /// `(−1, state_in ‖ pos)`.
    StateIn,
    /// `(+1, state_out ‖ pos_next)`.
    StateOut,
    /// `(+sel_init, initial ‖ 0)` (scope).
    Init,
    /// `(−sel_void, void ‖ void_pos)` (scope).
    Void,
}

pub(crate) fn entry_layout() -> &'static Vec<EntryKind> {
    static LAYOUT: std::sync::OnceLock<Vec<EntryKind>> = std::sync::OnceLock::new();
    LAYOUT.get_or_init(|| {
        let mut layout: Vec<EntryKind> = range_use_columns()
            .iter()
            .map(|&col| EntryKind::Range16(col))
            .collect();
        layout.extend(bound12_columns().iter().map(|&col| EntryKind::Range12(col)));
        layout.push(EntryKind::StateIn);
        layout.push(EntryKind::StateOut);
        layout.push(EntryKind::Init);
        layout.push(EntryKind::Void);
        layout
    })
}

/// Fraction (LogUp) columns of the main AIR (entries paired consecutively —
/// the official cairo-air component pattern).
pub fn main_interaction_columns() -> usize {
    entry_layout().len().div_ceil(2)
}

pub const TABLE16_INTERACTION_COLUMNS: usize = 1;
pub const TABLE12_INTERACTION_COLUMNS: usize = 1;

/// Total interaction M31 columns (each fraction column is one SecureField =
/// four M31 coordinate columns).
pub fn interaction_columns() -> usize {
    (main_interaction_columns() + TABLE16_INTERACTION_COLUMNS + TABLE12_INTERACTION_COLUMNS) * 4
}

// ===========================================================================
// Trace builder (witness generation)
// ===========================================================================

/// The honest trace of one chain statement: scope, witness, and both range
/// tables' multiplicities.
pub struct Poseidon252Trace {
    pub log_size: u32,
    /// `SCOPE_COLUMNS` scope columns.
    pub scope: Vec<Vec<M31>>,
    /// `WITNESS_COLUMNS` witness columns.
    pub witness: Vec<Vec<M31>>,
    /// 2^16 range-table multiplicities.
    pub multiplicities16: Vec<u32>,
    /// 2^12 range-table multiplicities.
    pub multiplicities12: Vec<u32>,
    /// v2 coprocessor rows (see git 历史（原 docs/plan-poseidon252-v2.md）): active rows
    /// only; the component layers pad to their own power-of-two domains
    /// with enabler-zero rows.
    pub mul_rows: Vec<MulRow>,
    pub reduce_rows: Vec<ReduceRow>,
    /// Padded domain sizes of the coprocessor components.
    pub mul_log: u32,
    pub reduce_log: u32,
}

/// One schoolbook multiplication row for the MulAir coprocessor:
/// `a(32) × b(16) = c(48)` over the integers.  Square rows arrive zero-padded
/// (`a = s_c ‖ 0¹⁶`, `c = sq ‖ 0¹⁶`); the convolution carry chain is padded
/// to the full-shape width of 47.
#[derive(Clone, Debug)]
pub struct MulRow {
    pub a: Vec<u16>,
    pub b: Vec<u16>,
    pub c: Vec<u16>,
    pub carry: Vec<u32>,
}

/// One modular reduction row for the ReduceAir coprocessor:
/// `x(48) = z(16) + q(32)·P`.  Mix rows arrive zero-padded; the carry chain
/// is padded to 47 like [`MulRow::carry`].
#[derive(Clone, Debug)]
pub struct ReduceRow {
    pub x: Vec<u16>,
    pub z: Vec<u16>,
    pub q: Vec<u16>,
    pub carry: Vec<u32>,
}

pub const MUL_A_LIMBS: usize = 2 * LIMBS;
pub const MUL_B_LIMBS: usize = LIMBS;
pub const MUL_C_LIMBS: usize = 3 * LIMBS;
/// Coordinates of the MulAir link tuple `(a ‖ b ‖ c)`.
pub const MUL_TUPLE: usize = MUL_A_LIMBS + MUL_B_LIMBS + MUL_C_LIMBS;
pub const RED_X_LIMBS: usize = 3 * LIMBS;
pub const RED_Q_LIMBS: usize = 2 * LIMBS;
/// Coordinates of the ReduceAir link tuple `(x ‖ z ‖ q)`.
pub const REDUCE_TUPLE: usize = RED_X_LIMBS + LIMBS + RED_Q_LIMBS;
/// Uniform carry-chain width of both coprocessors (max convolution length).
pub const GADGET_CARRY_LIMBS: usize = 3 * LIMBS - 1;

fn pad_to(values: &[u16], width: usize) -> Vec<u16> {
    let mut out = values.to_vec();
    out.resize(width, 0);
    out
}

fn pad_carries(values: &[u32]) -> Vec<u32> {
    let mut out = values.to_vec();
    out.resize(GADGET_CARRY_LIMBS, 0);
    out
}

use stwo::core::fields::m31::M31;

pub(crate) struct RoundScope {
    pub pos: u32,
    pub is_full: bool,
    pub k: [[u16; LIMBS]; 3],
    pub w: [[u16; LIMBS]; 2],
    pub sel_init: bool,
    pub sel_void: bool,
    pub sel_final: bool,
}

pub(crate) fn round_constants(pos: usize) -> [[u16; LIMBS]; 3] {
    let keys = compressed_round_keys();
    let zero = [0u16; LIMBS];
    let head = N_FULL_ROUNDS / 2;
    if pos < head {
        [
            felt_to_limbs(&keys[pos * 3]),
            felt_to_limbs(&keys[pos * 3 + 1]),
            felt_to_limbs(&keys[pos * 3 + 2]),
        ]
    } else if pos < head + N_PARTIAL_ROUNDS {
        let key = felt_to_limbs(&keys[3 * head + (pos - head)]);
        [zero, zero, key]
    } else {
        let tail = pos - (head + N_PARTIAL_ROUNDS);
        let base = 3 * head + N_PARTIAL_ROUNDS + 3 * tail;
        [
            felt_to_limbs(&keys[base]),
            felt_to_limbs(&keys[base + 1]),
            felt_to_limbs(&keys[base + 2]),
        ]
    }
}

/// One honest round of witness columns; returns the next state, the v1 flat
/// columns, and the v2 coprocessor rows.  Lanes 0/1 contribute square /
/// cube / cube-reduce rows only in full rounds (the partial-round gate makes
/// those values irrelevant); lane 2 and the three mix reductions always do.
pub(crate) fn one_round_witness(
    state_in: [[u16; LIMBS]; 3],
    scope: &RoundScope,
) -> ([[u16; LIMBS]; 3], Vec<Vec<M31>>, Vec<MulRow>, Vec<ReduceRow>) {
    let mut col: Vec<Vec<M31>> = Vec::with_capacity(WITNESS_COLUMNS);
    let mut muls: Vec<MulRow> = Vec::with_capacity(6);
    let mut reduces: Vec<ReduceRow> = Vec::with_capacity(6);
    // One column per limb position; each holds this row's single value.
    let push = |col: &mut Vec<Vec<M31>>, values: &[u16]| {
        for &v in values {
            col.push(vec![M31::from(v as u32)]);
        }
    };
    let push32 = |col: &mut Vec<Vec<M31>>, values: &[u32]| {
        for &v in values {
            col.push(vec![M31::from(v)]);
        }
    };

    for lane in 0..3 {
        push(&mut col, &state_in[lane]);
    }

    // absorb + round constant: s_c = state_in + w + k (the absorb words ride
    // on lanes 0/1 only; lane 2 never absorbs)
    let mut s_c = [[0u16; LIMBS]; 3];
    for lane in 0..3 {
        let zeros = [0u16; LIMBS];
        let absorbed: &[u16; LIMBS] = match lane {
            0 => &scope.w[0],
            1 => &scope.w[1],
            _ => &zeros,
        };
        let (out, carry) = add_witness(
            L,
            &[(1, &state_in[lane]), (1, absorbed), (1, &scope.k[lane])],
        );
        push(&mut col, &out);
        push32(&mut col, &carry);
        s_c[lane] = out.try_into().expect("16 limbs");
    }

    // s-boxes
    let mut post = [[0u16; LIMBS]; 3];
    for lane in 0..3 {
        let (square, square_carry) = mul_witness(&s_c[lane], &s_c[lane], 2 * L);
        let (x2, _x2c) = if lane < 2 {
            push(&mut col, &square);
            push32(&mut col, &square_carry);
            let gate = |v: u16| if scope.is_full { v } else { 0 };
            let gate32 = |v: u32| if scope.is_full { v } else { 0 };
            let gated: Vec<u16> = square.iter().map(|&v| gate(v)).collect();
            let gated_c: Vec<u32> = square_carry.iter().map(|&v| gate32(v)).collect();
            push(&mut col, &gated);
            push32(&mut col, &gated_c);
            (gated, gated_c)
        } else {
            push(&mut col, &square);
            push32(&mut col, &square_carry);
            (square.clone(), square_carry.clone())
        };
        let (x3, x3c) = mul_witness(&x2, &s_c[lane], 3 * L);
        push(&mut col, &x3);
        push32(&mut col, &x3c);
        let (q, z, qc) = reduce48_with_carries(&x3);
        push(&mut col, &q);
        push32(&mut col, &qc);
        push(&mut col, &z);
        if lane == 2 || scope.is_full {
            // square row: a = s_c ‖ 0¹⁶, b = s_c, c = sq ‖ 0¹⁶
            muls.push(MulRow {
                a: pad_to(&s_c[lane], MUL_A_LIMBS),
                b: s_c[lane].to_vec(),
                c: pad_to(&square, MUL_C_LIMBS),
                carry: pad_carries(&square_carry),
            });
            // cube row: a = x2, b = s_c, c = x3
            muls.push(MulRow {
                a: x2.clone(),
                b: s_c[lane].to_vec(),
                c: x3.clone(),
                carry: pad_carries(&x3c),
            });
            reduces.push(ReduceRow {
                x: x3.clone(),
                z: z.clone(),
                q: q.clone(),
                carry: pad_carries(&qc),
            });
        }
        let p: Vec<u16> = if lane < 2 {
            let value = if scope.is_full {
                z.clone()
            } else {
                s_c[lane].to_vec()
            };
            push(&mut col, &value);
            value
        } else {
            z.clone()
        };
        post[lane] = p.try_into().expect("16 limbs");
    }

    // mix
    let (t, tc) = add_witness(L, &[(1, &post[0]), (1, &post[1]), (1, &post[2])]);
    push(&mut col, &t);
    push32(&mut col, &tc);
    let k4 = p_multiple(4);
    let k6 = p_multiple(6);

    for lane in 0..3 {
        let coeff: u64 = if lane == 2 { 3 } else { 2 };
        let (d, dc) = add_witness(L, &[(coeff, &post[lane])]);
        push(&mut col, &d);
        push32(&mut col, &dc);
        let v;
        let bw;
        let vc;
        if lane == 0 {
            let (value, value_carry) = add_witness(L, &[(1, &d), (1, &t)]);
            v = value;
            vc = value_carry;
            bw = vec![0u16; L];
        } else {
            let multiple = if lane == 1 { k4 } else { k6 };
            let (u, uc) = add_witness(L, &[(1, &t), (1, &multiple)]);
            push(&mut col, &u);
            push32(&mut col, &uc);
            let (value, bits) = sub_witness(&u, &d);
            v = value;
            vc = vec![0u32; L];
            bw = bits;
        }
        let (qm, zm, rc) = reduce16_with_carries(&v);
        push(&mut col, &v);
        push32(&mut col, &vc);
        push32(&mut col, &rc);
        if lane != 0 {
            push(&mut col, &bw);
        }
        col.push(vec![M31::from(qm as u32)]);
        push(&mut col, &zm);
        // mix reduction row: x = v ‖ 0³², z = zm, q = qm ‖ 0³¹
        reduces.push(ReduceRow {
            x: pad_to(&v, RED_X_LIMBS),
            z: zm.to_vec(),
            q: pad_to(&[qm], RED_Q_LIMBS),
            carry: pad_carries(&rc),
        });
        post[lane] = zm;
    }

    // pos_next + wrap flag
    let is_wrap = scope.pos as usize == ROUND_COUNT - 1;
    let pos_next = if is_wrap { 0 } else { scope.pos + 1 };
    col.push(vec![M31::from(pos_next)]);
    col.push(vec![M31::from(u32::from(is_wrap))]);

    debug_assert_eq!(col.len(), WITNESS_COLUMNS);
    (post, col, muls, reduces)
}

/// Build the honest trace of one chain statement.
/// Rebuild the input-side scope schedule — position, round-type, round
/// keys, absorbed words, selectors and the initial-state tuple — from the
/// spec bytes alone, without touching the Poseidon permutation.
///
/// This is the verifier's side of the byte-scope binding: every column here
/// is a deterministic arrangement of public data (message bytes plus the
/// canonical round-constant table), so a verifier can reconstruct the whole
/// block and compare it against the committed preprocessed tree.  The
/// derived `S_VOID`/`S_ANCHOR` blocks are deliberately excluded — they are
/// what the STARK establishes, not public setup.
pub fn public_scope_columns(
    spec: &Poseidon252ChainSpec,
) -> TexasAirResult<Vec<Vec<M31>>> {
    spec.validate()?;
    let pairs = spec.absorb_pairs();
    let layout = spec.layout();
    let rows = layout.rows;
    let initial = spec.initial_limbs();

    let mut scope: Vec<Vec<M31>> = vec![Vec::new(); S_VOID];
    for row in 0..rows {
        let block = row / ROUND_COUNT;
        let pos = row % ROUND_COUNT;
        let is_real = block < layout.n_real;
        let is_full = pos < N_FULL_ROUNDS / 2 || pos >= N_FULL_ROUNDS / 2 + N_PARTIAL_ROUNDS;
        let k = round_constants(pos);
        let w: [[u16; LIMBS]; 2] = if pos == 0 && is_real {
            [felt_to_limbs(&pairs[block][0]), felt_to_limbs(&pairs[block][1])]
        } else {
            [[0u16; LIMBS]; 2]
        };

        scope[S_POS].push(M31::from(pos as u32));
        scope[S_IS_FULL].push(M31::from(u32::from(is_full)));
        for lane in 0..3 {
            for (i, &limb) in k[lane].iter().enumerate() {
                scope[S_K + lane * LIMBS + i].push(M31::from(limb as u32));
            }
        }
        for lane in 0..2 {
            for (i, &limb) in w[lane].iter().enumerate() {
                scope[S_W + lane * LIMBS + i].push(M31::from(limb as u32));
            }
        }
        let sel_init = row == 0;
        let sel_void = row == rows - 1;
        let sel_final = is_real && row == ROUND_COUNT * layout.n_real - 1;
        scope[S_SEL].push(M31::from(u32::from(sel_init)));
        scope[S_SEL + 1].push(M31::from(u32::from(sel_void)));
        scope[S_SEL + 2].push(M31::from(u32::from(sel_final)));
        for lane in 0..3 {
            for (i, &limb) in initial[lane].iter().enumerate() {
                scope[S_INIT + lane * LIMBS + i].push(M31::from(limb as u32));
            }
        }
        scope[S_INIT + 3 * LIMBS].push(M31::from(0));
    }
    Ok(scope)
}

/// Deterministic coprocessor row counts `(mul, reduce)` for a spec: every
/// real permutation contributes six mul and six reduce rows per full round,
/// and two mul / four reduce rows per partial round.  Padding rows carry no
/// algebra.  The verifier derives these from the layout alone, pinning the
/// preprocessed enabler columns without any witness access.
pub fn coprocessor_row_counts(spec: &Poseidon252ChainSpec) -> (usize, usize) {
    let layout = spec.layout();
    let mut mul = 0usize;
    let mut reduce = 0usize;
    for row in 0..layout.rows {
        let pos = row % ROUND_COUNT;
        let is_full = pos < N_FULL_ROUNDS / 2 || pos >= N_FULL_ROUNDS / 2 + N_PARTIAL_ROUNDS;
        // lanes with a nonlinear s-box (lane 2 always, lanes 0/1 in full
        // rounds) contribute two mul rows and one cube-reduce row each;
        // every round contributes the three mix reductions.
        let nonlinear_lanes = if is_full { 3 } else { 1 };
        mul += 2 * nonlinear_lanes;
        reduce += nonlinear_lanes + 3;
    }
    (mul, reduce)
}

pub fn build_chain_trace(spec: &Poseidon252ChainSpec) -> TexasAirResult<Poseidon252Trace> {
    spec.validate()?;
    let pairs = spec.absorb_pairs();
    let layout = spec.layout();
    let rows = layout.rows;
    let initial = spec.initial_limbs();
    let anchor_limbs: Vec<[u16; LIMBS]> = spec.anchor_state().iter().map(felt_to_limbs).collect();
    // After the final real permutation the trace continues with `n_pad`
    // complete zero-absorb permutations and then `leftover` truncated
    // rounds; the void tuple pins the terminal state of that whole padding
    // walk, so the multiset chain closes across every padded row.
    let mut evolved = spec.anchor_state();
    for _ in 0..layout.n_pad {
        for pos in 0..ROUND_COUNT {
            apply_round(&mut evolved, pos);
        }
    }
    for pos in 0..layout.leftover {
        apply_round(&mut evolved, pos);
    }
    let void_state: Vec<[u16; LIMBS]> = evolved.iter().map(felt_to_limbs).collect();
    let void_pos = (layout.leftover % ROUND_COUNT) as u32;

    let mut scope: Vec<Vec<M31>> = vec![Vec::new(); SCOPE_COLUMNS];
    let mut witness: Vec<Vec<M31>> = vec![Vec::new(); WITNESS_COLUMNS];
    let mut multiplicities16 = vec![0u32; 1 << 16];
    let mut multiplicities12 = vec![0u32; 1 << 12];
    let mut mul_rows: Vec<MulRow> = Vec::new();
    let mut reduce_rows: Vec<ReduceRow> = Vec::new();

    let mut state = initial;
    for row in 0..rows {
        let block = row / ROUND_COUNT;
        let pos = row % ROUND_COUNT;
        let is_real = block < layout.n_real;
        let scope_row = RoundScope {
            pos: pos as u32,
            is_full: pos < N_FULL_ROUNDS / 2 || pos >= N_FULL_ROUNDS / 2 + N_PARTIAL_ROUNDS,
            k: round_constants(pos),
            w: if pos == 0 && is_real {
                let pair = &pairs[block];
                [felt_to_limbs(&pair[0]), felt_to_limbs(&pair[1])]
            } else {
                [[0u16; LIMBS]; 2]
            },
            sel_init: row == 0,
            sel_void: row == rows - 1,
            sel_final: is_real && row == ROUND_COUNT * layout.n_real - 1,
        };

        scope[S_POS].push(M31::from(scope_row.pos));
        scope[S_IS_FULL].push(M31::from(u32::from(scope_row.is_full)));
        for lane in 0..3 {
            for (i, &limb) in scope_row.k[lane].iter().enumerate() {
                scope[S_K + lane * LIMBS + i].push(M31::from(limb as u32));
            }
        }
        for lane in 0..2 {
            for (i, &limb) in scope_row.w[lane].iter().enumerate() {
                scope[S_W + lane * LIMBS + i].push(M31::from(limb as u32));
            }
        }
        scope[S_SEL].push(M31::from(u32::from(scope_row.sel_init)));
        scope[S_SEL + 1].push(M31::from(u32::from(scope_row.sel_void)));
        scope[S_SEL + 2].push(M31::from(u32::from(scope_row.sel_final)));
        for lane in 0..3 {
            for (i, &limb) in initial[lane].iter().enumerate() {
                scope[S_INIT + lane * LIMBS + i].push(M31::from(limb as u32));
            }
        }
        scope[S_INIT + 3 * LIMBS].push(M31::from(0));
        for lane in 0..3 {
            for (i, &limb) in void_state[lane].iter().enumerate() {
                scope[S_VOID + lane * LIMBS + i].push(M31::from(limb as u32));
            }
        }
        scope[S_VOID + 3 * LIMBS].push(M31::from(void_pos));
        for lane in 0..3 {
            for (i, &limb) in anchor_limbs[lane].iter().enumerate() {
                scope[S_ANCHOR + lane * LIMBS + i].push(M31::from(limb as u32));
            }
        }

        let (state_out, row_witness, round_muls, round_reduces) =
            one_round_witness(state, &scope_row);
        for (col_index, values) in row_witness.into_iter().enumerate() {
            witness[col_index].push(values[0]);
        }
        mul_rows.extend(round_muls);
        reduce_rows.extend(round_reduces);

        for col in range_use_columns() {
            let value = witness[*col][row].0 as usize;
            assert!(
                value < 1 << 16,
                "range16 column {col} has value {value} at row {row}"
            );
            multiplicities16[value] += 1;
        }
        for &col in bound12_columns() {
            let value = witness[col][row].0 as usize;
            assert!(value < 1 << 12, "bound12 column exceeded 2^12: {value}");
            multiplicities12[value] += 1;
        }

        state = state_out;
        if scope_row.sel_final {
            let native = spec.anchor_state();
            for lane in 0..3 {
                debug_assert_eq!(
                    limbs_to_felt(&state[lane]),
                    native[lane],
                    "witness diverged from the native chain at the anchor row"
                );
            }
        }
    }

    for (index, column) in scope.iter().chain(witness.iter()).enumerate() {
        assert_eq!(column.len(), rows, "trace column {index} height mismatch");
    }

    let mul_log = mul_rows.len().next_power_of_two().max(2).ilog2();
    let reduce_log = reduce_rows.len().next_power_of_two().max(2).ilog2();

    Ok(Poseidon252Trace {
        log_size: layout.log_size,
        scope,
        witness,
        multiplicities16,
        multiplicities12,
        mul_rows,
        reduce_rows,
        mul_log,
        reduce_log,
    })
}

// ===========================================================================
// Native-layer tests (constants, limbs, sponge, witness consistency)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_matches_starknet_crypto() {
        // Deterministic pseudo-random states via a splitmix chain.
        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..8 {
            seed = seed
                .wrapping_mul(0x9E3779B97F4A7C15)
                .wrapping_add(0xBF58476D1CE4E5B9);
            let felt = |salt: u64| Felt::from(seed ^ salt.rotate_left(17));
            let mut state = [felt(1), felt(2), felt(3)];
            let mut reference = state;
            permute_comp(&mut state);
            starknet_crypto::poseidon_permute_comp(&mut reference);
            assert_eq!(state, reference, "AIR round keys must match the library");
            // single-round equivalence is exercised in
            // `witness_round_reproduces_native_permutation`
        }
    }

    #[test]
    fn sponge_matches_poseidon_hash_many() {
        for n in [0usize, 1, 2, 3, 5, 8, 13] {
            let message: Vec<Felt> = (0..n)
                .map(|i| Felt::from(1000u64 + i as u64 * 7919))
                .collect();
            let spec = Poseidon252ChainSpec::hash_many(&message);
            let expected = starknet_crypto::poseidon_hash_many(&message);
            assert_eq!(spec.anchor_state()[0], expected, "n = {n}");
        }
    }

    #[test]
    fn limbs_roundtrip_and_prime_constant() {
        // P = 2^251 + 17·2^192 + 1.
        // P is the field modulus, so limbs_to_felt (which requires a
        // canonical field element) must reject it — check the limb bytes
        // directly against 0x0800000000000011000...0001.
        let mut bytes = [0u8; 32];
        for (i, limb) in P_LIMBS.iter().enumerate() {
            let [hi, lo] = limb.to_be_bytes();
            bytes[30 - 2 * i] = hi;
            bytes[31 - 2 * i] = lo;
        }
        assert_eq!(bytes[0], 0x08);
        assert_eq!(bytes[1..=6], [0u8; 6]);
        assert_eq!(bytes[7], 0x11);
        assert_eq!(bytes[8..31], [0u8; 23]);
        assert_eq!(bytes[31], 0x01);
        // types-core 的 from_bytes_be 无失败路径（≥ P 静默归约），canonical
        // 判定走字节往返（P 归约后必非原字节）。
        assert!(crate::state_root::felt_from_canonical_bytes(&bytes).is_none());

        let value = Felt::from(0x0123456789abcdeu64);
        assert_eq!(limbs_to_felt(&felt_to_limbs(&value)), value);
    }

    #[test]
    fn witness_round_reproduces_native_permutation() {
        let mut state = [
            Felt::from(11u64),
            Felt::from(22u64),
            Felt::from(33u64),
        ];
        let mut native = state;
        let scope = RoundScope {
            pos: 3,
            is_full: true,
            k: round_constants(3),
            w: [[0u16; LIMBS]; 2],
            sel_init: false,
            sel_void: false,
            sel_final: false,
        };
        let limbs: [[u16; LIMBS]; 3] = state.each_ref().map(felt_to_limbs);
        let (next, columns, _, _) = one_round_witness(limbs, &scope);
        assert_eq!(columns.len(), WITNESS_COLUMNS);
        apply_round(&mut native, 3);
        for lane in 0..3 {
            assert_eq!(limbs_to_felt(&next[lane]), native[lane], "lane {lane}");
        }

        // partial round: only lane 2 is nonlinear
        let scope_partial = RoundScope {
            pos: 40,
            is_full: false,
            k: round_constants(40),
            w: [[0u16; LIMBS]; 2],
            sel_init: false,
            sel_void: false,
            sel_final: false,
        };
        let limbs_partial: [[u16; LIMBS]; 3] = state.each_ref().map(felt_to_limbs);
        let (next_partial, _, _, _) = one_round_witness(limbs_partial, &scope_partial);
        apply_round(&mut state, 40);
        for lane in 0..3 {
            assert_eq!(
                limbs_to_felt(&next_partial[lane]),
                state[lane],
                "partial lane {lane}"
            );
        }
    }

    #[test]
    fn full_chain_witness_tracks_the_native_sponge() {
        let message: Vec<Felt> = (0..5)
            .map(|i| Felt::from(9000u64 + i as u64 * 104729))
            .collect();
        let spec = Poseidon252ChainSpec::hash_many(&message);
        let trace = build_chain_trace(&spec).expect("witness builds");
        let layout = spec.layout();
        assert_eq!(trace.log_size, layout.log_size);
        // The last real row must equal the anchor (debug_assert covers it in
        // debug builds; re-derive here for release runs).
        let anchor_row = ROUND_COUNT * layout.n_real - 1;
        for lane in 0..3 {
            let mut limbs = [0u16; LIMBS];
            for (i, limb) in limbs.iter_mut().enumerate() {
                *limb = witness_column_value(&trace, w_mix_zm(lane) + i, anchor_row);
            }
            assert_eq!(limbs_to_felt(&limbs), spec.anchor_state()[lane]);
        }
    }

    fn witness_column_value(trace: &Poseidon252Trace, column: usize, row: usize) -> u16 {
        trace.witness[column][row].0 as u16
    }

    /// Big-integer value of a little-endian limb vector (no modular
    /// reduction) for cross-checking gadget rows.
    fn big_uint_value(limbs: &[u16]) -> num_bigint::BigUint {
        let mut v = num_bigint::BigUint::from(0u32);
        for &limb in limbs.iter().rev() {
            v = (v << 16) | num_bigint::BigUint::from(limb);
        }
        v
    }

    #[test]
    fn gadget_rows_are_self_consistent() {
        let message = [Felt::from(7u64), Felt::from(9u64)];
        let spec = Poseidon252ChainSpec::hash_many(&message);
        let trace = build_chain_trace(&spec).expect("witness builds");
        let p_big = {
            let bytes = P_LIMBS.iter().flat_map(|&l| l.to_le_bytes()).collect::<Vec<u8>>();
            num_bigint::BigUint::from_bytes_le(&bytes)
        };

        for (index, row) in trace.mul_rows.iter().enumerate() {
            assert_eq!(row.a.len(), MUL_A_LIMBS, "mul row {index} a width");
            assert_eq!(row.b.len(), MUL_B_LIMBS, "mul row {index} b width");
            assert_eq!(row.c.len(), MUL_C_LIMBS, "mul row {index} c width");
            assert_eq!(row.carry.len(), GADGET_CARRY_LIMBS, "mul row {index} carry width");
            assert_eq!(
                big_uint_value(&row.a) * big_uint_value(&row.b),
                big_uint_value(&row.c),
                "mul row {index}: c != a·b over the integers"
            );
        }
        for (index, row) in trace.reduce_rows.iter().enumerate() {
            assert_eq!(row.x.len(), RED_X_LIMBS, "reduce row {index} x width");
            assert_eq!(row.z.len(), LIMBS, "reduce row {index} z width");
            assert_eq!(row.q.len(), RED_Q_LIMBS, "reduce row {index} q width");
            assert_eq!(
                big_uint_value(&row.z) + big_uint_value(&row.q) * &p_big,
                big_uint_value(&row.x),
                "reduce row {index}: x != z + q·P"
            );
        }
    }

    #[test]
    fn gadget_row_counts_match_the_round_structure() {
        let message = [Felt::from(7u64), Felt::from(9u64)];
        let spec = Poseidon252ChainSpec::hash_many(&message);
        let layout = spec.layout();
        let trace = build_chain_trace(&spec).expect("witness builds");
        // 2-message chain at log 8: n_real = 2, n_pad = 0, leftover = 74 with
        // 4 full + 70 partial leftover rounds.
        let full_rounds =
            layout.n_real * N_FULL_ROUNDS + 4.min(layout.leftover);
        let partial_rounds = layout.n_real * N_PARTIAL_ROUNDS + layout.leftover.saturating_sub(4);
        let expected_muls = full_rounds * 6 + partial_rounds * 2;
        let expected_reduces = full_rounds * 6 + partial_rounds * 4;
        assert_eq!(trace.mul_rows.len(), expected_muls);
        assert_eq!(trace.reduce_rows.len(), expected_reduces);
        assert_eq!(trace.mul_log, expected_muls.next_power_of_two().ilog2());
        assert_eq!(trace.reduce_log, expected_reduces.next_power_of_two().ilog2());
    }
}
