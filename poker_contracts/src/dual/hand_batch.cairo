//! Hand-level batch verification of direct-sigma proofs on secp256k1
//! (DAPV without the pairing; docs/design/DUAL_PROOF_PROTOCOL.md v2.8 direction).
//!
//! Every proof's residual equations are replayed with the exact Keccak
//! transcript schedule of the individual verifiers (same labels), collected
//! in canonical order, and folded with powers of the hand challenge
//!
//!   rho = LE(keccak256("poker/hand-batch/v1" ‖ hand_id ‖
//!                       (coeff_be ‖ x_be ‖ y_be) per term)) mod n
//!
//! into one multi-scalar accumulation L = Σ_eq rho^eq Σ_term coeff·point.
//! The hand is accepted iff L is the identity — the group's own zero test,
//! which is a coordinate comparison here (the pairing form e(L, H2) = 1 is
//! algebraically equivalent and reserved for a future SNARK layer; see
//! docs/SOUNDNESS.md for the equivalence proof and the L==O decision).
//!
//! The hand_id inside rho's input binds the transcript to one hand
//! instance: a transcript minted for hand A folds to a non-zero L in hand
//! B's settlement (replay protection; rho-binding alone cannot achieve
//! this because zero residuals stay zero for any rho).
//!
//! Payload layout (u256 words, points as big-endian affine x/y):
//! [n_own, n_reveal, n_fold,
//!  ownership × n_own: [pk_x, pk_y, r_x, r_y, s],
//!  reveal   × n_reveal: [pk 2, c1 2, c2 2, token 2, t1 2, t2 2, nonce, s],
//!  fold     × n_fold: [n, pk 2, cpk 2, nonce, s,
//!                      in_c1 2n, in_c2 2n, out_c1 2n, out_c2 2n, a 2n]]
//!
//! Bayer-Groth shuffle proofs are not folded into the accumulator yet
//! (their eight equations need the commitment-key MSM refactor); the
//! settlement keeps calling the existing per-proof shuffle verifier until
//! the shuffle residuals land here.

use core::array::{ArrayTrait, SpanTrait};
use core::option::Option;
use core::starknet::secp256k1::Secp256k1Point;
use core::starknet::secp256_trait::{Secp256PointTrait, Secp256Trait};

use super::fr::{fr_mul, fr_neg};
use super::keccak::{challenge_mod_n, keccak256, u256_to_be_bytes, u256_to_le_bytes};
use super::keccak_transcript::{
    point_compressed, scalar_be, transcript_append, transcript_challenge, transcript_new,
};
use super::secp256k1_verifier::{GENERATOR_X, GENERATOR_Y, SECP256K1_P};

// ---- EC syscall wrappers (same pattern as secp256k1_verifier) ----

fn ec_decode(x: u256, y: u256) -> Option<Secp256k1Point> {
    match Secp256Trait::<Secp256k1Point>::secp256_ec_new_syscall(x, y) {
        Result::Ok(option) => option,
        Result::Err(_) => Option::None,
    }
}

fn ec_mul(point: Secp256k1Point, scalar: u256) -> Option<Secp256k1Point> {
    match Secp256PointTrait::mul(point, scalar) {
        Result::Ok(value) => Option::Some(value),
        Result::Err(_) => Option::None,
    }
}

fn ec_add(a: Secp256k1Point, b: Secp256k1Point) -> Option<Secp256k1Point> {
    match Secp256PointTrait::add(a, b) {
        Result::Ok(value) => Option::Some(value),
        Result::Err(_) => Option::None,
    }
}

fn coords(point: Secp256k1Point) -> Option<(u256, u256)> {
    match Secp256PointTrait::get_coordinates(point) {
        Result::Ok(pair) => Option::Some(pair),
        Result::Err(_) => Option::None,
    }
}

fn require_on_curve(x: u256, y: u256) -> bool {
    match ec_decode(x, y) {
        Option::Some(_) => true,
        Option::None => false,
    }
}

// ---- residual terms ----

/// One accumulator term: `coeff · (x, y)`.
#[derive(Copy, Drop, Debug)]
pub struct Term {
    pub coeff: u256,
    pub x: u256,
    pub y: u256,
}

/// Hand-bound transcript domain for every transcript-based proof in the
/// batch: keccak256("poker/hand-batch/proto" ‖ hand_id). A proof minted for
/// another hand replays with wrong challenges here, so its residual is
/// non-zero for ANY rho — this is what actually stops full-transcript
/// replay (rho binding alone cannot: zero residuals fold to zero under
/// every rho; docs/SOUNDNESS.md §8).
fn hand_transcript_domain(hand_id: Span<u8>) -> Array<u8> {
    let mut input: Array<u8> = array![];
    let prefix: Array<u8> = array![
        0x70, 0x6f, 0x6b, 0x65, 0x72, 0x2f, 0x68, 0x61, 0x6e, 0x64, 0x2d, 0x62, 0x61, 0x74,
        0x63, 0x68, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f
    ];
    let mut d: u32 = 0;
    while d < prefix.len() {
        input.append(*prefix.at(d));
        d += 1;
    }
    for byte in hand_id {
        input.append(*byte);
    }
    // keccak256 returns the digest as a little-endian integer; the raw
    // digest byte order (matching the Rust generator) is LE bytes.
    u256_to_le_bytes(keccak256(input.span()))
}

fn append_compressed(ref out: Array<u8>, x: u256, y: u256) {
    let tag: u8 = if y.low & 1 == 1 { 0x03 } else { 0x02 };
    out.append(tag);
    let x_bytes = u256_to_be_bytes(x);
    let mut i: u32 = 0;
    while i < 32 {
        out.append(*x_bytes.at(i));
        i += 1;
    }
}

fn append_be(ref out: Array<u8>, value: u256) {
    let bytes = u256_to_be_bytes(value);
    let mut i: u32 = 0;
    while i < 32 {
        out.append(*bytes.at(i));
        i += 1;
    }
}

/// Ownership residual `s·G − R − c·pk`. The challenge is derived on-chain
/// exactly like `verify_ownership` but **prepends the hand transcript
/// domain** (docs/SOUNDNESS.md §9-L2 / §14.1: without the hand context an
/// endorsement minted for hand A verifies unchanged under hand B — zero
/// residuals stay zero for any rho, §8). One equation.
fn ownership_terms(
    protocol_name: Span<u8>,
    pk: (u256, u256),
    big_r: (u256, u256),
    s: u256,
    ref terms: Array<Term>,
) -> bool {
    let (pk_x, pk_y) = pk;
    let (r_x, r_y) = big_r;
    if !require_on_curve(pk_x, pk_y) || !require_on_curve(r_x, r_y) {
        return false;
    }
    let mut input: Array<u8> = array![];
    let mut d: u32 = 0;
    while d < protocol_name.len() {
        input.append(*protocol_name.at(d));
        d += 1;
    }
    append_compressed(ref input, GENERATOR_X, GENERATOR_Y);
    append_compressed(ref input, pk_x, pk_y);
    append_compressed(ref input, r_x, r_y);
    let c = challenge_mod_n(input.span());
    terms.append(Term { coeff: s, x: GENERATOR_X, y: GENERATOR_Y });
    terms.append(Term { coeff: fr_neg(c), x: pk_x, y: pk_y });
    terms.append(Term { coeff: fr_neg(1_u256), x: r_x, y: r_y });
    true
}

/// Reveal-token residuals (two equations), transcript replay identical to
/// `verify_reveal_token`.
fn reveal_terms(
    protocol_name: Span<u8>,
    pk: (u256, u256),
    c1: (u256, u256),
    c2: (u256, u256),
    token: (u256, u256),
    t1: (u256, u256),
    t2: (u256, u256),
    nonce: u256,
    s: u256,
    ref terms: Array<Term>,
) -> bool {
    let (pk_x, pk_y) = pk;
    let (c1_x, c1_y) = c1;
    let (c2_x, c2_y) = c2;
    let (token_x, token_y) = token;
    let (t1_x, t1_y) = t1;
    let (t2_x, t2_y) = t2;
    if !require_on_curve(pk_x, pk_y)
        || !require_on_curve(c1_x, c1_y)
        || !require_on_curve(c2_x, c2_y)
        || !require_on_curve(token_x, token_y)
        || !require_on_curve(t1_x, t1_y)
        || !require_on_curve(t2_x, t2_y)
    {
        return false;
    }
    let l_nonce = label(array![
        0x72, 0x65, 0x76, 0x65, 0x61, 0x6c, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x6e,
        0x6f, 0x6e, 0x63, 0x65
    ].span());
    let l_pk = label(array![0x70, 0x6b].span());
    let l_c1 = label(array![0x63, 0x31].span());
    let l_c2 = label(array![0x63, 0x32].span());
    let l_token = label(array![
        0x72, 0x65, 0x76, 0x65, 0x61, 0x6c, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e
    ].span());
    let l_t1 = label(array![0x74, 0x31].span());
    let l_t2 = label(array![0x74, 0x32].span());
    let l_ch = label(array![
        0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65
    ].span());

    let mut state = transcript_new(protocol_name);
    state = transcript_append(state, l_nonce, scalar_be(nonce).span());
    state = transcript_append(state, l_pk, point_compressed(pk_x, pk_y).span());
    state = transcript_append(state, l_c1, point_compressed(c1_x, c1_y).span());
    state = transcript_append(state, l_c2, point_compressed(c2_x, c2_y).span());
    state = transcript_append(state, l_token, point_compressed(token_x, token_y).span());
    state = transcript_append(state, l_t1, point_compressed(t1_x, t1_y).span());
    state = transcript_append(state, l_t2, point_compressed(t2_x, t2_y).span());
    let c = transcript_challenge(state, l_ch);

    // s·G − t1 − c·pk = O
    terms.append(Term { coeff: s, x: GENERATOR_X, y: GENERATOR_Y });
    terms.append(Term { coeff: fr_neg(c), x: pk_x, y: pk_y });
    terms.append(Term { coeff: fr_neg(1_u256), x: t1_x, y: t1_y });
    // s·c1 − t2 − c·token = O
    terms.append(Term { coeff: s, x: c1_x, y: c1_y });
    terms.append(Term { coeff: fr_neg(c), x: token_x, y: token_y });
    terms.append(Term { coeff: fr_neg(1_u256), x: t2_x, y: t2_y });
    true
}

/// Leave/fold batch DLEQ residuals: one pk equation plus one equation per
/// card, transcript replay identical to `verify_fold_leave` (including the
/// on-chain d2 = in_c2 − out_c2 computation).
fn fold_terms(
    protocol_name: Span<u8>,
    pk: (u256, u256),
    cpk: (u256, u256),
    nonce: u256,
    s: u256,
    n: u32,
    in_c1: Span<u256>,
    in_c2: Span<u256>,
    out_c1: Span<u256>,
    out_c2: Span<u256>,
    a: Span<u256>,
    ref terms: Array<Term>,
) -> bool {
    let (pk_x, pk_y) = pk;
    let (cpk_x, cpk_y) = cpk;
    if !require_on_curve(pk_x, pk_y) || !require_on_curve(cpk_x, cpk_y) {
        return false;
    }
    let l_pk = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x70, 0x6b].span());
    let l_in_c1 = label(array![
        0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x31
    ].span());
    let l_in_c2 = label(array![
        0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x32
    ].span());
    let l_out_c1 = label(array![
        0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x31
    ].span());
    let l_out_c2 = label(array![
        0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x32
    ].span());
    let l_a = label(array![
        0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x70, 0x65, 0x72, 0x5f, 0x63, 0x61, 0x72, 0x64,
        0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74
    ].span());
    let l_cpk = label(array![
        0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
        0x6e, 0x74, 0x5f, 0x70, 0x6b
    ].span());
    let l_d2 = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x64, 0x32].span());
    let l_nonce = label(array![
        0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x6e, 0x6f, 0x6e, 0x63, 0x65
    ].span());
    let l_ch = label(array![
        0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67,
        0x65
    ].span());

    let mut state = transcript_new(protocol_name);
    state = transcript_append(state, l_pk, point_compressed(pk_x, pk_y).span());
    let mut i: u32 = 0;
    while i < n {
        state = transcript_append(
            state,
            l_in_c1,
            point_compressed(*in_c1.at(2 * i), *in_c1.at(2 * i + 1)).span(),
        );
        state = transcript_append(
            state,
            l_in_c2,
            point_compressed(*in_c2.at(2 * i), *in_c2.at(2 * i + 1)).span(),
        );
        i += 1;
    }
    i = 0;
    while i < n {
        state = transcript_append(
            state,
            l_out_c1,
            point_compressed(*out_c1.at(2 * i), *out_c1.at(2 * i + 1)).span(),
        );
        state = transcript_append(
            state,
            l_out_c2,
            point_compressed(*out_c2.at(2 * i), *out_c2.at(2 * i + 1)).span(),
        );
        i += 1;
    }
    i = 0;
    while i < n {
        state = transcript_append(
            state,
            l_a,
            point_compressed(*a.at(2 * i), *a.at(2 * i + 1)).span(),
        );
        i += 1;
    }
    state = transcript_append(state, l_cpk, point_compressed(cpk_x, cpk_y).span());
    // d2_i = in_c2_i − out_c2_i, computed on-chain and fed to the
    // transcript before the challenge, exactly like verify_fold_leave.
    let mut d2s: Array<(u256, u256)> = array![];
    i = 0;
    while i < n {
        let in_ok = require_on_curve(*in_c2.at(2 * i), *in_c2.at(2 * i + 1));
        let out_ok = require_on_curve(*out_c2.at(2 * i), *out_c2.at(2 * i + 1));
        if !in_ok || !out_ok {
            return false;
        }
        let in_point = match ec_decode(*in_c2.at(2 * i), *in_c2.at(2 * i + 1)) {
            Option::Some(p) => p,
            Option::None => { return false; },
        };
        let (nx, ny) = negate(*out_c2.at(2 * i), *out_c2.at(2 * i + 1));
        let neg_point = match ec_decode(nx, ny) {
            Option::Some(p) => p,
            Option::None => { return false; },
        };
        let d2 = match ec_add(in_point, neg_point) {
            Option::Some(p) => p,
            Option::None => { return false; },
        };
        let (dx, dy) = match coords(d2) {
            Option::Some(v) => v,
            Option::None => { return false; },
        };
        state = transcript_append(state, l_d2, point_compressed(dx, dy).span());
        d2s.append((dx, dy));
        i += 1;
    }
    state = transcript_append(state, l_nonce, scalar_be(nonce).span());
    let c = transcript_challenge(state, l_ch);

    // s·G − cpk − c·pk = O
    terms.append(Term { coeff: s, x: GENERATOR_X, y: GENERATOR_Y });
    terms.append(Term { coeff: fr_neg(c), x: pk_x, y: pk_y });
    terms.append(Term { coeff: fr_neg(1_u256), x: cpk_x, y: cpk_y });
    // per card: s·in_c1_i − a_i − c·d2_i = O
    i = 0;
    while i < n {
        if !require_on_curve(*in_c1.at(2 * i), *in_c1.at(2 * i + 1))
            || !require_on_curve(*a.at(2 * i), *a.at(2 * i + 1))
        {
            return false;
        }
        let (d2_x, d2_y) = *d2s.at(i);
        terms.append(Term { coeff: s, x: *in_c1.at(2 * i), y: *in_c1.at(2 * i + 1) });
        terms.append(Term { coeff: fr_neg(c), x: d2_x, y: d2_y });
        terms.append(Term { coeff: fr_neg(1_u256), x: *a.at(2 * i), y: *a.at(2 * i + 1) });
        i += 1;
    }
    true
}

fn negate(x: u256, y: u256) -> (u256, u256) {
    (x, SECP256K1_P - y)
}

fn label(parts: Span<u8>) -> Span<u8> {
    parts
}

// ---- rho + folding + the L == O check ----

fn hand_rho(hand_id: Span<u8>, terms: Span<Term>) -> u256 {
    let mut input: Array<u8> = array![];
    let domain: Array<u8> = array![
        0x70, 0x6f, 0x6b, 0x65, 0x72, 0x2f, 0x68, 0x61, 0x6e, 0x64, 0x2d, 0x62, 0x61, 0x74,
        0x63, 0x68, 0x2f, 0x76, 0x31
    ];
    let mut d: u32 = 0;
    while d < domain.len() {
        input.append(*domain.at(d));
        d += 1;
    }
    for byte in hand_id {
        input.append(*byte);
    }
    for term in terms {
        let value: Term = *term;
        append_be(ref input, value.coeff);
        append_be(ref input, value.x);
        append_be(ref input, value.y);
    }
    challenge_mod_n(input.span())
}

/// Fold all equations with powers of rho and check `L == O`.
///
/// The identity is never materialized through the syscall: the accumulator
/// covers every term except the last, and acceptance is the coordinate
/// comparison `acc == −(λ_last · P_last)`. A syscall `add` failure (which
/// includes mid-chain cancellation A + (−A), reachable only by adversarial
/// transcripts) rejects fail-closed.
fn fold_and_check(hand_id: Span<u8>, terms: Array<Term>, eq_sizes: Array<u32>) -> bool {
    let total = terms.len();
    if total == 0 {
        return eq_sizes.len() == 0;
    }
    let rho = hand_rho(hand_id, terms.span());
    let mut rpow: u256 = 1;
    let mut eq_idx: u32 = 0;
    let mut in_eq: u32 = 0;
    let mut acc: Option<Secp256k1Point> = Option::None;
    let mut last_lambda: u256 = 0;
    let mut last_x: u256 = 0;
    let mut last_y: u256 = 0;
    let mut i: u32 = 0;
    while i < total {
        let term = *terms.at(i);
        let lambda = fr_mul(rpow, term.coeff);
        if i == total - 1 {
            last_lambda = lambda;
            last_x = term.x;
            last_y = term.y;
            break;
        }
        if lambda != 0 {
            let point = match ec_decode(term.x, term.y) {
                Option::Some(p) => p,
                Option::None => { return false; },
            };
            let scaled = match ec_mul(point, lambda) {
                Option::Some(p) => p,
                Option::None => { return false; },
            };
            acc = match acc {
                Option::None => Option::Some(scaled),
                Option::Some(a) => match ec_add(a, scaled) {
                    Option::Some(v) => Option::Some(v),
                    Option::None => { return false; },
                },
            };
        }
        in_eq += 1;
        if in_eq >= *eq_sizes.at(eq_idx) {
            in_eq = 0;
            eq_idx += 1;
            rpow = fr_mul(rpow, rho);
        }
        i += 1;
    }
    // Honest equations always end with a non-zero coefficient term
    // (s / −c / −1 mod n); a zero here is treated as malformed, fail-closed.
    if last_lambda == 0 {
        return false;
    }
    let last_point = match ec_decode(last_x, last_y) {
        Option::Some(p) => p,
        Option::None => { return false; },
    };
    let last_scaled = match ec_mul(last_point, last_lambda) {
        Option::Some(p) => p,
        Option::None => { return false; },
    };
    let (tx, ty) = match coords(last_scaled) {
        Option::Some(v) => v,
        Option::None => { return false; },
    };
    match acc {
        Option::None => false,
        Option::Some(a) => {
            let (ax, ay) = match coords(a) {
                Option::Some(v) => v,
                Option::None => { return false; },
            };
            ax == tx && ay == SECP256K1_P - ty
        }
    }
}

/// Verify a whole hand of direct-sigma proofs in one folded check.
/// Fail-closed on malformed payloads and on any off-curve point.
pub fn verify_hand_batch(hand_id: Span<u8>, payload: Span<u256>) -> bool {
    if payload.len() < 3 {
        return false;
    }
    let protocol_name: Span<u8> = hand_transcript_domain(hand_id).span();
    let n_own: u32 = match (*payload.at(0)).try_into() {
        Option::Some(v) => v,
        Option::None => { return false; },
    };
    let n_reveal: u32 = match (*payload.at(1)).try_into() {
        Option::Some(v) => v,
        Option::None => { return false; },
    };
    let n_fold: u32 = match (*payload.at(2)).try_into() {
        Option::Some(v) => v,
        Option::None => { return false; },
    };

    // First pass: walk the fold entries and pin the exact total length.
    let mut cursor: u32 = 3 + 5 * n_own + 14 * n_reveal;
    let mut f: u32 = 0;
    while f < n_fold {
        if cursor >= payload.len() {
            return false;
        }
        let n_cards: u32 = match (*payload.at(cursor)).try_into() {
            Option::Some(v) => v,
            Option::None => { return false; },
        };
        cursor += 7 + 10 * n_cards;
        f += 1;
    }
    if cursor != payload.len() {
        return false;
    }

    // Second pass: extract residuals in canonical order.
    let mut terms: Array<Term> = array![];
    let mut eq_sizes: Array<u32> = array![];
    cursor = 3;
    let mut i: u32 = 0;
    while i < n_own {
        let pk = (*payload.at(cursor), *payload.at(cursor + 1));
        let big_r = (*payload.at(cursor + 2), *payload.at(cursor + 3));
        let s = *payload.at(cursor + 4);
        if !ownership_terms(protocol_name, pk, big_r, s, ref terms) {
            return false;
        }
        eq_sizes.append(3);
        cursor += 5;
        i += 1;
    }
    i = 0;
    while i < n_reveal {
        let pk = (*payload.at(cursor), *payload.at(cursor + 1));
        let c1 = (*payload.at(cursor + 2), *payload.at(cursor + 3));
        let c2 = (*payload.at(cursor + 4), *payload.at(cursor + 5));
        let token = (*payload.at(cursor + 6), *payload.at(cursor + 7));
        let t1 = (*payload.at(cursor + 8), *payload.at(cursor + 9));
        let t2 = (*payload.at(cursor + 10), *payload.at(cursor + 11));
        let nonce = *payload.at(cursor + 12);
        let s = *payload.at(cursor + 13);
        if !reveal_terms(
            protocol_name, pk, c1, c2, token, t1, t2, nonce, s, ref terms,
        ) {
            return false;
        }
        eq_sizes.append(3);
        eq_sizes.append(3);
        cursor += 14;
        i += 1;
    }
    i = 0;
    while i < n_fold {
        let n_cards: u32 = match (*payload.at(cursor)).try_into() {
            Option::Some(v) => v,
            Option::None => { return false; },
        };
        let pk = (*payload.at(cursor + 1), *payload.at(cursor + 2));
        let cpk = (*payload.at(cursor + 3), *payload.at(cursor + 4));
        let nonce = *payload.at(cursor + 5);
        let s = *payload.at(cursor + 6);
        let base = cursor + 7;
        let in_c1 = payload.slice(base, 2 * n_cards);
        let in_c2 = payload.slice(base + 2 * n_cards, 2 * n_cards);
        let out_c1 = payload.slice(base + 4 * n_cards, 2 * n_cards);
        let out_c2 = payload.slice(base + 6 * n_cards, 2 * n_cards);
        let a = payload.slice(base + 8 * n_cards, 2 * n_cards);
        if !fold_terms(
            protocol_name, pk, cpk, nonce, s, n_cards, in_c1, in_c2, out_c1, out_c2, a,
            ref terms,
        ) {
            return false;
        }
        let mut k: u32 = 0;
        while k < 1 + n_cards {
            eq_sizes.append(3);
            k += 1;
        }
        cursor += 7 + 10 * n_cards;
        i += 1;
    }

    fold_and_check(hand_id, terms, eq_sizes)
}

#[cfg(feature: 'dual_legacy_tests')]
mod tests {
    use super::super::hand_batch::verify_hand_batch;
    use core::array::{ArrayTrait, SpanTrait};

    // Generated by poker-protocol-core/tests/hand_batch_vectors.rs:
    // 2 ownership + 1 reveal token + 1 leave DLEQ (2 cards), honest hand.
    fn hand_id() -> Array<u8> {
        array![
            0xb4, 0x15, 0x39, 0xd9, 0x7a, 0x72, 0x39, 0x60, 0x04, 0x1d, 0xde, 0x6f, 0x40, 0x46, 0x03, 0xc9, 0x36, 0xe5, 0x59, 0xcf, 0x78, 0x1a, 0xa1, 0xff, 0x7b, 0x71, 0x12, 0x05, 0x73, 0x5c, 0x7d, 0xc8
        ]
    }

    fn payload() -> Array<u256> {
        array![
            2,
            1,
            1,
            0xe893b6bfd1531b78ecfd7c39ba5b1194d97ff860d80888a23594e5a67206077e,
            0x454acdcf653c7dd410d02c5b7212efaf0899c2b68623ab03864cdbedcbe7af1e,
            0x54d2fdc58dce65546664a08130e5f74a7d5fccfb16e168211f3c667e8b05a91b,
            0xefb379900276d424c524895bc2ee58aed3385e967d077192b9373142da1dd23d,
            0x09eda62d939f8fb2e5df578426206d0a5c2e480b78ce0ed6c2692e0bbe925619,
            0x18481e889a19b0f03f7c1e924741eb49f6a5b3d1a176daf8efdccd9338d0e3d4,
            0xe3047c491ece7f81a5583223ab7c9d9a4cd36b7f6dd05d114c4d4fd88cebcc9f,
            0x1904015e15da909e3419adcea6aad7be0bd1685a2ee16484c493305e8d2f9045,
            0xf532019133867c78a906e7911fbf17156f774b903915bb6e542c2f112b7f8e7d,
            0x7ba7a9ad8c13ad54c2866738261b20bc85d4d4f7d565da7f75898cd0d4a851de,
            0x0115a7ff47c69918c434bd481f480ba962f647cd2d08f71b60d1f7650cfda25a,
            0xa499291fdb78f7de732127a8523dedada0def1db567d229a54b271794054a28b,
            0x4ab7d017949f4be93c7ca4e06a9a6ff8c7201b2f05517ea19094a73663f452d6,
            0xc3823f86b90282259dae81864769a32ff59d7748a6d6e245e7130b8db660e588,
            0xab87c0f1ec97b42557c47b6e30dd8069bbd669f07ff473dd38d6b6e8a850b2b1,
            0xf66154259e38534c23d4517d64f5124a698806878eabcc34698be9e1a7c17626,
            0xe676890d4599831075ba0182fb7adeb19990a810abae89abcbb48db2a978037b,
            0x474e24495802b59ff2e7e3dee254cea2204e3e77cb58132d1d3540eb63ba544e,
            0x45e22fd4e7aff1e92c5bb2778c466c3b84b5f642f05690a83d8e7e534a84ca0c,
            0x3634893cb63c9fcb6ba1b4d5c45aaa3c52411e5dc899d4ada49a0279ec6b1a57,
            0xeaf205e58ef8a82e0aafba26f7381d65d71e60e71aa5750d20c2f8e268d980f2,
            0x0302b300317b5a5ef63bc87a5d45658bda928211a5f598237792c2d94a11984c,
            0x0a0b7991a1d0e8064ceced9ab533c919aa5a324ee8671f54cdd0ae2c07cbb86a,
            0x64efa66a9a1bbc909b96ca3e8a38f6a7c99051cf330e0dc13fb76105e9d30387,
            2,
            0x1fbc46f1b57c18c2964c0508efd6f235dc4993931e142f50c4024424ecf915bf,
            0xcb3be79e7e8dd8f91a5a5398ca07ab65c322fac09caf7e70cee89142ba899d74,
            0x27643c3e10865508b6b8c708d056d4e24067cc1378bea5af59db7118b5b7a92a,
            0x25495f6ed0dfc3046ce80179bc7ed65f8146ddd1c43ff42f362c8112d90d929a,
            0x99c8c21994a1bbc60da46401aa2ef4d7bf0d6c27f56da529f41b09f5aef39c47,
            0xad83788a16712fb846221e93dc43986f7e24beb1d7ffbf478b659eef6850effc,
            0xbed68acd83b2364772afd90f646cc7f944430b60bf2151c68a159391de314cbf,
            0x3c4eeccb09025ff89029e2b04f8329946513d982373f1626471ee3f56a8fe97a,
            0x37d68f1915a2a6557b7be888f35553ec5bd8415d0237d9137b52ed1d1e047dad,
            0x0867bbb2b06613ab6edd9f1f32be977901f0a27eebd9bcc6e92919e2f1352289,
            0x0ae8eae1bf08c10349fd2204ae6f89b02ff22de02af5dadf7b69e4c63ef9b5ae,
            0x2045624fef957657fcc7c49d0dd939403076c584195874edf89243492988f673,
            0x8c143b33730c687a6cacaac5383a4e6c5a396447f0210d5c490ddc62d5e8c1c9,
            0x9827c964b4d5d3e429c972f78eb9a4b4351ff13273480ee1a54b4aa82c5a2d1f,
            0xbed68acd83b2364772afd90f646cc7f944430b60bf2151c68a159391de314cbf,
            0x3c4eeccb09025ff89029e2b04f8329946513d982373f1626471ee3f56a8fe97a,
            0x37d68f1915a2a6557b7be888f35553ec5bd8415d0237d9137b52ed1d1e047dad,
            0x0867bbb2b06613ab6edd9f1f32be977901f0a27eebd9bcc6e92919e2f1352289,
            0x3bd400c0ad840dc32c17c531eb56bdbd55ba70e45be10205269e238c8243bebc,
            0xb1c69fe7507026527fe8a93ffd7dc558978cc873e74fd1218f7ea8f5a5e04d97,
            0xf8067dfd2789badb95acf8b9c59e81ac8010a3bed5ab7484d841cf34aa6a3c97,
            0x4a56e997d55278a71694469fa59fca41da4ca6547426e5b09cd104ace4af1113,
            0x4e8384ba82a411d85b288749983efb8fb38b9457d6ec13fedd66e93d700a6858,
            0x8eb25e88ff04fc9679ad523d9872ba938049676e05bbdae6753a2324558f7406,
            0xa626b2add8feb693b1fc96e2ecd1eb70ab8e07478650cbfa2eaa1c2fedb5cfc1,
            0x5809d54f093b4eff9599764b0aec3014f3426dbaaa501575b2192bf45e91dd7f,
        ]
    }

    // Arrays have no at_mut in this Cairo version; tamper by copying.
    fn bumped(payload: Array<u256>, index: u32) -> Array<u256> {
        let mut out: Array<u256> = array![];
        let mut i: u32 = 0;
        while i < payload.len() {
            if i == index {
                out.append(*payload.at(i) + 1);
            } else {
                out.append(*payload.at(i));
            }
            i += 1;
        }
        out
    }

    fn flipped_id() -> Array<u8> {
        let mut out: Array<u8> = array![];
        let id = hand_id();
        let mut i: u32 = 0;
        while i < id.len() {
            if i == 0 {
                out.append(*id.at(i) ^ 1_u8);
            } else {
                out.append(*id.at(i));
            }
            i += 1;
        }
        out
    }

    #[test]

    fn honest_hand_accepts() {
        assert!(
            verify_hand_batch(hand_id().span(), payload().span()),
            "honest hand must fold to L == O"
        );
    }

    #[test]
    fn tampered_ownership_response_rejected() {
        let p = bumped(payload(), 7); // ownership[0].s + 1
        assert!(!verify_hand_batch(hand_id().span(), p.span()));
    }

    #[test]
    fn tampered_reveal_commitment_rejected() {
        let p = bumped(payload(), 21); // reveal t1_x + 1
        assert!(!verify_hand_batch(hand_id().span(), p.span()));
    }

    #[test]
    fn cross_hand_replay_rejected() {
        // Same transcript settled under a different hand instance id: every
        // transcript replays, but rho differs and the residual terms are
        // challenged for the wrong hand — the fold must be non-zero.
        assert!(!verify_hand_batch(flipped_id().span(), payload().span()));
    }

    #[test]
    fn malformed_payload_rejected() {
        let p = payload();
        // Truncated payload: length walk fails.
        assert!(!verify_hand_batch(hand_id().span(), p.span().slice(0, 30)));
        // Off-curve ownership pk.
        let q = bumped(payload(), 3);
        assert!(!verify_hand_batch(hand_id().span(), q.span()));
    }
}
