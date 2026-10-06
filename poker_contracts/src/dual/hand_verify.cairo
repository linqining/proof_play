//! # hand_verify — provable full-hand verifier (Phase 1, Plan D layer 2)
//!
//! A **standalone Cairo program** (not a contract) that verifies an entire
//! hand's sigma-proof batch: ownership endorsements, reveal tokens,
//! leave/remask DLEQ, CP-DLEQ reconstruct and Bayer–Groth V2 shuffle
//! proofs (all direct residual checks — no Horner fold needed inside a
//! program; see `HAND_SHUFFLE_STATUS`).
//!
//! ## Why a program
//!
//! The linear-batch contract (`hand_batch_stark.cairo`) pays O(equations)
//! on-chain gas. This program does the same verification off-chain and is
//! proven by Stone/Stwo-Cairo (felt252 is the Cairo VM's native field —
//! the STARK curve's base field — so EC ops ride the EC_OP builtin and
//! Poseidon rides its builtin). On-chain cost becomes the constant cost of
//! verifying one STARK proof (Integrity contract path; SNIP-36 whitelist
//! applied for separately).
//!
//! ## Soundness
//!
//! Inside a STARK there is no need to compress N zero-tests into one
//! (Horner/fold): each residual is checked directly against the identity.
//! That is the ρ→∞ limiting case of the batch fold — strictly simpler,
//! trivially sound, same inner-protocol assumptions (DLP + ROM + BG
//! Pedersen binding). The challenge formulas are the **handbatch foldable
//! epoch** (felt-direct Poseidon; byte-identical to the Rust core
//! canonical `handbatch_*_challenge` / contract replay).
//!
//! ## Payload (identical wire format to hand_batch_stark)
//!
//! ```text
//! [n_own, n_shuffle, n_reveal, n_leave, n_recon, n_action,
//!  ownership × n_own:     [pk 2, R 2, s],
//!  shuffle   × n_shuffle: BG bucket (11n+31 words, deck n=52 — see
//!                         dual::bg_stark for the layout; residuals and
//!                         scalar checks verified directly),
//!  reveal    × n_reveal:  [pk 2, c1 2, c2 2, token 2, t1 2, t2 2, nonce, s],
//!  leave     × n_leave:   [n, pk 2, cpk 2, nonce, s,
//!                          in_c1 2n, in_c2 2n, out_c1 2n, out_c2 2n, a 2n],
//!  recon     × n_recon:   [g1 2, g2 2, p1 2, p2 2, A 2, B 2, s],
//!  action    × n_action:  [pk 2, R 2, s, table_id, hand_id, seq,
//!                           action_felt, amount]]  (v3 felt-domain)
//! ```
//!
//! ## Status
//!
//! - own/reveal/leave/recon: complete, corpus-verified (see tests).
//! - shuffle: BG port active — `n_shuffle > 0` is verified via
//!   `dual::bg_stark` (pinned CK n=52, transcript replay, direct
//!   residual + scalar checks).

use core::array::{ArrayTrait, SpanTrait};
use core::ec::{EcPoint, EcPointTrait, EcStateTrait, NonZeroEcPoint};
use core::option::Option;
use core::panic_with_felt252;
use core::poseidon::poseidon_hash_span;
use core::traits::TryInto;

use super::bg_stark;
use super::bg_stark::BG_DECK_SIZE;
use super::hand_batch_stark::{
    felt_to_u256, leave_equations, ownership_equation, reconstruct_equations, reveal_equations,
    GENERATOR_X, GENERATOR_Y,
};

/// Shuffle bucket support level for this build.
pub const HAND_SHUFFLE_STATUS: felt252 = 'BG_PORT_ACTIVE';

/// Verify a full hand batch (program form). Same wire format and semantics
/// as `hand_batch_stark::verify_hand_batch_stark`, expressed as a
/// standalone program for STARK proving.
///
/// Returns `true` iff every equation residual is the identity point.
pub fn verify_hand(hand_binding: felt252, payload: Span<felt252>) -> bool {
    if payload.len() < 5 {
        panic_with_felt252('F01');
    }
    let n_own = felt_to_u256(*payload.at(0));
    let n_shuffle = felt_to_u256(*payload.at(1));
    let n_reveal = felt_to_u256(*payload.at(2));
    let n_leave = felt_to_u256(*payload.at(3));
    let n_recon = felt_to_u256(*payload.at(4));
    let n_action = felt_to_u256(*payload.at(5));
    let n_own_u32: u32 = match n_own.try_into() {
        Option::Some(v) => v,
        Option::None => { panic_with_felt252('F02'); },
    };
    let n_shuffle_u32: u32 = match n_shuffle.try_into() {
        Option::Some(v) => v,
        Option::None => { panic_with_felt252('F03'); },
    };
    let n_reveal_u32: u32 = match n_reveal.try_into() {
        Option::Some(v) => v,
        Option::None => { panic_with_felt252('F04'); },
    };
    let n_leave_u32: u32 = match n_leave.try_into() {
        Option::Some(v) => v,
        Option::None => { panic_with_felt252('F05'); },
    };
    let n_recon_u32: u32 = match n_recon.try_into() {
        Option::Some(v) => v,
        Option::None => { panic_with_felt252('F06'); },
    };
    let n_action_u32: u32 = match n_action.try_into() {
        Option::Some(v) => v,
        Option::None => { panic_with_felt252('F07'); },
    };
    if payload.len() < 6 + 5 * n_own_u32 + 14 * n_reveal_u32 + 13 * n_recon_u32
        + 10 * n_action_u32 {
        panic_with_felt252('F08');
    }

    // Residual checks per statement — direct (no fold: this is a program,
    // each zero-test is a felt comparison).
    let mut cursor: u32 = 6;

    // ---- ownership: s·G − c·pk − R == O ----
    let mut i: u32 = 0;
    while i < n_own_u32 {
        let (eq, _words) = match ownership_equation(
            hand_binding,
            (*payload.at(cursor), *payload.at(cursor + 1)),
            (*payload.at(cursor + 2), *payload.at(cursor + 3)),
            *payload.at(cursor + 4),
        ) {
            Option::Some(v) => v,
            Option::None => { panic_with_felt252('F09'); }, // off-curve / malformed
        };
        if !residual_is_identity(eq) {
            panic_with_felt252('F10');
        }
        cursor += 5;
        i += 1;
    }

    // ---- shuffle: BG equations == O (direct) + scalar checks ----
    i = 0;
    while i < n_shuffle_u32 {
        let bucket_len: u32 = 11 * BG_DECK_SIZE + 31;
        if payload.len() < cursor + bucket_len {
            panic_with_felt252('F11');
        }
        if felt_to_u256(*payload.at(cursor)) != (BG_DECK_SIZE.into()) {
            panic_with_felt252('F12'); // CK pinned for n=52 only
        }
        let (bg_eqs, _ch, scalars_ok) = match bg_stark::bg_equations(
            payload.slice(cursor, bucket_len),
        ) {
            Option::Some(v) => v,
            Option::None => { panic_with_felt252('F13'); },
        };
        if !scalars_ok {
            panic_with_felt252('F14');
        }
        let mut k: u32 = 0;
        while k < bg_eqs.len() {
            if !residual_is_identity(*bg_eqs.at(k)) {
                panic_with_felt252('F15');
            }
            k += 1;
        }
        cursor += bucket_len;
        i += 1;
    }

    // ---- reveal: eq1, eq2 == O ----
    i = 0;
    while i < n_reveal_u32 { // DIAG: reveal enabled
        let ((eq1, eq2), _w) = match reveal_equations(
            hand_binding,
            (*payload.at(cursor), *payload.at(cursor + 1)),
            (*payload.at(cursor + 2), *payload.at(cursor + 3)),
            (*payload.at(cursor + 4), *payload.at(cursor + 5)),
            (*payload.at(cursor + 6), *payload.at(cursor + 7)),
            (*payload.at(cursor + 8), *payload.at(cursor + 9)),
            (*payload.at(cursor + 10), *payload.at(cursor + 11)),
            *payload.at(cursor + 12),
            *payload.at(cursor + 13),
        ) {
            Option::Some(v) => v,
            Option::None => { panic_with_felt252('F16'); },
        };
        if !residual_is_identity(eq1) || !residual_is_identity(eq2) {
            panic_with_felt252('F17');
        }
        cursor += 14;
        i += 1;
    }

    // ---- leave: eq0 + per-card == O ----
    i = 0;
    while i < n_leave_u32 { // DIAG: leave enabled
        let n_cards_f = felt_to_u256(*payload.at(cursor));
        let n_cards: u32 = match n_cards_f.try_into() {
            Option::Some(v) => v,
            Option::None => { panic_with_felt252('F18'); },
        };
        if payload.len() < cursor + 7 + 10 * n_cards {
            panic_with_felt252('F19');
        }
        let base = cursor + 7;
        let (eqs, _w) = match leave_equations(
            hand_binding,
            (*payload.at(cursor + 1), *payload.at(cursor + 2)),
            (*payload.at(cursor + 3), *payload.at(cursor + 4)),
            *payload.at(cursor + 5),
            *payload.at(cursor + 6),
            payload.slice(base, 2 * n_cards),
            payload.slice(base + 2 * n_cards, 2 * n_cards),
            payload.slice(base + 4 * n_cards, 2 * n_cards),
            payload.slice(base + 6 * n_cards, 2 * n_cards),
            payload.slice(base + 8 * n_cards, 2 * n_cards),
        ) {
            Option::Some(v) => v,
            Option::None => { panic_with_felt252('F20'); },
        };
        let mut k: u32 = 0;
        while k < eqs.len() {
            if !residual_is_identity(*eqs.at(k)) {
                panic_with_felt252('F21');
            }
            k += 1;
        }
        cursor += 7 + 10 * n_cards;
        i += 1;
    }

    // ---- recon: eq1, eq2 == O (CP-DLEQ, kind=4) ----
    i = 0;
    while i < n_recon_u32 { // DIAG: recon enabled
        let ((eq1, eq2), _w) = match reconstruct_equations(
            hand_binding,
            (*payload.at(cursor), *payload.at(cursor + 1)),
            (*payload.at(cursor + 2), *payload.at(cursor + 3)),
            (*payload.at(cursor + 4), *payload.at(cursor + 5)),
            (*payload.at(cursor + 6), *payload.at(cursor + 7)),
            (*payload.at(cursor + 8), *payload.at(cursor + 9)),
            (*payload.at(cursor + 10), *payload.at(cursor + 11)),
            *payload.at(cursor + 12),
        ) {
            Option::Some(v) => v,
            Option::None => { panic_with_felt252('F22'); },
        };
        if !residual_is_identity(eq1) || !residual_is_identity(eq2) {
            panic_with_felt252('F23');
        }
        cursor += 13;
        i += 1;
    }

    // ---- action sig: eq = s·G − R − c·pk == O (v3 felt-domain, kind=5) ----
    // c = poseidon([label, table_id, hand_id, seq, action_felt, amount,
    //               R_x, R_y]) — RAW (< P), no mod-n reduction (group order
    // makes it a no-op; same discipline as ownership_equation). Label =
    // short-string felt 'zgame.action-sig.v3' — byte-identical to the Rust
    // host's `action_sig_challenge_raw` (parity test pinned cross-crate).
    i = 0;
    while i < n_action_u32 { // DIAG: action enabled
        let pk_point = match EcPointTrait::new(
            *payload.at(cursor), *payload.at(cursor + 1),
        ) {
            Option::Some(p) => p,
            Option::None => { panic_with_felt252('F24'); },
        };
        let r_point = match EcPointTrait::new(
            *payload.at(cursor + 2), *payload.at(cursor + 3),
        ) {
            Option::Some(p) => p,
            Option::None => { panic_with_felt252('F25'); },
        };
        let s = *payload.at(cursor + 4);
        let c_input: Array<felt252> = array![
            'zgame.action-sig.v3',
            *payload.at(cursor + 5),
            *payload.at(cursor + 6),
            *payload.at(cursor + 7),
            *payload.at(cursor + 8),
            *payload.at(cursor + 9),
            *payload.at(cursor + 2),
            *payload.at(cursor + 3),
        ];
        let c = poseidon_hash_span(c_input.span());

        let g_nz: NonZeroEcPoint = EcPointTrait::new(GENERATOR_X, GENERATOR_Y)
            .unwrap()
            .try_into()
            .unwrap();
        let r_neg_nz: NonZeroEcPoint = match (-r_point).try_into() {
            Option::Some(nz) => nz,
            Option::None => { panic_with_felt252('F26'); },
        };
        let pk_neg_nz: NonZeroEcPoint = match (-pk_point).try_into() {
            Option::Some(nz) => nz,
            Option::None => { panic_with_felt252('F27'); },
        };
        let mut state = EcStateTrait::init();
        state.add_mul(s, g_nz);
        state.add_mul(c, pk_neg_nz);
        state.add(r_neg_nz);
        if !residual_is_identity(state.finalize()) {
            return false;
        }
        cursor += 10;
        i += 1;
    }

    true
}

/// A residual is accepted iff it is the group identity.
fn residual_is_identity(p: EcPoint) -> bool {
    let nz: Option<NonZeroEcPoint> = p.try_into();
    nz.is_none()
}

// ============================================================
// Corpus classification tests — the program must agree with
// hand_batch_stark on every vector in the shared corpus
// (Phase 1 exit criterion: dual-run consistency).
//
// v3 wire notes (vs. the shared hand_batch_stark corpus helpers, which are
// still 5-class): the header has SIX slots — `n_action` sits at slot 5 and
// every corpus word shifts right by one. `v3()` re-frames a 5-class corpus
// payload with n_action = 0; tamper indices >= 5 shift by +1 after the
// re-frame. Malformed/tampered inputs panic (`panic_with_felt252` — a
// panicking Cairo run produces no proof, the fail-closed program
// semantics); the only `false`-returning path left is a non-identity
// action-sig residual.
// ============================================================

#[cfg(target: 'test')]
mod tests {
    use super::super::hand_verify::verify_hand;
    use super::super::bg_stark::tests::{bg_bucket, BGV_BINDING};
    use super::super::hand_batch_stark::tests::{
        payload, payload_n4, full_hand_payload_n2, full_hand_payload_n9,
        leave_only_payload, recon_payload, full_payload_5bucket,
        FULL_HAND_BINDING, HAND_BINDING, bumped, flipped_binding,
    };
    use super::super::hand_batch_stark::{
        felt_to_u256, fr_mul, u256_to_felt, GENERATOR_X, GENERATOR_Y, STARK_N,
    };
    use core::array::{ArrayTrait, SpanTrait};
    use core::ec::{ec_point_unwrap, EcPointTrait, EcStateTrait, NonZeroEcPoint};
    use core::poseidon::poseidon_hash_span;
    use core::traits::TryInto;

    /// Re-frame a 5-class corpus payload on the v3 wire: insert
    /// `n_action = 0` at slot 5 (later words shift right by one).
    fn v3(p: Array<felt252>) -> Array<felt252> {
        let mut q: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < p.len() {
            if i == 5 {
                q.append(0);
            }
            q.append(*p.at(i));
            i += 1;
        }
        q
    }

    #[test]
    fn program_accepts_honest_n2() {
        assert!(verify_hand(HAND_BINDING, v3(payload()).span()), "program: honest n2");
    }

    #[test]
    fn program_accepts_honest_n4() {
        assert!(verify_hand(HAND_BINDING, v3(payload_n4()).span()), "program: honest n4");
    }

    #[test]
    fn program_accepts_leave_only() {
        assert!(verify_hand(FULL_HAND_BINDING, v3(leave_only_payload()).span()), "program: leave-only");
    }

    #[test]
    fn program_accepts_full_hand_n2() {
        assert!(verify_hand(FULL_HAND_BINDING, v3(full_hand_payload_n2()).span()), "program: full hand n2");
    }

    #[test]
    fn program_accepts_full_hand_n9() {
        assert!(verify_hand(FULL_HAND_BINDING, v3(full_hand_payload_n9()).span()), "program: full hand n9");
    }

    // ---- tamper corpus: every mutation the contract rejects, the program
    // must reject too (dual-run consistency, Phase 1 soundness gate).
    // v3 semantics: tampered residuals panic (fail-closed — no proof
    // exists for a rejected batch), so the corpus asserts the panic. ----

    #[test]
    #[should_panic]
    fn program_rejects_tampered_ownership_s() {
        // word 7 on the 5-class wire = own[0].R_x → slot 8 after the re-frame
        let p = bumped(v3(payload()), 8);
        verify_hand(HAND_BINDING, p.span());
    }

    #[test]
    #[should_panic]
    fn program_rejects_tampered_pk() {
        // ownership[1].pk_x + 1（word 10，与合约测试同款变异；re-frame 后 11）
        let p = bumped(v3(payload()), 11);
        verify_hand(HAND_BINDING, p.span());
    }

    #[test]
    #[should_panic]
    fn program_rejects_cross_hand_replay() {
        verify_hand(flipped_binding(), v3(payload()).span());
    }

    #[test]
    #[should_panic]
    fn program_rejects_malformed_truncated() {
        let p = v3(payload());
        verify_hand(HAND_BINDING, p.span().slice(0, 8));
    }

    #[test]
    #[should_panic]
    fn program_rejects_reserved_slot_nonzero() {
        // n_shuffle := 1 with no BG bucket behind it (slot 1, header-internal)
        let mut q: Array<felt252> = array![];
        let p = payload();
        let mut i: u32 = 0;
        while i < p.len() {
            if i == 1 {
                q.append(1);
            } else {
                q.append(*p.at(i));
            }
            i += 1;
        }
        verify_hand(HAND_BINDING, v3(q).span());
    }

    #[test]
    fn program_accepts_honest_shuffle_bucket() {
        // v3 header [0,1,0,0,0,0] + the honest n=52 BG bucket
        let bucket = bg_bucket();
        let mut q: Array<felt252> = array![0, 1, 0, 0, 0, 0];
        let mut i: u32 = 0;
        while i < bucket.len() {
            q.append(*bucket.at(i));
            i += 1;
        }
        assert!(verify_hand(BGV_BINDING, q.span()), "program: honest BG shuffle");
    }

    #[test]
    #[should_panic]
    fn program_rejects_tampered_shuffle_bucket() {
        // bump beta (bucket word 494)
        let bucket = bg_bucket();
        let mut q: Array<felt252> = array![0, 1, 0, 0, 0, 0];
        let mut i: u32 = 0;
        while i < bucket.len() {
            if i == 494 {
                q.append(*bucket.at(i) + 1);
            } else {
                q.append(*bucket.at(i));
            }
            i += 1;
        }
        verify_hand(BGV_BINDING, q.span());
    }

    #[test]
    fn program_accepts_honest_recon() {
        assert!(verify_hand(BGV_BINDING, v3(recon_payload()).span()), "program: honest CP-DLEQ");
    }

    #[test]
    #[should_panic]
    fn program_rejects_tampered_recon() {
        // word 17 on the 5-class wire → slot 18 after the re-frame
        let p = bumped(v3(recon_payload()), 18);
        verify_hand(BGV_BINDING, p.span());
    }

    #[test]
    fn program_accepts_full_5bucket() {
        assert!(verify_hand(BGV_BINDING, v3(full_payload_5bucket()).span()));
    }

    #[test]
    #[should_panic]
    fn program_rejects_full_5bucket_tamper() {
        // bump a response word inside the shuffle bucket (beta; word 504 on
        // the 5-class wire → slot 505 after the re-frame)
        let p = bumped(v3(full_payload_5bucket()), 505);
        verify_hand(BGV_BINDING, p.span());
    }

    #[test]
    #[should_panic]
    fn program_rejects_full_hand_tamper_n2() {
        let p = v3(full_hand_payload_n2());
        let last: u32 = (p.len() - 1).try_into().unwrap();
        let bumped_p = bumped(p, last);
        verify_hand(FULL_HAND_BINDING, bumped_p.span());
    }

    #[test]
    #[should_panic]
    fn program_rejects_full_hand_tamper_n9() {
        let p = v3(full_hand_payload_n9());
        let last: u32 = (p.len() - 1).try_into().unwrap();
        let bumped_p = bumped(p, last);
        verify_hand(FULL_HAND_BINDING, bumped_p.span());
    }

    // ---- v3 action-sig (kind=5): built in-test with the same EC/poseidon
    // primitives the verifier replays — pk = x·G, R = k·G,
    // c = poseidon([label, table_id, hand_id, seq, action_felt, amount,
    // R_x, R_y]) raw (< P), s = k + c·x mod n. ----

    fn action_sig_payload() -> Array<felt252> {
        let g_nz: NonZeroEcPoint = EcPointTrait::new(GENERATOR_X, GENERATOR_Y)
            .unwrap()
            .try_into()
            .unwrap();
        let x: u256 = 0x102030405060708090a0b0c0d0e0f101; // privkey scalar
        let k: u256 = 0x1f1e1d1c1b1a19181716151413121110; // nonce scalar
        let mut st = EcStateTrait::init();
        st.add_mul(u256_to_felt(x).unwrap(), g_nz);
        let pk_nz: NonZeroEcPoint = st.finalize().try_into().unwrap();
        let (pk_x, pk_y) = ec_point_unwrap(pk_nz);
        let mut st2 = EcStateTrait::init();
        st2.add_mul(u256_to_felt(k).unwrap(), g_nz);
        let r_nz: NonZeroEcPoint = st2.finalize().try_into().unwrap();
        let (r_x, r_y) = ec_point_unwrap(r_nz);
        let c = poseidon_hash_span(
            array![
                'zgame.action-sig.v3', 7, 8, 9, 0x21, 1000, r_x, r_y,
            ].span(),
        );
        let m = fr_mul(felt_to_u256(c), x); // c·x mod n (c < P < 2^252: lossless u256)
        let sum = k + m; // < 2n < 2^253: no u256 overflow
        let s = if sum >= STARK_N { sum - STARK_N } else { sum };
        array![
            0, 0, 0, 0, 0, 1, // v3 header: n_action = 1
            pk_x, pk_y, r_x, r_y, u256_to_felt(s).unwrap(), // action item
            7, 8, 9, 0x21, 1000, // table_id, hand_id, seq, action_felt, amount
        ]
    }

    #[test]
    fn program_accepts_action_sig_v3() {
        assert!(verify_hand(HAND_BINDING, action_sig_payload().span()), "program: action-sig v3");
    }

    #[test]
    fn program_rejects_tampered_action_sig() {
        // s + 1 (payload word 10 = header 6 + s offset 4): the action
        // residual is non-identity — v3's only false-returning path.
        let p = bumped(action_sig_payload(), 10);
        assert!(!verify_hand(HAND_BINDING, p.span()));
    }
}
