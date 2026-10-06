//! One-off cross-end parity check: compute the same golden transcript
//! vectors with the MAIN project's `poker-protocol-core` and print them for
//! comparison against hand-verify-native's `vectors` output.

use crypto_bigint::U256;
use crypto_bigint::Encoding;
use poker_protocol_core::stark_curve::{
    handbatch_endorsement_challenge, handbatch_leave_challenge, handbatch_reconstruct_challenge,
    handbatch_reveal_challenge, handbatch_rho, HandBatchEquationWords, HandLeaveCardWords,
    StarkCurve, StarkPoint, StarkScalar,
};
use poker_protocol_core::Curve;

fn scalar(v: u64) -> StarkScalar {
    StarkScalar::from_u256(U256::from(v)).unwrap()
}

fn hb_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = 0x6d;
    b[30] = 0xb1;
    b
}

fn scalar_bytes(s: &StarkScalar) -> [u8; 32] {
    s.to_u256().to_be_bytes()
}

fn print_scalar(name: &str, s: &StarkScalar) {
    println!("{name}: 0x{}", scalar_bytes(s).iter().map(|b| format!("{b:02x}")).collect::<String>());
}

fn main() {
    let hb = hb_bytes();
    let g = StarkCurve::base_g();
    let p2 = g * scalar(2);
    let p3 = g * scalar(3);
    let p4 = g * scalar(4);
    let p5 = g * scalar(5);
    let p6 = g * scalar(6);
    let p7 = g * scalar(7);

    let c_own = handbatch_endorsement_challenge(&hb, &g, &p2, &p3);
    let c_rev = handbatch_reveal_challenge(
        &hb, &p2, &p3, &p4, &p5, &p6, &p7, &scalar(8),
    );
    let card = HandLeaveCardWords { in_c1: p2, in_c2: p3, out_c1: p4, out_c2: p5, a: p6 };
    let c_leave = handbatch_leave_challenge(&hb, &p2, &p3, &scalar(8), &[card]);
    let c_recon = handbatch_reconstruct_challenge(&hb, &g, &p2, &p3, &p4, &p5, &p6);

    let rho_words = [
        HandBatchEquationWords { kind: 1, s: scalar_bytes(&scalar(11)), c: scalar_bytes(&c_own) },
        HandBatchEquationWords { kind: 2, s: scalar_bytes(&scalar(12)), c: scalar_bytes(&c_rev) },
        HandBatchEquationWords { kind: 4, s: scalar_bytes(&scalar(13)), c: scalar_bytes(&c_recon) },
    ];
    let rho = handbatch_rho(&hb, &rho_words);

    print_scalar("endorsement_challenge", &c_own);
    print_scalar("reveal_challenge", &c_rev);
    print_scalar("leave_challenge", &c_leave);
    print_scalar("reconstruct_challenge", &c_recon);
    print_scalar("hand_rho", &rho);
}
