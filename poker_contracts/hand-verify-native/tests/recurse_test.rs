//! Cairo-route recursion envelope test (form-③) — the recursive proof chain
//! plus its negative corpus.
//!
//! Heavy (each prove spawns the real Cairo pipeline, ~5–20 s per layer):
//! `#[ignore]`-gated. Run with:
//!   cargo test --release --test recurse_test -- --ignored --nocapture
//! Requires the prove-hand binary (built once):
//!   cd proving-tool && cargo build --release
//! The binary location can be overridden with HAND_VERIFY_PROVE_HAND.
#![cfg(not(debug_assertions))]

use std::path::PathBuf;

use hand_verify_native::air::KindCounts;
use hand_verify_native::recurse::{
    self, fold_accumulator, host_fold_tasks, mint_tasks, prove_layer, write_prod_params,
    GENESIS_ACC,
};

fn two_player() -> KindCounts {
    KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 }
}

fn out_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("output/recurse-test").join(tag);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

/// One honest envelope layer: the Cairo program's public accumulator must
/// equal the host-side fold (formula parity), and the proof must re-verify
/// standalone.
#[test]
#[ignore]
fn recursion_single_layer_parity() {
    let params = write_prod_params(&out_dir("params")).expect("params");
    let tasks = mint_tasks(two_player(), 2, 2, 1501);
    let expected = host_fold_tasks(&tasks, GENESIS_ACC).expect("host fold");
    let outcome =
        prove_layer(GENESIS_ACC, &tasks, expected, &out_dir("single"), Some(&params))
            .expect("envelope layer");
    assert_eq!(outcome.cairo_acc, expected, "parity gate");
    assert!(outcome.ec_ops > 0, "EC must be in the cairo trace");
    assert!(outcome.proof_bytes > 0);
}

/// The recursion chain: layer 1 consumes layer 0's public accumulator as its
/// prev_acc; the final public output equals the host-side chain fold.
#[test]
#[ignore]
fn recursion_chain_two_layers() {
    let params = write_prod_params(&out_dir("params")).expect("params");
    let report =
        recurse::run_recursion(two_player(), 2, 2, 2, 1511, &out_dir("chain"), Some(&params))
            .expect("recursion chain");
    assert_eq!(report.layers.len(), 2);
    // Layer 1's prev_acc is layer 0's public output (the chain is real).
    assert_eq!(report.layers[1].prev_acc, report.layers[0].cairo_acc);
    // And the final accumulator matches the host-side chain fold.
    assert_eq!(report.layers[1].cairo_acc, report.host_chain_acc);
    // Genesis anchor: layer 0 starts from the shared constant.
    assert_eq!(report.layers[0].prev_acc, GENESIS_ACC);
}

/// Tampered task (ownership s +1) must panic inside the envelope — the batch
/// produces no proof at all (fail-closed).
#[test]
#[ignore]
fn recursion_rejects_tampered_task() {
    let params = write_prod_params(&out_dir("params")).expect("params");
    recurse::run_negative_tampered_task(two_player(), 1521, &out_dir("neg-tampered"), Some(&params))
        .expect("tampered batch must be rejected");
}

/// A forged prev_acc (cross-layer splice) proves successfully against ITS OWN
/// input, but its public accumulator diverges from the honest chain fold —
/// the parity gate must reject it.
#[test]
#[ignore]
fn recursion_rejects_forged_prev_acc() {
    let params = write_prod_params(&out_dir("params")).expect("params");
    recurse::run_negative_wrong_prev(two_player(), 1522, &out_dir("neg-prev"), Some(&params))
        .expect("forged prev_acc must be caught");
}

/// Production shape (snip36 settlement, texas `recursion_prover::prove_batch_blocking`):
/// the recursive batch is action-sig-only — one statement per participant.
/// Times the full `prove_payload_layer` path (host verify → prove-hand →
/// parity gate → check-only) for a 2-seat and a full 9-seat table. Loose
/// upper bound only guards against order-of-magnitude regressions; the 3 s
/// goal line was validated on M3 Pro (2026-09-27, with exec compile cache).
#[test]
#[ignore]
fn recursion_prod_shape_action_sig_batch() {
    use hand_verify_native::curve::Point;
    use hand_verify_native::handbatch::{action_sig_challenge_raw, ascii_felt_pub};
    use hand_verify_native::recurse::{
        build_action_batch_payload, prove_payload_layer, ActionSigStatement, GENESIS_ACC,
    };
    use poker_protocol_core::curve::CurveScalar;
    use poker_protocol_core::stark_curve::StarkScalar;
    use starknet_crypto::Felt;
    use std::time::{Duration, Instant};

    let to_scalar =
        |f: Felt| <StarkScalar as CurveScalar>::from_bytes_mod_order(&f.to_bytes_be());
    let hex_fe = |f: Felt| -> String {
        let mut s = String::from("0x");
        for b in f.to_bytes_be() {
            s += &format!("{b:02x}");
        }
        s
    };

    // One honest action-sig statement (same algebra as mint.rs `mint_action`,
    // expressed against the public API): pk = sk·G, R = w·G,
    // c = challenge(pk, R, ...), s = (w + c·sk) mod n.
    let statement = |i: u64| -> ActionSigStatement {
        let g = Point::generator();
        let sk = Felt::from(101 + i);
        let pk = g.mul(sk);
        let w = Felt::from(1009 + 7 * i);
        let r = g.mul(w);
        let table_id = 7u32;
        let hand_id = 9u32;
        let seq = 100u64 + i;
        let action = "bet";
        let amount = 50u64;
        let c = action_sig_challenge_raw(
            table_id as u64,
            hand_id as u64,
            seq,
            ascii_felt_pub(action),
            amount,
            r,
        );
        let s = to_scalar(w) + to_scalar(c) * to_scalar(sk);
        let s_felt = Felt::from_bytes_be(&s.to_bytes_be());
        let (pkx, pky) = pk.to_affine().expect("pk affine");
        let (rx, ry) = r.to_affine().expect("R affine");
        ActionSigStatement {
            pk_x_hex: hex_fe(pkx),
            pk_y_hex: hex_fe(pky),
            r_x_hex: hex_fe(rx),
            r_y_hex: hex_fe(ry),
            s_hex: hex_fe(s_felt),
            table_id,
            hand_id,
            seq,
            action: action.into(),
            amount,
        }
    };

    let params = write_prod_params(&out_dir("params")).expect("params");
    for seats in [2usize, 9] {
        let statements: Vec<_> = (0..seats as u64).map(statement).collect();
        let hb = Felt::from(0x9_5EED_u64);
        let payload =
            build_action_batch_payload(hb, 7, 9, &statements).expect("payload build");
        let t = Instant::now();
        let (acc, outcome) = prove_payload_layer(
            hb,
            payload,
            GENESIS_ACC,
            &out_dir(&format!("prod-shape-{seats}")),
            Some(&params),
        )
        .expect("envelope layer");
        let elapsed = t.elapsed();
        assert_eq!(acc, outcome.expected_acc, "parity gate");
        assert!(outcome.ec_ops > 0, "EC must be in the cairo trace");
        println!(
            "| action-sig batch | {seats} statements | steps {} | EC_OP {} | total {} ms \
             (compile {} / run {} / prove {}) | reverify {} ms |",
            outcome.steps,
            outcome.ec_ops,
            outcome.total_ms,
            outcome.cairo_compile_ms,
            outcome.cairo_run_ms,
            outcome.cairo_prove_ms,
            outcome.check_verify_ms,
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "order-of-magnitude regression: {elapsed:?}"
        );
    }
}

/// The accumulator fold is order- and content-sensitive (sanity on the host
/// mirror itself, cheap — no proving involved).
#[test]
fn recursion_fold_accumulator_sensitivity() {
    let a = starknet_crypto::Felt::from(11u32);
    let b = starknet_crypto::Felt::from(22u32);
    assert_ne!(fold_accumulator(GENESIS_ACC, &[a, b]), fold_accumulator(GENESIS_ACC, &[b, a]));
    assert_ne!(fold_accumulator(GENESIS_ACC, &[a]), fold_accumulator(a, &[GENESIS_ACC]));
    // The empty batch folds to poseidon([prev_acc]) on both sides — the host
    // mirror matches the Cairo formula even at degenerate inputs.
    let empty = starknet_crypto::poseidon_hash_many(&[GENESIS_ACC]);
    assert_eq!(
        fold_accumulator(GENESIS_ACC, &[]).to_bytes_be(),
        empty.to_bytes_be()
    );
}
