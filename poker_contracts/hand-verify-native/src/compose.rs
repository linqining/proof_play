//! Form-② composition: native statement-table AIR + Cairo EC attestation.
//!
//! The EC residual checks are attested the Cairo way — the REAL
//! `hand_verify` program runs on the Cairo VM where the EC_OP builtin puts
//! every scalar-mult schedule into the trace (EC in trace), and the vendored
//! starkware-libs/proving stack turns that into a STARK proof. This module
//! drives the `prove-hand` CLI for that half and binds both halves to one
//! claim: the native claim carries the Cairo program hash in its
//! Fiat–Shamir channel, so a table proof is only valid alongside the Cairo
//! proof of the exact same program, on the exact same (hand_binding,
//! payload).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use starknet_crypto::Felt;

use crate::air::{HandBatchClaim, KindCounts};
use crate::handbatch::{payload_digest, verify_hand};
use crate::{mint, prove};

/// Result of one composed (form-②) round trip.
#[derive(Debug, Clone)]
pub struct ComposeReport {
    pub accepted: bool,
    pub native_prove_ms: u128,
    pub native_verify_ms: u128,
    pub cairo_prove_ms: u128,
    pub cairo_ec_ops: u64,
    pub cairo_program_hash: Felt,
    pub cairo_proof_path: PathBuf,
}

fn felt_hex(f: Felt) -> String {
    format!("0x{}", f.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn default_prove_hand() -> PathBuf {
    std::env::var("HAND_VERIFY_PROVE_HAND")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(|p| p.parent())
                .expect("crate lives inside the repo")
                .join("proving-tool/target/release/prove-hand")
        })
}

#[derive(Debug)]
struct CairoSummary {
    verified: bool,
    output_true: bool,
    ec_ops: u64,
    program_hash: Felt,
}

fn parse_summary(text: &str) -> CairoSummary {
    let verified = text.contains("\"verified\": true");
    let ec_ops = text
        .split("\"ec_op_builtin\":")
        .nth(1)
        .and_then(|rest| {
            rest.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect::<String>()
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0);
    let program_hash = text
        .split("\"program_hash\": \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .map(|h| Felt::from_hex(h).expect("program hash parses"))
        .expect("program hash present");
    // Public output: the executable's return value is the last output-builtin
    // entry; verify_hand returns `true` iff every residual is the identity.
    let output_true = text.contains("\"output\": [\n        \"0x1\"")
        || text.replace([' ', '\n'], "").contains("\"output\":[\"0x1\"");
    CairoSummary { verified, output_true, ec_ops, program_hash }
}

fn run_cairo_half(
    prove_hand: &Path,
    cairo_src: &Path,
    inputs_json: &Path,
    out_dir: &Path,
    extra_args: &[&str],
) -> Result<CairoSummary, String> {
    let mut cmd = Command::new(prove_hand);
    if !extra_args.is_empty() {
        cmd.args(extra_args);
    } else {
        cmd.arg("--program").arg(cairo_src).arg("--inputs").arg(inputs_json);
    }
    cmd.arg("--out-dir").arg(out_dir);
    let output = cmd
        .output()
        .map_err(|e| format!("spawn prove-hand: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "prove-hand failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if extra_args.is_empty() {
        // The Cairo program itself must have returned true (public output).
    }
    let summary_text =
        std::fs::read_to_string(out_dir.join("summary.json")).map_err(|e| e.to_string())?;
    let mut summary = parse_summary(&summary_text);
    if extra_args.is_empty() {
        if !summary.verified {
            return Err("cairo proof did not verify".into());
        }
        if !summary.output_true {
            return Err("cairo program returned false — verification failed on this payload".into());
        }
        if summary.ec_ops == 0 {
            return Err("cairo proof contains no EC_OP instances — wrong program?".into());
        }
    }
    // Silence unused warning for the check-only path where output_true/…
    // are not inspected.
    let _ = &mut summary.output_true;
    Ok(summary)
}

/// Run one composed form-② round trip:
/// 1. mint an honest payload bound to `hand_binding`;
/// 2. host-verify it (unchanged form-① code — the EC math is still computed
///    host-side; form-② adds the attestation, it does not move the math);
/// 3. prove the Cairo hand_verify executable (EC_OP builtin — EC in trace)
///    via the prove-hand CLI and read back its program hash;
/// 4. prove the native statement-table AIR with a claim that carries the
///    Cairo program hash, and verify it;
/// 5. re-verify the Cairo proof standalone (check-only).
pub fn run_compose(
    counts: KindCounts,
    seed: u64,
    out_dir: &Path,
) -> Result<ComposeReport, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let prove_hand = default_prove_hand();
    if !prove_hand.exists() {
        return Err(format!(
            "prove-hand binary not found at {} (build it: cd proving-tool && cargo build --release)",
            prove_hand.display()
        ));
    }
    let cairo_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cairo/src/lib.cairo");

    // Same binding derivation as the recursion envelope.
    let hand_binding = crate::recurse::hand_binding(seed);
    let payload = mint::mint_hand(
        hand_binding,
        counts.n_own,
        0,
        counts.n_reveal,
        counts.n_leave,
        counts.n_recon,
        seed,
    );

    // 2. host-native verification (same code as form-①; still the thing the
    // Cairo program re-runs in-trace).
    let report = verify_hand(hand_binding, &payload).map_err(|e| format!("host verify: {e:?}"))?;
    if !report.accepted() {
        return Err("minted payload must verify".into());
    }

    // 3. Cairo form-② half: inputs JSON = [hand_binding, payload_len, words…].
    let inputs_path = out_dir.join("inputs.json");
    let mut inputs = vec![felt_hex(hand_binding), format!("0x{:x}", payload.len())];
    inputs.extend(payload.iter().map(|w| felt_hex(*w)));
    std::fs::write(&inputs_path, serde_json::to_string(&inputs).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;

    let cairo_out = out_dir.join("cairo-proof");
    let t = Instant::now();
    let summary = run_cairo_half(&prove_hand, &cairo_src, &inputs_path, &cairo_out, &[])?;
    let cairo_prove_ms = t.elapsed().as_millis();

    // 4. native statement-table half, claim-bound to the Cairo program hash.
    let claim =
        HandBatchClaim::new(hand_binding, payload_digest(&payload), counts, summary.program_hash);
    let t = Instant::now();
    let proof = prove::prove_claim(&claim)?;
    let native_prove_ms = t.elapsed().as_millis();
    let t = Instant::now();
    prove::verify_claim(&claim, &proof)?;
    let native_verify_ms = t.elapsed().as_millis();

    // Cross-binding negative: the table proof must be rejected under any
    // other EC-attestation hash (Fiat–Shamir channel binding).
    let wrong_hash = summary.program_hash - Felt::from(1u32);
    let wrong = HandBatchClaim::new(hand_binding, payload_digest(&payload), counts, wrong_hash);
    if prove::verify_stark_against(&wrong, &proof.stark_proof).is_ok() {
        return Err("claim must be bound to the cairo program hash".into());
    }

    // 5. standalone Cairo re-verification (the L1 half that does not need
    // the spike at all).
    let proof_path = cairo_out.join("proof.json");
    run_cairo_half(
        &prove_hand,
        &cairo_src,
        &inputs_path,
        &cairo_out,
        &["--check-only", "--proof", proof_path.to_str().expect("utf8 path")],
    )?;

    Ok(ComposeReport {
        accepted: true,
        native_prove_ms,
        native_verify_ms,
        cairo_prove_ms,
        cairo_ec_ops: summary.ec_ops,
        cairo_program_hash: summary.program_hash,
        cairo_proof_path: proof_path,
    })
}
