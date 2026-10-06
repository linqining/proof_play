//! wrap-proof —— 输入 JSON → Groth16 证明 JSON。
//!
//! 用法：
//! ```text
//! cargo run -p groth16-wrap --bin wrap-proof -- <input.json> [--out proof.json]
//! ```
//! 输入 JSON：
//! ```json
//! {
//!   "program_hash": "0x…",
//!   "hand_binding": "0x…",
//!   "output": ["0x…"; 16]
//! }
//! ```
//! 流程：形状校验 → 宿主重算 fact（与 fact-verify 同式）→ 固定种子 setup →
//! prove → 本地 verify（必须通过，否则报错退出）→ 写出证明 JSON（含 EVM
//! calldata 顺序的 b_evm 与 SettleWrap.settle 的 calldata）。
//!
//! trusted setup 为固定种子单方仪式（测试网口径，见 lib.rs）。

use anyhow::{Context, Result};
use groth16_wrap::felt::{felt_from_hex, felt_to_fr, felt_to_hex};
use groth16_wrap::wrap_circuit::{WrapCircuit, WrapStatement, WrapWitness};
use groth16_wrap::{prove_with_pk, seeded_setup, verify_with_vk, Felt252};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct InputJson {
    program_hash: String,
    hand_binding: String,
    output: Vec<String>,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: wrap-proof <input.json> [--out proof.json]");
        std::process::exit(2);
    }
    let input_path = PathBuf::from(&args[1]);
    let out_path = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| input_path.with_file_name("wrap_proof.json"));

    let input: InputJson =
        serde_json::from_str(&std::fs::read_to_string(&input_path).context("read input")?)
            .context("parse input json")?;

    let program_hash = felt_from_hex(&input.program_hash)?;
    let hand_binding = felt_from_hex(&input.hand_binding)?;
    let output: Vec<Felt252> = input.output.iter().map(|h| felt_from_hex(h)).collect::<Result<_, _>>()?;
    let witness = WrapWitness { output };
    witness
        .validate()
        .map_err(|e| anyhow::anyhow!("witness invalid: {e}"))?;

    // fact 宿主重算（与 fact-verify `fact_for_output` 同式——同一 starknet-crypto）
    let fact = witness.expected_fact(&program_hash);
    let statement = WrapStatement {
        program_hash: felt_to_fr(&program_hash),
        hand_binding: felt_to_fr(&hand_binding),
        fact: felt_to_fr(&fact),
    };

    let t0 = std::time::Instant::now();
    let circuit = WrapCircuit {
        statement,
        witness: witness.clone(),
    };
    let pk = seeded_setup(circuit.clone()).context("setup")?;
    let setup_ms = t0.elapsed().as_millis();

    let t1 = std::time::Instant::now();
    let proof = prove_with_pk(&pk, &circuit).context("prove")?;
    let prove_ms = t1.elapsed().as_millis();

    let t2 = std::time::Instant::now();
    let ok = verify_with_vk(
        &pk.vk,
        &[statement.program_hash, statement.hand_binding, statement.fact],
        &proof,
    )?;
    let verify_ms = t2.elapsed().as_micros();
    anyhow::ensure!(ok, "local verify FAILED — 不写产物");

    let spj = groth16_wrap::StatementProofJson {
        program_hash: felt_to_hex(&program_hash),
        hand_binding: felt_to_hex(&hand_binding),
        fact: felt_to_hex(&fact),
        proof: groth16_wrap::ProofJson::from_ark(&proof),
    };
    let json = serde_json::to_string_pretty(&spj)?;
    std::fs::write(&out_path, &json)?;
    println!("statement proof written to {}", out_path.display());
    println!("fact       = {}", spj.fact);
    println!("setup_ms={setup_ms} prove_ms={prove_ms} verify_us={verify_ms}");
    Ok(())
}
