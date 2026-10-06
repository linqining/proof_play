//! bench-verify —— 全链路口径计时。
//!
//! 指标口径（如实标注，不混口径）：
//! - `stark_verify_ms`：**子进程**复用独立工作区 fact-verify CLI 对**真实**
//!   prove-hand 证明（settlement proof.json，12.2MB JSON）跑完整验证
//!   （JSON 反序列化 + stwo verify_cairo + fact 派生）。跑 3 次取最小值
//!   （降低进程启动/文件缓存噪声）；含 CLI 全流程，非纯 stwo verify。
//! - `setup_ms`：固定种子单方 Groth16 setup（可复现 trusted setup）。
//! - `groth16_prove_ms`：单手包裹电路证明（含二次约束合成）。
//! - `groth16_verify_ms`：单手包裹本地 Groth16 验证。
//! - `batch_*`：K 手批量电路（共享 program_hash 绑定，一次证明覆盖 K 手）。
//!
//! 用法：
//! ```text
//! cargo run -p groth16-wrap --release --bin bench-verify -- \
//!   [--proof ../proving-tool/output/settlement/proof.json] [--batch-k 4]
//! ```
//! fact-verify CLI 位置：env `FACT_VERIFY_BIN` 或
//! `<crate>/../fact-verify/target/release/fact-verify`（相对 CARGO_MANIFEST_DIR
//! 锚定，与调用时 CWD 无关；缺失时报错并给出构建命令）。

use anyhow::{Context, Result};
use groth16_wrap::batch_circuit::{BatchCircuit, BatchHand};
use groth16_wrap::felt::{felt_from_hex, felt_to_fr, felt_to_hex};
use groth16_wrap::wrap_circuit::{WrapCircuit, WrapStatement, WrapWitness};
use groth16_wrap::{prove_with_pk, seeded_setup, verify_with_vk, Felt252};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str, default: &str| -> String {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    // 默认路径锚定在本 crate（groth16-wrap/）而非进程 CWD：
    // `cargo run -p groth16-wrap …` 在仓库根执行时 CWD=仓库根，`../fact-verify`
    // 会解析到仓库外导致误报「不存在」。env/flag 覆盖仍优先。
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proof_path = PathBuf::from(arg(
        "--proof",
        &manifest_dir
            .join("../proving-tool/output/settlement/proof.json")
            .to_string_lossy(),
    ));
    let batch_k: usize = arg("--batch-k", "4").parse().context("--batch-k")?;

    // ---------- STARK：子进程复用 fact-verify（真实验证） ----------
    let fv_bin = std::env::var("FACT_VERIFY_BIN").unwrap_or_else(|_| {
        manifest_dir
            .join("../fact-verify/target/release/fact-verify")
            .to_string_lossy()
            .into_owned()
    });
    let fv = Path::new(&fv_bin);
    anyhow::ensure!(
        fv.exists(),
        "fact-verify CLI 不存在：{fv_bin}\n先构建：cargo build --release --manifest-path {}/../fact-verify/Cargo.toml",
        manifest_dir.display()
    );
    let mut stark_runs: Vec<u128> = Vec::new();
    let mut cli_fact = String::new();
    // 期望哈希取自证明自身的 public_outputs.json（钉扎 = 自洽性检查）——
    // 不得硬编码金向量常量：9 席迁移后金常量（0x744d…）已与盘上产物
    // （0xee3b…）失配，历史 SIGKILL 复跑在此处先行失败掩盖了真实进度。
    let expected_program_hash = read_program_hash(&proof_path)?;
    println!("expected_program_hash  = {expected_program_hash}（public_outputs.json）");
    for i in 0..3 {
        let t = Instant::now();
        let out = Command::new(fv)
            .arg(&proof_path)
            .arg("--expect-program-hash")
            .arg(&expected_program_hash)
            .output()
            .with_context(|| format!("spawn {fv_bin}"))?;
        let ms = t.elapsed().as_millis();
        anyhow::ensure!(
            out.status.success(),
            "fact-verify 第 {} 次运行失败（钉扎校验或 stwo verify 未过）：{}",
            i,
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        cli_fact = stdout
            .lines()
            .find_map(|l| l.strip_prefix("fact         = "))
            .unwrap_or_default()
            .trim()
            .to_string();
        stark_runs.push(ms);
    }
    let stark_verify_ms = *stark_runs.iter().min().unwrap();
    println!("--- STARK（fact-verify CLI，真实证明） ---");
    println!("runs_ms                = {:?}", stark_runs);
    println!("stark_verify_ms        = {stark_verify_ms}（3 次取最小；含 JSON 反序列化全流程）");
    println!("cli_fact               = {cli_fact}");

    // ---------- 语句：真实 STARK 公开段（public_outputs.json，与 CLI 验证同一产物） ----------
    let witness = read_public_outputs(&proof_path)?;
    witness.validate().map_err(|e| anyhow::anyhow!("STARK 公开段形状不符: {e}"))?;
    let program_hash = felt_from_hex(&expected_program_hash)?;
    let host_fact = witness.expected_fact(&program_hash);
    // CLI（fact-verify 真实验证产物）与宿主重算对拍
    anyhow::ensure!(
        !cli_fact.is_empty() && felt_from_hex(&cli_fact)? == host_fact,
        "CLI fact ({cli_fact}) 与宿主重算 ({}) 不一致",
        felt_to_hex(&host_fact)
    );
    let hb_felt = witness.output[groth16_wrap::wrap_circuit::HAND_BINDING_INDEX];
    let statement = WrapStatement {
        program_hash: felt_to_fr(&program_hash),
        hand_binding: felt_to_fr(&hb_felt),
        fact: felt_to_fr(&host_fact),
    };
    println!("segment: fact = {}", felt_to_hex(&host_fact));

    // ---------- 单手 Groth16 ----------
    let circuit = WrapCircuit {
        statement,
        witness: witness.clone(),
    };
    let t = Instant::now();
    let pk = seeded_setup(circuit.clone())?;
    let setup_ms = t.elapsed().as_millis();
    let constraints = {
        use ark_relations::gr1cs::ConstraintSynthesizer;
        let cs = ark_relations::gr1cs::ConstraintSystem::<groth16_wrap::Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone())?;
        cs.num_constraints()
    };

    let t = Instant::now();
    let proof = prove_with_pk(&pk, &circuit)?;
    let prove_ms = t.elapsed().as_millis();

    let t = Instant::now();
    let ok = verify_with_vk(&pk.vk, &[statement.program_hash, statement.hand_binding, statement.fact], &proof)?;
    let verify_us = t.elapsed().as_micros();
    anyhow::ensure!(ok, "groth16 verify FAILED");

    println!("--- 单手（真实 STARK 语句） ---");
    println!("constraints            = {constraints}");
    println!("setup_ms               = {setup_ms}");
    println!("groth16_prove_ms       = {prove_ms}");
    println!("groth16_verify_ms      = {:.3}", verify_us as f64 / 1000.0);

    // ---------- 批量（K 手） ----------
    let hands: Vec<BatchHand> = (0..batch_k)
        .map(|k| {
            let mut out = witness.output.clone();
            let hb = hb_felt + Felt252::from(k as u64);
            out[groth16_wrap::wrap_circuit::HAND_BINDING_INDEX] = hb;
            let w = WrapWitness { output: out };
            let fact = w.expected_fact(&program_hash);
            BatchHand {
                statement: WrapStatement {
                    program_hash: statement.program_hash,
                    hand_binding: felt_to_fr(&hb),
                    fact: felt_to_fr(&fact),
                },
                witness: w,
            }
        })
        .collect();
    let batch = BatchCircuit::new(statement.program_hash, hands).map_err(anyhow::Error::msg)?;

    let t = Instant::now();
    let bpk = seeded_setup(batch.clone())?;
    let b_setup_ms = t.elapsed().as_millis();

    let t = Instant::now();
    let bproof = prove_with_pk(&bpk, &batch)?;
    let b_prove_ms = t.elapsed().as_millis();

    let mut publics = vec![statement.program_hash];
    for h in &batch.hands {
        publics.push(h.statement.hand_binding);
        publics.push(h.statement.fact);
    }
    let t = Instant::now();
    let bok = verify_with_vk(&bpk.vk, &publics, &bproof)?;
    let b_verify_us = t.elapsed().as_micros();
    anyhow::ensure!(bok, "batch verify FAILED");

    println!("--- 批量 K={batch_k}（实现 C 电路口径；编译期默认 BATCH_N={}，feature n8/n64 可调） ---", groth16_wrap::batch::BATCH_N);
    println!("batch_setup_ms         = {b_setup_ms}");
    println!("batch_prove_ms         = {b_prove_ms}");
    println!("batch_verify_ms        = {:.3}", b_verify_us as f64 / 1000.0);
    println!("batch_per_hand_prove_ms= {:.1}", b_prove_ms as f64 / batch_k as f64);
    Ok(())
}

/// 读公开段（与 proof.json 同一次 prove 运行产出的 public_outputs.json）。
fn read_public_outputs(proof_path: &Path) -> Result<WrapWitness> {
    let po_path = proof_path.with_file_name("public_outputs.json");
    #[derive(serde::Deserialize)]
    struct Po {
        #[allow(dead_code)]
        program_hash: String,
        output: Vec<String>,
    }
    let po: Po = serde_json::from_str(
        &std::fs::read_to_string(&po_path)
            .with_context(|| format!("read {}", po_path.display()))?,
    )
    .context("parse public_outputs.json")?;
    let output = po
        .output
        .iter()
        .map(|h| felt_from_hex(h))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WrapWitness { output })
}

/// public_outputs.json 的 program_hash（证明自身的电路哈希——bench 钉扎
/// 与语句派生的单一来源）。
fn read_program_hash(proof_path: &Path) -> Result<String> {
    let po_path = proof_path.with_file_name("public_outputs.json");
    #[derive(serde::Deserialize)]
    struct Po {
        program_hash: String,
    }
    let po: Po = serde_json::from_str(
        &std::fs::read_to_string(&po_path)
            .with_context(|| format!("read {}", po_path.display()))?,
    )
    .context("parse public_outputs.json")?;
    Ok(po.program_hash)
}
