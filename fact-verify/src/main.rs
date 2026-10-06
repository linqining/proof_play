//! fact-verify CLI — 验证 prove-hand 证明并打印 settlement fact。
//!
//! 用法：
//! ```text
//! fact-verify <proof.json>                       # 验证 + 打印 program_hash/output/fact
//! fact-verify <proof.json> --expect-program-hash 0x744d…   # 额外钉扎断言
//! ```
use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "fact-verify",
    about = "验证 Cairo/Stwo 证明（prove-hand 产物）并派生 settlement fact（zchain/Starknet 双侧对拍用）"
)]
struct Args {
    /// prove-hand 产出的 proof.json
    proof: PathBuf,
    /// 预期程序哈希（可选；提供即断言 == 链上 set_circuit_program_hash 钉扎值）
    #[arg(long)]
    expect_program_hash: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let out = match args.expect_program_hash {
        Some(hash) => {
            let pinned = starknet_crypto::Felt::from_hex(hash.trim())
                .context("parse --expect-program-hash")?;
            fact_verify::verify_cairo_proof_file_pinned(&args.proof, pinned)?
        }
        None => fact_verify::verify_cairo_proof_file(&args.proof)?,
    };
    println!("program_hash = {:#x}", out.program_hash);
    println!(
        "output       = [{}]",
        out.output.iter().map(|f| format!("{f:#x}")).collect::<Vec<_>>().join(", ")
    );
    println!("fact         = {:#x}", out.fact);
    println!("OK ✓ — fact 可对照 DualSettlement.settlement_fact() / zchain registry 消费");
    Ok(())
}
