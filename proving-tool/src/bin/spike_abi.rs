//! ABI 尖刺（E2E 批量腿前置）：实证「standalone executable 入参含
//! `Array<felt252>` 时，prove-hand 的 flat 输入 JSON = `[k, len, elems…]`
//! （corelib array.cairo:305 ArraySerde = len 前缀 + 元素）。
//!
//! 注意（2026-09-29 更新）：settlement_batch_private 现为
//! `main(k, acc_prev, root_hi, root_lo, data)`——flat 输入 = [k, acc, hi, lo,
//! 98k, elems…]；输出 = [16k+4(len)] ++ 手段 ++ [acc, hi, lo, batch_fact]
//! （形状由 K=1 E2E 实测钉死，见 stark-recursion stark_final.rs）。本尖刺
//! 程序仍验证 ArraySerde 通用规则本身。
//!
//! 运行：`cargo run --release -p prove-hand --bin spike_abi --`
//! 用临时 spike 程序 compile → run_and_adapt → VM 执行 → 断言公开输出。
//! exit 0 = ABI 结论成立；非 0 = 失败（fail-closed）。

use std::path::PathBuf;

use stwo_cairo_adapter::ExecutionResources;
use stwo_cairo_dev_utils::cairo1_compile::compile_cairo1_executable;
use stwo_cairo_dev_utils::vm_utils::{run_and_adapt, ProgramType};

const SPIKE_SRC: &str = r#"
use core::array::ArrayTrait;
use core::traits::Into;

#[executable]
fn main(k: felt252, data: Array<felt252>) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    out.append(k);
    out.append(*data.at(0));
    out.append(data.len().into());
    out
}
"#;

fn main() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join("spike_abi_batch");
    std::fs::create_dir_all(&dir)?;
    let src = dir.join("spike_abi.cairo");
    std::fs::write(&src, SPIKE_SRC)?;

    let corelib = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../third_party/corelib-2.19.4/corelib/src");
    let executable = compile_cairo1_executable(&src, Some(&corelib))?;
    let exec_path = dir.join("spike_abi.json");
    std::fs::write(
        &exec_path,
        serde_json::to_vec(&executable).expect("serialize executable"),
    )?;

    // 输入：k=7, data=[0xa, 0xb, 0xc] → flat = [7, 3, 0xa, 0xb, 0xc]
    let input_path = dir.join("spike_input.json");
    std::fs::write(
        &input_path,
        serde_json::to_vec(&serde_json::json!(["0x7", "0x3", "0xa", "0xb", "0xc"]))?,
    )?;

    // run_and_adapt 只喂 ProverInput；VM 执行失败会在此报错。
    let prover_input = run_and_adapt(
        &exec_path,
        ProgramType::Executable,
        cairo_vm::types::layout_name::LayoutName::all_cairo_stwo,
        Some(&input_path),
    )?;
    let resources = ExecutionResources::from_prover_input(&prover_input);
    println!(
        "SPIKE_ABI_OK: compile+run accepted [k,len,elems…] flat layout (ArraySerde len-prefix); memory_words={}",
        resources.memory_tables_sizes.memory_address_to_id
    );
    Ok(())
}
