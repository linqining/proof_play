//! batch_inputs —— L1 批量终证腿的输入/清单生成器（stark-recursion host 公式直出）。
//!
//! 两阶段工作流（与 prove-hand 的 run 顺序对齐）：
//!
//! 1. **阶段 A（--phase a）**：从基础单手输入（102 felt JSON 数组）合成 K 手
//!    （每手 hand_id/hand_binding 递增、digest 由 host 重算），输出
//!    prove-hand `--inputs` JSON（占位链尾 acc=hi=lo=0）→ 先跑一次拿
//!    program_hash 与真实公开段。
//! 2. **阶段 B（--phase b）**：读阶段 A 的 public_outputs.json（17·K 手段 +
//!    4 felt 链尾），host 侧派生语句集 → keccak 批根（groth16-wrap
//!    batch::keccak_batch_root，与 zchain SettleBatch.sol 逐式一致）→
//!    hi/lo 拆分 → 输出带真实链尾的 `--inputs` JSON + 清单 JSON
//!    （statements/root/期望尾），供二次出证与对拍。
//!
//! host 公式全部复用本 crate 既有实现（poseidon_hash_many /
//! keccak_batch_root / split_root_hi_lo），E2E 对拍即公式交叉验证：
//! 电路内 HashState sponge（Cairo）↔ 宿主 poseidon_hash_many（Rust）。
//!
//! # 内存/复杂度
//!
//! 纯宿主算术（poseidon/keccak/blake 均为常数级），O(K) 内存，KB 级。
//!
//! 用法示例：
//! ```text
//! cargo run -p stark-recursion --bin batch_inputs -- \
//!   --phase a --base-input /tmp/settlement-prove/settlement_inputs.json \
//!   --hands 8 --out-inputs /tmp/settlement-batch/in_a8.json
//! cargo run -p stark-recursion --bin batch_inputs -- \
//!   --phase b --base-input … --hands 8 --acc 0x0 \
//!   --program-hash 0x5c40… --from-output …/public_outputs.json \
//!   --out-inputs /tmp/settlement-batch/in_b8.json --out-manifest …/manifest_k8.json
//! ```

use anyhow::{bail, Context, Result};
use groth16_wrap::batch::BatchStatement;
use groth16_wrap::felt::{felt_from_hex, felt_to_be_bytes, felt_to_hex, Felt252};
use groth16_wrap::poseidon::poseidon_hash_many;
use std::path::PathBuf;

struct Args {
    phase: char,
    base_input: PathBuf,
    hands: usize,
    acc: Option<String>,
    program_hash: Option<String>,
    from_output: Option<PathBuf>,
    out_inputs: PathBuf,
    out_manifest: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut a = Args {
        phase: 'a',
        base_input: PathBuf::from("/tmp/settlement-prove/settlement_inputs.json"),
        hands: 1,
        acc: None,
        program_hash: None,
        from_output: None,
        out_inputs: PathBuf::from("batch_inputs.json"),
        out_manifest: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or_else(|| anyhow::anyhow!("missing value for {k}"));
        match k.as_str() {
            "--phase" => {
                let v = val()?;
                if v != "a" && v != "b" {
                    bail!("--phase 只支持 a|b");
                }
                a.phase = v.chars().next().expect("checked");
            }
            "--base-input" => a.base_input = PathBuf::from(val()?),
            "--hands" => a.hands = val()?.parse()?,
            "--acc" => a.acc = Some(val()?),
            "--program-hash" => a.program_hash = Some(val()?),
            "--from-output" => a.from_output = Some(PathBuf::from(val()?)),
            "--out-inputs" => a.out_inputs = PathBuf::from(val()?),
            "--out-manifest" => a.out_manifest = Some(PathBuf::from(val()?)),
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => bail!("unknown arg {other}（--help 看用法）"),
        }
    }
    Ok(a)
}

fn print_help() {
    println!(
        "batch_inputs —— L1 批量终证腿输入/清单生成器\n\
         --phase a|b           a=合成 K 手占位输入；b=从真实公开段派生批根/链尾\n\
         --base-input PATH     基础单手输入（102 felt hex JSON 数组）\n\
         --hands N             手数（2 的幂，≤64）\n\
         --acc HEX             累加链接入 acc_prev（b 阶段必填；首批 0x0）\n\
         --program-hash HEX    批程序哈希（b 阶段必填；阶段 A 出证后取）\n\
         --from-output PATH    阶段 A 的 public_outputs.json（b 阶段必填）\n\
         --out-inputs PATH     输出 prove-hand --inputs JSON\n\
         --out-manifest PATH   输出语句/批根/期望尾清单 JSON（b 阶段）"
    );
}

/// 每手入参长度（与 settlement_batch_private.cairo HAND_INPUT_LEN 一致）。
const HAND_INPUT_LEN: usize = 102;
/// 每手公开段长度（settlement_batch_private 输出段 = 字面 16 前缀 + 语句 16）。
const SEGMENT_LEN: usize = 17;
/// 链尾长度：acc_prev / root_hi / root_lo / batch_fact。
const TAIL_LEN: usize = 4;
/// digest 的 sponge 载荷：hand_id + 9×(player, sign, mag) + action_log_digest。
const DIGEST_MSG_LEN: usize = 1 + 9 * 3 + 1;

/// 读手 i 的第 slot 个入参（flat 布局与电路 read() 一致）。
fn hand_input_felt(flat: &[Felt252], hand_idx: usize, slot: usize) -> Felt252 {
    flat[hand_idx * HAND_INPUT_LEN + slot]
}

/// 单手 digest（settlement_batch_private.cairo 约束 1 同式：HashState sponge ≡
/// poseidon_hash_many，宿主对拍见 stark_final 模块测试与 E2E）。
fn hand_digest(flat: &[Felt252], hand_idx: usize) -> Felt252 {
    let mut msg = Vec::with_capacity(DIGEST_MSG_LEN);
    msg.push(hand_input_felt(flat, hand_idx, 0)); // hand_id
    for i in 0..9usize {
        msg.push(hand_input_felt(flat, hand_idx, 4 + i)); // players
        msg.push(hand_input_felt(flat, hand_idx, 13 + i)); // signs
        msg.push(hand_input_felt(flat, hand_idx, 22 + i)); // mags
    }
    msg.push(hand_input_felt(flat, hand_idx, 40)); // action_log_digest
    poseidon_hash_many(&msg)
}

/// 从基础手合成 K 手 flat 入参：hand_id/hand_binding 递增、digest 重算。
/// （players/signs/mags/commitments/words 原样保留——零和、人数、动作链
/// 校验与 hand_id 无关；digest 是唯一 hand_id 的函数，重算即通过约束 1。）
fn synthesize_hands(base: &[Felt252], hands: usize) -> Result<Vec<Felt252>> {
    anyhow::ensure!(base.len() == HAND_INPUT_LEN, "base hand must be {HAND_INPUT_LEN} felts, got {}", base.len());
    let mut flat = Vec::with_capacity(hands * HAND_INPUT_LEN);
    for i in 0..hands {
        let mut h = base.to_vec();
        h[0] = h[0] + Felt252::from(i as u64); // hand_id
        h[3] = h[3] + Felt252::from(i as u64); // hand_binding（槽位 3）
        let d = hand_digest(&h, 0);
        h[1] = d; // registered_digest
        flat.extend_from_slice(&h);
    }
    Ok(flat)
}

/// 写 prove-hand --inputs JSON：[k, acc_prev, root_hi, root_lo, 102k(len), flat…]。
fn write_program_inputs(
    path: &PathBuf,
    k: usize,
    acc: &Felt252,
    hi: &Felt252,
    lo: &Felt252,
    flat: &[Felt252],
) -> Result<()> {
    let mut v = vec![
        felt_to_hex(&Felt252::from(k as u64)),
        felt_to_hex(acc),
        felt_to_hex(hi),
        felt_to_hex(lo),
        felt_to_hex(&Felt252::from((flat.len()) as u64)),
    ];
    v.extend(flat.iter().map(felt_to_hex));
    std::fs::write(path, serde_json::to_vec(&v)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// 从 public_outputs.json 提取 (program_hash, 手段序列, 链尾)。
/// 输出形状（9 人桌）：[len=17k+4] ++ 17k 手段 ++ [acc, hi, lo, fact]。
fn parse_proof_output(
    path: &PathBuf,
) -> Result<(Felt252, Vec<Felt252>, [Felt252; TAIL_LEN])> {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
            .context("parse public_outputs.json")?;
    let ph = felt_from_hex(
        v["program_hash"].as_str().context("missing program_hash")?,
    )?;
    let out: Vec<Felt252> = v["output"]
        .as_array()
        .context("missing output")?
        .iter()
        .map(|x| felt_from_hex(x.as_str().expect("hex str")))
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(out.len() >= 1 + SEGMENT_LEN + TAIL_LEN, "output too short: {}", out.len());
    let declared = out[0];
    let expect = Felt252::from((out.len() - 1) as u64);
    anyhow::ensure!(
        declared == expect,
        "output len prefix {declared} != elements {}（形状漂移，fail-closed）",
        out.len() - 1
    );
    let total = out.len() - 1;
    anyhow::ensure!(
        total >= SEGMENT_LEN + TAIL_LEN && (total - TAIL_LEN) % SEGMENT_LEN == 0,
        "output elements {total} 不满足 17k+4 形状"
    );
    let k = (total - TAIL_LEN) / SEGMENT_LEN;
    let segments = out[1..1 + k * SEGMENT_LEN].to_vec();
    let tail: [Felt252; TAIL_LEN] = std::array::from_fn(|i| out[1 + k * SEGMENT_LEN + i]);
    Ok((ph, segments, tail))
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let base_raw: Vec<String> = serde_json::from_str(&std::fs::read_to_string(&args.base_input).with_context(|| format!("read {}", args.base_input.display()))?)
        .context("parse base input JSON")?;
    let base: Vec<Felt252> = base_raw
        .iter()
        .map(|s| felt_from_hex(s))
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(
        args.hands >= 1 && args.hands.is_power_of_two() && args.hands <= 64,
        "--hands 必须 ∈ {{1,2,4,…,64}}"
    );

    match args.phase {
        'a' => {
            let flat = synthesize_hands(&base, args.hands)?;
            let zero = Felt252::from(0u64);
            write_program_inputs(&args.out_inputs, args.hands, &zero, &zero, &zero, &flat)?;
            println!(
                "[phase-a] {} hands → {}（占位链尾 acc=hi=lo=0；出证后用 public_outputs.json 进 --phase b）",
                args.hands,
                args.out_inputs.display()
            );
        }
        'b' => {
            let acc_hex = args.acc.clone().context("--phase b 需要 --acc（首批 0x0）")?;
            let acc = felt_from_hex(&acc_hex)?;
            let ph_hex = args.program_hash.clone().context("--phase b 需要 --program-hash")?;
            let ph = felt_from_hex(&ph_hex)?;
            let out_path = args.from_output.clone().context("--phase b 需要 --from-output")?;
            let (ph_out, segments, tail) = parse_proof_output(&out_path)?;
            anyhow::ensure!(
                felt_to_hex(&ph) == felt_to_hex(&ph_out),
                "--program-hash 与 public_outputs.json 的 program_hash 不一致（fail-closed）"
            );
            let k = segments.len() / SEGMENT_LEN;
            anyhow::ensure!(k == args.hands, "output 段数 {k} != --hands {}", args.hands);

            // 语句集：fact = poseidon([program_hash ‖ 16-felt 手段])（wrap_circuit
            // expected_fact 同式）；binding = 手段槽位 5。
            let statements: Vec<BatchStatement> = (0..k)
                .map(|i| {
                    let seg = &segments[i * SEGMENT_LEN..(i + 1) * SEGMENT_LEN];
                    let mut msg = Vec::with_capacity(1 + SEGMENT_LEN);
                    msg.push(ph);
                    msg.extend_from_slice(seg);
                    BatchStatement {
                        program_hash: ph,
                        hand_binding: seg[5],
                        fact: poseidon_hash_many(&msg),
                    }
                })
                .collect();
            let root = groth16_wrap::batch::keccak_batch_root(&statements)
                .context("keccak batch root")?;
            let (hi, lo) = stark_recursion::chain::split_root_hi_lo(&root);

            // 期望链尾（电路内公式的宿主镜像；与出证 tail 对拍 = 交叉验证）。
            let expected_fact =
                stark_recursion::stark_final::expected_batch_fact(&acc, &hi, &lo, k, &segments);
            println!("[phase-b] 期望尾 acc={} hi={} lo={} fact={}",
                felt_to_hex(&acc), felt_to_hex(&hi), felt_to_hex(&lo), felt_to_hex(&expected_fact));
            println!("[phase-b] 出证尾（阶段 A 占位）acc={} hi={} lo={} fact={}",
                felt_to_hex(&tail[0]), felt_to_hex(&tail[1]), felt_to_hex(&tail[2]), felt_to_hex(&tail[3]));
            println!("[phase-b] keccak 批根 = 0x{}", hex::encode(root));

            // 阶段 B 输入 = 原始 K 手数据 + 真实链尾。
            let flat = synthesize_hands(&base, args.hands)?;
            write_program_inputs(&args.out_inputs, args.hands, &acc, &hi, &lo, &flat)?;

            if let Some(mpath) = &args.out_manifest {
                let manifest = serde_json::json!({
                    "k": k,
                    "program_hash": felt_to_hex(&ph),
                    "acc_prev": felt_to_hex(&acc),
                    "keccak_batch_root": format!("0x{}", hex::encode(root)),
                    "root_hi": felt_to_hex(&hi),
                    "root_lo": felt_to_hex(&lo),
                    "expected_batch_fact": felt_to_hex(&expected_fact),
                    "statements": statements.iter().map(|s| serde_json::json!({
                        "program_hash": felt_to_hex(&s.program_hash),
                        "hand_binding": felt_to_hex(&s.hand_binding),
                        "fact": felt_to_hex(&s.fact),
                    })).collect::<Vec<_>>(),
                    "phase_a_tail": tail.iter().map(felt_to_hex).collect::<Vec<_>>(),
                });
                std::fs::write(mpath, serde_json::to_vec_pretty(&manifest)?)
                    .with_context(|| format!("write {}", mpath.display()))?;
                println!("[phase-b] manifest → {}", mpath.display());
            }
        }
        other => bail!("unknown phase {other}"),
    }
    Ok(())
}

// felt_to_be_bytes 目前仅清单展示用；保留引用避免 unused 告警的显式路径。
#[allow(dead_code)]
fn _touch(f: &Felt252) -> [u8; 32] {
    felt_to_be_bytes(f)
}
