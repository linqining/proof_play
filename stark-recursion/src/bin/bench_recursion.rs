//! bench-recursion —— 聚合链逐跳基准（真 K 在服务器跑；本机 K=2 冒烟）。
//!
//! # 用法
//!
//! ```text
//! cargo run --release -p stark-recursion --bin bench-recursion -- \
//!   --hands 64 --leaves 4 --batches 2 --backend mock --json /tmp/bench.json
//! ```
//!
//! - `--backend mock`（默认）：mock 叶/折叠（格式合规、H1 精确镜像），只测
//!   语句/累加/Groth16 包裹腿的真实开销——本机可跑。
//! - `--backend cli`：真实 stwo 链（leaf-prover / 递归树二进制 + registry 工件，
//!   `--leaf-bin/--tree-bin/--bootloader/--registry` 指路）。**未在本轮实跑**
//!   （需 scarb 2.18 + registry 工件 + 大内存）；跑前过 budget 闸门，超界
//!   fail-closed。
//! - `--wrap`（默认关；需 `--features groth16-baseline`）：Groth16 对照基线
//!   腿（seeded setup + prove + verify）。2026-09-29 裁定 Groth16 出终证路径，
//!   仅作对照回归；主链上链形态 = submitFinalProof STARK calldata（恒开）。
//!
//! # 内存纪律
//!
//! 每阶段打印耗时 + 进程峰值 RSS（getrusage ru_maxrss；macOS 字节 / Linux KiB）；
//! cli 后端每步一个子进程（叶 19.4GB / 折叠 7.4GB 不同时驻留，budget.rs 锚点），
//! 且开跑前过 [`stark_recursion::budget::check_step`] fail-closed 闸门。

use anyhow::{bail, Context, Result};
#[cfg(feature = "groth16-baseline")]
use ark_bn254::Bn254;
#[cfg(feature = "groth16-baseline")]
use ark_groth16::ProvingKey;
use serde::Serialize;
use std::path::PathBuf;
use std::time::Instant;

#[cfg(feature = "groth16-baseline")]
use groth16_wrap::felt::{felt_to_hex, fr_to_felt};
use groth16_wrap::felt::{felt_from_hex, Felt252};
use stark_recursion::backend::{CliBackend, LeafProver, MockBackend, TreeFolder};
use stark_recursion::chain::{
    acc_genesis, acc_next, BatchPlan, FoldPlan, HandEntry, MAX_HANDS_PER_LEAF,
};
#[cfg(feature = "groth16-baseline")]
use stark_recursion::envelope::{HandRecord, RootEnvelope, WrapSection};
#[cfg(not(feature = "groth16-baseline"))]
use stark_recursion::envelope::RootEnvelope;
#[cfg(feature = "groth16-baseline")]
use stark_recursion::onchain::{encode_settle_root_calldata, fr_publics_to_hex};
use stark_recursion::onchain::{encode_submit_final_calldata, output_commit};
#[cfg(feature = "groth16-baseline")]
use stark_recursion::root_circuit::{derive_statement, host_check, RootCircuit};
#[cfg(feature = "groth16-baseline")]
use stark_recursion::ProofJson;

struct Args {
    hands: usize,
    leaves: usize,
    batches: usize,
    backend: String,
    wrap: bool,
    json: Option<PathBuf>,
    leaf_bin: Option<PathBuf>,
    tree_bin: Option<PathBuf>,
    bootloader: Option<PathBuf>,
    registry: Option<PathBuf>,
}

/// 极简 arg 解析（免 clap 新依赖）：`--key value` / `--flag`。
fn parse_args() -> Result<Args> {
    let mut a = Args {
        hands: 2,
        leaves: 1,
        batches: 1,
        backend: "mock".into(),
        wrap: false,
        json: None,
        leaf_bin: None,
        tree_bin: None,
        bootloader: None,
        registry: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or_else(|| anyhow::anyhow!("missing value for {k}"));
        match k.as_str() {
            "--hands" => a.hands = val()?.parse()?,
            "--leaves" => a.leaves = val()?.parse()?,
            "--batches" => a.batches = val()?.parse()?,
            "--backend" => a.backend = val()?,
            "--wrap" => a.wrap = true,
            "--no-wrap" => a.wrap = false,
            "--json" => a.json = Some(PathBuf::from(val()?)),
            "--leaf-bin" => a.leaf_bin = Some(PathBuf::from(val()?)),
            "--tree-bin" => a.tree_bin = Some(PathBuf::from(val()?)),
            "--bootloader" => a.bootloader = Some(PathBuf::from(val()?)),
            "--registry" => a.registry = Some(PathBuf::from(val()?)),
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
        "bench-recursion —— 递归聚合链逐跳基准\n\
         --hands N            每批手数（2 的幂，≤{MAX_HANDS_PER_LEAF}；默认 2）\n\
         --leaves N           折叠树叶数（2 的幂，1=自折叠根；默认 1）\n\
         --batches N          累加链接的批数（默认 1）\n\
         --backend mock|cli   叶/折叠后端（默认 mock；cli 需工件，真 K 服务器跑）\n\
         --wrap|--no-wrap     Groth16 对照基线腿（默认 no-wrap；开需 feature groth16-baseline）\n\
         --json PATH          结果 JSON 落盘\n\
         --leaf-bin P --tree-bin P --bootloader P --registry P    cli 后端路径\n\
         \n\
         内存口径：mock 后端本机可跑；cli 后端叶腿实测峰值 19.4GB、折叠腿 7.4GB，\n\
         由 budget::check_step 按 --available 默认（服务器 7459MB）fail-closed。"
    );
}

#[derive(Serialize)]
struct PhaseReport {
    phase: String,
    elapsed_ms: u128,
    peak_rss_bytes: u64,
    note: String,
}

#[derive(Serialize)]
struct BenchReport {
    hands_per_batch: usize,
    leaves: usize,
    batches: usize,
    backend: String,
    wrap_enabled: bool,
    root_circuit_constraints: Option<usize>,
    wrap_proofs_verified: usize,
    calldata_bytes: Option<usize>,
    phases: Vec<PhaseReport>,
    peak_rss_note: String,
}

/// 进程峰值 RSS（getrusage.ru_maxrss；macOS 单位字节，Linux 单位 KiB）。
fn peak_rss_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe {
            if libc::getrusage(libc::RUSAGE_SELF, &mut ru) == 0 {
                return ru.ru_maxrss as u64; // macOS: bytes
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe {
            if libc::getrusage(libc::RUSAGE_SELF, &mut ru) == 0 {
                return ru.ru_maxrss as u64 * 1024; // Linux: KiB → bytes
            }
        }
    }
    0
}

fn peak_mib() -> f64 {
    peak_rss_bytes() as f64 / (1024.0 * 1024.0)
}

fn timed<F: FnOnce() -> Result<T>, T>(
    phases: &mut Vec<PhaseReport>,
    name: &str,
    note: &str,
    f: F,
) -> Result<T> {
    let t = Instant::now();
    let out = f()?;
    let ms = t.elapsed().as_millis();
    println!("[{name:22}] {ms:>9} ms  peakRSS {peak:>9.1} MiB  ({note})", peak = peak_mib());
    phases.push(PhaseReport {
        phase: name.to_string(),
        elapsed_ms: ms,
        peak_rss_bytes: peak_rss_bytes(),
        note: note.to_string(),
    });
    Ok(out)
}

/// 金向量段形态的合成手（bench 输入；binding = base + i，与
/// groth16-wrap batch::derive_batch_statements 同式）。
fn synthetic_batch(hands: usize, binding_base: u64) -> Result<Vec<HandEntry>> {
    let program_hash = felt_from_hex(groth16_wrap::golden::GOLDEN_PROGRAM_HASH)?;
    let base_segment: Vec<Felt252> = groth16_wrap::golden::GOLDEN_OUTPUT
        .iter()
        .map(|h| felt_from_hex(h))
        .collect::<Result<_, _>>()?;
    (0..hands)
        .map(|i| {
            let binding = felt_from_hex(groth16_wrap::golden::GOLDEN_HAND_BINDING)?
                + Felt252::from(binding_base + i as u64);
            let mut segment = base_segment.clone();
            segment[groth16_wrap::wrap_circuit::HAND_BINDING_INDEX] = binding;
            let fact = groth16_wrap::wrap_circuit::WrapWitness { output: segment.clone() }
                .expected_fact(&program_hash);
            Ok(HandEntry {
                statement: groth16_wrap::batch::BatchStatement {
                    program_hash,
                    hand_binding: binding,
                    fact,
                },
                segment,
            })
        })
        .collect()
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let work = std::env::temp_dir().join("stark-recursion-bench");
    std::fs::create_dir_all(&work)?;

    let mut phases = Vec::new();
    #[cfg_attr(not(feature = "groth16-baseline"), allow(unused_assignments, unused_variables))]
    let mut wrap_proofs_verified = 0usize;
    #[cfg_attr(not(feature = "groth16-baseline"), allow(unused_assignments, unused_variables))]
    let mut constraints: Option<usize> = None;
    let mut calldata_bytes: Option<usize> = None;

    // 后端选择（cli：先过输入自检 + 内存闸门）
    let cli = if args.backend == "cli" {
        let be = CliBackend {
            leaf_prover_bin: args.leaf_bin.clone().context("--leaf-bin required for --backend cli")?,
            recursive_tree_bin: args.tree_bin.clone().context("--tree-bin required for --backend cli")?,
            bootloader_path: args.bootloader.clone().context("--bootloader required for --backend cli")?,
            circuit_registry_json: args.registry.clone().context("--registry required for --backend cli")?,
            available_bytes: stark_recursion::budget::STARK_RAM_BYTES,
        };
        be.check_inputs().context("cli 后端输入自检（fail-closed）")?;
        Some(be)
    } else {
        anyhow::ensure!(args.backend == "mock", "--backend 只支持 mock|cli");
        None
    };

    anyhow::ensure!(
        args.leaves >= 1 && args.leaves.is_power_of_two(),
        "--leaves must be a power of two"
    );
    anyhow::ensure!(args.hands >= 1 && args.hands.is_power_of_two(), "--hands must be a power of two");
    anyhow::ensure!(args.hands <= MAX_HANDS_PER_LEAF, "--hands ≤ {MAX_HANDS_PER_LEAF}");
    anyhow::ensure!(args.hands % args.leaves == 0, "--hands 必须被 --leaves 整除（每叶 K/L 手）");

    // 终证腿程序哈希占位（'SP2M' 低 32bit）——真实值 = scarb 2.18 终证腿的
    // circuit-verifier 程序哈希，钉扎交付后替换；语句/电路结构不受影响。
    let agg_program_hash =
        felt_from_hex("0x000000000000000000000000000000000000000000000000000000005350324d")?;

    let mut acc = acc_genesis();
    let mut last_envelope: Option<RootEnvelope> = None;
    // pk 形状级复用：Groth16 pk 只依赖电路形状（K/语句无关）→ setup 一次，其后只 prove
    #[cfg(feature = "groth16-baseline")]
    let mut pk_cache: Option<ProvingKey<Bn254>> = None;
    #[cfg(not(feature = "groth16-baseline"))]
    let _ = args.wrap; // feature 关闭时该旗不可用（下方 fail-fast）

    for b in 0..args.batches {
        // ① K 手语句批
        let entries = timed(&mut phases, "1.synthetic-batch", &format!("K={} hands", args.hands), || {
            synthetic_batch(args.hands, (b * MAX_HANDS_PER_LEAF) as u64)
        })?;
        let plan = timed(&mut phases, "2.batch-validate", "形状/fact 重算/重复 binding 校验", || {
            BatchPlan::new(entries[0].statement.program_hash, entries)
        })?;
        let keccak_root = timed(&mut phases, "3.keccak-root", "SettleBatch 同式批根", || {
            plan.keccak_batch_root()
        })?;

        // ② 叶（K/L 手一叶；叶预映像 = [program_hash] ++ 本叶手段）
        let per_leaf = args.hands / args.leaves;
        let fold_plan = FoldPlan::new(args.leaves)?;
        let leaves: Vec<stark_recursion::envelope::LeafProofEnvelope> = timed(
            &mut phases,
            "4.leaf-proofs",
            &format!("L={} leaves × K/L={per_leaf} hands", args.leaves),
            || {
                (0..args.leaves)
                    .map(|l| {
                        let mut preimage = vec![plan.program_hash];
                        for h in plan.hands.iter().skip(l * per_leaf).take(per_leaf) {
                            preimage.extend_from_slice(&h.segment);
                        }
                        match &cli {
                            Some(be) => be.prove_leaf(&preimage, &work.join(format!("leaf_{b}_{l}"))),
                            None => MockBackend.prove_leaf(&preimage, &work.join(format!("leaf_{b}_{l}"))),
                        }
                    })
                    .collect::<Result<Vec<_>>>()
            },
        )?;

        // ③ 局部聚合（折叠树 → 根输出 8 词 + packed 树）
        #[cfg_attr(not(feature = "groth16-baseline"), allow(unused_variables))]
        let (root_output, packed) = timed(&mut phases, "5.fold-tree", &format!("L={} 折叠+根", args.leaves), || {
            match &cli {
                Some(be) => be.fold_tree(&leaves, &fold_plan, &work.join(format!("fold_{b}"))),
                None => MockBackend.fold_tree(&leaves, &fold_plan, &work.join(format!("fold_{b}"))),
            }
        })?;

        // ④ 累加链接 + 终证语句（host 公式；主链上链形态 = submitFinalProof）
        let (tree_fact, acc_prev_b) = timed(&mut phases, "6.statement+acc", "poseidon fact + 累加链", || {
            let (_hi, _lo, fact) = stark_recursion::chain::derive_batch_fact(
                &agg_program_hash, &root_output, &acc, &keccak_root,
            );
            let prev = acc;
            acc = acc_next(&acc, &fact);
            Ok((fact, prev))
        })?;
        // ④' 主链上链形态：submitFinalProof（STARK 验证合约提案 ABI）金字节编码。
        //   outputCommit = 树根输出 8 词的 felt 序列承诺（压缩层语句面口径）。
        let _ = timed(&mut phases, "6b.stark-calldata", "submitFinalProof 提案 ABI 编码", || {
            let commit_words: Vec<Felt252> =
                root_output.iter().map(|w| Felt252::from(*w)).collect();
            encode_submit_final_calldata(&keccak_root, &acc_prev_b, &tree_fact, &output_commit(&commit_words), b"bench-proof-bytes")
        })?;
        #[cfg(feature = "groth16-baseline")]
        let (statement, witness) = timed(&mut phases, "6c.wrap-statement", "对照基线语句（需 --wrap）", || {
            let (s, w) = derive_statement(&agg_program_hash, &root_output, &acc_prev_b, &keccak_root);
            host_check(&s, &w, &keccak_root).map_err(anyhow::Error::msg)?;
            Ok((s, w))
        })?;

        // ⑤ Groth16 终证包裹（对照基线；feature 隔离——终证路径禁 Groth16）
        #[cfg(feature = "groth16-baseline")]
        if args.wrap {
            let circuit = RootCircuit { statement, witness };
            let pk = if let Some(p) = pk_cache.clone() {
                p
            } else {
                let p = timed(&mut phases, "7.wrap-setup", "seeded setup（固定种子单方仪式；形状级只做一次）", || {
                    // 约束计数（只计一次）：形状 K 无关的结构证据
                    if constraints.is_none() {
                        let cs = ark_relations::gr1cs::ConstraintSystem::new_ref();
                        use ark_relations::gr1cs::ConstraintSynthesizer as _;
                        circuit.clone().generate_constraints(cs.clone())?;
                        constraints = Some(cs.num_constraints());
                    }
                    groth16_wrap::seeded_setup(circuit.clone())
                })?;
                pk_cache = Some(p.clone());
                p
            };
            let proof = timed(&mut phases, "8.wrap-prove", "Groth16 prove（blinding 固定种子）", || {
                groth16_wrap::prove_with_pk(&pk, &circuit)
            })?;
            let publics = circuit.publics();
            let ok = timed(&mut phases, "9.wrap-verify", "本地 verifyProof", || {
                groth16_wrap::verify_with_vk(&pk.vk, &publics, &proof)
            })?;
            anyhow::ensure!(ok, "wrap proof must verify");
            wrap_proofs_verified += 1;

            // ⑥ 上链形态（settleRoot 452B calldata + 终证信封落盘）
            let calldata = timed(&mut phases, "10.calldata", "settleRoot 静态 ABI 编码", || {
                let proof_json = ProofJson::from_ark(&proof);
                let pubs = fr_publics_to_hex(&publics);
                let arr: [String; 5] = pubs.try_into().expect("5 publics");
                encode_settle_root_calldata(&keccak_root, &proof_json, &arr)
            })?;
            calldata_bytes = Some(calldata.len());

            last_envelope = Some(RootEnvelope {
                protocol_version: 1,
                aggregator_program_hash: felt_to_hex(&agg_program_hash),
                root_output_words: root_output,
                keccak_batch_root: hex::encode(keccak_root),
                acc_prev: felt_to_hex(&acc_prev_b),
                batch_fact: felt_to_hex(
                    &fr_to_felt(&statement.batch_fact).map_err(|_| anyhow::anyhow!("fact not a felt"))?,
                ),
                statement_publics: {
                    let pubs = fr_publics_to_hex(&publics);
                    std::array::from_fn(|i| pubs[i].clone())
                },
                packed_tree: packed,
                hands: plan
                    .hands
                    .iter()
                    .map(|h| HandRecord {
                        hand_binding: felt_to_hex(&h.statement.hand_binding),
                        fact: felt_to_hex(&h.statement.fact),
                    })
                    .collect(),
                wrap: Some(WrapSection { proof: ProofJson::from_ark(&proof) }),
            });
        }
    }

    let report = BenchReport {
        hands_per_batch: args.hands,
        leaves: args.leaves,
        batches: args.batches,
        backend: args.backend.clone(),
        wrap_enabled: args.wrap,
        root_circuit_constraints: constraints,
        wrap_proofs_verified,
        calldata_bytes,
        phases,
        peak_rss_note: "getrusage ru_maxrss（macOS=bytes / Linux=KiB×1024）；cli 后端的子进程峰值另计（叶实测 19.4G/折叠实测 7.4G，budget.rs 锚点）".into(),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if let Some(path) = args.json {
        std::fs::write(&path, serde_json::to_vec_pretty(&report)?)?;
        println!("report → {}", path.display());
    }
    if let Some(env) = last_envelope {
        let p = work.join("root_envelope.json");
        std::fs::write(&p, serde_json::to_vec_pretty(&env)?)?;
        println!("root envelope → {}", p.display());
    }
    Ok(())
}
