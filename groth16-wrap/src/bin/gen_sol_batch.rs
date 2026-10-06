//! gen-sol-batch —— 生成批量包裹的金向量与 Solidity 集成件（实现 C）。
//!
//! 架构（wrapPath 批量方案）：批量电路 = [`BatchCircuit`] 的 sub_n 语句实例
//! （共享 program_hash 绑定，2·sub_n+1 公开输入）；**同形状电路共享同一
//! verifying key**（R1CS 只由形状决定），故一次 seeded setup 可出 sub_count
//! 个证明。生产口径 64 手 = 4 × N16 证明同钥连验；本机（36GB，swap 封顶
//! 4GB）金向量缩样用 `--sub-n 4 --sub-count 2`（8 条语句、2 证明——单 8
//! 语句证明的 setup 峰值实测被系统 SIGKILL（EXIT_STATUS=137），K=4 峰值减半
//! 可过）。
//!
//! 产物（写入 `<zchain>/contracts/monad`，env `WRAP_ZCHAIN_DIR`）：
//! 1. `src/Groth16VerifierBatch.sol`（批量 VK；公开输入 2·sub_n+1）；
//! 2. `test/WrapBatchGolden.sol`（sub_count 个证明 + 全部语句 + keccak/appchain
//!    批根 + calldata 组装函数）；
//! 3. `test/WrapBatchGolden.json`（部署/离线对拍用）。
//!
//! trusted setup：固定种子单方仪式（测试网口径）。
//!
//! `--parallel`：sub_count 个同形状电路互不依赖，各起一个 OS 线程并发
//! prove（PK/VK 共享只读）。prove_with_pk 的 blinding RNG 固定种子
//! （SETUP_SEED ^ 0xD1CE），证明与电路序号一一对应、与出证时序无关，
//! 故产物与串行版逐字节一致；默认（无 flag）行为不变。

use anyhow::{Context, Result};
use groth16_wrap::batch::{self, BatchGoldenJson, BatchStatement};
use groth16_wrap::batch_circuit::{BatchCircuit, BatchHand};
use groth16_wrap::felt::{felt_from_hex, felt_to_be_bytes, felt_to_fr, felt_to_hex};
use groth16_wrap::golden;
use groth16_wrap::wrap_circuit::WrapStatement;
use groth16_wrap::{g1_to_hex, g2_to_hex, prove_with_pk, seeded_setup, verify_with_vk};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let arg_of = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    };
    let sub_n: usize = match arg_of("--sub-n") {
        Some(v) => v.parse().context("--sub-n")?,
        None => 4,
    };
    let sub_count: usize = match arg_of("--sub-count") {
        Some(v) => v.parse().context("--sub-count")?,
        None => 2,
    };
    // --parallel：布尔 flag（无值）。多电路并发出证，产物与串行逐字节一致。
    let parallel = args.iter().any(|a| a == "--parallel");
    anyhow::ensure!(
        sub_n.is_power_of_two() && sub_count.is_power_of_two(),
        "sub-n/sub-count 须为 2 的幂"
    );
    let total = sub_n * sub_count;
    anyhow::ensure!(total <= 64, "语句总数 ≤ 64（方案口径）");

    // ---- 语句：真实语句装载（--statements-json）或金向量派生（默认） ----
    // 真实模式：每手 16-felt 公开段 + fact；宿主按 fact-verify 同式重算 fact
    // 并核对 output[5]==hand_binding，任一不符即拒绝（fail-closed）。
    let statements_path = arg_of("--statements-json");
    let derived: Vec<(BatchStatement, groth16_wrap::wrap_circuit::WrapWitness)> =
        match &statements_path {
            Some(p) => {
                #[derive(serde::Deserialize)]
                struct RealHand {
                    hand_binding: String,
                    fact: String,
                    output: Vec<String>,
                }
                #[derive(serde::Deserialize)]
                struct RealStatements {
                    program_hash: String,
                    hands: Vec<RealHand>,
                }
                let rs: RealStatements = serde_json::from_str(
                    &std::fs::read_to_string(p).context("read statements json")?,
                )
                .context("parse statements json")?;
                let ph = felt_from_hex(&rs.program_hash)?;
                let mut out = Vec::with_capacity(rs.hands.len());
                for h in &rs.hands {
                    let binding = felt_from_hex(&h.hand_binding)?;
                    let fact = felt_from_hex(&h.fact)?;
                    let output = h
                        .output
                        .iter()
                        .map(|x| felt_from_hex(x))
                        .collect::<Result<Vec<_>, _>>()?;
                    let witness = groth16_wrap::wrap_circuit::WrapWitness { output };
                    witness.validate().map_err(anyhow::Error::msg)?;
                    let recomputed = witness.expected_fact(&ph);
                    anyhow::ensure!(
                        recomputed == fact,
                        "fact mismatch for binding {binding}（文件 {fact} ≠ 宿主重算 {recomputed}）"
                    );
                    anyhow::ensure!(
                        witness.output[5] == binding,
                        "output[5] != hand_binding（语句形状不符）"
                    );
                    out.push((
                        BatchStatement { program_hash: ph, hand_binding: binding, fact },
                        witness,
                    ));
                }
                anyhow::ensure!(
                    out.len() == total,
                    "statements: {} hands != sub_n×sub_count = {total}",
                    out.len()
                );
                out
            }
            None => {
                let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH)?;
                let base_binding = felt_from_hex(golden::GOLDEN_HAND_BINDING)?;
                batch::derive_batch_statements(
                    &program_hash,
                    &base_binding,
                    &golden::golden_witness()?.output,
                    total,
                )
            }
        };
    // ---- 语句：共享 program_hash（真实模式取首语句，派生模式即金向量） ----
    let program_hash = derived[0].0.program_hash;
    let statements: Vec<BatchStatement> = derived.iter().map(|(st, _)| *st).collect();

    // ---- 分片成 sub_count 个同形状批量电路 ----
    let mut circuits: Vec<BatchCircuit> = Vec::with_capacity(sub_count);
    for chunk in derived.chunks(sub_n) {
        let hands: Vec<BatchHand> = chunk
            .iter()
            .map(|(st, w)| BatchHand {
                statement: WrapStatement {
                    program_hash: felt_to_fr(&st.program_hash),
                    hand_binding: felt_to_fr(&st.hand_binding),
                    fact: felt_to_fr(&st.fact),
                },
                witness: w.clone(),
            })
            .collect();
        circuits.push(
            BatchCircuit::new(felt_to_fr(&program_hash), hands).map_err(anyhow::Error::msg)?,
        );
    }

    // ---- keccak 批根（全语句集合；链上 SettleBatch 校验口径） ----
    let keccak_root = batch::keccak_batch_root(&statements)?;
    // ---- appchain 批根（离线对拍口径） ----
    let bindings: Vec<[u8; 32]> =
        statements.iter().map(|s| felt_to_be_bytes(&s.hand_binding)).collect();
    let appchain_root = batch::appchain_batch_root(&bindings);
    println!("sub_n={sub_n} sub_count={sub_count} total_statements={total}");
    println!("keccak_root   = 0x{}", hex::encode(keccak_root));
    println!("appchain_root = 0x{}", hex::encode(appchain_root));

    // ---- 一次 setup（形状决定 VK），sub_count 个证明 ----
    let t = std::time::Instant::now();
    let pk = seeded_setup(circuits[0].clone())?;
    let t_setup = t.elapsed();
    let constraints = {
        use ark_relations::gr1cs::ConstraintSynthesizer;
        let cs = ark_relations::gr1cs::ConstraintSystem::<groth16_wrap::Fr>::new_ref();
        circuits[0].clone().generate_constraints(cs.clone())?;
        cs.num_constraints()
    };
    // prove：各电路互不依赖，共享同一 PK（只读）。--parallel 时每电路一个
    // OS 线程并发出证；blinding RNG 固定种子 → 证明字节与串行版逐位一致，
    // 结果按电路顺序收集（产物与 prove 时序无关）。
    // 内存/墙钟边界（2026-09-29 M3 Pro 12 核 36GB 实测，2×K4 = 18,331,967
    // 约束/电路、real8 语句，`/usr/bin/time -l` 口径）：ark-groth16 默认
    // parallel feature（rayon 全局池 = 全核），两路 prove 共用同一线程池、
    // CPU 不超订，但单电路 prove 工作集即 ~14GiB RSS，按电路数叠加：
    // - 串行（默认）：全流程 573.9s（setup 204.0s + 2×prove ≈184s），峰值
    //   RSS 20.1GiB、footprint 55.5GiB —— 串行本身已贴物理内存上限；
    // - --parallel K4×2：两路并发 footprint ≥53.6GiB，swap 飙至 37GB 颠簸，
    //   773.7s 仍未出完证（比串行慢）——本机（36GB）K4+ 不可并行；
    // - --parallel K2×2（9.17M 约束/电路）：产物与串行逐字节一致，但墙钟
    //   215.8s vs 串行 221.7s 仅 -2.7%（共享池下两路 prove 总 CPU 功不变、
    //   几乎无重叠收益），footprint 24.0→43.4GiB。
    // 结论：--parallel 不省墙钟、费内存（K4 换 swap 抖动）。默认串行；
    // 仅 ≥64GB 机器可开它避免 swap（墙钟收益 ≈0）。要真正降墙钟需降约束
    // 数 / 换证明系统 / 缓存 setup 产物，不在本 CLI 范围。
    let proven: Vec<_> = if parallel && sub_count > 1 {
        println!("prove mode: parallel（{sub_count} 电路各一线程并发）");
        std::thread::scope(|s| -> Result<Vec<_>> {
            let handles: Vec<_> = circuits
                .iter()
                .map(|c| s.spawn(|| prove_with_pk(&pk, c)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().map_err(|_| anyhow::anyhow!("prove 线程 panic"))?)
                .collect()
        })?
    } else {
        circuits
            .iter()
            .map(|c| prove_with_pk(&pk, c))
            .collect::<Result<Vec<_>>>()?
    };
    let mut proofs = Vec::with_capacity(sub_count);
    for (j, c) in circuits.iter().enumerate() {
        let proof = &proven[j];
        let mut publics = vec![c.program_hash];
        for h in &c.hands {
            publics.push(h.statement.hand_binding);
            publics.push(h.statement.fact);
        }
        let ok = verify_with_vk(&pk.vk, &publics, proof)?;
        anyhow::ensure!(ok, "sub-proof {j} 本地 verify FAILED");
        proofs.push((proof.clone(), publics));
    }
    println!("setup done in {:?}", t_setup);
    println!(
        "setup + {sub_count} prove done in {:?}（单电路约束 {constraints}）",
        t.elapsed()
    );

    // ---- VK 常量 ----
    let alpha = g1_to_hex(&pk.vk.alpha_g1);
    let beta = g2_to_hex(&pk.vk.beta_g2);
    let gamma = g2_to_hex(&pk.vk.gamma_g2);
    let delta = g2_to_hex(&pk.vk.delta_g2);
    let ic: Vec<[String; 2]> = pk.vk.gamma_abc_g1.iter().map(g1_to_hex).collect();
    // IC = 常量项 + 每公开输入系数 → 长度 = (2N+1) + 1
    anyhow::ensure!(
        ic.len() == 2 * sub_n + 2,
        "IC len = {}（期望 {}）",
        ic.len(),
        2 * sub_n + 2
    );

    let g2_evm = |v: &[[String; 2]; 2]| -> [String; 4] {
        // EIP-197 Fp2 = a·i + b，字序 (虚部 c1, 实部 c0)（配平式实测钉死）
        [v[0][1].clone(), v[0][0].clone(), v[1][1].clone(), v[1][0].clone()]
    };
    let beta_evm = g2_evm(&beta);
    let gamma_evm = g2_evm(&gamma);
    let delta_evm = g2_evm(&delta);

    let zchain = std::env::var("WRAP_ZCHAIN_DIR")
        .unwrap_or_else(|_| format!("{}/../../zchain", env!("CARGO_MANIFEST_DIR")));
    let zchain = std::path::PathBuf::from(zchain).canonicalize().context("zchain dir")?;

    // ---- 1) Groth16VerifierBatch.sol ----
    let mut vk = VERIFIER_TEMPLATE
        .replace("@@SUB_N@@", &sub_n.to_string())
        .replace("@@NUM_PUBS@@", &(2 * sub_n + 1).to_string())
        .replace("@@ALPHA_X@@", &alpha[0])
        .replace("@@ALPHA_Y@@", &alpha[1])
        .replace("@@BETA0@@", &beta_evm[0])
        .replace("@@BETA1@@", &beta_evm[1])
        .replace("@@BETA2C@@", &beta_evm[2])
        .replace("@@BETA3@@", &beta_evm[3])
        .replace("@@GAMMA0@@", &gamma_evm[0])
        .replace("@@GAMMA1@@", &gamma_evm[1])
        .replace("@@GAMMA2C@@", &gamma_evm[2])
        .replace("@@GAMMA3@@", &gamma_evm[3])
        .replace("@@DELTA0@@", &delta_evm[0])
        .replace("@@DELTA1@@", &delta_evm[1])
        .replace("@@DELTA2C@@", &delta_evm[2])
        .replace("@@DELTA3@@", &delta_evm[3]);
    let mut consts = String::new();
    let mut assigns = String::new();
    for (k, pt) in ic.iter().enumerate() {
        consts.push_str(&format!(
            "    uint256 internal constant VK_IC{k}_X = {};\n    uint256 internal constant VK_IC{k}_Y = {};\n",
            pt[0], pt[1]
        ));
        assigns.push_str(&format!("        ic[{k}] = [VK_IC{k}_X, VK_IC{k}_Y];\n"));
    }
    vk = vk
        .replace("@@VK_IC_CONSTANTS@@", &consts)
        .replace("@@IC_ASSIGNMENTS@@", &assigns)
        .replace("@@NUM_PUBS_PLUS_1@@", &(2 * sub_n + 2).to_string());
    let verifier_path = zchain.join("contracts/monad/src/Groth16VerifierBatch.sol");
    std::fs::write(&verifier_path, &vk)?;
    println!("written {}", verifier_path.display());

    // ---- 2) WrapBatchGolden.sol ----
    let mut proof_consts = String::new();
    let mut calldata_arms = String::new();
    for (j, (proof, publics)) in proofs.iter().enumerate() {
        let pa = g1_to_hex(&proof.a);
        let pb = g2_to_hex(&proof.b);
        let pc = g1_to_hex(&proof.c);
        let pb_evm = [
            [pb[0][1].clone(), pb[0][0].clone()],
            [pb[1][1].clone(), pb[1][0].clone()],
        ];
        proof_consts.push_str(&format!(
            "    uint256 constant P{j}_A0 = {};\n    uint256 constant P{j}_A1 = {};\n",
            pa[0], pa[1]
        ));
        proof_consts.push_str(&format!(
            "    uint256 constant P{j}_B0 = {};\n    uint256 constant P{j}_B1 = {};\n    uint256 constant P{j}_B2 = {};\n    uint256 constant P{j}_B3 = {};\n",
            pb_evm[0][0], pb_evm[0][1], pb_evm[1][0], pb_evm[1][1]
        ));
        proof_consts.push_str(&format!(
            "    uint256 constant P{j}_C0 = {};\n    uint256 constant P{j}_C1 = {};\n",
            pc[0], pc[1]
        ));
        let mut pub_assigns = String::new();
        for (k, fr) in publics.iter().enumerate() {
            pub_assigns.push_str(&format!(
                "            p[{k}] = {};\n",
                groth16_wrap::felt::fr_to_hex(fr)
            ));
        }
        calldata_arms.push_str(&format!(
            "        if (j == {j}) {{\n            a = [P{j}_A0, P{j}_A1];\n            b[0] = [P{j}_B0, P{j}_B1];\n            b[1] = [P{j}_B2, P{j}_B3];\n            c = [P{j}_C0, P{j}_C1];\n            p = new uint256[](2 * SUB_N + 1);\n{pub_assigns}            return (a, b, c, p);\n        }}\n"
        ));
    }
    let mut leaf_assigns = String::new();
    for (k, _st) in statements.iter().enumerate() {
        leaf_assigns.push_str(&format!(
            "        out[{k}] = keccak256(abi.encodePacked(uint32({k}), PROGRAM_HASH, HB{k}, FACT{k}));\n"
        ));
    }
    let mut hb_consts = String::new();
    for (k, s) in statements.iter().enumerate() {
        hb_consts.push_str(&format!(
            "    uint256 constant HB{k} = {};\n    uint256 constant FACT{k} = {};\n",
            felt_to_hex(&s.hand_binding),
            felt_to_hex(&s.fact)
        ));
    }
    let golden_sol = GOLDEN_TEMPLATE
        .replace("@@SUB_N@@", &sub_n.to_string())
        .replace("@@SUB_COUNT@@", &sub_count.to_string())
        .replace("@@TOTAL@@", &total.to_string())
        .replace("@@KECCAK_ROOT@@", &format!("0x{}", hex::encode(keccak_root)))
        .replace("@@APPCHAIN_ROOT@@", &format!("0x{}", hex::encode(appchain_root)))
        .replace("@@PROGRAM_HASH@@", &felt_to_hex(&program_hash))
        .replace("@@HB_CONSTANTS@@", &hb_consts)
        .replace("@@PROOF_CONSTANTS@@", &proof_consts)
        .replace("@@CALLDATA_ARMS@@", &calldata_arms)
        .replace("@@LEAF_ASSIGNMENTS@@", &leaf_assigns);
    let golden_path = zchain.join("contracts/monad/test/WrapBatchGolden.sol");
    std::fs::write(&golden_path, &golden_sol)?;
    println!("written {}", golden_path.display());

    // ---- 3) WrapBatchGolden.json ----
    let golden_json = BatchGoldenJson {
        batch_n: sub_n,
        sub_count,
        program_hash: felt_to_hex(&program_hash),
        hand_bindings: statements
            .iter()
            .map(|s| felt_to_hex(&s.hand_binding))
            .collect(),
        facts: statements.iter().map(|s| felt_to_hex(&s.fact)).collect(),
        keccak_root: format!("0x{}", hex::encode(keccak_root)),
        appchain_root: format!("0x{}", hex::encode(appchain_root)),
        proofs: proofs
            .iter()
            .map(|(p, _)| groth16_wrap::ProofJson::from_ark(p))
            .collect(),
        publics: proofs
            .iter()
            .map(|(_, p)| p.iter().map(|f| groth16_wrap::felt::fr_to_hex(f)).collect())
            .collect(),
    };
    let json_path = zchain.join("contracts/monad/test/WrapBatchGolden.json");
    std::fs::write(&json_path, serde_json::to_string_pretty(&golden_json)?)?;
    println!("written {}", json_path.display());
    println!("gen-sol-batch: OK（重跑输出字节级一致）");
    Ok(())
}

const VERIFIER_TEMPLATE: &str = r#"// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @notice groth16-wrap 批量包裹电路（BN254，N=@@SUB_N@@ 条语句/证明）的
///         Groth16 verifier。
/// @dev 由 poker_texas_air/groth16-wrap 的 `gen-sol-batch --sub-n @@SUB_N@@`
///      生成，VK 来自固定种子单方仪式 —— **测试网口径**；主网部署必须换
///      MPC powers-of-tau ceremony。公开输入 2N+1 =
///      [program_hash, hand_binding_1, fact_1, …, hand_binding_N, fact_N]，
///      语义与单手电路逐字段相同（N 份并列、共享 program_hash 绑定）。
///      同形状电路共享本 VK：生产 64 手 = 4 × N16 证明连验，即同一 VK。
///      本合约 **不验证 STARK**。
contract Groth16VerifierBatch {
    // BN254 基域（EIP-197 alt_bn128 Fp）
    uint256 internal constant P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    uint256 internal constant SUB_N = @@SUB_N@@;
    uint256 internal constant NUM_PUBS = @@NUM_PUBS@@;

    // ---- Verifying Key（gen-sol-batch 注入；G2 字序 = EIP-197 (虚部 c1, 实部 c0)；
    //      solc 0.8 不支持数组型 constant，全部展开为标量） ----
    uint256 internal constant VK_ALPHA1_X = @@ALPHA_X@@;
    uint256 internal constant VK_ALPHA1_Y = @@ALPHA_Y@@;
    uint256 internal constant VK_BETA2_0 = @@BETA0@@;
    uint256 internal constant VK_BETA2_1 = @@BETA1@@;
    uint256 internal constant VK_BETA2_2 = @@BETA2C@@;
    uint256 internal constant VK_BETA2_3 = @@BETA3@@;
    uint256 internal constant VK_GAMMA2_0 = @@GAMMA0@@;
    uint256 internal constant VK_GAMMA2_1 = @@GAMMA1@@;
    uint256 internal constant VK_GAMMA2_2 = @@GAMMA2C@@;
    uint256 internal constant VK_GAMMA2_3 = @@GAMMA3@@;
    uint256 internal constant VK_DELTA2_0 = @@DELTA0@@;
    uint256 internal constant VK_DELTA2_1 = @@DELTA1@@;
    uint256 internal constant VK_DELTA2_2 = @@DELTA2C@@;
    uint256 internal constant VK_DELTA2_3 = @@DELTA3@@;
@@VK_IC_CONSTANTS@@
    error PairingPrecompileFailed();
    error EcOpPrecompileFailed();
    error BadPublicInputsLength();

    /// @notice 验证一个批量证明（覆盖 @@SUB_N@@ 条语句）。
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata _pubSignals
    ) external view returns (bool) {
        if (_pubSignals.length != NUM_PUBS) revert BadPublicInputsLength();
        // vk_x = IC0 + Σ pubSignals[i] · IC(i+1)（0x07 拒绝 ≥p 非规范标量
        // → 公开输入隐式域检查）
        uint256[2] memory vkx = [VK_IC0_X, VK_IC0_Y];
        uint256[2][@@NUM_PUBS_PLUS_1@@] memory ic;
@@IC_ASSIGNMENTS@@
        uint256[2] memory q;
        for (uint256 i = 0; i < _pubSignals.length; ++i) {
            q = ic[i + 1];
            vkx = _mulAdd(vkx, _pubSignals[i], q);
        }
        return _pairingCheck(_pA, _pB, _pC, vkx);
    }

    /// vk_x = p + s·q：先 0x07 求 q·s，再 0x06 加到 p。
    function _mulAdd(
        uint256[2] memory p,
        uint256 s,
        uint256[2] memory q
    ) internal view returns (uint256[2] memory) {
        (bool okM, bytes memory outM) = address(0x07).staticcall(
            abi.encodePacked(q[0], q[1], s)
        );
        if (!okM || outM.length != 64) revert EcOpPrecompileFailed();
        (uint256 mx, uint256 my) = abi.decode(outM, (uint256, uint256));
        (bool okA, bytes memory outA) = address(0x06).staticcall(
            abi.encodePacked(p[0], p[1], mx, my)
        );
        if (!okA || outA.length != 64) revert EcOpPrecompileFailed();
        uint256[2] memory out;
        (out[0], out[1]) = abi.decode(outA, (uint256, uint256));
        return out;
    }

    /// Groth16 配平：e(-A, B) · e(vk_x, γ) · e(C, δ) == e(α, β)。
    /// 分段拼接 bytes 以规避 stack too deep（不开 via-IR）。
    function _pairingCheck(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[2] memory vkx
    ) internal view returns (bool) {
        // EIP-197 每对 192B：G1(x, y) + G2(X_i, X_r, Y_i, Y_r)
        bytes memory segA = abi.encodePacked(_pA[0], _neg(_pA[1]), _pB[0][0], _pB[0][1], _pB[1][0], _pB[1][1]);
        bytes memory segG = abi.encodePacked(vkx[0], vkx[1], VK_GAMMA2_0, VK_GAMMA2_1, VK_GAMMA2_2, VK_GAMMA2_3);
        bytes memory segC = abi.encodePacked(_pC[0], _pC[1], VK_DELTA2_0, VK_DELTA2_1, VK_DELTA2_2, VK_DELTA2_3);
        bytes memory segV = abi.encodePacked(VK_ALPHA1_X, VK_ALPHA1_Y, VK_BETA2_0, VK_BETA2_1, VK_BETA2_2, VK_BETA2_3);
        bytes memory input = bytes.concat(segA, segG, segC, segV);
        (bool ok, bytes memory out) = address(0x08).staticcall(input);
        if (!ok || out.length != 32) revert PairingPrecompileFailed();
        return abi.decode(out, (bool));
    }

    function _neg(uint256 v) internal pure returns (uint256) {
        unchecked {
            return v == 0 ? 0 : P - v;
        }
    }
}
"#;

const GOLDEN_TEMPLATE: &str = r#"// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @notice groth16-wrap 批量金向量（gen-sol-batch --sub-n @@SUB_N@@
///         --sub-count @@SUB_COUNT@@ 生成；@@TOTAL@@ 条语句、@@SUB_COUNT@@ 个
///         证明共享同一 VK —— 与生产「64 手 = 4 × N16 连验」同构）。
/// @dev keccak 根 = SettleBatch 链上口径（leaf_i =
///         keccak256(uint32(i) ‖ program_hash ‖ hand_binding ‖ fact)，两两
///         折叠）；appchain 根 = poker-appchain pipeline.rs::batch_root 的
///         离线对拍口径（Monad 无 Poseidon 预编译，链上验不了）。
library BatchGolden {
    uint256 constant SUB_N = @@SUB_N@@;
    uint256 constant SUB_COUNT = @@SUB_COUNT@@;
    uint256 constant TOTAL_STATEMENTS = @@TOTAL@@;
    bytes32 constant KECCAK_ROOT = @@KECCAK_ROOT@@;
    bytes32 constant APPCHAIN_ROOT = @@APPCHAIN_ROOT@@;
    uint256 constant PROGRAM_HASH = @@PROGRAM_HASH@@;

@@HB_CONSTANTS@@

@@PROOF_CONSTANTS@@

    /// 第 j 个证明的 calldata（a/b/c + 该证明的 2N+1 公开输入）。
    function proofCalldata(uint256 j)
        internal pure
        returns (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[] memory p
        )
    {
@@CALLDATA_ARMS@@
        revert("no such proof");
    }

    /// keccak 叶子数组（语句顺序 = 电路语句序）。
    function leafs() internal pure returns (bytes32[] memory out) {
        out = new bytes32[](TOTAL_STATEMENTS);
@@LEAF_ASSIGNMENTS@@
    }
}
"#;
