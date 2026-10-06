//! gen-sol —— 生成金向量与 Solidity 集成件（确定性：setup/prove 全部固定种子）。
//!
//! 产物：
//! 1. `src/golden.rs`（本 crate 的金向量常量 + 解析函数）；
//! 2. `<zchain>/contracts/monad/src/Groth16Verifier.sol`（VK 常量注入）；
//! 3. `<zchain>/contracts/monad/test/WrapGoldenVector.sol`（证明 + 语句常量）。
//!
//! zchain 目录默认 `<manifest>/../../zchain`，可用环境变量 `WRAP_ZCHAIN_DIR` 覆盖。
//!
//! trusted setup 口径：固定种子单方仪式（测试网）。重跑本 bin 输出字节级一致。

use anyhow::{Context, Result};
use groth16_wrap::felt::{felt_from_hex, felt_to_fr, felt_to_hex};
use groth16_wrap::wrap_circuit::{WrapCircuit, WrapStatement, WrapWitness};
use groth16_wrap::{g1_to_hex, g2_to_hex, prove_with_pk, seeded_setup, verify_with_vk, Felt252};

/// 真实 prove-hand 产物的公开内存段（proving-tool/output/settlement/
/// public_outputs.json；program_hash = 主网钉扎值 0x744d16d3…）。
const GOLDEN_OUTPUT_HEX: [&str; 16] = [
    "0xf",
    "0x5350324d5f4f4b",
    "0x2a",
    "0x5364144191559f1422d70c68e974e5989e264e83fb0e794c23b60dcf03f6643",
    "0x3",
    "0xa6aa",
    "0x1995ebc947b50c02308072edc9387047e415b0519d6ff88920ed4eae2aa803e",
    "0x0",
    "0x0",
    "0x0",
    "0x0",
    "0x0",
    "0x0",
    "0x0",
    "0x429d069189e0000",
    "0x7655f9f71d5bbf3607ad0c2921cfa3b28d24cd6cdd4f5407059ba1293697a01",
];
const GOLDEN_PROGRAM_HASH_HEX: &str =
    "0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4";
const GOLDEN_HAND_BINDING_HEX: &str =
    "0x000000000000000000000000000000000000000000000000000000000000a6aa";

fn arr2(v: &[String; 2]) -> String {
    format!("[{:?}, {:?}]", v[0], v[1])
}
fn arr22(v: &[[String; 2]; 2]) -> String {
    format!("[{}, {}]", arr2(&v[0]), arr2(&v[1]))
}

fn main() -> Result<()> {
    // ---- 语句 + 见证（真实形状） ----
    let program_hash = felt_from_hex(GOLDEN_PROGRAM_HASH_HEX)?;
    let output: Vec<Felt252> = GOLDEN_OUTPUT_HEX
        .iter()
        .map(|h| felt_from_hex(h))
        .collect::<Result<_, _>>()?;
    let witness = WrapWitness { output };
    witness.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
    let hand_binding = felt_from_hex(GOLDEN_HAND_BINDING_HEX)?;
    let fact = witness.expected_fact(&program_hash);
    let statement = WrapStatement {
        program_hash: felt_to_fr(&program_hash),
        hand_binding: felt_to_fr(&hand_binding),
        fact: felt_to_fr(&fact),
    };
    println!("fact = {}", felt_to_hex(&fact));

    // ---- seeded setup + prove + 本地验证 ----
    let circuit = WrapCircuit {
        statement,
        witness: witness.clone(),
    };
    let t = std::time::Instant::now();
    let pk = seeded_setup(circuit.clone()).context("setup")?;
    {
        use ark_relations::gr1cs::ConstraintSynthesizer;
        let cs = ark_relations::gr1cs::ConstraintSystem::<groth16_wrap::Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone())?;
        eprintln!("setup done in {:?}（约束 {}）", t.elapsed(), cs.num_constraints());
    }
    let proof = prove_with_pk(&pk, &circuit).context("prove")?;
    let ok = verify_with_vk(
        &pk.vk,
        &[statement.program_hash, statement.hand_binding, statement.fact],
        &proof,
    )?;
    anyhow::ensure!(ok, "本地验证失败，拒绝生成产物");

    let alpha = g1_to_hex(&pk.vk.alpha_g1);
    let beta = g2_to_hex(&pk.vk.beta_g2);
    let gamma = g2_to_hex(&pk.vk.gamma_g2);
    let delta = g2_to_hex(&pk.vk.delta_g2);
    let ic: Vec<[String; 2]> = pk.vk.gamma_abc_g1.iter().map(g1_to_hex).collect();
    anyhow::ensure!(ic.len() == 4, "IC len = {}（期望 3 公开输入 + 1）", ic.len());
    let pa = g1_to_hex(&proof.a);
    let pb = g2_to_hex(&proof.b);
    let pc = g1_to_hex(&proof.c);

    // ---- 1) 生成 src/golden.rs ----
    let golden_rs = GOLDEN_RS_TEMPLATE
        .replace("@@FACT@@", &felt_to_hex(&fact))
        .replace("@@ALPHA@@", &arr2(&alpha))
        .replace("@@BETA@@", &arr22(&beta))
        .replace("@@GAMMA@@", &arr22(&gamma))
        .replace("@@DELTA@@", &arr22(&delta))
        .replace("@@IC@@", &ic.iter().map(arr2).collect::<Vec<_>>().join(", "))
        .replace("@@PA@@", &arr2(&pa))
        .replace("@@PB@@", &arr22(&pb))
        .replace("@@PC@@", &arr2(&pc))
        .replace("@@OUTPUT@@", &GOLDEN_OUTPUT_HEX.iter().map(|h| format!("{h:?}")).collect::<Vec<_>>().join(", "));
    let golden_rs_path = format!("{}/src/golden.rs", env!("CARGO_MANIFEST_DIR"));
    std::fs::write(&golden_rs_path, &golden_rs)?;
    println!("written {}", golden_rs_path);

    // ---- 2) 生成 Groth16Verifier.sol（VK 注入；G2 以 EVM 字序 [c1,c0] 存） ----
    // solc 0.8 不支持数组型 constant —— 全部展开为 uint256 标量常量。
    let g2_evm = |v: &[[String; 2]; 2]| -> [String; 4] {
        // EIP-197 Fp2 = a·i + b，字序 (a, b) = (虚部 c1, 实部 c0)；
        // twist 成员资格实测：ark G2 = c0 + c1·u，故 EVM 字必为 (c1, c0)
        [v[0][1].clone(), v[0][0].clone(), v[1][1].clone(), v[1][0].clone()]
    };
    let beta_evm = g2_evm(&beta);
    let gamma_evm = g2_evm(&gamma);
    let delta_evm = g2_evm(&delta);
    let verifier_sol = VERIFIER_TEMPLATE
        .replace("@@ALPHA_X@@", &alpha[0])
        .replace("@@ALPHA_Y@@", &alpha[1])
        .replace("@@BETA0@@", &beta_evm[0]).replace("@@BETA1@@", &beta_evm[1])
        .replace("@@BETA2C@@", &beta_evm[2]).replace("@@BETA3@@", &beta_evm[3])
        .replace("@@GAMMA0@@", &gamma_evm[0]).replace("@@GAMMA1@@", &gamma_evm[1])
        .replace("@@GAMMA2C@@", &gamma_evm[2]).replace("@@GAMMA3@@", &gamma_evm[3])
        .replace("@@DELTA0@@", &delta_evm[0]).replace("@@DELTA1@@", &delta_evm[1])
        .replace("@@DELTA2C@@", &delta_evm[2]).replace("@@DELTA3@@", &delta_evm[3])
        .replace("@@IC0_X@@", &ic[0][0]).replace("@@IC0_Y@@", &ic[0][1])
        .replace("@@IC1_X@@", &ic[1][0]).replace("@@IC1_Y@@", &ic[1][1])
        .replace("@@IC2_X@@", &ic[2][0]).replace("@@IC2_Y@@", &ic[2][1])
        .replace("@@IC3_X@@", &ic[3][0]).replace("@@IC3_Y@@", &ic[3][1]);
    let zchain = std::env::var("WRAP_ZCHAIN_DIR")
        .unwrap_or_else(|_| format!("{}/../../zchain", env!("CARGO_MANIFEST_DIR")));
    let zchain = std::path::PathBuf::from(zchain).canonicalize().context("zchain dir")?;
    let verifier_path = zchain.join("contracts/monad/src/Groth16Verifier.sol");
    std::fs::write(&verifier_path, &verifier_sol)?;
    println!("written {}", verifier_path.display());

    // ---- 3) 生成 WrapGoldenVector.sol（calldata 顺序常量） ----
    let golden_sol = GOLDEN_SOL_TEMPLATE
        .replace("@@PA0@@", &pa[0])
        .replace("@@PA1@@", &pa[1])
        .replace("@@PB0@@", &pb[0][1]) // EVM 字序 (c1, c0)：Fp2 虚部在前
        .replace("@@PB1@@", &pb[0][0])
        .replace("@@PB2@@", &pb[1][1])
        .replace("@@PB3@@", &pb[1][0])
        .replace("@@PC0@@", &pc[0])
        .replace("@@PC1@@", &pc[1])
        .replace("@@PUB0@@", &felt_to_hex(&program_hash))
        .replace("@@PUB1@@", &felt_to_hex(&hand_binding))
        .replace("@@PUB2@@", &felt_to_hex(&fact));
    let golden_sol_path = zchain.join("contracts/monad/test/WrapGoldenVector.sol");
    std::fs::write(&golden_sol_path, &golden_sol)?;
    println!("written {}", golden_sol_path.display());

    println!("gen-sol: OK（重跑输出字节级一致）");
    Ok(())
}

const GOLDEN_RS_TEMPLATE: &str = r#"//! 金向量常量与解析函数 —— 由 `cargo run -p groth16-wrap --bin gen-sol` 生成。
//!
//! 金向量 = 固定种子 trusted setup + 真实形状 witness（settlement 公开段）的
//! Groth16 证明；重跑 gen-sol 输出字节级一致。消费方：zchain contracts/monad
//! 的 Groth16Verifier.sol / WrapGoldenVector.sol / WrapSettle.t.sol。
//!
//! trusted setup 口径：固定种子单方仪式（测试网口径；主网需 MPC ceremony）。

use crate::felt::{felt_from_hex, felt_to_fr, felt_to_hex, fq_from_hex};
use crate::wrap_circuit::{WrapStatement, WrapWitness};

/// 金向量语句 program_hash（主网钉扎的 settlement 电路哈希）。
pub const GOLDEN_PROGRAM_HASH: &str = "0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4";
/// 金向量语句 hand_binding。
pub const GOLDEN_HAND_BINDING: &str = "0x000000000000000000000000000000000000000000000000000000000000a6aa";
/// 金向量语句 fact（= poseidon_hash_many(program_hash ‖ output)，宿主重算自证）。
pub const GOLDEN_FACT: &str = "@@FACT@@";
/// 金向量见证：完整公开内存段（16 felts，长度前缀 15 + 15 felt 返回数组）。
pub const GOLDEN_OUTPUT: [&str; 16] = [@@OUTPUT@@];

/// VK alpha（G1, [x, y]）。
pub const GOLDEN_VK_ALPHA_G1: [&str; 2] = @@ALPHA@@;
/// VK beta（G2，ark 顺序 [[x.c0, x.c1], [y.c0, y.c1]]）。
pub const GOLDEN_VK_BETA_G2: [[&str; 2]; 2] = @@BETA@@;
/// VK gamma（G2，ark 顺序）。
pub const GOLDEN_VK_GAMMA_G2: [[&str; 2]; 2] = @@GAMMA@@;
/// VK delta（G2，ark 顺序）。
pub const GOLDEN_VK_DELTA_G2: [[&str; 2]; 2] = @@DELTA@@;
/// VK IC（gamma_abc_g1，4 点 = 常量项 + 3 公开输入系数）。
pub const GOLDEN_VK_IC_G1: [[&str; 2]; 4] = [@@IC@@];

/// 金向量证明 A（G1）。
pub const GOLDEN_PROOF_A: [&str; 2] = @@PA@@;
/// 金向量证明 B（G2，ark 顺序；EVM/calldata 顺序见 ProofJson::b_evm）。
pub const GOLDEN_PROOF_B: [[&str; 2]; 2] = @@PB@@;
/// 金向量证明 C（G1）。
pub const GOLDEN_PROOF_C: [&str; 2] = @@PC@@;

/// 金向量见证。
///
/// # Errors
/// 常量非法（生成器保证不发生）。
pub fn golden_witness() -> anyhow::Result<WrapWitness> {
    let output = GOLDEN_OUTPUT.iter().map(|h| felt_from_hex(h)).collect::<anyhow::Result<Vec<_>>>()?;
    Ok(WrapWitness { output })
}

/// 金向量语句（fact 宿主重算并对照常量，双保险）。
///
/// # Errors
/// 常量非法或事实不符（不该发生）。
pub fn golden_statement() -> anyhow::Result<WrapStatement> {
    let program_hash = felt_from_hex(GOLDEN_PROGRAM_HASH)?;
    let witness = golden_witness()?;
    witness.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
    let fact = witness.expected_fact(&program_hash);
    anyhow::ensure!(felt_to_hex(&fact) == GOLDEN_FACT, "GOLDEN_FACT 常量与重算不符");
    Ok(WrapStatement {
        program_hash: felt_to_fr(&program_hash),
        hand_binding: felt_to_fr(&felt_from_hex(GOLDEN_HAND_BINDING)?),
        fact: felt_to_fr(&fact),
    })
}

fn g1(p: &[&str; 2]) -> anyhow::Result<ark_bn254::G1Affine> {
    Ok(ark_bn254::G1Affine::new(fq_from_hex(p[0])?, fq_from_hex(p[1])?))
}
fn g2(p: &[[&str; 2]; 2]) -> anyhow::Result<ark_bn254::G2Affine> {
    Ok(ark_bn254::G2Affine::new(
        ark_bn254::Fq2::new(fq_from_hex(p[0][0])?, fq_from_hex(p[0][1])?),
        ark_bn254::Fq2::new(fq_from_hex(p[1][0])?, fq_from_hex(p[1][1])?),
    ))
}

/// 金向量 verifying key。
///
/// # Errors
/// 常量非法（不该发生）。
pub fn golden_verifying_key() -> anyhow::Result<ark_groth16::VerifyingKey<ark_bn254::Bn254>> {
    Ok(ark_groth16::VerifyingKey {
        alpha_g1: g1(&GOLDEN_VK_ALPHA_G1)?,
        beta_g2: g2(&GOLDEN_VK_BETA_G2)?,
        gamma_g2: g2(&GOLDEN_VK_GAMMA_G2)?,
        delta_g2: g2(&GOLDEN_VK_DELTA_G2)?,
        gamma_abc_g1: GOLDEN_VK_IC_G1.iter().map(g1).collect::<anyhow::Result<Vec<_>>>()?,
    })
}

/// 金向量证明。
///
/// # Errors
/// 常量非法（不该发生）。
pub fn golden_proof() -> anyhow::Result<ark_groth16::Proof<ark_bn254::Bn254>> {
    Ok(ark_groth16::Proof {
        a: g1(&GOLDEN_PROOF_A)?,
        b: g2(&GOLDEN_PROOF_B)?,
        c: g1(&GOLDEN_PROOF_C)?,
    })
}
"#;

const VERIFIER_TEMPLATE: &str = r#"// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @notice groth16-wrap 单手包裹电路（BN254）的 Groth16 verifier。
/// @dev 由 poker_texas_air/groth16-wrap 的 `gen-sol` 生成，VK 常量来自固定
///      种子的单方仪式 —— **测试网口径**；主网部署必须换 MPC powers-of-tau
///      ceremony 并重新生成 VK。
///      语句（3 个公开输入）：[program_hash, hand_binding, fact]，语义为
///      fact == poseidon_hash_many([program_hash ‖ output]) 且 output 形状
///      合法且 output[5] == hand_binding。本合约 **不验证 STARK**。
contract Groth16Verifier {
    // BN254 基域（EIP-197 alt_bn128 Fp）
    uint256 internal constant P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // ---- Verifying Key（gen-sol 注入；G2 字序 = EIP-197 (虚部 c1, 实部 c0)；
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
    uint256 internal constant VK_IC0_X = @@IC0_X@@;
    uint256 internal constant VK_IC0_Y = @@IC0_Y@@;
    uint256 internal constant VK_IC1_X = @@IC1_X@@;
    uint256 internal constant VK_IC1_Y = @@IC1_Y@@;
    uint256 internal constant VK_IC2_X = @@IC2_X@@;
    uint256 internal constant VK_IC2_Y = @@IC2_Y@@;
    uint256 internal constant VK_IC3_X = @@IC3_X@@;
    uint256 internal constant VK_IC3_Y = @@IC3_Y@@;

    error PairingPrecompileFailed();
    error EcOpPrecompileFailed();

    /// @notice 验证单手包裹证明。
    /// @param _pA 证明 A（G1 [x, y]）
    /// @param _pB 证明 B（G2，EVM 字序 [[X_i, X_r], [Y_i, Y_r]]（Fp2 虚部在
    ///        前，EIP-197 a·i+b 编码；与 wrap-proof 产物 JSON 的 proof.b_evm
    ///        一致）——配平输入直接铺入
    /// @param _pC 证明 C（G1 [x, y]）
    /// @param _pubSignals [programHash, handBinding, fact]
    /// @dev 拆小函数避免 stack too deep（不开 via-IR，与 build_solc.sh 口径一致）。
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[3] calldata _pubSignals
    ) external view returns (bool) {
        // vk_x = IC0 + Σ pubSignals[i] · IC(i+1)
        // （0x07 拒绝 ≥p 的非规范标量 → 公开输入隐式域检查）
        uint256[2] memory vkx = [VK_IC0_X, VK_IC0_Y];
        vkx = _mulAdd(vkx, _pubSignals[0], VK_IC1_X, VK_IC1_Y);
        vkx = _mulAdd(vkx, _pubSignals[1], VK_IC2_X, VK_IC2_Y);
        vkx = _mulAdd(vkx, _pubSignals[2], VK_IC3_X, VK_IC3_Y);
        uint256[2] memory a = [_pA[0], _pA[1]];
        uint256[2][2] memory b = [_pB[0], _pB[1]];
        uint256[2] memory c = [_pC[0], _pC[1]];
        return _pairingCheck(a, b, c, vkx);
    }

    /// vk_x = p + s·q：先 0x07 求 q·s（标量乘 **IC 点**），再 0x06 加到 p。
    /// （初版误把累加元做了标量乘——金向量 forge 测试钉出的 bug。）
    function _mulAdd(
        uint256[2] memory p,
        uint256 s,
        uint256 qx,
        uint256 qy
    ) internal view returns (uint256[2] memory) {
        (bool okM, bytes memory outM) = address(0x07).staticcall(
            abi.encodePacked(qx, qy, s)
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
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory vkx
    ) internal view returns (bool) {
        // EIP-197 每对 192B：G1(x, y) + G2(X_i, X_r, Y_i, Y_r)；calldata 的
        // _pB 已是 EVM 字序，直接铺入
        bytes memory segA = abi.encodePacked(a[0], _neg(a[1]), b[0][0], b[0][1], b[1][0], b[1][1]);
        bytes memory segG = abi.encodePacked(vkx[0], vkx[1], VK_GAMMA2_0, VK_GAMMA2_1, VK_GAMMA2_2, VK_GAMMA2_3);
        bytes memory segC = abi.encodePacked(c[0], c[1], VK_DELTA2_0, VK_DELTA2_1, VK_DELTA2_2, VK_DELTA2_3);
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

const GOLDEN_SOL_TEMPLATE: &str = r#"// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @notice groth16-wrap 金向量（gen-sol 生成；与 Groth16Verifier.sol 的 VK
///         同一次固定种子 setup 产出）。
/// @dev calldata 字序：G2 为 EVM 字序 [i系数, 实系数]（= wrap-proof 产物
///         JSON 的 proof.b_evm）。solc 0.8 不支持数组型 constant ——
///         全部展开为标量；组装见 WrapSettle.t.sol。
library Golden {
    /// 证明 A（G1 x, y）。
    uint256 constant A0 = @@PA0@@;
    uint256 constant A1 = @@PA1@@;
    /// 证明 B（G2，EVM/calldata 字序 [Xi, Xr, Yi, Yr]）。
    uint256 constant B0 = @@PB0@@;
    uint256 constant B1 = @@PB1@@;
    uint256 constant B2 = @@PB2@@;
    uint256 constant B3 = @@PB3@@;
    /// 证明 C（G1 x, y）。
    uint256 constant C0 = @@PC0@@;
    uint256 constant C1 = @@PC1@@;
    /// 公开语句 [programHash, handBinding, fact]。
    uint256 constant PUB0 = @@PUB0@@;
    uint256 constant PUB1 = @@PUB1@@;
    uint256 constant PUB2 = @@PUB2@@;
}
"#;
