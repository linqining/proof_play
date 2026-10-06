//! 金向量常量与解析函数 —— 由 `cargo run -p groth16-wrap --bin gen-sol` 生成。
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
pub const GOLDEN_FACT: &str = "0x030675cf10171e01d672af7b19fcbd51c0e5f88bc8f5932186cc581e297c0ea5";
/// 金向量见证：完整公开内存段（16 felts，长度前缀 15 + 15 felt 返回数组）。
pub const GOLDEN_OUTPUT: [&str; 16] = ["0xf", "0x5350324d5f4f4b", "0x2a", "0x5364144191559f1422d70c68e974e5989e264e83fb0e794c23b60dcf03f6643", "0x3", "0xa6aa", "0x1995ebc947b50c02308072edc9387047e415b0519d6ff88920ed4eae2aa803e", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x429d069189e0000", "0x7655f9f71d5bbf3607ad0c2921cfa3b28d24cd6cdd4f5407059ba1293697a01"];

/// VK alpha（G1, [x, y]）。
pub const GOLDEN_VK_ALPHA_G1: [&str; 2] = ["0x229a9bba3e2ec298421ee522cbe43bf85c7a6520cff8040932df6fd00ec91299", "0x089b02f449d88577eb97bb1de2cd706d6bce159d305eeedc2f120fd59d627e87"];
/// VK beta（G2，ark 顺序 [[x.c0, x.c1], [y.c0, y.c1]]）。
pub const GOLDEN_VK_BETA_G2: [[&str; 2]; 2] = [["0x054a5c7f2ef53a63c982f9e0a8789c4195006760dade42c87b22038cb22454a9", "0x2db156a56688e73d697c5c955e0f4feae0244debd46583b3f4cc89239208cc04"], ["0x26fe1e63176ef4a7cf8562cd980f05d1e992b9cbf28eb5d20d3dfe9ea202e329", "0x11dd77b7501816361b5dc528314f0864c9fcc5903f10ee11186bacba8076f5f4"]];
/// VK gamma（G2，ark 顺序）。
pub const GOLDEN_VK_GAMMA_G2: [[&str; 2]; 2] = [["0x2a2df1e80152bbfd96b18e8f534016216a0b16234fdb85b9136f4137be794473", "0x13bfc874545c7adc450a1e087d17c9942f775be5dc2b7d5089f88d91def4e896"], ["0x2b55caf98584b2394b1d0aa560ebd002e6a17539c02aca49a5077995f9983ec5", "0x0801fa0f37bc3786fdd4c903d1c5ae2627dd39b558ee9c6951659562e372a2a4"]];
/// VK delta（G2，ark 顺序）。
pub const GOLDEN_VK_DELTA_G2: [[&str; 2]; 2] = [["0x215f18a3fcb939e8da53b1f187c4b38efa235317188d10c9a125838ecb2b1d82", "0x19d65d0aac55a4e7ae9d7351fb909bb9de7a691756df9688f83e86e18f80f63b"], ["0x2b323d1aed273d1989498e5bf97154fe33368339f86992b3fd4408f393210df1", "0x17cc0c58b35060ee50d78791138f0a395fb438af9d4b586c86db2e95b64bcc43"]];
/// VK IC（gamma_abc_g1，4 点 = 常量项 + 3 公开输入系数）。
pub const GOLDEN_VK_IC_G1: [[&str; 2]; 4] = [["0x13ecf783140e207fdd5fb5a1455ca86b1de9463b4c8a737c5c5b99af440cd56d", "0x06105c964dc195610658c475971bcb967417ecedf5f2fc2c6d965732bdf8dc0f"], ["0x0b447623a87298eb1d1f48ce7643b925cf6a2e4c0400e96491d2a6402d43733b", "0x207f00ace3caf27b4d528f67ad41537219e754fd442a0642894e2bb8f2c201a1"], ["0x1d7a8ec437fee8e9f9148484e39a957e4dcaa3c6e330a1bc018d59a5d694e143", "0x03f40e99a742b63a70d7c1d3e6c17ecc28a59eb50c11d0943dea6831d90e5bf2"], ["0x24cd4581a7cfacd5b3ef39ddff559dc7f4ca7cb05cbfbfaeeece1b3fd7b9cf76", "0x00eb58ddf5ffea01caace38d7ffe7a916f526467903b94041fc6803302c189fe"]];

/// 金向量证明 A（G1）。
pub const GOLDEN_PROOF_A: [&str; 2] = ["0x0dedead646aab1f3544f12de9b27439dd711b480edef104cde6899c6c1358d3f", "0x16ed535890efc097a02baa78b7b1e13553f3a3a8b8fa426c993c8c7bae1215a9"];
/// 金向量证明 B（G2，ark 顺序；EVM/calldata 顺序见 ProofJson::b_evm）。
pub const GOLDEN_PROOF_B: [[&str; 2]; 2] = [["0x284dbbeb78c75406e04d0690d02f02037cfeccdfc7f826d992af9dd5385ef080", "0x284e2bd320301377e3d82e6f428ef6dc1fd686dc5d7037ae7e56d4c73edcdf22"], ["0x06fbb473489311b42ad78310b116b843a337c6a64e63230fd9d4a02c2d9c1b44", "0x1090e4e70edccdb8c46d720c5eac76b7394e2eeaefc0a2b69b5fc2272066c6ee"]];
/// 金向量证明 C（G1）。
pub const GOLDEN_PROOF_C: [&str; 2] = ["0x1d40de7330c6358bee9381150fbec62fa72d485932d1aab657549423a351198e", "0x14b3c69d4883a0fa0989a8fb296737af073ce27285422cd834b73cd2ff1eeb2a"];

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
