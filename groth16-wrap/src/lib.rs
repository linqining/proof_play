//! groth16-wrap —— 单手 STARK→Groth16 包裹（BN254，upstream arkworks 0.5）。
//!
//! # 它验证什么
//! 语句（3 个公开输入）：`program_hash`、`hand_binding`、`fact`。电路约束：
//! 1. `fact == poseidon_hash_many([program_hash ‖ output])`（与 fact-verify
//!    `fact_for_output` / 链上 `fact_for_segment` 同式，电路内非原生重算）；
//! 2. `output[0] == 15`（长度前缀）、`output[1] == 'SP2M_OK'`（常量进预映像）；
//! 3. `output[5] == hand_binding`（反拼装绑定，与 src/hand_binding.rs 对齐）。
//! 见证 = Cairo 公开内存段 output（16 felts），由 prove-hand 产物给出。
//!
//! # 信任边界（如实声明）
//! - **不验证 STARK**：链上命题只是上述 hash 一致性，NOT「存在合法 STARK
//!   证明」。STARK 真伪由链下 fact-verify（stwo verify_cairo + 程序哈希钉扎
//!   `0x744d16d3…`）与运营方把关；被攻破的 operator 可包装任意格式良好的
//!   伪造 output 上链。Monad 上体现的是「operator 背书 + 电路一致」。
//! - **trusted setup**：Groth16 需要 per-circuit setup。本 crate 使用固定
//!   种子的单方仪式（[`SETUP_SEED`]，本地可复现 URS）——测试网口径可接受；
//!   主网必须换 MPC powers-of-tau ceremony 并重新生成 verifying key。
//!
//! # 门禁
//! `cargo test -p groth16-wrap`（本地 prove/verify roundtrip + 电路负例）
//! 与 zchain `forge test`（金向量链上 verifyProof == true）。

pub mod batch;
pub mod batch_circuit;
pub mod felt;
pub mod fri_ref;
pub mod fri_circuit;
pub mod fri_shadow;
pub mod golden;
pub mod poseidon;
pub mod poseidon_circuit;
pub mod wrap_circuit;

use anyhow::{Context, Result};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_serialize::CanonicalSerialize;
use rand::rngs::StdRng;
use rand::SeedableRng;

pub use felt::{Felt252, Fr};
pub use wrap_circuit::{WrapStatement, WrapWitness};

/// 单方仪式的固定种子（可复现 trusted setup；测试/测试网专用，见模块注释）。
pub const SETUP_SEED: u64 = 0x5350_324D_5F57_5241; // 'SP2M_WRA'

/// 复现式单方 setup：固定种子 → alpha/beta/gamma/delta 与生成元全部确定。
///
/// # Errors
/// 约束合成 / QAP 归约失败。
pub fn seeded_setup<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<ProvingKey<Bn254>> {
    let mut rng = StdRng::seed_from_u64(SETUP_SEED);
    Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)
        .context("groth16 setup")
}

/// 零知识证明（blinding 随机数同样取自固定种子 → 证明字节可复现）。
///
/// # Errors
/// 约束合成 / 证明失败。
pub fn prove_with_pk<C: ConstraintSynthesizer<Fr> + Clone>(
    pk: &ProvingKey<Bn254>,
    circuit: &C,
) -> Result<Proof<Bn254>> {
    let mut rng = StdRng::seed_from_u64(SETUP_SEED ^ 0xD1CE);
    Groth16::<Bn254>::create_random_proof_with_reduction(circuit.clone(), pk, &mut rng)
        .context("groth16 prove")
}

/// 本地验证（与链上 verifier 同一配平式：e(-A,B)·e(X,γ)·e(C,δ) == e(α,β)）。
///
/// # Errors
/// 输入构造失败。
pub fn verify_with_vk(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[Fr],
    proof: &Proof<Bn254>,
) -> Result<bool> {
    let pvk = ark_groth16::prepare_verifying_key(vk);
    verify_with_pvk(&pvk, public_inputs, proof)
}

/// 已预备 verifying key 的本地验证。
///
/// # Errors
/// 输入构造失败。
pub fn verify_with_pvk(
    pvk: &PreparedVerifyingKey<Bn254>,
    public_inputs: &[Fr],
    proof: &Proof<Bn254>,
) -> Result<bool> {
    Groth16::<Bn254>::verify_proof(pvk, proof, public_inputs).context("groth16 verify")
}

/// G1 点 → `[x_hex, y_hex]`（0x + 64 hex，EVM uint256 直填）。
#[must_use]
pub fn g1_to_hex(p: &G1Affine) -> [String; 2] {
    [
        crate::felt::bigint_to_hex(&p.x.into_bigint()),
        crate::felt::bigint_to_hex(&p.y.into_bigint()),
    ]
}

/// G2 点 → `[[x0_hex, x1_hex], [y0_hex, y1_hex]]`（ark 顺序：c0 在前）。
#[must_use]
pub fn g2_to_hex(p: &G2Affine) -> [[String; 2]; 2] {
    [
        [
            crate::felt::bigint_to_hex(&p.x.c0.into_bigint()),
            crate::felt::bigint_to_hex(&p.x.c1.into_bigint()),
        ],
        [
            crate::felt::bigint_to_hex(&p.y.c0.into_bigint()),
            crate::felt::bigint_to_hex(&p.y.c1.into_bigint()),
        ],
    ]
}

/// 证明体的 JSON 友好形态（wrap-proof 输出 & 金向量常量共用）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofJson {
    pub a: [String; 2],
    /// ark 顺序 [[x.c0, x.c1], [y.c0, y.c1]]
    pub b: [[String; 2]; 2],
    pub c: [String; 2],
    /// EVM/calldata 顺序 [[x.c1, x.c0], [y.c1, y.c0]]：EIP-197 Fp2 = a·i+b
    /// 字序（虚部在前）；与 Groth16Verifier.sol 的 calldata 约定一致
    /// （金向量 forge 测试实测钉死，见 zchain contracts/monad）。
    pub b_evm: [[String; 2]; 2],
}

/// 语句 + 证明的完整 JSON 形态。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatementProofJson {
    pub program_hash: String,
    pub hand_binding: String,
    pub fact: String,
    pub proof: ProofJson,
}

impl ProofJson {
    /// 从 ark Proof 导出。
    #[must_use]
    pub fn from_ark(p: &Proof<Bn254>) -> Self {
        let b_evm = [
            [
                crate::felt::bigint_to_hex(&p.b.x.c1.into_bigint()),
                crate::felt::bigint_to_hex(&p.b.x.c0.into_bigint()),
            ],
            [
                crate::felt::bigint_to_hex(&p.b.y.c1.into_bigint()),
                crate::felt::bigint_to_hex(&p.b.y.c0.into_bigint()),
            ],
        ];
        Self {
            a: g1_to_hex(&p.a),
            b: g2_to_hex(&p.b),
            c: g1_to_hex(&p.c),
            b_evm,
        }
    }

    /// 还原 ark Proof。
    ///
    /// # Errors
    /// 非法 hex。
    pub fn to_ark(&self) -> Result<Proof<Bn254>> {
        let fe = |s: &str| -> Result<ark_bn254::Fq> {
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s)?;
            Ok(ark_bn254::Fq::from_be_bytes_mod_order(&bytes))
        };
        let fp2 = |pair: &[String; 2]| -> Result<ark_bn254::Fq2> {
            Ok(ark_bn254::Fq2::new(fe(&pair[0])?, fe(&pair[1])?))
        };
        let g1 = |pair: &[String; 2]| -> Result<G1Affine> {
            Ok(G1Affine::new(fe(&pair[0])?, fe(&pair[1])?))
        };
        let g2 = |p: &[[String; 2]; 2]| -> Result<G2Affine> {
            Ok(G2Affine::new(fp2(&p[0])?, fp2(&p[1])?))
        };
        Ok(Proof {
            a: g1(&self.a)?,
            b: g2(&self.b)?,
            c: g1(&self.c)?,
        })
    }
}

/// 证明字节长度（未压缩序列化口径，日志用）。
#[must_use]
pub fn proof_size_bytes(proof: &Proof<Bn254>) -> usize {
    let mut buf = Vec::new();
    let _ = proof.serialize_uncompressed(&mut buf);
    buf.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 证明 JSON 往返无损（b 的 ark/EVM 两种顺序都要还原一致）。
    #[test]
    fn proof_json_roundtrip() {
        let g1 = G1Affine::new(ark_bn254::Fq::from(1u64), ark_bn254::Fq::from(2u64));
        let g2 = G2Affine::new(
            ark_bn254::Fq2::new(
                ark_bn254::g2::G2_GENERATOR_X_C0,
                ark_bn254::g2::G2_GENERATOR_X_C1,
            ),
            ark_bn254::Fq2::new(
                ark_bn254::g2::G2_GENERATOR_Y_C0,
                ark_bn254::g2::G2_GENERATOR_Y_C1,
            ),
        );
        let p = Proof::<Bn254> { a: g1, b: g2, c: g1 };
        let j = ProofJson::from_ark(&p);
        let back = j.to_ark().unwrap();
        assert_eq!(back.a, p.a);
        assert_eq!(back.b, p.b);
        assert_eq!(back.c, p.c);
        // EVM 顺序是 ark 顺序的分量交换
        assert_eq!(j.b_evm[0][0], j.b[0][1]);
        assert_eq!(j.b_evm[0][1], j.b[0][0]);
    }
}
