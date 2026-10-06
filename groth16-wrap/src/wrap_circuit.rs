//! 单手 STARK→Groth16 包裹电路。
//!
//! # 电路语句（R1CS over BN254 Fr，3 个公开输入）
//!
//! 公开输入（单个 Fr 各承载一个 felt252，编码无损：felt < 2^252 < r）：
//! 1. `program_hash` —— prove-hand 产出的 Cairo 程序哈希；
//! 2. `hand_binding` —— 双证明绑定 digest（src/hand_binding.rs 同值）；
//! 3. `fact`        —— `poseidon_hash_many([program_hash ‖ output])`
//!    （fact-verify/src/lib.rs:78-83 `fact_for_output` 同式）。
//!
//! 见证：Cairo 程序公开内存段 `output`（16 felts = 长度前缀 15 + 15 felt
//! 返回数组 `[MAGIC, hand_id, registered_digest, n_expected, hand_binding,
//! cm_0..cm_7, total_winnings, action_log_digest]`，与真实产物
//! proving-tool/output/settlement/public_outputs.json 同形）。
//!
//! # 约束
//! - `output[0] == 15` 与 `output[1] == MAGIC('SP2M_OK')`：作为常量直接进
//!   哈希预映像 —— 任何满足语句的证明必然提交到该形状（哈希抗碰）。
//! - `output[5]` 的哈希槽位就是与公开输入 `hand_binding` 位绑定的那个变量
//!   —— 反拼装绑定（P/G 两轨同 binding，见 src/hand_binding.rs）。
//! - `fact == poseidon_hash_many([program_hash ‖ output])`：电路内非原生
//!   Poseidon 重算，结果位绑定到公开输入 `fact`。
//!
//! # 信任边界（务必知悉）
//! 本电路 **不验证 STARK**。链上验证的命题是「fact 是 program_hash‖output
//! 的 Poseidon 像，且 output[5] = hand_binding，且 output 呈约定形状」这一
//! hash 一致性。STARK 真伪由链下 fact-verify（stwo verify_cairo + 程序哈希
//! 钉扎）把关；被攻破的 operator 可以包装任意格式良好的伪造 output 上链。
//! 即 Monad 上体现的是「operator 背书 + 电路一致」，非去信任事实。

use crate::felt::fr_to_felt;
use crate::felt::{Felt252, Fr};
use crate::poseidon_circuit::{constant_felt, poseidon_hash_many, witness_felt, CircuitFelt};
use ark_ff::Zero;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError};

/// 公开内存段总长（长度前缀 1 + 返回数组 15）。
pub const OUTPUT_LEN: usize = 16;
/// 返回数组长度前缀（output[0]）。
pub const SEGMENT_LEN: u64 = 15;
/// 公开段成功标记 'SP2M_OK'（output[1]）。
pub const SEGMENT_MAGIC: u64 = 0x5350324d5f4f4b;
/// hand_binding 在返回数组中的下标（= 公开段 output 下标 5）。
pub const HAND_BINDING_INDEX: usize = 5;

/// Groth16 语句（链上 verifier 的 3 个 public signals）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapStatement {
    pub program_hash: Fr,
    pub hand_binding: Fr,
    pub fact: Fr,
}

/// Groth16 见证（完整公开内存段，16 felts）。
#[derive(Debug, Clone)]
pub struct WrapWitness {
    /// `[15, MAGIC, hand_id, registered_digest, n_expected, hand_binding,
    ///  cm_0..cm_7, total_winnings, action_log_digest]`
    pub output: Vec<Felt252>,
}

impl WrapWitness {
    /// 形状校验（与真实 prove-hand 产物同形）。
    ///
    /// # Errors
    /// 长度不是 16、长度前缀 ≠ 15、MAGIC 不符。
    pub fn validate(&self) -> Result<(), String> {
        if self.output.len() != OUTPUT_LEN {
            return Err(format!("output len = {}, expected {OUTPUT_LEN}", self.output.len()));
        }
        if self.output[0] != Felt252::from(SEGMENT_LEN) {
            return Err("output[0] must be the length prefix 15".into());
        }
        if self.output[1] != Felt252::from(SEGMENT_MAGIC) {
            return Err("output[1] must be MAGIC 'SP2M_OK' (0x5350324d5f4f4b)".into());
        }
        Ok(())
    }

    /// 该见证对应的 fact（与 fact-verify `fact_for_output` 同式，宿主重算）。
    #[must_use]
    pub fn expected_fact(&self, program_hash: &Felt252) -> Felt252 {
        let mut felts = Vec::with_capacity(OUTPUT_LEN + 1);
        felts.push(*program_hash);
        felts.extend_from_slice(&self.output);
        crate::poseidon::poseidon_hash_many(&felts)
    }
}

/// 位绑定：公开 Fr 变量与电路内非原生 Fp252 变量是同一个 felt252。
///
/// 两侧均为各自域内规范值的 LSB 位分解（to_bits_le 内部强制位布尔性 +
/// 值 < 模），齐长后逐位相等 ⟺ 数值相等。填充位两侧都必须是 0 —— 对
/// nn 侧由 ≤ p_felt 规范性强制，对 pub 侧由 < r_BN254 的规范位分解强制。
pub(crate) fn bind_felt_public(pub_var: &FpVar<Fr>, nn: &CircuitFelt) -> R1CSResult<()> {
    let mut a = pub_var.to_bits_le()?;
    let mut b = nn.to_bits_le()?;
    let n = a.len().max(b.len());
    a.resize(n, Boolean::constant(false));
    b.resize(n, Boolean::constant(false));
    for i in 0..n {
        a[i].enforce_equal(&b[i])?;
    }
    Ok(())
}

/// 单手语句的电路体：给 program_hash 的 nn 变量与该手的 (hand_binding,
/// fact) 公开输入、见证 output，生成全部约束。
///
/// `ph_nn` 跨手共享（batch 复用同一变量），由调用方完成它与 program_hash
/// 公开输入的位绑定。
pub(crate) fn enforce_wrap_body(
    cs: ConstraintSystemRef<Fr>,
    ph_nn: &CircuitFelt,
    hb_pub: &FpVar<Fr>,
    fact_pub: &FpVar<Fr>,
    output: &[Felt252],
) -> R1CSResult<()> {
    let hb_felt = fr_to_felt(&hb_pub.value().unwrap_or(Fr::zero()))
        .map_err(|_| SynthesisError::Unsatisfiable)?;
    let hb_nn = witness_felt(cs.clone(), hb_felt)?;
    bind_felt_public(hb_pub, &hb_nn)?;

    // 预映像 = [program_hash ‖ output]（17 felts）：
    //   [0]=ph_nn  [1]=C15  [2]=CMAGIC  [3..5]=out2..4  [6]=hb_nn(=out5)
    //   [7..16]=out6..15
    let mut preimage: Vec<CircuitFelt> = Vec::with_capacity(OUTPUT_LEN + 1);
    preimage.push(ph_nn.clone());
    preimage.push(constant_felt(cs.clone(), Felt252::from(SEGMENT_LEN))?);
    preimage.push(constant_felt(cs.clone(), Felt252::from(SEGMENT_MAGIC))?);
    for (i, felt) in output.iter().enumerate().take(OUTPUT_LEN).skip(2) {
        if i == HAND_BINDING_INDEX {
            preimage.push(hb_nn.clone());
        } else {
            preimage.push(witness_felt(cs.clone(), *felt)?);
        }
    }
    debug_assert_eq!(preimage.len(), OUTPUT_LEN + 1);

    let computed = poseidon_hash_many(&cs, &preimage)?;
    // 计算结果 ⟷ 公开 fact 位绑定（computed 的 to_bits_le 强制规范值）
    bind_felt_public(fact_pub, &computed)?;
    Ok(())
}

/// 单手包裹电路（setup/prove 共用； Witness 为真实值）。
#[derive(Debug, Clone)]
pub struct WrapCircuit {
    pub statement: WrapStatement,
    pub witness: WrapWitness,
}

impl WrapCircuit {
    /// program_hash 的 felt252 形式（见证侧）。
    fn program_hash_felt(&self) -> R1CSResult<Felt252> {
        fr_to_felt(&self.statement.program_hash).map_err(|_| SynthesisError::Unsatisfiable)
    }
}

impl ConstraintSynthesizer<Fr> for WrapCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R1CSResult<()> {
        self.witness.validate().map_err(|_| SynthesisError::Unsatisfiable)?;
        let ph_pub = FpVar::new_input(ark_relations::ns!(cs, "program_hash"), || Ok(self.statement.program_hash))?;
        let hb_pub = FpVar::new_input(ark_relations::ns!(cs, "hand_binding"), || Ok(self.statement.hand_binding))?;
        let fact_pub = FpVar::new_input(ark_relations::ns!(cs, "fact"), || Ok(self.statement.fact))?;

        let ph_nn = witness_felt(cs.clone(), self.program_hash_felt()?)?;
        bind_felt_public(&ph_pub, &ph_nn)?;

        enforce_wrap_body(cs, &ph_nn, &hb_pub, &fact_pub, &self.witness.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt::felt_to_fr;

    fn sample() -> (WrapStatement, WrapWitness) {
        let program_hash = crate::felt::felt_from_hex(
            "0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4",
        )
        .unwrap();
        let output: Vec<Felt252> = [
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
        ]
        .iter()
        .map(|h| crate::felt::felt_from_hex(h).unwrap())
        .collect();
        let witness = WrapWitness { output };
        let fact = witness.expected_fact(&program_hash);
        let statement = WrapStatement {
            program_hash: felt_to_fr(&program_hash),
            hand_binding: felt_to_fr(&crate::felt::felt_from_hex("0xa6aa").unwrap()),
            fact: felt_to_fr(&fact),
        };
        (statement, witness)
    }

    /// 电路与宿主 fact 公式一致：真实 witness 下约束满足。
    #[test]
    fn circuit_satisfied_with_real_shaped_witness() {
        let (statement, witness) = sample();
        let cs = ark_relations::gr1cs::ConstraintSystem::<Fr>::new_ref();
        WrapCircuit { statement, witness }
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(cs.is_satisfied().unwrap(), "circuit must be satisfied");
        println!("wrap circuit constraints = {}", cs.num_constraints());
    }

    /// 宿主 fact 与电路必须共享同一个 poseidon —— 值错一位即不满足。
    #[test]
    fn circuit_rejects_wrong_fact() {
        let (mut statement, witness) = sample();
        statement.fact += Fr::from(1u64);
        let cs = ark_relations::gr1cs::ConstraintSystem::<Fr>::new_ref();
        WrapCircuit { statement, witness }
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(!cs.is_satisfied().unwrap(), "wrong fact must be rejected");
    }

    /// MAGIC / 长度前缀形状校验：坏形状在 witness 校验层直接拒绝。
    #[test]
    fn circuit_rejects_bad_segment_shape() {
        let (statement, mut witness) = sample();
        witness.output[1] += Felt252::from(1u64); // 破坏 MAGIC
        let cs = ark_relations::gr1cs::ConstraintSystem::<Fr>::new_ref();
        assert!(
            WrapCircuit { statement, witness }
                .generate_constraints(cs.clone())
                .is_err(),
            "broken MAGIC must be rejected at witness validation"
        );
        // 前缀破坏同理
        let (statement, mut witness) = sample();
        witness.output[0] = Felt252::from(14u64);
        assert!(WrapCircuit { statement, witness }
            .generate_constraints(cs)
            .is_err());
    }
}
