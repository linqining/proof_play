//! 批量包裹电路：K 手共享一次 Groth16 证明。
//!
//! 公开输入：`[program_hash, hand_binding_1, fact_1, …, hand_binding_K, fact_K]`
//! （2K+1 个 Fr）。电路体是 K 份单手语句的并列（program_hash 的非原生变量
//! 与位绑定共享一份），无跨手哈希链 —— 语义与 K 次单手验证完全等价，
//! 摊薄的是证明/验证固定开销与 program_hash 绑定成本。
//!
//! 同样 **不验证 STARK**（信任边界见 `wrap_circuit` 模块注释）。

use crate::felt::fr_to_felt;
use crate::felt::Fr;
use crate::poseidon_circuit::witness_felt;
use crate::wrap_circuit::{bind_felt_public, enforce_wrap_body, WrapStatement, WrapWitness};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError};

/// 批内单手条目。
#[derive(Debug, Clone)]
pub struct BatchHand {
    pub statement: WrapStatement,
    pub witness: WrapWitness,
}

/// K 手批量电路。
#[derive(Debug, Clone)]
pub struct BatchCircuit {
    pub program_hash: Fr,
    pub hands: Vec<BatchHand>,
}

impl BatchCircuit {
    /// 构造并做逐手形状校验。
    ///
    /// # Errors
    /// 任意手的见证形状不符，或 hand_binding/program_hash 与见证不一致。
    pub fn new(program_hash: Fr, hands: Vec<BatchHand>) -> Result<Self, String> {
        for (k, h) in hands.iter().enumerate() {
            h.witness.validate().map_err(|e| format!("hand {k}: {e}"))?;
            let ph_felt = fr_to_felt(&h.statement.program_hash)
                .map_err(|_| format!("hand {k}: program_hash not a felt"))?;
            let fact = h.witness.expected_fact(&ph_felt);
            if crate::felt::felt_to_fr(&fact) != h.statement.fact {
                return Err(format!("hand {k}: fact != poseidon(program_hash ‖ output)"));
            }
        }
        Ok(Self { program_hash, hands })
    }
}

impl ConstraintSynthesizer<Fr> for BatchCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R1CSResult<()> {
        let ph_pub = FpVar::new_input(ark_relations::ns!(cs, "program_hash"), || Ok(self.program_hash))?;
        let ph_felt = fr_to_felt(&self.program_hash).map_err(|_| SynthesisError::Unsatisfiable)?;
        let ph_nn = witness_felt(cs.clone(), ph_felt)?;
        bind_felt_public(&ph_pub, &ph_nn)?;

        for (k, hand) in self.hands.iter().enumerate() {
            // ns! 只接受字面量名；手序号写入变量名注释即可（约束形状与命名无关）
            let _ = k;
            let hb_pub = FpVar::new_input(ark_relations::ns!(cs, "batch_hand_binding"), || {
                Ok(hand.statement.hand_binding)
            })?;
            let fact_pub = FpVar::new_input(ark_relations::ns!(cs, "batch_fact"), || {
                Ok(hand.statement.fact)
            })?;
            enforce_wrap_body(cs.clone(), &ph_nn, &hb_pub, &fact_pub, &hand.witness.output)?;
        }
        Ok(())
    }
}
