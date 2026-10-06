//! 端到端 roundtrip：真实形状语句 → seeded setup → Groth16 证明 → 本地验证；
//! 负例（错 fact / 错 hand_binding / 金向量语句篡改）必须验证失败。
//!
//! trusted setup 说明见 lib.rs 模块注释（固定种子单方仪式，测试网口径）。

use groth16_wrap::batch_circuit::{BatchCircuit, BatchHand};
use groth16_wrap::felt::{felt_from_hex, felt_to_fr};
use groth16_wrap::wrap_circuit::{WrapCircuit, WrapStatement, WrapWitness};
use ark_relations::gr1cs::ConstraintSynthesizer;
use groth16_wrap::{golden, prove_with_pk, seeded_setup, verify_with_vk, Fr};

/// 真实 prove-hand 产物的公开内存段（proving-tool/output/settlement/
/// public_outputs.json，program_hash = 主网钉扎值）。
fn golden_segment() -> (WrapStatement, WrapWitness) {
    let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap();
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
    .map(|h| felt_from_hex(h).unwrap())
    .collect();
    let witness = WrapWitness { output };
    // fact 由宿主 poseidon（与 starknet-crypto 对拍过）计算
    let fact = witness.expected_fact(&program_hash);
    let hand_binding = felt_from_hex(golden::GOLDEN_HAND_BINDING).unwrap();
    let statement = WrapStatement {
        program_hash: felt_to_fr(&program_hash),
        hand_binding: felt_to_fr(&hand_binding),
        fact: felt_to_fr(&fact),
    };
    (statement, witness)
}

use groth16_wrap::Felt252;

#[test]
fn prove_then_verify_roundtrip() {
    let (statement, witness) = golden_segment();
    let circuit = WrapCircuit {
        statement,
        witness: witness.clone(),
    };
    let pk = seeded_setup(circuit.clone()).expect("setup");
    let proof = prove_with_pk(&pk, &circuit).expect("prove");
    let ok = verify_with_vk(&pk.vk, &[statement.program_hash, statement.hand_binding, statement.fact], &proof)
        .expect("verify inputs");
    assert!(ok, "roundtrip proof must verify");
}

/// 篡改公开输入（fact/hand_binding 各试一次）→ 链下验证必须拒绝。
#[test]
fn tampered_statements_are_rejected() {
    let (statement, witness) = golden_segment();
    let circuit = WrapCircuit { statement, witness };
    let pk = seeded_setup(circuit.clone()).expect("setup");
    let proof = prove_with_pk(&pk, &circuit).expect("prove");

    let wrong_fact = [statement.program_hash, statement.hand_binding, statement.fact + Fr::from(1u64)];
    assert!(
        !verify_with_vk(&pk.vk, &wrong_fact, &proof).unwrap(),
        "wrong fact must fail"
    );

    let wrong_hb = [statement.program_hash, statement.hand_binding + Fr::from(1u64), statement.fact];
    assert!(
        !verify_with_vk(&pk.vk, &wrong_hb, &proof).unwrap(),
        "wrong hand_binding must fail"
    );
}

/// 见证形状违规（MAGIC / 长度前缀）必须被 validate 拒绝。
#[test]
fn witness_validation_gates() {
    let (_, mut witness) = golden_segment();
    witness.output[0] = Felt252::from(14u64);
    assert!(witness.validate().is_err());
    witness.output[0] = Felt252::from(15u64);
    witness.output[1] += Felt252::from(1u64);
    assert!(witness.validate().is_err());
}

/// 宿主 fact 与 fact-verify 的公式同源：hand_binding 必须绑到 output[5]。
#[test]
fn hand_binding_binds_segment_slot_5() {
    let (mut statement, witness) = golden_segment();
    // 把见证里 output[5]（= hand_binding 槽）换成别的值，fact 相应重算，
    // 语句的 hand_binding 保持不变 → 电路不满足（不能伪造不同 binding）。
    let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap();
    let mut tampered = witness.clone();
    tampered.output[groth16_wrap::wrap_circuit::HAND_BINDING_INDEX] += Felt252::from(1u64);
    statement.fact = felt_to_fr(&tampered.expected_fact(&program_hash));
    let cs = ark_relations::gr1cs::ConstraintSystem::<Fr>::new_ref();
    WrapCircuit { statement, witness: tampered }
        .generate_constraints(cs.clone())
        .unwrap();
    assert!(!cs.is_satisfied().unwrap(), "swapped binding slot must break satisfaction");
}

/// 批量电路（K=2）：一次 setup/一次证明覆盖两手语句。
#[test]
fn batch_of_two_proves_and_verifies() {
    let (statement, witness) = golden_segment();
    let ph = statement.program_hash;
    let hands = vec![
        BatchHand { statement, witness: witness.clone() },
        // 第二手换一个 hand_binding（见证槽位同步换），fact 重算
        {
            let hb2 = felt_from_hex("0xbbbb").unwrap();
            let mut out2 = witness.output.clone();
            out2[groth16_wrap::wrap_circuit::HAND_BINDING_INDEX] = hb2;
            let w2 = WrapWitness { output: out2 };
            let fact2 = w2.expected_fact(&felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap());
            BatchHand {
                statement: WrapStatement {
                    program_hash: ph,
                    hand_binding: felt_to_fr(&hb2),
                    fact: felt_to_fr(&fact2),
                },
                witness: w2,
            }
        },
    ];
    let circuit = BatchCircuit::new(ph, hands).expect("batch circuit");
    let pk = seeded_setup(circuit.clone()).expect("batch setup");
    let proof = prove_with_pk(&pk, &circuit).expect("batch prove");
    let mut publics = vec![ph];
    for h in &circuit.hands {
        publics.push(h.statement.hand_binding);
        publics.push(h.statement.fact);
    }
    assert!(
        verify_with_vk(&pk.vk, &publics, &proof).expect("verify"),
        "batch proof must verify"
    );
}

/// 金向量一致性：提交的常量若已生成，必须能本地验证通过（PLACEHOLDER 时跳过）。
#[test]
fn golden_vector_constants_verify_locally() {
    if golden::GOLDEN_FACT.starts_with("PLACEHOLDER") {
        eprintln!("golden.rs 尚未生成（运行 gen-sol）——跳过");
        return;
    }
    let statement = golden::golden_statement().unwrap();
    let proof = golden::golden_proof().unwrap();
    let vk = golden::golden_verifying_key().unwrap();
    let ok = verify_with_vk(&vk, &[statement.program_hash, statement.hand_binding, statement.fact], &proof)
        .expect("verify");
    assert!(ok, "committed golden vector must verify");
}
