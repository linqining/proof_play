//! T3-FRI 影子管线 E2E：prove_shadow → stwo 泛型 verify（独立校验）→
//! extract_shadow → verify_shadow（接受）+ 篡改负例（全拒绝）。
//! 差分口径见 out/t3-fri-wrap-design.md §4。

use ark_ff::PrimeField;
use hand_verify_native::air::{HandBatchClaim, KindCounts};
use starknet_crypto::Felt;

use groth16_wrap::fri_shadow::{
    extract_shadow, prove_shadow, verify_shadow, ShadowWitness,
};

fn small_claim() -> HandBatchClaim {
    HandBatchClaim::new(
        Felt::from(12345u64),
        Felt::from(0xdead_beefu64),
        KindCounts { n_own: 1, n_reveal: 1, n_leave: 0, n_recon: 0 },
        Felt::ZERO,
    )
}

fn feltj_to_fr(s: &str) -> ark_bn254::Fr {
    groth16_wrap::felt::fr_from_hex(s).unwrap()
}

/// stwo 自带 verifier 对影子证明的独立校验（泛型 MerkleChannel）。
fn stwo_verify_shadow(hand: &groth16_wrap::fri_shadow::ShadowProof) -> anyhow::Result<()> {
    use stwo::core::channel::Poseidon252Channel as _UnusedChannel;
    let _ = std::marker::PhantomData::<_UnusedChannel>;
    use stwo::core::channel::Channel;
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
    use stwo::core::vcs_lifted::verifier::MerkleVerifierLifted;
    use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

    let claim = hand.claim;
    let proof = &hand.stark_proof;
    let config: PcsConfig = groth16_wrap::fri_shadow::protocol_pcs_config();

    let mut channel = groth16_wrap::fri_shadow::ShadowChannel::default();
    claim.mix_into(&mut channel);
    let mut commitment_scheme =
        CommitmentSchemeVerifier::<groth16_wrap::fri_shadow::ShadowMerkleChannel>::new(config);
    // tree0: 空
    commitment_scheme.commit(proof.commitments.0[0], &[], &mut channel);
    // tree1: trace
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        hand_verify_native::air::HandBatchEval::new(&claim),
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    use stwo::core::air::Component as _;
    let sizes = component.trace_log_degree_bounds();
    let blowup = config.fri_config.log_blowup_factor;
    // 注意：commit 内部会 +blowup，这里必须传原始 log size（verify_stark_against 同口径）
    let trace_sizes: Vec<u32> = sizes[1].clone();
    commitment_scheme.commit(proof.commitments.0[1], &trace_sizes, &mut channel);
    // tree2: quotient（verify_ex 内提交）
    let components = stwo::core::air::Components {
        components: vec![&component],
        n_preprocessed_columns: 0,
    };
    let comp_bound = components.composition_log_degree_bound();
    let split = comp_bound - stwo::core::verifier::COMPOSITION_LOG_SPLIT;
    let lifting = stwo::core::pcs::utils::get_lifting_log_size(&config, split + blowup);
    let max_bound = lifting - blowup;
    // tree2（composition）由 verify_ex 内部提交——这里不能重复混根。
    if std::env::var("T3_DEBUG").is_ok() {
        eprintln!("[t3][helper] trace_sizes={:?} lifting={} max_bound={} decommit_lens={:?} sampled_lens0={:?}",
            &trace_sizes, lifting, max_bound,
            proof.decommitments.0.iter().map(|d| d.hash_witness.len()).collect::<Vec<_>>(),
            proof.sampled_values.0[1].iter().map(|c| c.len()).collect::<Vec<_>>().iter().take(5).collect::<Vec<_>>());
    }
    stwo::core::verifier::verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        proof.clone(),
    )
    .map_err(|e| anyhow::anyhow!("stwo verify: {e}"))
}

fn tamper<T>(mut w: ShadowWitness, f: impl FnOnce(&mut ShadowWitness)) -> ShadowWitness {
    f(&mut w);
    w
}

#[test]
fn shadow_pipeline_roundtrip_and_negatives() {
    let claim = small_claim();
    let hand = prove_shadow(&claim).expect("prove_shadow");
    // 独立事实源：stwo 泛型 verifier
    stwo_verify_shadow(&hand).expect("stwo verify shadow");
    // 提取 + 参照验证
    let w = extract_shadow(&hand).expect("extract");
    verify_shadow(&w).expect("verify_shadow accept");

    // ---- 篡改负例 ----
    // 1. 篡改 trace 叶值（第一行第一列）
    let mut t = w.clone();
    t.pcs_trees[0].leaf_rows[0][0] ^= 1;
    assert!(verify_shadow(&t).is_err(), "tampered trace leaf must fail");
    // 2. 篡改 FRI 层子集值
    let mut t = w.clone();
    t.fri_layers[0].subset_rows[0][0][0] ^= 1;
    assert!(verify_shadow(&t).is_err(), "tampered fri leaf must fail");
    // 3. 篡改兄弟哈希
    let mut t = w.clone();
    let idx = t.pcs_trees[0].hash_witness.len() / 2;
    let mut fr = feltj_to_fr(&t.pcs_trees[0].hash_witness[idx]);
    fr += ark_bn254::Fr::from(1u8);
    t.pcs_trees[0].hash_witness[idx] = groth16_wrap::felt::fr_to_hex(&fr);
    assert!(verify_shadow(&t).is_err(), "tampered sibling hash must fail");
    // 4. 篡改根
    let mut t = w.clone();
    let fr = feltj_to_fr(&t.trace_root) + ark_bn254::Fr::from(1u8);
    t.trace_root = groth16_wrap::felt::fr_to_hex(&fr);
    assert!(verify_shadow(&t).is_err(), "tampered root must fail");
    // 5. 篡改末层常数
    let mut t = w.clone();
    t.last_layer_poly[1] = t.last_layer_poly[1].wrapping_add(1);
    assert!(verify_shadow(&t).is_err(), "tampered last poly must fail");
    // 6. 篡改 OOD 值（通道变化 → 查询位置不匹配）
    let mut t = w.clone();
    t.ood_values[0][0] ^= 1;
    assert!(verify_shadow(&t).is_err(), "tampered ood value must fail");
    // 7. 篡改商表
    let mut t = w.clone();
    t.tables.per_query[0].batches[0].denom_inv[0] ^= 1;
    assert!(verify_shadow(&t).is_err(), "tampered table must fail");
    // 8. 篡改查询位置
    let mut t = w.clone();
    t.queries[0] ^= 1;
    assert!(verify_shadow(&t).is_err(), "tampered query must fail");
}

/// 与主 Poseidon252 证明的形状一致性（同一 claim 两次独立 STARK）。
#[test]
fn shadow_and_main_share_shape() {
    let claim = small_claim();
    let main = hand_verify_native::prove::prove_claim(&claim).unwrap();
    let shadow = prove_shadow(&claim).unwrap();
    let wm = groth16_wrap::fri_ref::extract(&main).unwrap();
    let ws = extract_shadow(&shadow).unwrap();
    assert_eq!(wm.log_size, ws.log_size);
    assert_eq!(wm.n_fri_layers, ws.n_fri_layers);
    assert_eq!(wm.lifting_log_size, ws.lifting_log_size);
    assert_eq!(wm.ood_col_lens, ws.ood_col_lens);
    assert_eq!(wm.ood_values.len(), ws.ood_values.len());
    assert_eq!(wm.ood_points.len(), ws.ood_points.len());
}

/// 静态回归：确认我们引用的 stwo 是供应商化补丁版（泛型 blanket）。
#[test]
fn vendored_patch_marker_present() {
    let manifest = include_str!("../../third_party/stwo/src/prover/backend/cpu/mod.rs");
    assert!(
        manifest.contains("[T3-FRI patch]"),
        "vendored stwo must carry the T3-FRI patch marker"
    );
}

// ---------------------------------------------------------------------------
// T3-FRI 电路：Groth16 roundtrip + 电路负例
// ---------------------------------------------------------------------------

use ark_ff::PrimeField as _;
use ark_relations::gr1cs::ConstraintSynthesizer;
use groth16_wrap::fri_circuit::{FriWrapCircuit, public_inputs};

/// 小实例全链路：prove_shadow → extract → verify_shadow → 电路 setup/prove/
/// verify + 篡改负例。性能口径见 `fri_circuit_perf`（ignored）。
#[test]
fn fri_circuit_roundtrip_small() {
    let claim = small_claim();
    let hand = prove_shadow(&claim).expect("prove_shadow");
    let w = extract_shadow(&hand).expect("extract");
    verify_shadow(&w).expect("verify_shadow");

    let circuit = FriWrapCircuit { w: w.clone() };
    let t_setup = std::time::Instant::now();
    let pk = groth16_wrap::seeded_setup(circuit.clone()).expect("setup");
    eprintln!("[perf] log={} setup={:?}", w.log_size, t_setup.elapsed());
    let t_prove = std::time::Instant::now();
    let proof = groth16_wrap::prove_with_pk(&pk, &circuit).expect("groth16 prove");
    eprintln!("[perf] prove={:?}", t_prove.elapsed());
    let pi = public_inputs(&w);
    let t_verify = std::time::Instant::now();
    let ok = groth16_wrap::verify_with_vk(&pk.vk, &pi, &proof).expect("groth16 verify");
    eprintln!("[perf] verify={:?} ok={}", t_verify.elapsed(), ok);
    assert!(ok, "circuit roundtrip must verify");

    // 电路负例：篡改公开输入（trace 根）
    let mut bad = pi.clone();
    bad[6] += ark_bn254::Fr::from(1u8);
    let ok_bad = groth16_wrap::verify_with_vk(&pk.vk, &bad, &proof).unwrap();
    assert!(!ok_bad, "tampered root public must fail");

    // 电路负例：篡改 witness（层 0 子集值）→ 电路约束应不满足
    let mut wt = w.clone();
    wt.fri_layers[0].subset_rows[0][0][0] ^= 1;
    let bad_circuit = FriWrapCircuit { w: wt };
    let r = groth16_wrap::prove_with_pk(&pk, &bad_circuit);
    assert!(r.is_err(), "tampered fri leaf witness must fail synthesis/prove");
}

/// 性能口径（验收用；ignored——K=64 规模 prove 数分钟）。
/// cargo test -p groth16-wrap --test fri_shadow_e2e fri_circuit_perf -- --ignored --nocapture
#[test]
#[ignore]
fn fri_circuit_perf() {
    use hand_verify_native::air::{HandBatchClaim, KindCounts};
    // K=64 语句表：counts 和 ≤ 2^15（log_size 15）
    let claim = HandBatchClaim::new(
        Felt::from(0xA11CEu64),
        Felt::from(0xB0Bu64),
        KindCounts { n_own: 16000, n_reveal: 16000, n_leave: 768, n_recon: 0 },
        Felt::ZERO,
    );
    assert_eq!(claim.log_size, 15);
    let t0 = std::time::Instant::now();
    let hand = prove_shadow(&claim).expect("prove_shadow log15");
    eprintln!("[perf] K64 shadow prove={:?}", t0.elapsed());
    let t1 = std::time::Instant::now();
    let w = extract_shadow(&hand).expect("extract");
    eprintln!("[perf] K64 extract={:?} queries={}", t1.elapsed(), w.queries.len());
    let t2 = std::time::Instant::now();
    verify_shadow(&w).expect("verify_shadow");
    eprintln!("[perf] K64 verify_shadow={:?}", t2.elapsed());
    let circuit = FriWrapCircuit { w: w.clone() };
    let t3 = std::time::Instant::now();
    let pk = groth16_wrap::seeded_setup(circuit.clone()).expect("setup");
    eprintln!("[perf] K64 setup={:?}", t3.elapsed());
    let t4 = std::time::Instant::now();
    let proof = groth16_wrap::prove_with_pk(&pk, &circuit).expect("groth16 prove");
    eprintln!("[perf] K64 groth16 prove={:?}", t4.elapsed());
    let pi = public_inputs(&w);
    let ok = groth16_wrap::verify_with_vk(&pk.vk, &pi, &proof).expect("verify");
    eprintln!("[perf] K64 groth16 verify ok={} publics={} proof_bytes={}", ok, pi.len(), groth16_wrap::proof_size_bytes(&proof));
    assert!(ok);
}

/// setup 失败定位：直接合成约束看不满足点。
#[test]
fn fri_circuit_synthesis_only() {
    let claim = small_claim();
    let hand = prove_shadow(&claim).unwrap();
    let w = extract_shadow(&hand).unwrap();
    let cs = ark_relations::gr1cs::ConstraintSystem::<ark_bn254::Fr>::new_ref();
    cs.set_optimization_goal(ark_relations::gr1cs::OptimizationGoal::Constraints);
    FriWrapCircuit { w }.generate_constraints(cs.clone()).unwrap();
    eprintln!("[perf] num_constraints={}", cs.num_constraints());
    let unsat = cs.which_is_unsatisfied().unwrap_or(None);
    eprintln!("[perf] satisfied={} unsat={:?}", cs.is_satisfied().unwrap(), unsat);
    assert!(cs.is_satisfied().unwrap(), "synthesis must be satisfied; unsat={unsat:?}");
}
