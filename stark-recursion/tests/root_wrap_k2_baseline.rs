//! K=2 Groth16 终证包裹 roundtrip —— **对照基线**（feature `groth16-baseline`）。
//!
//! 2026-09-29 裁定：Groth16 出终证路径，本测试降级为对照基线（保留真出证
//! roundtrip 与负例，供回归比对；不进默认门禁）。默认门禁样本 = tests/final_k2.rs
//! （L1 STARK 终证腿，纯 host）。运行需显式启用 feature，<10 分钟预算不变。
#![cfg(feature = "groth16-baseline")]
//! K=2 小批端到端（原 <10 分钟门禁样本）。
//!
//! 覆盖：K 手语句批 → keccak 根 → 叶（H1 精确镜像）→ L=1 自折叠根 →
//! 累加链接语句 → host 预检 → seeded setup → Groth16 prove → 本地 verify
//! → 负例（fact / 根 hi-lo / acc_prev 篡改皆拒绝）→ settleRoot calldata。
//!
//! # 边界（如实）
//!
//! 叶/折叠为 MockBackend（格式合规 + H1 镜像；真实 stwo 叶/折叠腿需 registry
//! 工件 + 大内存，不在本机门禁范围——真 K 由 bench-recursion 在服务器跑）。
//! Groth16 终证包裹是**真出证**（固定种子仪式），其约束数打印为 K 无关的量级
//! 证据（上界 = 单手 wrap 实测 4,584,665，report §5）。
//!
//! # 内存依据
//!
//! 电路约束 < 4.58M（同单手 wrap 量级）→ 峰值低于 K=4 批量电路（18.3M，本机
//! 36GB 稳定通过，report §4）→ 本测试内存安全。单重负载：全程只做 1 次
//! setup + 1 次 prove，其余为 <2ms 的 verify；与 lib 测试无并发重活（lib 测试
//! 全部纯宿主逻辑）。

use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use groth16_wrap::felt::{felt_from_hex, felt_to_hex, fr_to_felt, Felt252, Fr};
use groth16_wrap::golden;
use groth16_wrap::wrap_circuit::{WrapWitness, HAND_BINDING_INDEX};
use groth16_wrap::{prove_with_pk, seeded_setup, verify_with_vk};
use stark_recursion::backend::{LeafProver, MockBackend, TreeFolder};
use stark_recursion::chain::{
    acc_genesis, acc_next, BatchPlan, FoldPlan, HandEntry,
};
use stark_recursion::envelope::RootEnvelope;
use stark_recursion::onchain::{encode_settle_root_calldata, fr_publics_to_hex};
use stark_recursion::root_circuit::{derive_statement, host_check, RootCircuit};
use stark_recursion::ProofJson;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

/// 重活串行闸门（当前仅一个重测试；防未来追加时并发撞内存）。
fn heavy_lock() -> MutexGuard<'static, ()> {
    static HEAVY: Mutex<()> = Mutex::new(());
    HEAVY.lock().unwrap()
}

/// 金向量段形态的 K 手（第二手换 binding，同 groth16-wrap roundtrip 批量口径）。
fn golden_hands(k: u64) -> Vec<HandEntry> {
    let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap();
    let base_segment: Vec<Felt252> =
        golden::GOLDEN_OUTPUT.iter().map(|h| felt_from_hex(h).unwrap()).collect();
    (0..k)
        .map(|i| {
            let binding =
                felt_from_hex(golden::GOLDEN_HAND_BINDING).unwrap() + Felt252::from(i);
            let mut segment = base_segment.clone();
            segment[HAND_BINDING_INDEX] = binding;
            let fact =
                WrapWitness { output: segment.clone() }.expected_fact(&program_hash);
            HandEntry {
                statement: groth16_wrap::batch::BatchStatement {
                    program_hash,
                    hand_binding: binding,
                    fact,
                },
                segment,
            }
        })
        .collect()
}

/// felt → Fr 的测试辅助（BatchStatement 载荷是 felt 轨，语句是 Fr 轨）。
fn felt_to_fr_val(f: &Felt252) -> Fr {
    groth16_wrap::felt::felt_to_fr(f)
}

/// 进程峰值 RSS（getrusage；macOS 字节 / Linux KiB）——测试自身内存的证据输出。
fn peak_rss_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe {
            if libc::getrusage(libc::RUSAGE_SELF, &mut ru) == 0 {
                return ru.ru_maxrss as u64;
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe {
            if libc::getrusage(libc::RUSAGE_SELF, &mut ru) == 0 {
                return ru.ru_maxrss as u64 * 1024;
            }
        }
    }
    0
}

#[test]
fn root_wrap_k2_end_to_end() {
    let _gate = heavy_lock();
    let t0 = Instant::now();

    // ── ① K=2 批语句 + keccak 批根 ──────────────────────────────────────
    let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap();
    let plan = BatchPlan::new(program_hash, golden_hands(2)).expect("K=2 batch");
    let keccak_root = plan.keccak_batch_root().unwrap();
    assert_eq!(plan.hands.len(), 2);

    // ── ② 叶（L=1，K 手一叶；H1 = leaf_io.rs:44-63 镜像）─────────────────
    let leaf = MockBackend.prove_leaf(&plan.leaf_preimage(), std::path::Path::new("/tmp"))
        .expect("mock leaf");
    let leaf_words = leaf.output_words().expect("leaf H1");
    assert_eq!(leaf_words, plan.leaf_output_words().unwrap(), "信封 H1 与 chain 层直算一致");

    // ── ③ 局部聚合（L=1 自折叠根，fold.rs:114-120 同形）──────────────────
    let fold_plan = FoldPlan::new(1).unwrap();
    let (root_output, packed) =
        MockBackend.fold_tree(std::slice::from_ref(&leaf), &fold_plan, std::path::Path::new("/tmp"))
            .expect("mock fold");
    packed.validate_shape().expect("packed 树形状");

    // ── ④ 累加链接 + 终证语句 + host 预检 ───────────────────────────────
    // aggregator_program_hash：终证腿程序哈希（scarb 2.18 腿钉扎交付前用占位值；
    // 占位只影响本测试语句值，不影响电路/链路结构）
    let aph = felt_from_hex("0x000000000000000000000000000000000000000000000000000000005350324d")
        .unwrap();
    let acc0 = acc_genesis();
    let (statement, witness) = derive_statement(&aph, &root_output, &acc0, &keccak_root);
    host_check(&statement, &witness, &keccak_root).expect("host 预检必须通过");

    // 累加链接：下一批 acc = 本批 fact（下一批语句会绑定它）
    let fact_felt = fr_to_felt(&statement.batch_fact).unwrap();
    let acc1 = acc_next(&acc0, &fact_felt);
    assert_eq!(felt_to_hex(&fact_felt), felt_to_hex(&acc1));

    // ── ⑤ Groth16 终证包裹（真出证；K 无关）────────────────────────────
    let circuit = RootCircuit { statement, witness: witness.clone() };
    let cs = ConstraintSystem::new_ref();
    circuit.clone().generate_constraints(cs.clone()).expect("合成约束");
    let n_constraints = cs.num_constraints();
    // 上界证据：K=2 终证电路约束必须低于单手 wrap 实测 4,584,665（13 felts vs
    // 17 felts 的 poseidon_hash_many；K 不进入电路形状）
    assert!(
        n_constraints < 4_584_665,
        "root circuit constraints {n_constraints} must stay under single-hand wrap 4,584,665"
    );
    println!("[root-wrap-k2] constraints = {n_constraints} (single-hand wrap = 4,584,665, report §5)");

    let setup_t = Instant::now();
    let pk = seeded_setup(circuit.clone()).expect("seeded setup");
    let setup_secs = setup_t.elapsed().as_secs_f64();
    let prove_t = Instant::now();
    let proof = prove_with_pk(&pk, &circuit).expect("prove");
    let prove_secs = prove_t.elapsed().as_secs_f64();
    println!(
        "[root-wrap-k2] setup = {:.1}s, prove = {:.1}s, peakRSS = {:.1} MiB",
        setup_secs,
        prove_secs,
        peak_rss_bytes() as f64 / (1024.0 * 1024.0)
    );

    // 正例：公开输入全序验证
    let publics = circuit.publics();
    let ok = verify_with_vk(&pk.vk, &publics, &proof).expect("verify");
    assert!(ok, "K=2 终证包裹必须验证通过");

    // 负例 ×3（同一证明、篡改公开输入 → 必须 false）：
    // fact 篡改（语句本体）、root_lo 篡改（keccak 根绑定）、acc_prev 篡改（累加链接）
    let one = Fr::from(1u64);
    let bad_fact = [publics[0], publics[1], publics[2], publics[3], publics[4] + one];
    assert!(!verify_with_vk(&pk.vk, &bad_fact, &proof).unwrap(), "fact 篡改必须拒绝");
    let bad_root = [publics[0], publics[1], publics[2], publics[3] + one, publics[4]];
    assert!(!verify_with_vk(&pk.vk, &bad_root, &proof).unwrap(), "keccak 根篡改必须拒绝");
    let bad_acc = [publics[0], publics[1] + one, publics[2], publics[3], publics[4]];
    assert!(!verify_with_vk(&pk.vk, &bad_acc, &proof).unwrap(), "acc_prev 篡改必须拒绝");

    // ── ⑥ 上链形态：settleRoot calldata + 终证信封 ─────────────────────
    let proof_json = ProofJson::from_ark(&proof);
    let pubs_hex = fr_publics_to_hex(&publics);
    let arr: [String; 5] = pubs_hex.clone().try_into().unwrap();
    let calldata = encode_settle_root_calldata(&keccak_root, &proof_json, &arr).expect("calldata");
    assert_eq!(calldata.len(), 452, "settleRoot 静态 ABI 总长");

    let envelope = RootEnvelope {
        protocol_version: 1,
        aggregator_program_hash: felt_to_hex(&aph),
        root_output_words: root_output,
        keccak_batch_root: hex::encode(keccak_root),
        acc_prev: felt_to_hex(&acc0),
        batch_fact: felt_to_hex(&fr_to_felt(&statement.batch_fact).unwrap()),
        statement_publics: arr,
        packed_tree: packed,
        hands: plan
            .hands
            .iter()
            .map(|h| stark_recursion::envelope::HandRecord {
                hand_binding: felt_to_hex(&h.statement.hand_binding),
                fact: felt_to_hex(&h.statement.fact),
            })
            .collect(),
        wrap: Some(stark_recursion::envelope::WrapSection { proof: proof_json }),
    };
    let s = serde_json::to_string(&envelope).unwrap();
    let back: RootEnvelope = serde_json::from_str(&s).unwrap();
    assert_eq!(back, envelope, "终证信封 serde 往返无损");
    assert_eq!(back.hands.len(), 2);

    println!(
        "[root-wrap-k2] total = {:.1}s（含 setup+prove；门禁预算 <10 分钟）",
        t0.elapsed().as_secs_f64()
    );
    assert!(
        t0.elapsed().as_secs() < 600,
        "K=2 端到端必须 <10 分钟（实测 {:.1}s）",
        t0.elapsed().as_secs_f64()
    );
}

/// 累加链接的双批语句推导（纯 host，无重活）：批 2 的语句绑定批 1 的 fact。
#[test]
fn k2_two_batch_accumulator_host_chain() {
    let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap();
    let aph = felt_from_hex("0x000000000000000000000000000000000000000000000000000000005350324d")
        .unwrap();
    let plan = BatchPlan::new(program_hash, golden_hands(2)).unwrap();
    let root = plan.keccak_batch_root().unwrap();
    let words = plan.leaf_output_words().unwrap();

    let (s1, w1) = derive_statement(&aph, &words, &acc_genesis(), &root);
    host_check(&s1, &w1, &root).unwrap();
    let acc1 = acc_next(&acc_genesis(), &fr_to_felt(&s1.batch_fact).unwrap());

    // 批 2：换批根输出词（不同聚合产物）→ 不同 fact，且语句绑定 acc1
    let mut words2 = words;
    words2[7] = words2[7].wrapping_add(1);
    let (s2, w2) = derive_statement(&aph, &words2, &acc1, &root);
    host_check(&s2, &w2, &root).unwrap();
    assert_ne!(s1.batch_fact, s2.batch_fact);
    assert_eq!(s2.acc_prev, felt_to_fr_val(&acc1), "批 2 语句必须绑定批 1 的 fact（累加链接）");
}
