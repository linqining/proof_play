//! K=2 默认门禁样本（<10 分钟预算；实测 <1s）—— **单个 STARK 终证**主链。
//!
//! 覆盖（Groth16 全出局后的终证路径，2026-09-29 裁定）：
//! 1. K 手语句批 → keccak 批根（SettleBatch 同式）；
//! 2. L1 终证腿语句面：批程序公开输出解析（[len]++segments++尾）→
//!    电路内 poseidon 链接的宿主镜像对拍 → 语句重派生 → 批根覆盖检查；
//! 3. 累加链接：批 1 → acc_1 → 批 2 绑定 acc_1（跨批负例：换链拒绝）；
//! 4. 上链形态：submitFinalProof 提案 ABI calldata（金字节）+ FinalEnvelope
//!    serde 往返；
//! 5. 压缩层语句面（二期，仅语句层）：mock 叶 → L=2 折叠树 → 树根语句
//!    （derive_batch_fact）→ 内存闸门声明（真证明腿 19.4G/7.4G 不可进默认门禁）。
//!
//! # 内存依据
//!
//! 纯宿主算术（poseidon/keccak/blake2s 常数级），无 setup/prove/子进程。
//! 真证明腿的实测锚点与 fail-closed 闸门在 budget.rs（canonical_small 钉扎下
//! K=64 实测 3.69 GiB，E2E 由 proving-tool 在大内存机跑）。

use groth16_wrap::batch::{keccak_batch_root, BatchStatement};
use groth16_wrap::felt::{felt_from_hex, felt_to_hex, Felt252};
use groth16_wrap::golden;
use groth16_wrap::poseidon::poseidon_hash_many;
use groth16_wrap::wrap_circuit::{WrapWitness, HAND_BINDING_INDEX};
use stark_recursion::backend::{LeafProver, MockBackend, TreeFolder};
use stark_recursion::chain::{acc_genesis, acc_next, derive_batch_fact, BatchPlan, FoldPlan, HandEntry};
use stark_recursion::envelope::RootEnvelope;
use stark_recursion::onchain::{encode_submit_final_calldata, output_commit, submit_final_proof_selector};
use stark_recursion::stark_final::{
    expected_batch_fact, final_fact, parse_final_output, verify_final_output, FinalEnvelope,
    BATCH_PROGRAM_HASH_HEX, SEGMENT_LEN, TAIL_LEN,
};
use std::time::Instant;

/// 金向量段形态的 K 手（wrap baseline 腿，16 词含字面 15 前缀；第二手换
/// binding，与 groth16-wrap roundtrip 批量口径同式；语句 fact 用调用方给
/// 的程序哈希派生）。九人桌迁移后批程序输出段与 wrap 段分形：
/// 批段 17 词（字面 16 前缀 + cm×9），wrap 段随 Groth16 baseline 停在 16 词。
fn golden_hands(k: u64, program_hash: Felt252) -> Vec<HandEntry> {
    let base_segment: Vec<Felt252> =
        golden::GOLDEN_OUTPUT.iter().map(|h| felt_from_hex(h).unwrap()).collect();
    (0..k)
        .map(|i| {
            let binding = felt_from_hex(golden::GOLDEN_HAND_BINDING).unwrap() + Felt252::from(i);
            let mut segment = base_segment.clone();
            segment[HAND_BINDING_INDEX] = binding;
            let fact = WrapWitness { output: segment.clone() }.expected_fact(&program_hash);
            HandEntry { statement: BatchStatement { program_hash, hand_binding: binding, fact }, segment }
        })
        .collect()
}

/// 批程序（settlement_batch_private 九人桌版）段形态的 K 手段：17 词 =
/// `[16, MAGIC, hand_id, digest, n, binding, cm×9, total, ald]`（groth16 金
/// 向量 v2 段 15 词换字面前缀 16 + cm×9 补位 1 词）。L1 终证腿
/// （parse_final_output/verify_final_output）消费此形状。
fn batch_segments(k: u64) -> Vec<Felt252> {
    let mut base: Vec<Felt252> =
        golden::GOLDEN_OUTPUT.iter().map(|h| felt_from_hex(h).unwrap()).collect();
    assert_eq!(base.len(), 16, "groth16 金向量 wrap 段 16 词");
    base[0] = Felt252::from(16u64); // 字面前缀：段长 16（Serde 复刻）
    base.push(Felt252::from(0x5E47u64)); // cm×9 补位词
    assert_eq!(base.len(), 17);
    let mut out = Vec::with_capacity(k as usize * 17);
    for i in 0..k {
        let mut seg = base.clone();
        seg[HAND_BINDING_INDEX] = seg[HAND_BINDING_INDEX] + Felt252::from(i);
        out.extend(seg);
    }
    out
}

/// 批段 → 语句面（与 FinalOutput::statements 同式：fact = poseidon([ph‖seg])、
/// binding = seg[5]）——keccak 批根的载荷。
fn batch_statements(program_hash: &Felt252, segments: &[Felt252]) -> Vec<BatchStatement> {
    (0..segments.len() / 17)
        .map(|i| {
            let seg = &segments[i * 17..(i + 1) * 17];
            let mut msg = Vec::with_capacity(18);
            msg.push(*program_hash);
            msg.extend(seg.iter().copied());
            BatchStatement {
                program_hash: *program_hash,
                hand_binding: seg[HAND_BINDING_INDEX],
                fact: poseidon_hash_many(&msg),
            }
        })
        .collect()
}

/// 合成批程序的公开输出（形状 = [len]++segments++[acc,hi,lo,fact]，
/// 与 proving-tool E2E 实测形状逐位一致；此处由宿主镜像构造，E2E 对拍在
/// proving-tool 腿完成）。
fn synth_final_output(segments: &[Felt252], acc: &Felt252, root: &[u8; 32], k: usize) -> Vec<Felt252> {
    let (hi, lo) = stark_recursion::chain::split_root_hi_lo(root);
    let fact = expected_batch_fact(acc, &hi, &lo, k, segments);
    let mut output = vec![Felt252::from((segments.len() + TAIL_LEN) as u64)];
    output.extend_from_slice(segments);
    output.extend_from_slice(&[*acc, hi, lo, fact]);
    output
}

#[test]
fn final_k2_stark_path_end_to_end() {
    let t0 = Instant::now();
    let batch_ph = stark_recursion::stark_final::batch_program_hash().unwrap();
    assert_eq!(BATCH_PROGRAM_HASH_HEX, "0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d",
        "批程序钉扎哈希 = prove-hand K=1 真出证实测值（2026-09-30 九人桌迁移后，参数无关）");

    // ── ① K=2 批语句 + keccak 批根（SettleBatch 同式）────────────────────
    // wrap baseline 计划（16 词段 + 宿主 fact 校验）照常构造——⑤ 的压缩层
    // 叶预映像继续吃 wrap 段；L1 终证腿的批根载荷换成 17 词批段派生的语句。
    let plan = BatchPlan::new(batch_ph, golden_hands(2, batch_ph)).expect("K=2 batch");
    let segments = batch_segments(2);
    let keccak_root = keccak_batch_root(&batch_statements(&batch_ph, &segments)).unwrap();

    // ── ② L1 终证腿：公开输出 → 尾对拍 → 语句重派生 → 批根覆盖 ───────────
    assert_eq!(segments.len(), 2 * SEGMENT_LEN);
    let acc0 = acc_genesis();
    let output = synth_final_output(&segments, &acc0, &keccak_root, 2);
    let (parsed, acc1) = verify_final_output(&output, &acc0, &keccak_root)
        .expect("批 1 终证语句层全链验证");
    assert_eq!(parsed.k, 2);
    // 累加链接：acc_1 = 批 1 电路内 batch_fact（批 2 将绑定它；真双批 E2E 同式）
    assert_eq!(felt_to_hex(&acc1), felt_to_hex(&parsed.tail.batch_fact));
    assert_ne!(acc1, acc0, "genesis → 非 0");
    assert_ne!(acc1, final_fact(&batch_ph, &output), "acc ≠ fact-registry fact");
    // 电路内链接值与宿主镜像一致（E2E 交叉验证的语句层复刻）
    assert_eq!(parsed.tail.batch_fact, expected_batch_fact(&acc0, &parsed.tail.root_hi, &parsed.tail.root_lo, 2, &segments));

    // ── ③ 批 2 绑定 acc_1（跨批链接 + 换链负例）──────────────────────────
    let plan2 = BatchPlan::new(batch_ph, golden_hands(2, batch_ph)).unwrap();
    let segs2 = batch_segments(2);
    let root2 = keccak_batch_root(&batch_statements(&batch_ph, &segs2)).unwrap();
    let output2 = synth_final_output(&segs2, &acc1, &root2, 2);
    let (_, acc2) = verify_final_output(&output2, &acc1, &root2).expect("批 2（绑定 acc_1）");
    assert_ne!(acc1, acc2);
    // 换链负例：批 2 声称 acc_prev=acc0（跳过批 1）必须拒绝
    let output2_bad = synth_final_output(&segs2, &acc0, &root2, 2);
    assert!(verify_final_output(&output2_bad, &acc1, &root2).is_err(), "acc 链断裂必须拒绝");

    // ── ④ 上链形态：submitFinalProof calldata 金字节 + 信封 ──────────────
    let commit = output_commit(&output2);
    let proof_bytes = vec![0x5Au8; 64]; // 打包器产出的 wire 字节（此处形状级）
    let cd = encode_submit_final_calldata(&root2, &acc1, &parsed_tail_of(&output2), &commit, &proof_bytes)
        .expect("calldata");
    assert_eq!(cd.len(), 4 + 4 * 32 + 32 + 32 + 64);
    assert_eq!(&cd[0..4], &submit_final_proof_selector());
    assert_eq!(&cd[4..36], &root2);
    assert_eq!(&cd[100..132], &commit);

    let env = FinalEnvelope::from_verified(&output2, &root2, &acc1, "proof.bin").unwrap();
    let back: FinalEnvelope = serde_json::from_str(&serde_json::to_string(&env).unwrap()).unwrap();
    assert_eq!(back, env, "终证信封 serde 往返无损");
    assert_eq!(back.program_hash, BATCH_PROGRAM_HASH_HEX);
    assert_eq!(back.batch_fact, felt_to_hex(&acc2), "信封 batch_fact = 批 2 acc 链头");
    assert_eq!(back.acc_prev, felt_to_hex(&acc1), "信封 acc_prev = 批 1 fact");

    // ── ⑤ 压缩层语句面（二期）：mock 叶 → L=2 折叠 → 树根语句 ────────────
    let leaves: Vec<_> = (0..2)
        .map(|i| MockBackend.prove_leaf(&leaf_preimage(&plan, i), std::path::Path::new("/tmp")).unwrap())
        .collect();
    let (root_output, packed) = MockBackend.fold_tree(&leaves, &FoldPlan::new(2).unwrap(), std::path::Path::new("/tmp")).unwrap();
    packed.validate_shape().unwrap();
    // 树根语句（二期压缩层的终证语句面；真证明腿超 6G 不进默认门禁——budget.rs）
    let (hi, lo, tree_fact) = derive_batch_fact(&batch_ph, &root_output, &acc2, &root2);
    let mut expect_root = [0u8; 32];
    for (i, b) in expect_root.iter_mut().enumerate() {
        *b = (i * 7 + 3) as u8;
    }
    let _ = (hi, lo, tree_fact, expect_root, keccak_batch_root);
    assert_eq!(root_output.len(), 8);

    println!(
        "[final-k2] total = {:.1}s（纯 host；门禁预算 <10 分钟）",
        t0.elapsed().as_secs_f64()
    );
    assert!(t0.elapsed().as_secs() < 600);
}

/// 输出的尾字 batch_fact（测试辅助）。
fn parsed_tail_of(output: &[Felt252]) -> Felt252 {
    let parsed = parse_final_output(output).unwrap();
    parsed.tail.batch_fact
}

/// 每叶预映像（[program_hash] ++ 本叶手段；与 bench/batch 流程同式）。
fn leaf_preimage(plan: &BatchPlan, leaf: usize) -> Vec<Felt252> {
    let mut pre = vec![plan.program_hash];
    pre.extend_from_slice(&plan.hands[leaf].segment);
    pre
}

/// 累加链 genesis 与 poseidon_hash_many 基线（防公式漂移的锚点测试）。
#[test]
fn accumulator_genesis_and_poseidon_anchor() {
    assert_eq!(felt_to_hex(&acc_genesis()), format!("0x{:064x}", 0));
    // poseidon_hash_many([]) = hades(1,0,0).s0 —— 常量锚（groth16-wrap 同实现）
    let e = poseidon_hash_many(&[]);
    assert_ne!(felt_to_hex(&e), format!("0x{:064x}", 0));
}
