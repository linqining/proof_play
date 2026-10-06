//! fold/combined 双跑对拍（规格 out/fold-spec.md §5/D5）——同一 settle 语料
//! 双吃：combined 腿逐手 17 词信封、fold 腿一批 K 手 18 词段，跨腿对拍。
//!
//! 两个形态（形态按规格 D5，本文件承载两档）：
//!
//! 1. **轻量 host 对拍**（默认门禁，`fold_combined_parity_same_settle_corpus_host`）：
//!    不出证——两腿各走 host 期望侧，同一 102 词 wire 单一来源：
//!    - combined 腿：诚实 action 任务 `host_fold_tasks` 直验折叠出 acc 链，
//!      信封 = `[acc] ++ expected_segment(16)`（combined.cairo 输出同形）；
//!    - fold 腿：生产 D2 真槽映射（m1←wire[1]、m2←wire[2]、hand_binding←wire[3]、
//!      cm_digest←poseidon(wire[31..=39])）→ claim → 批终 acc =
//!      `fold_acc(prev, claims)`（批级，Q-1）→ 段 = `[批终 acc] ++
//!      expected_segment(16) ++ [roster_digest]`（D1 布局）；
//!    - 断言 = D5 机器化 3a（跨腿 word 1..=16 逐词相等）/ 3b（fold 批 acc
//!      两路径一致）/ 3c（slot 17 == roster 注册面锚）+ D2 槽位钉死 + D2a
//!      ald 传递绑定演示。**对 soundness 零证明力**（T4 语义：只钉公式/
//!      映射/布局漂移；「wire pks == 注册 pks」的闭合点在生产 roster_registry
//!      合约对照，fold_batch_test T9/T10 与合约负例臂承载）。
//!
//! 1b. **轻量多桌 host 对拍**（默认门禁，`fold_multitable_parity_two_tables_host`）：
//!    1 的多桌形态——两桌**不同人数**（P=5/K=2 + P=2/K=1）同批，fold 腿的
//!    M_h roster_digest 槽取**本桌**锚、claims 桌序串接；断言 = 3a 跨腿逐手
//!    word 1..=16 相等 + 3b **跨桌** slot 0 同值 == `fold_acc(prev, claims
//!    桌序串接)`（换桌序 ⇒ 换 acc）+ 3c seg[17] 桌内常量 == 本桌 H(pks_t)
//!    （两桌各异）+ m2 槽逐桌独立（n_expected = 本桌人数）。
//!
//! 2. **heavy 出证腿**（`#[ignore]`，`t13_fold_combined_parity_heavy_prove_roundtrip`，
//!    D5.1–3/5 全形）：combined 腿逐手 `prove_combined_layer`（其内部 acc/
//!    segment 双 parity 门即该腿既有机器核对，D5.2）、fold 腿 `prove_fold_batch`
//!    一次吃 8 手（其内部「出证后」roster/acc/段 parity 门 + `--check-only`
//!    独立复验即 D5.5 门序纪律与 D5.3d）；断言 = fold 段 word 1..=16 ==
//!    combined 输出 word 1..=16（跨腿主对拍）+ 逐链 acc/roster 锚出证后对照。
//!
//! 3. **heavy 多桌对拍腿**（`#[ignore]`，`t14_multitable_parity_heavy_prove_roundtrip`，
//!    多桌规格 M9-5(a) 的 fold_parity 泛化）：≥2 桌**不同人数**语料（P=9/K=2 +
//!    P=2/K=2，ΣK=4）——combined 腿仍逐手 17 词信封（桌结构无关）、fold 腿
//!    `prove_fold_batch_multitable` 多桌一批 18 词段；断言 = 逐手 3a（跨腿
//!    word 1..=16 逐词相等）+ 3b（slot 0 全段同值 == 共享批终 acc =
//!    `fold_acc(prev, claims 桌序串接)`）+ 3c（**桌锚**：seg[17] == 本桌
//!    anchor.roster_digest，两桌 digest 各异）。仍**不断言** combined acc ==
//!    fold acc（D5-4 不变）。运行形态同 heavy（`#[ignore]` + `--release --
//!    --ignored --nocapture`，多桌规格 §9 M9-5 行）。
//!
//! **明确不断言**（D5.4）：combined chain_acc == fold acc。两链 claim 公式
//! 不同源——combined claim = poseidon([hand_binding, payload_digest, 桶计数…])
//! 无域标签（combined.cairo claim_preimage）；fold claim = poseidon([CLAIM_LABEL,
//! hand_binding, M_h])（fold_batch.cairo:152）。两条 acc 链是**有意的两个
//! 对象**：parity 只做逐链 host 重算一致 + 跨腿结算词一致，无跨链 acc 比较。
//!
//! 运行（heavy 依赖 prove-hand 二进制）：
//!   cargo test -p hand-verify-native --test fold_parity_test            # 轻量（默认门禁）
//!   cargo test --release -p hand-verify-native \
//!     --test fold_parity_test -- --ignored --nocapture                  # heavy（与 T1 同形态）
//!
//! D5.6 的合约层负例臂（未注册 roster / 16 词段 / 错哈希 fact / 重放）属
//! PokerDualSettlement 测试区（snforge），不在本 host 文件承载。

use std::path::PathBuf;

use starknet_crypto::{poseidon_hash_many, Felt};

use hand_verify_native::combined::{
    acc_fold, action_log_domain, build_settle_statement, host_verify, prove_combined_layer,
    segment_magic, SettleStatement, GENESIS,
};
use hand_verify_native::foldagg::{
    aggregate_sign, claim_word, cm_digest_from_wire, expected_public_output,
    expected_public_output_tables, fold_acc, mint_roster_sks, msg_digest, parse_settle_wire,
    prove_fold_batch, prove_fold_batch_multitable, roster_digest, roster_pks_from_sks,
    AggregatedHand, FoldTable, FOLD_ROSTER_INDEX, FOLD_SEGMENT_LEN, SETTLE_CM_START,
    SETTLE_CM_WORDS, SETTLE_WORDS,
};
use hand_verify_native::mint::mint_hand;
use hand_verify_native::recurse::{hand_binding as task_binding, host_fold_tasks, RecurseTask};

// ---------------------------------------------------------------------------
// 公共 fixture：一张 9 人 roster × 8 手，同一 settle 语料双吃（D5.1）
// ---------------------------------------------------------------------------

const PARITY_SEED: u64 = 0x9A17;
const N_PLAYERS: usize = 9;
const K_HANDS: usize = 8;

fn det(seed: u64, i: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(i), Felt::from(0xF01Du64)])
}

/// 一手对拍语料：一条 settle 语句 + 其 102 词 wire（两腿单一来源）+ 该手的
/// 诚实 action 任务（combined 腿 claims 来源；binding 与 settle 一致）。
struct HandCorpus {
    hb: Felt,
    settle: SettleStatement,
    wire: Vec<Felt>,
    tasks: Vec<RecurseTask>,
}

/// 铸对拍语料：9 席全参与零和（席 0/1 赢、席 2..8 均摊输）、空动作日志
/// （count=0 → ald = poseidon([DOMAIN])，与 combined_test/fold T1 已证语料
/// 同形）、赢家承诺非零。`wire = settle.wire_words()` 即 fold 腿的
/// FoldHand.settle 与 combined 腿语句的共同源。
///
/// **为何语料不带非空动作日志**：log 词在电路内有语义校验（settlement_stmt
/// 「LOG_OVER_202BIT」/action ∈ {FOLD,CHECK,CALL,RAISE}/auto-legality 规则），
/// 且 host `expected_segment` 的链根公式（combined.rs:127-131 折 entry 双词）
/// 与电路重放（settlement_stmt.cairo:118 只折 log 词）在 count>0 时不同式——
/// 该分歧属 combined/settlement_stmt 两侧的既有面，不在本对拍修复范围；
/// 空日志（count=0）两式同归 poseidon([DOMAIN])，语料取此已证形状。
fn build_corpus() -> Vec<HandCorpus> {
    (0..K_HANDS as u64)
        .map(|h| {
            let hb = task_binding(PARITY_SEED * 1000 + h);
            let players: Vec<Felt> =
                (0..9u64).map(|i| det(PARITY_SEED + h, 10 + i) + Felt::ONE).collect();
            let unit = 100 * (h as i128 + 1);
            let deltas: Vec<i128> =
                vec![6 * unit, unit, -unit, -unit, -unit, -unit, -unit, -unit, -unit];
            let commitments: Vec<Felt> =
                (0..9u64).map(|i| det(PARITY_SEED + h, 30 + i)).collect();
            let ald = poseidon_hash_many(&[action_log_domain()]);
            let settle = build_settle_statement(
                500 + h,
                hb,
                &players,
                &deltas,
                &commitments,
                ald,
                &[],
            )
            .expect("honest settle statement");
            let wire = settle.wire_words();
            let tasks: Vec<RecurseTask> = (0..1u64)
                .map(|_| RecurseTask {
                    hand_binding: hb,
                    payload: mint_hand(hb, 2, 1, 0, 0, 0, PARITY_SEED + h),
                })
                .collect();
            HandCorpus { hb, settle, wire, tasks }
        })
        .collect()
}

fn out_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("output/fold-parity-test")
        .join(tag);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

/// 多桌对拍语料（M9-5a）：一张 P 人桌的 K 手——settle 语句按**本桌人数**铸
/// （首席赢 (P−1)·unit、其余席各 −unit，零和）、空动作日志（与 build_corpus
/// 同一已证形状）、承诺恒 9 词（wire 布局 cm×9 与人数无关）；hand_id 全批
/// 唯一（id_base 按桌段隔离）。seed 同时是本桌 roster 铸种（mint_roster_sks）。
fn build_table_corpus(players: usize, k_hands: usize, seed: u64, id_base: u64) -> Vec<HandCorpus> {
    (0..k_hands as u64)
        .map(|h| {
            let hb = task_binding(seed * 1000 + h);
            let ps: Vec<Felt> =
                (0..players as u64).map(|i| det(seed + h, 10 + i) + Felt::ONE).collect();
            let unit = 100 * (h as i128 + 1);
            let mut deltas: Vec<i128> = vec![-unit; players];
            deltas[0] = unit * (players as i128 - 1); // 零和：赢 (P−1)u、输家各 u
            let commitments: Vec<Felt> = (0..9u64).map(|i| det(seed + h, 30 + i)).collect();
            let ald = poseidon_hash_many(&[action_log_domain()]);
            let settle = build_settle_statement(
                500 + id_base + h,
                hb,
                &ps,
                &deltas,
                &commitments,
                ald,
                &[],
            )
            .expect("honest multitable settle statement");
            let wire = settle.wire_words();
            let tasks: Vec<RecurseTask> = (0..1u64)
                .map(|_| RecurseTask {
                    hand_binding: hb,
                    payload: mint_hand(hb, 2, 1, 0, 0, 0, seed + h),
                })
                .collect();
            HandCorpus { hb, settle, wire, tasks }
        })
        .collect()
}

/// canonical_small 参数（L1 批量终证腿钉扎参数集；与 fold_batch_test T1 同口径）。
fn canonical_params() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("proving-tool/params/canonical_small.json");
    p.exists().then_some(p)
}

// ---------------------------------------------------------------------------
// 轻量 host 对拍（默认门禁；T4 语义——公式/映射/布局漂移检测，零证明力）
// ---------------------------------------------------------------------------

/// **轻量 D5 host 形**：同一 102 词 settle wire 双吃——combined 腿（诚实任务
/// acc 链 + 17 词信封）vs fold 腿（D2 真槽映射 claims + 批终 acc + 18 词段）。
/// 断言：D5 3a 跨腿 word 1..=16 逐词相等、3b fold 批 acc 两路径一致、3c
/// slot 17 == roster 锚（批常量）、D2 槽位钉死（含 K-4 的 9 词 cm 压缩）、
/// D2a ald 传递绑定演示。
#[test]
fn fold_combined_parity_same_settle_corpus_host() {
    let hands = build_corpus();
    let sks = mint_roster_sks(N_PLAYERS, PARITY_SEED);
    let pks = roster_pks_from_sks(&sks);
    let roster_d = roster_digest(&pks);

    // ---- combined 腿（host 期望侧）：逐手 acc 链 + 16 词信封 ----
    let mut prev_acc = GENESIS;
    let mut envelopes: Vec<Vec<Felt>> = Vec::with_capacity(K_HANDS);
    let mut combined_claims: Vec<Felt> = Vec::with_capacity(K_HANDS);
    for (h, hc) in hands.iter().enumerate() {
        let acc = host_fold_tasks(&hc.tasks, prev_acc).expect("combined acc chain");
        // 两路径：claim 词独立重算（host 直验 → RecurseTask::claim → 折叠）
        let report = host_verify(hc.hb, &hc.tasks[0].payload).expect("host verify");
        let claim = hc.tasks[0].claim(&report);
        assert_eq!(
            acc,
            acc_fold(prev_acc, &[claim]),
            "hand {h}: combined acc 两路径一致（host_fold_tasks vs 手工折叠）"
        );
        combined_claims.push(claim);
        let segment = hc.settle.expected_segment().expect("expected segment");
        assert_eq!(segment.len(), 16);
        let mut env = Vec::with_capacity(17);
        env.push(acc);
        env.extend_from_slice(&segment);
        envelopes.push(env);
        prev_acc = acc;
    }

    // ---- fold 腿（host 期望侧）：D2 真槽映射 → claim → 批终 acc → 17 词段 ----
    let mut fold_claims: Vec<Felt> = Vec::with_capacity(K_HANDS);
    for (h, hc) in hands.iter().enumerate() {
        let w = &hc.wire;
        assert_eq!(w.len(), SETTLE_WORDS, "hand {h}: settle wire 102 词");
        // D2 槽位钉死（settlement_stmt.cairo 布局）：wire[1]=registered_digest、
        // wire[2]=n_expected、wire[3]=hand_binding、wire[31..=39]=c0..c8、
        // wire[40]=ald。
        assert_eq!(w[1], hc.settle.registered_digest, "hand {h}: wire[1] = registered_digest");
        assert_eq!(w[2], Felt::from(hc.settle.n_expected), "hand {h}: wire[2] = n_expected");
        assert_eq!(w[3], hc.hb, "hand {h}: wire[3] = hand_binding");
        assert_eq!(
            &w[SETTLE_CM_START..SETTLE_CM_START + SETTLE_CM_WORDS],
            &hc.settle.commitments[..],
            "hand {h}: wire[31..=39] = c0..c8（9 词，K-4）"
        );
        assert_eq!(w[40], hc.settle.action_log_digest, "hand {h}: wire[40] = ald");
        // cm_digest 是 9 词压缩（D2/K-4）——与切片 2 词占位压缩必不同值。
        let cm8 = cm_digest_from_wire(w);
        assert_eq!(
            cm8,
            poseidon_hash_many(&w[SETTLE_CM_START..SETTLE_CM_START + SETTLE_CM_WORDS]),
            "hand {h}: cm_digest = poseidon(wire[31..=39]) 内联一致"
        );
        assert_ne!(
            cm8,
            poseidon_hash_many(&w[SETTLE_CM_START..SETTLE_CM_START + 2]),
            "hand {h}: 8 词压缩 ≠ 切片 2 词占位（K-4 修复面）"
        );
        // M_h 三自由槽（D2）：m1←wire[1]、m2←wire[2]（不是 roster 人数占位）、
        // hand_binding←wire[3]；roster_digest 为电路内自算值（host = 注册面锚）。
        let m_h = msg_digest(w[3], w[1], w[2], cm8, roster_d);
        fold_claims.push(claim_word(w[3], m_h));
        // m2 槽活性：m2 = wire[2]（本手非零结算人数 9）≠ roster 人数占位
        // 语义混用面（9 人 roster 恰好同为 9——用另一手人数差异钉：语料全部
        // 9 参与本钉不动，改由 D2a 演示承担槽活性）。
        assert_eq!(w[2], Felt::from(9u64), "hand {h}: n_expected = 9（全席参与）");
    }
    let batch_acc = fold_acc(GENESIS, &fold_claims);
    // 3b：批终 acc 独立内联重算（poseidon([prev] ++ claims)）。
    let mut acc_in = vec![GENESIS];
    acc_in.extend_from_slice(&fold_claims);
    assert_eq!(
        batch_acc,
        poseidon_hash_many(&acc_in),
        "fold 批终 acc 两路径一致（fold_acc vs 内联 poseidon）"
    );

    // fold 18 词段装配（D1 布局）：语句段走 foldagg 自有 wire→statement
    // 解析路径（parse_settle_wire），非直接复用 combined 侧语句对象。
    let mut fold_segments: Vec<Vec<Felt>> = Vec::with_capacity(K_HANDS);
    for hc in &hands {
        let reparsed = parse_settle_wire(&hc.wire).expect("wire → statement round trip");
        let segment = reparsed.expected_segment().expect("reparsed segment");
        let mut seg = Vec::with_capacity(FOLD_SEGMENT_LEN);
        seg.push(batch_acc); // slot 0：批终 acc（Q-1，一批同值）
        seg.extend_from_slice(&segment); // word 1..=16
        seg.push(roster_d); // slot 17：roster 批常量（D1a）
        assert_eq!(seg.len(), FOLD_SEGMENT_LEN);
        fold_segments.push(seg);
    }

    // ---- D5 断言 ----
    // 3a 跨腿主对拍：fold 段 word 1..=16 == combined 信封 word 1..=16
    // （两侧同源 settlement_statement(settle)——等值才有「同账」意义）。
    for h in 0..K_HANDS {
        assert_eq!(
            fold_segments[h][1..FOLD_ROSTER_INDEX],
            envelopes[h][1..17],
            "hand {h}: fold seg words 1..=16 must equal combined envelope words 1..=16"
        );
        assert_eq!(fold_segments[h][1], segment_magic(), "hand {h}: 段首 MAGIC 锚");
    }
    // 3c roster 门：slot 17 批常量 == 注册面锚 == H(pks)。
    for (h, seg) in fold_segments.iter().enumerate() {
        assert_eq!(seg[FOLD_ROSTER_INDEX], roster_d, "hand {h}: slot 17 roster 批常量");
    }
    assert_eq!(roster_d, roster_digest(&pks), "roster 锚 == H(pks)");
    // D1 布局形状：combined 信封 17 词、fold 段 18 词（唯一新增 slot 17）。
    assert_eq!(envelopes[0].len(), 17);
    assert_eq!(fold_segments[0].len(), FOLD_SEGMENT_LEN);

    // D2a ald 传递绑定演示：改 ald 必改 registered_digest（=wire[1]=m1∈M_h）
    // 必改 claim 必改批 acc——ald 不是 M_h 独立槽，但其改动无法绕过 M_h。
    // st2 携一条合法 CALL 动作日志（log 词 = 电路 log_w 编码的 ASCII 'CALL'，
    // auto=0 ⇒ legality=0 合法；链根取电路重放式 poseidon([DOMAIN, log_w])）。
    // 仅取 expected_digest（ald 参与折叠），不调 expected_segment——
    // count>0 的链根公式 host/电路分歧见 build_corpus 注释。
    {
        let hc = &hands[0];
        let log_call = Felt::from_hex("0x43414c4c").expect("ASCII 'CALL'"); // settlement_stmt W_CALL
        let ald2 = poseidon_hash_many(&[action_log_domain(), log_call]);
        let players: Vec<Felt> =
            (0..9u64).map(|i| det(PARITY_SEED, 10 + i) + Felt::ONE).collect();
        let unit = 100i128;
        let deltas = vec![6 * unit, unit, -unit, -unit, -unit, -unit, -unit, -unit, -unit];
        let commitments: Vec<Felt> =
            (0..9u64).map(|i| det(PARITY_SEED, 30 + i)).collect();
        let st2 = build_settle_statement(
            500,
            hc.hb,
            &players,
            &deltas,
            &commitments,
            ald2,
            &[[log_call, Felt::ZERO]],
        )
        .expect("alternate-ald statement");
        assert_ne!(
            st2.expected_digest(),
            hc.settle.expected_digest(),
            "改 ald 必改 expected_digest（= wire[1] = m1 ∈ M_h，D2a）"
        );
        let m_h2 = msg_digest(
            hc.hb,
            st2.expected_digest(),
            Felt::from(9u64),
            cm_digest_from_wire(&hc.wire),
            roster_d,
        );
        assert_ne!(
            claim_word(hc.hb, m_h2),
            fold_claims[0],
            "改 ald 经 m1 必改 claim（传递绑定闭合，D2a）"
        );
    }

    // 两链 claim 公式不同源（D5.4 公式面）：同手两链 claim 词必不同——
    // combined claim 无域标签、fold claim 带 CLAIM_LABEL + M_h。
    for h in 0..K_HANDS {
        assert_ne!(
            combined_claims[h],
            fold_claims[h],
            "hand {h}: 两链 claim 词不同源（不同 preimage）"
        );
    }
    // D5.4：**无** combined acc vs fold acc 的比较断言——两条 acc 链是有意
    // 的两个对象（见模块注释），parity 只做逐链重算一致 + 跨腿结算词一致。
}

// ---------------------------------------------------------------------------
// 轻量多桌 host 对拍（默认门禁；多桌规格 M9-5(a) host 侧——D5 形态多桌扩展）
// ---------------------------------------------------------------------------

/// **轻量多桌 D5 host 形**（与单桌轻量形态同构，T4 语义——公式/映射/布局
/// 漂移检测，**零证明力**）：两桌**不同人数**（P=5/K=2 + P=2/K=1，ΣK=3）
/// 同批双吃同一 settle 语料——
/// - combined 腿：桌结构无关，桌序串接逐手 acc 链 + 16 词信封；
/// - fold 腿：逐手 D2 真槽映射，M_h 的 roster_digest 槽取**本桌**锚 →
///   claims 桌序串接 → 批终 acc（Q-1 单次折叠）→ 18 词段（slot 17 = 本桌
///   digest，D1a 桌内常量）。
///
/// 断言：3a 跨腿逐手 word 1..=16 相等（桌结构无关）；3b **跨桌** slot 0
/// 同值 == `fold_acc(GENESIS, claims 桌序串接)`（两路径一致 + 换桌序 ⇒ 换
/// acc）；3c seg[17] 桌内常量 == 本桌 H(pks_t)（两桌各异）；多桌槽活性：
/// m2 = wire[2] = 本桌 n_expected（5 ≠ 2——m2 槽按桌独立）；M_h 桌绑定
/// 镜像：换他桌 digest ⇒ 本桌 M_h/claim 变（跨桌闭合的 host 镜像——真闸
/// 在电路 m9_2a/m9_2b（panic）与出证后门 m9_2c，此处只钉 host 公式槽位）。
#[test]
fn fold_multitable_parity_two_tables_host() {
    const MT_HOST_SEED: u64 = 0x5D2E;
    // 两桌不同人数（M9-5a：≥2 桌不同人数；seed 与 t14 heavy 腿语料解耦）。
    let table_specs: [(usize, usize); 2] = [(5, 2), (2, 1)];
    let total_hands: usize = table_specs.iter().map(|&(_, k)| k).sum();
    let corpora: Vec<Vec<HandCorpus>> = table_specs
        .iter()
        .enumerate()
        .map(|(t, &(p, k))| build_table_corpus(p, k, MT_HOST_SEED + t as u64, 200 * t as u64))
        .collect();
    // 逐桌 roster（fold 腿锚）：sks/pks/digest 与语料 seed 同源派生。
    let rosters: Vec<(Vec<Felt>, Vec<(Felt, Felt)>, Felt)> = table_specs
        .iter()
        .enumerate()
        .map(|(t, &(p, _))| {
            let sks = mint_roster_sks(p, MT_HOST_SEED + t as u64);
            let pks = roster_pks_from_sks(&sks);
            let rd = roster_digest(&pks);
            (sks, pks, rd)
        })
        .collect();
    assert_ne!(rosters[0].2, rosters[1].2, "不同人数两桌 roster 锚必各异（语料前提）");

    // ---- combined 腿（host 期望侧，桌结构无关）：桌序串接逐手 acc 链 ----
    let mut prev_acc = GENESIS;
    let mut envelopes: Vec<Vec<Felt>> = Vec::with_capacity(total_hands);
    let mut combined_claims: Vec<Felt> = Vec::with_capacity(total_hands);
    for (t, corpus) in corpora.iter().enumerate() {
        for (h, hc) in corpus.iter().enumerate() {
            let acc = host_fold_tasks(&hc.tasks, prev_acc).expect("combined acc chain");
            let report = host_verify(hc.hb, &hc.tasks[0].payload).expect("host verify");
            let claim = hc.tasks[0].claim(&report);
            assert_eq!(
                acc,
                acc_fold(prev_acc, &[claim]),
                "table {t} hand {h}: combined acc 两路径一致"
            );
            combined_claims.push(claim);
            let segment = hc.settle.expected_segment().expect("expected segment");
            assert_eq!(segment.len(), 16);
            let mut env = Vec::with_capacity(17);
            env.push(acc);
            env.extend_from_slice(&segment);
            envelopes.push(env);
            prev_acc = acc;
        }
    }
    assert_eq!(envelopes.len(), total_hands);

    // ---- fold 腿（host 期望侧）：D2 真槽映射（对本桌锚）→ claims 桌序串接 ----
    let mut fold_claims: Vec<Felt> = Vec::with_capacity(total_hands);
    let mut n_expecteds: Vec<u64> = Vec::with_capacity(total_hands);
    for (t, corpus) in corpora.iter().enumerate() {
        let roster_d = rosters[t].2;
        for (h, hc) in corpus.iter().enumerate() {
            let w = &hc.wire;
            assert_eq!(w.len(), SETTLE_WORDS, "table {t} hand {h}: settle wire 102 词");
            // D2 槽位钉死（多桌：槽语义逐桌独立——m2 = 本桌 n_expected）。
            assert_eq!(
                w[1],
                hc.settle.registered_digest,
                "table {t} hand {h}: wire[1] = registered_digest"
            );
            assert_eq!(
                w[2],
                Felt::from(hc.settle.n_expected),
                "table {t} hand {h}: wire[2] = n_expected"
            );
            assert_eq!(w[3], hc.hb, "table {t} hand {h}: wire[3] = hand_binding");
            assert_eq!(
                &w[SETTLE_CM_START..SETTLE_CM_START + SETTLE_CM_WORDS],
                &hc.settle.commitments[..],
                "table {t} hand {h}: wire[31..=39] = c0..c8（9 词，K-4）"
            );
            assert_eq!(w[40], hc.settle.action_log_digest, "table {t} hand {h}: wire[40] = ald");
            n_expecteds.push(hc.settle.n_expected);
            let cm8 = cm_digest_from_wire(w);
            let m_h = msg_digest(w[3], w[1], w[2], cm8, roster_d);
            fold_claims.push(claim_word(w[3], m_h));
        }
    }
    // 多桌 m2 槽活性：两桌 n_expected 各为本桌人数（5/5 vs 2——同批共存且
    // 互不等，证明 m2 槽逐桌独立、无跨桌串扰）。
    assert_eq!(n_expecteds, vec![5, 5, 2], "m2 槽逐桌独立（P_1=5、P_2=2）");

    // 3b：批终 acc 两路径（fold_acc vs 内联 poseidon([prev] ++ claims)）。
    let batch_acc = fold_acc(GENESIS, &fold_claims);
    let mut acc_in = vec![GENESIS];
    acc_in.extend_from_slice(&fold_claims);
    assert_eq!(
        batch_acc,
        poseidon_hash_many(&acc_in),
        "多桌批终 acc 两路径一致（claims 桌序串接）"
    );
    // 换桌序 ⇒ 换 acc（claims 顺序绑定，Q-1 单次折叠的顺序面）。
    let (t0_claims, t1_claims) = fold_claims.split_at(table_specs[0].1);
    let swapped_acc = fold_acc(GENESIS, &[t1_claims, t0_claims].concat());
    assert_ne!(swapped_acc, batch_acc, "换桌序 ⇒ 换批终 acc（claims 顺序绑定）");

    // fold 18 词段装配（D1a 布局）：逐手段 slot 17 = 本桌 digest。
    let mut fold_segments: Vec<Vec<Felt>> = Vec::with_capacity(total_hands);
    for (t, corpus) in corpora.iter().enumerate() {
        let roster_d = rosters[t].2;
        for hc in corpus {
            let reparsed = parse_settle_wire(&hc.wire).expect("wire → statement round trip");
            let segment = reparsed.expected_segment().expect("reparsed segment");
            let mut seg = Vec::with_capacity(FOLD_SEGMENT_LEN);
            seg.push(batch_acc); // slot 0：批终 acc（Q-1，跨桌同值）
            seg.extend_from_slice(&segment); // word 1..=16
            seg.push(roster_d); // slot 17：本桌 roster digest（D1a 桌内常量）
            assert_eq!(seg.len(), FOLD_SEGMENT_LEN);
            fold_segments.push(seg);
        }
    }

    // ---- D5 断言（多桌形态）----
    // 3a 跨腿主对拍：fold 段 word 1..=16 == combined 信封 word 1..=16
    // （桌序 = combined 串接序；桌结构对语句词零漂移）。
    for j in 0..total_hands {
        assert_eq!(
            fold_segments[j][1..FOLD_ROSTER_INDEX],
            envelopes[j][1..17],
            "hand {j}: fold seg words 1..=16 must equal combined envelope words 1..=16"
        );
        assert_eq!(fold_segments[j][1], segment_magic(), "hand {j}: 段首 MAGIC 锚");
    }
    // 3b 桌内/跨桌 acc 锚：全部段（两桌）slot 0 同值 == 批终 acc（Q-1）。
    assert!(
        fold_segments.iter().all(|s| s[0] == batch_acc),
        "slot 0 跨桌全部段同值（Q-1 单次折叠）"
    );
    // 3c 桌内 roster 锚：seg[17] == 本桌锚（桌内常量、两桌各异）。
    let mut j = 0usize;
    for (t, corpus) in corpora.iter().enumerate() {
        let roster_d = rosters[t].2;
        for _ in corpus {
            assert_eq!(
                fold_segments[j][FOLD_ROSTER_INDEX],
                roster_d,
                "hand {j} (table {t}): slot 17 == 本桌 roster 锚"
            );
            j += 1;
        }
    }
    assert_eq!(j, total_hands);
    assert_eq!(envelopes[0].len(), 17);
    assert_eq!(fold_segments[0].len(), FOLD_SEGMENT_LEN);

    // M_h 桌绑定镜像（零证明力，T4 语义）：本桌手换他桌 digest ⇒ M_h/claim
    // 必变（跨桌闭合的真闸在电路 m9_2a/m9_2b 与出证后门 m9_2c；此处只钉
    // host 公式的 digest 槽确实取本桌锚）。
    {
        let w = &corpora[0][0].wire;
        let own = msg_digest(w[3], w[1], w[2], cm_digest_from_wire(w), rosters[0].2);
        let cross = msg_digest(w[3], w[1], w[2], cm_digest_from_wire(w), rosters[1].2);
        assert_ne!(cross, own, "M_h 的 roster_digest 槽取本桌锚（跨桌必变）");
        assert_ne!(claim_word(w[3], cross), fold_claims[0], "换桌 digest 必改本桌 claim");
        assert_eq!(claim_word(w[3], own), fold_claims[0], "本桌锚重算 claim 一致");
    }
    // D5.4（多桌不变）：两链 claim 公式不同源——同手两链 claim 词必不同。
    for j in 0..total_hands {
        assert_ne!(combined_claims[j], fold_claims[j], "hand {j}: 两链 claim 词不同源");
    }
}

// ---------------------------------------------------------------------------
// heavy 出证腿（#[ignore]；D5.1–3/5 全形；与 T1 同运行形态）
// ---------------------------------------------------------------------------

/// **T13（heavy，D5 全形）**：同一 8 手语料双腿真出证——combined 腿逐手
/// `prove_combined_layer`（内部 acc/segment 双 parity 门 + `--check-only`，
/// D5.2）、fold 腿 `prove_fold_batch` 一次吃 8 手（内部「出证后」roster/acc/
/// 段三重 parity 门 + `--check-only` 独立复验，D5.3d/5 门序纪律）。断言 =
/// fold 段 word 1..=15 == combined 输出 word 1..=15（跨腿主对拍）+ 逐链
/// acc/roster 锚出证后对照。**不断言两链 acc 跨等**（D5.4）。
#[test]
#[ignore]
fn t13_fold_combined_parity_heavy_prove_roundtrip() {
    let params = canonical_params();
    let hands = build_corpus();
    let sks = mint_roster_sks(N_PLAYERS, PARITY_SEED);
    let pks = roster_pks_from_sks(&sks);
    let roster_d = roster_digest(&pks);
    let magic = segment_magic();

    // ---- combined 腿：逐手真出证（17 词信封 = [acc] ++ segment 16）----
    let mut prev_acc = GENESIS;
    let mut combined_envelopes: Vec<Vec<Felt>> = Vec::with_capacity(K_HANDS);
    for (h, hc) in hands.iter().enumerate() {
        let outcome = prove_combined_layer(
            &hc.tasks,
            &hc.settle,
            prev_acc,
            &out_dir(&format!("t13-combined-h{h}")),
            params.as_deref(),
        )
        .expect("combined leg must prove");
        // 从 MAGIC 锚定信封（runner 可能在输出前部有回显词，同
        // prove_combined_layer 内部定位法）。
        let mp = outcome
            .public_output
            .iter()
            .position(|w| *w == magic)
            .expect("MAGIC in combined public output");
        assert!(mp >= 1, "public output has no room for acc before MAGIC");
        let envelope: Vec<Felt> = outcome.public_output[mp - 1..mp + 16].to_vec();
        assert_eq!(envelope.len(), 17);
        combined_envelopes.push(envelope);
        prev_acc = outcome.cairo_acc;
    }

    // ---- fold 腿：8 手一批真出证（K×18 词段）----
    let mut agg_hands: Vec<AggregatedHand> = Vec::with_capacity(K_HANDS);
    for (h, hc) in hands.iter().enumerate() {
        let ws: Vec<Felt> =
            (0..N_PLAYERS as u64).map(|i| det(PARITY_SEED + h as u64, 200 + i)).collect();
        let agg = aggregate_sign(&sks, &ws, &hc.wire).expect("honest aggregate");
        // host 公式两路径：AggregatedHand.claim == 轻量映射重算（同 wire）。
        let w = &hc.wire;
        let m_h = msg_digest(w[3], w[1], w[2], cm_digest_from_wire(w), roster_d);
        assert_eq!(
            agg.claim,
            claim_word(w[3], m_h),
            "hand {h}: fold claim 两路径一致（aggregate_sign vs D2 映射重算）"
        );
        agg_hands.push(agg);
    }
    // 注册面锚（host 切片模拟）：批终 acc = fold_acc(prev, claims)、
    // roster_digest = H(pks)。**先出证、后对照**的门序由 prove_fold_batch
    // 内部承载（foldagg.rs 门序注释：电路对 wire pks 自由，锚对照在出证后）。
    let anchor = expected_public_output(GENESIS, &pks, &agg_hands);
    assert_eq!(anchor.roster_digest, roster_d);
    let fold_outcome = prove_fold_batch(
        GENESIS,
        &pks,
        &agg_hands,
        &anchor,
        &out_dir("t13-fold-k8"),
        params.as_deref(),
    )
    .expect("fold leg must prove");
    assert_eq!(fold_outcome.segments.len(), K_HANDS);

    // ---- D5 断言（全部出证后）----
    println!(
        "| leg | hands | steps | EC_OP | poseidon | prove ms | total ms | reverify ms | proof B |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    println!(
        "| combined | 1×{} | - | - | - | - | - | - | - |（逐手出证见 output/fold-parity-test/t13-combined-h*）|",
        K_HANDS
    );
    println!(
        "| fold | {} | {} | {} | {} | {} | {} | {} | {} |",
        K_HANDS,
        fold_outcome.steps,
        fold_outcome.ec_ops,
        fold_outcome.poseidon_ops,
        fold_outcome.cairo_prove_ms,
        fold_outcome.total_ms,
        fold_outcome.check_verify_ms,
        fold_outcome.proof_bytes,
    );
    for h in 0..K_HANDS {
        let seg = &fold_outcome.segments[h];
        assert_eq!(seg.len(), FOLD_SEGMENT_LEN, "hand {h}: 18 词段");
        // 3a 跨腿主对拍：同一 settle 语料，两腿结算词零漂移。
        assert_eq!(
            seg[1..FOLD_ROSTER_INDEX],
            combined_envelopes[h][1..17],
            "hand {h}: fold seg words 1..=16 must equal combined output words 1..=16（跨腿主对拍）"
        );
        // 3c roster 门（出证后对照注册面锚；prove_fold_batch 内部已门，此处
        // 复述为对拍记录）。
        assert_eq!(seg[FOLD_ROSTER_INDEX], anchor.roster_digest, "hand {h}: slot 17 roster 锚");
        // 3b acc 门（批终 acc 一批同值；prove_fold_batch 内部已门，复述记录）。
        assert_eq!(seg[0], anchor.expected_acc, "hand {h}: slot 0 批终 acc 锚");
    }
    // 批终 acc 批常量（Q-1）：K 段 slot 0 全同值。
    let first_acc = fold_outcome.segments[0][0];
    assert!(fold_outcome.segments.iter().all(|s| s[0] == first_acc));
    // D5.4：无 combined chain acc vs fold 批 acc 的跨链比较——两条 acc 链
    // 是有意的两个对象（claim 公式不同源，见模块注释）。
}

// ---------------------------------------------------------------------------
// heavy 多桌对拍腿（#[ignore]；多桌规格 M9-5(a)；--release -- --ignored）
// ---------------------------------------------------------------------------

/// **T14（heavy，M9-5(a) 的 fold_parity 泛化）**：多桌语料（≥2 桌**不同
/// 人数**：P=9/K=2 + P=2/K=2，ΣK=4）双腿真出证——combined 腿逐手
/// `prove_combined_layer`（桌结构无关，17 词信封）、fold 腿
/// `prove_fold_batch_multitable` 两桌一批（18 词段；其内部 parity 门逐手对
/// **本桌**锚）。断言（逐手 3a-3c 带桌锚）：3a 跨腿 word 1..=16 逐词相等、
/// 3b slot 0 == 共享批终 acc == `fold_acc(prev, claims 桌序串接)`（两路径）、
/// 3c seg[17] == 本桌 anchor.roster_digest（两桌各异）。**不断言两链 acc
/// 跨等**（D5-4 不变——多桌化不改变该裁定）。
#[test]
#[ignore]
fn t14_multitable_parity_heavy_prove_roundtrip() {
    let params = canonical_params();
    const MT_SEED: u64 = 0x9A71;
    // 两桌不同人数（M9-5a 语料要求 ≥2 桌不同人数；K_t=2 控制出证时长）。
    let table_specs: [(usize, usize); 2] = [(9, 2), (2, 2)];
    let total_hands: usize = table_specs.iter().map(|&(_, k)| k).sum();
    let corpora: Vec<Vec<HandCorpus>> = table_specs
        .iter()
        .enumerate()
        .map(|(t, &(p, k))| build_table_corpus(p, k, MT_SEED + t as u64, 100 * t as u64))
        .collect();
    // 逐桌 roster（fold 腿签名面）：sks/pks/digest 与语料 seed 同源派生。
    let rosters: Vec<(Vec<Felt>, Vec<(Felt, Felt)>, Felt)> = table_specs
        .iter()
        .enumerate()
        .map(|(t, &(p, _))| {
            let sks = mint_roster_sks(p, MT_SEED + t as u64);
            let pks = roster_pks_from_sks(&sks);
            let rd = roster_digest(&pks);
            (sks, pks, rd)
        })
        .collect();
    let magic = segment_magic();

    // ---- combined 腿：逐手真出证（桌序串接；17 词信封 = [acc] ++ segment 16）----
    let mut prev_acc = GENESIS;
    let mut combined_envelopes: Vec<Vec<Felt>> = Vec::with_capacity(total_hands);
    for (t, corpus) in corpora.iter().enumerate() {
        for (h, hc) in corpus.iter().enumerate() {
            let outcome = prove_combined_layer(
                &hc.tasks,
                &hc.settle,
                prev_acc,
                &out_dir(&format!("t14-combined-t{t}h{h}")),
                params.as_deref(),
            )
            .expect("combined leg must prove (table structure is irrelevant to it)");
            let mp = outcome
                .public_output
                .iter()
                .position(|w| *w == magic)
                .expect("MAGIC in combined public output");
            assert!(mp >= 1, "public output has no room for acc before MAGIC");
            let envelope: Vec<Felt> = outcome.public_output[mp - 1..mp + 16].to_vec();
            assert_eq!(envelope.len(), 17);
            combined_envelopes.push(envelope);
            prev_acc = outcome.cairo_acc;
        }
    }
    assert_eq!(combined_envelopes.len(), total_hands);

    // ---- fold 腿：两桌一批真出证（ΣK×18 词段，桌序 = 段序）----
    let mut tables: Vec<FoldTable> = Vec::with_capacity(table_specs.len());
    for (t, corpus) in corpora.iter().enumerate() {
        let (sks, pks, roster_d) = &rosters[t];
        let mut agg_hands: Vec<AggregatedHand> = Vec::with_capacity(corpus.len());
        for (h, hc) in corpus.iter().enumerate() {
            let ws: Vec<Felt> = (0..table_specs[t].0 as u64)
                .map(|i| det(MT_SEED + t as u64 + h as u64, 200 + i))
                .collect();
            let agg = aggregate_sign(sks, &ws, &hc.wire).expect("honest aggregate");
            // host 公式两路径（对本桌锚）：AggregatedHand.claim == D2 映射重算。
            let w = &hc.wire;
            let m_h = msg_digest(w[3], w[1], w[2], cm_digest_from_wire(w), *roster_d);
            assert_eq!(
                agg.claim,
                claim_word(w[3], m_h),
                "table {t} hand {h}: fold claim 两路径一致（对本桌 roster 锚）"
            );
            agg_hands.push(agg);
        }
        tables.push(FoldTable::new(pks.clone(), agg_hands).expect("honest table"));
    }
    // 逐桌锚（注册面 host 切片）：expected_acc 全桌共享（Q-1 单次折叠）。
    let anchors = expected_public_output_tables(GENESIS, &tables);
    assert_ne!(
        anchors[0].roster_digest, anchors[1].roster_digest,
        "不同人数两桌的 roster 锚必须各异（M9-5a 语料前提）"
    );
    for (t, (_, _, rd)) in rosters.iter().enumerate() {
        assert_eq!(anchors[t].roster_digest, *rd, "table {t} anchor == H(pks_t) 注册面");
    }
    let fold_outcome = prove_fold_batch_multitable(
        GENESIS,
        &tables,
        &anchors,
        &out_dir("t14-fold-t2-p8p2-k2k2"),
        params.as_deref(),
    )
    .expect("multitable fold leg must prove");
    assert_eq!(fold_outcome.segments.len(), total_hands);
    assert_eq!(fold_outcome.n_tables, table_specs.len());
    assert_eq!(fold_outcome.table_players, vec![9, 2]);
    assert_eq!(fold_outcome.table_hands, vec![2, 2]);

    // ---- M9-5(a) 断言（全部出证后，逐手 3a-3c 带桌锚）----
    let mut j = 0usize;
    for (t, table) in tables.iter().enumerate() {
        for _ in &table.hands {
            let seg = &fold_outcome.segments[j];
            assert_eq!(seg.len(), FOLD_SEGMENT_LEN, "hand {j} (table {t}): 18 词段");
            // 3a 跨腿主对拍：同一 settle 语料，两腿结算词零漂移（桌结构无关）。
            assert_eq!(
                seg[1..FOLD_ROSTER_INDEX],
                combined_envelopes[j][1..17],
                "hand {j} (table {t}): fold seg words 1..=16 must equal combined output words 1..=16（跨腿主对拍）"
            );
            // 3c 桌锚（出证后对照注册面；prove_fold_batch_multitable 内部已逐手
            // 门，此处复述为对拍记录）。
            assert_eq!(
                seg[FOLD_ROSTER_INDEX],
                anchors[t].roster_digest,
                "hand {j} (table {t}): slot 17 == 本桌 roster 锚"
            );
            // 3b acc 门：slot 0 == 共享批终 acc（两桌同值）。
            assert_eq!(
                seg[0],
                anchors[t].expected_acc,
                "hand {j} (table {t}): slot 0 == 共享批终 acc"
            );
            j += 1;
        }
    }
    assert_eq!(j, fold_outcome.segments.len());
    // 3b 期望侧独立重算：claims 桌序串接 → fold_acc（两路径一致）。
    let claims: Vec<Felt> = tables.iter().flat_map(|t| t.hands.iter().map(|h| h.claim)).collect();
    let expect_acc = fold_acc(GENESIS, &claims);
    assert!(
        anchors.iter().all(|a| a.expected_acc == expect_acc),
        "两桌锚共享同一批终 acc（Q-1 单次折叠）"
    );
    assert_eq!(fold_outcome.cairo_acc, expect_acc, "批终 acc 出证值 == host 重算");
    // 逐桌 cairo 段 slot17（D1a 桌内常量）== 本桌锚。
    assert_eq!(fold_outcome.cairo_table_roster_digests, vec![anchors[0].roster_digest, anchors[1].roster_digest]);
    println!(
        "| fold-MT | T=2 (9×2+2×2) | steps {} | EC_OP {} | poseidon {} | total {} ms | reverify {} ms | proof {} B |",
        fold_outcome.steps,
        fold_outcome.ec_ops,
        fold_outcome.poseidon_ops,
        fold_outcome.total_ms,
        fold_outcome.check_verify_ms,
        fold_outcome.proof_bytes,
    );
    // D5.4：无 combined chain acc vs fold 批 acc 的跨链比较——两条 acc 链是
    // 有意的两个对象（claim 公式不同源；多桌化不改变该裁定，见模块注释）。
}
