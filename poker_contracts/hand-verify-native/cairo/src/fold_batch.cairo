//! fold_batch — 牌桌手级聚合签名验证 + acc 链折叠（**生产版·多桌**：
//! 并入 102 词 settle wire，FoldDesign v2；多桌规格 out/fold-multitable-spec.md）。
//!
//! 一批 = **T 张牌桌（T ≥ 1）的桌段串接**：每桌 roster（该桌玩家的公钥集）
//! 只进一次电路、keyagg 只算一次；每手 = `settlement_stmt::settlement_statement`
//! 全量语句约束（digest 折叠、NOT_ZERO_SUM、COUNT_MISMATCH、动作日志整链重放、
//! 认领承诺）+ 3 次 poseidon + 单方程 EC 检查 + z̄ 范围检查，claim 逐手
//! 折进 acc 链。**T=1 时 wire 与公开输出与单桌生产版逐词一致**（桌段自定界
//! 串接、无全局 T 词——多桌规格 §2/§8，金样回归钉死）。
//!
//! ## 公开输出（生产形状，fold-spec D1 + 多桌 D1a 修订 + 9 人桌迁移）
//!
//! 每手公开段 = **18 词** = combined 17 词信封原样 + roster_digest 尾插
//! index 17；main 返回 (ΣK) 段 18 词平铺（runner 序列化为 `[len, elements…]`）：
//!
//! ```text
//! 段 index:  0          1        2        3                4        5        6..=14  15      16     17
//!            chain_acc  MAGIC   hand_id  registered_digest n_expected binding cm×9   total   ald    roster_digest
//! ```
//!
//! - word 0–16 与 combined 信封逐词同位（`combined.cairo` 输出 = [new_acc]
//!   ++ settlement 16 词公开段），全部既有槽位锚（MAGIC@1、digest@3、n@4、
//!   binding@5、cm@6..14、total@15、ald@16）零位移复用；唯一新增语义收口
//!   在 index 17（roster_digest，消费面对照 `roster_registry` 注册值——
//!   H1 单射 ⇒ wire pks == 注册 pks）。
//! - **word 0 = 批终 acc 复制**（Q-1 定案）：本程序只有一次 acc 折叠
//!   （`poseidon([prev_acc] ++ claims)`，跨桌 claims 按桌序串接后仍一批一个
//!   链节点——多桌规格 §6），不存在逐手 prev_acc 输入——每段 slot 0 携带
//!   同一批终 acc，使每手段独立成 fact（`poseidon([ph‖seg])`）时都钉住整批
//!   链状态；两链 acc 公式不同源（fold claim 带域标签），跨链 acc 不对等是
//!   有意设计（fold-spec D5-4）。
//! - **word 17 = 本桌 roster_digest（D1a 多桌修订：桌内常量）**：每桌算一次、
//!   桌内段复制（电路结构保证）；不同桌的段在 slot 17 携不同值，段本身
//!   零改动。批内同值检查放宽为链层 run 分组语义（chain.rs，多桌规格 §4）。
//!
//! ## 与 agg0/agg1 测量原型的关系（攻击复审后的生产形状）
//!
//! - agg0 形状（P̄ 为自由 wire 词）已被审方 forge0 攻击否决（wire 自选
//!   P̄ + 攻击者自签 → verified=true/388 steps）——本电路**弃用**该形状。
//! - 本电路内重算（agg1 骨架 + 切片第 2-5 步断言链，语义不动；多桌 =
//!   把「读一次头 + 一层 K 循环」套进桌循环，每手对**所属桌**的 P̄_t 验证）：
//!   1. roster 逐 pk on-curve（`EcPointTrait::new` Option 模式）+ 非恒等
//!      （`NonZeroEcPoint`）——Stark 群阶素数 / cofactor=1（审方 F-1 实测：
//!      无 2-torsion、n·G=O）⇒ on-curve + 非恒等即满阶；z̄<n 用 u256 比较
//!      （RangeCheck 面板，felt 无 PartialOrd）；
//!   2. **电路内 keyagg（每桌一次）**：μ_i = poseidon([keyagg_label, n_t,
//!      pkx, pky])（BDN 系数，Bellare–Neven CCS'06 plain-PK 形状——μ 只经
//!      RO 依赖各自 pk，rogue-key 退化为 poseidon 不动点难度；n 槽取本桌
//!      P_t——同 pks 集不同人数的两桌 μ 不同，多桌规格 §5），
//!      P̄_t = Σ μ_i·pk_i；roster_digest = poseidon([roster_label, n_t]
//!      ++ pks) 电路内从同一桌 wire pks 重算；
//!   3. roster_digest **作为每手公开段 index 17 词**（本桌的）——soundness
//!      不在电路内闭合：换 pks 电路照样自洽（wire pks 仍自由），闭合点在
//!      消费面对照 roster_registry 注册值（H1 单射 ⇒ wire pks == 注册 pks）。
//!      切片阶段 = host parity 门模拟注册面（fold_batch_test T9/T10 与
//!      多桌负例 M9-2）；
//!   4. c = poseidon([sig_label, hand_binding, M_h, P̄_t_x, P̄_t_y, R̄_x,
//!      R̄_y]) 电路内重算；M_h = poseidon([m_label, hand_binding, m1, m2,
//!      cm_digest, roster_digest_t])——**真槽映射（D2，以 settlement_stmt.cairo
//!      实际布局为准）**：hand_binding = wire[3]、m1 = wire[1]
//!      （registered_digest）、m2 = wire[2]（n_expected）、cm_digest =
//!      poseidon(wire[31..=39])（9 词 c0..c8 压缩）。**ald（wire[40]）不是
//!      M_h 独立槽（D2a）**：约束 1 把 ald 吸收进 digest 且断言
//!      digest == registered_digest = wire[1] ∈ M_h，ACTION_CHAIN_MISMATCH
//!      另钉链根 == wire[40]——改 ald 必改 digest 必破 m1。hand_binding 进
//!      c ⇒ 跨手重放 (R̄,z̄) 必改 c（T3）；**roster_digest_t 进 M_h、P̄_t
//!      进 c ⇒ 跨桌混签必拒**（桌 A 手配桌 B roster ⇒ M_h/c 变 ⇒ 方程
//!      z̄·G − c·P̄_B − R̄_A ≠ O ⇒ RESIDUAL_NOT_IDENTITY——多桌规格 §5）；
//!   5. 单方程 z̄·G − c·P̄_t − R̄ == O assert（残差非恒等 → panic → 无证明，
//!      fail-closed）。challenge 均为 raw felt（< P，不显式 mod n）——EC
//!      标量乘按群阶自动归约，与 handbatch `action_sig_challenge_raw`
//!      同纪律，host 镜像逐 felt parity（foldagg.rs）。
//!
//! ## wire 布局（inputs Span，生产版·多桌：桌段自定界串接，无全局 T 词）
//!
//! ```text
//! [P_1, (pkx, pky)×P_1, K_1, (settle 102 词, R̄x, R̄y, z̄)×K_1]
//!   ++ [P_2, pks_2, K_2, blocks×K_2] ++ … ++ [P_T, pks_T, K_T, blocks×K_T]
//! ```
//!
//! - 每桌头 = 单桌头的原样复用（P 运行时变长解析）；每手块 = settle 102 词
//!   + 签名见证 3 词（与单桌块逐词同形）；词数 = Σ_t(2 + 2·P_t + 105·K_t)。
//! - 电路按 cursor 消费桌段：越过本桌 blocks 后 `cursor == words.len()`
//!   即终止——**桌数由 wire 长度自证**，无 T 与实际桌数不一致的检查面。
//! - 桌序 = wire 序 = 段序 = claims 序（多桌规格 §2）；T=1 退化 = 单桌头 +
//!   一层 K 循环，逐词一致。
//! - settle 102 词 = `settlement_stmt.cairo` wire 布局：
//!   `[hand_id, registered_digest, n_expected, hand_binding, p0..p8, s0..s8,
//!   m0..m8, c0..c8, action_log_digest, action_count, w0..w59]`。
//!
//! main 的完整 inputs = `[prev_acc, span_len] ++ 上述 Span`（Span 参数
//! [len, elements…] 摊平，与 combined.cairo 同约定）。
//!
//! ## fail-closed
//! 任何桌任何 roster 点非满阶编码 / z̄ ≥ n / 任一语句约束失败（digest 折叠 /
//! 动作链重放 / sign∈{0,1} / |delta|≤u64 / NOT_ZERO_SUM / COUNT_MISMATCH /
//! 认领承诺）/ 任一残差非恒等 / 桌段截断或越界（at()/slice() 越界 panic）
//! → panic → 无证明。K_t=0 空桌段不检（无 soundness 影响，只浪费 keyagg
//! steps；host 构造器拒绝——多桌规格 M1-b/Q-M2）。

mod settlement_stmt;

use core::array::{ArrayTrait, SpanTrait};
use core::ec::{ec_point_unwrap, EcPoint, EcPointTrait, EcStateTrait, NonZeroEcPoint};
use core::option::Option;
use core::poseidon::poseidon_hash_span;
use core::traits::TryInto;

use settlement_stmt::settlement_statement;

/// STARK 曲线群阶（与 dual::hand_batch_stark::STARK_N 同一常量；n < P）。
const STARK_N: u256 =
    0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f;

/// STARK 曲线生成元（与 dual::hand_batch_stark / agg1.cairo 同一常量）。
const GENERATOR_X: felt252 =
    0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca;
const GENERATOR_Y: felt252 =
    0x005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f;

// ---- BDN 域标签（T8 KAT 与 foldagg.rs 逐字节钉死；语义不动）----
const KEYAGG_LABEL: felt252 = 'poker/fold-batch/keyagg.v1';
const ROSTER_LABEL: felt252 = 'poker/fold-batch/roster.v1';
const M_LABEL: felt252 = 'poker/fold-batch/msg.v1';
const SIG_LABEL: felt252 = 'poker/fold-batch/sig.v1';
const CLAIM_LABEL: felt252 = 'poker/fold-batch/claim.v1';

/// settle wire 词数（settlement_stmt.cairo SETTLE_WORDS 同值）。
const SETTLE_WORDS: usize = 102;
/// cm 槽起点：c0..c8 = settle wire[31..=39]（settlement_stmt.cairo
/// 以 settle.at(31 + i)、i∈0..9 吸收的实测布局）。
const CM_START: usize = 31;
/// cm 槽词数（9 词 c0..c8 压缩进 cm_digest，D2/K-4）。
const CM_WORDS: usize = 9;
/// 每手签名见证词数（R̄x, R̄y, z̄）。
const SIG_WORDS: usize = 3;
/// 每手 wire 块词数 = settle 102 + 签名见证 3。
const HAND_WORDS: usize = SETTLE_WORDS + SIG_WORDS;
/// settlement_statement 公开段词数（[MAGIC … ald]，combined.cairo 输出尾）。
const STMT_WORDS: usize = 16;
/// 每手公开段词数 = [acc] ++ 语句公开段 16 ++ [roster_digest]（D1）。
pub const SEGMENT_LEN: usize = STMT_WORDS + 2;

#[executable]
fn main(prev_acc: felt252, words: Span<felt252>) -> Array<felt252> {
    let words_len = words.len();
    let g_nz: NonZeroEcPoint = EcPointTrait::new(GENERATOR_X, GENERATOR_Y)
        .unwrap()
        .try_into()
        .unwrap();
    // 跨桌 claims 按桌序（桌内手序）append——acc 单次折叠的输入（Q-1/M6）
    let mut claims: Array<felt252> = array![];
    // 语句公开段缓冲（ΣK×16 词；acc 为批常量、roster_digest 为桌内常量，
    // 末尾统一插——Q-1/D1a）
    let mut stmt_words: Array<felt252> = array![];
    // 逐手段的本桌 roster_digest（D1a 多桌修订：桌内常量、跨桌可异）
    let mut seg_rosters: Array<felt252> = array![];
    let mut total_hands: usize = 0;

    // ---- 桌循环：cursor 越过本桌 blocks 后 == words.len() 即终止（桌数由
    // wire 长度自证——M2；截断/越界 ⇒ at()/slice() 越界 panic，fail-closed）
    let mut cursor: usize = 0;
    while cursor < words_len {
        // ---- 第 1-2 步（本桌）：roster 逐 pk 满阶编码检查 + 电路内 keyagg
        // + roster_digest（每桌一次——M2/M5；n 槽 = 本桌 P_t）
        let n_players: usize = (*words.at(cursor)).try_into().unwrap();
        let mut roster_in: Array<felt252> = array![ROSTER_LABEL, *words.at(cursor)];
        let mut agg = EcStateTrait::init();
        let mut i: usize = 0;
        while i < n_players {
            let pkx = *words.at(cursor + 1 + 2 * i);
            let pky = *words.at(cursor + 2 + 2 * i);
            roster_in.append(pkx);
            roster_in.append(pky);
            // on-curve（EcPointTrait::new Option 模式）+ 非恒等：n 素 /
            // cofactor=1 / 无 2-torsion（审方 F-1 实测）⇒ 满阶，fail-closed。
            let pk_nz: NonZeroEcPoint = match EcPointTrait::new(pkx, pky) {
                Option::Some(p) => match p.try_into() {
                    Option::Some(nz) => nz,
                    Option::None => panic_with_felt252('PK_IS_IDENTITY'),
                },
                Option::None => panic_with_felt252('PK_OFF_CURVE'),
            };
            // BDN 系数（μ 只经 poseidon RO 依赖 (n_t, pk)，CCS'06 plain-PK 形状）
            let mu = poseidon_hash_span(
                array![KEYAGG_LABEL, *words.at(cursor), pkx, pky].span(),
            );
            agg.add_mul(mu, pk_nz);
            i += 1;
        }
        let roster_digest = poseidon_hash_span(roster_in.span());
        let pbar_pt: EcPoint = agg.finalize();
        let pbar_nz: NonZeroEcPoint = match pbar_pt.try_into() {
            Option::Some(nz) => nz,
            Option::None => panic_with_felt252('PBAR_IS_IDENTITY'),
        };
        let (pbar_x, pbar_y) = ec_point_unwrap(pbar_nz);

        // ---- 第 3-5 步（本桌逐手）：语句约束 + M_h/c 真槽重算 + z̄ 范围
        // 检查 + 单方程（对本桌 P̄_t 验证——M5 跨桌闭合点）
        let n_hands: usize = (*words.at(cursor + 1 + 2 * n_players)).try_into().unwrap();
        let mut block: usize = cursor + 2 + 2 * n_players;
        let mut j: usize = 0;
        while j < n_hands {
            // 本手 102 词 settle wire；语句函数内全部 assert（digest 按实际人数
            // 折叠、动作日志整链重放、sign∈{0,1}、|delta|≤u64、NOT_ZERO_SUM、
            // COUNT_MISMATCH、认领承诺），fail-closed。
            let settle = words.slice(block, SETTLE_WORDS);
            let segment = settlement_statement(settle);
            let seg = segment.span();
            assert!(seg.len() == STMT_WORDS, "BAD_STMT_SEGMENT_LEN");

            // M_h 真槽（D2）：hand_binding=wire[3]、m1=wire[1]
            // （registered_digest）、m2=wire[2]（n_expected）、
            // cm_digest=poseidon(wire[31..=39])（9 词 c0..c8 压缩）。
            let hand_binding = *settle.at(3);
            let m1 = *settle.at(1);
            let m2 = *settle.at(2);
            let cm_digest = poseidon_hash_span(settle.slice(CM_START, CM_WORDS));

            let rbar_x = *words.at(block + SETTLE_WORDS);
            let rbar_y = *words.at(block + SETTLE_WORDS + 1);
            let zbar = *words.at(block + SETTLE_WORDS + 2);

            // R̄ 满阶编码检查（fail-closed）
            let rbar_pt: EcPoint = match EcPointTrait::new(rbar_x, rbar_y) {
                Option::Some(p) => p,
                Option::None => panic_with_felt252('RBAR_OFF_CURVE'),
            };
            let _rbar_nz: NonZeroEcPoint = match rbar_pt.try_into() {
                Option::Some(nz) => nz,
                Option::None => panic_with_felt252('RBAR_IS_IDENTITY'),
            };

            // z̄ < n（RangeCheck 面板；z̄ 出域即签名方程无意义）
            let z_u: u256 = zbar.into();
            assert!(z_u < STARK_N, "ZBAR_OUT_OF_RANGE");

            // M_h（修复 2/4 形状：真槽 + 本桌 roster_digest 进共签消息）
            let m_h = poseidon_hash_span(
                array![M_LABEL, hand_binding, m1, m2, cm_digest, roster_digest].span(),
            );
            // 挑战 c（raw felt——群阶自动归约，与 host 逐 felt parity）
            let c = poseidon_hash_span(
                array![SIG_LABEL, hand_binding, m_h, pbar_x, pbar_y, rbar_x, rbar_y].span(),
            );

            // claim 绑定手（binding + 共签消息）后折进 acc 链
            claims.append(poseidon_hash_span(array![CLAIM_LABEL, hand_binding, m_h].span()));

            // 单方程：z̄·G − c·P̄_t − R̄ == O（残差非恒等 → panic → 无证明）
            let pbar_neg_nz: NonZeroEcPoint = match (-pbar_pt).try_into() {
                Option::Some(nz) => nz,
                Option::None => panic_with_felt252('PBAR_IS_IDENTITY'),
            };
            let rbar_neg_nz: NonZeroEcPoint = match (-rbar_pt).try_into() {
                Option::Some(nz) => nz,
                Option::None => panic_with_felt252('RBAR_IS_IDENTITY'),
            };
            let mut st = EcStateTrait::init();
            st.add_mul(zbar, g_nz);
            st.add_mul(c, pbar_neg_nz);
            st.add(rbar_neg_nz);
            let residual: EcPoint = st.finalize();
            let residual_nz: Option<NonZeroEcPoint> = residual.try_into();
            match residual_nz {
                Option::None => {},
                Option::Some(_) => panic_with_felt252('RESIDUAL_NOT_IDENTITY'),
            }

            // 语句公开段 16 词入批缓冲 + 本手段记本桌 digest
            let mut w: usize = 0;
            while w < STMT_WORDS {
                stmt_words.append(*seg.at(w));
                w += 1;
            }
            seg_rosters.append(roster_digest);

            block += HAND_WORDS;
            j += 1;
        }
        total_hands += n_hands;
        cursor = block;
    }

    // ---- acc 链折叠：acc = poseidon([prev_acc] ++ claims)（与 host
    // fold_acc / recurse::fold_accumulator 同公式；跨桌 claims 已按桌序
    // 串接——单次折叠，Q-1/M6）
    let mut acc_in: Array<felt252> = array![prev_acc];
    let claims_span = claims.span();
    let mut w: usize = 0;
    while w < claims_span.len() {
        acc_in.append(*claims_span.at(w));
        w += 1;
    }
    let acc = poseidon_hash_span(acc_in.span());

    // ---- 公开输出：(ΣK) 段 × 18 词平铺，段 = [acc] ++ 语句公开段(16) ++
    // [本桌 roster_digest]（D1：word 0–16 = combined 信封同位、index 17 =
    // 本桌 roster_digest——D1a 多桌修订；acc 为批常量、roster_digest 为
    // 桌内常量）
    let stmts = stmt_words.span();
    let rosters = seg_rosters.span();
    let mut out = ArrayTrait::new();
    let mut j: usize = 0;
    while j < total_hands {
        out.append(acc);
        let mut w: usize = 0;
        while w < STMT_WORDS {
            out.append(*stmts.at(j * STMT_WORDS + w));
            w += 1;
        }
        out.append(*rosters.at(j));
        j += 1;
    }
    out
}
