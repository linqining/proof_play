//! P2-M2 结算隐私电路（Cairo1 executable，走 prove-hand 的 Cairo VM → Stwo 管线）。
//!
//! 语句与约束见根 crate `src/settlement_private_circuit.rs` 模块头（P2-M1）。
//! 本程序把规格四条约束真正落进证明：
//! 1. digest：`PoseidonTrait` sponge 吸收 `[hand_id] ++ Σ(player, sign, |delta|)
//!    ++ [action_log_digest]` 后 finalize，必须等于公开入参 `registered_digest`
//!    （与合约 `compute_settlement_digest` 的 `poseidon_hash_span` 同一 sponge：
//!    配对吸收、余项补 1，逐字段一致）。`action_log_digest` 为 #18 Phase B
//!    接线的第 37 词——本手动作日志哈希（game 层 starknet_keccak 链，含
//!    auto 代打标记），把结算锚定到完整动作日志；
//! 2. 零和：`Σ sign·|delta| == 0`（|delta| ≤ u64 在下方强制；9 项之和
//!    < 9·2^64 < 2^68 << felt 素数，模零 ⟺ 整数零）；
//! 3. 人数：非零 |delta| 参与者数 == `n_expected`；
//! 4. 每赢家输出 `cm_i = Poseidon(commitment_i, hand_binding, amount_lo, amount_hi)`
//!    （amount = u256(delta)，low = |delta|，high = 0），非赢家 cm = 0
//!    ——与合约写入 `claim_cms` 的公式逐字段一致。
//!
//! ## Span ABI（2026-09-30 重构 + 9 人桌迁移）
//!
//! 旧 ABI 是 98 个独立命名入参（8 席 + 60 词条词，顶满 standalone 100 参
//! 上限的实测）；9 人桌需 102 词、超限——重构为单一 Span 摊平 wire（与
//! combined.cairo / fold_batch.cairo 的 `[len, elements…]` 摊平约定一致，
//! prove-hand flat 输入 = `[102, w0..w101]` 共 103 词）。**wire 布局与
//! settlement_stmt.cairo（根 crate 语句模块）逐槽对齐**：
//!
//! ```text
//! [0]hand_id [1]registered_digest [2]n_expected [3]hand_binding
//! [4..13] p0..p8   [13..22] s0..s8   [22..31] m0..m8   [31..40] c0..c8
//! [40] action_log_digest   [41] action_count   [42..102] w0..w59（30 词条 ×2）
//! ```
//!
//! 电路体约束**逐条保留**（digest sponge、动作日志整链重放、sign/值域、
//! 零和、人数、认领承诺公式），只把命名参数引用改为槽位索引；席位容量
//! 8 → 9（四组席位循环界右移，公开段 cm×8 → cm×9）。**digest 语义保持
//! 「固定 9 槽全吸收」**（既有语义，仅循环界右移）——与共享模块
//! settlement_stmt.cairo 的「按实际参与者前缀折叠」是两处已知的分叉：
//! 链上注册 digest 按实际人数折叠，故本电路只在满桌（9 席全非零）语料
//! 下与注册值一致（与 settlement_batch_private 同口径）；n<9 的手走
//! combined 路径（settlement_stmt 前缀折叠）。
//!
//! 隐私模型：`(players, signs, mags, commitments)` 是 prove-hand 的程序入参
//!（witness，不进公开段）；公开段（public_outputs.json / Stwo public memory）
//! 只有返回数组 `[MAGIC, hand_id, registered_digest, n_expected, hand_binding,
//! cm_0..cm_8, total_winnings, action_log_digest]`（16 felt，9 人桌口径——
//! v2 合约入口 `SETTLEMENT_SEGMENT_LEN=16` 的段长）—— P2-M3 的
//! `verify_and_settle_dapv_stark_private_v2` 合约以 `registered_digest ==
//! 已登记 digest ∧ 公开段 cms == 待写 claim_cms ∧ segment[15] == 注册的
//! action_log 承诺` 消费该段。
//!
//! §8.2 状态（#18 Phase B/C）：动作日志哈希已进吸收链与公开段；电路内
//! "合法默认"校验（零下注才可 auto-check 等）已落地（Phase C 切片 1/2）；
//! seq 单调仍待落地——主网上线门槛
//! （`docs/design/ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §8.2）。

use core::array::{ArrayTrait, SpanTrait};
use core::num::traits::DivRem;
use core::poseidon::PoseidonTrait;
use core::hash::HashStateTrait;
use core::traits::TryInto;

/// 公开段成功标记（'SP2M_OK' 短字符串）。
const MAGIC: felt252 = 0x5350324d5f4f4b;

/// 参与者上限（9 人桌常规桌型，与根 crate MAX_PARTICIPANTS 一致）。
const N_PLAYERS: usize = 9;

/// settle wire 词数（固定 102：4 头 + 9×4 槽 + ald + count + 60 词条词，
/// settlement_stmt.cairo SETTLE_WORDS 同值）。
const SETTLE_WORDS: usize = 102;

/// 动作日志 Poseidon 吸收链域标签（starknet_keccak(b"zgame.action_log.v1")
/// 的数值，与 texas `action_log_domain()` 同一冻结字面量）——
/// #18 Phase C 切片 1。
const DOMAIN: felt252 = 0x11b4269299cbd19c8d701730e13001ca46cbdd2d7a74ba25d7b30be4258fa6e;
/// 动作名白名单（大端 ASCII felt）。
const W_FOLD: felt252 = 0x464F4C44;
const W_CHECK: felt252 = 0x434845434B;
const W_CALL: felt252 = 0x43414C4C;
const W_RAISE: felt252 = 0x5241495345;

/// 词条解包/规则常量（u256）。
const P2_1: u256 = 2;
const P2_2: u256 = 4;
const P2_4: u256 = 16;
const P2_40: u256 = 1099511627776; // 2^40
const P2_64: u256 = 0x10000000000000000; // 2^64
/// 打包日志词值域上限 2^202（u256 高 128 位段 < 2^74）。
const LOG_MAX_HIGH: u128 = 0x400000000000000000000;
/// 合法性词值域上限 2^194（u256 高 128 位段 < 2^66）。
const LEG_MAX_HIGH: u128 = 0x40000000000000000;

/// 词条区槽位数（30 槽 ×2 词）。
const N_ENTRIES: usize = 30;

#[executable]
fn main(words: Span<felt252>) -> Array<felt252> {
    assert!(words.len() == SETTLE_WORDS, "BAD_SETTLE_LEN");
    let hand_id = *words.at(0);
    let registered_digest = *words.at(1);
    let n_expected = *words.at(2);
    let hand_binding = *words.at(3);
    // players 4..13, signs 13..22, mags 22..31, commitments 31..40,
    // action_log_digest 40, action_count 41, 词条区 42..102。

    // --- 约束 1：digest 匹配（Starknet Poseidon sponge，与链上逐字段一致） ---
    let mut h = PoseidonTrait::new();
    h = h.update(hand_id);
    let mut i: usize = 0;
    while i < N_PLAYERS {
        h = h.update(*words.at(4 + i));
        h = h.update(*words.at(13 + i));
        h = h.update(*words.at(22 + i));
        i += 1;
    }
    // 吸收链尾词：本手动作日志哈希（与 register/register 侧 digest 同公式）。
    h = h.update(*words.at(40));
    let digest = h.finalize();
    assert!(digest == registered_digest, "DIGEST_MISMATCH");

    // --- #18 Phase C 切片 1：动作日志整链重放（poseidon_builtin） ---
    // 语句钉死 30 槽上限（§9.5；wire 102 词 = 41 标量 + count + 30×2）；
    // 每词条 2 词：[日志打包词, 合法性词]。日志词为单 felt
    // 打包（低 → 高）：
    // `action(40) | flags(2)@40 | amount(64)@42 | seq(64)@106 | seat(32)@170`
    // 总宽 202 位；词序与游戏层 action_log_digest_felt 逐字段一致：
    // [DOMAIN] ++ Σ packed_word。合法性词
    // `kind(2) | owed(64)@2 | my_bet(64)@66 | big_blind(64)@130`（194 位）
    // 只作规则见证、不进吸收链；非 auto 词条 canonical 为 0。
    let action_count = *words.at(41);
    let count_us: usize = action_count.try_into().expect('COUNT_NOT_USIZE');
    assert!(count_us <= N_ENTRIES, "COUNT_OVER_30");

    let mut ah = PoseidonTrait::new();
    ah = ah.update(DOMAIN);

    // 打包词值域上限 2^202（= u256 高 128 位段 < 2^74）。
    let mut i: usize = 0;
    while i < N_ENTRIES {
        let log_w = *words.at(42 + i * 2);
        let leg_w = *words.at(42 + i * 2 + 1);
        let log_u: u256 = log_w.try_into().expect('LOG_NOT_U256');
        assert!(log_u.high < LOG_MAX_HIGH, "LOG_OVER_202BIT");
        if i < count_us {
            // 解包（div_rem 返回 (商, 余数)——低位字段在余数侧）：日志词
            // action(40) 低 40 位 | flags(2)@40 | amount(64)@42 |
            // seq(64)@106 | seat(32)@170。
            let (rest, action) = log_u.div_rem(P2_40.try_into().unwrap());
            let (_amount_hi, flags) = rest.div_rem(P2_4.try_into().unwrap());
            // flags = auto | sig_ok<<1：auto = flags 低位。
            let (_sig_ok, auto) = flags.div_rem(P2_1.try_into().unwrap());
            // 动作白名单（大端 ASCII 规范名）。action < 2^40，转 felt 无损。
            let action_felt: felt252 = action.try_into().expect('ACTION_NOT_FELT');
            assert!(
                action_felt == W_FOLD
                    || action_felt == W_CHECK
                    || action_felt == W_CALL
                    || action_felt == W_RAISE,
                "BAD_ACTION"
            );
            if auto == 1 {
                // "合法默认"规则（规则源 = legal_auto_action，§8.2 主网门槛）：
                // owed==0 或 my_bet≥owed ⇒ Check(0)；差额≤大盲 ⇒ Call(1)；
                // 差额>大盲 ⇒ Fold(2)。Raise(3) 不是合法默认。合法性词：
                // kind(2) 低 2 位 | owed(64)@2 | my_bet(64)@66 | big_blind(64)@130。
                let leg_u: u256 = leg_w.try_into().expect('LEG_NOT_U256');
                assert!(leg_u.high < LEG_MAX_HIGH, "LEG_OVER_194BIT");
                let (_q1, kind) = leg_u.div_rem(P2_4.try_into().unwrap());
                let (q2, owed) = _q1.div_rem(P2_64.try_into().unwrap());
                let (big_blind, my_bet) = q2.div_rem(P2_64.try_into().unwrap());
                assert!(kind != 3, "BAD_AUTO_KIND");
                if owed == 0 || my_bet >= owed {
                    assert!(kind == 0, "AUTO_CHECK_REQUIRED");
                } else {
                    let diff = owed - my_bet;
                    if diff <= big_blind {
                        assert!(kind == 1, "AUTO_CALL_REQUIRED");
                    } else {
                        assert!(kind == 2, "AUTO_FOLD_REQUIRED");
                    }
                }
            } else {
                // 非 auto 词条 canonical 为 0（游戏层合法性词打包约定）。
                assert!(leg_w == 0, "NON_AUTO_LEGALITY_ZERO");
            }
            // 吸收链只收日志打包词（与游戏层 digest 同链）。
            ah = ah.update(log_w);
        } else {
            assert!(log_w == 0, "PADDING_NOT_ZERO");
            assert!(leg_w == 0, "PADDING_NOT_ZERO");
        }
        i += 1;
    }

    let chain_root = ah.finalize();
    // 链根必须等于吸收进 settlement digest 的动作日志哈希——电路内重算的
    // 整链与游戏层 digest 锚定一致。
    assert!(chain_root == *words.at(40), "ACTION_CHAIN_MISMATCH");
    // --- 见证良构：sign ∈ {0,1}，|delta| ≤ u64（规格分解的值域） ---
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = *words.at(13 + i);
        let m = *words.at(22 + i);
        assert!(s * (s - 1) == 0, "SIGN_NOT_BOOL");
        // felt→u64 try_into 失败即 |delta| 超出 u64 值域（合约同款守卫）
        let _m_u64: u64 = m.try_into().expect('MAGNITUDE_OVER_U64');
        i += 1;
    }

    // --- 约束 2：零和（有界模零 ⟺ 整数零）；约束 3：人数 ---
    let mut sum: felt252 = 0;
    let mut count: felt252 = 0;
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = *words.at(13 + i);
        let m = *words.at(22 + i);
        if s == 1 {
            sum += m;
        } else {
            sum -= m;
        };
        if m != 0 {
            count += 1;
        };
        i += 1;
    }
    assert!(sum == 0, "NOT_ZERO_SUM");
    assert!(count == n_expected, "COUNT_MISMATCH");

    // --- 约束 4：赢家认领承诺（公开段输出） ---
    let mut out = ArrayTrait::new();
    out.append(MAGIC);
    out.append(hand_id);
    out.append(registered_digest);
    out.append(n_expected);
    out.append(hand_binding);
    // total_winnings = Σ 赢家 |delta|（有界 < 9·2^64 < 2^68，无模回绕）——
    // v2 合约据此把 pot 划入认领托管（公开段取代明文 deltas 成为托管金额来源）。
    let mut total_winnings: felt252 = 0;
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = *words.at(13 + i);
        let m = *words.at(22 + i);
        if s == 1 {
            if m != 0 {
                total_winnings += m;
                let mut ch = PoseidonTrait::new();
                ch = ch.update(*words.at(31 + i));
                ch = ch.update(hand_binding);
                ch = ch.update(m);
                ch = ch.update(0);
                out.append(ch.finalize());
            } else {
                out.append(0);
            };
        } else {
            out.append(0);
        };
        i += 1;
    }
    out.append(total_winnings);
    // 公开段尾词（第 16 felt）：动作日志哈希——v2 合约与注册承诺逐 felt 比对。
    out.append(*words.at(40));
    out
}
