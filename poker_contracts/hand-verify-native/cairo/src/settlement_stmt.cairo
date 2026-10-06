//! 结算隐私语句（shared module）——供 combined.cairo（合并证明）内联调用。
//!
//! 移植自 `proving-tool/src/settlement_private.cairo`（P2-M2 独立电路），
//! 两处实质差异：
//! 1. **digest 按实际参与者数折叠**：独立电路固定吸收 8 槽（含补零槽的
//!    (0, sign, 0) 三元组），而链上注册的 digest（合约
//!    `compute_settlement_digest` / texas `submit.rs`）只按 calldata 实际
//!    人数折叠——n<8 时两者必然失配（独立电路 `DIGEST_MISMATCH` 中止，
//!    fail-closed 不出证）。本模块改为吸收 player≠0 的前缀槽并强制
//!    「尾部全零」规范：空槽不进吸收链，与链上公式逐字段一致。
//! 2. 语句体做成普通函数（`#[executable]` 包装移到调用方），签名改为
//!    单一 Span 摊平 wire（102 词），供合并程序与未来独立入口复用。
//!
//! **9 人桌迁移（2026-09-30）**：席位容量 8 → 9（德扑常规桌型）。四组
//! 席位索引数组各 +1 词（p/s/m/c × 9），尾部字段右移 4 词；语句公开段
//! 15 → 16 词（cm×9）。约束链（digest 折叠/动作链重放/零和/人数/认领
//! 承诺）逐 assert 语义不动——只有布局常量与循环界右移。
//!
//! wire 布局（settle span，102 词）：
//! ```text
//! [hand_id, registered_digest, n_expected, hand_binding,
//!  p0..p8, s0..s8, m0..m8, c0..c8,
//!  action_log_digest, action_count, w0..w59]
//! ```
//!
//! 返回 16 词公开段 `[MAGIC, hand_id, registered_digest, n_expected,
//! hand_binding, cm_0..cm_8, total_winnings, action_log_digest]`——
//! 公式与 v2 合约逐字段一致（见模块级注释的约束 1–4）。

use core::array::ArrayTrait;
use core::num::traits::DivRem;
use core::poseidon::PoseidonTrait;
use core::hash::HashStateTrait;
use core::traits::TryInto;

/// 公开段成功标记（'SP2M_OK' 短字符串）。
const MAGIC: felt252 = 0x5350324d5f4f4b;

/// 参与者上限（9 人桌常规桌型）。
const N_PLAYERS: usize = 9;

/// 动作日志 Poseidon 吸收链域标签（starknet_keccak(b"zgame.action_log.v1")，
/// 与 texas `action_log_domain()` 同一冻结字面量）。
const DOMAIN: felt252 = 0x11b4269299cbd19c8d701730e13001ca46cbdd2d7a74ba25d7b30be4258fa6e;
/// 动作名白名单（大端 ASCII felt）。
const W_FOLD: felt252 = 0x464F4C44;
const W_CHECK: felt252 = 0x434845434B;
const W_CALL: felt252 = 0x43414C4C;
const W_RAISE: felt252 = 0x5241495345;

/// 词条解包/规则常量（u256）。
const P2_1: u256 = 2;
const P2_4: u256 = 16;
const P2_40: u256 = 1099511627776; // 2^40
const P2_64: u256 = 0x10000000000000000; // 2^64
/// 打包日志词值域上限 2^202（u256 高 128 位段 < 2^74）。
const LOG_MAX_HIGH: u128 = 0x400000000000000000000;
/// 合法性词值域上限 2^194（u256 高 128 位段 < 2^66）。
const LEG_MAX_HIGH: u128 = 0x40000000000000000;

/// settle span 词数（固定 102：4 头 + 9×4 槽 + ald + count + 60 词条词）。
pub const SETTLE_WORDS: usize = 102;

/// 结算隐私语句主函数：全部约束 assert，通过则返回 16 词公开段。
pub fn settlement_statement(settle: Span<felt252>) -> Array<felt252> {
    assert!(settle.len() == SETTLE_WORDS, "BAD_SETTLE_LEN");
    let hand_id = *settle.at(0);
    let registered_digest = *settle.at(1);
    let n_expected = *settle.at(2);
    let hand_binding = *settle.at(3);

    // --- 约束 1：digest 匹配（按实际参与者前缀折叠——与链上注册公式一致） ---
    // 吸收 player≠0 的前缀槽；一旦遇零玩家强制其后全零（规范尾部），空槽
    // 不进吸收链（固定 9 槽全吸收在 n<9 时与注册值失配）。
    let mut h = PoseidonTrait::new();
    h = h.update(hand_id);
    let mut i: usize = 0;
    let mut in_tail = false;
    while i < N_PLAYERS {
        let player = *settle.at(4 + i);
        if player == 0 {
            in_tail = true;
        };
        assert!(!in_tail || player == 0, "NON_TRAILING_EMPTY_SLOT");
        if !in_tail {
            h = h.update(player);
            h = h.update(*settle.at(13 + i));
            h = h.update(*settle.at(22 + i));
        };
        i += 1;
    }
    h = h.update(*settle.at(40));
    let digest = h.finalize();
    assert!(digest == registered_digest, "DIGEST_MISMATCH");

    // --- #18 Phase C 切片 1：动作日志整链重放（30 槽上限） ---
    let action_count = *settle.at(41);
    let count_us: usize = action_count.try_into().expect('COUNT_NOT_USIZE');
    assert!(count_us <= 30, "COUNT_OVER_30");

    let mut ah = PoseidonTrait::new();
    ah = ah.update(DOMAIN);
    let mut i: usize = 0;
    while i < 30 {
        let log_w = *settle.at(42 + i * 2);
        let leg_w = *settle.at(42 + i * 2 + 1);
        let log_u: u256 = log_w.try_into().expect('LOG_NOT_U256');
        assert!(log_u.high < LOG_MAX_HIGH, "LOG_OVER_202BIT");
        if i < count_us {
            let (rest, action) = log_u.div_rem(P2_40.try_into().unwrap());
            let (_amount_hi, flags) = rest.div_rem(P2_4.try_into().unwrap());
            let (_sig_ok, auto) = flags.div_rem(P2_1.try_into().unwrap());
            let action_felt: felt252 = action.try_into().expect('ACTION_NOT_FELT');
            assert!(
                action_felt == W_FOLD
                    || action_felt == W_CHECK
                    || action_felt == W_CALL
                    || action_felt == W_RAISE,
                "BAD_ACTION"
            );
            if auto == 1 {
                // "合法默认"规则（§8.2）：owed==0 或 my_bet≥owed ⇒ Check；
                // 差额≤大盲 ⇒ Call；差额>大盲 ⇒ Fold。Raise 不是合法默认。
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
                assert!(leg_w == 0, "NON_AUTO_LEGALITY_ZERO");
            }
            ah = ah.update(log_w);
        } else {
            assert!(log_w == 0, "PADDING_NOT_ZERO");
            assert!(leg_w == 0, "PADDING_NOT_ZERO");
        }
        i += 1;
    }
    let chain_root = ah.finalize();
    assert!(chain_root == *settle.at(40), "ACTION_CHAIN_MISMATCH");

    // --- 见证良构：sign ∈ {0,1}，|delta| ≤ u64 ---
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = *settle.at(13 + i);
        let m = *settle.at(22 + i);
        assert!(s * (s - 1) == 0, "SIGN_NOT_BOOL");
        let _m_u64: u64 = m.try_into().expect('MAGNITUDE_OVER_U64');
        i += 1;
    }

    // --- 约束 2：零和；约束 3：非零人数 ---
    let mut sum: felt252 = 0;
    let mut count: felt252 = 0;
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = *settle.at(13 + i);
        let m = *settle.at(22 + i);
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
    let mut total_winnings: felt252 = 0;
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = *settle.at(13 + i);
        let m = *settle.at(22 + i);
        if s == 1 {
            if m != 0 {
                total_winnings += m;
                let mut ch = PoseidonTrait::new();
                ch = ch.update(*settle.at(31 + i));
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
    out.append(*settle.at(40));
    out
}
