//! settlement_batch_private —— K 手结算语句批量 Cairo 电路（L1 终证腿）。
//!
//! 与单手 `settlement_private.cairo`（P2-M2）逐字段同逻辑：digest sponge、
//! 零和、人数、赢家 cm、动作日志整链重放与合法性词规则——差别只在入参
//! 形态、公开段分段与累加链尾：
//! - 入参 `main(k, acc_prev, root_hi, root_lo, data)`：`data` 为 K × 102 felt
//!   的单手入参顺次拼接（每手内部布局与 settlement_stmt.cairo wire 同序；
//!   `Array<felt252>` 走 corelib ArraySerde = [len, elems…] 前缀，prove-hand
//!   flat 输入 = [k, acc_prev, root_hi, root_lo, 102·k, …]，ABI 由 spike_abi
//!   实证）。单手独立电路的 98 参数形态在 9 人桌下需 102 参数，顶破
//!   Cairo1 standalone 入参上限 100——批量数组形态是唯一可行 ABI。
//! - 公开段：每手 17 felt `[16, MAGIC, hand_id, digest, n, binding,
//!   cm_0..cm_8, total, action_digest]`（字面 16 前缀 = Serde 形态复刻），
//!   K 手顺次拼接。
//! - **累加链尾（递归聚合陈述层，stark-recursion/src/stark_final.rs 镜像）**：
//!   程序把 `acc_prev`（批 n-1 的 fact；首批 = 0）与 keccak 批根拆分
//!   `root_hi/root_lo`（batch.rs:46-55 同式，与 zchain SettleBatch.sol 逐式
//!   一致）复制进公开段，并在**电路内**以 corelib HashState sponge
//!   （= groth16-wrap poseidon_hash_many 同一构造，宿主已对拍）计算
//!   `batch_fact = poseidon([acc_prev, root_hi, root_lo, k] ++ 全部手段)`。
//!   终局 fact = poseidon([program_hash ‖ 全部公开输出])（fact-verify
//!   fact_for_output 同式）——由归纳法把全部历史批 fact 链进本批证明。
//!
//! **9 人桌迁移（2026-09-30）**：席位 8 → 9——四组席位索引数组各 +1 词，
//! 尾部字段右移 4 词（ald 36→40、count 37→41、词条区 38→42）、公开段
//! 16 → 17 felt（字面前缀 15→16、cm×8→cm×9）。约束链语义一行不动。
//! 重编必然换 program_hash → 同步重钉 stark_final.rs / proving-tool
//! main.rs / fact-verify 三处钉扎。
//!
//! 语句钉死：任一手任一断言失败 → 整批无证明（fail-closed）。
//! 手数上限 64（canonical_small trace 地板 2^20 内的政策上限；
//! chain.rs:44-51 测试钉死）。

use core::array::ArrayTrait;
use core::num::traits::DivRem;
use core::poseidon::PoseidonTrait;
use core::hash::HashStateTrait;
use core::traits::TryInto;

const MAGIC: felt252 = 0x5350324d5f4f4b;
const N_PLAYERS: usize = 9;
const N_WORDS: usize = 30; // 每手 30 词条 ×2 词
const HAND_WORDS: usize = 60; // 词条区 60 felt
const HAND_INPUT_LEN: usize = 41 + 1 + HAND_WORDS; // 102

const DOMAIN: felt252 = 0x11b4269299cbd19c8d701730e13001ca46cbdd2d7a74ba25d7b30be4258fa6e;
const W_FOLD: felt252 = 0x464F4C44;
const W_CHECK: felt252 = 0x434845434B;
const W_CALL: felt252 = 0x43414C4C;
const W_RAISE: felt252 = 0x5241495345;

const P2_1: u256 = 2;
const P2_4: u256 = 4;
const P2_40: u256 = 1099511627776; // 2^40
const P2_64: u256 = 0x10000000000000000; // 2^64
const LOG_MAX_HIGH: u128 = 0x400000000000000000000;
const LEG_MAX_HIGH: u128 = 0x40000000000000000;

const MAX_HANDS: usize = 64;

/// 读第 hand_idx 手的第 i 个入参 felt（data 内按 102 布局顺次排布）。
fn read(data: Span<felt252>, hand_idx: usize, i: usize) -> felt252 {
    *data.at(hand_idx * HAND_INPUT_LEN + i)
}

/// 处理一手：与单手程序逐字段同逻辑，返回该手 17 felt 公开段
/// `[16, MAGIC, hand_id, digest, n, binding, cm×9, total, action_digest]`。
fn process_hand(data: Span<felt252>, hand_idx: usize) -> (felt252, Array<felt252>) {
    let hand_id = read(data, hand_idx, 0);
    let registered_digest = read(data, hand_idx, 1);
    let n_expected = read(data, hand_idx, 2);
    let hand_binding = read(data, hand_idx, 3);
    // players 4..13, signs 13..22, mags 22..31, commitments 31..40,
    // action_log_digest 40, action_count 41, words 42..102。
    let words_base = 42;

    // --- 约束 1：digest 匹配（Starknet Poseidon sponge，与链上同式） ---
    let mut h = PoseidonTrait::new();
    h = h.update(hand_id);
    let mut i: usize = 0;
    while i < N_PLAYERS {
        h = h.update(read(data, hand_idx, 4 + i));
        h = h.update(read(data, hand_idx, 13 + i));
        h = h.update(read(data, hand_idx, 22 + i));
        i += 1;
    }
    h = h.update(read(data, hand_idx, 40));
    let digest = h.finalize();
    assert!(digest == registered_digest, "DIGEST_MISMATCH");

    // --- 动作日志整链重放（与单手同式；30 槽上限钉死） ---
    let count_f = read(data, hand_idx, 41);
    let count_us: usize = count_f.try_into().expect('COUNT_NOT_USIZE');
    assert!(count_us <= N_WORDS, "COUNT_OVER_30");

    let mut ah = PoseidonTrait::new();
    ah = ah.update(DOMAIN);
    let mut i: usize = 0;
    while i < N_WORDS {
        let log_w = read(data, hand_idx, words_base + i * 2);
        let leg_w = read(data, hand_idx, words_base + i * 2 + 1);
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
    assert!(chain_root == read(data, hand_idx, 40), "ACTION_CHAIN_MISMATCH");

    // --- 见证良构：sign∈{0,1}，|delta|≤u64 ---
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = read(data, hand_idx, 13 + i);
        let m = read(data, hand_idx, 22 + i);
        assert!(s * (s - 1) == 0, "SIGN_NOT_BOOL");
        let _m_u64: u64 = m.try_into().expect('MAGNITUDE_OVER_U64');
        i += 1;
    }

    // --- 约束 2/3：零和 + 人数 ---
    let mut sum: felt252 = 0;
    let mut count: felt252 = 0;
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = read(data, hand_idx, 13 + i);
        let m = read(data, hand_idx, 22 + i);
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

    // --- 约束 4：赢家 cm + 该手 17 felt 公开段 ---
    let mut seg = ArrayTrait::new();
    seg.append(16); // 单手 Serde 前缀的字面复刻（9 人桌段长 16）
    seg.append(MAGIC);
    seg.append(hand_id);
    seg.append(registered_digest);
    seg.append(n_expected);
    seg.append(hand_binding);
    let mut total_winnings: felt252 = 0;
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = read(data, hand_idx, 13 + i);
        let m = read(data, hand_idx, 22 + i);
        if s == 1 {
            if m != 0 {
                total_winnings += m;
                let mut ch = PoseidonTrait::new();
                ch = ch.update(read(data, hand_idx, 31 + i));
                ch = ch.update(hand_binding);
                ch = ch.update(m);
                ch = ch.update(0);
                seg.append(ch.finalize());
            } else {
                seg.append(0);
            };
        } else {
            seg.append(0);
        };
        i += 1;
    }
    seg.append(total_winnings);
    seg.append(read(data, hand_idx, 40));
    (hand_id, seg)
}

#[executable]
fn main(
    k: felt252,
    acc_prev: felt252,
    root_hi: felt252,
    root_lo: felt252,
    data: Array<felt252>,
) -> Array<felt252> {
    let k_us: usize = k.try_into().expect('K_NOT_USIZE');
    assert!(k_us >= 1, "K_EMPTY");
    assert!(k_us <= MAX_HANDS, "K_OVER_64");
    assert!(data.len() == k_us * HAND_INPUT_LEN, "DATA_LEN_MISMATCH");

    let mut out = ArrayTrait::new();
    let mut i: usize = 0;
    while i < k_us {
        let (_hand_id, seg) = process_hand(data.span(), i);
        let mut j: usize = 0;
        while j < 17 {
            out.append(*seg.at(j));
            j += 1;
        }
        i += 1;
    }

    // --- 累加链尾（电路内 poseidon 链接）：batch_fact =
    //     poseidon([acc_prev, root_hi, root_lo, k] ++ 全部 17·k 手段)。
    //     sponge = corelib HashState（rate-2、耗尽补 1、末置换取 s0）——与
    //     groth16-wrap poseidon_hash_many 同一构造（stark-recursion 镜像 +
    //     E2E 对拍钉死）。批根 hi/lo 与 acc_prev 先复制进公开段再参与哈希，
    //     运算符无法提交「证明与语句/链锚脱钩」的终证。
    let seg_span = out.span();
    let mut h = PoseidonTrait::new();
    h = h.update(acc_prev);
    h = h.update(root_hi);
    h = h.update(root_lo);
    h = h.update(k);
    let mut i: usize = 0;
    while i < seg_span.len() {
        h = h.update(*seg_span.at(i));
        i += 1;
    }
    let batch_fact = h.finalize();

    out.append(acc_prev);
    out.append(root_hi);
    out.append(root_lo);
    out.append(batch_fact);
    out
}
