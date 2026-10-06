//! 合并信封（combined envelope）——P 层递归 + 结算隐私语句，一份 Stwo 证明。
//!
//! 动机：此前每手牌出两份证明（递归信封 ~2.2s + settlement_private ~2s），
//! 各付一次 Stwo 固定开销、各登记一个 fact。本程序把两类语句合进**一次**
//! Cairo VM 执行 / 一次承诺 / 一次 FRI：公开输出 = `[new_acc] ++ settlement
//! 公开段(16 词)`（共 17 词），链上单 fact 消费（combined entry）。
//!
//! ## 与 recursion.cairo 的差异
//! - 任务循环体不变（`dual::hand_verify::verify_hand` 真验证 + claim 链
//!   电路内重算），新增**绑定断言**：每个任务的 hand_binding 必须等于
//!   settle 段的 hand_binding——证明语义从「某批任务」收紧为「**这一手**
//!   的 P 语句 + 这一手 的结算」。多手批量仍走 recursion.cairo。
//! - 第二个 Span（settle，102 词）跑 `settlement_stmt::settlement_statement`
//!   （digest/零和/人数/认领承诺/动作日志整链重放，全 assert，fail-closed）。
//!
//! ## fail-closed
//! 任一语句失败（P 层验证、绑定断言、任一结算约束）→ panic → 无证明。
//!
//! inputs 布局（prove-hand `--inputs`，hex felt 数组）：
//! `[prev_acc, tasks_len, tasks…, settle_len, settle…]`
//! （Span 参数 = [len, elements…] 摊平，与 recursion.cairo 同约定）。

mod dual;
mod settlement_stmt;

use core::array::ArrayTrait;
use core::panic_with_felt252;
use core::poseidon::poseidon_hash_span;
use core::traits::TryInto;

use settlement_stmt::settlement_statement;

/// Genesis 累计承诺（与 recursion.cairo / host GENESIS_ACC 同值）。
pub const GENESIS_ACC: felt252 = 0;

#[executable]
fn main(prev_acc: felt252, tasks: Span<felt252>, settle: Span<felt252>) -> Array<felt252> {
    let n_tasks: u32 = match (*tasks.at(0)).try_into() {
        Option::Some(v) => v,
        Option::None => panic_with_felt252('BAD_TASK_COUNT'),
    };
    // 绑定锚：settle 段第 4 词 = hand_binding（settlement_stmt wire 头）。
    let settle_binding = *settle.at(3);
    assert!(settle_binding != 0, "ZERO_SETTLE_BINDING");

    let mut cursor: u32 = 1;
    let mut claims: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n_tasks {
        let hand_binding = *tasks.at(cursor);
        let payload_len: u32 = match (*tasks.at(cursor + 1)).try_into() {
            Option::Some(v) => v,
            Option::None => panic_with_felt252('BAD_PAYLOAD_LEN'),
        };
        let payload = tasks.slice(cursor + 2, payload_len);

        // 合并语义的绑定断言：P 语句必须属于 settle 段锚定的那手牌。
        assert!(hand_binding == settle_binding, "TASK_BINDING_MISMATCH");

        // 真验证（EC in trace）。失败即 panic：该批次无证明。
        if !dual::hand_verify::verify_hand(hand_binding, payload) {
            panic_with_felt252('HAND_VERIFY_FAILED');
        }

        let mut digest_preimage: Array<felt252> = array![];
        digest_preimage.append(payload_len.into());
        let mut j: u32 = 0;
        while j < payload_len {
            digest_preimage.append(*payload.at(j));
            j += 1;
        }
        let digest = poseidon_hash_span(digest_preimage.span());

        let mut claim_preimage: Array<felt252> = array![];
        claim_preimage.append(hand_binding);
        claim_preimage.append(digest);
        claim_preimage.append(*payload.at(0));
        claim_preimage.append(*payload.at(2));
        claim_preimage.append(*payload.at(3));
        claim_preimage.append(*payload.at(4));
        claim_preimage.append(*payload.at(5));
        claims.append(poseidon_hash_span(claim_preimage.span()));

        cursor += 2 + payload_len;
        i += 1;
    }

    // 结算半边：全部约束在语句函数内 assert（fail-closed）。
    let segment = settlement_statement(settle);

    let mut acc_preimage: Array<felt252> = array![];
    acc_preimage.append(prev_acc);
    let claims_span = claims.span();
    let mut k: u32 = 0;
    while k < claims_span.len() {
        acc_preimage.append(*claims_span.at(k));
        k += 1;
    }
    let new_acc = poseidon_hash_span(acc_preimage.span());

    // 公开输出（17 词）：[new_acc] ++ segment。
    let mut out = ArrayTrait::new();
    out.append(new_acc);
    let seg_span = segment.span();
    let mut w: u32 = 0;
    while w < seg_span.len() {
        out.append(*seg_span.at(w));
        w += 1;
    }
    out
}
