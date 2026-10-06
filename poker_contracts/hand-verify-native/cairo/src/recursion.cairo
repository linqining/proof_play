//! hand_verify 递归信封（recursion envelope）—— Cairo 路线递归证明（form-③）。
//!
//! 调研与选型：`docs/cairo-recursion-research.md`。形态与执行计划
//! `docs/plan-snip36-execution.md` P3.3（ADR-2026-09-06-1）同构：σ 校验
//! 并进电路 + 承诺链由电路内部重算。本程序是独立 crate root（与 form-②
//! 的 `lib.cairo` 并存、共享 `dual/` 验证器模块），由 prove-hand 以
//! `--program cairo/src/recursion.cairo` 出证。
//!
//! ## 程序语义
//!
//! 输入 `tasks` 的 wire 格式（与 form-② 的输入编码同风格，Span 参数 =
//! [len, elements…] 摊平）：
//!
//! ```text
//! [n_tasks, (hand_binding, payload_len, payload words)*]
//! ```
//!
//! 对每个任务调用 `dual::hand_verify::verify_hand`（真验证——EC 残差经
//! EC_OP builtin 进 trace，Poseidon 挑战经 Poseidon builtin），然后**在
//! 电路内**重算承诺链：
//!
//! ```text
//! digest_i = poseidon([payload_len] ++ payload_i)
//!            // 与 host `handbatch::payload_digest` 逐 felt 同构
//! claim_i  = poseidon([hand_binding_i, digest_i, n_own, n_reveal,
//!                      n_leave, n_recon])
//!            // P3.3 公式 poseidon(hand_binding, poseidon(p_batch words))
//!            // 的多任务推广；counts 取自 payload header（验证器本身
//!            // 消费同一 header，越界计数已在 verify_hand 内拒绝）
//! new_acc  = poseidon([prev_acc] ++ claim_1 … claim_N)
//! ```
//!
//! 返回 `new_acc`（公开输出）。下一层把上一层证明的公开输出作为本层
//! `prev_acc` 输入——proof-carrying data 链：最终一份证明锚定「全部层的
//! 全部任务都通过真验证，且累计承诺是逐层折出的」。
//!
//! ## fail-closed
//!
//! 任一任务验证失败、计数溢出、或 wire 格式不合法 → panic → Cairo 运行
//! 失败 → **该批次无证明**。不存在「跳过失败任务继续出证」的路径。

mod dual;

use core::array::ArrayTrait;
use core::panic_with_felt252;
use core::poseidon::poseidon_hash_span;
use core::traits::TryInto;

/// Genesis 累计承诺：链的第 0 层以 `prev_acc = 0` 起（host 侧同值）。
pub const GENESIS_ACC: felt252 = 0;

#[executable]
fn main(prev_acc: felt252, tasks: Span<felt252>) -> felt252 {
    let n_tasks: u32 = match (*tasks.at(0)).try_into() {
        Option::Some(v) => v,
        Option::None => panic_with_felt252('BAD_TASK_COUNT'),
    };
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

    let mut acc_preimage: Array<felt252> = array![];
    acc_preimage.append(prev_acc);
    let claims_span = claims.span();
    let mut k = 0;
    while k < claims_span.len() {
        acc_preimage.append(*claims_span.at(k));
        k += 1;
    }
    poseidon_hash_span(acc_preimage.span())
}
