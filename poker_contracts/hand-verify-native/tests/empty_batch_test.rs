//! 空批次语义钉死（2026-09-07 生产复现）：
//! 全零计数的批次在 verify_hand 必然 Truncated（Horner 折叠需要至少一条
//! 方程，equations.last() 为 None 直接报 Truncated）。这不是要修的 bug——
//! 空批次没有可证语句，调用侧（texas hooks snip36 流）必须在材料为空时
//! 跳过出证，而不是把空 payload 送进来。
use hand_verify_native::handbatch::{verify_hand, VerifyError};
use hand_verify_native::recurse::build_action_batch_payload;

#[test]
fn empty_action_batch_rejected_as_truncated() {
    let hb = starknet_crypto::Felt::from_bytes_be(&[0x01; 32]);
    let payload = build_action_batch_payload(hb, 1, 42, &[]).expect("payload build");
    assert_eq!(payload.len(), 6, "empty batch = header only");
    assert_eq!(
        verify_hand(hb, &payload),
        Err(VerifyError::Truncated),
        "empty equation set must not verify — callers skip proving instead"
    );
}
