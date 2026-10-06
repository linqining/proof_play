//! Socket 错误标准（全站复用）。
//!
//! 结构化错误 payload（`error` 事件）：
//! ```json
//! { "code": "INSUFFICIENT_CHIPS", "msg": "筹码不足…", "detail": "<技术细节>", "action"?: "...", "table_id"?: ... }
//! ```
//! - `code`：稳定机器标识（客户端据此做分支/映射，不随文案变化）；
//! - `msg`：**用户可读**的中文提示（直接可展示；新增码必须在此登记文案）；
//! - `detail`：原始技术细节（排障用，客户端只进 console）。
//!
//! 客户端约定（useGameSocket 的 error 处理器）：展示 `msg`；`code` 用于
//! 特殊分支（如静默的良性重复提交）；`detail` 只打 console。


/// 错误码 + 用户文案登记表。新增错误必须在此登记文案，禁止裸字符串。
pub fn user_message(code: &str) -> &'static str {
    match code {
        // 买入 / 下坐
        "INSUFFICIENT_CHIPS" => "筹码不足：请确认买入已上链，或降低买入额度",
        "BUYIN_TX_PENDING" => "买入交易确认中，请稍候几秒后重试",
        "BUYIN_TX_REVERTED" => "买入交易失败：请检查钱包交易记录",
        "BUYIN_VERIFY_FAILED" => "买入校验未通过：请稍后重试，或联系支持",
        "AMOUNT_POSITIVE" => "买入额度必须大于 0",
        "AMOUNT_TOO_LARGE" => "买入额度超出上限",
        // 通用
        "AUTH_FAILED" => "登录已失效，请重新连接钱包",
        "NOT_TURN_OR_PHASE" => "还没轮到你，或牌局不在下注阶段",
        "SIG_INVALID" => "动作签名校验失败，请刷新页面重试",
        "SEQ_NON_MONOTONIC" => "动作序列异常，请刷新页面重试",
        "RATE_LIMITED" => "请求过于频繁，请稍候再试",
        _ => "操作失败，请稍候重试",
    }
}

/// 构造结构化错误 payload。`code` 必须是本模块登记过的错误码；
/// `detail` 是给开发者看的技术细节（不会展示给用户）。
/// 与 `error_payload` 相同，但额外携带 action / table_id 上下文
///（客户端据此关闭下注 loading 遮罩等）。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_code_has_user_message() {
        for code in [
            "INSUFFICIENT_CHIPS",
            "BUYIN_TX_PENDING",
            "BUYIN_TX_REVERTED",
            "BUYIN_VERIFY_FAILED",
            "AMOUNT_POSITIVE",
            "AMOUNT_TOO_LARGE",
            "AUTH_FAILED",
            "NOT_TURN_OR_PHASE",
            "SIG_INVALID",
            "SEQ_NON_MONOTONIC",
            "RATE_LIMITED",
        ] {
            let msg = user_message(code);
            assert!(!msg.is_empty(), "{code} 必须登记用户文案");
            assert_ne!(msg, code, "{code} 文案不应是裸码");
        }
        // 未知码回退到通用文案
        assert_eq!(user_message("UNKNOWN_X"), "操作失败，请稍候重试");
    }

    #[test]
    fn payload_carries_code_msg_detail() {
        let v = error_payload("INSUFFICIENT_CHIPS", "available=0 required=1000");
        assert_eq!(v["code"], "INSUFFICIENT_CHIPS");
        assert_eq!(v["key"], "socket_error_INSUFFICIENT_CHIPS");
        assert!(v["msg"].as_str().unwrap().contains("筹码不足"));
        assert_eq!(v["detail"], "available=0 required=1000");
    }

    #[test]
    fn ctx_payload_includes_action_and_table() {
        let v = error_payload_with_ctx("AMOUNT_POSITIVE", "bad", "raise", 7);
        assert_eq!(v["action"], "raise");
        assert_eq!(v["table_id"], 7);
    }
}

/// 构造结构化错误 payload（测试断言用）。
#[cfg(test)]
pub fn error_payload(code: &'static str, detail: impl std::fmt::Display) -> serde_json::Value {
    serde_json::json!({
        "code": code,
        // 稳定 i18n key：前端 locale 文件按此 key 查本地化文案（缺失时回退 msg）
        "key": format!("socket_error_{code}"),
        "msg": user_message(code),
        "detail": detail.to_string(),
    })
}

/// 与 `error_payload` 相同，但额外携带 action / table_id 上下文。
#[cfg(test)]
pub fn error_payload_with_ctx(
    code: &'static str,
    detail: impl std::fmt::Display,
    action: &str,
    table_id: u32,
) -> serde_json::Value {
    let mut v = error_payload(code, detail);
    if let Some(obj) = v.as_object_mut() {
        obj.insert("action".into(), serde_json::Value::String(action.to_string()));
        obj.insert("table_id".into(), serde_json::Value::from(table_id));
    }
    v
}
