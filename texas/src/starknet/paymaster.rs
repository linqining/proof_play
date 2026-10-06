//! Plan C 执行层加固 —— paymaster 中继（API key 只留服务端）。
//!
//! 客户端用 starknet.js 的 `PaymasterRpc` 把本端点当作 paymaster JSON-RPC
//! 服务：`paymaster_*` 请求被原样透传给上游 paymaster（如 AVNU），转发时
//! 由服务端注入 `x-api-key`。上游以自己的账户合约提交交易（OutsideExecution），
//! 链上交易的发送者不是用户地址 —— 链下执行方无法按用户身份定向审查。
//!
//! 隐私边界：签名与证明全部留在客户端，本模块只见 calls 与 typed data；
//! API key 永不出现在前端。
//!
//! 未配置（STARKNET_PAYMASTER_URL 为空）时 status 返回 configured=false、
//! 中继返回 503 JSON-RPC 错误，客户端自动回退 session key 直签路径。

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::time::Duration;

/// 上游请求超时。paymaster_buildTransaction 含费用估算，给足余量。
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

pub struct PaymasterConfig {
    /// 上游 paymaster JSON-RPC 端点（如 https://api.avnu.fi/paymaster）。
    pub url: String,
    /// 上游 API key，经 x-api-key 头注入。可留空（上游免鉴权时）。
    pub api_key: String,
}

static PAYMASTER: OnceLock<Option<PaymasterConfig>> = OnceLock::new();

/// main.rs 启动时调用一次；未配置则进入"未启用"态（中继 503 + status=false）。
pub fn init_from_env() {
    let cfg = match std::env::var("STARKNET_PAYMASTER_URL") {
        Ok(url) if !url.trim().is_empty() => Some(PaymasterConfig {
            url: url.trim().to_string(),
            api_key: std::env::var("STARKNET_PAYMASTER_API_KEY").unwrap_or_default(),
        }),
        _ => None,
    };
    match &cfg {
        Some(c) => tracing::info!("[starknet-paymaster] relay enabled → {}", c.url),
        None => tracing::info!(
            "[starknet-paymaster] not configured (STARKNET_PAYMASTER_URL empty); \
             clients fall back to session-key direct submission"
        ),
    }
    let _ = PAYMASTER.set(cfg);
}

fn config() -> Option<&'static PaymasterConfig> {
    PAYMASTER.get().and_then(|c| c.as_ref())
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub configured: bool,
}

/// GET /api/starknet/paymaster/status —— 客户端能力探测（不回显 url/key）。
pub async fn status() -> Json<StatusResponse> {
    Json(StatusResponse {
        configured: config().is_some(),
    })
}

/// JSON-RPC 错误信封，与 starknet.js PaymasterRpc 的错误解析预期一致。
fn rpc_error(id: Value, code: i64, message: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": code, "message": message }
        })),
    )
        .into_response()
}

/// POST /api/starknet/paymaster —— `paymaster_*` JSON-RPC 透明中继。
///
/// 只透传 `paymaster_` 前缀方法（isAvailable / buildTransaction /
/// executeTransaction / getSupportedTokens），避免成为任意 RPC 代理。
pub async fn relay(Json(body): Json<Value>) -> Response {
    let id = body.get("id").cloned().unwrap_or(Value::Null);

    let Some(cfg) = config() else {
        return rpc_error(id, -32601, "paymaster relay not configured");
    };
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if !method.starts_with("paymaster_") {
        return rpc_error(id, -32601, &format!("method {method:?} not allowed"));
    }

    // ===== #30 签名加固 =====
    // executeTransaction 携带用户对 OutsideExecution typed data 的签名——
    // 服务端本地验证（SNIP-12 hash + 链上 get_public_key + starknet_crypto）。
    // STARKNET_PAYMASTER_SIG_REQUIRED=1 时无效/缺失 → 拒绝（401）；
    // 默认 off：验证结果仅记日志（迁移期兼容）。
    if method == "paymaster_executeTransaction" {
        match verify_execute_signature(&body).await {
            Ok(user) => {
                tracing::info!("[paymaster] executeTransaction signature OK (user {user})");
            }
            Err(e) => {
                tracing::warn!("[paymaster] executeTransaction signature check failed: {e}");
                if sig_required() {
                    return rpc_error(id, -32001, &format!("signature check failed: {e}"));
                }
            }
        }
    }

    let client = match reqwest::Client::builder().timeout(UPSTREAM_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => return rpc_error(id, -32603, &format!("http client: {e}")),
    };
    let mut req = client
        .post(&cfg.url)
        .header("Content-Type", "application/json");
    if !cfg.api_key.is_empty() {
        req = req.header("x-api-key", &cfg.api_key);
    }

    let resp = match req.json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("[starknet-paymaster] upstream {} error: {e}", cfg.url);
            return rpc_error(id, -32603, "paymaster upstream unreachable");
        }
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = resp.bytes().await.unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|e| rpc_error(id, -32603, &format!("response build: {e}")))
}

// ============================================================
// Plan D P2.1：客户端 Hand-batch 认可注册端点（挂在 paymaster 模块的邻近路由）
// ============================================================

/// 客户端认可注册请求体（P2.1）。
// ============================================================
// #30 签名加固：executeTransaction 的用户签名本地验证
// ============================================================

/// enforcement 开关：`STARKNET_PAYMASTER_SIG_REQUIRED=1` 时
/// executeTransaction 必须携带可验证的用户签名（缺失/无效 → 401）。
fn sig_required() -> bool {
    std::env::var("STARKNET_PAYMASTER_SIG_REQUIRED").as_deref() == Ok("1")
}

/// 递归查找同时携带 userAddress / typedData / signature 的对象
///（兼容 params 数组或对象包裹两种 wire 形态）。
fn find_execute_fields(value: &Value) -> Option<(&Value, &Value, &Value)> {
    match value {
        Value::Object(map) => {
            let user = map.get("userAddress");
            let td = map.get("typedData");
            let sig = map.get("signature");
            if let (Some(u), Some(t), Some(s)) = (user, td, sig) {
                return Some((u, t, s));
            }
            for v in map.values() {
                if let Some(found) = find_execute_fields(v) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(find_execute_fields),
        _ => None,
    }
}

/// 验证 executeTransaction 的用户签名：
/// 1. 从 body 提取 (userAddress, typedData, signature)；
/// 2. TypedData::message_hash(user) 计算 SNIP-12 哈希；
/// 3. 链上 `get_public_key()`（带 TTL 缓存）+ starknet_crypto::verify。
/// 返回 Ok(user_address_hex) 表示签名有效。
async fn verify_execute_signature(body: &Value) -> Result<String, String> {
    let (user_value, typed_data_value, signature) = find_execute_fields(body)
        .ok_or_else(|| "execute fields not found in body".to_string())?;

    let user_str = user_value
        .as_str()
        .ok_or_else(|| "userAddress not a string".to_string())?;
    let user_felt = crate::starknet::chain::parse_felt(user_str)
        .ok_or_else(|| "userAddress not a felt".to_string())?;

    // 签名数组：标准账户为 [r, s]（十进制字符串）；其他形状直接判无效
    let sig_items = signature
        .as_array()
        .ok_or_else(|| "signature not an array".to_string())?;
    if sig_items.len() != 2 {
        return Err(format!(
            "unsupported signature shape (len={})",
            sig_items.len()
        ));
    }
    let r = starknet::core::types::Felt::from_dec_str(
        sig_items[0].as_str().unwrap_or_default(),
    )
    .map_err(|e| format!("sig r: {e}"))?;
    let s = starknet::core::types::Felt::from_dec_str(
        sig_items[1].as_str().unwrap_or_default(),
    )
    .map_err(|e| format!("sig s: {e}"))?;

    // SNIP-12 哈希（typed data 三段拆解后交给 TypedData）
    let td_obj = typed_data_value
        .as_object()
        .ok_or_else(|| "typedData not an object".to_string())?;
    let types = td_obj
        .get("types")
        .cloned()
        .ok_or_else(|| "typedData.types missing".to_string())?;
    let domain = td_obj
        .get("domain")
        .cloned()
        .ok_or_else(|| "typedData.domain missing".to_string())?;
    let primary = td_obj
        .get("primaryType")
        .cloned()
        .ok_or_else(|| "typedData.primaryType missing".to_string())?;
    let message = td_obj
        .get("message")
        .cloned()
        .ok_or_else(|| "typedData.message missing".to_string())?;

    let types_typed: starknet::core::types::typed_data::Types =
        serde_json::from_value(types).map_err(|e| format!("types: {e}"))?;
    let domain_typed: starknet::core::types::typed_data::Domain =
        serde_json::from_value(domain).map_err(|e| format!("domain: {e}"))?;
    let primary_ref: starknet::core::types::typed_data::InlineTypeReference =
        serde_json::from_value(primary).map_err(|e| format!("primaryType: {e}"))?;
    let message_val: starknet::core::types::typed_data::Value =
        serde_json::from_value(message).map_err(|e| format!("message: {e}"))?;

    let typed_data = starknet::core::types::TypedData::new(
        types_typed,
        domain_typed,
        primary_ref,
        message_val,
    )
    .map_err(|e| format!("typed data invalid: {e}"))?;
    let hash = typed_data
        .message_hash(user_felt)
        .map_err(|e| format!("message hash: {e}"))?;

    // signer pk：链上 account.get_public_key()（TTL 缓存）
    let pk = get_public_key_cached(user_felt).await?;

    // starknet-crypto 0.8 的 verify 直接吃 types-core Felt（链上 Felt 同型）。
    let ok = starknet_crypto::verify(&pk, &hash, &r, &s)
        .map_err(|e| format!("verify: {e}"))?;
    if !ok {
        return Err("signature does not match user public key".into());
    }
    Ok(user_str.to_string())
}

static PK_CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, starknet::core::types::Felt)>>> =
    std::sync::OnceLock::new();
const PK_TTL: std::time::Duration = std::time::Duration::from_secs(600);

async fn get_public_key_cached(
    user: starknet::core::types::Felt,
) -> Result<starknet::core::types::Felt, String> {
    let cache = PK_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    {
        let map = match cache.lock() {
            Ok(m) => m,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some((ts, pk)) = map.get(&user.to_hex_string()) {
            if ts.elapsed() < PK_TTL {
                return Ok(*pk);
            }
        }
    }
    let selector = starknet::core::utils::starknet_keccak(b"get_public_key");
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let felts = chain
        .call_contract(user, selector, vec![])
        .await
        .map_err(|e| format!("get_public_key call failed: {e}"))?;
    let pk_felt = felts
        .first()
        .copied()
        .ok_or_else(|| "empty get_public_key result".to_string())?;
    {
        let mut map = match cache.lock() {
            Ok(m) => m,
            Err(poisoned) => poisoned.into_inner(),
        };
        if map.len() > 1000 {
            map.clear();
        }
        map.insert(user.to_hex_string(), (std::time::Instant::now(), pk_felt));
    }
    Ok(pk_felt)
}

#[cfg(test)]
mod sig_tests {
    use super::*;

    #[test]
    fn find_execute_fields_walks_nested_params() {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "paymaster_executeTransaction",
            "params": [{
                "type": "invoke",
                "invoke": {
                    "userAddress": "0x1234",
                    "typedData": { "types": {}, "primaryType": "OutsideExecution", "domain": {}, "message": {} },
                    "signature": ["123", "456"]
                }
            }, { "version": "0x1" }]
        });
        let (user, typed_data, sig) =
            find_execute_fields(&body).expect("fields must be found");
        assert_eq!(user.as_str(), Some("0x1234"));
        assert!(typed_data.get("types").is_some());
        assert_eq!(sig.as_array().map(|a| a.len()), Some(2));
    }

    #[test]
    fn find_execute_fields_returns_none_when_absent() {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "paymaster_isAvailable", "params": []
        });
        assert!(find_execute_fields(&body).is_none());
    }

    #[test]
    fn enforcement_flag_defaults_off() {
        // 未设 env 时迁移期默认放行（signature check 仅记日志）
        assert!(!sig_required());
    }
}
