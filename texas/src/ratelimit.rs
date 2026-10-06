//! G17：/api 固定窗口限流（per-IP）。
//!
//! - 键：对端 IP（`ConnectInfo<SocketAddr>`，需 serve 侧
//!   `into_make_service_with_connect_info` 配合）；扩展不可得时退化为全局桶
//!   （保守：比不限流安全）。
//! - 固定窗口：默认 10 秒 200 次，超限返回 429。
//! - 桶数量超阈值时清理陈旧窗口，防长期运行内存无界增长。
//! - 直连部署不信任 `X-Forwarded-For`（可伪造）；上反向代理时应在代理层
//!   覆写为可信值并把键来源切到该头。
//!
//! 仅应用于 `/api` REST 路由；socket.io 通道不在本层保护范围
//! （握手/长轮询走 socket.io 自身路径，游戏动作已有会话与业务校验）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use crate::relayer::util::now_ms;

use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// 窗口长度（毫秒）。
pub const WINDOW_MS: u64 = 10_000;
/// 每 IP 每窗口最大请求数。
pub const MAX_REQUESTS: u32 = 200;
/// 触发 GC 的桶数量阈值。
const GC_THRESHOLD: usize = 10_000;

/// 键不可得时使用的全局桶名。
const GLOBAL_KEY: &str = "__global__";

struct Buckets(HashMap<String, (u64, u32)>);

static BUCKETS: OnceLock<Mutex<Buckets>> = OnceLock::new();

fn buckets() -> &'static Mutex<Buckets> {
    BUCKETS.get_or_init(|| Mutex::new(Buckets(HashMap::new())))
}

/// 固定窗口取令牌。返回 false 表示超限。
fn allow_request(key: &str, now: u64) -> bool {
    let mut guard = match buckets().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.0.len() > GC_THRESHOLD {
        guard
            .0
            .retain(|_, (start, _)| now.saturating_sub(*start) < WINDOW_MS * 2);
    }
    let (start, count) = guard.0.entry(key.to_string()).or_insert((now, 0));
    if now.saturating_sub(*start) >= WINDOW_MS {
        *start = now;
        *count = 0;
    }
    *count = count.saturating_add(1);
    *count <= MAX_REQUESTS
}

/// axum 中间件：挂在 `/api` 路由上（`axum::middleware::from_fn`）。
pub async fn limit(req: Request, next: Next) -> Response {
    let key = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| GLOBAL_KEY.to_string());
    if !allow_request(&key, now_ms()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({"error": "rate limit exceeded, retry later"})),
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_window_and_blocks_over_limit() {
        let key = "test-allow";
        let now = now_ms();
        for _ in 0..MAX_REQUESTS {
            assert!(allow_request(key, now));
        }
        assert!(!allow_request(key, now), "超过窗口上限应拒绝");
    }

    #[test]
    fn window_reset_restores_allowance() {
        let key = "test-reset";
        let now = now_ms();
        for _ in 0..MAX_REQUESTS {
            allow_request(key, now);
        }
        assert!(!allow_request(key, now));
        // 窗口滑走后重新计数
        assert!(allow_request(key, now + WINDOW_MS + 1));
    }

    #[test]
    fn keys_are_isolated() {
        let now = now_ms();
        for _ in 0..MAX_REQUESTS {
            allow_request("iso-a", now);
        }
        assert!(!allow_request("iso-a", now));
        assert!(allow_request("iso-b", now), "不同 IP 互不影响");
    }
}
