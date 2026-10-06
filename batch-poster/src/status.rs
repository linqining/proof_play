//! status JSON 端点（survey §9.7 监控最小集）+ 手动 drain 逃生口。
//!
//! 监控最小集：pending 批数 / 最老批年龄 / in-flight / 余额（余额观测由
//! 调用方注入——StarknetSend 接缝不含余额读取，避免 poster 自行扩展
//! 链上触点）。drain = 停止拾取新任务、完成在途后退出（运营逃生）。

use serde::{Deserialize, Serialize};

/// poster 运行状态快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PosterStatus {
    /// 队列中未终态任务数（poster 已拾取未回执）。
    pub pending_tasks: usize,
    /// fold 攒批中（未回执）批数。
    pub pending_batches: usize,
    /// 最老未决批年龄（秒；None = 无在途批）。
    pub oldest_batch_age_secs: Option<u64>,
    /// txmgr 在途交易数。
    pub in_flight_txs: usize,
    /// txmgr 熔断位（true = fail-closed 停发，需人工 resume）。
    pub txmgr_halted: bool,
    /// drain 已触发。
    pub draining: bool,
    /// 操作员余额（观测值；None = 未接入）。
    pub operator_balance: Option<String>,
    /// 余额树当前根（escape 地基；None = rollup 未启用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance_root_head: Option<String>,
    /// 余额树累计已应用手数（与 pending_tasks 对照可发现漏入树面）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance_applied_hands: Option<u64>,
}

impl PosterStatus {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// 阈值评估（survey §9.7 监控最小集 → alerts）。纯函数：不触网、
    /// 不改态；`alerts` 为空 = 全部健康。阈值未配置的项不告警（缺省
    /// 静默，避免误报风暴）；`txmgr_halted` 是硬告警，无需阈值。
    pub fn evaluate_alerts(&self, th: &AlertThresholds) -> Vec<StatusAlert> {
        let mut out = Vec::new();
        let mut push = |code: &str, detail: String| {
            out.push(StatusAlert {
                code: code.into(),
                detail,
            });
        };
        if self.txmgr_halted {
            push(
                "txmgr_halted",
                "txmgr 熔断停发（fail-closed），需人工 resume_after_halt".into(),
            );
        }
        if let Some(max) = th.max_pending_tasks {
            if self.pending_tasks > max {
                push(
                    "pending_tasks_high",
                    format!("pending_tasks={} > 阈值 {max}", self.pending_tasks),
                );
            }
        }
        if let Some(max) = th.max_pending_batches {
            if self.pending_batches > max {
                push(
                    "pending_batches_high",
                    format!("pending_batches={} > 阈值 {max}", self.pending_batches),
                );
            }
        }
        if let (Some(max), Some(age)) = (th.max_batch_age_secs, self.oldest_batch_age_secs) {
            if age > max {
                push(
                    "oldest_batch_age_high",
                    format!("最老未决批年龄 {age}s > 阈值 {max}s"),
                );
            }
        }
        if let Some(max) = th.max_in_flight_txs {
            if self.in_flight_txs > max {
                push(
                    "in_flight_txs_high",
                    format!("in_flight_txs={} > 阈值 {max}", self.in_flight_txs),
                );
            }
        }
        if let Some(min) = th.min_operator_balance_wei {
            // survey §9.7：operator 账户余额按 Arbitrum ~3 天发帖成本口径
            // 告警。余额未接入观测/不可解析而阈值已配置 = 监控缺口本身
            // 要可见（fail-closed 告警，不放空）。
            match self.operator_balance.as_deref().map(parse_balance_wei) {
                Some(Some(v)) if v < min => push(
                    "operator_balance_low",
                    format!("operator 余额 {v} wei < 阈值 {min} wei"),
                ),
                Some(Some(_)) => {}
                _ => push(
                    "operator_balance_unobserved",
                    "已配置余额告警阈值但 operator_balance 未接入/不可解析（hex/十进制 \
                     STRK wei 字符串）"
                        .into(),
                ),
            }
        }
        out
    }

    /// status JSON + `alerts` 字段（HTTP 端点口径）。`PosterStatus` 本体
    /// 不加字段（构造点在 lib.rs / bin 的结构体字面量），alerts 在序列化
    /// 时以扁平信封并入。
    pub fn to_alerted_json(&self, th: &AlertThresholds) -> String {
        #[derive(Serialize)]
        struct Envelope<'a> {
            #[serde(flatten)]
            status: &'a PosterStatus,
            alerts: Vec<StatusAlert>,
        }
        serde_json::to_string_pretty(&Envelope {
            status: self,
            alerts: self.evaluate_alerts(th),
        })
        .unwrap_or_default()
    }
}

/// 单条告警（status JSON `alerts` 数组元素）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusAlert {
    /// 机器可读告警码（稳定词汇：txmgr_halted / pending_tasks_high /
    /// pending_batches_high / oldest_batch_age_high / in_flight_txs_high /
    /// operator_balance_low / operator_balance_unobserved）。
    pub code: String,
    /// 人读详情（含当前值与阈值）。
    pub detail: String,
}

/// 告警阈值——**env 直读进本模块**（不走 config.rs 运营配置：阈值属监控
/// 面，部署单元 env 文件即可调，见 deploy/batch-poster.env）。未设置的项
/// 不告警。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlertThresholds {
    /// 待驱动任务数上限（超过告警）。
    pub max_pending_tasks: Option<usize>,
    /// 在途批数上限。
    pub max_pending_batches: Option<usize>,
    /// 最老未决批年龄上限（秒；min 语义见 lib.rs `status`——对 created_at
    /// 取 min 再算龄，接告警前已复核）。
    pub max_batch_age_secs: Option<u64>,
    /// txmgr 在途交易数上限。
    pub max_in_flight_txs: Option<usize>,
    /// operator 余额下限（STRK wei）——survey §9.7 原文「operator 账户
    /// 余额（Arbitrum 按 ~3 天成本告警）」：余额低于约 3 天发帖开销即告
    /// 警；具体数值由部署方按实测日均 gas 消耗校准（无仓内实测锚，不设
    /// 数值缺省）。
    pub min_operator_balance_wei: Option<u128>,
}

impl AlertThresholds {
    pub fn from_env() -> Self {
        fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
            std::env::var(name).ok().and_then(|s| s.trim().parse().ok())
        }
        Self {
            max_pending_tasks: env_parse("TEXAS_POSTER_ALERT_MAX_PENDING_TASKS"),
            max_pending_batches: env_parse("TEXAS_POSTER_ALERT_MAX_PENDING_BATCHES"),
            max_batch_age_secs: env_parse("TEXAS_POSTER_ALERT_MAX_BATCH_AGE_SECS"),
            max_in_flight_txs: env_parse("TEXAS_POSTER_ALERT_MAX_IN_FLIGHT_TXS"),
            min_operator_balance_wei: env_parse::<String>("TEXAS_POSTER_ALERT_MIN_BALANCE_WEI")
                .and_then(|s| parse_balance_wei(&s)),
        }
    }
}

/// 余额字面量（十进制或 0x hex）→ STRK wei（`operator_balance` 字符串
/// 同口径；观测值未接线前恒 None → 阈值已配即告警 unobserved）。
pub fn parse_balance_wei(s: &str) -> Option<u128> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u128::from_str_radix(h, 16).ok()
    } else {
        t.parse().ok()
    }
}

/// 最小 HTTP 端点（单次连接、GET → status JSON）。骨架实现：daemon 内
/// 循环 accept；生产可换 axum。响应体 = [`PosterStatus`] 扁平字段 +
/// `alerts` 数组（阈值 env 每连接读入——运维改 env 需重启，语义同
/// systemd EnvironmentFile）。
pub async fn serve_status_once(
    listener: &tokio::net::TcpListener,
    status: &PosterStatus,
) -> std::io::Result<()> {
    let (mut socket, _) = listener.accept().await?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 1024];
    let _ = socket.read(&mut buf).await;
    let body = status.to_alerted_json(&AlertThresholds::from_env());
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    socket.write_all(resp.as_bytes()).await?;
    socket.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// status JSON 字段（监控最小集口径）。
    #[test]
    fn status_json_fields() {
        let st = PosterStatus {
            pending_tasks: 3,
            pending_batches: 1,
            oldest_batch_age_secs: Some(120),
            in_flight_txs: 2,
            txmgr_halted: false,
            draining: false,
            operator_balance: None,
            balance_root_head: None,
            balance_applied_hands: None,
        };
        let json = st.to_json();
        for field in [
            "pending_tasks",
            "pending_batches",
            "oldest_batch_age_secs",
            "in_flight_txs",
            "txmgr_halted",
            "draining",
        ] {
            assert!(json.contains(field), "缺字段 {field}");
        }
        let back: PosterStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, st);
    }

    /// 健康快照 + 无阈值 → 零告警（缺省静默）。
    #[test]
    fn no_thresholds_no_alerts() {
        let st = PosterStatus {
            pending_tasks: 999,
            pending_batches: 0,
            oldest_batch_age_secs: None,
            in_flight_txs: 0,
            txmgr_halted: false,
            draining: false,
            operator_balance: None,
            balance_root_head: None,
            balance_applied_hands: None,
        };
        assert!(st.evaluate_alerts(&AlertThresholds::default()).is_empty());
    }

    /// 阈值矩阵：各项超限 + 熔断硬告警 + 余额下限（含 unobserved 缺口）。
    #[test]
    fn threshold_matrix_and_alert_codes() {
        let th = AlertThresholds {
            max_pending_tasks: Some(10),
            max_pending_batches: Some(2),
            max_batch_age_secs: Some(600),
            max_in_flight_txs: Some(4),
            min_operator_balance_wei: Some(150),
        };
        // 全绿。
        let ok = PosterStatus {
            pending_tasks: 10,
            pending_batches: 2,
            oldest_batch_age_secs: Some(600),
            in_flight_txs: 4,
            txmgr_halted: false,
            draining: false,
            operator_balance: Some("0x96".into()), // 150
            balance_root_head: None,
            balance_applied_hands: None,
        };
        assert_eq!(ok.evaluate_alerts(&th), Vec::<StatusAlert>::new());
        // 全红（阈值判 >，边界值不告警）。
        let bad = PosterStatus {
            pending_tasks: 11,
            pending_batches: 3,
            oldest_batch_age_secs: Some(601),
            in_flight_txs: 5,
            txmgr_halted: true,
            draining: false,
            operator_balance: Some("149".into()),
            balance_root_head: None,
            balance_applied_hands: None,
        };
        let bad_alerts = bad.evaluate_alerts(&th);
        let codes: Vec<&str> = bad_alerts.iter().map(|a| a.code.as_str()).collect();
        for expected in [
            "txmgr_halted",
            "pending_tasks_high",
            "pending_batches_high",
            "oldest_batch_age_high",
            "in_flight_txs_high",
            "operator_balance_low",
        ] {
            assert!(codes.contains(&expected), "缺告警 {expected}（实际 {codes:?}）");
        }
        // 阈值已配但余额未接入 → 监控缺口本身告警。
        let mut unobserved = ok.clone();
        unobserved.operator_balance = None;
        let unobserved_alerts = unobserved.evaluate_alerts(&th);
        let codes: Vec<&str> = unobserved_alerts.iter().map(|a| a.code.as_str()).collect();
        assert!(codes.contains(&"operator_balance_unobserved"));
        // 余额不可解析同样告警缺口（不放空）。
        let mut junk = ok;
        junk.operator_balance = Some("not-a-number".into());
        assert!(junk
            .evaluate_alerts(&th)
            .iter()
            .any(|a| a.code == "operator_balance_unobserved"));
    }

    /// 端点口径 JSON：PosterStatus 字段扁平 + alerts 并入（serde flatten）。
    #[test]
    fn alerted_json_envelope() {
        let st = PosterStatus {
            pending_tasks: 3,
            pending_batches: 1,
            oldest_batch_age_secs: Some(120),
            in_flight_txs: 2,
            txmgr_halted: true,
            draining: false,
            operator_balance: None,
            balance_root_head: None,
            balance_applied_hands: None,
        };
        let json = st.to_alerted_json(&AlertThresholds::default());
        for field in [
            "pending_tasks",
            "oldest_batch_age_secs",
            "txmgr_halted",
            "alerts",
            "txmgr_halted\"",
        ] {
            assert!(json.contains(field), "缺字段 {field}");
        }
        assert!(json.contains("txmgr_halted\\n") || json.contains("txmgr_halted"));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // 扁平化成立：顶层就是 status 字段（不是嵌套 status 对象）。
        assert!(v.get("pending_tasks").is_some());
        assert!(v.get("status").is_none(), "status 不得成为嵌套键");
        let alerts = v.get("alerts").and_then(|a| a.as_array()).unwrap();
        assert_eq!(alerts.len(), 1, "halted 应产生 1 条硬告警");
        assert_eq!(alerts[0]["code"], "txmgr_halted");
    }

    /// 余额字面量解析：十进制 / 0x hex / 非法。
    #[test]
    fn balance_wei_parsing() {
        assert_eq!(parse_balance_wei("150"), Some(150));
        assert_eq!(parse_balance_wei(" 0x96 "), Some(150));
        assert_eq!(parse_balance_wei("0X96"), Some(150));
        assert_eq!(parse_balance_wei("junk"), None);
    }
}
