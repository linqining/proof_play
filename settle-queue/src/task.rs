//! 条目与路由判别：`SettleTask` + `SettleRoute`。
//!
//! ## SettleRoute 判别绑 STARKNET_SETTLEMENT_MODE（终审修订）
//!
//! 队列判别器收敛为两态 [`SettleRoute::{Legacy, Dual}`]，判别**只**绑
//! `STARKNET_SETTLEMENT_MODE`（settlement_mode，
//! `texas/src/starknet/config.rs:136-149`：仅认 `legacy | snip36`，其余钉
//! legacy 并告警；运行时分支 = `settlement_mode_snip36()`，
//! `texas/src/starknet/config.rs:214` / hooks `settle_from_live_mirror`
//! 的 `settlement_mode_snip36()` 分支）：
//!
//! - `legacy` → [`SettleRoute::Legacy`]（register_aggregate → settle_hand
//!   两笔，`texas/src/starknet/submit.rs` 的 `submit_settlement` 形态）；
//! - `snip36` → [`SettleRoute::Dual`]（register_hand → verify_and_settle_dapv*
//!   两笔，dual_settle.rs 形态）。
//!
//! `STARKNET_DAPV_SETTLE_ENTRY`（`texas/src/starknet/config.rs:63-77`，取值
//! 域 v2/proved_private/snip36/combined）**不参与 Legacy/Dual 判别**（该 env
//! 无任何 legacy 值，绑它判别永远分不出 Legacy）——它作为 Dual 路内的合约
//! 入口参数随条目携带：[`SettleTask::dapv_entry`]。
//!
//! ## 与 SettlementExit 的映射（显式固化）
//!
//! [`route_for_exit`] 镜像 `appchain::SettlementExit`（
//! `texas/src/starknet/appchain/exit.rs:59-65`）的 parse 语义（`"starknet" |
//! "legacy"` → Starknet 变体，`exit.rs:71-74`）：
//!
//! - `SettlementExit::Starknet`（parse 自 "starknet"|"legacy"）→ 按
//!   settlement_mode 细分 SettleRoute；
//! - `SettlementExit::Appchain` → **不入队**（返回 `None`，appchain 软确认链
//!   自有持久化，不经过本投递层）。

use serde::{Deserialize, Serialize};

/// 单手键 `(table_id, hand_id)`——**仅做队列去重**；批级幂等键是
/// poster sidecar 的 `batch_key = keccak_root`（键域闭合，见 crate 文档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SettleKey {
    pub table_id: u32,
    pub hand_id: u32,
}

impl SettleKey {
    pub const fn new(table_id: u32, hand_id: u32) -> Self {
        Self { table_id, hand_id }
    }

    /// sidecar 文件名片段（`receipts/<key>.json` / `dead/<key>.json`）。
    pub fn file_stem(&self) -> String {
        format!("{}-{}", self.table_id, self.hand_id)
    }
}

impl std::fmt::Display for SettleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({},{})", self.table_id, self.hand_id)
    }
}

/// 投递路由判别器（两态，终审修订）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettleRoute {
    /// legacy 路：texas 预构建的 register_aggregate → settle_hand 两笔
    /// calldata 直投（submit.rs 形态）。
    Legacy,
    /// Dual 路：register_hand → verify_and_settle_dapv*（入口由
    /// `dapv_entry` 携带）；可被 poster 攒入 fold 批（批形态是 poster 运营
    /// 策略，不是条目级 route——现状 `SettleMode` 仅 {Linear, Proved}，
    /// `texas/src/starknet/config.rs:24-39`，无 fold 开关）。
    Dual,
}

impl SettleRoute {
    /// 按 `STARKNET_SETTLEMENT_MODE` 判别（config.rs:136-149 语义镜像：
    /// 精确匹配、仅认 `legacy | snip36`，**其余一律钉 legacy**——未知值
    /// 告警语义由 config.rs:142-148 承担，本函数保持纯函数、不重复告警）。
    pub fn from_settlement_mode(mode: &str) -> Self {
        match mode.trim() {
            "snip36" => SettleRoute::Dual,
            _ => SettleRoute::Legacy,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SettleRoute::Legacy => "legacy",
            SettleRoute::Dual => "dual",
        }
    }
}

/// 结算出口 → 投递路由映射（SettlementExit 与 SettleRoute 的显式固化）。
///
/// `exit_raw` = `STARKNET_SETTLEMENT_EXIT` 原文：`"starknet" | "legacy"`
/// （大小写不敏感）走 Starknet 投递路并按 settlement_mode 细分；其余
/// （含空/未知，Appchain 默认语义，exit.rs:71-74）返回 `None`——不入队。
pub fn route_for_exit(exit_raw: &str, settlement_mode: &str) -> Option<SettleRoute> {
    let starknet_exit = matches!(
        exit_raw.trim().to_ascii_lowercase().as_str(),
        "starknet" | "legacy"
    );
    if starknet_exit {
        Some(SettleRoute::from_settlement_mode(settlement_mode))
    } else {
        None
    }
}

/// Felt 词的 hex 载体（`0x…` 或裸 hex，32 字节大端语义；由 texas 侧编码、
/// poster 侧原样转发——队列不理解 calldata 语义）。
pub type FeltHex = String;

/// Dual 路且可入 fold 批时的语句面（`groth16_wrap::batch::BatchStatement`
/// 的 serde 镜像：program_hash / hand_binding / fact 三 hex 词）。fold 批键
/// `batch_key = keccak_root` 由 batch-poster 用同公式派生（与
/// zchain SettleBatch.sol 逐式一致）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldStatement {
    pub program_hash: FeltHex,
    pub hand_binding: FeltHex,
    pub fact: FeltHex,
}

/// 一笔交易的完整调用面（selector + calldata 词；texas 预构建，队列/poster
/// 只透传不重建语义）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegCalldata {
    /// 入口 selector（hex felt；如 register_aggregate / settle_hand /
    /// register_hand / verify_and_settle_dapv*）。
    pub selector: FeltHex,
    /// calldata 词（hex felt）。
    pub calldata: Vec<FeltHex>,
}

/// texas 预构建 calldata（队列只透传，不重建）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlePayload {
    /// 第一笔：legacy = register_aggregate / dual = register_hand。
    pub register: LegCalldata,
    /// 第二笔：legacy = settle_hand / dual = verify_and_settle_dapv*（入口
    /// 由 dapv_entry 指示）。
    pub settle: LegCalldata,
    /// Dual 路且 fold 攒批开启时携带；None = 条目只走逐手两笔。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fold_statement: Option<FoldStatement>,
}

/// i128 向量的字符串 serde（WAL 载体兼容：serde_json 部分版本不支持
/// i128 直序列化；十进制字符串对跨语言消费方也更稳）。
mod i128_vec_as_strings {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &[i128], serializer: S) -> Result<S::Ok, S::Error> {
        value
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<i128>, D::Error> {
        let raw = Vec::<String>::deserialize(deserializer)?;
        raw.iter()
            .map(|s| s.parse::<i128>().map_err(serde::de::Error::custom))
            .collect()
    }
}

/// 每手余额增量（escape 地基语料：balance-rollup 随批推进的输入，
/// docs/design/PRIVACY_PROFILE.md §3）。texas 入队时携带（重映射后的
/// 全钱包 felt + wei 净输赢，零和）；队列/poster 不解释语义、原样转发
/// 给 balance-rollup。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceEntry {
    /// 重映射后玩家（全钱包 felt hex；与 vault 键域一致，顺序自由）。
    pub players: Vec<FeltHex>,
    /// 与 players 一一对应的净输赢（wei，零和）。
    #[serde(with = "i128_vec_as_strings")]
    pub deltas_wei: Vec<i128>,
}

/// 队列条目。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleTask {
    /// 单手粒度去重键。
    pub key: SettleKey,
    /// 投递路由（判别见 [`SettleRoute::from_settlement_mode`]）。
    pub route: SettleRoute,
    /// Dual 路内合约入口参数（STARKNET_DAPV_SETTLE_ENTRY 原文：
    /// v2/proved_private/snip36/combined，config.rs:63-77）——不参与判别。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dapv_entry: Option<String>,
    /// texas 预构建 calldata。
    pub payload: SettlePayload,
    /// Dual 条目的 legacy 保底 payload（降级重投用——hooks.rs
    /// `snip36_settle_flow`
    /// 「结算永不因证明阻塞/失败而丢失」：texas 在入队 Dual 条目时同步
    /// 预构建 legacy 保底腿，Dual→Legacy 降级后 poster 改投此 payload。
    /// **降级时保底缺失 = 投递期死信**（fail-closed——poster 绝不拿 dual
    /// calldata 冒充 legacy，判定见 batch-poster 驱动层）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_fallback: Option<SettlePayload>,
    /// 每手余额增量（balance-rollup 语料；None = 升级前历史条目/不入树
    /// 路径——serde default 向后兼容既有 WAL 文件）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance_entry: Option<BalanceEntry>,
    /// 入队时刻（unix 秒）。
    pub created_at: u64,
}

impl SettleTask {
    /// 构造 Dual 条目（入口参数随条目携带）。
    pub fn dual(
        key: SettleKey,
        dapv_entry: String,
        payload: SettlePayload,
        legacy_fallback: Option<SettlePayload>,
        created_at: u64,
    ) -> Self {
        Self {
            key,
            route: SettleRoute::Dual,
            dapv_entry: Some(dapv_entry),
            payload,
            legacy_fallback,
            balance_entry: None,
            created_at,
        }
    }

    /// 构造 Legacy 条目。
    pub fn legacy(key: SettleKey, payload: SettlePayload, created_at: u64) -> Self {
        Self {
            key,
            route: SettleRoute::Legacy,
            dapv_entry: None,
            payload,
            legacy_fallback: None,
            balance_entry: None,
            created_at,
        }
    }

    /// 携带余额增量语料（builder；balance-rollup 随批推进的输入）。
    pub fn with_balance_entry(mut self, entry: BalanceEntry) -> Self {
        self.balance_entry = Some(entry);
        self
    }

    /// 当前路由下的有效 payload：Dual 用主 payload；Legacy 且带保底用
    /// legacy_fallback，否则用主 payload（原生 Legacy 条目的主 payload 即
    /// legacy calldata）。**降级后保底缺失的 fail-closed 判定在驱动层**
    /// （batch-poster 依据 Downgraded 事件区分原生/降级）。
    pub fn effective_payload(&self) -> &SettlePayload {
        match self.route {
            SettleRoute::Dual => &self.payload,
            SettleRoute::Legacy => self.legacy_fallback.as_ref().unwrap_or(&self.payload),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> SettlePayload {
        SettlePayload {
            register: LegCalldata {
                selector: "0x11".into(),
                calldata: vec!["0x1".into()],
            },
            settle: LegCalldata {
                selector: "0x22".into(),
                calldata: vec!["0x2".into()],
            },
            fold_statement: None,
        }
    }

    /// 判别绑 settlement_mode：legacy→Legacy、snip36→Dual、其余钉 Legacy
    /// （config.rs:136-149 镜像——**精确匹配**，大小写敏感，与 from_env
    /// 的 match 语义逐字一致）。
    #[test]
    fn route_discriminates_on_settlement_mode() {
        assert_eq!(
            SettleRoute::from_settlement_mode("legacy"),
            SettleRoute::Legacy
        );
        assert_eq!(
            SettleRoute::from_settlement_mode("snip36"),
            SettleRoute::Dual
        );
        // 未知/空值钉 legacy（不 panic、不产生第三态）。
        assert_eq!(SettleRoute::from_settlement_mode(""), SettleRoute::Legacy);
        assert_eq!(
            SettleRoute::from_settlement_mode("auto"),
            SettleRoute::Legacy
        );
        assert_eq!(
            SettleRoute::from_settlement_mode("SNIP36"),
            SettleRoute::Legacy,
            "config.rs 精确匹配：大小写变体也钉 legacy"
        );
    }

    /// SettlementExit 映射：starknet|legacy → 按 mode 细分；appchain/空 →
    /// 不入队（exit.rs:59-65/:71-74 镜像）。
    #[test]
    fn route_for_exit_maps_settlement_exit() {
        assert_eq!(
            route_for_exit("starknet", "legacy"),
            Some(SettleRoute::Legacy)
        );
        assert_eq!(route_for_exit("legacy", "snip36"), Some(SettleRoute::Dual));
        assert_eq!(
            route_for_exit("", "snip36"),
            None,
            "appchain 默认语义不入队"
        );
        assert_eq!(route_for_exit("appchain", "snip36"), None);
        assert_eq!(
            route_for_exit("Starknet", "legacy"),
            Some(SettleRoute::Legacy)
        );
    }

    /// DAPV 入口参数只随 Dual 条目携带，Legacy 条目为 None；effective_payload
    /// 在降级后切到 legacy 保底。
    #[test]
    fn dapv_entry_and_fallback_payload() {
        let mut d = SettleTask::dual(
            SettleKey::new(1, 2),
            "snip36".into(),
            payload(),
            Some(payload()),
            0,
        );
        assert_eq!(d.route, SettleRoute::Dual);
        assert_eq!(d.dapv_entry.as_deref(), Some("snip36"));
        assert_eq!(
            d.effective_payload().settle.selector,
            "0x22",
            "Dual 用主 payload"
        );
        // 降级（WAL Downgraded 重放语义）后切保底。
        d.route = SettleRoute::Legacy;
        d.legacy_fallback = Some(SettlePayload {
            register: LegCalldata {
                selector: "0xleg1".into(),
                calldata: vec![],
            },
            settle: LegCalldata {
                selector: "0xleg2".into(),
                calldata: vec![],
            },
            fold_statement: None,
        });
        assert_eq!(d.effective_payload().settle.selector, "0xleg2");
        let l = SettleTask::legacy(SettleKey::new(1, 3), payload(), 0);
        assert_eq!(l.route, SettleRoute::Legacy);
        assert!(l.dapv_entry.is_none());
        assert_eq!(
            l.effective_payload().settle.selector,
            "0x22",
            "原生 legacy 主 payload 即 legacy calldata"
        );
    }

    /// serde 往返（WAL/sidecar 的 JSON 载体）+ 旧格式兼容（缺
    /// balance_entry 字段的历史条目反序列化为 None——serde default）。
    #[test]
    fn task_serde_roundtrip() {
        let t = SettleTask::dual(
            SettleKey::new(7, 42),
            "combined".into(),
            SettlePayload {
                register: LegCalldata {
                    selector: "0xaa".into(),
                    calldata: vec!["0x1".into()],
                },
                settle: LegCalldata {
                    selector: "0xbb".into(),
                    calldata: vec!["0x2".into()],
                },
                fold_statement: Some(FoldStatement {
                    program_hash: "0x1".into(),
                    hand_binding: "0x2".into(),
                    fact: "0x3".into(),
                }),
            },
            Some(payload()),
            1_700_000_000,
        )
        .with_balance_entry(BalanceEntry {
            players: vec!["0xaaa".into()],
            deltas_wei: vec![5, -5],
        });
        assert!(t.balance_entry.is_some(), "builder 已携带语料");
        let s = serde_json::to_string(&t).unwrap();
        assert!(s.contains("balance_entry"));
        let back: SettleTask = serde_json::from_str(&s).unwrap();
        assert_eq!(back, t);

        // 旧格式（无 balance_entry 字段）→ None（向后兼容）。
        let mut legacy_json = serde_json::to_string(&SettleTask::legacy(
            SettleKey::new(1, 1),
            payload(),
            0,
        ))
        .unwrap();
        assert!(!legacy_json.contains("balance_entry"), "None 不序列化");
        legacy_json = legacy_json.replace("\"created_at\"", "\"balance_entry\":null,\"created_at\"");
        let old: SettleTask = serde_json::from_str(&legacy_json).unwrap();
        assert!(old.balance_entry.is_none());
    }
}
