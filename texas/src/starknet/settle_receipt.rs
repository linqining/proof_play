//! 结算回执注册表（D2/D3/D4：牌桌设计稿链上元数据下发，
//! `design/table/data-gaps-onchain.md`）。
//!
//! 三条结算出口（appchain / dual / legacy）的成功、拒绝与终局失败都在
//! 此落一条 [`HandSettleReceipt`]，供：
//!
//! - REST 证明通道 `/api/tables/:id/hands/:seq/proof` 的 `settlement` 段
//!   （T4「已上链结算」印章 / T6 托管提示）；
//! - WS `settlement_result` 实时广播（印章免刷新翻面，FAILED 可展开原因）；
//! - D2：starknet 出口成功后异步拉 `starknet_getTransactionReceipt`
//!   回填 `block_number` + `gas_fee`（STRK 十进制串）；链下/appchain 出口
//!   无 L1 receipt，两行由前端按空省略；
//! - D3：回执携带本手结算走的合约地址 + 验证者展示标签（以服务端下发
//!   为准，客户端 env 只留 fallback）；
//! - D4：`hand_binding` ↔ (table_id, hand_id) 映射的服务端权威落点
//!   （方案 1：texas 落 binding，客户端不再直查 gateway 过滤 table）。
//!
//! 注册表进程内有界（每桌 [`CAPACITY_PER_TABLE`] 条 FIFO）；重启即空与
//! history store 同语义（in-memory 看板）。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use starknet::providers::Provider as _;

/// 每桌保留的结算回执条数。
pub const CAPACITY_PER_TABLE: usize = 200;

/// WS 事件名（`pokergame::actions::SETTLEMENT_RESULT` 的规范常量）。
pub const SETTLEMENT_RESULT_EVENT: &str = crate::pokergame::actions::SETTLEMENT_RESULT;

/// 结算终态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleStatus {
    /// 已上链 / 已入 appchain 软确认链（T4 印章绿态）。
    Settled,
    /// 对账拒绝（确定性失败：镜像分歧 / 守恒破坏 / 交叉校验不过）。
    Refused,
    /// 构建/提交终局失败（重试上限后放弃）。
    Failed,
}

impl SettleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Settled => "settled",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }
}

/// 单手结算回执（REST `settlement` 段 + WS `settlement_result` 载荷）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandSettleReceipt {
    pub table_id: u32,
    /// 本手 id（与证明留存 / history.hand_id 同源）。
    pub hand_id: u32,
    /// 对应 history hand_seq（下发时回填；终局记录尚未落时为 None）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hand_seq: Option<u64>,
    pub status: &'static str,
    /// 结算出口："appchain" | "dual" | "legacy"。
    pub exit: &'static str,
    /// 手绑定（32 字节 0x-hex）。appchain = 归档 batch/派生域摘要；
    /// dual = `compute_hand_binding`；legacy = None（以 aggregate digest
    /// 锚定，见 `aggregate_digest`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hand_binding: Option<String>,
    /// legacy 出口的聚合摘要（0x-hex；链上 register/settle 的锚）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_digest: Option<String>,
    /// 上链交易 digest（register / settle；0x-hex）。
    pub tx_digests: Vec<String>,
    /// 首个交易所在区块号（D2，starknet 出口回填）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// gas 费展示串（D2，如 "0.0031 STRK"；多笔为合计）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_fee: Option<String>,
    /// 本手结算合约地址（D3；appchain 出口为 None）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
    /// 验证者展示标签（D3）：按结算拓扑给出，客户端只展示不解释。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    /// appchain：settle 操作帧链序号。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settle_op_index: Option<u64>,
    /// appchain：覆盖本手的批次根（proven 时有）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_root: Option<String>,
    /// appchain：是否已落批出证。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proven: Option<bool>,
    /// 拒绝/失败原因（FAILED 态面板展开）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub ts_ms: u64,
}

fn registry() -> &'static Mutex<HashMap<u32, VecDeque<HandSettleReceipt>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u32, VecDeque<HandSettleReceipt>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 当前毫秒时间戳（与 relayer::util::now_ms 同源语义）。
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 落一条回执（upsert：同 (table, hand) 覆盖，保留已有 block/gas 元数据
/// 除非新回执自带）。同时做 history hand_seq 对账回填。
pub fn record(mut receipt: HandSettleReceipt) {
    // hand_seq 对账：终局记录已落时给出映射（证明通道 / WS 都消费）。
    receipt.hand_seq = crate::pokergame::history_store::global_store()
        .find_seq_by_hand_id(receipt.table_id, receipt.hand_id)
        .or(receipt.hand_seq);
    let mut map = match registry().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let queue = map.entry(receipt.table_id).or_default();
    // upsert：tx meta 异步回填后重写时保留先前的区块/gas。
    if let Some(existing) = queue.iter_mut().find(|r| r.hand_id == receipt.hand_id) {
        if receipt.block_number.is_none() {
            receipt.block_number = existing.block_number;
        }
        if receipt.gas_fee.is_none() {
            receipt.gas_fee = existing.gas_fee.clone();
        }
    }
    queue.retain(|r| r.hand_id != receipt.hand_id);
    queue.push_back(receipt);
    while queue.len() > CAPACITY_PER_TABLE {
        queue.pop_front();
    }
}

/// 查单手回执。
pub fn get(table_id: u32, hand_id: u32) -> Option<HandSettleReceipt> {
    let map = match registry().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.get(&table_id)?
        .iter()
        .rev()
        .find(|r| r.hand_id == hand_id)
        .cloned()
}

/// D2：starknet 出口成功后异步回填 block/gas（best-effort，失败仅告警——
/// 两行展示数据绝不阻塞结算主流程）。回填后重写注册表并补播 WS 事件。
pub async fn attach_tx_meta(table_id: u32, hand_id: u32, tx_hashes: &[String]) {
    let Some(chain) = super::chain() else { return };
    let mut block_number: Option<u64> = None;
    let mut total_fee: Option<u128> = None;
    for hash in tx_hashes {
        let Ok(felt) = starknet::core::types::Felt::from_hex(hash) else { continue };
        // 有界等待：公共 RPC 秒级出块，30×2s 足够 accepted 交易出现回执。
        for _ in 0..30 {
            match chain.provider().get_transaction_receipt(felt).await {
                Ok(receipt) => {
                    use starknet::core::types::TransactionReceipt as R;
                    let fee = match &receipt.receipt {
                        R::Invoke(t) => Some(t.actual_fee.amount),
                        R::L1Handler(t) => Some(t.actual_fee.amount),
                        R::Declare(t) => Some(t.actual_fee.amount),
                        R::Deploy(t) => Some(t.actual_fee.amount),
                        R::DeployAccount(t) => Some(t.actual_fee.amount),
                    };
                    if let Some(fee) = fee {
                        // FRI（STRK）18 位小数；u128 足够（fee 上界 2^128 内）。
                        let bytes = fee.to_bytes_be();
                        let amount = u128::from_be_bytes(bytes[16..32].try_into().expect("16 bytes"));
                        let high = &bytes[..16];
                        let amount = if high.iter().all(|b| *b == 0) {
                            amount
                        } else {
                            u128::MAX // 超精度上界，展示层饱和
                        };
                        total_fee = Some(total_fee.map_or(amount, |acc| acc.saturating_add(amount)));
                    }
                    if block_number.is_none() {
                        block_number = Some(receipt.block.block_number());
                    }
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }
    if block_number.is_none() && total_fee.is_none() {
        tracing::warn!("[settle-receipt] table {table_id} hand {hand_id}: no tx receipt observed for {tx_hashes:?}");
        return;
    }
    let mut updated = get(table_id, hand_id).map(|mut r| {
        r.block_number = block_number;
        r.gas_fee = total_fee.map(|fee| format_fee_strk(fee));
        r
    });
    if let Some(receipt) = updated.take() {
        record(receipt.clone());
        broadcast(table_id, &receipt).await;
    }
}

/// gas 费整数（FRI/STRK 18 位小数）→ 十进制串。
fn format_fee_strk(amount: u128) -> String {
    let digits = amount.to_string();
    let (int_part, frac_part) = if digits.len() > 18 {
        let split = digits.len() - 18;
        (digits[..split].to_owned(), digits[split..].to_owned())
    } else {
        ("0".to_owned(), format!("{digits:0>18}"))
    };
    let frac = frac_part.trim_end_matches('0');
    if frac.is_empty() {
        format!("{int_part} STRK")
    } else {
        format!("{int_part}.{frac} STRK")
    }
}

/// 广播 `settlement_result` 给该桌（观测事件：失败只记日志，不传播错误）。
pub async fn broadcast(table_id: u32, receipt: &HandSettleReceipt) {
    let Some(io) = crate::socket::get_socket_io() else { return };
    let room = crate::socket::table_room_name(table_id);
    if let Err(e) = io.to(room).emit(SETTLEMENT_RESULT_EVENT, receipt).await {
        tracing::warn!(
            "[settle-receipt] broadcast failed: table={table_id} hand={} error={e:?}",
            receipt.hand_id
        );
    }
}

/// 落回执并广播（成功路径组合入口）。
pub async fn record_and_broadcast(receipt: HandSettleReceipt) {
    record(receipt.clone());
    broadcast(receipt.table_id, &receipt).await;
}

/// D3：链上元数据（随证明通道下发；以服务端配置为准）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainMeta {
    /// 生效结算出口："appchain" | "starknet"。
    pub exit: String,
    /// 本手相关结算合约（dual 优先，回退 legacy settlement；空 = 未配置）。
    pub contract: Option<String>,
    pub dual_settlement: Option<String>,
    pub settlement: Option<String>,
    pub vault: Option<String>,
    /// 验证者展示标签（D3：按拓扑给的静态标签）。
    pub verifier: Option<String>,
    /// explorer gateway 基址（配置了才有；`/api/v1/settlement/{binding}`
    /// 详情 / `/api/v1/proof/{binding_hex}` attestation 的前缀）。
    pub gateway: Option<String>,
}

impl ChainMeta {
    pub fn from_config() -> Self {
        let Some(chain) = super::chain() else {
            return Self {
                exit: "appchain".to_owned(),
                contract: None,
                dual_settlement: None,
                settlement: None,
                vault: None,
                verifier: None,
                gateway: None,
            };
        };
        let cfg = &chain.config;
        let dual = non_empty(cfg.dual_settlement_address.clone());
        let settlement = non_empty(cfg.settlement_address.clone());
        let contract = dual.clone().or(settlement.clone());
        let verifier = if contract.is_some() {
            Some("starknet verifier".to_owned())
        } else {
            Some("appchain attestor".to_owned())
        };
        Self {
            exit: if cfg.settlement_exit_appchain() { "appchain".to_owned() } else { "starknet".to_owned() },
            contract,
            dual_settlement: dual,
            settlement,
            vault: non_empty(cfg.vault_address.clone()),
            verifier,
            gateway: non_empty(cfg.gateway_base_url.clone()),
        }
    }
}

fn non_empty(s: String) -> Option<String> {
    if s.trim().is_empty() { None } else { Some(s) }
}

/// 便捷构造：appchain 出口成功。
pub fn appchain_settled(table_id: u32, hand_id: u32, hand_binding: [u8; 32], settle_op_index: u64, proven: bool, batch_root: Option<[u8; 32]>) -> HandSettleReceipt {
    HandSettleReceipt {
        table_id,
        hand_id,
        hand_seq: None,
        status: SettleStatus::Settled.as_str(),
        exit: "appchain",
        hand_binding: Some(format!("0x{}", hex::encode(hand_binding))),
        aggregate_digest: None,
        tx_digests: Vec::new(),
        block_number: None,
        gas_fee: None,
        contract: None,
        verifier: Some("appchain attestor".to_owned()),
        settle_op_index: Some(settle_op_index),
        batch_root: batch_root.map(|r| format!("0x{}", hex::encode(r))),
        proven: Some(proven),
        reason: None,
        ts_ms: now_ms(),
    }
}

/// 便捷构造：starknet 出口（dual / legacy）成功。
pub fn starknet_settled(table_id: u32, hand_id: u32, exit: &'static str, hand_binding: Option<String>, aggregate_digest: Option<String>, tx_digests: Vec<String>, contract: Option<String>) -> HandSettleReceipt {
    HandSettleReceipt {
        table_id,
        hand_id,
        hand_seq: None,
        status: SettleStatus::Settled.as_str(),
        exit,
        hand_binding,
        aggregate_digest,
        tx_digests,
        block_number: None,
        gas_fee: None,
        contract,
        verifier: Some("starknet verifier".to_owned()),
        settle_op_index: None,
        batch_root: None,
        proven: None,
        reason: None,
        ts_ms: now_ms(),
    }
}

/// 便捷构造：拒绝 / 终局失败。
pub fn terminal_failure(table_id: u32, hand_id: u32, status: SettleStatus, exit: &'static str, reason: String) -> HandSettleReceipt {
    HandSettleReceipt {
        table_id,
        hand_id,
        hand_seq: None,
        status: status.as_str(),
        exit,
        hand_binding: None,
        aggregate_digest: None,
        tx_digests: Vec::new(),
        block_number: None,
        gas_fee: None,
        contract: None,
        verifier: None,
        settle_op_index: None,
        batch_root: None,
        proven: None,
        reason: Some(reason),
        ts_ms: now_ms(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settled(table: u32, hand: u32) -> HandSettleReceipt {
        starknet_settled(
            table,
            hand,
            "dual",
            Some("0xab".to_owned()),
            None,
            vec!["0x1".to_owned(), "0x2".to_owned()],
            Some("0xcontract".to_owned()),
        )
    }

    #[test]
    fn upsert_overrides_and_keeps_tx_meta() {
        record(settled(101, 5));
        record(settled(101, 5));
        let got = get(101, 5).expect("upserted");
        assert_eq!(got.tx_digests.len(), 2);
        // 覆盖后保留异步回填的 block/gas
        let mut with_meta = settled(101, 5);
        with_meta.block_number = Some(842_119);
        with_meta.gas_fee = Some("0.0031 STRK".to_owned());
        record(with_meta);
        let plain = settled(101, 5);
        record(plain);
        assert_eq!(get(101, 5).unwrap().block_number, Some(842_119), "重写保留 block");
        assert_eq!(get(101, 5).unwrap().gas_fee.as_deref(), Some("0.0031 STRK"));
    }

    #[test]
    fn capacity_per_table_bounded() {
        for hand in 0..(CAPACITY_PER_TABLE as u32 + 10) {
            record(settled(102, hand));
        }
        assert!(get(102, 0).is_none(), "最旧被淘汰");
        assert!(get(102, CAPACITY_PER_TABLE as u32 + 9).is_some());
    }

    #[test]
    fn fee_formatting() {
        assert_eq!(format_fee_strk(3_100_000_000_000_000), "0.0031 STRK");
        assert_eq!(format_fee_strk(0), "0 STRK");
        assert_eq!(format_fee_strk(1_000_000_000_000_000_000), "1 STRK");
        assert_eq!(format_fee_strk(2_500_000_000_000_000_000), "2.5 STRK");
    }
}
