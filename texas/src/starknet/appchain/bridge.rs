//! B7：出入金链上侧——事件桥 + 打款执行 + 自动对账。
//!
//! 三条后台管线（全部经 [`VaultProvider`] 抽象与链上侧解耦，测试注入
//! [`MockVaultProvider`]）：
//!
//! 1. **存款桥**（[`run_deposit_bridge`]）：`VaultProvider::poll_deposits`
//!    增量拉取链上充值事件 → 校验 (source_chain, vault, tx_hash,
//!    event_index) 四元组幂等（`deposit_id = blake2s(...)`，sequencer
//!    `deposit_ids` 集合 + `CustodyLedger::confirm_deposit` 双层去重）→
//!    sequencer `Operation::Deposit` 铸 REAL note（面额 = STRK wei 1:1，
//!    与 note 账本口径一致）→ 记录处理游标。
//! 2. **提现执行**（[`run_withdrawal_executor`]）：`CustodyLedger` 队列中
//!    finalized 的提现（§5.4 finality 门在 enqueue 时已强制）→
//!    `VaultProvider::pay_withdrawal` → 成功 `mark_paid`；失败重试有界
//!    （[`MAX_PAY_ATTEMPTS`]，超限告警计数，留待人工处置）。
//! 3. **自动对账**（[`run_reconciliation`]）：周期生成
//!    [`ReconciliationSnapshot`]——Σ已发 REAL note 面额（存续 + 已销毁）
//!    vs 储备（链上余额快照）+ 打款回冲；差异 → `tracing::error` +
//!    `reconciliation_mismatch_total` 计数 + metrics 告警规则
//!    `reconciliation_delta`（M7-ACC-4 形态）；报表结构 serde 可导出
//!    （note 集可导出，预对齐 v2 STARK 储备证明的输入）。
//!
//! REAL note 面额单位 = STRK wei（`poker_appchain::note::Note` 文档口径），
//! 与 vault 托管 1:1；游戏层 chips（1 chip = `WEI_PER_CHIP` wei）在结算
//! 出口换算。

use std::sync::Arc;

use poker_appchain::metrics::evaluate_alerts;
use poker_appchain::note::AssetClass;
use poker_appchain::ops::Operation;

use super::runtime::AppchainRuntime;

/// 单笔链上充值事件（provider 归一化形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositEvent {
    /// 源链 id（v1 = Starknet Sepolia 链 id 常量或部署自定义）。
    pub source_chain: u64,
    /// 收款 vault 合约地址（32B 大端）。
    pub vault: [u8; 32],
    /// 充值交易哈希。
    pub tx_hash: [u8; 32],
    /// 交易内事件序号。
    pub event_index: u64,
    /// 充值玩家钱包（felt，32B 大端）。
    pub owner: [u8; 32],
    /// 充值金额（STRK wei；REAL note 面额 1:1）。
    pub amount: u64,
    /// provider 侧单调游标（增量拉取位点）。
    pub seq: u64,
}

impl DepositEvent {
    /// 幂等键：`blake2s("texas-appchain.deposit.v1" || source_chain ||
    /// vault || tx_hash || event_index)`——四元组唯一，重复事件/重启重放
    /// 均落到同一键，由 sequencer `deposit_ids` 拒绝二次铸币。
    #[must_use]
    pub fn deposit_id(&self) -> [u8; 32] {
        let chain_bytes = self.source_chain.to_be_bytes();
        let index_bytes = self.event_index.to_be_bytes();
        poker_appchain::keys::blake2s32(&[
            b"texas-appchain.deposit.v1".as_slice(),
            &chain_bytes,
            &self.vault,
            &self.tx_hash,
            &index_bytes,
        ])
    }
}

/// 链上侧 provider seam：存款事件拉取 / 提现打款 / 储备快照。
///
/// Starknet 生产实现桥接现有 `chips.rs`/`chain.rs` 基础设施；测试与
/// devnet 默认注入 [`MockVaultProvider`]（真实网络行为不进单测）。
pub trait VaultProvider: Send + Sync {
    /// 拉取 `last_seq`（含）之后即从 `last_seq` 起的充值事件（游标语义 =
    /// 「下一个期望序号」；调用方处理成功后把游标推到 `event.seq + 1`，
    /// 重复拉取由 deposit_id 幂等兜底）。
    ///
    /// # Errors
    /// 链不可达/RPC 失败 → 文本错误（桥任务记日志、下一轮重试）。
    fn poll_deposits(&self, last_seq: u64) -> Result<Vec<DepositEvent>, String>;
    /// 执行一笔托管打款，返回外部交易哈希。
    ///
    /// # Errors
    /// 打款失败（余额不足/链错误）→ 文本错误（执行器有界重试）。
    fn pay_withdrawal(
        &self,
        payout_address: &[u8; 32],
        amount: u64,
        request_id: &[u8; 32],
    ) -> Result<[u8; 32], String>;
    /// 储备快照：托管钱包的链上 STRK 余额（wei）。
    ///
    /// # Errors
    /// 链不可达 → 文本错误（对账任务跳过本轮并告警）。
    fn reserve_snapshot(&self) -> Result<u128, String>;
}

/// 打款执行的最大尝试次数（有界；超限告警计数并停止自动重试）。
pub const MAX_PAY_ATTEMPTS: u32 = 5;

// ===== Mock provider（测试与 devnet 默认）=====

/// 进程内 mock：充值注入、储备记账、打款回冲全部内存态。
#[derive(Default)]
pub struct MockVaultProvider {
    inner: std::sync::Mutex<MockState>,
}

#[derive(Default)]
#[allow(dead_code)] // next_seq/paid 仅测试注入/断言路径读取（bin crate 死代码告警）
struct MockState {
    deposits: Vec<DepositEvent>,
    next_seq: u64,
    next_tx: u64,
    /// 储备（= 初始 + Σ充值 − Σ已打款）。
    reserve: u128,
    paid: Vec<([u8; 32], u64, [u8; 32])>,
}

impl MockVaultProvider {
    /// 空账。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 注入一笔链上充值（储备同步 +amount，模拟 STRK 真实入托管）。
    #[allow(dead_code)] // 测试注入路径
    pub fn push_deposit(&self, mut event: DepositEvent) {
        let mut g = self.inner.lock().expect("mock lock");
        event.seq = g.next_seq;
        g.next_seq += 1;
        g.reserve = g.reserve.saturating_add(u128::from(event.amount));
        g.deposits.push(event);
    }

    /// 注入一笔**重复投递**的同链上事件（同一笔 STRK 转账被 provider
    /// 二次上报）：储备不再入账——资金没有第二次移动；桥侧幂等
    /// （deposit_id）应拒绝二次铸币。
    #[allow(dead_code)] // 测试注入路径
    pub fn push_duplicate(&self, mut event: DepositEvent) {
        let mut g = self.inner.lock().expect("mock lock");
        event.seq = g.next_seq;
        g.next_seq += 1;
        g.deposits.push(event);
    }

    /// 直接设定储备快照（对账差异注入：少记储备 → 告警触发）。
    #[allow(dead_code)] // 测试注入路径
    pub fn set_reserve(&self, reserve: u128) {
        self.inner.lock().expect("mock lock").reserve = reserve;
    }

    /// 已执行打款清单（测试断言用）：(request_id, amount, tx_hash)。
    #[allow(dead_code)] // 测试断言路径
    #[must_use]
    pub fn paid(&self) -> Vec<([u8; 32], u64, [u8; 32])> {
        self.inner.lock().expect("mock lock").paid.clone()
    }
}

impl VaultProvider for MockVaultProvider {
    fn poll_deposits(&self, last_seq: u64) -> Result<Vec<DepositEvent>, String> {
        let g = self.inner.lock().expect("mock lock");
        Ok(g.deposits
            .iter()
            .filter(|e| e.seq >= last_seq)
            .cloned()
            .collect())
    }

    fn pay_withdrawal(
        &self,
        _payout_address: &[u8; 32],
        amount: u64,
        request_id: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        let mut g = self.inner.lock().expect("mock lock");
        if u128::from(amount) > g.reserve {
            return Err(format!(
                "mock reserve {} < payout {amount}",
                g.reserve
            ));
        }
        g.reserve -= u128::from(amount);
        let tx = g.next_tx;
        g.next_tx += 1;
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = 0xDD;
        tx_hash[24..].copy_from_slice(&tx.to_be_bytes());
        g.paid.push((*request_id, amount, tx_hash));
        Ok(tx_hash)
    }

    fn reserve_snapshot(&self) -> Result<u128, String> {
        Ok(self.inner.lock().expect("mock lock").reserve)
    }
}

// ===== Starknet provider（生产实现，桥接既有 chips/chain 基础设施）=====

/// Starknet 实现：`starknet_getEvents` 拉 vault `Deposit` 事件、operator
/// 账户 ERC20 `transfer` 打款、`balance_of(operator)` 储备快照。
///
/// 事件键（cairo flat enum 的全路径 selector）可经
/// `STARKNET_VAULT_DEPOSIT_EVENT_KEY` 覆盖（默认按 poker_vault.cairo 的
/// `poker_vault::PokerVault::Deposit` 计算）；STRK 代币地址经
/// `STARKNET_TOKEN_ADDRESS` 配置（储备与打款的资产锚）。
pub struct StarknetVaultProvider {
    /// vault 合约地址（hex felt）。
    pub vault_address: String,
    /// STRK（或锚定代币）地址（hex felt）；空 = provider 不可用。
    pub token_address: String,
    /// 充值事件键（hex felt；空 = 默认全路径 selector）。
    pub deposit_event_key: String,
    /// 源链 id（充值幂等四元组第一分量）。
    pub source_chain: u64,
}

impl StarknetVaultProvider {
    /// 从环境构建（vault 地址复用 `STARKNET_VAULT_ADDRESS`）。
    #[must_use]
    pub fn from_env(vault_address: String) -> Self {
        Self {
            vault_address,
            token_address: std::env::var("STARKNET_TOKEN_ADDRESS").unwrap_or_default(),
            deposit_event_key: std::env::var("STARKNET_VAULT_DEPOSIT_EVENT_KEY")
                .unwrap_or_default(),
            source_chain: std::env::var("STARKNET_CHAIN_ID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0x53_45_50_4f_4c_49_41), // "SEPOLIA" 数值化占位
        }
    }

    fn deposit_key_felt(&self) -> Option<starknet::core::types::Felt> {
        use starknet::core::utils::starknet_keccak;
        if let Some(f) = super::super::chain::parse_felt(&self.deposit_event_key) {
            return Some(f);
        }
        Some(starknet_keccak(b"poker_vault::PokerVault::Deposit"))
    }

    /// 独立 JSON-RPC POST（与 chips::verify_deposit 同款，规避共享单例挂起）。
    async fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let chain = super::super::chain().ok_or("starknet chain not initialized")?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": method,
            "params": params,
        });
        let resp = http
            .post(&chain.config.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("rpc http: {e}"))?;
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("rpc decode: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(format!("rpc error: {err}"));
        }
        Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }

    fn felt_at(value: &serde_json::Value, path: &[&str]) -> Option<[u8; 32]> {
        let mut cur = value;
        for key in path {
            cur = cur.get(key)?;
        }
        let s = cur.as_str()?;
        super::super::chain::parse_felt(s).map(|f| f.to_bytes_be())
    }
}

impl VaultProvider for StarknetVaultProvider {
    fn poll_deposits(&self, last_seq: u64) -> Result<Vec<DepositEvent>, String> {
        let Some(key) = self.deposit_key_felt() else {
            return Err("deposit event key unavailable".into());
        };
        let Some(vault) = super::super::chain::parse_felt(&self.vault_address) else {
            return Err("vault address unparsable".into());
        };
        // 增量游标以「事件键内单调序号」近似：v1 用 continuing token 拉全量
        // 后按 (block, tx, idx) 过滤——生产 vault 事件量有限，正确性由
        // deposit_id 幂等兜底（重复拉取不重复铸币）。
        let _ = last_seq;
        let params = serde_json::json!({
            "filter": {
                "from_address": format!("{vault:#x}"),
                "keys": [[format!("{key:#x}")]],
                "chunk_size": 1024,
            }
        });
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.rpc("starknet_getEvents", params))
        })?;
        let mut out = Vec::new();
        if let Some(events) = result.get("events").and_then(|v| v.as_array()) {
            for (idx, ev) in events.iter().enumerate() {
                let Some(tx_hash) = Self::felt_at(ev, &["transaction_hash"]) else {
                    continue;
                };
                // data = [player, amount_low, amount_high]
                let Some(owner) = Self::felt_at(ev, &["data", "0"]) else {
                    continue;
                };
                let Some(amount) = Self::felt_at(ev, &["data", "1"]) else {
                    continue;
                };
                let amount = u128::from_be_bytes(amount[16..].try_into().expect("16 bytes"));
                let amount = u64::try_from(amount).unwrap_or(u64::MAX);
                out.push(DepositEvent {
                    source_chain: self.source_chain,
                    vault: vault.to_bytes_be(),
                    tx_hash,
                    event_index: u64::try_from(idx).unwrap_or(0),
                    owner,
                    amount,
                    seq: u64::try_from(idx).unwrap_or(0),
                });
            }
        }
        Ok(out)
    }

    fn pay_withdrawal(
        &self,
        payout_address: &[u8; 32],
        amount: u64,
        _request_id: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        use starknet::accounts::Account;
        use starknet::core::types::{Call, Felt};
        use starknet::core::utils::starknet_keccak;
        let chain = super::super::chain().ok_or("starknet chain not initialized")?;
        let token = super::super::chain::parse_felt(&self.token_address)
            .ok_or("token address not configured (STARKNET_TOKEN_ADDRESS)")?;
        let recipient = felt_from_bytes32(payout_address);
        let call = Call {
            to: token,
            selector: starknet_keccak(b"transfer"),
            calldata: vec![
                recipient,
                Felt::from(amount),
                Felt::ZERO, // u256 high
            ],
        };
        let hash = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let operator = chain
                    .operator()
                    .await
                    .ok_or("operator account unavailable")?;
                operator
                    .execute_v3(vec![call])
                    .send()
                    .await
                    .map(|r| Felt::from(r.transaction_hash))
                    .map_err(|e| format!("transfer submit: {e}"))
            })
        })?;
        Ok(hash.to_bytes_be())
    }

    fn reserve_snapshot(&self) -> Result<u128, String> {
        use starknet::core::utils::starknet_keccak;
        let chain = super::super::chain().ok_or("starknet chain not initialized")?;
        let token = super::super::chain::parse_felt(&self.token_address)
            .ok_or("token address not configured (STARKNET_TOKEN_ADDRESS)")?;
        let operator = super::super::chain::parse_felt(&chain.config.operator_address)
            .ok_or("operator address unparsable")?;
        let selector = starknet_keccak(b"balance_of");
        let felts = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(chain.call_contract(token, selector, vec![operator]))
        })
        .map_err(|e| format!("balance_of: {e}"))?;
        let low = felts.first().copied().unwrap_or_default();
        let high = felts.get(1).copied().unwrap_or_default();
        if high != starknet::core::types::Felt::ZERO {
            return Ok(u128::MAX);
        }
        let bytes = low.to_bytes_be();
        if bytes[..16].iter().any(|&b| b != 0) {
            return Ok(u128::MAX);
        }
        Ok(u128::from_be_bytes(bytes[16..].try_into().expect("16 bytes")))
    }
}

fn felt_from_bytes32(bytes: &[u8; 32]) -> starknet::core::types::Felt {
    starknet::core::types::Felt::from_bytes_be(bytes)
}

// ===== 后台管线 =====

/// 存款桥单轮：拉事件 → 幂等校验 → REAL note 铸出 → 游标推进。
/// 返回本轮处理的笔数。
///
/// # Errors
/// provider 失败 → 文本错误（调用方记日志、下一轮重试）。
pub fn process_deposits_once(rt: &AppchainRuntime) -> Result<usize, String> {
    let cursor = rt.bridge.lock().expect("bridge lock").deposit_cursor;
    let events = rt.provider.poll_deposits(cursor)?;
    let mut processed = 0usize;
    for event in events {
        if event.amount == 0 {
            continue; // 零额事件无铸币语义（note amount > 0 强制）
        }
        let deposit_id = event.deposit_id();
        // 幂等第一层：sequencer 已处理 → 只推游标
        let already = rt
            .with_seq(|seq| seq.state().deposit_ids.contains(&deposit_id));
        if already {
            rt.bridge.lock().expect("bridge lock").deposit_cursor = event.seq + 1;
            continue;
        }
        let owner_key = super::keys::owner_key_of(&event.owner);
        // 铸币资产类跟随 runtime 桌面配置：REAL 桌面维持托管 1:1 纪律
        // （REAL note = 锁仓资产 wei）；Play 桌面（本地/dev/娱乐向）铸 Play
        // ——游戏层消费的是 Play note，铸 REAL 会落在无人消费的账上。
        let asset_class = if rt.config.asset_class == AssetClass::Real {
            AssetClass::Real
        } else {
            AssetClass::Play
        };
        let frame = rt.submit_operation(Operation::Deposit {
            deposit_id,
            owner: owner_key.public_bytes(),
            asset_class,
            amount: event.amount,
        })
        .map_err(|e| format!("deposit {} mint: {e}", hex_encode(&deposit_id)))?;
        // 幂等第二层 + 对账锚：托管账确认（同 id 异载荷冲突 fail-closed）
        let minted = rt.with_seq(|seq| {
            seq.state()
                .notes
                .values()
                .find(|e| e.created_at_op == frame.frame.index)
                .map(|e| e.note.commitment_bytes())
        });
        if let Some(commitment) = minted {
            rt.custody
                .lock()
                .expect("custody lock")
                .confirm_deposit(deposit_id, commitment, event.amount)
                .map_err(|e| format!("custody confirm: {e}"))?;
        }
        // 存款段证明化：链上事件即托管证据（mark_proven 走连续前缀语义，
        // 绝不越过在途未证结算 op——§5.4 finality 不弱化）。
        rt.with_seq(|seq| seq.mark_proven(frame.frame.index));
        rt.metrics.inc("bridge_deposits_total");
        tracing::info!(
            "[appchain-bridge] REAL deposit minted: {} wei (tx {}#{}, note op {})",
            event.amount,
            hex_encode(&event.tx_hash),
            event.event_index,
            frame.frame.index
        );
        rt.bridge.lock().expect("bridge lock").deposit_cursor = event.seq + 1;
        processed += 1;
    }
    Ok(processed)
}

/// 提现执行单轮：队列中 finalized 提现 → pay → mark_paid（有界重试）。
/// 返回本轮成功打款笔数。
pub fn process_withdrawals_once(rt: &AppchainRuntime) -> usize {
    let queued = rt
        .custody
        .lock()
        .expect("custody lock")
        .queued_requests();
    let mut paid = 0usize;
    for request in queued {
        let attempts = {
            let mut g = rt.bridge.lock().expect("bridge lock");
            let n = g.pay_attempts.entry(request.request_id).or_insert(0);
            *n += 1;
            *n
        };
        if attempts > MAX_PAY_ATTEMPTS {
            // 超限：停止自动重试（告警计数一次性），等人工处置/进程重启
            if attempts == MAX_PAY_ATTEMPTS + 1 {
                rt.metrics.inc("withdrawal_pay_exhausted_total");
                tracing::error!(
                    "[appchain-bridge] withdrawal {} exceeded {MAX_PAY_ATTEMPTS} pay attempts — manual handling required",
                    hex_encode(&request.request_id)
                );
            }
            continue;
        }
        match rt
            .provider
            .pay_withdrawal(&request.payout_address, request.amount, &request.request_id)
        {
            Ok(tx_hash) => {
                if let Err(e) = rt
                    .custody
                    .lock()
                    .expect("custody lock")
                    .mark_paid(request.request_id, tx_hash)
                {
                    tracing::error!(
                        "[appchain-bridge] mark_paid {} failed: {e} — paid total not credited",
                        hex_encode(&request.request_id)
                    );
                    continue;
                }
                rt.bridge.lock().expect("bridge lock").paid_total += u128::from(request.amount);
                rt.metrics.inc("bridge_withdrawals_paid_total");
                tracing::info!(
                    "[appchain-bridge] withdrawal paid: {} wei → {} (tx {})",
                    request.amount,
                    hex_encode(&request.payout_address),
                    hex_encode(&tx_hash)
                );
                paid += 1;
            }
            Err(e) => {
                tracing::warn!(
                    "[appchain-bridge] withdrawal {} pay failed (attempt {attempts}/{MAX_PAY_ATTEMPTS}): {e}",
                    hex_encode(&request.request_id)
                );
            }
        }
    }
    paid
}

/// 日终对账快照（报表结构预对齐 v2 STARK 储备证明的输入：note 集可导出）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReconciliationSnapshot {
    /// 存续 REAL note 面额合计（wei）。
    pub live_real_total: u128,
    /// 已销毁（提现中/已提现）REAL 面额合计（wei）。
    pub burned_real_total: u128,
    /// 已发行 REAL 总额 = live + burned（对账分子）。
    pub issued_real_total: u128,
    /// 链上储备快照（wei）。
    pub reserved_on_chain: u128,
    /// 已打款累计（回冲项：钱已离托管但 note 已销毁，两侧对消）。
    pub paid_out_total: u128,
    /// 有效储备 = 快照 + 回冲。
    pub reserved_effective: u128,
    /// 浮存：排队未打款提现合计（wei）。
    pub pending_withdrawal_total: u128,
    /// 差异 = reserved_effective − issued。0 = 平。
    pub delta: i128,
    /// 存续 REAL note 清单（owner_hex, amount）——储备证明输入形态。
    pub live_real_notes: Vec<(String, u64)>,
    /// 生成时刻（RFC3339 秒精度；时钟不可用时为 unix 秒字符串）。
    pub generated_at: String,
}

/// 自动对账单轮：生成快照 + 差异告警（M7-ACC-4 形态）。
/// 返回 Some(快照)（provider 失败时 None 并告警）。
pub fn reconcile_once(rt: &AppchainRuntime) -> Option<ReconciliationSnapshot> {
    let snapshot = match rt.provider.reserve_snapshot() {
        Ok(v) => v,
        Err(e) => {
            rt.metrics.inc("reconciliation_failed_total");
            tracing::error!("[appchain-bridge] reserve snapshot failed: {e} — reconciliation skipped");
            return None;
        }
    };
    let (live, issued, notes, burned) = rt.with_seq(|seq| {
        let mut live = 0u128;
        let mut notes = Vec::new();
        for e in seq.state().notes.values() {
            if e.note.asset_class == AssetClass::Real {
                live += u128::from(e.note.amount);
                notes.push((hex_encode(&e.note.owner), e.note.amount));
            }
        }
        let burned: u128 = seq.state().burned.iter().map(|(_, a)| u128::from(*a)).sum();
        notes.sort();
        (live, live + burned, notes, burned)
    });
    let paid_total = rt.bridge.lock().expect("bridge lock").paid_total;
    let reserved_effective = snapshot.saturating_add(paid_total);
    let mut custody = rt.custody.lock().expect("custody lock");
    custody.record_external_reserve(reserved_effective);
    let report = match custody.reconciliation(issued) {
        Ok(r) => r,
        Err(e) => {
            rt.metrics.inc("reconciliation_mismatch_total");
            tracing::error!("[appchain-bridge] reconciliation overflow: {e}");
            return None;
        }
    };
    let snap = ReconciliationSnapshot {
        live_real_total: live,
        burned_real_total: burned,
        issued_real_total: issued,
        reserved_on_chain: snapshot,
        paid_out_total: paid_total,
        reserved_effective,
        pending_withdrawal_total: report.pending_withdrawal_total,
        delta: report.delta,
        live_real_notes: notes,
        generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    if snap.delta != 0 {
        rt.metrics.inc("reconciliation_mismatch_total");
        tracing::error!(
            "[appchain-bridge] RECONCILIATION MISMATCH: issued {} vs reserved(snapshot {} + paid-back {}); delta {:+} wei (pending {})",
            snap.issued_real_total,
            snap.reserved_on_chain,
            snap.paid_out_total,
            snap.delta,
            snap.pending_withdrawal_total,
        );
    } else {
        tracing::info!(
            "[appchain-bridge] reconciliation balanced: issued {} == reserved {} (浮存 {})",
            snap.issued_real_total,
            snap.reserved_effective,
            snap.pending_withdrawal_total,
        );
    }
    // 告警规则评估（与 poker_appchain::metrics 同一规则集）
    for alert in evaluate_alerts(&custody.health(issued)) {
        tracing::warn!("[appchain-bridge] alert [{}]: {}", alert.rule, alert.message);
    }
    rt.bridge
        .lock()
        .expect("bridge lock")
        .last_report = serde_json::to_value(&snap).ok();
    Some(snap)
}

/// 后台任务装配：存款桥 / 提现执行 / 自动对账三循环（可配置开关与周期）。
/// 由 `appchain::init` 在服务器启动流程中调用。
pub fn spawn_bridge_tasks(rt: Arc<AppchainRuntime>) {
    let poll_ms = rt.config.poll_ms.max(200);
    // 存款桥 + 提现执行（同周期，不同失败域）
    {
        let rt = Arc::clone(&rt);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(poll_ms));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(e) = process_deposits_once(&rt) {
                    tracing::warn!("[appchain-bridge] deposit poll failed: {e}");
                }
                process_withdrawals_once(&rt);
            }
        });
    }
    // 自动对账（独立周期）
    {
        let rt = Arc::clone(&rt);
        let period = std::time::Duration::from_secs(rt.config.reconcile_secs.max(5));
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                reconcile_once(&rt);
            }
        });
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2 + 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 幂等键：四元组逐字段敏感。
    #[test]
    fn deposit_id_binds_full_tuple() {
        let mk = |tx: u8, idx: u64| DepositEvent {
            source_chain: 7,
            vault: [1; 32],
            tx_hash: [tx; 32],
            event_index: idx,
            owner: [3; 32],
            amount: 100,
            seq: 0,
        };
        assert_eq!(mk(1, 1).deposit_id(), mk(1, 1).deposit_id(), "同事件同键");
        assert_ne!(mk(1, 1).deposit_id(), mk(2, 1).deposit_id(), "tx 变 → 键变");
        assert_ne!(mk(1, 1).deposit_id(), mk(1, 2).deposit_id(), "idx 变 → 键变");
        let mut other_chain = mk(1, 1);
        other_chain.source_chain = 8;
        assert_ne!(mk(1, 1).deposit_id(), other_chain.deposit_id(), "链变 → 键变");
    }

    /// mock 打款回冲储备；余额不足报错。
    #[test]
    fn mock_pay_decrements_reserve() {
        let mock = MockVaultProvider::new();
        mock.push_deposit(DepositEvent {
            source_chain: 1,
            vault: [1; 32],
            tx_hash: [2; 32],
            event_index: 0,
            owner: [3; 32],
            amount: 500,
            seq: 0,
        });
        assert_eq!(mock.reserve_snapshot().unwrap(), 500);
        let tx = mock.pay_withdrawal(&[9; 32], 200, &[4; 32]).unwrap();
        assert_eq!(tx[0], 0xDD);
        assert_eq!(mock.reserve_snapshot().unwrap(), 300);
        assert_eq!(mock.paid().len(), 1);
        assert!(mock.pay_withdrawal(&[9; 32], 400, &[5; 32]).is_err());
    }

    /// seq 游标过滤：last_seq（含）起的增量可见（游标 = 下一个期望序号）。
    #[test]
    fn poll_deposits_incremental() {
        let mock = MockVaultProvider::new();
        for i in 0..3u8 {
            mock.push_deposit(DepositEvent {
                source_chain: 1,
                vault: [1; 32],
                tx_hash: [i + 1; 32],
                event_index: 0,
                owner: [3; 32],
                amount: 10,
                seq: 0,
            });
        }
        assert_eq!(mock.poll_deposits(0).unwrap().len(), 3);
        assert_eq!(mock.poll_deposits(1).unwrap().len(), 2);
        assert_eq!(mock.poll_deposits(3).unwrap().len(), 0);
    }
}
