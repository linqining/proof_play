//! Monad（EVM）L1Bridge 出入金 provider——proof_play 的 L1 切换件。
//!
//! Starknet PokerVault（Cairo）→ Monad `L1Bridge`（Solidity，contracts/monad）：
//! 玩家 `depositNative(to)` 锁 MON → `DepositInitiated(nonce, token, to, amount)`
//! 事件 → 本 provider 经 `eth_getLogs` 拉取 → 既有存款桥幂等铸 appchain note
//! （与 StarknetVaultProvider 同一 [`VaultProvider`] seam，引擎零改动）。
//!
//! 环境面：
//! - `MONAD_RPC_URL`——EVM JSON-RPC（Monad testnet `https://testnet-rpc.monad.xyz`
//!   / 本地 anvil `http://127.0.0.1:8545 --chain-id 10143`）
//! - `MONAD_L1BRIDGE_ADDRESS`——L1Bridge 合约（0x + 20B hex）
//! - `MONAD_DEPOSIT_FROM_BLOCK`——事件扫描起始块（缺省 0；生产按部署块设，
//!   重启后重放由 deposit_id 幂等兜底）
//!
//! 启用：`TEXAS_APPCHAIN_PROVIDER=monad`。
//!
//! 未实现面：`pay_withdrawal`（出金方向需要 EVM 交易签名——留待 EVM txmgr
//! 一起接线，本片只做买入闭环，调用即显式报错而非静默）。

use sha3::digest::Digest;

use super::bridge::{DepositEvent, VaultProvider};

/// L1Bridge `DepositInitiated(uint256 indexed nonce, address indexed token,
/// address indexed to, uint256 amount)` 的事件主题。
fn deposit_topic0() -> [u8; 32] {
    let mut h = sha3::Keccak256::new();
    h.update(b"DepositInitiated(uint256,address,address,uint256)");
    h.finalize().into()
}

/// EVM 地址 hex（0x 前缀，大小写不限）→ 20 字节。
fn parse_address(s: &str) -> Option<[u8; 20]> {
    let hex = s.trim().trim_start_matches("0x");
    if hex.len() != 40 {
        return None;
    }
    let bytes = hex::decode(hex).ok()?;
    bytes.try_into().ok()
}

/// 事件 indexed address topic（32B 左补零）→ 20 字节（高 12B 非零拒绝）。
fn address_from_topic(topic: &str) -> Option<[u8; 20]> {
    let digits = topic.trim().trim_start_matches("0x");
    if digits.len() != 64 {
        return None;
    }
    let bytes = hex::decode(digits).ok()?;
    if bytes[..12].iter().any(|&b| b != 0) {
        return None;
    }
    Some(bytes[12..].try_into().expect("20 bytes"))
}

/// `u256`/任意长度大端 → u128（高位非零饱和；不足 16 字节左补零——
/// JSON-RPC quantity/uint256 的紧凑 hex 解码后长度不固定）。
fn u128_from_be(bytes: &[u8]) -> u128 {
    if bytes.len() > 16 {
        if bytes[..bytes.len() - 16].iter().any(|&b| b != 0) {
            return u128::MAX;
        }
        return u128::from_be_bytes(
            bytes[bytes.len() - 16..].try_into().expect("16 bytes"),
        );
    }
    let mut buf = [0u8; 16];
    buf[16 - bytes.len()..].copy_from_slice(bytes);
    u128::from_be_bytes(buf)
}

pub struct MonadVaultProvider {
    rpc_url: String,
    bridge: [u8; 20],
    from_block: u64,
    source_chain: u64,
    http: reqwest::Client,
}

impl MonadVaultProvider {
    /// 从环境构造；`MONAD_RPC_URL`/`MONAD_L1BRIDGE_ADDRESS` 缺失即报错
    /// （provider 选择处已按 env 前置判断，走到这里说明配置不完整）。
    pub fn from_env() -> Result<Self, String> {
        let rpc_url = std::env::var("MONAD_RPC_URL").map_err(|_| "MONAD_RPC_URL not set".to_string())?;
        let bridge = parse_address(
            &std::env::var("MONAD_L1BRIDGE_ADDRESS")
                .map_err(|_| "MONAD_L1BRIDGE_ADDRESS not set".to_string())?,
        )
        .ok_or_else(|| "MONAD_L1BRIDGE_ADDRESS invalid (expect 0x + 40 hex)".to_string())?;
        let from_block = std::env::var("MONAD_DEPOSIT_FROM_BLOCK")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        // source_chain 仅作 deposit_id 幂等键原料；取 RPC 实际 chainId，
        // 取不到时用 0（幂等键仍然含 tx_hash + event_index，不失效）。
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self {
            rpc_url,
            bridge,
            from_block,
            source_chain: 0,
            http,
        })
    }

    /// 启动日志用（不含密钥面）。
    pub fn rpc_url_for_log(&self) -> &str {
        &self.rpc_url
    }

    pub fn bridge_for_log(&self) -> [u8; 20] {
        self.bridge
    }

    /// 同步 JSON-RPC POST（VaultProvider 为同步 trait；与 StarknetVaultProvider
    /// 相同的 block_in_place 模式——桥循环在 tokio worker 上跑）。
    fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params
        });
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let resp = self
                    .http
                    .post(&self.rpc_url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| format!("rpc http: {e}"))?;
                let v: serde_json::Value =
                    resp.json().await.map_err(|e| format!("rpc json: {e}"))?;
                if let Some(err) = v.get("error") {
                    return Err(format!("rpc {method}: {err}"));
                }
                Ok(v["result"].clone())
            })
        })
    }

    /// 单条日志 → DepositEvent。topics = [topic0, nonce, token, to]，
    /// data = amount（非索引 uint256）。
    fn decode_log(&self, log: &serde_json::Value) -> Option<DepositEvent> {
        let addr_hex = log.get("address")?.as_str()?;
        if parse_address(addr_hex)? != self.bridge {
            return None;
        }
        let topics = log.get("topics")?.as_array()?;
        let topic0 = format!("0x{}", hex::encode(deposit_topic0()));
        if topics.len() < 4
            || !topics[0]
                .as_str()?
                .eq_ignore_ascii_case(&topic0)
        {
            return None;
        }
        let to_topic = topics[3].as_str()?;
        let to20 = address_from_topic(to_topic)?;
        // felt 形态 32B（与 dev faucet / Starknet 事件同一 owner 编码）。
        let mut owner = [0u8; 32];
        owner[12..].copy_from_slice(&to20);

        let tx_hash: [u8; 32] = hex::decode(log.get("transactionHash")?.as_str()?.trim_start_matches("0x"))
            .ok()?
            .try_into()
            .ok()?;
        let block = u64::from_str_radix(
            log.get("blockNumber")?.as_str()?.trim_start_matches("0x"),
            16,
        )
        .ok()?;
        let event_index = log
            .get("logIndex")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let amount = log
            .get("data")
            .and_then(|v| v.as_str())
            .map(|s| hex::decode(s.trim_start_matches("0x")).unwrap_or_default())
            .filter(|d| !d.is_empty())
            .map(|d| u128_from_be(&d))
            .unwrap_or(0);
        let mut vault = [0u8; 32];
        vault[12..].copy_from_slice(&self.bridge);
        Some(DepositEvent {
            source_chain: self.source_chain,
            vault,
            tx_hash,
            event_index,
            owner,
            amount: u64::try_from(amount).unwrap_or(u64::MAX),
            seq: block,
        })
    }
}

impl VaultProvider for MonadVaultProvider {
    fn poll_deposits(&self, last_seq: u64) -> Result<Vec<DepositEvent>, String> {
        let from = self.from_block.max(last_seq);
        // 游标可能已越过链头（处理过最新一块后 cursor = latest+1）；部分节点
        // （含 anvil）对 fromBlock > latest 直接报 invalid block range——
        // 此时静默空轮询，等下一个块再扫。
        if let Ok(v) = self.rpc("eth_blockNumber", serde_json::json!([])) {
            if let Some(hexn) = v.as_str() {
                if let Ok(latest) = u64::from_str_radix(hexn.trim_start_matches("0x"), 16) {
                    if from > latest {
                        return Ok(Vec::new());
                    }
                }
            }
        }
        let params = serde_json::json!([{
            "fromBlock": format!("0x{from:x}"),
            "toBlock": "latest",
            "address": format!("0x{}", hex::encode(self.bridge)),
            "topics": [format!("0x{}", hex::encode(deposit_topic0()))],
        }]);
        let result = self.rpc("eth_getLogs", params)?;
        let logs = result
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut out: Vec<DepositEvent> = logs.iter().filter_map(|l| self.decode_log(l)).collect();
        // 同块内按 logIndex 排序（铸币顺序稳定 → 幂等键稳定）。
        out.sort_by_key(|e| (e.seq, e.event_index));
        Ok(out)
    }

    fn reserve_snapshot(&self) -> Result<u128, String> {
        let result = self.rpc(
            "eth_getBalance",
            serde_json::json!([
                format!("0x{}", hex::encode(self.bridge)),
                "latest"
            ]),
        )?;
        let wei_hex = result
            .as_str()
            .ok_or_else(|| "eth_getBalance: unexpected response".to_string())?;
        // EVM quantity 会剥前导零（奇数长度），hex::decode 只吃偶数位——左补零。
        let digits = wei_hex.trim_start_matches("0x");
        let digits = if digits.len() % 2 == 1 {
            format!("0{digits}")
        } else {
            digits.to_string()
        };
        let bytes = hex::decode(&digits).map_err(|e| format!("eth_getBalance hex: {e}"))?;
        Ok(u128_from_be(&bytes))
    }

    fn pay_withdrawal(
        &self,
        _payout_address: &[u8; 32],
        _amount: u64,
        _request_id: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        // 买入闭环（本片）不覆盖出金：显式失败，不静默 mock——待 EVM txmgr
        // 接线后实现（需要运营方 EVM 签名与 nonce 管理）。
        Err("monad pay_withdrawal not wired yet (deposit-only slice)".to_string())
    }
}

// ===== 买入存证核验（SIT_DOWN_V2 携带 EVM tx hash 时） =====

/// 解码后的买入存证。
struct DepositProof {
    to: [u8; 20],
    amount: u128,
}

/// `eth_getTransactionReceipt` → 交易成功 + 找到本 bridge 的
/// DepositInitiated 日志。REVERTED 即拒。
async fn fetch_deposit_proof(
    provider: &MonadVaultProvider,
    tx_hash: &str,
) -> Result<DepositProof, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash]
    });
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    // 回执未上链时轮询（anvil 即时；公网有 ~1s 延迟），30s 上限——
    // 与 Starknet 路径同一验收口径（钱包返回哈希 ≠ 上链确认）。
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let v: serde_json::Value = http
            .post(&provider.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("receipt http: {e}"))?
            .json()
            .await
            .map_err(|e| format!("receipt json: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(format!("receipt rpc: {err}"));
        }
        let result = &v["result"];
        if !result.is_null() {
            let status = result["status"].as_str().unwrap_or_default();
            if status != "0x1" {
                return Err(format!("monad deposit tx {tx_hash} status={status} (not success)"));
            }
            // 地址/topic 比较统一到字节/小写（anvil 回执地址是 EIP-55 大小写）。
            let bridge20 = provider.bridge_for_log();
            let topic0 = format!("0x{}", hex::encode(deposit_topic0()));
            if let Some(logs) = result["logs"].as_array() {
                for log in logs {
                    let addr_ok = log["address"]
                        .as_str()
                        .and_then(parse_address)
                        .is_some_and(|a| a == bridge20);
                    let topic_ok = log["topics"]
                        .as_array()
                        .and_then(|t| t.first())
                        .and_then(|t| t.as_str())
                        .is_some_and(|t| t.eq_ignore_ascii_case(&topic0));
                    if !addr_ok || !topic_ok {
                        continue;
                    }
                    // decode_log 复用（provider 已持有 bridge/topic 校验）。
                    if let Some(ev) = provider.decode_log(log) {
                        let mut to = [0u8; 20];
                        to.copy_from_slice(&ev.owner[12..]);
                        let data = log["data"].as_str().unwrap_or("0x0");
                        let amount = hex::decode(data.trim_start_matches("0x"))
                            .map(|d| u128_from_be(&d))
                            .unwrap_or(0);
                        return Ok(DepositProof { to, amount });
                    }
                }
            }
            return Err(format!(
                "monad deposit tx {tx_hash} has no L1Bridge DepositInitiated event"
            ));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("monad deposit tx {tx_hash} not confirmed within 30s"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
}

/// SIT_DOWN_V2 存证核验 + 即时铸 note：
/// 1. 回执成功且 DepositInitiated.to == 玩家钱包、
///    `已可用余额 + 存款面额 ≥ chips×WEI_PER_CHIP`（客户端只补差额上链，
///    已有 note 余额的部分不重复锁仓）；
/// 2. 直接推一轮存款桥（process_deposits_once 同步提交 Deposit op），
///    不等 200ms 桥循环——入座前的余额读数即含新铸 note。
///
/// 仅在 `TEXAS_APPCHAIN_PROVIDER=monad` 时由入座校验调用（Starknet 哈希
/// 与 zchain-buyin: 前缀哈希都不进这里）。
pub async fn verify_deposit_and_mint(
    tx_hash: &str,
    buyer: &str,
    chips: i64,
    already_available_chips: i64,
) -> Result<(), String> {
    let provider = MonadVaultProvider::from_env()?;
    let proof = fetch_deposit_proof(&provider, tx_hash).await?;
    let buyer20 = parse_address(buyer)
        .ok_or_else(|| format!("buyer address invalid: {buyer}"))?;
    if proof.to != buyer20 {
        return Err(format!(
            "monad deposit recipient {} != buyer {}",
            hex::encode(proof.to),
            hex::encode(buyer20)
        ));
    }
    let required = (chips.max(0) as u128)
        .checked_mul(crate::starknet::config::WEI_PER_CHIP)
        .ok_or("chip amount overflow")?;
    let covered = (already_available_chips.max(0) as u128)
        .saturating_mul(crate::starknet::config::WEI_PER_CHIP)
        .saturating_add(proof.amount);
    if covered < required {
        return Err(format!(
            "monad deposit {} wei + available balance < required {} wei",
            proof.amount, required
        ));
    }
    // 即时铸 note（同步；幂等由 deposit_id 兜底——桥循环重放无害）。
    let rt = super::runtime::runtime()
        .ok_or_else(|| "appchain runtime not enabled".to_string())?;
    super::bridge::process_deposits_once(rt)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_and_address_parsing() {
        // 主题锚定 cast keccak "DepositInitiated(uint256,address,address,uint256)"
        // （2026-10-06 anvil 实链事件核对值）。
        assert_eq!(
            hex::encode(deposit_topic0()),
            "7142c1446622b71fb14ba6808d8d08a5973a86e4433f33546e133c1d6cfa86bc"
        );
        // 主题是 keccak256 签名哈希（前缀已知值自校验长度与确定性）。
        let t = deposit_topic0();
        assert_eq!(t, deposit_topic0());
        assert_eq!(t.len(), 32);
        assert_eq!(
            parse_address("0x8626f6940e2eb28930efb4cef49b2d1f2c9c1199"),
            Some([
                0x86, 0x26, 0xf6, 0x94, 0x0e, 0x2e, 0xb2, 0x89, 0x30, 0xef, 0xb4, 0xce, 0xf4, 0x9b,
                0x2d, 0x1f, 0x2c, 0x9c, 0x11, 0x99
            ])
        );
        assert_eq!(parse_address("0x123"), None);
        assert_eq!(parse_address("nothex"), None);
    }

    #[test]
    fn u128_saturation() {
        assert_eq!(u128_from_be(&[1u8]), 1);
        assert_eq!(u128_from_be(&[0xffu8; 32]), u128::MAX);
        assert_eq!(
            u128_from_be(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            u128::MAX
        );
    }

    #[test]
    fn decode_anvil_deposit_log() {
        // 2026-10-06 anvil 实链事件（地址 EIP-55 大小写、紧凑 quantity）。
        let provider = MonadVaultProvider {
            rpc_url: "http://127.0.0.1:8545".into(),
            bridge: parse_address("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap(),
            from_block: 0,
            source_chain: 0,
            http: reqwest::Client::new(),
        };
        let log: serde_json::Value = serde_json::json!({
            "address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
            "topics": [
                "0x7142c1446622b71fb14ba6808d8d08a5973a86e4433f33546e133c1d6cfa86bc",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
            ],
            "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
            "blockNumber": "0x2",
            "transactionHash": "0x96f3a1f6d73b7949c29af265b4f7a7ae168a06fad97a12d3d1b108b4f5fbd223",
            "logIndex": "0x0"
        });
        let ev = provider.decode_log(&log).expect("decode anvil deposit log");
        assert_eq!(ev.amount, 1_000_000_000_000_000_000);
        assert_eq!(&ev.owner[12..], &parse_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap()[..]);
        assert_eq!(ev.seq, 2);
    }
}
