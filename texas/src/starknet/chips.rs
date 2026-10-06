//! STRK20 / PokerVault 链上查询与买入校验。
//!
//! 买入流程（前端 → 服务端）：
//! 1. 公开路径：前端钱包执行 `STRK20.approve(vault, amount)` + `PokerVault.deposit(amount)`
//! 2. 私密路径（方案 B）：STRK20 隐私池私密交易内由 PokerVaultAnonymizer 执行
//!    `vault.deposit_for(player, amount)` —— 链上看不到付款人，只有匿名izer 给
//!    玩家记账的公开动作；此时前端没有玩家钱包签名的 deposit 交易
//! 3. 前端把 deposit 交易哈希（depositTxHash，可为空）随 SIT_DOWN_V2 提交
//! 4. 服务端 [`verify_deposit`]：非空哈希时拉取交易回执要求 SUCCEEDED，且
//!    （配置了 vault 时）校验 `vault.chip_balance(buyer) >= chips * WEI_PER_CHIP` ——
//!    空哈希（私密买入）时以 chip_balance 为权威校验
//!
//! dev 模式（未配置 RPC）跳过校验直接放行，保持离线可玩。

use starknet::core::types::Felt;

use super::chain::{parse_felt, selector};
use super::config::WEI_PER_CHIP;

/// 查询 PokerVault 中玩家的筹码余额（wei）。未配置 vault 返回 None。
pub async fn vault_chip_balance_wei(address: &str) -> Option<u128> {
    let chain = super::chain()?;
    let vault = parse_felt(&chain.config.vault_address)?;
    let player = parse_felt(address)?;
    let res = chain
        .call_contract(vault, selector("chip_balance"), vec![player])
        .await
        .ok()?;
    Some(u256_from_felts(&res))
}

/// 校验买入交易：回执成功（非私密买入）+ vault 筹码余额覆盖买入数量。
///
/// * `deposit_tx_hash` — 前端钱包 deposit 交易哈希（0x hex）；私密买入（方案 B）
///   时可为空 —— 此时跳过回执检查，以 vault chip_balance 为权威校验
/// * `buyer`           — 玩家钱包地址
/// * `chips`           — 买入筹码数（1 chip = WEI_PER_CHIP wei）
///
/// 返回 Ok(()) 表示校验通过（或 dev 模式放行）。
pub async fn verify_deposit(
    deposit_tx_hash: &str,
    buyer: &str,
    chips: i64,
) -> Result<(), String> {
    let Some(chain) = super::chain() else {
        tracing::debug!("[starknet-chips] chain not initialized, skipping deposit check");
        return Ok(());
    };
    if !chain.config.rpc_enabled() {
        tracing::debug!("[starknet-chips] dev mode: skipping deposit verification");
        return Ok(());
    }

    // 私密买入：没有玩家签名的 deposit 交易可查，筹码余额检查即权威证明
    //（匿名izer 在隐私池私密交易内已把 STRK 付给 vault 并给玩家记账）。
    if deposit_tx_hash.is_empty() {
        tracing::info!("[starknet-chips] empty deposit tx hash (private buy-in); relying on chip_balance check");
        return verify_chip_coverage(buyer, chips).await;
    }

    // 规避共享 provider 单例挂起：为本次校验新建独立 client
    let _url = url::Url::parse(&chain.config.rpc_url)
        .unwrap_or_else(|_| url::Url::parse("http://127.0.0.1:5051").unwrap());
    let tx_hash = parse_felt(deposit_tx_hash)
        .ok_or_else(|| format!("invalid deposit tx hash: {deposit_tx_hash}"))?;
    // starknet-rs 的 get_transaction_receipt 在 devnet 场景下挂起，
    // 改用手写 JSON-RPC POST（reqwest）。
    let receipt_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "starknet_getTransactionReceipt",
        "params": {"transaction_hash": format!("{tx_hash:#x}")}
    });
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    // #验收修复：钱包返回哈希 ≠ 上链确认。轮询回执直到 SUCCEEDED /
    // REVERTED / 超时（30s），网络层失败按指数间隔重试——避免"提交后
    // 立刻下坐"被 latest 态误拒。
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut attempt: u64 = 0;
    let mut last_err = String::new();
    let status;
    loop {
        attempt += 1;
        let res = http.post(&chain.config.rpc_url).json(&receipt_body).send().await;
        let parsed = match res {
            Ok(resp) => match resp.text().await {
                Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        last_err = format!("receipt json: {e}");
                        None
                    }
                },
                Err(e) => {
                    last_err = format!("receipt text: {e}");
                    None
                }
            },
            Err(e) => {
                last_err = format!("receipt http: {e}");
                None
            }
        };
        if let Some(rj) = parsed {
            match rj["result"]["execution_status"].as_str() {
                Some("SUCCEEDED") => {
                    eprintln!("[verify_deposit] receipt SUCCEEDED after {attempt} poll(s)");
                    status = "SUCCEEDED".to_string();
                    break;
                }
                Some(other) if other.contains("REVERTED") => {
                    return Err(format!("deposit tx {deposit_tx_hash} reverted"));
                }
                other => {
                    // RECEIVED / NOT_RECEIVED / 无字段 = 仍待确认
                    last_err = format!(
                        "pending (status={:?})",
                        other
                    );
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "deposit not confirmed within 30s: {last_err}"
            ));
        }
        eprintln!("[verify_deposit] poll {attempt}: not confirmed yet ({})…", last_err);
        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
    }
    eprintln!("[verify_deposit] receipt status={status}");

    // 2. 未配置 vault → 只要求回执成功（devnet 部署可能没有 vault）。
    // 3. vault 筹码余额必须覆盖买入数量。
    verify_chip_coverage(buyer, chips).await
}

/// vault 筹码余额权威校验：余额必须覆盖买入数量（未配置 vault 时放行）。
async fn verify_chip_coverage(buyer: &str, chips: i64) -> Result<(), String> {
    let Some(chain) = super::chain() else {
        return Ok(());
    };
    if chain.config.vault_address.is_empty() {
        tracing::info!(
            "[starknet-chips] vault not configured; deposit verified by receipt only"
        );
        return Ok(());
    }

    let required = (chips.max(0) as u128)
        .checked_mul(WEI_PER_CHIP)
        .ok_or("chip amount overflow")?;
    eprintln!("[verify_deposit] step3: querying chip_balance");
    let balance = vault_chip_balance_wei(buyer)
        .await
        .ok_or("failed to query vault chip_balance")?;
    eprintln!("[verify_deposit] step4: balance={balance}");
    if balance < required {
        return Err(format!(
            "vault chip balance {} wei < required {} wei",
            balance, required
        ));
    }
    Ok(())
}

/// [low, high] felts → u128。high 非零或 low 超 2^128 时饱和为 u128::MAX
/// （筹码/STRK 数量级远小于 2^128，饱和只会在异常场景出现，方向安全：
/// 余额校验按"余额足够"放行的风险由回执校验兜底）。
fn u256_from_felts(felts: &[Felt]) -> u128 {
    let low = felts.first().copied().unwrap_or_default();
    let high = felts.get(1).copied().unwrap_or_default();
    if high != Felt::ZERO {
        return u128::MAX;
    }
    let bytes = low.to_bytes_be();
    if bytes[..16].iter().any(|&b| b != 0) {
        return u128::MAX;
    }
    u128::from_be_bytes(bytes[16..].try_into().expect("16 bytes"))
}
