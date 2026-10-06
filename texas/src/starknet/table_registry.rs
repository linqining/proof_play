//! PokerTableRegistry 链上桌台注册（"关桌后不开新手"的锚定层）。
//!
//! 职责（设计讨论定稿 2026-09-11）：
//! - 建桌：`create_table(params_hash)` 拿**合约分配**的 table_id（唯一不
//!   依赖服务端诚信的 id 唯一性来源），`params_hash` 一次性钉死规则承诺；
//! - 关桌：`close_table(id)` 写链（终态，只追加生命周期）；
//! - 读回：`is_open(id)` 供开局前的可验证状态检查。
//!
//! 语义边界（诚实清单）：
//! - 注册表**不碰钱**（资金在 vault），不进任何证明约束（poker_l1 AIR 零
//!   改动）——它是绊线与审计轨迹，不是缰绳：恶意宿主自报 table_id 可绕过
//!   链上检查，真正的防线是客户端"只在 Open 桌上玩" + mental poker 需要
//!   在座玩家密码学配合才能开局 + vault TTL 兜底；
//! - 全部接口**尽力而为**（best-effort）：链不可用/交易失败只告警不阻塞
//!   牌局——注册表是锚定增强，不是资金安全的依赖（资金安全由 vault 锁 +
//!   `unlock_after_deadline` 保证）。

use starknet::accounts::Account;
use starknet::core::types::Call;
use starknet_crypto::Felt;

use super::chain::{parse_felt, selector};

/// 桌台规则承诺：`poseidon_hash_many([max_players, small_blind, big_blind])`。
///
/// 字段顺序即跨端契约：Cairo 侧（将来客户端/第三方复验）必须按同一顺序
/// 重算。只存承诺不存明文——注册表不泄漏盲注等桌台元数据（隐私边界与
/// README "What's private" 一致）。
#[must_use]
pub fn compute_params_hash(max_players: u32, small_blind: u64, big_blind: u64) -> Felt {
    starknet_crypto::poseidon_hash_many(&[
        Felt::from(max_players),
        Felt::from(small_blind),
        Felt::from(big_blind),
    ])
}

fn registry_address() -> Result<Felt, String> {
    let addr = &super::chain()
        .ok_or("starknet chain not initialized")?
        .config
        .table_registry_address;
    if addr.is_empty() {
        return Err("table registry not configured".into());
    }
    parse_felt(addr).ok_or_else(|| format!("table registry address invalid: {addr}"))
}

/// 建桌登记：返回合约分配的全局唯一 table_id（从 1 递增；0 = 失败）。
///
/// id 推导：invoke 前读 `table_count`（= count_before），id = count_before + 1。
/// 前提是"无并发建桌"——建桌只发生在启动引导与管理端单线程路径，成立。
/// 尽力而为：未配置/链不可用/交易失败返回 `None` 并告警，桌台仍按纯
/// 链下模式运行（`registry_table_id` 留空即成对不可用的诚实标记）。
pub async fn register_table(max_players: u32, small_blind: u64, big_blind: u64) -> Option<u64> {
    if !super::chain().is_some_and(|c| c.config.table_registry_enabled() && c.config.rpc_enabled())
    {
        return None;
    }
    let count_before = read_table_count().await?;
    let new_id = count_before.checked_add(1)?;
    let params_hash = compute_params_hash(max_players, small_blind, big_blind);
    match invoke_registry("create_table", vec![params_hash]).await {
        Ok(tx_hash) => {
            tracing::info!(
                "[table-registry] create_table tx={:#x} params_hash={:#x} → id {new_id}",
                tx_hash,
                params_hash
            );
            // 登记后读回核验（对齐部署工具的 read-back 惯例）：交易从提交到
            // accepted 有几秒延迟，轮询三次；读回失败只告警——id 推导基于
            // 计数器，不依赖本检查。
            for attempt in 1..=3 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                match is_open(new_id).await {
                    Some(true) => {
                        tracing::info!("[table-registry] read-back ok: id {new_id} is Open on-chain");
                        break;
                    }
                    other => {
                        tracing::warn!(
                            "[table-registry] read-back attempt {attempt}/3: id {new_id} state {other:?}"
                        );
                    }
                }
            }
            Some(new_id)
        }
        Err(e) => {
            tracing::warn!("[table-registry] create_table failed: {e} — running without on-chain anchor");
            None
        }
    }
}

/// 关桌写链（终态）。尽力而为：失败只告警——本地 closed 标志已经
/// 阻止开局，链上写失败只是丢了锚点。
pub async fn close_table(registry_table_id: u64) {
    if registry_table_id == 0 {
        return;
    }
    if let Err(e) = invoke_registry("close_table", vec![Felt::from(registry_table_id)]).await {
        tracing::warn!("[table-registry] close_table({registry_table_id}) failed: {e}");
    }
}

/// 链上桌台是否 Open。`None` = 无法判定（未配置/链不可用）——调用方
/// 不得把 None 当作 Open 使用（fail-closed 读回）。
pub async fn is_open(registry_table_id: u64) -> Option<bool> {
    if registry_table_id == 0 {
        return None;
    }
    let chain = super::chain()?;
    let address = registry_address().ok()?;
    let res = chain
        .call_contract(address, selector("is_open"), vec![Felt::from(registry_table_id)])
        .await
        .ok()?;
    res.first().map(|f| *f == Felt::ONE)
}

async fn read_table_count() -> Option<u64> {
    let chain = super::chain()?;
    let address = registry_address().ok()?;
    let res = chain
        .call_contract(address, selector("table_count"), vec![])
        .await
        .ok()?;
    let felt = *res.first()?;
    let bytes = felt.to_bytes_be();
    if bytes[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let arr: [u8; 8] = bytes[24..].try_into().ok()?;
    Some(u64::from_be_bytes(arr))
}

/// 注册表 owner-gated 调用统一入口（复用 vault 的 operator 账户与
/// nonce 竞争重试模式；注册表不碰钱，operator 只需有权 close）。
async fn invoke_registry(fn_name: &str, calldata: Vec<Felt>) -> Result<Felt, String> {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        match invoke_registry_once(fn_name, &calldata).await {
            Ok(tx) => return Ok(tx),
            Err(e) => {
                last_err = e.clone();
                if super::lock::is_nonce_race(&e) && attempt < MAX_ATTEMPTS {
                    tracing::warn!(
                        "[table-registry] {fn_name} nonce race (attempt {attempt}/{MAX_ATTEMPTS}) — retrying"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last_err)
}

async fn invoke_registry_once(fn_name: &str, calldata: &[Felt]) -> Result<Felt, String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let address = registry_address()?;
    let operator = chain.operator().await.ok_or("operator account unavailable")?;
    let call = Call {
        to: address,
        selector: selector(fn_name),
        calldata: calldata.to_vec(),
    };
    let res = operator
        .execute_v3(vec![call])
        .send()
        .await
        .map_err(|e| format!("invoke {fn_name}: {e:?}"))?;
    Ok(res.transaction_hash)
}

#[cfg(test)]
mod tests {
    use super::compute_params_hash;
    use starknet_crypto::Felt;

    /// 跨端契约：字段顺序 [max_players, small_blind, big_blind] 一旦上链
    /// 即冻结。此向量锁定 poseidon_hash_many 的具体值，Cairo/客户端复验
    /// 端实现后以此对拍。
    #[test]
    fn params_hash_field_order_is_the_cross_end_contract() {
        let h = compute_params_hash(9, 100, 200);
        let expected = starknet_crypto::poseidon_hash_many(&[
            Felt::from(9_u32),
            Felt::from(100_u64),
            Felt::from(200_u64),
        ]);
        assert_eq!(h, expected, "field order must stay [max, sb, bb]");
        // 不同字段不同 hash（避免字段错位碰撞）
        assert_ne!(h, compute_params_hash(8, 100, 200));
        assert_ne!(h, compute_params_hash(9, 200, 100));
        assert_ne!(h, compute_params_hash(9, 100, 201));
    }
}
