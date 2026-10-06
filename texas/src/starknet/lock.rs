//! #33 在局锁定（vault v3）服务端接线。
//!
//! 资金安全模型（docs/TODO.md #33）：玩家入座即由 operator 把本手买入
//! 锁进 `vault.lock`（只可花未锁定余额）；每手结算成功后续 session 时钟
//! （`refresh_session`）；离桌后不自动解锁——玩家可在 TTL（默认 12h）后
//! 无许可 `unlock_after_deadline`，operator 保留 `force_unlock` 应急。
//!
//! 设计原则：锁定/续钟失败只告警不阻塞牌局（链下照打，链上锁定尽力而为）；
//! 所有调用都是 operator 签名的独立交易，与结算提交共用 nonce 管线
//! （operator 账户 block_id = PreConfirmed）。

use starknet::accounts::Account;
use starknet::core::types::{Call, Felt};

use super::chain::{parse_felt, selector};

fn vault_address() -> Result<Felt, String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let addr = chain.config.vault_address.clone();
    if addr.is_empty() {
        return Err("vault address not configured".into());
    }
    parse_felt(&addr).ok_or_else(|| format!("vault address invalid: {addr}"))
}

/// 玩家入座成功后锁定买入筹码（owner-gated）。异步尽力而为：
/// 失败仅告警——锁定缺失的代价是 #33 逃单窗口重新打开，日志必须显眼。
pub async fn lock_player_chips(player_address: &str, chips: i64) {
    if chips <= 0 {
        return;
    }
    let Some(wei) = (chips as i128)
        .checked_mul(super::config::WEI_PER_CHIP as i128)
        .and_then(|w| u128::try_from(w).ok())
    else {
        tracing::error!("[in-hand-lock] lock amount overflow for {player_address}: {chips} chips");
        return;
    };
    let (lo, hi) = wei_to_u256_felts(wei);
    match invoke_vault(player_address, "lock", vec![lo, hi]).await {
        Ok(tx) => tracing::info!("[in-hand-lock] locked {chips} chips for {player_address}, tx={tx:#x}"),
        Err(e) => tracing::error!(
            "[in-hand-lock] LOCK FAILED for {player_address} ({chips} chips): {e} — 逃单窗口未关闭，需人工 vault.lock 补锁"
        ),
    }
}

/// 每手结算成功后续各参与者的 session 时钟（owner-gated）。
/// 从未锁定的玩家（历史买入）会因 "No active session" 失败——仅告警。
/// nonce 竞争重试统一在 invoke_vault 内处理。
pub async fn refresh_player_session(player_address: &str) {
    match invoke_vault(player_address, "refresh_session", vec![]).await {
        Ok(tx) => tracing::debug!("[in-hand-lock] session refreshed for {player_address}, tx={tx:#x}"),
        Err(e) => tracing::warn!("[in-hand-lock] session refresh failed for {player_address}: {e}"),
    }
}

// ===== #33 离桌快解锁 + 结算原子锁账（2026-09-07 逃单窗口修复）=====
//
// 漏洞（用户复现报告）：apply_settlement 正向 delta 只加 chip 不加锁，
// 赢额从结算落地起永远可提（withdraw 只断言 spendable = chips - locked），
// 而服务端 stack 仍可全押它——输家把差额提走后，下一手结算的
// "Insufficient chip balance" 断言必失败，且结算是一整手打包一笔交易，
// 一个逃单者让全手（含赢家）结算 revert。
//
// 修正模型（operator = vault owner = 结算提交者，零合约改动）：
// - 在座：结算单笔 invoke 原子串起 register → settle → 赢额回锁 lock()
//   → 续钟 refresh_session()——同交易按序执行、整体回滚，不存在
//   "结算落地→回锁落地"的异步窗口。
// - 离桌：牌局进行中离开 → 挂起，随最后一手的结算交易同笔 force_unlock；
//   牌局未进行时离开 → 已结算即立即单独 force_unlock。

/// 离桌快解锁的挂起登记：wallet → 该玩家最后一手 hand_id。
/// 手牌进行中离桌的玩家等那手结算成功后由 [`flush_leave_releases`] 释放。
fn pending_leave_releases() -> &'static std::sync::Mutex<std::collections::HashMap<String, u32>> {
    static S: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, u32>>> =
        std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 结算提交前取回"最后一手 = 本手"的挂起离桌玩家（随结算同笔释放）。
/// 精确匹配（==）——更晚结算的其他手不代表该玩家的手已结算。
pub fn take_pending_releases_for(hand_id: u32) -> Vec<String> {
    pending_leave_releases()
        .lock()
        .map(|mut g| {
            let due: Vec<String> = g
                .iter()
                .filter(|(_, h)| **h == hand_id)
                .map(|(w, _)| w.clone())
                .collect();
            for w in &due {
                g.remove(w);
            }
            due
        })
        .unwrap_or_default()
}

/// 结算提交失败时归还挂起条目（下次该手重试随结算再释放）。
pub fn restore_pending_releases(entries: Vec<String>, hand_id: u32) {
    pending_leave_releases()
        .lock()
        .map(|mut g| {
            for w in entries {
                g.insert(w, hand_id);
            }
        })
        .ok();
}

/// 结算成功后的兜底释放：bundle 构建时取走的名单可能漏掉"结算流程
/// 启动后才注册离桌"的玩家（2026-09-07 线上：挂起写入比 take_pending
/// 晚 0.1s → departed-released=0 → 释放滞留）。此刻"该手已结算 + 玩家
/// 已离桌"两条件与注册时序无关地成立，补放同样安全。
pub async fn flush_leave_releases(settled_hand_id: u32) {
    let due = take_pending_releases_for(settled_hand_id);
    for wallet in due {
        release_player_lock(&wallet).await;
    }
}

/// 手牌中止（refund_all_bets：摊牌物化失败 / reveal 超时 / 重建失败 /
/// 洗牌失败，全员退款、无链上结算）时释放该手的挂起离桌玩家——
/// 中止手永远不会有 settle 来触发释放，不在此处理就会滞留到 TTL。
/// 游戏层同步代码调用：spawn 出去执行链上操作，无 runtime 时告警
/// 留给 TTL 兜底。
pub fn abort_flush_leave_releases(hand_id: u32) {
    let due = take_pending_releases_for(hand_id);
    if due.is_empty() {
        return;
    }
    tracing::info!(
        "[in-hand-lock] hand {hand_id} aborted — releasing {} pending leave players",
        due.len()
    );
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                for wallet in due {
                    release_player_lock(&wallet).await;
                }
            });
        }
        Err(_) => tracing::warn!(
            "[in-hand-lock] no tokio runtime at abort — {hand_id} leave releases deferred to TTL"
        ),
    }
}

/// 结算构建永久失败（一次性、无重试）的手。此后挂到这些手上的离桌
/// 释放不能等结算——注册时直接释放。兜底 abort_flush 与 leave 注册
/// 的时序竞态：flush 先于注册到达时条目滞留到 TTL（2026-09-08
/// hand 1788804610：flush 先于注册 1s → 双钱包滞留）。
fn failed_hands() -> &'static std::sync::Mutex<std::collections::HashSet<u32>> {
    static S: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u32>>> =
        std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

pub fn mark_hand_settlement_failed(hand_id: u32) {
    failed_hands()
        .lock()
        .map(|mut g| {
            // 手牌 id 单调递增；上限防无限增长（清空的只会是久远旧手，
            // 其挂起释放早已被 TTL 兜底）。
            if g.len() > 4096 {
                g.clear();
            }
            g.insert(hand_id);
        })
        .ok();
}

pub fn hand_settlement_failed(hand_id: u32) -> bool {
    failed_hands()
        .lock()
        .map(|g| g.contains(&hand_id))
        .unwrap_or(false)
}

/// 离桌时排程释放。`hand_settled` = 该玩家最后一手是否已结算成功
/// （hooks::settle_ok_already）：是则立即释放，否则挂起等那手 settle
/// （随该手的结算交易同笔原子释放，见 dual_settle 的线性编排）。
pub async fn schedule_leave_release(wallet: &str, last_hand_id: u32, hand_settled: bool) {
    let wallet = normalize_wallet(wallet);
    if hand_settled || hand_settlement_failed(last_hand_id) {
        release_player_lock(&wallet).await;
    } else {
        pending_leave_releases()
            .lock()
            .map(|mut g| g.insert(wallet.clone(), last_hand_id))
            .ok();
        tracing::info!(
            "[in-hand-lock] leave release pending for {wallet} after hand {last_hand_id} settles"
        );
    }
}

/// 全量释放玩家锁（force_unlock）：仅在"已离桌且最后一手已结算"或
/// "桌台关闭、在座玩家集体离场"时调用。
pub(crate) async fn release_player_lock(wallet: &str) {
    let Some(chain) = super::chain() else { return };
    let vault = match vault_address() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("[in-hand-lock] leave release skipped for {wallet}: {e}");
            return;
        }
    };
    // 链上实际锁定量为准（服务端不追踪，重启/多进程都不影响正确性）。
    let player = match parse_felt(wallet) {
        Some(f) => f,
        None => {
            tracing::warn!("[in-hand-lock] leave release skipped: invalid wallet {wallet}");
            return;
        }
    };
    let locked_wei = match chain
        .call_contract(vault, selector("locked_balance"), vec![player])
        .await
    {
        Ok(felts) => {
            let lo = felts
                .first()
                .and_then(|f| <[u8; 16]>::try_from(&f.to_bytes_be()[16..32]).ok())
                .map(u128::from_be_bytes)
                .unwrap_or(0);
            // u256 hi 段在真实量级下恒为 0；非 0 时按饱和处理告警放弃。
            let hi_nonzero = felts.get(1).map(|f| *f != Felt::ZERO).unwrap_or(false);
            if hi_nonzero {
                tracing::warn!("[in-hand-lock] leave release skipped for {wallet}: locked u256 high limb non-zero");
                return;
            }
            lo
        }
        Err(e) => {
            tracing::warn!("[in-hand-lock] leave release read failed for {wallet}: {e:?}");
            return;
        }
    };
    if locked_wei == 0 {
        tracing::debug!("[in-hand-lock] leave release: {wallet} already unlocked");
        return;
    }
    match invoke_vault(wallet, "force_unlock", vec![]).await {
        Ok(tx) => tracing::info!(
            "[in-hand-lock] leave release: unlocked {:.4} STRK for {wallet}, tx={tx:#x}",
            locked_wei as f64 / 1e18
        ),
        Err(e) => tracing::error!(
            "[in-hand-lock] LEAVE RELEASE FAILED for {wallet} ({:.4} STRK): {e} — 玩家可等 TTL 自助解锁",
            locked_wei as f64 / 1e18
        ),
    }
}

fn normalize_wallet(w: &str) -> String {
    w.trim().trim_start_matches("wallet:").to_lowercase()
}

/// 钱包 felt → `0x` 前缀全 64 位 hex（hooks / dual_settle 的结算参与者键）。
pub(crate) fn wallet_of_felt(p: &starknet_crypto::Felt) -> String {
    format!("0x{}", super::chain::hex_encode(&p.to_bytes_be()))
}

/// 玩家是否有活跃在局 session（view；结算编排用它过滤续钟调用，
/// 避免对无 session 玩家的 refresh_session 断言 revert 拖垮整笔原子交易）。
pub async fn vault_session_active(wallet: &str) -> bool {
    let Some(chain) = super::chain() else { return false };
    let Ok(vault) = vault_address() else { return false };
    let Some(player) = parse_felt(wallet) else { return false };
    chain
        .call_contract(
            vault,
            selector("session_active"),
            vec![player],
        )
        .await
        .ok()
        .and_then(|felts| felts.first().cloned())
        .map(|f| f == Felt::ONE)
        .unwrap_or(false)
}

/// P1-2 会话委托：查钱包在 vault 上当前**有效**登记的会话交易公钥
/// （`active_session_tx_pk`；未登记/已过期 = None）。
///
/// join 接受点用它核验"客户端声明的会话钥 == 链上登记钥"——登记在
/// 买入时完成（非私密路径玩家 multicall `set_session_tx_pk`；STRK20
/// 私密路径 anonymizer 同笔私交易 `set_session_tx_pk_for`）。view 调用
/// 零链上足迹（重连不产生任何交易）。
pub async fn vault_active_session_tx_pk(wallet: &str) -> Option<[u8; 32]> {
    let chain = super::chain()?;
    let vault = vault_address().ok()?;
    let player = parse_felt(wallet)?;
    let felts = chain
        .call_contract(vault, selector("active_session_tx_pk"), vec![player])
        .await
        .ok()?;
    let pk = felts.first()?;
    let bytes = pk.to_bytes_be();
    if bytes.iter().all(|&b| b == 0) {
        return None; // 未登记
    }
    Some(bytes)
}

/// P1-2 会话委托核验（join 接受点）：客户端声明的会话交易公钥（32B 压缩
/// 点 hex）与链上 vault 登记逐字节一致 → `Some(bytes)`（随 join 缓冲进入
/// 座位状态，成为该座 VM 层交易签名验证锚）；未声明 / 格式错 / 链上未
/// 登记 / 不一致 → `None`（该参与者签名路径未激活——过渡期仅告警，
/// TableRuntime 接线后对 None fail-closed）。
/// P1-2 会话委托门的事件计数（监控/告警接线用；测试断言同源）。
/// `mismatches` 是**攻击信号**（有人以该钱包名义声明了错误的钥），
/// `unregistered` 是旧客户端/未登记的正常过渡态。
pub static SESSION_TX_PK_MISMATCHES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub static SESSION_TX_PK_UNREGISTERED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub async fn verify_session_tx_pk(wallet: &str, declared_hex: Option<&str>) -> Option<Vec<u8>> {
    use std::sync::atomic::Ordering::Relaxed;
    let declared = declared_hex?.trim();
    if declared.is_empty() {
        return None;
    }
    let body = declared.strip_prefix("0x").unwrap_or(declared);
    let bytes = match hex::decode(body) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            SESSION_TX_PK_MISMATCHES.fetch_add(1, Relaxed);
            tracing::warn!(
                target: "session_tx_pk_mismatch",
                "[session-tx-pk] ATTACK SIGNAL: {wallet} 声明的会话公钥格式非法（期望 32B hex）— 计数 {}",
                SESSION_TX_PK_MISMATCHES.load(Relaxed)
            );
            return None;
        }
    };
    match vault_active_session_tx_pk(wallet).await {
        Some(mut onchain) => {
            // 编码说明：stark_curve compress() = x 坐标 + byte[0] 高位 0x80
            // y 奇偶标志。标志位会让数值越出 felt252（见 poker_vault
            // set_session_tx_pk 的 felt 入参），所以链上登记存的是 x-only，
            // 而声明值（客户端 compress 全形式）带标志——对拍按 x-only
            // 掩码比较；通过后返回**声明原值**作为座位 VM 签名锚
            // （stark_scheme::verify 的 from_compressed 需要奇偶标志）。
            onchain[0] &= 0x7f;
            let mut declared_x = bytes.clone();
            declared_x[0] &= 0x7f;
            if onchain.as_slice() == declared_x.as_slice() {
                // 成功路径刻意留痕：绑定是否生效此前只能靠链上 view 反查
                // （2026-09-11 审核结论），info 级一行让日志可直接核实。
                tracing::info!(
                    target: "session_tx_pk",
                    "[session-tx-pk] {wallet} session key verified & registered (pk=0x{}…) — join 携带 VM 签名锚",
                    hex::encode(&bytes[..8])
                );
                Some(bytes)
            } else {
                SESSION_TX_PK_MISMATCHES.fetch_add(1, Relaxed);
                tracing::warn!(
                    target: "session_tx_pk_mismatch",
                    "[session-tx-pk] ATTACK SIGNAL: {wallet} 声明 {}.. 与链上登记 {}.. 不一致 — 拒绝登记，计数 {}",
                    &declared[..8.min(declared.len())],
                    hex::encode(&onchain[..4]),
                    SESSION_TX_PK_MISMATCHES.load(Relaxed)
                );
                None
            }
        }
        None => {
            SESSION_TX_PK_UNREGISTERED.fetch_add(1, Relaxed);
            tracing::debug!(
                target: "session_tx_pk_unregistered",
                "[session-tx-pk] {wallet} 链上未登记会话公钥（旧客户端/未买入登记）— 计数 {}",
                SESSION_TX_PK_UNREGISTERED.load(Relaxed)
            );
            None
        }
    }
}

/// operator 账户 nonce 竞态判定（结算 bundle / vault 调用共用）：
/// 相邻两手结算或结算与释放并发时，后一笔按旧 nonce 构建会被内存池
/// 拒绝——可退避重试（重发会按链上最新 nonce 重建）。注意执行期错误
/// 文本是 "Invalid transaction nonce"（TransactionExecutionError），
/// 提交期才是 "NonceTooOld"/"DuplicateNonce"——两者都要匹配
/// （2026-09-08 线上：leave release 因此丢弃重试、滞留到 TTL）。
pub(crate) fn is_nonce_race(err: &str) -> bool {
    err.contains("NonceTooOld")
        || err.contains("DuplicateNonce")
        || err.contains("Invalid transaction nonce")
}

/// wei → u256 calldata（lo, hi）。
pub(crate) fn wei_to_u256_felts(wei: u128) -> (Felt, Felt) {
    (Felt::from(wei), Felt::from(0_u8))
}

/// owner-gated vault 调用统一入口（player 地址为第一参）。
/// nonce 竞争统一退避重试：结算 bundle/释放/续钟共用 operator 账户，
/// 前一笔还在内存池时本笔易以旧 nonce 构建被拒（不上链不花 gas——
/// 2026-09-07 线上：OPP 离桌释放 2.08 STRK 因无重试直接丢失）。
async fn invoke_vault(
    player_address: &str,
    fn_name: &str,
    extra_calldata: Vec<Felt>,
) -> Result<Felt, String> {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        match invoke_vault_once(player_address, fn_name, &extra_calldata).await {
            Ok(tx) => return Ok(tx),
            Err(e) => {
                last_err = e.clone();
                if is_nonce_race(&e) && attempt < MAX_ATTEMPTS {
                    tracing::warn!(
                        "[in-hand-lock] vault {fn_name} nonce race for {player_address} (attempt {attempt}/{MAX_ATTEMPTS}) — retrying"
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

async fn invoke_vault_once(
    player_address: &str,
    fn_name: &str,
    extra_calldata: &[Felt],
) -> Result<Felt, String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let vault = vault_address()?;
    let operator = chain.operator().await.ok_or("operator account unavailable")?;
    let player = parse_felt(player_address)
        .ok_or_else(|| format!("player address invalid: {player_address}"))?;
    let mut calldata = vec![player];
    calldata.extend(extra_calldata.iter().cloned());
    let call = Call {
        to: vault,
        selector: selector(fn_name),
        calldata,
    };
    let res = operator
        .execute_v3(vec![call])
        .send()
        .await
        .map_err(|e| format!("invoke {fn_name}: {e:?}"))?;
    Ok(res.transaction_hash)
}

