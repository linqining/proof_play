//! Starknet 钱包签名验证。
//!
//! 验证模型：前端用连接钱包对一段 SNIP-12 typed data 签名，并随请求附上
//! `messageHash`（starknet.js `TypedData.getMessageHash(typedData, address)`
//! 的结果）。服务端调用该地址账户合约的 `isValidSignature(hash, signature)`
//! 视图完成验证（ArgentX / Braavos 账户均实现此入口）。
//!
//! `STARKNET_AUTH_STRICT=false`（默认）时 dev 模式放行：无 RPC 或调用失败
//! 仅记日志，方便离线联调；生产必须显式设为 true。

use starknet::core::types::Felt;
use starknet::core::utils::starknet_keccak;

use super::chain::parse_felt;

/// `isValidSignature` 的 Cairo selector。
fn is_valid_signature_selector() -> Felt {
    starknet_keccak("isValidSignature".as_bytes())
}

/// 验证钱包对 messageHash 的签名。
///
/// * `address`  — 账户合约地址（0x hex）
/// * `message_hash` — 前端计算的 SNIP-12 消息哈希（0x hex）
/// * `signature` — 签名 felts（r, s 或带版本前缀）
pub async fn verify_wallet_signature(
    address: &str,
    message_hash: &str,
    signature: &[String],
) -> Result<(), String> {
    let Some(chain) = super::chain() else {
        return skip_or_err("starknet chain not initialized");
    };
    if !chain.config.auth_strict {
        tracing::debug!("[starknet-auth] dev mode: skipping on-chain signature verification");
        return Ok(());
    }
    if !chain.config.rpc_enabled() {
        return Err("STARKNET_AUTH_STRICT=true requires STARKNET_RPC_URL".into());
    }

    let addr = parse_felt(address).ok_or("invalid wallet address")?;
    let hash = parse_felt(message_hash).ok_or("invalid message hash")?;
    let mut sig = Vec::with_capacity(signature.len());
    for s in signature {
        sig.push(parse_felt(s).ok_or_else(|| format!("invalid signature felt: {s}"))?);
    }
    if sig.len() < 2 {
        return Err("signature must contain at least [r, s]".into());
    }

    let mut calldata = Vec::with_capacity(3 + sig.len());
    calldata.push(hash);
    calldata.push(Felt::from(sig.len() as u64));
    calldata.extend(sig.iter().copied());

    let result = chain
        .call_contract(addr, is_valid_signature_selector(), calldata)
        .await
        .map_err(|e| {
            // 未部署账户：钱包能本地签名但链上没有账户合约可验签
            // （starknet-rs 报 Contract not found / Contract not registered）。
            if e.to_ascii_lowercase().contains("not found")
                || e.to_ascii_lowercase().contains("not registered")
            {
                "钱包地址尚未在当前网络激活（无账户合约）。请在钱包中先完成任意一笔交易以部署账户，再重新登录".to_string()
            } else {
                e
            }
        })?;

    // Argent/Braavos 约定：VALID = felt 短串 "VALID"（0x00...56414c4944）。
    // Argent 旧版 camelCase 入口（isValidSignature）按合约源码语义：
    // 有效返回 1，无效 panic（不返回 VALID magic）——两种都要认。
    let ok = result
        .first()
        .and_then(|f| starknet::core::utils::parse_cairo_short_string(f).ok())
        .map(|s| s == "VALID")
        .unwrap_or(false)
        || result.first().map(|f| *f == Felt::ONE).unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(format!(
            "isValidSignature rejected: {:?}",
            result.iter().map(|f| format!("{f:#x}")).collect::<Vec<_>>()
        ))
    }
}

fn skip_or_err(reason: &str) -> Result<(), String> {
    // 非 strict 模式下链不可用 → 放行；strict 模式由调用方感知失败。
    tracing::warn!("[starknet-auth] {reason}; proceeding (dev mode)");
    Ok(())
}
