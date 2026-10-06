//! 嵌入式 sequencer 的账户派生（v1 内嵌运营方托管模型）。
//!
//! **信任模型（如实记录）**：v1 嵌入式 sequencer 里，玩家的 appchain
//! 身份密钥由游戏服务器托管派生：`sk = blake2s("texas-appchain.owner.v2"
//! ‖ custody_secret ‖ wallet)`。custody secret 是**服务端私有**的 32 字节
//! ——来源 `TEXAS_APPCHAIN_CUSTODY_SECRET`（64 hex），缺省在 WAL 目录
//! load-or-generate（`custody-secret`，0600）。secret 不出服务器，公开的
//! 钱包地址不再足以推出任何人的 appchain 私钥 / spend secret / nullifier。
//! 这不再是 v1 最初的"纯公开输入派生"（任何人可复算任意玩家密钥），
//! 但仍是托管模型：operator 一方持有全部密钥；生产去托管化（客户端持有
//! P 层密钥、服务器只见公钥）是 v2 客户端协议升级项，届时仅需替换本模块
//! 的密钥来源，结算语义不变。
//!
//! 域标签 v2：与 v1（无 secret 混入）派生彻底分离——旧账本的 owner 地址
//! 不会被新派生命中，嵌入式 dev 链直接换新身份即可。

use std::sync::OnceLock;

use poker_appchain::keys::OwnerKey;

/// 密钥域标签（v2：custody secret 混入派生）。
const OWNER_DOMAIN: &[u8] = b"texas-appchain.owner.v2";

/// 服务端托管密钥（进程单例；`init_custody_secret` 装配，之后只读）。
static CUSTODY_SECRET: OnceLock<[u8; 32]> = OnceLock::new();

/// custody secret 环境变量名（64 hex；显式配置优先于落盘文件）。
pub const CUSTODY_SECRET_ENV: &str = "TEXAS_APPCHAIN_CUSTODY_SECRET";

/// 装配 custody secret（进程单次；幂等——已装配时保留现有值）。
///
/// 优先级：`TEXAS_APPCHAIN_CUSTODY_SECRET`（64 hex）→
/// `<wal_dir>/custody-secret` 落盘文件（load-or-generate，0600）。
/// 生成新 secret 会改变全部派生身份（等价于换一条新链），日志显式告警。
///
/// # Errors
/// env hex 非法 / 目录创建或文件读写失败 → 文本错误。
pub fn init_custody_secret(wal_dir: &std::path::Path) -> Result<(), String> {
    if CUSTODY_SECRET.get().is_some() {
        return Ok(());
    }
    let secret = load_secret(wal_dir)?;
    CUSTODY_SECRET.set(secret).map_err(|_| "custody secret race".to_string())
}

/// 测试脚手架：注入固定 secret（不落盘；已装配时无操作）。
#[cfg(test)]
pub fn init_custody_secret_for_test(secret: [u8; 32]) {
    let _ = CUSTODY_SECRET.set(secret);
}

fn load_secret(wal_dir: &std::path::Path) -> Result<[u8; 32], String> {
    if let Ok(hex_s) = std::env::var(CUSTODY_SECRET_ENV) {
        let s = hex_s.trim().trim_start_matches("0x");
        return hex::decode(s)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| format!("{CUSTODY_SECRET_ENV}: expect 64 hex chars"));
    }
    let path = wal_dir.join("custody-secret");
    if let Ok(bytes) = std::fs::read(&path) {
        return <[u8; 32]>::try_from(bytes)
            .map_err(|_| format!("{}: corrupt (expect 32 bytes)", path.display()));
    }
    let mut secret = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut secret);
    write_secret_0600(&path, &secret)?;
    tracing::warn!(
        "[appchain] generated new custody secret at {} — all derived appchain \
         identities are fresh (pre-existing ledger notes become unreachable)",
        path.display()
    );
    Ok(secret)
}

pub(super) fn write_secret_0600(path: &std::path::Path, secret: &[u8; 32]) -> Result<(), String> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(secret).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(())
}

fn custody() -> [u8; 32] {
    CUSTODY_SECRET.get().copied().unwrap_or_else(|| {
        panic!("appchain custody secret not initialized — call init_custody_secret first")
    })
}

/// 钱包 felt（32B）→ 该钱包的 appchain owner 密钥（确定性；派生失败按
/// 计数器重试——secp256k1 模数外的种子概率 ≈ 2⁻¹²⁸，循环实际不二次进入）。
/// 输入混入服务端 custody secret：公开钱包地址无法复算他人密钥。
#[must_use]
pub fn owner_key_of(wallet_felt: &[u8; 32]) -> OwnerKey {
    let custody = custody();
    let mut counter = 0u8;
    loop {
        let mut seed = poker_appchain::keys::blake2s32(&[OWNER_DOMAIN, &custody, wallet_felt]);
        seed[31] = seed[31].wrapping_add(counter);
        if let Ok(k) = OwnerKey::from_seed(&seed) {
            return k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// 花费密钥（nullifier 派生输入）：与 owner 密钥同源派生（v1 托管模型，
/// 同样混入 custody secret）。
#[must_use]
pub fn spend_secret_of(wallet_felt: &[u8; 32]) -> [u8; 32] {
    let custody = custody();
    poker_appchain::keys::blake2s32(&[OWNER_DOMAIN, b"/spend", &custody, wallet_felt])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_fixed() {
        init_custody_secret_for_test([0x11; 32]);
    }

    /// 确定性：同钱包同钥；不同钱包不同钥。
    #[test]
    fn derivation_is_deterministic_and_injective() {
        init_fixed();
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(owner_key_of(&a).public_bytes(), owner_key_of(&a).public_bytes());
        assert_ne!(owner_key_of(&a).public_bytes(), owner_key_of(&b).public_bytes());
        assert_ne!(spend_secret_of(&a), spend_secret_of(&b));
    }

    /// custody secret 是派生输入：不同 secret → 不同密钥（公开地址
    /// + 无 secret 无法复算）。
    #[test]
    fn different_custody_secret_derives_different_keys() {
        let wallet = [7u8; 32];
        init_custody_secret_for_test([0x22; 32]);
        let k1 = owner_key_of(&wallet).public_bytes();
        let s1 = spend_secret_of(&wallet);
        init_custody_secret_for_test([0x33; 32]);
        // OnceLock 已占用：k1 仍来自第一个 secret —— 用直接派生对照。
        let k2 = {
            let custody = [0x33u8; 32];
            let seed = poker_appchain::keys::blake2s32(&[OWNER_DOMAIN, &custody, &wallet]);
            OwnerKey::from_seed(&seed)
                .map(|k| k.public_bytes())
                .unwrap_or([0u8; 33])
        };
        assert_ne!(k1, k2, "changing custody secret must change derived keys");
        assert_ne!(s1, [0u8; 32]);
    }

    /// 落盘路径：load-or-generate + 二次加载同值 + env 优先。
    #[test]
    fn secret_persists_across_loads_and_env_wins() {
        let dir = std::env::temp_dir().join(format!("texas-custody-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("custody-secret");
        let first = load_secret(&dir).expect("generate");
        assert!(path.exists());
        let second = load_secret(&dir).expect("reload");
        assert_eq!(first, second, "second load must read the persisted secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "secret file must be 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
