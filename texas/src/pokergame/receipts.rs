//! #17 签名回执（`docs/design/ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §7.1）。
//!
//! 服务器对每个动作的"决定"（accepted / auto-accepted / rejected+reason）
//! 回签收据 `Sig_operator(...)`，经 ACTION_RECEIPT 广播给全桌。玩家留存
//! 回执 + settle 的 accepted-seq 向量即可构成审查的可判定证据：
//! 持 seq=N 的签名动作 + accepted-seq < N ⇒ 密码学证明动作被丢弃。
//!
//! operator 游戏域密钥：首次启动随机生成并持久化到
//! `<STARKNET_PROVER_WORK_DIR>/operator-game-key.json`（与钱包零派生，
//! 泄露影响 = 伪造回执能力，不涉及资金）。公钥随每张回执下发。

use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar};
use poker_protocol::crypto::curve::StarkCurve;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

pub const RECEIPT_DOMAIN: &[u8] = b"zgame.action-receipt.v1";

/// 动作决定。
/// 回执载荷（签名的确切字节序，见 [`receipt_msg_bytes`]）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionReceipt {
    pub table_id: u32,
    /// 座位牌局公钥（压缩 hex）。
    pub player_pk: String,
    pub seq: u64,
    pub action: String,
    pub amount: u64,
    /// accepted / autoAccepted / rejected
    pub decision: String,
    /// rejected 时的理由短码（accepted 为空串）。
    pub reason: String,
    /// operator 游戏域公钥（压缩 hex），客户端据此本地验签。
    pub operator_pk: String,
}

/// 回执签名的确切字节序（服务端签名 / 客户端验签三方共用）。
pub fn receipt_msg_bytes(receipt: &ActionReceipt) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(RECEIPT_DOMAIN);
    m.extend_from_slice(&receipt.table_id.to_be_bytes());
    m.extend_from_slice(hex::decode(&receipt.player_pk).unwrap_or_default().as_slice());
    m.extend_from_slice(&receipt.seq.to_be_bytes());
    m.extend_from_slice(&(receipt.action.len() as u32).to_be_bytes());
    m.extend_from_slice(receipt.action.as_bytes());
    m.extend_from_slice(&receipt.amount.to_be_bytes());
    m.extend_from_slice(&(receipt.decision.len() as u32).to_be_bytes());
    m.extend_from_slice(receipt.decision.as_bytes());
    m.extend_from_slice(&(receipt.reason.len() as u32).to_be_bytes());
    m.extend_from_slice(receipt.reason.as_bytes());
    m
}

/// operator 游戏域密钥（sk 为 32 字节大端 hex）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorGameKey {
    pub sk_hex: String,
}

/// 加载或生成 operator 游戏域密钥（文件不存在时生成并写回）。
pub fn load_or_generate_key(path: &std::path::Path) -> Result<(StarkCurveScalar, String), String> {
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(key) = serde_json::from_str::<OperatorGameKey>(&content) {
            let sk = parse_sk(&key.sk_hex)?;
            let pk = StarkCurve::base_g() * sk;
            return Ok((sk, point_to_hex(&pk)));
        }
    }
    let sk = <StarkCurve as Curve>::Scalar::random(&mut OsRngAdapter);
    let sk_hex = hex::encode(sk.as_bytes());
    let pk = StarkCurve::base_g() * sk;
    let pk_hex = point_to_hex(&pk);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create key dir: {e}"))?;
    }
    let content = serde_json::to_string(&OperatorGameKey { sk_hex })
        .map_err(|e| format!("serialize key: {e}"))?;
    std::fs::write(path, content).map_err(|e| format!("write key: {e}"))?;
    Ok((sk, pk_hex))
}

/// 对回执签名（StarkCurve，与动作签名同域形状）。
pub fn sign_receipt(
    sk: &StarkCurveScalar,
    receipt: &ActionReceipt,
    rng: &mut (impl RngCore + CryptoRng),
) -> (String, String) {
    let msg = receipt_msg_bytes(receipt);
    loop {
        let w = <StarkCurve as Curve>::Scalar::random(rng);
        if w == <StarkCurve as Curve>::Scalar::zero() {
            continue;
        }
        let g = StarkCurve::base_g();
        let r = g * w;
        if r.is_identity() {
            continue;
        }
        let mut challenge_input = msg.clone();
        challenge_input.extend_from_slice(r.compress().as_ref());
        let c = StarkCurve::hash_to_scalar(&challenge_input);
        let s = w + c * *sk;
        if s == <StarkCurve as Curve>::Scalar::zero() {
            continue;
        }
        return (hex::encode(r.compress().as_ref()), hex::encode(s.as_bytes()));
    }
}

// ---- 内部小工具（StarkCurve 编解码） ----

type StarkCurveScalar = <StarkCurve as Curve>::Scalar;

fn parse_sk(hex_str: &str) -> Result<StarkCurveScalar, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("sk hex: {e}"))?;
    <StarkCurve as Curve>::Scalar::from_canonical_bytes(&bytes)
        .ok_or_else(|| "sk out of range".into())
}

/// 回执验证（客户端同式；服务端测试用）。
#[cfg(test)]
pub(crate) fn verify_receipt(
    operator_pk_hex: &str,
    receipt: &ActionReceipt,
    r_hex: &str,
    s_hex: &str,
) -> bool {
    let Some(pk) = point_from_hex(operator_pk_hex) else {
        return false;
    };
    let Some(r) = point_from_hex(r_hex) else {
        return false;
    };
    let Some(s) = scalar_from_hex(s_hex) else {
        return false;
    };
    let msg = receipt_msg_bytes(receipt);
    let mut challenge_input = msg;
    challenge_input.extend_from_slice(r.compress().as_ref());
    let c = StarkCurve::hash_to_scalar(&challenge_input);
    let g = StarkCurve::base_g();
    g * s == r + pk * c
}

#[cfg(test)]
fn point_from_hex(hex_str: &str) -> Option<<StarkCurve as Curve>::Point> {
    let bytes = hex::decode(hex_str).ok()?;
    <StarkCurve as Curve>::Point::from_compressed(&bytes)
}

#[cfg(test)]
fn scalar_from_hex(hex_str: &str) -> Option<StarkCurveScalar> {
    let bytes = hex::decode(hex_str).ok()?;
    <StarkCurve as Curve>::Scalar::from_canonical_bytes(&bytes)
}

fn point_to_hex(p: &<StarkCurve as Curve>::Point) -> String {
    hex::encode(p.compress().as_ref())
}

/// rand_core 0.6 适配（poker-protocol-core 的 CryptoRng/RngCore 为同版本，
/// 但 bound 要求独立类型参数，包一层以获得具体类型）。
struct OsRngAdapter;

impl RngCore for OsRngAdapter {
    fn next_u32(&mut self) -> u32 {
        rand_core::OsRng.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::OsRng.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::OsRng.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        rand_core::OsRng.try_fill_bytes(dest)
    }
}

impl CryptoRng for OsRngAdapter {}

/// 进程级 operator 游戏域密钥：首次使用时从
/// `<STARKNET_PROVER_WORK_DIR 或 ./data>/operator-game-key.json` 加载或生成。
pub fn operator() -> Option<(StarkCurveScalar, String)> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Option<(StarkCurveScalar, String)>> = OnceLock::new();
    KEY.get_or_init(|| {
        let dir = std::env::var("STARKNET_PROVER_WORK_DIR").unwrap_or_else(|_| "./data".into());
        let path = std::path::Path::new(&dir).join("operator-game-key.json");
        load_or_generate_key(&path)
            .map_err(|e| tracing::warn!("[receipts] operator key init failed: {e}"))
            .ok()
    })
    .clone()
}

/// 用 operator 密钥对回执签名（无密钥时返回 None——回执退化为未签名通知）。
pub fn sign_receipt_with_operator(receipt: &ActionReceipt) -> Option<(String, String)> {
    let (sk, _) = operator()?;
    Some(sign_receipt(&sk, receipt, &mut OsRngAdapter))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_receipt(operator_pk: &str) -> ActionReceipt {
        ActionReceipt {
            table_id: 1,
            player_pk: "0xaaa".into(),
            seq: 5,
            action: "raise".into(),
            amount: 320,
            decision: "accepted".into(),
            reason: String::new(),
            operator_pk: operator_pk.into(),
        }
    }

    #[test]
    fn receipt_sign_verify_roundtrip() {
        let (sk, pk_hex) = load_or_generate_key(&std::env::temp_dir().join(format!(
            "op-key-test-{}.json",
            std::process::id()
        )))
        .expect("key");
        let receipt = sample_receipt(&pk_hex);
        let (r_hex, s_hex) = sign_receipt(&sk, &receipt, &mut rand_core::OsRng);
        assert!(verify_receipt(&pk_hex, &receipt, &r_hex, &s_hex));
    }

    #[test]
    fn receipt_tamper_rejected() {
        let (sk, pk_hex) = load_or_generate_key(&std::env::temp_dir().join(format!(
            "op-key-test-tamper-{}.json",
            std::process::id()
        )))
        .expect("key");
        let mut receipt = sample_receipt(&pk_hex);
        let (r_hex, s_hex) = sign_receipt(&sk, &receipt, &mut rand_core::OsRng);
        // 任何字段被改（如 seq 递增）都应验签失败
        receipt.seq += 1;
        assert!(!verify_receipt(&pk_hex, &receipt, &r_hex, &s_hex));
    }

    #[test]
    fn key_persists_across_reloads() {
        let path = std::env::temp_dir().join(format!(
            "op-key-test-persist-{}.json",
            std::process::id()
        ));
        let (sk1, pk1) = load_or_generate_key(&path).expect("key 1");
        let (sk2, pk2) = load_or_generate_key(&path).expect("key 2");
        assert_eq!(pk1, pk2, "重载必须得到同一公钥");
        assert_eq!(
            hex::encode(sk1.as_bytes()),
            hex::encode(sk2.as_bytes()),
            "重载必须得到同一 sk"
        );
        let _ = std::fs::remove_file(&path);
    }
}
