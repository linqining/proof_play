//! secp256k1 ECDSA recoverable 签名验证（NEW-L1 + SEC-L2 + IMPL-SEC-1 修复实现）
//!
//! spec 要求：
//! - signature = `r (32B) || s (32B) || v (1B)`，v ∈ {0, 1}
//! - **NEW-L1（BIP-62）**：强制 low-s — `s > n/2` 返回 `InvalidSignatureLowS`（拒绝，不规范化）
//! - **SEC-L2**：low-s 校验在签名解析后、pubkey 恢复前执行（DoS 缓解）
//! - **IMPL-SEC-1**：
//!   - 使用 `libsecp256k1` 绑定 crate（`secp256k1` ≥ 0.28），禁用纯 Rust 于主网共识路径
//!   - 全程常数时间：v recovery / pubkey 比对 / low-s 比较 / tag 解析
//!   - 硬件钱包路径与软件路径一致（不 bypass）

use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::ct_util::ct_lt_be32;
use crate::signature::tagged_pubkey::{SignatureScheme, TaggedPubkey};
use secp256k1::{
    Message,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use subtle::ConstantTimeEq as _;

/// secp256k1 曲线阶数 n 的一半（BIP-62 low-s 阈值），big-endian。
///
/// n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
/// n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
const SECP256K1_N_HALF_BE: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// secp256k1 recoverable 签名长度：r(32) || s(32) || v(1) = 65 字节。
pub const SECP256K1_SIG_LEN: usize = 65;

/// 验证 secp256k1 ECDSA recoverable 签名。
///
/// 流程（严格遵循 SEC-L2 时机要求）：
/// 1. 校验签名长度 = 65
/// 2. 解析 r || s || v 字节
/// 3. **low-s 校验**（常数时间，`s > n/2` 返回 `InvalidSignatureLowS`）— 在 pubkey 恢复前
/// 4. 校验 v ∈ {0, 1}
/// 5. `RecoverableSignature::from_compact` 解析（libsecp256k1 常数时间）
/// 6. `recover` 恢复 pubkey（libsecp256k1 常数时间，依赖 global-context feature）
/// 7. 常数时间比对恢复的 pubkey 与 tagged pubkey 的 raw bytes
pub fn verify(
    tagged_pubkey: &TaggedPubkey,
    sig_bytes: &[u8],
    msg_hash: &[u8; 32],
) -> PokerL1Result<()> {
    if tagged_pubkey.scheme()? != SignatureScheme::Secp256k1 {
        return Err(PokerL1Error::CurveMismatch {
            pub_tag: tagged_pubkey.tag,
            sig_tag: tagged_pubkey.tag,
        });
    }
    if sig_bytes.len() != SECP256K1_SIG_LEN {
        return Err(PokerL1Error::InvalidSignatureLength {
            actual: sig_bytes.len(),
            expected: SECP256K1_SIG_LEN,
        });
    }

    // 解析 r || s || v
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig_bytes[32..64]);
    let v_byte = sig_bytes[64];

    // === NEW-L1: low-s 校验（常数时间，BIP-62）===
    // s > n/2 → high-s → 拒绝（不规范化转换）
    // s > n/2 等价于 n/2 < s，即 ct_lt_be32(n/2, s)
    if ct_lt_be32(&SECP256K1_N_HALF_BE, &s_bytes) {
        return Err(PokerL1Error::InvalidSignatureLowS);
    }

    // === 校验 v ∈ {0, 1} ===
    // spec：v ∈ {0, 1}（不接受 v ∈ {2, 3}）
    if v_byte > 1 {
        return Err(PokerL1Error::InvalidSignature);
    }

    // === libsecp256k1 解析 + 恢复 ===
    // secp256k1 0.29 API：from_compact(data: &[u8], recid: RecoveryId)
    // 只取 r||s 部分（前 64 字节），v 单独传入 RecoveryId
    let recovery_id =
        RecoveryId::from_i32(v_byte as i32).map_err(|_| PokerL1Error::InvalidSignature)?;
    let recoverable = RecoverableSignature::from_compact(&sig_bytes[0..64], recovery_id)
        .map_err(|_| PokerL1Error::InvalidSignature)?;

    let msg = Message::from_digest(*msg_hash);
    // global-context feature 下 recover 不需要显式 context
    let recovered = recoverable
        .recover(&msg)
        .map_err(|_| PokerL1Error::InvalidSignature)?;

    // === 常数时间比对恢复的 pubkey 与 tagged pubkey ===
    let recovered_compressed = recovered.serialize(); // [u8; 33] compressed
    if recovered_compressed.len() != tagged_pubkey.raw.len() {
        return Err(PokerL1Error::InvalidSignature);
    }
    // ConstantTimeEq 对 [u8] slice 实现：ct_eq 返回 Choice
    let ct_eq = recovered_compressed.ct_eq(tagged_pubkey.raw.as_slice());
    if bool::from(ct_eq) {
        Ok(())
    } else {
        Err(PokerL1Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::ct_util::ct_lt_be32;
    use crate::signature::tagged_pubkey::encode_tag;
    use rand::rngs::OsRng;
    use secp256k1::Secp256k1;

    fn sign_and_get_tagged(msg_hash: &[u8; 32]) -> (TaggedPubkey, Vec<u8>) {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (sk, pk) = secp.generate_keypair(&mut rng);
        let msg = Message::from_digest(*msg_hash);
        let sig = secp.sign_ecdsa_recoverable(&msg, &sk);
        let (recovery_id, compact) = sig.serialize_compact();
        // v 必须在 {0, 1}（libsecp256k1 sign 产生的 recovery_id 通常是 0 或 1）
        let v = recovery_id.to_i32() as u8;
        assert!(v <= 1, "recovery_id 应为 0 或 1");

        let compressed = pk.serialize();
        let tagged = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: compressed.to_vec(),
        };
        let mut full_sig = compact.to_vec();
        full_sig.push(v);
        (tagged, full_sig)
    }

    #[test]
    fn verify_valid_signature() {
        let msg = [0x42u8; 32];
        let (tp, sig) = sign_and_get_tagged(&msg);
        verify(&tp, &sig, &msg).expect("合法签名必须验证通过");
    }

    #[test]
    fn verify_wrong_message_fails() {
        let msg1 = [0x42u8; 32];
        let msg2 = [0x99u8; 32];
        let (tp, sig) = sign_and_get_tagged(&msg1);
        let err = verify(&tp, &sig, &msg2).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidSignature));
    }

    #[test]
    fn verify_wrong_pubkey_fails() {
        let msg = [0x42u8; 32];
        let (_tp, sig) = sign_and_get_tagged(&msg);
        // 用另一个 pubkey 验证
        let secp = Secp256k1::new();
        let (_sk2, pk2) = secp.generate_keypair(&mut OsRng);
        let wrong_tp = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: pk2.serialize().to_vec(),
        };
        let err = verify(&wrong_tp, &sig, &msg).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidSignature));
    }

    #[test]
    fn verify_wrong_sig_length() {
        let msg = [0x42u8; 32];
        let (tp, _sig) = sign_and_get_tagged(&msg);
        let err = verify(&tp, &[0u8; 64], &msg).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidSignatureLength { .. }));
    }

    #[test]
    fn verify_rejects_high_s() {
        // 构造 high-s 签名：先正常签名，然后将 s 翻转为 high-s
        let msg = [0x42u8; 32];
        let (tp, mut sig) = sign_and_get_tagged(&msg);

        // 取 s，若为 low-s 则翻转为 n - s（high-s）
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&sig[32..64]);

        // 检查当前 s 是否为 low-s：n/2 < s 为真则 high-s
        let is_high = ct_lt_be32(&SECP256K1_N_HALF_BE, &s_bytes);
        if !is_high {
            // 当前是 low-s，翻转 s = n - s 使其变为 high-s
            // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            let n_bytes: [u8; 32] = [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
                0xD0, 0x36, 0x41, 0x41,
            ];
            // n - s（big-endian 借位减法）
            let mut result = [0u8; 32];
            let mut borrow: i32 = 0;
            for i in (0..32).rev() {
                let diff = n_bytes[i] as i32 - s_bytes[i] as i32 - borrow;
                if diff < 0 {
                    result[i] = (diff + 256) as u8;
                    borrow = 1;
                } else {
                    result[i] = diff as u8;
                    borrow = 0;
                }
            }
            sig[32..64].copy_from_slice(&result);

            // 验证被拒绝
            let err = verify(&tp, &sig, &msg).unwrap_err();
            assert!(
                matches!(err, PokerL1Error::InvalidSignatureLowS),
                "high-s 签名必须返回 InvalidSignatureLowS"
            );
        }
    }

    #[test]
    fn verify_rejects_invalid_v() {
        let msg = [0x42u8; 32];
        let (tp, mut sig) = sign_and_get_tagged(&msg);
        sig[64] = 2; // 非法 v
        let err = verify(&tp, &sig, &msg).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidSignature));
    }

    #[test]
    fn verify_rejects_ed25519_tagged_pubkey() {
        let msg = [0x42u8; 32];
        let (tp, sig) = sign_and_get_tagged(&msg);
        // 用 ed25519 tag 的 pubkey 验证 secp256k1 签名
        let wrong_tp = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Ed25519, 1),
            raw: tp.raw,
        };
        let err = verify(&wrong_tp, &sig, &msg).unwrap_err();
        assert!(matches!(err, PokerL1Error::CurveMismatch { .. }));
    }
}
