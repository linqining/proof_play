//! ed25519 签名验证（SEC2-L1 修复实现 — 签名规范化）
//!
//! spec SEC2-L1：
//! - 校验 R 编码 canonical（y < 2^255 - 19）
//! - 校验 S 编码 canonical（S < L，L 为子群阶数）
//! - 非规范化返回 `InvalidSignatureCanonical`
//! - 应用于所有 ed25519 签名路径（tx / ACK / operator_ack / multi-replica receipt）
//!
//! signature = R (32B) || S (32B) = 64 字节

use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::ct_util::{ct_eq_be32, ct_lt_be32};
use crate::signature::tagged_pubkey::{SignatureScheme, TaggedPubkey};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// ed25519 签名长度：R(32) || S(32) = 64 字节。
pub const ED25519_SIG_LEN: usize = 64;

/// ed25519 子群阶数 L = 2^252 + 27742317777372353535851937790883648493
/// big-endian: 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
const L_BE: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED,
];

/// 素数 p = 2^255 - 19
/// big-endian: 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
const P_BE: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED,
];

/// 验证 ed25519 签名。
///
/// 流程（SEC2-L1）：
/// 1. 校验签名长度 = 64
/// 2. **R canonical 校验**：R 的 y 坐标 < p（常数时间）
/// 3. **S canonical 校验**：S < L（常数时间）
/// 4. 非规范化返回 `InvalidSignatureCanonical`
/// 5. ed25519-dalek 验证签名
pub fn verify(
    tagged_pubkey: &TaggedPubkey,
    sig_bytes: &[u8],
    msg_hash: &[u8; 32],
) -> PokerL1Result<()> {
    if tagged_pubkey.scheme()? != SignatureScheme::Ed25519 {
        return Err(PokerL1Error::CurveMismatch {
            pub_tag: tagged_pubkey.tag,
            sig_tag: tagged_pubkey.tag,
        });
    }
    if sig_bytes.len() != ED25519_SIG_LEN {
        return Err(PokerL1Error::InvalidSignatureLength {
            actual: sig_bytes.len(),
            expected: ED25519_SIG_LEN,
        });
    }

    // === SEC2-L1: R canonical 校验 ===
    // R 是压缩 Edwards 点：32 字节，最高位（byte[31] 的 bit 7）是 sign bit，
    // 剩余 255 bits 是 y 坐标（little-endian）。
    // canonical 要求 y < p = 2^255 - 19。
    // 转换为 big-endian 比较：取 R，清除 byte[31] 的最高位，转为 big-endian，与 P_BE 比较。
    let mut r_y_le = [0u8; 32];
    r_y_le.copy_from_slice(&sig_bytes[0..32]);
    r_y_le[31] &= 0x7F; // 清除 sign bit，保留 y 的低 255 位
    let r_y_be = le_to_be(&r_y_le);
    // y >= p（非 canonical）等价于 p < y 或 p == y
    // 注意：p = 2^255 - 19，y 的最大合法值是 p - 1，所以 y >= p 即非 canonical
    // 但 y 的最大值（255 bits）= 2^255 - 1 < 2*p，所以 y < p 或 y >= p 二分
    // p < y 即 ct_lt_be32(&P_BE, &r_y_be)
    // p == y 即 ct_eq_be32(&P_BE, &r_y_be)（理论上 y == p 不会发生因为 p 最高位是 0x7F，
    //   但清除 sign bit 后 y 最高位也是 0x7F，所以 y 可能等于 p）
    let r_non_canonical = ct_lt_be32(&P_BE, &r_y_be) || ct_eq_be32(&P_BE, &r_y_be);
    if r_non_canonical {
        // y >= p，非 canonical
        return Err(PokerL1Error::InvalidSignatureCanonical);
    }

    // === SEC2-L1: S canonical 校验 ===
    // S 是 32 字节 little-endian 整数，canonical 要求 S < L。
    let mut s_le = [0u8; 32];
    s_le.copy_from_slice(&sig_bytes[32..64]);
    let s_be = le_to_be(&s_le);
    // S >= L（非 canonical）等价于 L < S 或 L == S
    let s_ge_l = ct_lt_be32(&L_BE, &s_be);
    let s_eq_l = ct_eq_be32(&L_BE, &s_be);
    if s_ge_l || s_eq_l {
        return Err(PokerL1Error::InvalidSignatureCanonical);
    }

    // === ed25519-dalek 验证 ===
    let pk_bytes: [u8; 32] =
        tagged_pubkey
            .raw
            .as_slice()
            .try_into()
            .map_err(|_| PokerL1Error::InvalidPubkeyLength {
                tag: tagged_pubkey.tag,
                actual: tagged_pubkey.raw.len(),
                expected: 32,
            })?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| PokerL1Error::InvalidSignature)?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let sig = Signature::from_bytes(&sig_arr);

    vk.verify(msg_hash.as_slice(), &sig)
        .map_err(|_| PokerL1Error::InvalidSignature)?;
    Ok(())
}

/// little-endian [u8;32] → big-endian [u8;32]
fn le_to_be(le: &[u8; 32]) -> [u8; 32] {
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    be
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::tagged_pubkey::encode_tag;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn sign_and_get_tagged(msg_hash: &[u8; 32]) -> (TaggedPubkey, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = VerifyingKey::from(&sk);
        let sig = sk.sign(msg_hash.as_slice());
        let tagged = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Ed25519, 1),
            raw: pk.to_bytes().to_vec(),
        };
        (tagged, sig.to_bytes().to_vec())
    }

    #[test]
    fn verify_valid_signature() {
        let msg = [0x42u8; 32];
        let (tp, sig) = sign_and_get_tagged(&msg);
        verify(&tp, &sig, &msg).expect("合法 ed25519 签名必须验证通过");
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
        let sk2 = SigningKey::generate(&mut OsRng);
        let wrong_tp = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Ed25519, 1),
            raw: VerifyingKey::from(&sk2).to_bytes().to_vec(),
        };
        let err = verify(&wrong_tp, &sig, &msg).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidSignature));
    }

    #[test]
    fn verify_wrong_sig_length() {
        let msg = [0x42u8; 32];
        let (tp, _sig) = sign_and_get_tagged(&msg);
        let err = verify(&tp, &[0u8; 63], &msg).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidSignatureLength { .. }));
    }

    #[test]
    fn verify_rejects_wrong_pubkey_length() {
        let msg = [0x42u8; 32];
        let (_tp, sig) = sign_and_get_tagged(&msg);

        // raw.len()=31（应为 32）的 ed25519 tagged pubkey
        let wrong_tp = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Ed25519, 1),
            raw: vec![0u8; 31],
        };

        let err = verify(&wrong_tp, &sig, &msg).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::InvalidPubkeyLength {
                actual: 31,
                expected: 32,
                ..
            }
        ));
    }

    #[test]
    fn verify_rejects_non_canonical_s() {
        let msg = [0x42u8; 32];
        let (tp, mut sig) = sign_and_get_tagged(&msg);

        // 将 S 设为 L（非 canonical，S == L 应被拒绝）
        let l_le = le_to_be(&L_BE);
        sig[32..64].copy_from_slice(&l_le);

        let err = verify(&tp, &sig, &msg).unwrap_err();
        assert!(
            matches!(err, PokerL1Error::InvalidSignatureCanonical),
            "S == L 必须返回 InvalidSignatureCanonical"
        );
    }

    #[test]
    fn verify_rejects_non_canonical_s_above_l() {
        let msg = [0x42u8; 32];
        let (tp, mut sig) = sign_and_get_tagged(&msg);

        // 将 S 设为 L + 1（非 canonical）
        let mut l_le = le_to_be(&L_BE);
        // little-endian + 1
        for byte in l_le.iter_mut() {
            if *byte == 0xFF {
                *byte = 0;
            } else {
                *byte += 1;
                break;
            }
        }
        sig[32..64].copy_from_slice(&l_le);

        let err = verify(&tp, &sig, &msg).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidSignatureCanonical));
    }

    #[test]
    fn verify_rejects_secp256k1_tagged_pubkey() {
        let msg = [0x42u8; 32];
        let (tp, sig) = sign_and_get_tagged(&msg);
        let wrong_tp = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: tp.raw,
        };
        let err = verify(&wrong_tp, &sig, &msg).unwrap_err();
        assert!(matches!(err, PokerL1Error::CurveMismatch { .. }));
    }

    #[test]
    fn le_be_roundtrip() {
        let original = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
            0x70, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x7F,
        ];
        let be = le_to_be(&original);
        let back = le_to_be(&be);
        assert_eq!(original, back);
    }
}
