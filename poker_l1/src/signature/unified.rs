//! 统一签名验证路由（SubTask 5.4）
//!
//! spec：`verify_signature(tagged_pubkey, sig, msg_hash) -> bool` 按 tag 路由到对应曲线验证器。
//! 未知 tag 返回 `UnknownScheme`。
//!
//! IMPL-SEC-1：tag 解析常数时间（不因 scheme 不同而提前返回时间差异）。
//! 所有 scheme 内部均使用常数时间实现。

use crate::error::PokerL1Result;
use crate::signature::ed25519_scheme;
use crate::signature::secp256k1_scheme;
use crate::signature::stark_scheme;
use crate::signature::tagged_pubkey::{SignatureScheme, TaggedPubkey};

/// 统一签名验证：按 tagged pubkey 的 tag 路由到对应曲线验证器。
///
/// 返回 `Ok(())` 表示验证通过，`Err(_)` 表示失败（含具体错误原因）。
///
/// # 参数
/// - `tagged_pubkey`：tagged 编码的公钥（1B tag || raw pubkey）
/// - `sig`：签名字节（secp256k1 = 65B r||s||v；ed25519 = 64B R||S）
/// - `msg_hash`：消息哈希（32 字节，签名对象已哈希）
pub fn verify_signature(
    tagged_pubkey: &TaggedPubkey,
    sig: &[u8],
    msg_hash: &[u8; 32],
) -> PokerL1Result<()> {
    // 常数时间 tag 解析：parse_tag 内部使用 match 但不泄露 scheme 信息的时间差
    // （match 本身在编译后为跳转表，无数据依赖分支）
    let scheme = tagged_pubkey.scheme()?;

    match scheme {
        SignatureScheme::Secp256k1 => secp256k1_scheme::verify(tagged_pubkey, sig, msg_hash),
        SignatureScheme::Ed25519 => ed25519_scheme::verify(tagged_pubkey, sig, msg_hash),
        SignatureScheme::Stark => stark_scheme::verify(tagged_pubkey, sig, msg_hash),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PokerL1Error;
    use crate::signature::tagged_pubkey::encode_tag;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use rand::rngs::OsRng;
    use secp256k1::{Message, Secp256k1};

    #[test]
    fn unified_verify_secp256k1() {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        let msg = [0x42u8; 32];
        let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(msg), &sk);
        let (rid, compact) = sig.serialize_compact();
        let mut full_sig = compact.to_vec();
        full_sig.push(rid.to_i32() as u8);

        let tp = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: pk.serialize().to_vec(),
        };
        verify_signature(&tp, &full_sig, &msg).expect("secp256k1 统一验证必须通过");
    }

    #[test]
    fn unified_verify_ed25519() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = VerifyingKey::from(&sk);
        let msg = [0x42u8; 32];
        let sig = sk.sign(msg.as_slice());

        let tp = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Ed25519, 1),
            raw: pk.to_bytes().to_vec(),
        };
        verify_signature(&tp, &sig.to_bytes(), &msg).expect("ed25519 统一验证必须通过");
    }

    #[test]
    fn unified_verify_unknown_scheme() {
        // scheme_id = 5（未定义）
        let tp = TaggedPubkey {
            tag: 0x51,
            raw: vec![0; 33],
        };
        let err = verify_signature(&tp, &[0; 65], &[0; 32]).unwrap_err();
        assert!(matches!(err, PokerL1Error::UnknownScheme { tag: 0x51 }));
    }

    #[test]
    fn unified_verify_rejects_tampered_secp256k1() {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        let msg = [0x42u8; 32];
        let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(msg), &sk);
        let (rid, mut compact) = sig.serialize_compact();
        // 篡改 r 的首字节
        compact[0] ^= 0x01;
        let mut full_sig = compact.to_vec();
        full_sig.push(rid.to_i32() as u8);

        let tp = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: pk.serialize().to_vec(),
        };
        let err = verify_signature(&tp, &full_sig, &msg).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidSignature));
    }
}
