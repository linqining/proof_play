//! Stark 曲线 Schnorr 签名（P1-2 确定性身份配套方案，scheme_id = 2）。
//!
//! 与 ed25519/secp256k1 方案平级，由 [`super::unified::verify_signature`]
//! 按 tag 路由。公钥编码 = StarkPoint 32B 压缩点（x 坐标 + y 奇偶位，
//! 见 `CurvePoint::compress`）；签名 = `R_compressed(32B) ‖ s_be(32B)`。
//!
//! 验签方程：`base_g() · s − pk · e == R`，其中
//! `e = H("zchain.schnorr.v1" ‖ R ‖ pk ‖ msg_hash)`。
//!
//! 2026-09-10：签名核心（sign / schnorr_challenge / 域常量）下沉到
//! `poker_protocol_core::tx_schnorr`（单一权威，client-wasm
//! `WasmTxSession` 同源）；本文件保留路由/验签外壳与 poker_l1 错误类型。
//!
//! 注意：本方案配套的调用方身份是**公开可派生**的（见
//! `contracts::texas_poker::runtime::caller_id`）——签名是完整性
//! 层（消息/nonce 承诺 + 重放锚），不是钱包持有证明。

use poker_protocol::crypto::curve::{CurvePoint, CurveScalar};
use poker_protocol::crypto::types::{EcPoint, Scalar, base_g};
use poker_protocol_core::tx_schnorr;

use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme, TaggedPubkey, encode_tag};

/// 签名字节长度：R 压缩(32B) ‖ s 大端(32B)（core 单一源）。
pub const SIGNATURE_LEN: usize = tx_schnorr::SIGNATURE_LEN;

/// 签名（确定性 nonce，core `tx_schnorr::sign` 薄包装）。
///
/// - `r = H(nonce_domain ‖ sk ‖ msg_hash)`（可复现，测试与重放友好）
/// - `R = base_g() · r`，`e = H(challenge_domain ‖ R ‖ pk ‖ msg_hash)`
/// - `s = r + e · sk`
#[must_use]
pub fn sign(sk: &Scalar, msg_hash: &[u8; 32]) -> [u8; SIGNATURE_LEN] {
    tx_schnorr::sign(sk, msg_hash)
}

/// 统一路由入口：scheme tag 校验后解析公钥做点级验签。
pub fn verify(tagged_pubkey: &TaggedPubkey, sig: &[u8], msg_hash: &[u8; 32]) -> PokerL1Result<()> {
    if tagged_pubkey.scheme()? != SignatureScheme::Stark {
        return Err(PokerL1Error::CurveMismatch {
            pub_tag: tagged_pubkey.tag,
            sig_tag: encode_tag(SignatureScheme::Stark, CURRENT_VERSION),
        });
    }
    if tagged_pubkey.raw.len() != 32 {
        return Err(PokerL1Error::InvalidPubkeyLength {
            tag: tagged_pubkey.tag,
            actual: tagged_pubkey.raw.len(),
            expected: 32,
        });
    }
    let raw: &[u8; 32] = tagged_pubkey
        .raw
        .as_slice()
        .try_into()
        .expect("length checked above");
    let pk = EcPoint::from_compressed(raw).ok_or(PokerL1Error::InvalidSignature)?;
    verify_point(&pk, msg_hash, sig)
}

/// 点级验签：`base_g() · s − pk · e == R`。
///
/// 拒绝条件：长度错误、s 非规范化（≥ 群阶）、R/pk 非法编码或恒等元、
/// 方程不成立。
pub fn verify_point(pk: &EcPoint, msg_hash: &[u8; 32], sig: &[u8]) -> PokerL1Result<()> {
    if sig.len() != SIGNATURE_LEN {
        return Err(PokerL1Error::InvalidSignatureLength {
            actual: sig.len(),
            expected: SIGNATURE_LEN,
        });
    }
    let r_bytes: &[u8; 32] = sig[..32].try_into().expect("length checked above");
    let big_r = EcPoint::from_compressed(r_bytes).ok_or(PokerL1Error::InvalidSignature)?;
    if big_r.is_identity() || pk.is_identity() {
        return Err(PokerL1Error::InvalidSignature);
    }
    let s = Scalar::from_canonical_bytes(&sig[32..]).ok_or(PokerL1Error::InvalidSignature)?;

    let e = tx_schnorr::schnorr_challenge(&big_r, pk, msg_hash);
    let rhs = base_g() * s - *pk * e;
    if rhs == big_r {
        Ok(())
    } else {
        Err(PokerL1Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_protocol::crypto::types::hash_to_scalar;

    fn sk_of(wallet: &str) -> Scalar {
        hash_to_scalar(wallet.as_bytes())
    }

    fn tagged_pk_of(sk: &Scalar) -> TaggedPubkey {
        let raw = (base_g() * *sk).compress().as_ref().to_vec();
        TaggedPubkey::new(SignatureScheme::Stark, CURRENT_VERSION, raw).unwrap()
    }

/// 跨 crate 已知答案向量（P2-2）：固定 sk 与消息的签名期望值。
    /// **收敛后自证**（2026-09-10）：签名核心单一源于
    /// poker-protocol-core::tx_schnorr，本向量与 client-wasm
    /// `WasmTxSession` 测试携带同一向量——任何一侧对 core 的接线
    /// 漂移（类型/编码/调用路径）都会在此失败。
    /// sk = hash_to_scalar(b"zgame.tx-vector.kat.v1")。
    #[test]
    fn schnorr_known_answer_vector() {
        let sk = poker_protocol::crypto::hash_to_scalar(b"zgame.tx-vector.kat.v1");
        let msg = [0x42u8; 32];
        let sig = sign(&sk, &msg);
        assert_eq!(
            hex::encode(sig),
            "80e93d41175f69487f916da094a1cacb0d2b1dfc0c4c5caa386c7263ca78a09e007bfd2b92bf6112390243cc66f4b77fdfd71c03021a1d33c9ccae0543200c42",
            "KAT mismatch — wasm/poker_l1 signature spaces have drifted"
        );
        let pk = poker_protocol::crypto::types::base_g() * sk;
        verify_point(&pk, &msg, &sig).expect("KAT signature verifies");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let msg = [0x42u8; 32];
        let sk = sk_of("0xabc");
        let sig = sign(&sk, &msg);
        assert_eq!(sig.len(), SIGNATURE_LEN);
        verify(&tagged_pk_of(&sk), &sig, &msg).expect("own signature verifies");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let sk = sk_of("0xabc");
        let sig = sign(&sk, &[0x42u8; 32]);
        let mut other = [0x43u8; 32];
        other[31] ^= 1;
        assert!(verify(&tagged_pk_of(&sk), &sig, &other).is_err());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let msg = [0x42u8; 32];
        let sk = sk_of("0xabc");
        let mut sig = sign(&sk, &msg);
        sig[40] ^= 0x01; // 篡改 s
        assert!(verify(&tagged_pk_of(&sk), &sig, &msg).is_err());
        let mut sig2 = sign(&sk, &msg);
        sig2[0] ^= 0x01; // 篡改 R
        assert!(verify(&tagged_pk_of(&sk), &sig2, &msg).is_err());
        // 长度错误
        assert!(verify(&tagged_pk_of(&sk), &sig2[..63], &msg).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let msg = [0x42u8; 32];
        let sig = sign(&sk_of("0xabc"), &msg);
        // 另一把钥匙的公钥验不过
        assert!(verify(&tagged_pk_of(&sk_of("0xdef")), &sig, &msg).is_err());
    }

    #[test]
    fn verify_rejects_non_canonical_s() {
        let msg = [0x42u8; 32];
        let sk = sk_of("0xabc");
        let sig = sign(&sk, &msg);
        // s = 群阶（≥ n，非规范化）必须被 from_canonical_bytes 拒绝。
        let ec_order =
            hex::decode("0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f")
                .unwrap();
        let mut bad = [0u8; SIGNATURE_LEN];
        bad[..32].copy_from_slice(&sig[..32]);
        bad[32..].copy_from_slice(&ec_order);
        assert!(verify(&tagged_pk_of(&sk), &bad, &msg).is_err());
    }

    #[test]
    fn deterministic_nonce_reproduces_signature() {
        let msg = [0x42u8; 32];
        let sk = sk_of("0xabc");
        assert_eq!(sign(&sk, &msg), sign(&sk, &msg));
    }

    #[test]
    fn tag_encoding_stark_v1() {
        assert_eq!(encode_tag(SignatureScheme::Stark, 1), 0x21);
        assert_eq!(
            TaggedPubkey::parse_tag(0x21).unwrap(),
            (SignatureScheme::Stark, 1)
        );
    }
}
