//! Felt252 —— Starknet 域（p = 2^251 + 17·2^192 + 1）的 arkworks 载体。
//!
//! 电路侧所有 felt252 运算发生在 [`Felt252`]；约束生成在 BN254 Fr 上以
//! ark-r1cs-std 非原生（emulated）算术完成。编码无损性：p_felt < 2^252 <
//! r_BN254（254 bit），每个 felt252 恰好装进一个 Fr 标量，公开输入即可用
//! 单个 Fr 变量承载（见 `wrap_circuit` 的绑定约束）。

use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use ark_ff::{BigInteger, BigInteger256, PrimeField, Zero};

/// Starknet 域配置（derive 生成 MontBackend 实例；generator=3 为该域的
/// 乘法生成元——本 crate 不使用 FFT 根，该值仅满足配置完整性）。
#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[generator = "3"]
pub struct Felt252Config;

/// Starknet felt252（p = 2^251 + 17·2^192 + 1）。
pub type Felt252 = Fp256<MontBackend<Felt252Config, 4>>;

/// BN254 标量域（Groth16 电路的约束域与公开输入域）。
pub type Fr = ark_bn254::Fr;

/// `0x` 可选前缀的 felt 十六进制解析（大小写不敏感；奇数位自动补前导 0）。
///
/// # Errors
/// 非法 hex 字符串。
pub fn felt_from_hex(s: &str) -> anyhow::Result<Felt252> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.is_empty() {
        return Ok(Felt252::zero());
    }
    let padded = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_string() };
    let bytes = hex::decode(&padded)?;
    Ok(Felt252::from_be_bytes_mod_order(&bytes))
}

/// felt 的 32 字节大端表示（与 starknet Felt 的 wire 格式一致）。
#[must_use]
pub fn felt_to_be_bytes(f: &Felt252) -> [u8; 32] {
    let mut out = [0u8; 32];
    let le = f.into_bigint().to_bytes_le();
    out.copy_from_slice(&le);
    out.reverse();
    out
}

/// felt 的 `0x…` 十六进制（"0x" + 64 位小写 hex，齐零填充）。
#[must_use]
pub fn felt_to_hex(f: &Felt252) -> String {
    format!("0x{}", hex::encode(felt_to_be_bytes(f)))
}

/// felt252 → BN254 Fr：数值恒等映射（felt < 2^252 < r，模归约不发生）。
#[must_use]
pub fn felt_to_fr(f: &Felt252) -> Fr {
    // 两个域同为 4×64 位 limb 的 BigInteger256，位模式即数值，直接搬运。
    Fr::from_bigint(f.into_bigint())
        .unwrap_or_else(|| unreachable!("felt252 < 2^252 < r_BN254，from_bigint 不可能失败"))
}

/// BN254 Fr → felt252（取模意义下的代表元；调用方保证值 < 2^252）。
///
/// # Errors
/// 值 ≥ p_felt 时（不该发生在本协议的合法语句里）。
pub fn fr_to_felt(x: &Fr) -> anyhow::Result<Felt252> {
    Felt252::from_bigint(x.into_bigint())
        .ok_or_else(|| anyhow::anyhow!("Fr value does not fit in felt252"))
}

/// Fr 的 `0x…` 十六进制（"0x" + 64 位小写 hex，齐零填充）。
#[must_use]
pub fn fr_to_hex(x: &Fr) -> String {
    let mut out = [0u8; 32];
    let le = x.into_bigint().to_bytes_le();
    out.copy_from_slice(&le);
    out.reverse();
    format!("0x{}", hex::encode(out))
}

/// `0x…` 十六进制 → Fr（mod r 归约；调用方保证源值是 felt252）。
///
/// # Errors
/// 非法 hex 字符串。
pub fn fr_from_hex(s: &str) -> anyhow::Result<Fr> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(s)?;
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

/// BN254 基域元素 → `0x…` 十六进制（32 字节大端，G1/G2 坐标用）。
#[must_use]
pub fn fq_to_hex(x: &ark_bn254::Fq) -> String {
    bigint_to_hex(&x.into_bigint())
}

/// 任意 ark BigInteger256 → 32 字节大端 `0x…` hex。
#[must_use]
pub fn bigint_to_hex(bigint: &BigInteger256) -> String {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bigint.to_bytes_le());
    out.reverse();
    format!("0x{}", hex::encode(out))
}

/// `0x…` hex → BN254 基域元素（G1/G2 坐标解析用）。
///
/// # Errors
/// 非法 hex。
pub fn fq_from_hex(s: &str) -> anyhow::Result<ark_bn254::Fq> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(s)?;
    Ok(ark_bn254::Fq::from_be_bytes_mod_order(&bytes))
}

/// starknet-crypto Felt（starknet-types-core 载体）→ ark Felt252。
#[must_use]
pub fn felt_from_starknet(f: &starknet_crypto::Felt) -> Felt252 {
    Felt252::from_be_bytes_mod_order(&f.to_bytes_be())
}

/// ark Felt252 → starknet-crypto Felt。
#[must_use]
pub fn felt_to_starknet(f: &Felt252) -> starknet_crypto::Felt {
    starknet_crypto::Felt::from_bytes_be(&felt_to_be_bytes(f))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    #[test]
    fn modulus_is_stark_prime() {
        // p = 2^251 + 17·2^192 + 1（数值恒等式自证：逐项构造的 p 值 ≡ 0）
        let two = Felt252::from(2u64);
        let p = two.pow([251u64]) + Felt252::from(17u64) * two.pow([192u64, 0]) + Felt252::from(1u64);
        assert_eq!(p, Felt252::zero(), "characteristic must equal 2^251 + 17·2^192 + 1");
        // 2^251 的字节形态：最高字节（大端首位）= 0x08
        let top = felt_to_be_bytes(&two.pow([251u64]));
        assert_eq!(top[0], 0x08);
        assert!(top[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn hex_roundtrip_padded() {
        let f = felt_from_hex("0x5350324d5f4f4b").unwrap();
        assert_eq!(felt_to_hex(&f), format!("0x{:0>64}", "5350324d5f4f4b"));
        assert_eq!(felt_from_hex(&felt_to_hex(&f)).unwrap(), f);
        assert_eq!(felt_from_hex("0x0").unwrap(), Felt252::zero());
        assert_eq!(felt_to_hex(&Felt252::zero()), format!("0x{}", "0".repeat(64)));
    }

    #[test]
    fn felt_fr_roundtrip_is_lossless() {
        for hex in [
            "0x0",
            "0x1",
            "0x5350324d5f4f4b",
            // 主网钉扎的 settlement 电路程序哈希
            "0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4",
            // p_felt - 1（< 2^252 的最大域元素）
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            let f = felt_from_hex(hex).unwrap();
            let fr = felt_to_fr(&f);
            assert_eq!(fr_to_felt(&fr).unwrap(), f, "roundtrip must be lossless for {hex}");
            // hex 层面对拍
            assert_eq!(fr_to_hex(&felt_to_fr(&felt_from_hex(hex).unwrap())), felt_to_hex(&f));
        }
    }

    #[test]
    fn starknet_felt_bridge() {
        let s = starknet_crypto::Felt::from_hex("0x1234").unwrap();
        let f = felt_from_starknet(&s);
        assert_eq!(felt_to_starknet(&f), s);
    }
}
