//! 常数时间比较工具（IMPL-SEC-1）
//!
//! `subtle` crate 的 `ConstantTimeLess` 仅对整数类型实现，未对 `[u8; N]` 实现。
//! 本模块提供 32 字节 big-endian 无符号整数的常数时间 less-than / equal 比较，
//! 供 secp256k1 low-s 校验与 ed25519 canonical 校验共享。
//!
//! 实现：将 32 字节拆为 4 个 u64 chunk，逐 chunk 用 `subtle::ConstantTimeLess`
//! 与 `ConstantTimeEq` 组合，全程无数据依赖分支。

use subtle::{ConstantTimeEq as _, ConstantTimeLess as _};

/// 常数时间比较：a < b（big-endian 32 字节无符号整数）。
///
/// 返回 `bool`（内部已 unwrap `Choice`）。
pub fn ct_lt_be32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let a0 = u64::from_be_bytes(a[0..8].try_into().unwrap());
    let a1 = u64::from_be_bytes(a[8..16].try_into().unwrap());
    let a2 = u64::from_be_bytes(a[16..24].try_into().unwrap());
    let a3 = u64::from_be_bytes(a[24..32].try_into().unwrap());
    let b0 = u64::from_be_bytes(b[0..8].try_into().unwrap());
    let b1 = u64::from_be_bytes(b[8..16].try_into().unwrap());
    let b2 = u64::from_be_bytes(b[16..24].try_into().unwrap());
    let b3 = u64::from_be_bytes(b[24..32].try_into().unwrap());

    let lt0 = a0.ct_lt(&b0);
    let lt1 = a1.ct_lt(&b1);
    let lt2 = a2.ct_lt(&b2);
    let lt3 = a3.ct_lt(&b3);
    let eq0 = a0.ct_eq(&b0);
    let eq1 = a1.ct_eq(&b1);
    let eq2 = a2.ct_eq(&b2);

    // a < b = lt0 | (eq0 & lt1) | (eq0 & eq1 & lt2) | (eq0 & eq1 & eq2 & lt3)
    let result = lt0 | (eq0 & lt1) | (eq0 & eq1 & lt2) | (eq0 & eq1 & eq2 & lt3);
    bool::from(result)
}

/// 常数时间比较：a == b（big-endian 32 字节无符号整数）。
///
/// 返回 `bool`（内部已 unwrap `Choice`）。
pub fn ct_eq_be32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    // 直接逐字节异或后 OR，再取反；subtle 对 [u8] 有 ct_eq 但返回 Choice，
    // 这里保持与 ct_lt_be32 一致的接口。
    let a0 = u64::from_be_bytes(a[0..8].try_into().unwrap());
    let a1 = u64::from_be_bytes(a[8..16].try_into().unwrap());
    let a2 = u64::from_be_bytes(a[16..24].try_into().unwrap());
    let a3 = u64::from_be_bytes(a[24..32].try_into().unwrap());
    let b0 = u64::from_be_bytes(b[0..8].try_into().unwrap());
    let b1 = u64::from_be_bytes(b[8..16].try_into().unwrap());
    let b2 = u64::from_be_bytes(b[16..24].try_into().unwrap());
    let b3 = u64::from_be_bytes(b[24..32].try_into().unwrap());

    let eq = a0.ct_eq(&b0) & a1.ct_eq(&b1) & a2.ct_eq(&b2) & a3.ct_eq(&b3);
    bool::from(eq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lt_basic() {
        let a = [0u8; 32];
        let b = [1u8; 32];
        assert!(ct_lt_be32(&a, &b));
        assert!(!ct_lt_be32(&b, &a));
        assert!(!ct_lt_be32(&a, &a));
    }

    #[test]
    fn lt_high_byte_dominates() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 0x01;
        b[31] = 0xFF;
        // a = 0x01000...0 > b = 0x0000...FF
        assert!(ct_lt_be32(&b, &a));
        assert!(!ct_lt_be32(&a, &b));
    }

    #[test]
    fn lt_secp_n_half_boundary() {
        // s = n/2 应被接受（low-s），s = n/2 + 1 应被拒绝（high-s）
        let n_half: [u8; 32] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46,
            0x68, 0x1B, 0x20, 0xA0,
        ];
        let mut s_plus_one = n_half;
        // big-endian + 1
        for i in (0..32).rev() {
            if s_plus_one[i] == 0xFF {
                s_plus_one[i] = 0;
            } else {
                s_plus_one[i] += 1;
                break;
            }
        }
        // n/2 < n/2 + 1 → true
        assert!(ct_lt_be32(&n_half, &s_plus_one));
        // n/2 < n/2 → false
        assert!(!ct_lt_be32(&n_half, &n_half));
    }

    #[test]
    fn eq_basic() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        let c = [0x43u8; 32];
        assert!(ct_eq_be32(&a, &b));
        assert!(!ct_eq_be32(&a, &c));
    }
}
