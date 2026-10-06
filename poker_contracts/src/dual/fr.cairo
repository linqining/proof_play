//! secp256k1 scalar-field (Fr) arithmetic mod n in Cairo
//! (docs/design/DUAL_PROOF_PROTOCOL.md — BG shuffle on-chain verification).
//!
//! Multiplication rides `core::math::u256_mul_mod_n` (512-bit safe division
//! under the hood); addition/subtraction are one conditional correction each.
//! All values are canonical (`< n`), matching the Rust wire encoding
//! (32-byte big-endian scalars interpreted as integers).

use core::math::u256_mul_mod_n;
use core::num::traits::Zero;

/// The secp256k1 group order n.
pub const SECP256K1_N: u256 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

/// `2^256 − n` (used to fold the addition carry back into the field).
const TWO256_MINUS_N: u256 = 0x14551231950b75fc4402da1732fc9bebf;

/// Non-zero wrapper for n (infallible: n is prime).
fn nz_n() -> NonZero<u256> {
    let nz: Option<NonZero<u256>> = SECP256K1_N.try_into();
    match nz {
        Option::Some(value) => value,
        Option::None => core::panic_with_felt252(0),
    }
}

const U256_MAX: u256 = u256 { high: 0xffffffffffffffffffffffffffffffff_u128, low: 0xffffffffffffffffffffffffffffffff_u128 };

/// `a + b mod n` for canonical inputs. Overflow of the raw u256 addition is
/// detected by comparison first (Cairo's `+` panics on overflow); the
/// correction `wrapped + (2^256 − n)` provably stays below 2^256 because
/// the true sum is below 2n.
pub fn fr_add(a: u256, b: u256) -> u256 {
    if a > U256_MAX - b {
        // True sum = a + b = wrapped + 2^256 with wrapped = a + b − 2^256.
        // u256 subtraction gives a − (U256_MAX − b) = wrapped + 1 (since
        // U256_MAX = 2^256 − 1), so subtract the unit back; the guard makes
        // the intermediate at least 1, keeping the subtraction in range.
        let wrapped = a - (U256_MAX - b) - 1;
        let reduced = wrapped + TWO256_MINUS_N; // = sum − n, no overflow
        if reduced >= SECP256K1_N {
            reduced - SECP256K1_N
        } else {
            reduced
        }
    } else {
        let sum = a + b;
        if sum >= SECP256K1_N {
            sum - SECP256K1_N
        } else {
            sum
        }
    }
}

/// `a − b mod n` for canonical inputs.
pub fn fr_sub(a: u256, b: u256) -> u256 {
    if a >= b {
        a - b
    } else {
        // a − b + n; a < n and b > a ⇒ a + (n − b) < n, no overflow.
        a + (SECP256K1_N - b)
    }
}

/// `a · b mod n`.
pub fn fr_mul(a: u256, b: u256) -> u256 {
    u256_mul_mod_n(a, b, nz_n())
}

/// Negation `−a mod n` (canonical input; zero maps to zero).
pub fn fr_neg(a: u256) -> u256 {
    if a.is_zero() {
        0
    } else {
        SECP256K1_N - a
    }
}

/// A small integer as a field element.
pub fn fr_from_u64(value: u64) -> u256 {
    u256 { low: value.into(), high: 0 }
}

#[cfg(target: 'test')]
mod tests {
    use super::*;

    #[test]
    fn fr_add_small_values() {
        let a: u256 = 0x1234567890abcdef1234567890abcdef_u128.into();
        let sum = fr_add(a, fr_from_u64(7));
        let expected: u256 = a + fr_from_u64(7);
        assert!(sum == expected, "add exact");
    }

    #[test]
    fn fr_add_carry_wrap() {
        assert!(fr_add(SECP256K1_N - 1, fr_from_u64(2)) == 1, "carry wrap");
    }

    #[test]
    fn fr_add_reduce() {
        assert!(
            fr_add(SECP256K1_N - 1, SECP256K1_N - 1) == SECP256K1_N - 2,
            "reduce"
        );
    }

    #[test]
    fn fr_sub_back() {
        let a: u256 = 0x1234567890abcdef1234567890abcdef_u128.into();
        let sum = fr_add(a, fr_from_u64(7));
        assert!(fr_sub(sum, fr_from_u64(7)) == a, "sub back");
    }

    #[test]
    fn fr_mul_matches_small_cases() {
        // 6·7 = 42
        assert!(fr_mul(fr_from_u64(6), fr_from_u64(7)) == fr_from_u64(42), "small");
        // (n−1)·(n−1) = 1 mod n
        assert!(fr_mul(SECP256K1_N - 1, SECP256K1_N - 1) == 1, "neg squared");
    }
}
