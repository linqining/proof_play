//! Keccak-256 via Starknet's native keccak builtin (docs/design/DUAL_PROOF_PROTOCOL.md
//! v2.3, §4.2 transcript replay).
//!
//! The `keccak_syscall` absorbs pre-padded 1088-bit blocks (17 little-endian
//! u64 words); the caller applies pad10*1 with the legacy 0x01 leading byte.
//! One syscall covers any message length (multi-block input is absorbed
//! internally), so a full Keccak-256 costs a handful of steps regardless of
//! transcript size.
//!
//! Byte-order convention (must match `Secp256k1Curve::hash_to_scalar` in
//! Rust): the returned `u256` is the digest's little-endian integer
//! interpretation; challenge scalars are that value reduced mod n, which is
//! a single `u256 % n` here.

use core::starknet::syscalls::keccak_syscall;

/// secp256k1 group order n.
pub const SECP256K1_N: u256 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

const RATE: u32 = 136;
const BLOCK_WORDS: u32 = 17;

/// Complete legacy Keccak-256 over raw bytes, as a little-endian u256.
pub fn keccak256(message: Span<u8>) -> u256 {
    let len = message.len();

    // pad10*1 with leading 0x01: smallest multiple of RATE >= len + 1.
    let mut padded_len = len + 1;
    let rem = padded_len % RATE;
    if rem != 0 {
        padded_len += RATE - rem;
    }

    let mut padded: Array<u8> = array![];
    let mut i: u32 = 0;
    while i < len {
        padded.append(*message.at(i));
        i += 1;
    }
    if padded_len == len + 1 {
        // The single pad byte is also the final byte: 0x01 | 0x80.
        padded.append(0x81);
    } else {
        padded.append(0x01);
        while padded.len() < padded_len - 1 {
            padded.append(0);
        }
        padded.append(0x80);
    }

    // 17 little-endian u64 words per 136-byte block.
    let mut words: Array<u64> = array![];
    let mut block: u32 = 0;
    while block < padded_len / RATE {
        let base = block * RATE;
        let mut w: u32 = 0;
        while w < BLOCK_WORDS {
            let byte_base = base + w * 8;
            let mut word: u64 = 0;
            let mut b: u32 = 0;
            while b < 8 {
                let byte: u64 = (*padded.at(byte_base + b)).into();
                let scale: u64 = pow256_u64(b).into();
                word += byte * scale;
                b += 1;
            }
            words.append(word);
            w += 1;
        }
        block += 1;
    }

    match keccak_syscall(words.span()) {
        Result::Ok(hash) => hash,
        Result::Err(_) => 0,
    }
}

/// Challenge scalar: keccak digest interpreted as a little-endian integer,
/// reduced mod n. Matches `Secp256k1Curve::hash_to_scalar` in Rust.
pub fn challenge_mod_n(message: Span<u8>) -> u256 {
    keccak256(message) % SECP256K1_N
}

/// u256 → 32 little-endian bytes.
pub fn u256_to_le_bytes(value: u256) -> Array<u8> {
    let mut out: Array<u8> = array![];
    append_u128_le(ref out, value.low);
    append_u128_le(ref out, value.high);
    out
}

/// u128 → 16 little-endian bytes, appended.
fn append_u128_le(ref out: Array<u8>, value: u128) {
    let mut i: u32 = 0;
    while i < 16 {
        let byte: u8 = ((value / pow2_u128(8 * i)) & 0xFF).try_into().expect('low byte');
        out.append(byte);
        i += 1;
    }
}

/// u256 → 32 big-endian bytes.
pub fn u256_to_be_bytes(value: u256) -> Array<u8> {
    let mut out: Array<u8> = array![];
    append_u128_be(ref out, value.high);
    append_u128_be(ref out, value.low);
    out
}

fn append_u128_be(ref out: Array<u8>, value: u128) {
    let mut i: u32 = 0;
    while i < 16 {
        let byte: u8 = ((value / pow2_u128(120 - 8 * i)) & 0xFF).try_into().expect('low byte');
        out.append(byte);
        i += 1;
    }
}

/// u32 → 4 little-endian bytes, appended.
pub fn append_u32_le(ref out: Array<u8>, value: u32) {
    let mut i: u32 = 0;
    while i < 4 {
        let byte: u8 = ((value / pow256_u32(i)) & 0xFF).try_into().expect('low byte');
        out.append(byte);
        i += 1;
    }
}

/// 256^i in the u64 domain (i < 8).
#[inline(always)]
fn pow256_u64(i: u32) -> u64 {
    let mut result: u64 = 1;
    let mut j: u32 = 0;
    while j < i {
        result *= 256;
        j += 1;
    }
    result
}

#[inline(always)]
fn pow256_u32(i: u32) -> u32 {
    let mut result: u32 = 1;
    let mut j: u32 = 0;
    while j < i {
        result *= 256;
        j += 1;
    }
    result
}

#[inline(always)]
fn pow2_u128(k: u32) -> u128 {
    let mut result: u128 = 1;
    let mut j: u32 = 0;
    while j < k {
        result *= 2;
        j += 1;
    }
    result
}

#[cfg(target: 'test')]
mod tests {
    use super::*;

    fn bytes(values: Array<u8>) -> Span<u8> {
        values.span()
    }

    #[test]
    fn keccak256_empty_nist_vector() {
        // Keccak-256("") — legacy keccak, not SHA3. The builtin returns the
        // digest as a little-endian u256.
        let empty: Array<u8> = array![];
        let expected = 0x70a4855d04d8fa7b3b2782ca53b600e5c003c7dcb27d7e923c23f7860146d2c5;
        assert!(keccak256(bytes(empty)) == expected, "empty input vector");
    }

    #[test]
    fn keccak256_abc_vector() {
        // Keccak-256("abc") — little-endian u256 interpretation.
        let abc: Array<u8> = array![0x61, 0x62, 0x63];
        let expected = 0x456c2da18ff544ec36a0643ae3e6d1c067d6c826a87bd4c74fa945ea7a65034e;
        assert!(keccak256(bytes(abc)) == expected, "abc vector");
    }

    #[test]
    fn challenge_reduces_mod_n() {
        // A challenge of all-ones must reduce below n.
        let mut ones: Array<u8> = array![];
        let mut i: u32 = 0;
        while i < 32 {
            ones.append(0xff);
            i += 1;
        }
        let challenge = challenge_mod_n(bytes(ones));
        assert!(challenge < SECP256K1_N, "challenge reduced mod n");
    }
}
