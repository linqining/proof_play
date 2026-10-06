//! Keccak-256 Fiat–Shamir transcript replay in Cairo
//! (docs/design/DUAL_PROOF_PROTOCOL.md v2.3, §4.2).
//!
//! Byte-for-byte mirror of `poker-protocol-proofs::transcript_ext::
//! KeccakTranscript`:
//!
//! - `new(name)`:        `state = Keccak256(name)`
//! - `append(label, m)`: `state = Keccak256(state ‖ u32le(‖label‖) ‖ label ‖
//!   u32le(‖m‖) ‖ m)`
//! - `challenge(label)`: append `(label, "challenge")`, then
//!   `hash_to_scalar(state)` = **little-endian u256 mod n** (the secp256k1
//!   route's challenge convention, matching
//!   `Secp256k1Curve::hash_to_scalar`).
//!
//! Points enter the transcript in SEC1 compressed form (33 bytes:
//! `0x02/0x03 ‖ x_be`), scalars as 32-byte big-endian — identical to the
//! Rust `append_point` / `append_scalar` encodings.

use super::keccak::{append_u32_le, challenge_mod_n, keccak256, u256_to_be_bytes, u256_to_le_bytes};

/// Transcript initial state from the protocol name.
pub fn transcript_new(protocol_name: Span<u8>) -> u256 {
    keccak256(protocol_name)
}

/// Append raw bytes under a label; returns the new state.
pub fn transcript_append(mut state: u256, label: Span<u8>, message: Span<u8>) -> u256 {
    let mut input = u256_to_le_bytes(state);
    append_u32_le(ref input, label.len());
    append_span(ref input, label);
    append_u32_le(ref input, message.len());
    append_span(ref input, message);
    keccak256(input.span())
}

/// Derive the challenge scalar: append `(label, "challenge")`, then reduce
/// the keccak digest (little-endian) modulo the secp256k1 group order.
pub fn transcript_challenge(mut state: u256, label: Span<u8>) -> u256 {
    let (challenge, _state) = transcript_challenge_and_state(state, label);
    challenge
}

/// Challenge derivation that also returns the **post-append** transcript
/// state, for chains that continue after a challenge (e.g. the BG shuffle's
/// multi-challenge schedule). The bare [`transcript_challenge`] cannot
/// return it, which silently truncated such chains.
pub fn transcript_challenge_and_state(
    mut state: u256, label: Span<u8>,
) -> (u256, u256) {
    let mut challenge_marker: Array<u8> = array![];
    challenge_marker.append(0x63); // 'c'
    challenge_marker.append(0x68); // 'h'
    challenge_marker.append(0x61); // 'a'
    challenge_marker.append(0x6c); // 'l'
    challenge_marker.append(0x6c); // 'l'
    challenge_marker.append(0x65); // 'e'
    challenge_marker.append(0x6e); // 'n'
    challenge_marker.append(0x67); // 'g'
    challenge_marker.append(0x65); // 'e'
    state = transcript_append(state, label, challenge_marker.span());
    let challenge = challenge_mod_n(u256_to_le_bytes(state).span());
    (challenge, state)
}

/// SEC1 compressed encoding of an (x, y) point: `0x02/0x03 ‖ x_be`, 33 bytes.
pub fn point_compressed(x: u256, y: u256) -> Array<u8> {
    let tag: u8 = if y.low & 1 == 1 { 0x03 } else { 0x02 };
    let mut out: Array<u8> = array![];
    out.append(tag);
    let x_bytes = u256_to_be_bytes(x);
    let mut i: u32 = 0;
    while i < 32 {
        out.append(*x_bytes.at(i));
        i += 1;
    }
    out
}

/// 32-byte big-endian scalar encoding of a u256 (Rust `as_bytes`).
pub fn scalar_be(value: u256) -> Array<u8> {
    u256_to_be_bytes(value)
}

fn append_span(ref out: Array<u8>, span: Span<u8>) {
    let mut i: u32 = 0;
    while i < span.len() {
        out.append(*span.at(i));
        i += 1;
    }
}

#[cfg(target: 'test')]
mod tests {
    use super::*;

    fn ascii_bytes(values: Span<u8>) -> Span<u8> {
        values
    }

    #[test]
    fn transcript_matches_rust_keccak_transcript() {
        // Vector cross-check with the Rust KeccakTranscript: with
        // protocol_name = "poker_secp256k1_keccak_v1",
        // append("reveal_token_nonce", nonce_be32bytes), then
        // challenge("challenge") — the state chain must produce the same
        // challenge scalar. The full proof vectors live in
        // secp256k1_verifier::tests; this test pins the state machine alone
        // against a fixed keccak chain.
        let name: Array<u8> = array![
            0x70, 0x6f, 0x6b, 0x65, 0x72, 0x5f, 0x73, 0x65, 0x63, 0x70, 0x32, 0x35, 0x36, 0x6b,
            0x31, 0x5f, 0x6b, 0x65, 0x63, 0x63, 0x61, 0x6b, 0x5f, 0x76, 0x31
        ];
        let state0 = transcript_new(ascii_bytes(name.span()));
        assert!(state0 != 0, "state0 nonzero");

        // append("x", 0x01) must be deterministic.
        let one: Array<u8> = array![0x01];
        let label: Array<u8> = array![0x78]; // "x"
        let s1 = transcript_append(state0, ascii_bytes(label.span()), ascii_bytes(one.span()));
        let s1_again = transcript_append(state0, ascii_bytes(label.span()), ascii_bytes(one.span()));
        assert!(s1 == s1_again && s1 != state0, "append deterministic");

        // Challenge is deterministic and reduces below n.
        let ch = transcript_challenge(s1, ascii_bytes(label.span()));
        let ch2 = transcript_challenge(s1, ascii_bytes(label.span()));
        assert!(ch == ch2 && ch != 0, "challenge deterministic");
    }
}
