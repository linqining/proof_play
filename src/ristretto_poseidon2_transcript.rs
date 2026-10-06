//! Poseidon2-M31 native Fiat--Shamir transcript (Flock-elimination).
//!
//! A fourth [`CryptoTranscript`] implementation whose entire state machine
//! is M31-native: the sponge state is the [`crate::ristretto_poseidon2_air`]
//! 16-lane Poseidon2 permutation, message absorption adds framed 31-bit
//! limbs into the rate lanes, and challenges squeeze two permutations
//! (496 bits, truncated to 256) before rejection sampling against the
//! group order — the same discipline as [`crate::ristretto_shuffle_air::
//! FlockShuffleTranscript`], minus the binary-field Flock sidecar.
//!
//! Every absorb-and-permute step is recorded as a public word vector, so
//! the whole transcript run is one [`Poseidon2ChainSpec`] that folds into
//! the unified admission STARK's Poseidon2 segment: the statement digest
//! pins the schedule, the segment's LogUp pins every intermediate state,
//! and the Flock archive disappears from this path.  Native verification
//! replays the same deterministic schedule and compares states.

use poker_protocol_core::transcript::CryptoTranscript;
use poker_protocol_core::{Curve, CurvePoint, CurveScalar};

use stwo::core::fields::m31::M31;

use crate::ristretto_poseidon2_air::{
    N_RATE_LANES, N_STATE, Poseidon2ChainSpec, absorb_and_permute,
};

/// Domain tag mixed into the initial state derivation.
pub const POSEIDON2_TRANSCRIPT_DOMAIN: &[u8] = b"zchain.texas.poseidon2-transcript.v1";
/// Squeeze domain tag, absorbed as the first limbs of every challenge step.
const POSEIDON2_CHALLENGE_TAG: &[u8] = b"zchain.texas.poseidon2-challenge";

/// Little-endian group order (Ristretto255 scalar field), for rejection
/// sampling of 256-bit challenge images.
const GROUP_ORDER_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10,
];

fn scalar_magnitude_ok(bytes: &[u8; 32]) -> bool {
    for index in (0..32).rev() {
        match bytes[index].cmp(&GROUP_ORDER_BYTES[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
}

const fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

const fn to_m31_bits(value: u64) -> u32 {
    let modulus = (1u64 << 31) - 1;
    let folded = (value & modulus) + (value >> 31);
    let folded = (folded & modulus) + (folded >> 31);
    (folded % modulus) as u32
}

/// FNV-1a over the byte stream, then a splitmix chain: deterministic,
/// public, dependency-free initial-state derivation.
fn derive_initial_state(protocol_name: &[u8]) -> [u32; N_STATE] {
    let mut seed = 0xcbf2_9ce4_8422_2325u64;
    for byte in POSEIDON2_TRANSCRIPT_DOMAIN.iter().chain(protocol_name) {
        seed ^= *byte as u64;
        seed = seed.wrapping_mul(0x1000_0000_01b3);
    }
    core::array::from_fn(|_| {
        seed = splitmix64(seed);
        to_m31_bits(seed)
    })
}

/// Pack a byte stream into 31-bit limbs (three little-endian bytes per
/// limb, so every limb is a canonical M31 element).
fn pack_limbs(bytes: &[u8]) -> Vec<M31> {
    bytes
        .chunks(3)
        .map(|chunk| {
            let mut value = 0u32;
            for (shift, byte) in chunk.iter().enumerate() {
                value |= (*byte as u32) << (8 * shift);
            }
            M31::from_u32_unchecked(value)
        })
        .collect()
}

/// The Poseidon2-M31 transcript state machine.
#[derive(Debug, Clone)]
pub struct Poseidon2M31Transcript {
    state: [M31; N_STATE],
    initial_state: [u32; N_STATE],
    /// Framed absorb limbs not yet consumed by a permutation step.
    pending: Vec<M31>,
    /// Every step's absorbed word vector (the public chain schedule).
    words: Vec<[u32; N_RATE_LANES]>,
    /// Accepted challenge images, in derivation order (the wire record a
    /// verifier replays against).
    challenge_images: Vec<[u8; 32]>,
    /// Rejection-sampling retries consumed per accepted challenge image.
    challenge_retries: Vec<u32>,
    /// Number of challenges derived so far (challenge ordinal).
    challenges: usize,
}

impl Poseidon2M31Transcript {
    /// Build a transcript over a domain-separated initial state.
    pub fn new(protocol_name: &[u8]) -> Self {
        let initial_state = derive_initial_state(protocol_name);
        Self {
            state: core::array::from_fn(|i| M31::from_u32_unchecked(initial_state[i])),
            initial_state,
            pending: Vec::new(),
            words: Vec::new(),
            challenge_images: Vec::new(),
            challenge_retries: Vec::new(),
            challenges: 0,
        }
    }

    /// The accepted challenge images, in derivation order.
    pub fn challenge_images(&self) -> &[[u8; 32]] {
        &self.challenge_images
    }

    /// Rejection-sampling retries consumed per accepted challenge image.
    pub fn challenge_retries(&self) -> &[u32] {
        &self.challenge_retries
    }

    /// The transcript's current state limbs (for digesting callers).
    pub fn state_limbs(&self) -> [u32; N_STATE] {
        core::array::from_fn(|i| self.state[i].0)
    }

    /// One absorb-and-permute step over the next eight pending limbs
    /// (zero-padded), recording the public word vector.
    fn step(&mut self, limbs: Vec<M31>) {
        let mut words = [0u32; N_RATE_LANES];
        for (lane, limb) in limbs.iter().take(N_RATE_LANES).enumerate() {
            words[lane] = limb.0;
        }
        absorb_and_permute(&mut self.state, &words);
        self.words.push(words);
    }

    fn flush_pending(&mut self) {
        while self.pending.len() > N_RATE_LANES {
            let limbs: Vec<M31> = self.pending.drain(..N_RATE_LANES).collect();
            self.step(limbs);
        }
        let rest: Vec<M31> = self.pending.drain(..).collect();
        self.step(rest);
    }

    /// Squeeze a 256-bit challenge image: absorb the framed challenge
    /// label (with ordinal and retry counters), permute twice, and read
    /// the first nine state lanes (279 ≥ 256 bits).
    fn derive_challenge_image(&mut self, label: &[u8]) -> [u8; 32] {
        self.flush_pending();
        let ordinal = self.challenges as u32;
        let mut retry = 0u32;
        loop {
            let mut framed = Vec::with_capacity(64 + label.len());
            framed.extend_from_slice(POSEIDON2_CHALLENGE_TAG);
            framed.extend_from_slice(&ordinal.to_le_bytes());
            framed.extend_from_slice(&retry.to_le_bytes());
            framed.extend_from_slice(&(label.len() as u32).to_le_bytes());
            framed.extend_from_slice(label);
            let limbs = pack_limbs(&framed);
            let first: Vec<M31> = limbs.iter().take(N_RATE_LANES).cloned().collect();
            let second: Vec<M31> = limbs.iter().skip(N_RATE_LANES).cloned().collect();
            self.step(first);
            self.step(second);
            let mut image = [0u8; 32];
            let mut filled = 0usize;
            for lane in 0..N_STATE {
                let bytes = self.state[lane].0.to_le_bytes();
                // 31 significant bits per lane: take three full bytes plus
                // the low seven bits of the fourth.
                for byte in bytes.iter().take(3) {
                    if filled < 32 {
                        image[filled] = *byte;
                        filled += 1;
                    }
                }
                if filled < 32 {
                    image[filled] = bytes[3] & 0x7f;
                    filled += 1;
                }
                if filled == 32 {
                    break;
                }
            }
            debug_assert_eq!(filled, 32);
            if image != [0u8; 32] && scalar_magnitude_ok(&image) {
                self.challenges += 1;
                self.challenge_images.push(image);
                self.challenge_retries.push(retry);
                return image;
            }
            retry = retry
                .checked_add(1)
                .expect("challenge rejection sampling cannot overflow u32 retries");
        }
    }

    /// The full transcript run as a foldable chain statement.
    pub fn into_chain_spec(self) -> Poseidon2ChainSpec {
        let chain_length = self.words.len() as u32;
        Poseidon2ChainSpec {
            initial_states: vec![self.initial_state],
            absorbed_words: self.words,
            chain_length,
        }
    }

    /// Borrow the chain schedule without consuming the transcript.
    pub fn chain_spec(&self) -> Poseidon2ChainSpec {
        Poseidon2ChainSpec {
            initial_states: vec![self.initial_state],
            absorbed_words: self.words.clone(),
            chain_length: self.words.len() as u32,
        }
    }
}

/// M31-native root over a list of 16-limb chain digests: absorb each
/// digest and squeeze 32 bytes.  This is the hand-transcript root that
/// tags a whole-hand admission statement.
pub fn poseidon2_root(digests: &[[u32; N_STATE]]) -> [u8; 32] {
    let mut transcript = Poseidon2M31Transcript::new(b"zchain.texas.poseidon2-hand-root");
    for digest in digests {
        let mut bytes = [0u8; 4 * N_STATE];
        for (index, limb) in digest.iter().enumerate() {
            bytes[4 * index..4 * index + 4].copy_from_slice(&limb.to_le_bytes());
        }
        transcript.append_message(b"digest", &bytes);
    }
    let mut root = [0u8; 32];
    transcript.challenge_bytes(b"root", &mut root);
    root
}

impl CryptoTranscript for Poseidon2M31Transcript {
    fn new(protocol_name: &[u8]) -> Self {
        Self::new(protocol_name)
    }

    fn append_message(&mut self, label: &[u8], message: &[u8]) {
        let mut framed = Vec::with_capacity(8 + label.len() + message.len());
        framed.extend_from_slice(&(label.len() as u32).to_le_bytes());
        framed.extend_from_slice(label);
        framed.extend_from_slice(&(message.len() as u32).to_le_bytes());
        framed.extend_from_slice(message);
        self.pending.extend(pack_limbs(&framed));
    }

    fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            let image = self.derive_challenge_image(label);
            chunk.copy_from_slice(&image[..chunk.len()]);
        }
    }

    fn append_point<C: Curve>(&mut self, label: &[u8], point: &C::Point) {
        self.append_message(label, point.compress().as_ref());
    }

    fn append_scalar<C: Curve>(&mut self, label: &[u8], scalar: &C::Scalar) {
        self.append_message(label, &scalar.as_bytes());
    }

    fn challenge<C: Curve>(&mut self, label: &[u8]) -> poker_protocol_core::Challenge<C> {
        let image = self.derive_challenge_image(label);
        let scalar = C::Scalar::from_canonical_bytes(&image)
            .expect("rejection sampling accepted only canonical images");
        poker_protocol_core::Challenge { scalar }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_protocol::crypto::curve::RistrettoCurve;

    #[test]
    fn transcript_is_deterministic_and_label_sensitive() {
        let run = |label: &[u8]| {
            let mut transcript = Poseidon2M31Transcript::new(b"poker/ristretto-air/v2/test");
            transcript.append_message(b"context", b"hand-1-seat-0");
            transcript.append_message(label, b"commitment");
            let challenge = transcript.challenge::<RistrettoCurve>(b"challenge");
            (challenge.scalar.as_bytes().to_vec(), transcript.chain_spec())
        };
        let (bytes_a, spec_a) = run(b"alpha");
        let (bytes_b, spec_b) = run(b"alpha");
        let (bytes_c, spec_c) = run(b"beta");
        assert_eq!(bytes_a, bytes_b);
        assert_eq!(spec_a, spec_b);
        assert_ne!(bytes_a, bytes_c);
        assert_ne!(spec_a.absorbed_words, spec_c.absorbed_words);
    }

    #[test]
    fn chain_spec_digests_match_final_state() {
        let mut transcript = Poseidon2M31Transcript::new(b"poker/ristretto-air/v2/test");
        transcript.append_message(b"context", b"recursion-hand1-seat0");
        transcript.append_message(b"pk", &[7u8; 32]);
        let _ = transcript.challenge::<RistrettoCurve>(b"challenge");
        let spec = transcript.chain_spec();
        spec.validate().expect("shape");
        let digest = spec.digests()[0];
        assert_eq!(digest, transcript.state_limbs());
        assert!(spec.chain_length >= 2);
    }

    #[test]
    fn distinct_protocols_diverge() {
        let challenge = |name: &[u8]| {
            let mut transcript = Poseidon2M31Transcript::new(name);
            transcript.append_message(b"context", b"same");
            transcript.challenge::<RistrettoCurve>(b"challenge")
        };
        assert_ne!(
            challenge(b"poker/ownership").scalar.as_bytes(),
            challenge(b"poker/reveal").scalar.as_bytes()
        );
    }
}
