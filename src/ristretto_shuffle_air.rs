//! RistrettoAirV2 shuffle: a complete, low-latency 52-card shuffle argument.
//!
//! # Why the permutation never enters a STARK trace
//!
//! A shuffle proof must hide `π` from every verifier, including the backend.
//! The Fp-program STARKs used elsewhere in this crate are transparent: the
//! witness rows are serialized into the archive and FRI openings reveal
//! queried trace cells, so any `π`-dependent witness would leak card
//! positions.  The V2 shuffle therefore keeps the permutation inside a
//! Bayer--Groth sigma argument (curve-generic implementation in
//! `poker-protocol-bg`), whose masked responses and Pedersen-style vector
//! commitments are honest-verifier zero-knowledge by construction.
//!
//! # What the AIR layer owns
//!
//! The only host-trust-sensitive part of a Fiat--Shamir shuffle is the
//! challenge schedule.  V2 derives every challenge from this project's
//! Flock-BLAKE3 chain digests ([`FlockShuffleTranscript`]): each transcript
//! state transition is a public `blake3_chain_digest` statement, and the
//! client attaches one Flock STARK covering those statements.  The server
//! re-derives the same schedule natively (it must hash the request anyway to
//! bind the statement), verifies the Bayer--Groth public-equation checks, and
//! verifies the Flock archive.  No custom host-side transcript or challenge
//! seed is trusted.
//!
//! # Cost profile
//!
//! Client proving is a handful of 52-way MSMs (milliseconds); the proof wire
//! is a few kilobytes; server verification is one 52-way MSM batch plus one
//! Flock STARK over roughly a dozen chain statements.  This replaces the
//! 104-scalar-multiplication Fp-program expansion (~35k wide trace rows) that
//! a direct "π in the AIR" encoding would require.

#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use rand_core::{CryptoRng, RngCore};

use poker_protocol::precompile_abi::{
    CurveId, ShuffleProofSystem, ShuffleVerifyRequest, TranscriptId,
};
use poker_protocol_bg::BayerGrothShuffleProof;
use poker_protocol_core::{
    CryptoTranscript, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, RistrettoCurve,
    VerificationError,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::{ArchivedHashProof, HashStatement, HashProofProvider};
use crate::ristretto_poseidon2_air::Poseidon2ChainSpec;
use crate::ristretto_poseidon2_transcript::Poseidon2M31Transcript;
/// Fixed 52-card deck size for the V2 Ristretto wire (was
/// `CANONICAL_RECONSTRUCTION_CARDS` in the retired reconstruction module).
pub const RISTRETTO_V2_DECK_CARDS: usize = 52;

/// Compressed ElGamal ciphertext on the V2 wire.
#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct RistrettoCiphertextProofWire {
    pub c1: [u8; 32],
    pub c2: [u8; 32],
}

impl Default for RistrettoCiphertextProofWire {
    fn default() -> Self {
        Self { c1: [0; 32], c2: [0; 32] }
    }
}

/// Fixed 52-card Bayer--Groth V2 public wire, represented with Ristretto
/// compressed points/scalars rather than legacy BLS serialisation.
#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct RistrettoBayerGrothShuffleProofWire {
    pub c_permutation: [u8; 32],
    pub c_permuted_powers: [u8; 32],
    pub c_alpha: [u8; 32],
    pub c_beta: [u8; 32],
    pub ciphertext_0: RistrettoCiphertextProofWire,
    pub ciphertext_1: RistrettoCiphertextProofWire,
    pub alpha_response: [[u8; 32]; RISTRETTO_V2_DECK_CARDS],
    pub commitment_response: [u8; 32],
    pub beta: [u8; 32],
    pub beta_blinding_response: [u8; 32],
    pub rerandomization_response: [u8; 32],
    pub c_d: [u8; 32],
    pub c_delta: [u8; 32],
    pub c_capital_delta: [u8; 32],
    pub a_response: [[u8; 32]; RISTRETTO_V2_DECK_CARDS],
    pub b_response: [[u8; 32]; RISTRETTO_V2_DECK_CARDS],
    pub r_response: [u8; 32],
    pub s_response: [u8; 32],
}

impl Default for RistrettoBayerGrothShuffleProofWire {
    fn default() -> Self {
        Self {
            c_permutation: [0; 32],
            c_permuted_powers: [0; 32],
            c_alpha: [0; 32],
            c_beta: [0; 32],
            ciphertext_0: RistrettoCiphertextProofWire::default(),
            ciphertext_1: RistrettoCiphertextProofWire::default(),
            alpha_response: [[0; 32]; RISTRETTO_V2_DECK_CARDS],
            commitment_response: [0; 32],
            beta: [0; 32],
            beta_blinding_response: [0; 32],
            rerandomization_response: [0; 32],
            c_d: [0; 32],
            c_delta: [0; 32],
            c_capital_delta: [0; 32],
            a_response: [[0; 32]; RISTRETTO_V2_DECK_CARDS],
            b_response: [[0; 32]; RISTRETTO_V2_DECK_CARDS],
            r_response: [0; 32],
            s_response: [0; 32],
        }
    }
}

/// Magic prefix of the serialized V2 shuffle proof envelope.
pub const RISTRETTO_SHUFFLE_V2_PROOF_MAGIC: [u8; 4] = *b"ZRS2";
/// Version of the V2 shuffle proof envelope.  Version 2 introduced the
/// versioned transcript sidecar ([`RistrettoShuffleV2TranscriptProof`]);
/// version 1 envelopes are rejected fail-closed at the wire layer.
pub const RISTRETTO_SHUFFLE_V2_PROOF_VERSION: u8 = 2;
/// Transcript domain for the V2 shuffle Fiat--Shamir schedule.
pub const RISTRETTO_SHUFFLE_V2_TRANSCRIPT_DOMAIN: &[u8] =
    b"zchain.texas.ristretto-air-v2.shuffle-transcript.v1";
const STATEMENT_DOMAIN: &[u8] = b"zchain.texas.ristretto-air-v2.shuffle.statement.v1";
const COMPONENT_DOMAIN: &[u8] = b"zchain.texas.ristretto-air-v2.shuffle.components.v1";
/// Maximum number of per-challenge rejection-sampling retries recorded on the
/// wire.  A canonical Ristretto scalar is accepted with probability close to
/// `q/2^256`, so even the bound of a handful of retries is never approached;
/// the cap only rejects unbounded-squeeze archive abuse.
pub const RISTRETTO_SHUFFLE_V2_MAX_CHALLENGE_RETRIES: u32 = 1024;

type RistrettoPoint = <RistrettoCurve as Curve>::Point;
type RistrettoScalar = <RistrettoCurve as Curve>::Scalar;
type RistrettoCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

fn chain_digest(message: &[u8]) -> [u8; 32] {
    crate::blake3_flock::blake3_chain_digest(message)
}

/// The Ristretto255 group order as a little-endian magnitude for canonical
/// scalar rejection sampling.
const GROUP_ORDER_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn scalar_magnitude_ok(bytes: &[u8; 32]) -> bool {
    // Little-endian strict comparison against the group order.
    for index in (0..32).rev() {
        match bytes[index].cmp(&GROUP_ORDER_BYTES[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
}

/// One derived Fiat--Shamir challenge recorded on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoShuffleV2ChallengeWire {
    /// Canonical 32-byte challenge image (the squeeze output before scalar
    /// reduction; identical on prover and verifier).
    pub image: [u8; 32],
    /// Rejection-sampling retries consumed before the image was accepted.
    pub retry_count: u32,
}

/// Flock-BLAKE3 Fiat--Shamir transcript for the V2 shuffle.
///
/// The transcript is a strict chain: absorbed public data accumulates in a
/// pending buffer, and every challenge first folds the buffer into the chain
/// state (`state' = blake3_chain_digest(state || pending)`, one Flock chain
/// statement) and then squeezes a challenge image
/// (`image = blake3_chain_digest(state' || tag || ordinal || retry || label)`).
/// The new state becomes the accepted image, so every later statement and
/// challenge transitively binds every earlier one.  Both the prover and the
/// verifier drive the same deterministic call sequence, so their statement
/// lists, images, and retry counts must agree exactly.
pub struct FlockShuffleTranscript {
    state: [u8; 32],
    pending: Vec<u8>,
    statements: Vec<HashStatement>,
    challenges: Vec<RistrettoShuffleV2ChallengeWire>,
}

impl FlockShuffleTranscript {
    /// Create the transcript and record its domain-seeded initial statement.
    pub fn new(protocol_name: &[u8]) -> Self {
        let mut preimage =
            Vec::with_capacity(RISTRETTO_SHUFFLE_V2_TRANSCRIPT_DOMAIN.len() + protocol_name.len());
        preimage.extend_from_slice(RISTRETTO_SHUFFLE_V2_TRANSCRIPT_DOMAIN);
        preimage.extend_from_slice(&(protocol_name.len() as u32).to_le_bytes());
        preimage.extend_from_slice(protocol_name);
        let state = chain_digest(&preimage);
        let statements = vec![HashStatement::new(preimage, state)];
        Self {
            state,
            pending: Vec::new(),
            statements,
            challenges: Vec::new(),
        }
    }

    /// The ordered chain statements produced so far (Flock-provable).
    pub fn statements(&self) -> &[HashStatement] {
        &self.statements
    }

    /// The ordered challenge images and retry counts produced so far.
    pub fn challenges(&self) -> &[RistrettoShuffleV2ChallengeWire] {
        &self.challenges
    }

    /// Absorb public data into the pending buffer without deriving a
    /// challenge.  Callers composing larger protocols (for example the
    /// reconstruction contribution shuffle) use this to bind their statement
    /// digest ahead of the Bayer--Groth schedule.
    pub fn absorb(&mut self, label: &[u8], message: &[u8]) {
        self.absorb_framed(label, message);
    }

    fn absorb_framed(&mut self, label: &[u8], message: &[u8]) {
        self.pending
            .extend_from_slice(&(label.len() as u32).to_le_bytes());
        self.pending.extend_from_slice(label);
        self.pending
            .extend_from_slice(&(message.len() as u32).to_le_bytes());
        self.pending.extend_from_slice(message);
    }

    fn flush_pending(&mut self) {
        let mut message = Vec::with_capacity(32 + self.pending.len());
        message.extend_from_slice(&self.state);
        message.extend_from_slice(&self.pending);
        self.state = chain_digest(&message);
        self.statements
            .push(HashStatement::new(message, self.state));
        self.pending.clear();
    }

    fn derive_challenge_image(&mut self, label: &[u8]) -> ([u8; 32], u32) {
        self.flush_pending();
        let ordinal = self.challenges.len() as u32;
        let mut retry = 0u32;
        loop {
            let mut input = Vec::with_capacity(32 + 16 + 8 + label.len());
            input.extend_from_slice(&self.state);
            input.extend_from_slice(b"zrs2-challenge");
            input.extend_from_slice(&ordinal.to_le_bytes());
            input.extend_from_slice(&retry.to_le_bytes());
            input.extend_from_slice(&(label.len() as u32).to_le_bytes());
            input.extend_from_slice(label);
            let candidate = chain_digest(&input);
            // Reject zero alongside non-canonical magnitudes so the
            // Bayer--Groth `challenge_nonzero` wrapper never appends its own
            // retry messages: the recorded schedule keeps exactly one image
            // per `challenge` call.
            if candidate != [0u8; 32] && scalar_magnitude_ok(&candidate) {
                self.challenges.push(RistrettoShuffleV2ChallengeWire {
                    image: candidate,
                    retry_count: retry,
                });
                return (candidate, retry);
            }
            retry = retry
                .checked_add(1)
                .expect("challenge rejection sampling cannot overflow u32 retries");
        }
    }
}

impl CryptoTranscript for FlockShuffleTranscript {
    fn new(protocol_name: &[u8]) -> Self {
        FlockShuffleTranscript::new(protocol_name)
    }

    fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.absorb_framed(label, message);
    }

    fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            let (image, _) = self.derive_challenge_image(label);
            self.state = image;
            chunk.copy_from_slice(&image[..chunk.len()]);
        }
    }

    fn append_point<C: Curve>(&mut self, label: &[u8], point: &C::Point) {
        self.absorb_framed(label, point.compress().as_ref());
    }

    fn append_scalar<C: Curve>(&mut self, label: &[u8], scalar: &C::Scalar) {
        self.absorb_framed(label, &scalar.as_bytes());
    }

    fn challenge<C: Curve>(&mut self, label: &[u8]) -> poker_protocol_core::Challenge<C> {
        let (image, _) = self.derive_challenge_image(label);
        self.state = image;
        let scalar = C::Scalar::from_canonical_bytes(&image)
            .expect("rejection sampling accepted only canonical images");
        poker_protocol_core::Challenge { scalar }
    }
}

fn append_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> TexasAirResult<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| TexasAirError::SpecViolation("shuffle statement field is too large".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Digest the complete public shuffle statement without the `proof` payload.
///
/// This is the Fiat--Shamir anchor: the transcript's first absorbed statement
/// and the envelope's `statement_digest` are both derived from it, so a proof
/// cannot be replayed against a different deck, key, or call scope.
pub fn shuffle_v2_statement_digest(request: &ShuffleVerifyRequest) -> TexasAirResult<[u8; 32]> {
    request.validate().map_err(|error| {
        TexasAirError::SpecViolation(format!("invalid shuffle request: {error}"))
    })?;
    let mut preimage = Vec::new();
    preimage.extend_from_slice(STATEMENT_DOMAIN);
    preimage.extend_from_slice(&[
        request.curve as u8,
        request.proof_system as u8,
        request.transcript as u8,
    ]);
    append_bytes(&mut preimage, &request.context)?;
    append_bytes(&mut preimage, &request.call_context)?;
    append_bytes(&mut preimage, &request.public_key)?;
    let input_count = u32::try_from(request.input.len())
        .map_err(|_| TexasAirError::SpecViolation("too many shuffle inputs".into()))?;
    preimage.extend_from_slice(&input_count.to_le_bytes());
    for ciphertext in &request.input {
        append_bytes(&mut preimage, &ciphertext.c1)?;
        append_bytes(&mut preimage, &ciphertext.c2)?;
    }
    let output_count = u32::try_from(request.output.len())
        .map_err(|_| TexasAirError::SpecViolation("too many shuffle outputs".into()))?;
    preimage.extend_from_slice(&output_count.to_le_bytes());
    for ciphertext in &request.output {
        append_bytes(&mut preimage, &ciphertext.c1)?;
        append_bytes(&mut preimage, &ciphertext.c2)?;
    }
    Ok(chain_digest(&preimage))
}

fn decode_point(bytes: &[u8]) -> TexasAirResult<RistrettoPoint> {
    let array: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| TexasAirError::SpecViolation("shuffle point must be 32 bytes".into()))?;
    RistrettoPoint::from_compressed(array).ok_or_else(|| {
        TexasAirError::SpecViolation("shuffle point failed canonical decompression".into())
    })
}

fn decode_scalar(bytes: &[u8; 32]) -> TexasAirResult<RistrettoScalar> {
    <RistrettoScalar as CurveScalar>::from_canonical_bytes(bytes).ok_or_else(|| {
        TexasAirError::SpecViolation("shuffle scalar is not canonically encoded".into())
    })
}

fn decode_ciphertext(c1: &[u8], c2: &[u8]) -> TexasAirResult<RistrettoCiphertext> {
    Ok(RistrettoCiphertext {
        c1: decode_point(c1)?,
        c2: decode_point(c2)?,
    })
}

fn point_bytes(point: &RistrettoPoint) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(point.compress().as_bytes());
    out
}

fn scalar_bytes(scalar: &RistrettoScalar) -> [u8; 32] {
    let bytes = scalar.as_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

impl RistrettoBayerGrothShuffleProofWire {
    /// Encode a native Ristretto Bayer--Groth proof into the fixed wire shape.
    pub fn from_proof(proof: &BayerGrothShuffleProof<RistrettoCurve>) -> Self {
        let mexp = &proof.multi_exponentiation;
        Self {
            c_permutation: point_bytes(&proof.c_permutation),
            c_permuted_powers: point_bytes(&proof.c_permuted_powers),
            c_alpha: point_bytes(&mexp.c_alpha),
            c_beta: point_bytes(&mexp.c_beta),
            ciphertext_0: RistrettoCiphertextProofWire {
                c1: point_bytes(&mexp.ciphertext_0.c1),
                c2: point_bytes(&mexp.ciphertext_0.c2),
            },
            ciphertext_1: RistrettoCiphertextProofWire {
                c1: point_bytes(&mexp.ciphertext_1.c1),
                c2: point_bytes(&mexp.ciphertext_1.c2),
            },
            alpha_response: mexp
                .alpha_response
                .iter()
                .map(scalar_bytes)
                .collect::<Vec<_>>()
                .try_into()
                .expect("Bayer-Groth responses are fixed to the 52-card deck"),
            commitment_response: scalar_bytes(&mexp.commitment_response),
            beta: scalar_bytes(&mexp.beta),
            beta_blinding_response: scalar_bytes(&mexp.beta_blinding_response),
            rerandomization_response: scalar_bytes(&mexp.rerandomization_response),
            c_d: point_bytes(&proof.product.c_d),
            c_delta: point_bytes(&proof.product.c_delta),
            c_capital_delta: point_bytes(&proof.product.c_capital_delta),
            a_response: proof
                .product
                .a_response
                .iter()
                .map(scalar_bytes)
                .collect::<Vec<_>>()
                .try_into()
                .expect("Bayer-Groth responses are fixed to the 52-card deck"),
            b_response: proof
                .product
                .b_response
                .iter()
                .map(scalar_bytes)
                .collect::<Vec<_>>()
                .try_into()
                .expect("Bayer-Groth responses are fixed to the 52-card deck"),
            r_response: scalar_bytes(&proof.product.r_response),
            s_response: scalar_bytes(&proof.product.s_response),
        }
    }

    /// Decode the wire shape into a native proof, rejecting every
    /// non-canonical point or scalar encoding.
    pub fn to_proof(&self) -> TexasAirResult<BayerGrothShuffleProof<RistrettoCurve>> {
        let decode_ciphertext = |wire: &RistrettoCiphertextProofWire| -> TexasAirResult<_> {
            Ok(RistrettoCiphertext {
                c1: decode_point(&wire.c1)?,
                c2: decode_point(&wire.c2)?,
            })
        };
        let mut alpha_response = Vec::with_capacity(self.alpha_response.len());
        for scalar in &self.alpha_response {
            alpha_response.push(decode_scalar(scalar)?);
        }
        let mut a_response = Vec::with_capacity(self.a_response.len());
        for scalar in &self.a_response {
            a_response.push(decode_scalar(scalar)?);
        }
        let mut b_response = Vec::with_capacity(self.b_response.len());
        for scalar in &self.b_response {
            b_response.push(decode_scalar(scalar)?);
        }
        Ok(BayerGrothShuffleProof {
            c_permutation: decode_point(&self.c_permutation)?,
            c_permuted_powers: decode_point(&self.c_permuted_powers)?,
            multi_exponentiation: poker_protocol_bg::MultiExponentiationArgument {
                c_alpha: decode_point(&self.c_alpha)?,
                c_beta: decode_point(&self.c_beta)?,
                ciphertext_0: decode_ciphertext(&self.ciphertext_0)?,
                ciphertext_1: decode_ciphertext(&self.ciphertext_1)?,
                alpha_response,
                commitment_response: decode_scalar(&self.commitment_response)?,
                beta: decode_scalar(&self.beta)?,
                beta_blinding_response: decode_scalar(&self.beta_blinding_response)?,
                rerandomization_response: decode_scalar(&self.rerandomization_response)?,
            },
            product: poker_protocol_bg::ProductArgument {
                c_d: decode_point(&self.c_d)?,
                c_delta: decode_point(&self.c_delta)?,
                c_capital_delta: decode_point(&self.c_capital_delta)?,
                a_response,
                b_response,
                r_response: decode_scalar(&self.r_response)?,
                s_response: decode_scalar(&self.s_response)?,
            },
        })
    }
}

/// Versioned transcript sidecar of the V2 shuffle envelope.
///
/// The Flock variant is the trustless route: a Flock STARK over the
/// transcript's BLAKE3 chain statements.  The Poseidon2 variant is the
/// deployment route: the M31-native chain schedule travels as a
/// [`Poseidon2ChainSpec`] and the verifier replays it natively — no Flock
/// archive, no session Flock setup.  Unknown variants fail closed at the
/// borsh decode layer.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RistrettoShuffleV2TranscriptProof {
    /// Flock STARK over the Flock-BLAKE3 chain statements.
    Flock(ArchivedHashProof),
    /// Poseidon2-M31 chain schedule; the verifier replays the same
    /// deterministic absorb-and-permute steps and compares terminal states.
    Poseidon2 {
        chain_spec: Poseidon2ChainSpec,
    },
}

/// Complete, self-describing RistrettoAirV2 shuffle proof package.
///
/// The envelope binds the Bayer--Groth wire, the derived challenge schedule,
/// and the transcript sidecar to the shuffle statement digest, so no
/// component can be spliced between statements or proofs.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoShuffleV2Proof {
    pub version: u8,
    pub statement_digest: [u8; 32],
    /// Digest of [`RISTRETTO_SHUFFLE_V2_TRANSCRIPT_DOMAIN`]; a domain tag,
    /// not a Fiat--Shamir challenge.
    pub transcript_domain_digest: [u8; 32],
    pub shuffle: RistrettoBayerGrothShuffleProofWire,
    pub challenges: Vec<RistrettoShuffleV2ChallengeWire>,
    /// Versioned transcript sidecar (Flock STARK or Poseidon2 chain spec).
    pub transcript: RistrettoShuffleV2TranscriptProof,
    pub component_digest: [u8; 32],
}

impl ArchivedRistrettoShuffleV2Proof {
    fn component_digest(&self) -> TexasAirResult<[u8; 32]> {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(COMPONENT_DOMAIN);
        preimage.extend_from_slice(&self.statement_digest);
        preimage.extend_from_slice(&self.transcript_domain_digest);
        borsh::to_writer(&mut preimage, &self.shuffle)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
        borsh::to_writer(&mut preimage, &self.challenges)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
        match &self.transcript {
            RistrettoShuffleV2TranscriptProof::Flock(flock) => {
                preimage.push(0);
                for statement in flock.statements() {
                    preimage.extend_from_slice(&(statement.message.len() as u32).to_le_bytes());
                    preimage.extend_from_slice(&statement.message);
                    preimage.extend_from_slice(&statement.digest);
                }
            }
            RistrettoShuffleV2TranscriptProof::Poseidon2 { chain_spec } => {
                preimage.push(1);
                borsh::to_writer(&mut preimage, chain_spec).map_err(|error| {
                    TexasAirError::SerializationError(error.to_string())
                })?;
            }
        }
        Ok(chain_digest(&preimage))
    }

    /// Assemble the envelope from a proven shuffle and its Flock transcript.
    pub fn from_parts(
        statement_digest: [u8; 32],
        shuffle: RistrettoBayerGrothShuffleProofWire,
        transcript: &FlockShuffleTranscript,
        flock: ArchivedHashProof,
    ) -> TexasAirResult<Self> {
        let mut envelope = Self {
            version: RISTRETTO_SHUFFLE_V2_PROOF_VERSION,
            statement_digest,
            transcript_domain_digest: chain_digest(RISTRETTO_SHUFFLE_V2_TRANSCRIPT_DOMAIN),
            shuffle,
            challenges: transcript.challenges().to_vec(),
            transcript: RistrettoShuffleV2TranscriptProof::Flock(flock),
            component_digest: [0; 32],
        };
        if let RistrettoShuffleV2TranscriptProof::Flock(flock) = &envelope.transcript {
            if flock.statements() != transcript.statements() {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "Flock proof does not cover the exact shuffle transcript statements".into(),
                ));
            }
        }
        envelope.component_digest = envelope.component_digest()?;
        Ok(envelope)
    }

    /// Assemble the envelope from a Poseidon2-path proven shuffle: the
    /// recorded challenge schedule and chain spec come directly from the
    /// prover's transcript run, so both stay bound to the statement digest.
    pub fn from_parts_poseidon2(
        statement_digest: [u8; 32],
        shuffle: RistrettoBayerGrothShuffleProofWire,
        transcript: &Poseidon2M31Transcript,
    ) -> TexasAirResult<Self> {
        let images = transcript.challenge_images();
        let retries = transcript.challenge_retries();
        if images.len() != retries.len() {
            return Err(TexasAirError::SpecViolation(
                "Poseidon2 transcript challenge schedule is inconsistent".into(),
            ));
        }
        let challenges = images
            .iter()
            .zip(retries)
            .map(|(image, retry)| RistrettoShuffleV2ChallengeWire {
                image: *image,
                retry_count: *retry,
            })
            .collect::<Vec<_>>();
        let mut envelope = Self {
            version: RISTRETTO_SHUFFLE_V2_PROOF_VERSION,
            statement_digest,
            transcript_domain_digest: chain_digest(RISTRETTO_SHUFFLE_V2_TRANSCRIPT_DOMAIN),
            shuffle,
            challenges,
            transcript: RistrettoShuffleV2TranscriptProof::Poseidon2 {
                chain_spec: transcript.chain_spec(),
            },
            component_digest: [0; 32],
        };
        envelope.component_digest = envelope.component_digest()?;
        Ok(envelope)
    }

    /// Serialize with the strict magic/version framing.
    pub fn encode_wire(&self) -> TexasAirResult<Vec<u8>> {
        self.validate_shape()?;
        let payload = borsh::to_vec(self)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
        let mut out = Vec::with_capacity(RISTRETTO_SHUFFLE_V2_PROOF_MAGIC.len() + payload.len());
        out.extend_from_slice(&RISTRETTO_SHUFFLE_V2_PROOF_MAGIC);
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Decode the strict envelope, rejecting trailing or non-canonical bytes.
    pub fn decode_wire(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.len() < RISTRETTO_SHUFFLE_V2_PROOF_MAGIC.len()
            || bytes[..RISTRETTO_SHUFFLE_V2_PROOF_MAGIC.len()] != RISTRETTO_SHUFFLE_V2_PROOF_MAGIC
        {
            return Err(TexasAirError::SerializationError(
                "Ristretto shuffle V2 proof magic mismatch".into(),
            ));
        }
        let envelope: Self = borsh::from_slice(&bytes[RISTRETTO_SHUFFLE_V2_PROOF_MAGIC.len()..])
            .map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "Ristretto shuffle V2 proof decode failed: {error}"
                ))
            })?;
        envelope.validate_shape()?;
        if envelope.encode_wire()? != bytes {
            return Err(TexasAirError::SerializationError(
                "Ristretto shuffle V2 proof is not canonically encoded".into(),
            ));
        }
        Ok(envelope)
    }

    /// Check the transport-level self-consistency of the envelope.
    pub fn validate_shape(&self) -> TexasAirResult<()> {
        if self.version != RISTRETTO_SHUFFLE_V2_PROOF_VERSION {
            return Err(TexasAirError::SpecViolation(
                "unsupported Ristretto shuffle V2 proof version".into(),
            ));
        }
        if self.transcript_domain_digest != chain_digest(RISTRETTO_SHUFFLE_V2_TRANSCRIPT_DOMAIN) {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto shuffle V2 transcript domain is detached".into(),
            ));
        }
        for challenge in &self.challenges {
            if challenge.retry_count > RISTRETTO_SHUFFLE_V2_MAX_CHALLENGE_RETRIES {
                return Err(TexasAirError::SpecViolation(
                    "Ristretto shuffle V2 challenge retry count exceeds the bound".into(),
                ));
            }
        }
        if let RistrettoShuffleV2TranscriptProof::Poseidon2 { chain_spec } = &self.transcript {
            chain_spec.validate().map_err(|error| {
                TexasAirError::SpecViolation(format!(
                    "Ristretto shuffle V2 Poseidon2 chain spec is malformed: {error}"
                ))
            })?;
        }
        if self.component_digest != self.component_digest()? {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto shuffle V2 component digest is detached".into(),
            ));
        }
        Ok(())
    }

    /// Check that the envelope is bound to one exact canonical request.
    pub fn validate_against_request(&self, request: &ShuffleVerifyRequest) -> TexasAirResult<()> {
        if request.curve != CurveId::Ristretto255
            || request.proof_system != ShuffleProofSystem::RistrettoAirV2
        {
            return Err(TexasAirError::SpecViolation(
                "Ristretto shuffle V2 proof is bound to the fixed V2 discriminators".into(),
            ));
        }
        let routes_match = match (request.transcript, &self.transcript) {
            (
                TranscriptId::FlockBlake3,
                RistrettoShuffleV2TranscriptProof::Flock(_),
            ) => true,
            (
                TranscriptId::Poseidon2M31,
                RistrettoShuffleV2TranscriptProof::Poseidon2 { .. },
            ) => true,
            _ => false,
        };
        if !routes_match {
            return Err(TexasAirError::SpecViolation(
                "Ristretto shuffle V2 transcript sidecar does not match the request transcript discriminator"
                    .into(),
            ));
        }
        if self.statement_digest != shuffle_v2_statement_digest(request)? {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto shuffle V2 proof is detached from the request statement".into(),
            ));
        }
        Ok(())
    }
}

fn request_points(
    request: &ShuffleVerifyRequest,
) -> TexasAirResult<(
    Vec<RistrettoCiphertext>,
    Vec<RistrettoCiphertext>,
    RistrettoPoint,
)> {
    let input = request
        .input
        .iter()
        .map(|ciphertext| decode_ciphertext(&ciphertext.c1, &ciphertext.c2))
        .collect::<TexasAirResult<Vec<_>>>()?;
    let output = request
        .output
        .iter()
        .map(|ciphertext| decode_ciphertext(&ciphertext.c1, &ciphertext.c2))
        .collect::<TexasAirResult<Vec<_>>>()?;
    let public_key = decode_point(&request.public_key)?;
    Ok((input, output, public_key))
}

/// Prove the complete V2 shuffle for one canonical request.
///
/// `request.proof` may be empty on input: the statement digest deliberately
/// excludes it, and the caller attaches the returned envelope's wire bytes to
/// the request after proving.
pub fn prove_ristretto_air_v2_shuffle(
    request: &ShuffleVerifyRequest,
    permutation: &[usize],
    rerandomizers: &[RistrettoScalar],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<ArchivedRistrettoShuffleV2Proof> {
    request.validate().map_err(|error| {
        TexasAirError::SpecViolation(format!("invalid shuffle request: {error}"))
    })?;
    if request.curve != CurveId::Ristretto255
        || request.proof_system != ShuffleProofSystem::RistrettoAirV2
        || request.transcript != TranscriptId::FlockBlake3
    {
        return Err(TexasAirError::SpecViolation(
            "Ristretto shuffle V2 proving requires the fixed V2 discriminators".into(),
        ));
    }    let (input, output, public_key) = request_points(request)?;
    let statement_digest = shuffle_v2_statement_digest(request)?;
    let mut transcript = FlockShuffleTranscript::new(
        poker_protocol::ristretto_air::RISTRETTO_AIR_V2_SHUFFLE_CONTEXT,
    );
    let proof = BayerGrothShuffleProof::<RistrettoCurve>::prove(
        &input,
        &output,
        permutation,
        rerandomizers,
        &public_key,
        rng,
        &mut transcript,
    )
    .map_err(|error| {
        TexasAirError::ConstraintUnsatisfied(format!("Bayer-Groth shuffle proving failed: {error}"))
    })?;
    let flock = crate::blake3_flock::FlockProvider
        .prove_statements(transcript.statements())
        .map_err(|error| {
            TexasAirError::StwoProverError(format!("Flock transcript proving failed: {error}"))
        })?;
    ArchivedRistrettoShuffleV2Proof::from_parts(
        statement_digest,
        RistrettoBayerGrothShuffleProofWire::from_proof(&proof),
        &transcript,
        flock,
    )
}

/// Prove the complete V2 shuffle under the Poseidon2-M31 transcript.
///
/// Deployment-route twin of [`prove_ristretto_air_v2_shuffle`]: the
/// Fiat--Shamir schedule is driven by the M31-native sponge and the envelope
/// carries the foldable [`Poseidon2ChainSpec`] instead of a Flock archive, so
/// the wire shrinks from megabytes to kilobytes and the verifier needs no
/// Flock setup.  The request must carry the `Poseidon2M31` discriminator.
pub fn prove_ristretto_air_v2_shuffle_poseidon2(
    request: &ShuffleVerifyRequest,
    permutation: &[usize],
    rerandomizers: &[RistrettoScalar],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<ArchivedRistrettoShuffleV2Proof> {
    request.validate().map_err(|error| {
        TexasAirError::SpecViolation(format!("invalid shuffle request: {error}"))
    })?;
    if request.curve != CurveId::Ristretto255
        || request.proof_system != ShuffleProofSystem::RistrettoAirV2
        || request.transcript != TranscriptId::Poseidon2M31
    {
        return Err(TexasAirError::SpecViolation(
            "Ristretto shuffle V2 Poseidon2 proving requires the Poseidon2M31 discriminator"
                .into(),
        ));
    }
    let (input, output, public_key) = request_points(request)?;
    let statement_digest = shuffle_v2_statement_digest(request)?;
    let mut transcript = Poseidon2M31Transcript::new(
        poker_protocol::ristretto_air::RISTRETTO_AIR_V2_SHUFFLE_CONTEXT,
    );
    let proof = BayerGrothShuffleProof::<RistrettoCurve>::prove(
        &input,
        &output,
        permutation,
        rerandomizers,
        &public_key,
        rng,
        &mut transcript,
    )
    .map_err(|error| {
        TexasAirError::ConstraintUnsatisfied(format!("Bayer-Groth shuffle proving failed: {error}"))
    })?;
    ArchivedRistrettoShuffleV2Proof::from_parts_poseidon2(
        statement_digest,
        RistrettoBayerGrothShuffleProofWire::from_proof(&proof),
        &transcript,
    )
}

fn map_verification_error(error: VerificationError) -> TexasAirError {
    TexasAirError::ConstraintUnsatisfied(format!(
        "Bayer-Groth shuffle verification failed: {error:?}"
    ))
}

/// Drive one native Bayer--Groth verification against a caller-owned
/// transcript.  Composers (for example the reconstruction contribution
/// shuffle) seed and absorb their own statement into the transcript first;
/// this helper only runs the argument and maps its error type.
pub fn run_bayer_groth_verify(
    proof: &BayerGrothShuffleProof<RistrettoCurve>,
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    public_key: &RistrettoPoint,
    transcript: &mut FlockShuffleTranscript,
) -> TexasAirResult<()> {
    proof
        .verify(input, output, public_key, transcript)
        .map_err(map_verification_error)
}

/// Verify one complete V2 shuffle submission against its canonical request.
///
/// This checks, in order: the request discriminators and canonical encoding,
/// the envelope's statement/component bindings, the native Bayer--Groth
/// public-equation argument under the request's transcript route (Flock or
/// Poseidon2), the recomputed challenge schedule, and the route's transcript
/// proof (Flock STARK verification or Poseidon2 chain replay).
pub fn verify_ristretto_air_v2_shuffle_submission(
    request_bytes: &[u8],
) -> TexasAirResult<ArchivedRistrettoShuffleV2Proof> {
    let request = decode_v2_shuffle_request(request_bytes)?;
    let envelope = ArchivedRistrettoShuffleV2Proof::decode_wire(&request.proof)?;
    envelope.validate_against_request(&request)?;
    let proof = envelope.shuffle.to_proof()?;
    let (input, output, public_key) = request_points(&request)?;
    match &envelope.transcript {
        RistrettoShuffleV2TranscriptProof::Flock(flock) => {
            let mut transcript = FlockShuffleTranscript::new(
                poker_protocol::ristretto_air::RISTRETTO_AIR_V2_SHUFFLE_CONTEXT,
            );
            proof
                .verify(&input, &output, &public_key, &mut transcript)
                .map_err(map_verification_error)?;
            if transcript.challenges() != envelope.challenges.as_slice() {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "Ristretto shuffle V2 challenge schedule is detached from the transcript"
                        .into(),
                ));
            }
            crate::blake3_flock::FlockProvider
                .verify_statements(flock, transcript.statements())
                .map_err(|error| {
                    TexasAirError::ConstraintUnsatisfied(format!(
                        "Flock transcript verification failed: {error}"
                    ))
                })?;
        }
        RistrettoShuffleV2TranscriptProof::Poseidon2 { chain_spec } => {
            let mut transcript = Poseidon2M31Transcript::new(
                poker_protocol::ristretto_air::RISTRETTO_AIR_V2_SHUFFLE_CONTEXT,
            );
            proof
                .verify(&input, &output, &public_key, &mut transcript)
                .map_err(map_verification_error)?;
            let replayed = transcript
                .challenge_images()
                .iter()
                .zip(transcript.challenge_retries())
                .map(|(image, retry)| RistrettoShuffleV2ChallengeWire {
                    image: *image,
                    retry_count: *retry,
                })
                .collect::<Vec<_>>();
            if replayed != envelope.challenges {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "Ristretto shuffle V2 challenge schedule is detached from the transcript"
                        .into(),
                ));
            }
            if transcript.chain_spec() != *chain_spec {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "Ristretto shuffle V2 Poseidon2 chain schedule is detached from the transcript"
                        .into(),
                ));
            }
        }
    }
    Ok(envelope)
}

/// Production V2 shuffle admission boundary.
///
/// Unlike the reconstruction bundle, the shuffle relation is complete once
/// the Bayer--Groth argument, the Flock transcript, and the canonical request
/// binding all verify: the argument proves the output deck is a rerandomized
/// permutation of the input deck under the aggregate key.  Admission can
/// therefore succeed here without a residual completeness gate.
pub fn admit_ristretto_air_v2_shuffle_submission(request_bytes: &[u8]) -> TexasAirResult<()> {
    verify_ristretto_air_v2_shuffle_submission(request_bytes).map(|_| ())
}

/// Everything a recursive aggregation circuit must consume to move the V2
/// shuffle admission decision on-chain (Path A).
///
/// The native verifier evaluates three layers: the Flock transcript STARKs
/// (already AIR), the canonical request bindings (already digest checks), and
/// the Bayer--Groth public-equation checks (native today).  A recursion that
/// proves the admission decision must constrain exactly this component set:
///
/// 1. the transcript chain statements below (binary-field BLAKE3 chains —
///    constrain via the same statements the Flock STARKs already cover);
/// 2. the scalar-side Bayer--Groth schedule over the Ristretto scalar field
///    `mod l`: the powers table `x^1..x^52`, the expected product
///    `∏(y·i + x^i − z)`, and `b_response[51] = pc · expected_product`.  This
///    needs a `mod l` program AIR (the existing FpProgram AIR constrains
///    `p = 2^255 − 19` only);
/// 3. the point-side multi-exponentiation equalities of
///    `BayerGrothShuffleProof::verify` over the decoded proof, decks, and
///    challenge scalars below (~7 checks over 52-way MSMs ≈ 300 in-circuit
///    scalar multiplications — the dominant recursion cost, and the reason a
///    dedicated fixed-window scalar-multiplication AIR is the Path A
///    prerequisite).
///
/// This extractor performs every cheap binding check first, so a circuit
/// builder cannot accidentally consume components detached from the request.
#[derive(Debug, Clone)]
pub struct RistrettoAirV2ShuffleInCircuitComponents {
    /// Digest of the canonical request statement (without `proof`).
    pub statement_digest: [u8; 32],
    /// Decoded canonical input deck.
    pub input: Vec<RistrettoCiphertext>,
    /// Decoded submitted output deck.
    pub output: Vec<RistrettoCiphertext>,
    /// Decoded aggregate key.
    pub public_key: RistrettoPoint,
    /// Decoded Bayer--Groth proof (canonical points and scalars).
    pub proof: BayerGrothShuffleProof<RistrettoCurve>,
    /// Transcript challenges in derivation order as canonical scalars:
    /// `x (powers), y (product), z (product), mexp, product`.
    pub challenges: Vec<RistrettoScalar>,
    /// The transcript chain statements the Flock STARKs cover.
    pub transcript_statements: Vec<HashStatement>,
}

/// Extract the on-chain recursion component set for one V2 shuffle request.
///
/// Checks the canonical request encoding, the envelope bindings, and the
/// Bayer--Groth argument itself (natively — the same evaluation the admission
/// boundary performs), then returns the exact components a circuit must
/// constrain.  The Flock STARKs are *not* re-verified here; a recursion
/// re-proves them as statement constraints instead.
pub fn ristretto_air_v2_shuffle_in_circuit_components(
    request_bytes: &[u8],
) -> TexasAirResult<RistrettoAirV2ShuffleInCircuitComponents> {
    let request = decode_v2_shuffle_request(request_bytes)?;
    let envelope = ArchivedRistrettoShuffleV2Proof::decode_wire(&request.proof)?;
    envelope.validate_against_request(&request)?;
    let proof = envelope.shuffle.to_proof()?;
    let (input, output, public_key) = request_points(&request)?;
    let mut transcript = FlockShuffleTranscript::new(
        poker_protocol::ristretto_air::RISTRETTO_AIR_V2_SHUFFLE_CONTEXT,
    );
    run_bayer_groth_verify(&proof, &input, &output, &public_key, &mut transcript)?;
    let challenges = transcript
        .challenges()
        .iter()
        .map(|challenge| {
            <RistrettoScalar as CurveScalar>::from_canonical_bytes(&challenge.image).ok_or_else(
                || {
                    TexasAirError::ConstraintUnsatisfied(
                        "V2 shuffle challenge image is not a canonical scalar".into(),
                    )
                },
            )
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    Ok(RistrettoAirV2ShuffleInCircuitComponents {
        statement_digest: envelope.statement_digest,
        input,
        output,
        public_key,
        proof,
        challenges,
        transcript_statements: transcript.statements().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_protocol::ristretto_air::{
        RISTRETTO_AIR_V2_SHUFFLE_CONTEXT, RISTRETTO_TEXAS_DECK_SIZE, RistrettoAirCiphertext,
        RistrettoShuffleSubmission,
    };

    fn test_rng() -> rand::rngs::StdRng {
        use rand::SeedableRng;
        rand::rngs::StdRng::seed_from_u64(0x5A1E)
    }

    /// `ShuffleVerifyRequest::validate` rejects an empty proof, so callers
    /// prove against a placeholder and replace `request.proof` afterwards.
    const PROOF_PLACEHOLDER: &[u8] = &[0; 8];

    fn deck_submission() -> (
        RistrettoShuffleSubmission,
        Vec<usize>,
        Vec<RistrettoScalar>,
        <RistrettoCurve as Curve>::Point,
    ) {
        let mut rng = test_rng();
        let secret = RistrettoScalar::random(&mut rng);
        let public_key = RistrettoCurve::base_g() * secret;
        let base = poker_protocol::ristretto_air::RistrettoTexasDeck::canonical_base(&public_key)
            .expect("canonical base deck");
        let mut permutation: Vec<usize> = (0..RISTRETTO_TEXAS_DECK_SIZE).collect();
        // Deterministic Fisher-Yates with a cheap xorshift stream.
        let mut seed = 0x1234_5678_9abc_def0u64;
        for index in (1..permutation.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let pick = (seed % (index as u64 + 1)) as usize;
            permutation.swap(index, pick);
        }
        let rerandomizers = (0..RISTRETTO_TEXAS_DECK_SIZE)
            .map(|_| RistrettoScalar::random(&mut rng))
            .collect::<Vec<_>>();
        let input: Vec<RistrettoAirCiphertext> = base.encrypted.to_vec();
        let output = permutation
            .iter()
            .zip(&rerandomizers)
            .map(|(&source, rerandomizer)| {
                let ciphertext = RistrettoCiphertext {
                    c1: decode_point(&input[source].c1).expect("input point decodes"),
                    c2: decode_point(&input[source].c2).expect("input point decodes"),
                };
                let rerandomized = ciphertext.re_encrypt(&public_key, rerandomizer);
                RistrettoAirCiphertext {
                    c1: point_bytes(&rerandomized.c1),
                    c2: point_bytes(&rerandomized.c2),
                }
            })
            .collect::<Vec<_>>();
        let submission = RistrettoShuffleSubmission {
            aggregate_pk: point_bytes(&public_key),
            input: input.try_into().expect("fixed input deck"),
            output: output.try_into().expect("fixed output deck"),
            air_proof: PROOF_PLACEHOLDER.to_vec(),
        };
        (submission, permutation, rerandomizers, public_key)
    }

    fn proved_request() -> Vec<u8> {
        let (submission, permutation, rerandomizers, _public_key) = deck_submission();
        let mut rng = test_rng();
        let mut request = submission
            .to_verify_request_v2(vec![7; 32])
            .expect("V2 request");
        let envelope =
            prove_ristretto_air_v2_shuffle(&request, &permutation, &rerandomizers, &mut rng)
                .expect("V2 shuffle proof");
        request.proof = envelope.encode_wire().expect("envelope wire");
        request.encode().expect("canonical request bytes")
    }

    fn proved_request_poseidon2() -> Vec<u8> {
        let (submission, permutation, rerandomizers, _public_key) = deck_submission();
        let mut rng = test_rng();
        let mut request = submission
            .to_verify_request_v2(vec![7; 32])
            .expect("V2 request");
        request.transcript = TranscriptId::Poseidon2M31;
        let envelope =
            prove_ristretto_air_v2_shuffle_poseidon2(&request, &permutation, &rerandomizers, &mut rng)
                .expect("V2 Poseidon2 shuffle proof");
        request.proof = envelope.encode_wire().expect("envelope wire");
        request.encode().expect("canonical request bytes")
    }

    #[test]
    fn transcript_is_deterministic_and_statement_bound() {
        let (submission, permutation, rerandomizers, _public_key) = deck_submission();
        let mut rng = test_rng();
        let request = submission
            .to_verify_request_v2(vec![7; 32])
            .expect("V2 request");
        let (input, output, public_key) = request_points(&request).expect("request points");
        let mut transcript = FlockShuffleTranscript::new(RISTRETTO_AIR_V2_SHUFFLE_CONTEXT);
        let proof = BayerGrothShuffleProof::<RistrettoCurve>::prove(
            &input,
            &output,
            &permutation,
            &rerandomizers,
            &public_key,
            &mut rng,
            &mut transcript,
        )
        .expect("Bayer-Groth proof");
        assert!(transcript.statements().len() >= 6);
        assert_eq!(transcript.challenges().len(), 5);

        // The verifier-side run must reproduce the identical schedule from the
        // public statement plus the proof wire alone.
        let wire = RistrettoBayerGrothShuffleProofWire::from_proof(&proof);
        let decoded = wire.to_proof().expect("wire roundtrip");
        let mut verify_transcript = FlockShuffleTranscript::new(RISTRETTO_AIR_V2_SHUFFLE_CONTEXT);
        decoded
            .verify(&input, &output, &public_key, &mut verify_transcript)
            .expect("Bayer-Groth verify");
        assert_eq!(transcript.statements(), verify_transcript.statements());
        assert_eq!(transcript.challenges(), verify_transcript.challenges());
    }

    #[ignore = "slow prove (~5s); full gate runs `--include-ignored`"]
    #[test]
    fn proves_and_verifies_a_complete_v2_shuffle() {
        let started = std::time::Instant::now();
        let request_bytes = proved_request();
        let prove_elapsed = started.elapsed();
        let request = ShuffleVerifyRequest::decode(&request_bytes).expect("decode");
        let envelope =
            ArchivedRistrettoShuffleV2Proof::decode_wire(&request.proof).expect("envelope");
        let shuffle_wire = borsh::to_vec(&envelope.shuffle).expect("shuffle wire");
        let flock_wire = match &envelope.transcript {
            RistrettoShuffleV2TranscriptProof::Flock(flock) => {
                let count = flock.statements().len();
                (
                    borsh::to_vec(flock).expect("flock wire").len(),
                    count,
                )
            }
            _ => panic!("flock proved request must carry the Flock sidecar"),
        };
        let started = std::time::Instant::now();
        admit_ristretto_air_v2_shuffle_submission(&request_bytes)
            .expect("complete V2 shuffle submission admits");
        eprintln!(
            "ristretto-air v2 shuffle: prove {:?}, verify+admit {:?}, request wire {} bytes (argument {}, flock {}, statements {})",
            prove_elapsed,
            started.elapsed(),
            request_bytes.len(),
            shuffle_wire.len(),
            flock_wire.0,
            flock_wire.1,
        );
    }

    #[test]
    fn proves_and_verifies_a_poseidon2_v2_shuffle() {
        let started = std::time::Instant::now();
        let request_bytes = proved_request_poseidon2();
        let prove_elapsed = started.elapsed();
        let request = ShuffleVerifyRequest::decode(&request_bytes).expect("decode");
        let envelope =
            ArchivedRistrettoShuffleV2Proof::decode_wire(&request.proof).expect("envelope");
        assert!(matches!(
            envelope.transcript,
            RistrettoShuffleV2TranscriptProof::Poseidon2 { .. }
        ));
        let started = std::time::Instant::now();
        admit_ristretto_air_v2_shuffle_submission(&request_bytes)
            .expect("Poseidon2 V2 shuffle submission admits");
        eprintln!(
            "ristretto-air v2 shuffle (poseidon2): prove {:?}, verify+admit {:?}, request wire {} bytes",
            prove_elapsed,
            started.elapsed(),
            request_bytes.len(),
        );
    }

    #[test]
    fn poseidon2_route_rejects_tampered_and_mismatched_routes() {
        let request_bytes = proved_request_poseidon2();
        admit_ristretto_air_v2_shuffle_submission(&request_bytes)
            .expect("baseline Poseidon2 submission admits");

        // Route splice: submit the Poseidon2 envelope under the Flock
        // discriminator.  The statement digest and the sidecar check both
        // detach.
        let request = ShuffleVerifyRequest::decode(&request_bytes).expect("decode");
        let mut flock_route = request.clone();
        flock_route.transcript = TranscriptId::FlockBlake3;
        assert!(
            admit_ristretto_air_v2_shuffle_submission(&flock_route.encode().expect("encode"))
                .is_err()
        );

        // Chain-schedule splice inside the envelope.
        let mut envelope =
            ArchivedRistrettoShuffleV2Proof::decode_wire(&request.proof).expect("envelope");
        if let RistrettoShuffleV2TranscriptProof::Poseidon2 { chain_spec } =
            &mut envelope.transcript
        {
            if let Some(word) = chain_spec.absorbed_words.first_mut() {
                word[0] = word[0].wrapping_add(1);
            } else {
                panic!("poseidon2 chain spec carries at least one step");
            }
        }
        envelope.component_digest = envelope.component_digest().expect("digest");
        let mut tampered = request.clone();
        tampered.proof = envelope.encode_wire().expect("wire");
        assert!(
            admit_ristretto_air_v2_shuffle_submission(&tampered.encode().expect("encode")).is_err()
        );

        // Challenge-schedule splice reaches the replay comparison.
        let mut envelope =
            ArchivedRistrettoShuffleV2Proof::decode_wire(&request.proof).expect("envelope");
        envelope.challenges[2].image[0] ^= 1;
        envelope.component_digest = envelope.component_digest().expect("digest");
        let mut tampered = request.clone();
        tampered.proof = envelope.encode_wire().expect("wire");
        let error = admit_ristretto_air_v2_shuffle_submission(&tampered.encode().expect("encode"))
            .expect_err("spliced challenge schedule must fail");
        assert!(error.to_string().contains("challenge schedule"));

        // Bayer-Groth response splice reaches the argument layer.
        let mut envelope =
            ArchivedRistrettoShuffleV2Proof::decode_wire(&request.proof).expect("envelope");
        envelope.shuffle.a_response[3][20] ^= 1;
        envelope.component_digest = envelope.component_digest().expect("digest");
        let mut tampered = request.clone();
        tampered.proof = envelope.encode_wire().expect("wire");
        let error = admit_ristretto_air_v2_shuffle_submission(&tampered.encode().expect("encode"))
            .expect_err("tampered response must fail");
        assert!(error.to_string().contains("Bayer-Groth"));
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn verifier_rejects_tampered_submissions() {
        let request_bytes = proved_request();
        admit_ristretto_air_v2_shuffle_submission(&request_bytes)
            .expect("baseline submission admits");

        // Splice the request's output deck: the statement digest detaches.
        let request = ShuffleVerifyRequest::decode(&request_bytes).expect("decode");
        let mut swapped = request.clone();
        swapped.output[0] = swapped.output[1].clone();
        let swapped_bytes = swapped.encode().expect("encode");
        assert!(admit_ristretto_air_v2_shuffle_submission(&swapped_bytes).is_err());

        // Splice one Bayer-Groth response scalar inside the envelope.  Byte
        // 20 of a canonical Ristretto scalar can be flipped without leaving
        // the canonical range, so the tamper reaches the argument layer.
        let mut envelope =
            ArchivedRistrettoShuffleV2Proof::decode_wire(&request.proof).expect("envelope");
        envelope.shuffle.a_response[3][20] ^= 1;
        // Re-derive a consistent component digest so the tamper reaches the
        // argument layer rather than the transport layer.
        envelope.component_digest = envelope.component_digest().expect("digest");
        let mut tampered = request.clone();
        tampered.proof = envelope.encode_wire().expect("wire");
        let tampered_bytes = tampered.encode().expect("encode");
        let error = admit_ristretto_air_v2_shuffle_submission(&tampered_bytes)
            .expect_err("tampered response must fail");
        assert!(error.to_string().contains("Bayer-Groth"));

        // Splice a commitment point.
        let mut envelope =
            ArchivedRistrettoShuffleV2Proof::decode_wire(&request.proof).expect("envelope");
        envelope.shuffle.c_permutation[7] ^= 4;
        envelope.component_digest = envelope.component_digest().expect("digest");
        let mut tampered = request.clone();
        tampered.proof = envelope.encode_wire().expect("wire");
        assert!(
            admit_ristretto_air_v2_shuffle_submission(&tampered.encode().expect("encode")).is_err()
        );

        // Splice the recorded challenge schedule.
        let mut envelope =
            ArchivedRistrettoShuffleV2Proof::decode_wire(&request.proof).expect("envelope");
        envelope.challenges[2].image[0] ^= 1;
        envelope.component_digest = envelope.component_digest().expect("digest");
        let mut tampered = request.clone();
        tampered.proof = envelope.encode_wire().expect("wire");
        let error = admit_ristretto_air_v2_shuffle_submission(&tampered.encode().expect("encode"))
            .expect_err("spliced challenge schedule must fail");
        assert!(error.to_string().contains("challenge schedule"));

        // Non-canonical trailing bytes are rejected at the wire layer.
        let mut proof_trailing = request.proof.clone();
        proof_trailing.push(0);
        assert!(ArchivedRistrettoShuffleV2Proof::decode_wire(&proof_trailing).is_err());
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn in_circuit_components_match_the_native_schedule() {
        let request_bytes = proved_request();
        let components = ristretto_air_v2_shuffle_in_circuit_components(&request_bytes)
            .expect("in-circuit component extraction");
        assert_eq!(components.challenges.len(), 5);
        assert!(components.transcript_statements.len() >= 6);
        assert_eq!(components.input.len(), RISTRETTO_TEXAS_DECK_SIZE);
        assert_eq!(components.output.len(), RISTRETTO_TEXAS_DECK_SIZE);
        // Detached requests must not yield components.
        let request = ShuffleVerifyRequest::decode(&request_bytes).expect("decode");
        let mut other = request.clone();
        other.call_context = vec![8; 32];
        let other_bytes = other.encode().expect("encode");
        assert!(ristretto_air_v2_shuffle_in_circuit_components(&other_bytes).is_err());
    }

    #[ignore = "slow prove (~4s); full gate runs `--include-ignored`"]
    #[test]
    fn verifier_rejects_a_wrong_shuffle_relation() {
        // Prove a shuffle of the correct input deck, then submit it against a
        // request whose input deck differs: the statement digest detaches
        // before any expensive verification runs.
        let (submission, permutation, rerandomizers, _public_key) = deck_submission();
        let mut rng = test_rng();
        let mut request = submission
            .to_verify_request_v2(vec![7; 32])
            .expect("V2 request");
        let envelope =
            prove_ristretto_air_v2_shuffle(&request, &permutation, &rerandomizers, &mut rng)
                .expect("V2 shuffle proof");
        request.proof = envelope.encode_wire().expect("envelope wire");

        let mut other = request.clone();
        other.call_context = vec![8; 32];
        let other_bytes = other.encode().expect("canonical bytes");
        let error = admit_ristretto_air_v2_shuffle_submission(&other_bytes)
            .expect_err("proof replayed against a different call context must fail");
        assert!(
            error
                .to_string()
                .contains("detached from the request statement")
        );
    }
}

/// Canonical-decode a V2 shuffle request (moved from the retired
/// reconstruction composition module).
fn decode_v2_shuffle_request(
    request_bytes: &[u8],
) -> TexasAirResult<poker_protocol::precompile_abi::ShuffleVerifyRequest> {
    use poker_protocol::precompile_abi::{ShuffleProofSystem, ShuffleVerifyRequest};
    let request = ShuffleVerifyRequest::decode(request_bytes).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "Ristretto AIR V2 shuffle request decode failed: {error}"
        ))
    })?;
    if request.proof_system != ShuffleProofSystem::RistrettoAirV2
        || request.context.as_slice()
            != poker_protocol::ristretto_air::RISTRETTO_AIR_V2_SHUFFLE_CONTEXT
    {
        return Err(TexasAirError::SpecViolation(
            "Ristretto AIR V2 shuffle endpoint received a non-V2 request".into(),
        ));
    }
    let canonical = request.encode().map_err(|error| {
        TexasAirError::SerializationError(format!(
            "Ristretto AIR V2 shuffle request encoding failed: {error}"
        ))
    })?;
    if canonical != request_bytes {
        return Err(TexasAirError::SerializationError(
            "Ristretto AIR V2 shuffle request is not canonically encoded".into(),
        ));
    }
    Ok(request)
}
