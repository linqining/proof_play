//! Shuffle/deal proof-chain stage-0 producer + native two-sided verification
//! (route A upstream half, `shuffle-chain stage0`).
//!
//! Stage 0 of the shuffle/deal proof-chain plan (`docs/shuffle-deal-proof-design.md`
//! §4 milestone 0) asks one question: can a **single canonical tagged batch**
//! carry ordinary betting transitions *together with* the protocol rows
//! `SubmitShuffle(7)` / `SubmitReveal(8)` / `SubmitReconstruct(9)`, prove and
//! verify end to end, with the deck commitment chain anchored to **real
//! ciphertexts** rather than fixture placeholders?
//!
//! The canonical AIR deliberately leaves the cryptographic equations outside
//! the trace (upstream Plan D): a `SubmitShuffle` row only freezes the
//! resulting deck-commitment anchor, never the Bayer–Groth relation itself.
//! This module closes the gap on the producer/verifier side:
//!
//! 1. **Producer wiring** — [`ShuffleChainBuilder`] runs the real mental-poker
//!    crypto over the production curve (`DefaultCurve` = Stark curve) with the
//!    production Poseidon transcript domains, verifies each proof **before**
//!    emitting the canonical witness row (fail-closed: a producer never
//!    anchors an unverified statement), and writes the commitment rotations
//!    computed from the actual ciphertexts into the state-image chain.
//! 2. **Native verification** — [`verify_canonical_batch_with_shuffle_chain`]
//!    runs the full STARK verification first, then re-verifies every BG/DLEq/V3
//!    statement natively and re-derives each commitment from the sidecar
//!    ciphertexts, so the deck chain is checked at both ends (route A).
//! 3. **Receipt digests** — [`ShuffleChainReceipt`] freezes the per-row
//!    statement digests plus the deck/reveal chain digests into one
//!    engine-computable digest (route B upstream half; attestation v2.2 wiring
//!    lives on the zchain side).
//!
//! # Honest scope notes (stage 0)
//!
//! - The canonical 32B `deck_commitment` derivation has no upstream-frozen
//!   definition (design doc §6-Q3). [`canonical_deck_commitment`] is the
//!   stage-0 **proposal**: `poseidon_hash_many` over the flattened
//!   `(c1, c2)` point sequence, mirroring the protocol-constant
//!   `plaintext_cards_commitment`. It must be frozen (or replaced) before
//!   ABI v1.3.
//! - The BG/DLEq/V3 proof material is **not** transported inside the canonical
//!   archive (design doc §6-Q2). The sidecar here is an in-memory stage-0
//!   container; the wire shape (sidecar package vs archive suffix vs pull) is
//!   still open.
//! - A reconstruct completion lands the hand in `Shuffling/subtag-2`
//!   (reconstruct-shuffle). The AIR's shuffle-completion opening only accepts
//!   the preflop subtag 1, so a post-reconstruct reshuffle → reveal → betting
//!   continuation is **not expressible** in the current canonical AIR; batches
//!   built here end at the reconstruct boundary and report the gap.
//! - Reveal-timeout kick rows rotate the reveal ledger too, but their
//!   authentication lives in the reveal-assignment opening (`canonical_reveal_
//!   opening`, ZR4A), not in this sidecar; the reveal-chain receipts therefore
//!   cover the sidecar-covered reveal rows only.

use poker_protocol::crypto::curve::{Curve, CurvePoint};
use poker_protocol::crypto::types::{DefaultCurve, EcPoint, ElGamalCiphertext};
use poker_protocol::transcript_domains;
use poker_protocol::zk_shuffle::bayer_groth::BayerGrothShuffleProof;
use poker_protocol::zk_shuffle::reconstruction::{
    apply_reconstruction_contributions, canonical_base_deck, ReconstructProof,
    ReconstructionStatement,
};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol_core::{
    poseidon_bytes_digest, poseidon_points_commitment, PoseidonFeltTranscript,
};
use rand_core::{CryptoRng, RngCore};

use crate::canonical_rake_opening::{CanonicalBlindOpening, CanonicalRakeOpening};
use crate::error::{TexasAirError, TexasAirResult};
use crate::texas_canonical::{
    CanonicalActionPayload, CanonicalProtocolCompletionKind, CanonicalProtocolCompletionOpening,
    CanonicalPhase, CanonicalSeatStatus, CanonicalStateImage, CanonicalTransitionKind,
    CanonicalTransitionWitness, NO_CANONICAL_SEAT,
};
use crate::texas_canonical_air::{
    batch_digest_for_witnesses, verify_canonical_tagged_proof, ArchivedCanonicalTaggedProof,
};

/// Stage-0 domain for the receipt/statement digests produced by this module.
/// Distinct from every settlement domain; bump (not reuse) when the digest
/// layout changes.
pub const SHUFFLE_CHAIN_STAGE0_DOMAIN: &[u8] = b"zchain.texas.canonical-shuffle-chain.v1";

/// Maximum deck size accepted by the commitment helpers (52-card Texas deck).
const MAX_DECK_LEN: usize = 52;

// ============================================================
// Stage-0 canonical commitment derivations (§6-Q3 proposals)
// ============================================================

/// Stage-0 canonical 32B commitment of an encrypted deck (§6-Q3 proposal).
///
/// `poseidon_hash_many(⌊c1₀, c2₀, c1₁, c2₁, …⌋)` — the same felt-direct shape
/// as the protocol-constant `plaintext_cards_commitment`, applied to the
/// ciphertext pairs in canonical order. Order and content binding are exact;
/// the derivation is Cairo-replicable without byte packing.
///
/// Not yet a frozen cross-repo ABI value: freezing is exactly the §6-Q3
/// decision this stage-0 report feeds.
pub fn canonical_deck_commitment(deck: &[ElGamalCiphertext]) -> TexasAirResult<[u8; 32]> {
    if deck.is_empty() || deck.len() > MAX_DECK_LEN {
        return Err(TexasAirError::SpecViolation(format!(
            "deck commitment needs 1..={MAX_DECK_LEN} cards, got {}",
            deck.len()
        )));
    }
    let mut points = Vec::with_capacity(deck.len() * 2);
    for card in deck {
        if !card.is_valid() {
            return Err(TexasAirError::SpecViolation(
                "deck commitment rejects placeholder/identity ciphertexts".into(),
            ));
        }
        points.push(card.c1);
        points.push(card.c2);
    }
    Ok(poseidon_points_commitment(&points))
}

/// One card whose reveal material enters the reveal-ledger commitment.
#[derive(Debug, Clone, Copy)]
pub struct RevealedCard {
    /// The ciphertext the token applies to (the current deck lineage entry).
    pub encrypted_card: ElGamalCiphertext,
    /// `c1 · sk_seat` — the participant's partial-decryption share.
    pub reveal_token: EcPoint,
}

/// Stage-0 canonical reveal-ledger commitment rotation (§6-Q3 proposal).
///
/// `poseidon_bytes_digest(DOMAIN ‖ "reveal-ledger" ‖ pre_reveal_commitment ‖
/// seat ‖ count ‖ per-card(c1 ‖ c2 ‖ token))`. The rotation is chained:
/// every reveal row folds the previous ledger value, so reveal rows cannot be
/// reordered or dropped without breaking the chain.
pub fn canonical_reveal_commitment(
    pre_reveal_commitment: &[u8; 32],
    seat: u8,
    revealed: &[RevealedCard],
) -> TexasAirResult<[u8; 32]> {
    if revealed.is_empty() {
        return Err(TexasAirError::SpecViolation(
            "reveal commitment rotation needs at least one revealed card".into(),
        ));
    }
    let mut material = Vec::with_capacity(96 + revealed.len() * 96);
    material.extend_from_slice(SHUFFLE_CHAIN_STAGE0_DOMAIN);
    material.extend_from_slice(b"reveal-ledger");
    material.extend_from_slice(pre_reveal_commitment);
    material.push(seat);
    material.push(revealed.len() as u8);
    for card in revealed {
        if !card.encrypted_card.is_valid() || card.reveal_token.is_identity() {
            return Err(TexasAirError::SpecViolation(
                "reveal commitment rejects placeholder cards/tokens".into(),
            ));
        }
        material.extend_from_slice(card.encrypted_card.c1.compress().as_ref());
        material.extend_from_slice(card.encrypted_card.c2.compress().as_ref());
        material.extend_from_slice(card.reveal_token.compress().as_ref());
    }
    Ok(poseidon_bytes_digest(&material))
}

/// Stage-0 canonical reconstruction-commitment derivation (§6-Q3 proposal):
/// Poseidon digest over the V3 statement's contribution vector.
pub fn canonical_reconstruction_commitment(
    statement: &ReconstructionStatement<DefaultCurve>,
) -> [u8; 32] {
    let mut material = Vec::with_capacity(96 + statement.contributions.len() * 64);
    material.extend_from_slice(SHUFFLE_CHAIN_STAGE0_DOMAIN);
    material.extend_from_slice(b"reconstruct-ledger");
    for contribution in &statement.contributions {
        material.extend_from_slice(contribution.c1.compress().as_ref());
        material.extend_from_slice(contribution.c2.compress().as_ref());
    }
    poseidon_bytes_digest(&material)
}

/// The deterministic initial encrypted deck (stage-0 spec decision).
///
/// `canonical_base_deck`: `encrypt(card_i, aggregate_pk, r = i+1)` — public,
/// deterministic per-index randomness, so the deck is a *well-formed
/// aggregate-key encryption* (decryptable by the share sum, re-encryptable by
/// Bayer–Groth, and V3-rebuildable) while remaining Cairo-replicable.
///
/// This deliberately diverges from the poker_l1 `set_initial_encrypted_deck`
/// `(G, plaintext_i)` seed form: that shape is only decryptable under the
/// token-sum convention before any shuffle and is not a valid aggregate-key
/// ciphertext (its implied randomness `r = 1` never appears in `c2`). The
/// divergence and the reconciliation duty are recorded in the stage-0 report.
pub fn canonical_initial_deck(aggregate_pk: &EcPoint) -> TexasAirResult<Vec<ElGamalCiphertext>> {
    if aggregate_pk.is_identity() {
        return Err(TexasAirError::SpecViolation(
            "initial deck needs a non-identity aggregate key".into(),
        ));
    }
    let plaintexts = poker_l1::contracts::texas_poker::core::utils::generate_plaintext_cards();
    canonical_base_deck::<DefaultCurve>(&plaintexts, aggregate_pk).map_err(|error| {
        TexasAirError::SpecViolation(format!("canonical base deck rejected: {error}"))
    })
}

// ============================================================
// Sidecar: per-row native proof material (§6-Q2 stage-0 container)
// ============================================================

/// Native material for one `SubmitShuffle` row (in-memory stage-0 sidecar;
/// the transport shape is §6-Q2 and stays open).
#[derive(Debug, Clone)]
pub struct ShuffleRowMaterial {
    /// Submitting seat; must equal the canonical row's `action.seat`.
    pub seat: u8,
    /// Aggregate encryption key the deck is layered under.
    pub aggregate_pk: EcPoint,
    /// Deck before this contribution (commitment = row `pre.deck_commitment`).
    pub input_deck: Vec<ElGamalCiphertext>,
    /// Deck after this contribution (commitment = row `post.deck_commitment`).
    pub output_deck: Vec<ElGamalCiphertext>,
    /// Bayer–Groth V2 proof of `output = permute·re-encrypt(input; pk)`.
    pub proof: BayerGrothShuffleProof<DefaultCurve>,
}

/// Native material for one `SubmitReveal` row.
#[derive(Debug, Clone)]
pub struct RevealRowMaterial {
    /// Submitting seat; must equal the canonical row's `action.seat`.
    pub seat: u8,
    /// The seat's registered encryption key (token ownership binding).
    pub seat_pk: EcPoint,
    /// Per-card token material; the row's reveal commitment rotates over it.
    pub revealed: Vec<RevealedCardMaterial>,
}

/// One reveal token plus its DLEq proof.
#[derive(Debug, Clone)]
pub struct RevealedCardMaterial {
    /// Token material entering the ledger commitment rotation.
    pub revealed: RevealedCard,
    /// Sigma proof `log_g(sk) = log_{c1}(token)` bound to the seat key.
    pub proof: RevealTokenProof<DefaultCurve>,
}

/// Native material for one `SubmitReconstruct` row.
#[derive(Debug, Clone)]
pub struct ReconstructRowMaterial {
    /// Submitting seat; must equal the canonical row's `action.seat`.
    pub seat: u8,
    /// V3 public statement (contributions, cards, keys, digests).
    pub statement: ReconstructionStatement<DefaultCurve>,
    /// Lean-fixed V3 proof over the statement.
    pub proof: ReconstructProof<DefaultCurve>,
    /// Deck rebuilt from the canonical base plus the statement contributions
    /// (commitment = the completion row's `post.deck_commitment`).
    pub rebuilt_deck: Vec<ElGamalCiphertext>,
}


/// Stage-0 in-memory sidecar carrying the native proof material for every
/// protocol row of one canonical batch, in batch order.
#[derive(Debug, Clone, Default)]
pub struct ShuffleChainSidecar {
    /// Materials aligned with the batch's `SubmitShuffle` rows, in order.
    pub shuffles: Vec<ShuffleRowMaterial>,
    /// Materials aligned with the batch's plain `SubmitReveal` rows (the
    /// reveal-timeout kick rows carry their own ZR4A opening instead), in order.
    pub reveals: Vec<RevealRowMaterial>,
    /// Materials aligned with the batch's `SubmitReconstruct` rows, in order.
    pub reconstructs: Vec<ReconstructRowMaterial>,
}

impl ShuffleChainSidecar {
    fn take_shuffle(&mut self, seat: u8) -> TexasAirResult<ShuffleRowMaterial> {
        let aligned = self
            .shuffles
            .first()
            .ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "shuffle-chain sidecar has no material for a SubmitShuffle row".into(),
                )
            })?
            .seat
            == seat;
        if !aligned {
            return Err(TexasAirError::SpecViolation(
                "shuffle-chain sidecar shuffle material is misaligned with the batch order".into(),
            ));
        }
        Ok(self.shuffles.remove(0))
    }

    fn take_reveal(&mut self, seat: u8) -> TexasAirResult<RevealRowMaterial> {
        let aligned = self
            .reveals
            .first()
            .ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "shuffle-chain sidecar has no material for a SubmitReveal row".into(),
                )
            })?
            .seat
            == seat;
        if !aligned {
            return Err(TexasAirError::SpecViolation(
                "shuffle-chain sidecar reveal material is misaligned with the batch order".into(),
            ));
        }
        Ok(self.reveals.remove(0))
    }

    fn take_reconstruct(&mut self, seat: u8) -> TexasAirResult<ReconstructRowMaterial> {
        let aligned = self
            .reconstructs
            .first()
            .ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "shuffle-chain sidecar has no material for a SubmitReconstruct row".into(),
                )
            })?
            .seat
            == seat;
        if !aligned {
            return Err(TexasAirError::SpecViolation(
                "shuffle-chain sidecar reconstruct material is misaligned with the batch order"
                    .into(),
            ));
        }
        Ok(self.reconstructs.remove(0))
    }
}

// ============================================================
// Receipts (route B upstream half)
// ============================================================

/// Verifier-computed shuffle-chain receipts for one canonical batch.
///
/// Everything here is re-derivable by any party holding the archive, the
/// witnesses, and the sidecar material — the digests are the anchoring points
/// for attestation v2.2 and watcher replay (route B), not a trust root by
/// themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShuffleChainReceipt {
    /// `batch_digest` of the proven witness sequence (blake2b tagged-batch v2).
    pub batch_digest: [u8; 32],
    /// Poseidon fold of every deck-chain commitment in batch order (initial
    /// deck + one entry per shuffle/reconstruct rotation).
    pub deck_chain_digest: [u8; 32],
    /// Poseidon fold of every sidecar-covered reveal-ledger rotation, in
    /// batch order.
    pub reveal_chain_digest: [u8; 32],
    /// Poseidon fold of every reconstruction-commitment rotation, in order.
    pub reconstruct_chain_digest: [u8; 32],
    /// One statement digest per protocol row, in batch order.
    pub statement_digests: Vec<[u8; 32]>,
    /// Engine receipt digest: Poseidon fold of the domain, the batch digest,
    /// the three chain digests, and every statement digest. Consumers archive
    /// this value alongside the attestation.
    pub engine_receipt_digest: [u8; 32],
}

// ============================================================
// Producer: fail-closed witness construction from real crypto
// ============================================================

/// Per-player key material registered for a hand.
#[derive(Debug, Clone)]
pub struct PlayerKeys {
    /// Canonical seat index this key pair acts for.
    pub seat: u8,
    /// Mental-poker secret key (never leaves the producer).
    pub secret: <DefaultCurve as Curve>::Scalar,
    /// `g · secret` — the registered encryption key.
    pub public: EcPoint,
}

/// Derived betting header for the RevealComplete normalization (VM
/// `post_blinds` + `start_betting_round(is_preflop=true)` projection). The
/// seats/turn are derived from the pre image; the caller only supplies the
/// authenticated blind amounts.
#[derive(Debug, Clone, Copy)]
struct RevealCompletionHeader {
    sb_amount: u64,
    bb_amount: u64,
}

/// Stage-0 shuffle-chain producer.
///
/// Owns the live deck lineage of one hand and emits canonical protocol rows
/// whose commitment rotations are computed from the real ciphertexts. Every
/// method verifies its proof natively **before** touching the lineage, so a
/// producer bug can only stall the hand, never anchor an unverified statement.
#[derive(Debug, Clone)]
pub struct ShuffleChainBuilder {
    players: Vec<PlayerKeys>,
    aggregate_pk: EcPoint,
    deck: Vec<ElGamalCiphertext>,
    sidecar: ShuffleChainSidecar,
    /// Deck-chain commitments in emission order (starts with the initial deck).
    deck_chain: Vec<[u8; 32]>,
    /// Authenticated blind amounts for the final reveal row (sb, bb).
    reveal_completion_header: Option<RevealCompletionHeader>,
}

impl ShuffleChainBuilder {
    /// Create a builder for one hand: initial deck `(G, m_i)` under the
    /// aggregate key of the registered players.
    pub fn new(players: Vec<PlayerKeys>) -> TexasAirResult<Self> {
        if players.len() < 2 {
            return Err(TexasAirError::SpecViolation(
                "shuffle-chain builder needs at least two players".into(),
            ));
        }
        let mut aggregate_pk = EcPoint::identity();
        for player in &players {
            if player.public.is_identity()
                || player.public != DefaultCurve::base_g() * player.secret
            {
                return Err(TexasAirError::SpecViolation("player key is not g^sk".into()));
            }
            aggregate_pk += player.public;
        }
        let deck = canonical_initial_deck(&aggregate_pk)?;
        let initial = canonical_deck_commitment(&deck)?;
        Ok(Self {
            players,
            aggregate_pk,
            deck,
            sidecar: ShuffleChainSidecar::default(),
            deck_chain: vec![initial],
            reveal_completion_header: None,
        })
    }

    /// Commitment of the current deck lineage (the pre-deck endpoint the next
    /// rotation must anchor).
    pub fn current_deck_commitment(&self) -> TexasAirResult<[u8; 32]> {
        canonical_deck_commitment(&self.deck)
    }

    /// The initial-deck commitment (deck-chain genesis; the `StartHand` row
    /// anchors this value into the hand's opening state image, S1).
    pub fn initial_deck_commitment(&self) -> [u8; 32] {
        self.deck_chain[0]
    }

    /// The aggregate encryption key of the registered players.
    pub fn aggregate_pk(&self) -> EcPoint {
        self.aggregate_pk
    }

    /// The live deck lineage (stage-0 test/producer introspection; a real
    /// operator would hold this server-side).
    pub fn deck(&self) -> &[ElGamalCiphertext] {
        &self.deck
    }

    /// Aggregate secret `Σ sk_i`. Stage-0 honesty marker (design doc §6-Q4):
    /// in v1 every participant key is operator-custodied, so the test/producer
    /// can reconstruct it; a production deployment must never need this value
    /// outside the client wallets.
    pub fn aggregate_secret(&self) -> <DefaultCurve as Curve>::Scalar {
        self.players.iter().map(|player| player.secret).sum()
    }

    /// Stage-0 debug/introspection accessor for one seat's secret key.
    pub fn seat_secret_pub(&self, seat: u8) -> <DefaultCurve as Curve>::Scalar {
        *self.seat_secret(seat).expect("known seat")
    }

    /// The per-seat reveal token a seat's key layer contributes to one deck
    /// ciphertext (`c1 · sk_seat`).
    pub fn reveal_token_for(&self, seat: u8, card: &ElGamalCiphertext) -> TexasAirResult<EcPoint> {
        Ok(card.gen_reveal_token(self.seat_secret(seat)?))
    }

    /// Supply the authenticated blind amounts (from the table rules) for the
    /// final reveal row's RevealComplete normalization. Blind seats and the
    /// UTG turn are derived from the pre image at production time.
    pub fn set_reveal_completion_blinds(&mut self, sb_amount: u64, bb_amount: u64) {
        self.reveal_completion_header = Some(RevealCompletionHeader {
            sb_amount,
            bb_amount,
        });
    }

    fn seat_secret(&self, seat: u8) -> TexasAirResult<&<DefaultCurve as Curve>::Scalar> {
        self.players
            .iter()
            .find(|player| player.seat == seat)
            .map(|player| &player.secret)
            .ok_or_else(|| TexasAirError::SpecViolation("unknown seat".into()))
    }

    fn seat_public(&self, seat: u8) -> TexasAirResult<&EcPoint> {
        self.players
            .iter()
            .find(|player| player.seat == seat)
            .map(|player| &player.public)
            .ok_or_else(|| TexasAirError::SpecViolation("unknown seat".into()))
    }

    /// Produce one `SubmitShuffle` witness row: prove Bayer–Groth V2 over the
    /// live deck with a caller-supplied permutation/rerandomizer schedule,
    /// verify the proof natively, then rotate the lineage.
    ///
    /// `permute(n)` must return a permutation of `0..n` plus `n` fresh
    /// rerandomization scalars. The caller keeps entropy control; the builder
    /// keeps correctness control.
    pub fn produce_shuffle_row(
        &mut self,
        pre: CanonicalStateImage,
        rng: &mut (impl CryptoRng + RngCore),
        permute: impl FnOnce(usize) -> (Vec<usize>, Vec<<DefaultCurve as Curve>::Scalar>),
    ) -> TexasAirResult<CanonicalTransitionWitness> {
        let seat = pre_call_seat_of(&pre, CanonicalTransitionKind::SubmitShuffle)?;
        let (permutation, rerandomizers) = permute(self.deck.len());
        if permutation.len() != self.deck.len() || rerandomizers.len() != self.deck.len() {
            return Err(TexasAirError::SpecViolation(
                "shuffle permutation/rerandomizer length mismatch".into(),
            ));
        }
        let input_deck = self.deck.clone();
        let output_deck: Vec<ElGamalCiphertext> = permutation
            .iter()
            .zip(&rerandomizers)
            .map(|(&source, r)| input_deck[source].re_encrypt(&self.aggregate_pk, r))
            .collect();
        let mut transcript =
            PoseidonFeltTranscript::new_domain(transcript_domains::SHUFFLE_V2_POSEIDON);
        let proof = BayerGrothShuffleProof::<DefaultCurve>::prove(
            &input_deck,
            &output_deck,
            &permutation,
            &rerandomizers,
            &self.aggregate_pk,
            rng,
            &mut transcript,
        )
        .map_err(|error| {
            TexasAirError::SpecViolation(format!("BG prove rejected its own statement: {error}"))
        })?;
        // Fail-closed producer: verify before anchoring.
        let mut verify_transcript =
            PoseidonFeltTranscript::new_domain(transcript_domains::SHUFFLE_V2_POSEIDON);
        proof
            .verify(
                &input_deck,
                &output_deck,
                &self.aggregate_pk,
                &mut verify_transcript,
            )
            .map_err(|error| {
                TexasAirError::SpecViolation(format!("producer BG verify failed: {error}"))
            })?;

        let output_commitment = canonical_deck_commitment(&output_deck)?;
        let is_final = pre.protocol_pending_mask.count_ones() == 1;
        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        post.protocol_pending_mask = pre.protocol_pending_mask & !(1u16 << seat);
        post.deck_commitment = output_commitment;
        let completion = if is_final {
            // Final contribution: the completion opening normalizes the hand
            // into the preflop reveal phase (VM `advance_shuffle` tail).
            let completion_timestamp = stage0_timestamp(&pre);
            post.phase = CanonicalPhase::Revealing;
            post.phase_subtag = 1;
            // NOTE (stage-0 finding): the AIR pins `post.street == pre.street`
            // here, while the reveal-completion header demands street 1 — a
            // StartHand-origin batch (street 0) can therefore never reach
            // RevealComplete in one batch. Callers bridge this by handing the
            // producer a hand-start projection whose street already carries
            // the preflop value (see tests/canonical_shuffle_chain_stage0.rs);
            // the upstream fix proposal is documented in the stage-0 report.
            post.deadline_ms = completion_timestamp
                .checked_add(u64::from(pre.reveal_timeout_ms))
                .ok_or_else(|| TexasAirError::SpecViolation("reveal deadline overflow".into()))?;
            let active_mask = active_reveal_mask(&post.seats);
            post.protocol_pending_mask = active_mask;
            CanonicalProtocolCompletionOpening {
                kind: CanonicalProtocolCompletionKind::Shuffle,
                completion_timestamp_ms: completion_timestamp,
                pre_cards_dealt: 0,
                post_cards_dealt: u8::try_from(2 * active_mask.count_ones()).map_err(|_| {
                    TexasAirError::SpecViolation("participant count exceeds u8".into())
                })?,
                post_shuffle_pending_mask: active_mask,
                post_shuffle_completed_mask: active_mask,
                pre_deck_commitment: pre.deck_commitment,
                post_deck_commitment: output_commitment,
                pre_reconstruction_commitment: pre.reconstruction_commitment,
                post_reconstruction_commitment: pre.reconstruction_commitment,
                ..Default::default()
            }
        } else {
            Default::default()
        };
        let witness = build_protocol_row(
            pre,
            post,
            CanonicalTransitionKind::SubmitShuffle,
            seat,
            output_commitment,
            completion,
            CanonicalBlindOpening::ZERO,
        );
        self.deck = output_deck;
        self.deck_chain.push(output_commitment);
        self.sidecar.shuffles.push(ShuffleRowMaterial {
            seat,
            aggregate_pk: self.aggregate_pk,
            input_deck,
            output_deck: self.deck.clone(),
            proof,
        });
        Ok(witness)
    }

    /// Produce one `SubmitReveal` witness row for `card_indices` (deck-lineage
    /// indices) of `seat`: generate + prove the per-card reveal tokens, verify
    /// them natively, then rotate the reveal ledger commitment. The final
    /// pending contribution normalizes into the preflop betting round with
    /// the blinds previously supplied to
    /// [`Self::set_reveal_completion_blinds`].
    pub fn produce_reveal_row(
        &mut self,
        pre: CanonicalStateImage,
        seat: u8,
        card_indices: &[usize],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> TexasAirResult<CanonicalTransitionWitness> {
        if card_indices.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "reveal row needs at least one card index".into(),
            ));
        }
        let secret = *self.seat_secret(seat)?;
        let seat_pk = *self.seat_public(seat)?;
        let mut revealed = Vec::with_capacity(card_indices.len());
        let mut materials = Vec::with_capacity(card_indices.len());
        for &index in card_indices {
            let encrypted_card = *self.deck.get(index).ok_or_else(|| {
                TexasAirError::SpecViolation("reveal index outside the deck lineage".into())
            })?;
            let reveal_token = encrypted_card.gen_reveal_token(&secret);
            let mut transcript =
                PoseidonFeltTranscript::new_domain(transcript_domains::REVEAL_TOKEN_V3_POSEIDON);
            let proof = RevealTokenProof::<DefaultCurve>::prove(
                &secret,
                &seat_pk,
                &encrypted_card,
                &reveal_token,
                rng,
                &mut transcript,
            );
            // Fail-closed producer: verify before anchoring.
            let mut verify_transcript = PoseidonFeltTranscript::new_domain(
                transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
            );
            proof
                .verify(
                    &encrypted_card,
                    &reveal_token,
                    &seat_pk,
                    &mut verify_transcript,
                )
                .map_err(|error| {
                    TexasAirError::SpecViolation(format!(
                        "producer reveal-token verify failed: {error:?}"
                    ))
                })?;
            revealed.push(RevealedCard {
                encrypted_card,
                reveal_token,
            });
            materials.push(RevealedCardMaterial {
                revealed: *revealed.last().expect("just pushed"),
                proof,
            });
        }
        let pre_reveal = pre.reveal_commitment;
        let reveal_commitment = canonical_reveal_commitment(&pre_reveal, seat, &revealed)?;

        let is_final = pre.protocol_pending_mask.count_ones() == 1;
        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        post.protocol_pending_mask = pre.protocol_pending_mask & !(1u16 << seat);
        post.reveal_commitment = reveal_commitment;
        let completion = if is_final {
            // Final contribution: RevealComplete normalizes the hand into the
            // preflop betting round (VM `post_blinds` + `start_betting_round`).
            let header = self.reveal_completion_header.ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "final reveal row requires set_reveal_completion_blinds".into(),
                )
            })?;
            let completion_timestamp = stage0_timestamp(&pre);
            let (sb_seat, bb_seat) = blind_seats_of(&pre)?;
            // Dead small blind 成对纪律：SB 座位空缺 ⟺ SB 金额为零。
            if (sb_seat == NO_CANONICAL_SEAT) != (header.sb_amount == 0)
                || header.bb_amount == 0
                || header.sb_amount > header.bb_amount
            {
                return Err(TexasAirError::SpecViolation(
                    "reveal completion needs 0 <= sb <= bb (dead sb allowed)".into(),
                ));
            }
            let current_turn =
                next_active_seat(&pre.seats, bb_seat, pre.max_players).ok_or_else(|| {
                    TexasAirError::SpecViolation("reveal completion has no UTG seat".into())
                })?;
            // dead button 盲注轨道：本手大盲座位成为下一手的轮转基准。
            post.last_bb_seat = bb_seat;
            post.phase = CanonicalPhase::Betting;
            post.phase_subtag = 1;
            post.deadline_ms = completion_timestamp
                .checked_add(u64::from(pre.betting_timeout_ms))
                .ok_or_else(|| TexasAirError::SpecViolation("betting deadline overflow".into()))?;
            post.protocol_pending_mask = 0;
            post.current_turn = current_turn;
            post.current_bet = header.bb_amount;
            post.min_raise = header.bb_amount;
            for (index, seat_state) in post.seats.iter_mut().enumerate() {
                let posted = if index == usize::from(sb_seat) {
                    header.sb_amount
                } else if index == usize::from(bb_seat) {
                    header.bb_amount
                } else {
                    0
                };
                let stack = seat_state.stack.checked_sub(posted).ok_or_else(|| {
                    TexasAirError::SpecViolation("blinds exceed a seat stack".into())
                })?;
                if posted > 0 && stack == 0 {
                    return Err(TexasAirError::SpecViolation(
                        "blinds cap a seat stack (uncapped discipline)".into(),
                    ));
                }
                seat_state.stack = stack;
                seat_state.bet = posted;
                seat_state.total_bet = posted;
            }
            CanonicalProtocolCompletionOpening {
                kind: CanonicalProtocolCompletionKind::Reveal,
                completion_timestamp_ms: completion_timestamp,
                post_current_turn: current_turn,
                sb_seat,
                bb_seat,
                sb_amount: header.sb_amount,
                bb_amount: header.bb_amount,
                is_heads_up: is_heads_up(&pre),
                pre_reveal_commitment: pre_reveal,
                post_reveal_commitment: reveal_commitment,
                pre_deck_commitment: pre.deck_commitment,
                post_deck_commitment: pre.deck_commitment,
                pre_reconstruction_commitment: pre.reconstruction_commitment,
                post_reconstruction_commitment: pre.reconstruction_commitment,
                ..Default::default()
            }
        } else {
            Default::default()
        };
        let witness = build_protocol_row(
            pre,
            post,
            CanonicalTransitionKind::SubmitReveal,
            seat,
            reveal_commitment,
            completion,
            if is_final {
                CanonicalBlindOpening {
                    small_blind: self
                        .reveal_completion_header
                        .map(|header| header.sb_amount)
                        .unwrap_or(0),
                    big_blind: self
                        .reveal_completion_header
                        .map(|header| header.bb_amount)
                        .unwrap_or(0),
                    ante_mode: 0,
                    ante_amount: 0,
                }
            } else {
                CanonicalBlindOpening::ZERO
            },
        );
        self.sidecar.reveals.push(RevealRowMaterial {
            seat,
            seat_pk,
            revealed: materials,
        });
        Ok(witness)
    }

    /// Produce one `SubmitReconstruct` witness row: prove reconstruction V3
    /// over `readable_cards` — the owner-readable ciphertexts (owner key
    /// layer only) the caller derived from the live lineage — verify
    /// natively, and anchor the commitments. The completion row opens the
    /// **fresh V3 lineage** (canonical base + contributions) as the new deck
    /// commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn produce_reconstruct_row(
        &mut self,
        pre: CanonicalStateImage,
        seat: u8,
        readable_cards: &[ElGamalCiphertext],
        context_digest: [u8; 32],
        reconstruction_epoch: u64,
        prior_state_digest: [u8; 32],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> TexasAirResult<CanonicalTransitionWitness> {
        if readable_cards.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "reconstruct row needs at least one readable card".into(),
            ));
        }
        let secret = *self.seat_secret(seat)?;
        let seat_pk = *self.seat_public(seat)?;
        let readable_cards = readable_cards.to_vec();
        let cards = poker_l1::contracts::texas_poker::core::utils::generate_plaintext_cards();
        let mut transcript =
            PoseidonFeltTranscript::new_domain(transcript_domains::RECONSTRUCT_POSEIDON);
        let (statement, proof) = ReconstructProof::<DefaultCurve>::prove(
            context_digest,
            reconstruction_epoch,
            prior_state_digest,
            cards,
            readable_cards,
            &secret,
            &seat_pk,
            &self.aggregate_pk,
            rng,
            &mut transcript,
        )
        .map_err(|error| {
            TexasAirError::SpecViolation(format!("V3 prove rejected its own statement: {error}"))
        })?;
        // Fail-closed producer: verify before anchoring.
        let mut verify_transcript =
            PoseidonFeltTranscript::new_domain(transcript_domains::RECONSTRUCT_POSEIDON);
        proof
            .verify(&statement, &mut verify_transcript)
            .map_err(|error| {
                TexasAirError::SpecViolation(format!("producer V3 verify failed: {error}"))
            })?;
        let base = canonical_base_deck::<DefaultCurve>(&statement.cards, &statement.aggregate_pk)
            .map_err(|error| {
                TexasAirError::SpecViolation(format!("V3 canonical base rejected: {error}"))
            })?;
        let rebuilt = apply_reconstruction_contributions(&base, &statement.contributions)
            .map_err(|error| {
                TexasAirError::SpecViolation(format!("V3 contribution apply rejected: {error}"))
            })?;
        let rebuilt_commitment = canonical_deck_commitment(&rebuilt)?;
        let reconstruction_commitment = canonical_reconstruction_commitment(&statement);

        let is_final = pre.protocol_pending_mask.count_ones() == 1;
        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        post.protocol_pending_mask = pre.protocol_pending_mask & !(1u16 << seat);
        post.reconstruction_commitment = reconstruction_commitment;
        let completion = if is_final {
            // Reconstruct completion: the VM restarts the protocol with a
            // freshly rebuilt deck (Shuffling / reconstruct-shuffle subtag 2).
            let completion_timestamp = stage0_timestamp(&pre);
            post.phase = CanonicalPhase::Shuffling;
            post.phase_subtag = crate::texas_canonical::CANONICAL_SHUFFLE_RECONSTRUCT_SUBTAG;
            post.deadline_ms = completion_timestamp
                .checked_add(u64::from(pre.shuffle_timeout_ms))
                .ok_or_else(|| TexasAirError::SpecViolation("shuffle deadline overflow".into()))?;
            let active_mask = active_reveal_mask(&post.seats);
            post.protocol_pending_mask = active_mask;
            post.deck_commitment = rebuilt_commitment;
            CanonicalProtocolCompletionOpening {
                kind: CanonicalProtocolCompletionKind::Reconstruct,
                completion_timestamp_ms: completion_timestamp,
                pre_cards_dealt: 0,
                post_cards_dealt: 0,
                suspended_reveal_commitment: pre.reveal_commitment,
                post_shuffle_pending_mask: active_mask,
                post_shuffle_completed_mask: 0,
                pre_deck_commitment: pre.deck_commitment,
                post_deck_commitment: rebuilt_commitment,
                pre_reconstruction_commitment: pre.reconstruction_commitment,
                post_reconstruction_commitment: reconstruction_commitment,
                ..Default::default()
            }
        } else {
            Default::default()
        };
        let witness = build_protocol_row(
            pre,
            post,
            CanonicalTransitionKind::SubmitReconstruct,
            seat,
            reconstruction_commitment,
            completion,
            CanonicalBlindOpening::ZERO,
        );
        if is_final {
            self.deck = rebuilt.clone();
            self.deck_chain.push(rebuilt_commitment);
        }
        self.sidecar.reconstructs.push(ReconstructRowMaterial {
            seat,
            statement,
            proof,
            rebuilt_deck: rebuilt,
        });
        Ok(witness)
    }

    /// Detach the accumulated sidecar (leaves the builder's lineage intact).
    pub fn into_sidecar(&self) -> ShuffleChainSidecar {
        self.sidecar.clone()
    }
}

// ============================================================
// Native verification (route A) + receipts (route B)
// ============================================================

/// Verify one canonical tagged batch **together with** its shuffle-chain
/// sidecar: full STARK verification, archive↔witness binding, per-row native
/// BG/DLEq/V3 verification, and commitment-chain re-derivation (route A),
/// then the receipt digests (route B).
///
/// Fail-closed on every mismatch: a missing, extra, misordered, or tampered
/// sidecar entry rejects the batch.
pub fn verify_canonical_batch_with_shuffle_chain(
    archive: &ArchivedCanonicalTaggedProof,
    witnesses: &[CanonicalTransitionWitness],
    sidecar: &mut ShuffleChainSidecar,
) -> TexasAirResult<ShuffleChainReceipt> {
    // 1. Full canonical STARK verification (shape, endpoints, rake/blind
    //    bindings, stwo proof).
    verify_canonical_tagged_proof(archive)?;

    // 2. The witness sequence must be the proven one.
    if witnesses.is_empty() {
        return Err(TexasAirError::SpecViolation(
            "shuffle-chain verification needs a non-empty witness batch".into(),
        ));
    }
    crate::texas_canonical::validate_direct_batch(witnesses)
        .map_err(TexasAirError::SpecViolation)?;
    if batch_digest_for_witnesses(witnesses) != archive.batch_digest {
        return Err(TexasAirError::SpecViolation(
            "witness batch digest is detached from the canonical archive".into(),
        ));
    }
    if witnesses.len() != usize::from(archive.transition_count)
        || witnesses[0].kind as u8 != archive.first_transition_kind
        || witnesses[witnesses.len() - 1].kind as u8 != archive.last_transition_kind
        || witnesses[0].pre.table_id != archive.table_id
    {
        return Err(TexasAirError::SpecViolation(
            "witness batch envelope is detached from the canonical archive".into(),
        ));
    }
    let pre_bytes = borsh::to_vec(&witnesses[0].pre)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let post_bytes = borsh::to_vec(&witnesses[witnesses.len() - 1].post)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    if pre_bytes != archive.pre_state_image_bytes || post_bytes != archive.post_state_image_bytes {
        return Err(TexasAirError::SpecViolation(
            "witness endpoint images are detached from the canonical archive".into(),
        ));
    }

    // 3. Native per-row verification with commitment-chain re-derivation.
    let mut deck_chain: Vec<[u8; 32]> = Vec::new();
    let mut reveal_chain: Vec<[u8; 32]> = Vec::new();
    let mut reconstruct_chain: Vec<[u8; 32]> = Vec::new();
    let mut statement_digests: Vec<[u8; 32]> = Vec::new();
    for witness in witnesses {
        match witness.kind {
            CanonicalTransitionKind::SubmitShuffle => {
                let seat = witness.action.seat;
                let material = sidecar.take_shuffle(seat)?;
                let input = canonical_deck_commitment(&material.input_deck)?;
                let output = canonical_deck_commitment(&material.output_deck)?;
                if input != witness.pre.deck_commitment {
                    return Err(TexasAirError::SpecViolation(
                        "shuffle input ciphertexts do not hash to the row's pre deck commitment"
                            .into(),
                    ));
                }
                if output != witness.post.deck_commitment {
                    return Err(TexasAirError::SpecViolation(
                        "shuffle output ciphertexts do not hash to the row's post deck commitment"
                            .into(),
                    ));
                }
                let mut transcript =
                    PoseidonFeltTranscript::new_domain(transcript_domains::SHUFFLE_V2_POSEIDON);
                material
                    .proof
                    .verify(
                        &material.input_deck,
                        &material.output_deck,
                        &material.aggregate_pk,
                        &mut transcript,
                    )
                    .map_err(|error| {
                        TexasAirError::SpecViolation(format!(
                            "native BG verify failed for seat {seat}: {error}"
                        ))
                    })?;
                statement_digests.push(statement_digest(
                    b"shuffle",
                    seat,
                    witness.pre.deck_commitment,
                    witness.post.deck_commitment,
                ));
                deck_chain.push(output);
            }
            CanonicalTransitionKind::SubmitReveal => {
                let seat = witness.action.seat;
                let material = sidecar.take_reveal(seat)?;
                for entry in &material.revealed {
                    let mut transcript = PoseidonFeltTranscript::new_domain(
                        transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
                    );
                    entry
                        .proof
                        .verify(
                            &entry.revealed.encrypted_card,
                            &entry.revealed.reveal_token,
                            &material.seat_pk,
                            &mut transcript,
                        )
                        .map_err(|error| {
                            TexasAirError::SpecViolation(format!(
                                "native reveal-token verify failed for seat {seat}: {error:?}"
                            ))
                        })?;
                }
                let rotated = canonical_reveal_commitment(
                    &witness.pre.reveal_commitment,
                    seat,
                    &material
                        .revealed
                        .iter()
                        .map(|entry| entry.revealed)
                        .collect::<Vec<_>>(),
                )?;
                if rotated != witness.post.reveal_commitment {
                    return Err(TexasAirError::SpecViolation(
                        "reveal tokens do not re-derive the row's reveal commitment rotation"
                            .into(),
                    ));
                }
                statement_digests.push(statement_digest(
                    b"reveal",
                    seat,
                    witness.pre.reveal_commitment,
                    witness.post.reveal_commitment,
                ));
                reveal_chain.push(rotated);
            }
            CanonicalTransitionKind::SubmitReconstruct => {
                let seat = witness.action.seat;
                let material = sidecar.take_reconstruct(seat)?;
                let mut transcript =
                    PoseidonFeltTranscript::new_domain(transcript_domains::RECONSTRUCT_POSEIDON);
                material
                    .proof
                    .verify(&material.statement, &mut transcript)
                    .map_err(|error| {
                        TexasAirError::SpecViolation(format!(
                            "native V3 verify failed for seat {seat}: {error}"
                        ))
                    })?;
                let rotated = canonical_reconstruction_commitment(&material.statement);
                if rotated != witness.post.reconstruction_commitment {
                    return Err(TexasAirError::SpecViolation(
                        "V3 statement does not re-derive the row's reconstruction commitment"
                            .into(),
                    ));
                }
                if rotated
                    == witness.protocol_completion.pre_reconstruction_commitment
                    && witness.protocol_completion.kind
                        != CanonicalProtocolCompletionKind::None
                {
                    return Err(TexasAirError::SpecViolation(
                        "reconstruct completion did not rotate the reconstruction commitment"
                            .into(),
                    ));
                }
                if witness.protocol_completion.kind == CanonicalProtocolCompletionKind::Reconstruct
                {
                    let rebuilt = canonical_deck_commitment(&material.rebuilt_deck)?;
                    if rebuilt != witness.post.deck_commitment {
                        return Err(TexasAirError::SpecViolation(
                            "rebuilt deck does not hash to the completion row's post deck commitment"
                                .into(),
                        ));
                    }
                }
                statement_digests.push(statement_digest(
                    b"reconstruct",
                    seat,
                    witness.pre.reconstruction_commitment,
                    witness.post.reconstruction_commitment,
                ));
                reconstruct_chain.push(rotated);
            }
            _ => {}
        }
    }

    // No surplus material: every sidecar entry must have been consumed.
    if !sidecar.shuffles.is_empty()
        || !sidecar.reveals.is_empty()
        || !sidecar.reconstructs.is_empty()
    {
        return Err(TexasAirError::SpecViolation(
            "shuffle-chain sidecar carries unconsumed material".into(),
        ));
    }

    // 4. Receipt digests (route B upstream half).
    let deck_chain_digest = fold_chain(b"deck-chain", &deck_chain);
    let reveal_chain_digest = fold_chain(b"reveal-chain", &reveal_chain);
    let reconstruct_chain_digest = fold_chain(b"reconstruct-chain", &reconstruct_chain);
    let mut engine_material = Vec::with_capacity(160 + statement_digests.len() * 32);
    engine_material.extend_from_slice(SHUFFLE_CHAIN_STAGE0_DOMAIN);
    engine_material.extend_from_slice(b"receipt");
    engine_material.extend_from_slice(&archive.batch_digest);
    engine_material.extend_from_slice(&deck_chain_digest);
    engine_material.extend_from_slice(&reveal_chain_digest);
    engine_material.extend_from_slice(&reconstruct_chain_digest);
    for digest in &statement_digests {
        engine_material.extend_from_slice(digest);
    }
    let engine_receipt_digest = poseidon_bytes_digest(&engine_material);
    Ok(ShuffleChainReceipt {
        batch_digest: archive.batch_digest,
        deck_chain_digest,
        reveal_chain_digest,
        reconstruct_chain_digest,
        statement_digests,
        engine_receipt_digest,
    })
}

// ============================================================
// Internal helpers
// ============================================================

fn statement_digest(kind: &[u8], seat: u8, pre: [u8; 32], post: [u8; 32]) -> [u8; 32] {
    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(SHUFFLE_CHAIN_STAGE0_DOMAIN);
    material.extend_from_slice(kind);
    material.push(seat);
    material.extend_from_slice(&pre);
    material.extend_from_slice(&post);
    poseidon_bytes_digest(&material)
}

fn fold_chain(label: &[u8], chain: &[[u8; 32]]) -> [u8; 32] {
    let mut material =
        Vec::with_capacity(SHUFFLE_CHAIN_STAGE0_DOMAIN.len() + label.len() + chain.len() * 32);
    material.extend_from_slice(SHUFFLE_CHAIN_STAGE0_DOMAIN);
    material.extend_from_slice(label);
    for entry in chain {
        material.extend_from_slice(entry);
    }
    poseidon_bytes_digest(&material)
}

/// Canonical participating-seat scan (occupied, non-`Empty`/`Out`), mirroring
/// the VM's `find_next_participating_seat` used for SB/BB location.
fn next_participating_seat(
    seats: &[crate::texas_canonical::CanonicalSeat],
    from: u8,
    max: u8,
) -> Option<u8> {
    let max = usize::from(max);
    (1..=max)
        .map(|offset| (usize::from(from) + offset) % max)
        .find(|&index| {
            !matches!(
                seats[index].status,
                CanonicalSeatStatus::Empty | CanonicalSeatStatus::Out
            )
        })
        .map(|index| index as u8)
}

/// Canonical active-seat scan, mirroring the VM's `find_next_active_seat`.
fn next_active_seat(
    seats: &[crate::texas_canonical::CanonicalSeat],
    from: u8,
    max: u8,
) -> Option<u8> {
    let max = usize::from(max);
    (1..=max)
        .map(|offset| (usize::from(from) + offset) % max)
        .find(|&index| seats[index].status == CanonicalSeatStatus::Active)
        .map(|index| index as u8)
}

/// Union of Active/Folded/AllIn participants — the canonical reveal mask.
fn active_reveal_mask(seats: &[crate::texas_canonical::CanonicalSeat]) -> u16 {
    seats.iter().enumerate().fold(0u16, |mask, (index, seat)| {
        if matches!(
            seat.status,
            CanonicalSeatStatus::Active | CanonicalSeatStatus::Folded | CanonicalSeatStatus::AllIn
        ) {
            mask | (1u16 << index)
        } else {
            mask
        }
    })
}

fn is_heads_up(pre: &CanonicalStateImage) -> bool {
    pre.seats
        .iter()
        .filter(|seat| seat.status == CanonicalSeatStatus::Active)
        .count()
        == 2
}

/// `(sb, bb)` per the VM's `post_blinds` dead-button rotation rule.  The big
/// blind is the first participating seat after the previous hand's big blind
/// (the button for a rotation-free table); the small blind is the previous
/// big-blind seat itself, or the other participant heads-up.  A dead small
/// blind is reported as [`NO_CANONICAL_SEAT`].
fn blind_seats_of(pre: &CanonicalStateImage) -> TexasAirResult<(u8, u8)> {
    let rotation_base = if pre.last_bb_seat != NO_CANONICAL_SEAT {
        pre.last_bb_seat
    } else {
        pre.button
    };
    let bb = next_participating_seat(&pre.seats, rotation_base, pre.max_players)
        .unwrap_or(rotation_base);
    if is_heads_up(pre) {
        let sb = next_participating_seat(&pre.seats, bb, pre.max_players).unwrap_or(bb);
        Ok((sb, bb))
    } else {
        let base = &pre.seats[usize::from(rotation_base)];
        let sb = if rotation_base != bb
            && base.status != CanonicalSeatStatus::Empty
            && base.status != CanonicalSeatStatus::Out
        {
            rotation_base
        } else {
            NO_CANONICAL_SEAT
        };
        Ok((sb, bb))
    }
}

/// Stage-0 consensus-timestamp stand-in: the pre deadline (nonzero). Real
/// producers pass the authenticated timestamp; the AIR only checks the
/// derived deadline arithmetic, which the timeout fields pin.
fn stage0_timestamp(pre: &CanonicalStateImage) -> u64 {
    pre.deadline_ms.max(1)
}

fn build_protocol_row(
    pre: CanonicalStateImage,
    post: CanonicalStateImage,
    kind: CanonicalTransitionKind,
    seat: u8,
    proof_commitment: [u8; 32],
    completion: CanonicalProtocolCompletionOpening,
    blind_opening: CanonicalBlindOpening,
) -> CanonicalTransitionWitness {
    let actor = {
        let index = usize::from(seat);
        if index < pre.seats.len() {
            pre.seats[index].identity_commitment
        } else {
            [0; 32]
        }
    };
    let mut witness = CanonicalTransitionWitness {
        pre,
        post,
        kind,
        actor,
        action: CanonicalActionPayload {
            seat,
            amount: 0,
            auxiliary: 0,
            flag: false,
            proof_commitment,
        },
        round_advance: Default::default(),
        protocol_completion: completion,
        rake_opening: CanonicalRakeOpening::ZERO,
        blind_opening,
        transition_commitment: [0; 32],
        nullifier: [0; 32],
        deadline_height: 0,
    };
    witness.seal();
    witness
}

/// The submitting seat for the next protocol row: the canonical next
/// contributor is the lowest pending seat.
fn pre_call_seat_of(
    pre: &CanonicalStateImage,
    kind: CanonicalTransitionKind,
) -> TexasAirResult<u8> {
    let expected_phase = match kind {
        CanonicalTransitionKind::SubmitShuffle => CanonicalPhase::Shuffling,
        CanonicalTransitionKind::SubmitReveal => CanonicalPhase::Revealing,
        CanonicalTransitionKind::SubmitReconstruct => CanonicalPhase::Reconstructing,
        _ => {
            return Err(TexasAirError::SpecViolation(
                "pre_call_seat_of only accepts protocol submit rows".into(),
            ))
        }
    };
    if pre.phase != expected_phase || pre.protocol_pending_mask == 0 {
        return Err(TexasAirError::SpecViolation(
            "producer row requested outside the matching protocol phase/pending mask".into(),
        ));
    }
    u8::try_from(pre.protocol_pending_mask.trailing_zeros())
        .map_err(|_| TexasAirError::SpecViolation("pending seat exceeds u8".into()))
}
