//! Shuffle/deal proof-chain stage 0 — single-batch merged measurement tests
//! (`shuffle-chain stage0`).
//!
//! Stage-0 exit question (docs/shuffle-deal-proof-design.md §4 milestone 0):
//! can one canonical tagged batch carry ordinary betting transitions together
//! with the protocol rows `SubmitShuffle(7)` / `SubmitReveal(8)` /
//! `SubmitReconstruct(9)` and prove + verify end to end, with the deck
//! commitment chain anchored to real Stark-curve ciphertexts and the
//! Bayer–Groth/DLEq statements verified natively on the verify path?
//!
//! Tests print their measurement data; run with `-- --nocapture` to collect
//! the stage-0 report numbers (trace rows, log-size choice, prove/verify
//! wall-clock).

use std::time::Instant;

use poker_protocol::crypto::curve::{Curve, CurveScalar};
use poker_protocol::crypto::types::ElGamalCiphertext;
use poker_protocol::crypto::types::{DefaultCurve, Scalar};
use poker_texas_air::canonical_rake_opening::{
    CanonicalBlindOpening, CanonicalRakeOpening, canonical_rules_commitment,
};
use poker_texas_air::canonical_shuffle_chain::{
    PlayerKeys, ShuffleChainBuilder, ShuffleChainSidecar, verify_canonical_batch_with_shuffle_chain,
};
use poker_texas_air::texas_canonical::{
    CanonicalActionPayload, CanonicalBoardRevealAssignment, CanonicalPhase,
    CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus, CanonicalStateImage,
    CanonicalTransitionKind, CanonicalTransitionWitness, NO_CANONICAL_SEAT, validate_batch,
};
use poker_texas_air::texas_canonical_air::{
    ArchivedCanonicalTaggedProof, prove_canonical_reveal_completion_batch,
    prove_canonical_tagged_batch, verify_canonical_tagged_proof,
};

use rand::SeedableRng;
use rand::rngs::StdRng;

// ============================================================
// Fixtures: a four-player ring with real Stark-curve key material
// ============================================================

const SEATS: u8 = 4;
const BUY_IN: u64 = 10_000;
const SB: u64 = 50;
const BB: u64 = 100;
const RAISE_TO: u64 = 300;
const TABLE_ID: u64 = 7;
const TERMINAL_TIME_BANK_MS: u32 = 30_000;

fn table_rules() -> poker_l1::contracts::texas_poker::types::TableRules {
    poker_l1::contracts::texas_poker::types::TableRules {
        max_players: SEATS,
        small_blind: SB,
        big_blind: BB,
        timeout_config: Default::default(),
        ante_mode: 0,
        ante_amount: 0,
        rake_mode: 0,
        rake_bps: 0,
        rake_cap: 0,
        rit_mode: 0,
    }
}

fn base_image(rules_commitment: [u8; 32], deck_commitment: [u8; 32]) -> CanonicalStateImage {
    CanonicalStateImage {
        abi_version: poker_texas_air::texas_canonical::CANONICAL_ABI_VERSION,
        table_id: TABLE_ID,
        hand_id: 1,
        call_seq: 0,
        phase: CanonicalPhase::Waiting,
        phase_subtag: 0,
        street: 0,
        current_turn: NO_CANONICAL_SEAT,
        deadline_ms: 0,
        shuffle_timeout_ms: 10_000,
        reveal_timeout_ms: 10_000,
        betting_timeout_ms: 30_000,
        reconstruct_timeout_ms: 10_000,
        showdown_display_ms: 3_000,
        current_bet: 0,
        min_raise: 0,
        chip_pool: 0,
        pot: 0,
        button: 0,
        last_bb_seat: NO_CANONICAL_SEAT,
        max_players: SEATS,
        acted_mask: 0,
        leave_after_hand_mask: 0,
        protocol_pending_mask: 0,
        board_cards_commitment: [0; 32],
        deck_commitment,
        reveal_commitment: [0; 32],
        reconstruction_commitment: [0; 32],
        run_it_twice_commitment: [0; 32],
        rules_commitment,
        governance_commitment: [7; 32],
        settlement_commitment: [8; 32],
        custody_commitment: [9; 32],
        lifecycle_root: [10; 32],
        overlay_root: [11; 32],
        state_root: [12; 32],
        seats: [CanonicalSeat::EMPTY; poker_texas_air::texas_canonical::MAX_CANONICAL_SEATS],
    }
}

fn empty_row(
    pre: CanonicalStateImage,
    post: CanonicalStateImage,
    kind: CanonicalTransitionKind,
    seat: u8,
    actor: [u8; 32],
    amount: u64,
    proof_commitment: [u8; 32],
) -> CanonicalTransitionWitness {
    let mut witness = CanonicalTransitionWitness {
        pre,
        post,
        kind,
        actor,
        action: CanonicalActionPayload {
            seat,
            amount,
            auxiliary: 0,
            flag: false,
            proof_commitment,
        },
        round_advance: CanonicalRoundAdvanceOpening::default(),
        protocol_completion: Default::default(),
        rake_opening: CanonicalRakeOpening::ZERO,
        blind_opening: CanonicalBlindOpening::ZERO,
        transition_commitment: [0; 32],
        nullifier: [0; 32],
        deadline_height: 0,
    };
    witness.seal();
    witness
}

fn identity_of(pre: &CanonicalStateImage, seat: u8) -> [u8; 32] {
    pre.seats[usize::from(seat)].identity_commitment
}

fn join_row(pre: CanonicalStateImage, seat: u8, actor_seed: u8) -> CanonicalTransitionWitness {
    let mut post = pre.clone();
    post.call_seq = pre.call_seq + 1;
    post.chip_pool = pre.chip_pool + BUY_IN;
    post.seats[usize::from(seat)] = CanonicalSeat {
        status: CanonicalSeatStatus::Waiting,
        acted: false,
        stack: BUY_IN,
        bet: 0,
        total_bet: 0,
        pending_addon: 0,
        time_bank_ms: TERMINAL_TIME_BANK_MS,
        identity_commitment: [actor_seed; 32],
        key_commitment: [actor_seed + 10; 32],
        hole_cards_commitment: [0; 32],
    };
    empty_row(
        pre,
        post,
        CanonicalTransitionKind::JoinTable,
        seat,
        [actor_seed; 32],
        BUY_IN,
        [0; 32],
    )
}

fn start_hand_row(pre: CanonicalStateImage, hand_id: u32) -> CanonicalTransitionWitness {
    let post = hand_start_projection(&pre, hand_id, false);
    let actor = identity_of(&pre, 0);
    empty_row(
        pre,
        post,
        CanonicalTransitionKind::StartHand,
        NO_CANONICAL_SEAT,
        actor,
        0,
        [0; 32],
    )
}

/// The hand-start state projection the batch producer starts from.
///
/// `street_fix = true` is the stage-0 bridge: the canonical AIR pins
/// `StartHand -> street 0` and pins the shuffle completion to
/// `post.street == pre.street`, while the reveal-completion header demands
/// street 1 — so a StartHand-origin batch can never reach RevealComplete.
/// The producer therefore hands the batch a hand-start projection whose
/// street already carries the preflop value; the upstream fix proposal
/// (allow street 0→1 at the shuffle completion) is in the stage-0 report.
fn hand_start_projection(
    pre: &CanonicalStateImage,
    hand_id: u32,
    street_fix: bool,
) -> CanonicalStateImage {
    let mut post = pre.clone();
    // StartHand resets the per-hand call sequence.
    post.call_seq = 0;
    post.hand_id = hand_id;
    // Dead button rule: the button advances unconditionally by one seat —
    // the landing seat may be empty (dead button), no skipping.
    let max = usize::from(pre.max_players);
    post.button = ((usize::from(pre.button) + 1) % max) as u8;
    post.phase = CanonicalPhase::Shuffling;
    post.phase_subtag = 1;
    post.street = if street_fix { 1 } else { 0 };
    post.deadline_ms = 100;
    post.acted_mask = 0;
    post.current_turn = NO_CANONICAL_SEAT;
    post.protocol_pending_mask = (0..usize::from(SEATS))
        .filter(|&index| {
            matches!(
                pre.seats[index].status,
                CanonicalSeatStatus::Active | CanonicalSeatStatus::Waiting
            )
        })
        .fold(0u16, |mask, index| mask | (1u16 << index));
    // StartHand promotes every waiting seat into the new hand.
    for (pre_seat, post_seat) in pre.seats.iter().zip(post.seats.iter_mut()) {
        if pre_seat.status == CanonicalSeatStatus::Waiting {
            post_seat.status = CanonicalSeatStatus::Active;
        }
    }
    post
}

fn next_seat(from: u8, step: usize) -> u8 {
    ((usize::from(from) + step) % usize::from(SEATS)) as u8
}

fn betting_rows(pre: CanonicalStateImage) -> Vec<CanonicalTransitionWitness> {
    let mut rows = Vec::new();
    let mut current = pre;
    let button = current.button;
    // Dead-button first-hand blinds: the rotation base falls back to the
    // button, so SB = the button seat itself and BB = the next seat; UTG =
    // first active seat after the BB (mirrors `blind_seats_of`).
    let _sb = button;
    let bb = next_seat(button, 1);
    let utg = next_seat(bb, 1);

    // UTG raises to 300.
    {
        let mut post = current.clone();
        post.call_seq += 1;
        post.current_turn = next_seat(utg, 1);
        post.acted_mask |= 1u16 << utg;
        let seat = &mut post.seats[usize::from(utg)];
        seat.stack -= RAISE_TO;
        seat.bet = RAISE_TO;
        seat.total_bet = RAISE_TO;
        seat.acted = true;
        post.current_bet = RAISE_TO;
        post.min_raise = RAISE_TO - BB;
        let actor = identity_of(&current, utg);
        let pre_image = current;
        rows.push(empty_row(
            pre_image,
            post.clone(),
            CanonicalTransitionKind::Raise,
            utg,
            actor,
            RAISE_TO,
            [0; 32],
        ));
        current = post;
    }

    // Every other seat folds in turn order; the last fold leaves no
    // actionable successor.
    let mut fold_seat = next_seat(utg, 1);
    for _ in 0..3 {
        let mut post = current.clone();
        post.call_seq += 1;
        post.acted_mask |= 1u16 << fold_seat;
        let seat_state = &mut post.seats[usize::from(fold_seat)];
        seat_state.status = CanonicalSeatStatus::Folded;
        seat_state.acted = true;
        // Scan AFTER the fold so the folding seat is out of the successor
        // sweep (mirrors `expected_betting_successor` on the post image).
        let remaining_actionable = (1..=usize::from(SEATS))
            .map(|step| next_seat(fold_seat, step))
            .any(|candidate| {
                post.seats[usize::from(candidate)].status == CanonicalSeatStatus::Active
                    && (!post.seats[usize::from(candidate)].acted
                        || post.seats[usize::from(candidate)].bet < post.current_bet)
            });
        post.current_turn = if remaining_actionable {
            next_seat(fold_seat, 1)
        } else {
            NO_CANONICAL_SEAT
        };
        let actor = identity_of(&current, fold_seat);
        let pre_image = current;
        rows.push(empty_row(
            pre_image,
            post.clone(),
            CanonicalTransitionKind::Fold,
            fold_seat,
            actor,
            0,
            [0; 32],
        ));
        current = post;
        fold_seat = next_seat(fold_seat, 1);
    }

    // Sole-survivor terminal: collect `pot + Σ bets` and reset for the next
    // hand. The deck commitment stays on the live lineage; reveal/reconstruct
    // ledgers are cleared.
    let gross_pot: u64 = current.pot + current.seats.iter().map(|seat| seat.bet).sum::<u64>();
    let winner = utg;
    let mut post = current.clone();
    post.call_seq += 1;
    post.phase = CanonicalPhase::Waiting;
    post.phase_subtag = 0;
    post.street = 0;
    post.current_turn = NO_CANONICAL_SEAT;
    post.deadline_ms = 0;
    post.current_bet = 0;
    post.min_raise = 0;
    post.pot = 0;
    post.acted_mask = 0;
    post.protocol_pending_mask = 0;
    post.board_cards_commitment = [0; 32];
    post.reveal_commitment = [0; 32];
    post.reconstruction_commitment = [0; 32];
    post.run_it_twice_commitment = [0; 32];
    for (index, seat_state) in post.seats.iter_mut().enumerate() {
        let before = &current.seats[index];
        seat_state.status = if before.status == CanonicalSeatStatus::Empty {
            CanonicalSeatStatus::Empty
        } else {
            CanonicalSeatStatus::Active
        };
        seat_state.acted = false;
        seat_state.bet = 0;
        seat_state.total_bet = 0;
        seat_state.hole_cards_commitment = [0; 32];
        if index == usize::from(winner) {
            seat_state.stack = before.stack + gross_pot;
        }
    }
    let deck_commitment = post.deck_commitment;
    // The terminal is permissionless: zero actor.
    rows.push(empty_row(
        current,
        post,
        CanonicalTransitionKind::EndWithoutShowdown,
        winner,
        [0; 32],
        gross_pot,
        deck_commitment,
    ));
    rows
}

struct MergedHand {
    witnesses: Vec<CanonicalTransitionWitness>,
    sidecar: ShuffleChainSidecar,
    end_image: CanonicalStateImage,
}

/// Build one merged full hand (shuffle → reveal → betting → settlement) on
/// top of a hand-start projection, driving the real Stark-curve
/// mental-poker crypto through the stage-0 producer. 13 canonical rows:
/// SubmitShuffle×4 → SubmitReveal×4 → Raise → Fold×3 → EndWithoutShowdown.
fn merged_hand(
    builder: &mut ShuffleChainBuilder,
    start: CanonicalStateImage,
    rng: &mut StdRng,
) -> MergedHand {
    let mut witnesses = Vec::new();
    let mut current = start;

    // SubmitShuffle × SEATS — real Bayer–Groth V2 over the live deck.
    for index in 0..usize::from(SEATS) {
        let row = builder
            .produce_shuffle_row(current.clone(), rng, |n| {
                deterministic_permutation(n, 700 + index as u64)
            })
            .expect("shuffle row");
        current = row.post.clone();
        witnesses.push(row);
    }

    // SubmitReveal × SEATS — real reveal-token DLEq per card. Mental poker:
    // every pending card decrypts only under every participant's share, so
    // each contribution row carries the seat's tokens for the whole pending
    // hole set (cards 0..2n in the live lineage).
    builder.set_reveal_completion_blinds(SB, BB);
    let hole_set: Vec<usize> = (0..2 * usize::from(SEATS)).collect();
    for seat in 0..SEATS {
        let row = builder
            .produce_reveal_row(current.clone(), seat, &hole_set, rng)
            .expect("reveal row");
        current = row.post.clone();
        witnesses.push(row);
    }

    // Betting: raise → three folds → sole-survivor terminal.
    witnesses.extend(betting_rows(current));

    let end_image = witnesses.last().expect("rows").post.clone();
    MergedHand {
        witnesses,
        sidecar: builder.into_sidecar(),
        end_image,
    }
}

/// The JoinTable → StartHand → SubmitShuffle batch (route-A segment A0):
/// proves the table ops and the shuffle protocol legally in one batch at the
/// canonical street-0 hand start; the reveal-completion street gap blocks the
/// continuation in the same batch (stage-0 report).
fn table_and_shuffle_batch(
    builder: &mut ShuffleChainBuilder,
    waiting_image: CanonicalStateImage,
    rng: &mut StdRng,
) -> (Vec<CanonicalTransitionWitness>, CanonicalStateImage) {
    let mut witnesses = Vec::new();
    let mut current = waiting_image;
    for seat in 0..SEATS {
        let row = join_row(current.clone(), seat, 30 + seat);
        current = row.post.clone();
        witnesses.push(row);
    }
    let start = start_hand_row(current, 2);
    current = start.post.clone();
    witnesses.push(start);
    for index in 0..usize::from(SEATS) {
        let row = builder
            .produce_shuffle_row(current.clone(), rng, |n| {
                deterministic_permutation(n, 900 + index as u64)
            })
            .expect("shuffle row");
        current = row.post.clone();
        witnesses.push(row);
    }
    (witnesses, current)
}

fn deterministic_permutation(n: usize, seed: u64) -> (Vec<usize>, Vec<Scalar>) {
    let mut permutation: Vec<usize> = (0..n).collect();
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    for index in (1..permutation.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        permutation.swap(index, (state % (index as u64 + 1)) as usize);
    }
    let mut rng = StdRng::seed_from_u64(state);
    let rerandomizers: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    (permutation, rerandomizers)
}

struct Harness {
    builder: ShuffleChainBuilder,
    waiting_image: CanonicalStateImage,
}

fn harness() -> Harness {
    let rules = table_rules();
    let rules_commitment = canonical_rules_commitment(&rules).expect("rules commitment");
    let mut rng = StdRng::seed_from_u64(0x57A6_E001);
    let players: Vec<PlayerKeys> = (0..SEATS)
        .map(|seat| {
            let secret = Scalar::random(&mut rng);
            PlayerKeys {
                seat,
                public: DefaultCurve::base_g() * secret,
                secret,
            }
        })
        .collect();
    let builder = ShuffleChainBuilder::new(players).expect("builder");
    let waiting_image = base_image(rules_commitment, builder.initial_deck_commitment());
    Harness {
        builder,
        waiting_image,
    }
}

/// The hand-start projection with the stage-0 street bridge: Shuffling/1
/// **street 1** so the shuffle completion → reveal completion → betting chain
/// is expressible inside one batch.
fn hand_start_image(waiting: &CanonicalStateImage, hand_id: u32) -> CanonicalStateImage {
    let image = hand_start_projection(waiting, hand_id, true);
    // The projection inherits the four JoinTable rows when the caller applied
    // them; the stage-0 batches apply joins separately.
    image
}

fn merged_single_hand() -> MergedHand {
    let mut rng = StdRng::seed_from_u64(0x57A6_E002);
    let Harness {
        mut builder,
        mut waiting_image,
    } = harness();
    // Four joins build the table (outside the merged protocol batch; the
    // table lifetime spans many hands).
    for seat in 0..SEATS {
        waiting_image = join_row(waiting_image, seat, 30 + seat).post;
    }
    let start = hand_start_image(&waiting_image, 2);
    merged_hand(&mut builder, start, &mut rng)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Byte offset of `image.deck_commitment` inside its Borsh encoding (the
/// value appears exactly once).
fn deck_commitment_offset(image: &CanonicalStateImage) -> usize {
    let bytes = borsh::to_vec(image).expect("canonical image serialization");
    let needle = image.deck_commitment;
    bytes
        .windows(32)
        .position(|window| window == needle)
        .expect("deck commitment appears in the image encoding")
}
// ============================================================
// Stage-0 primary: single merged batch, prove + STARK verify + native verify
// ============================================================

#[test]
fn stage0_single_batch_full_hand_prove_verify_and_native_crypto() {
    let started = Instant::now();
    let hand = merged_single_hand();
    let build_elapsed = started.elapsed();

    assert_eq!(
        hand.witnesses.len(),
        13,
        "4 shuffles + 4 reveals + raise + 3 folds + settlement"
    );
    assert_eq!(
        hand.witnesses[0].kind,
        CanonicalTransitionKind::SubmitShuffle
    );
    assert_eq!(
        hand.witnesses[3].kind,
        CanonicalTransitionKind::SubmitShuffle
    );
    assert_eq!(
        hand.witnesses[4].kind,
        CanonicalTransitionKind::SubmitReveal
    );
    assert_eq!(
        hand.witnesses[7].kind,
        CanonicalTransitionKind::SubmitReveal
    );
    assert_eq!(hand.witnesses[8].kind, CanonicalTransitionKind::Raise);
    assert_eq!(
        hand.witnesses[12].kind,
        CanonicalTransitionKind::EndWithoutShowdown
    );
    for (index, row) in hand.witnesses.iter().enumerate() {
        row.validate_shape()
            .unwrap_or_else(|error| panic!("row {index} ({:?}) invalid: {error}", row.kind));
    }
    validate_batch(&hand.witnesses).expect("witness chain is contiguous and well-formed");

    // ---- Prove the merged batch (reveal-completion channel: binds the
    // blind opening + table rules). ----
    let prove_started = Instant::now();
    let rules = table_rules();
    let archive = prove_canonical_reveal_completion_batch(&hand.witnesses, &rules)
        .expect("merged single-batch proof");
    let prove_elapsed = prove_started.elapsed();

    // ---- STARK verify. ----
    let verify_started = Instant::now();
    verify_canonical_tagged_proof(&archive).expect("merged single-batch STARK verify");
    let stark_verify_elapsed = verify_started.elapsed();

    // ---- Native shuffle-chain verification (route A) + receipts (route B).
    let mut sidecar = hand.sidecar.clone();
    let native_started = Instant::now();
    let receipt =
        verify_canonical_batch_with_shuffle_chain(&archive, &hand.witnesses, &mut sidecar)
            .expect("native BG/DLEq shuffle-chain verification");
    let native_verify_elapsed = native_started.elapsed();

    assert_eq!(
        receipt.statement_digests.len(),
        8,
        "4 shuffle + 4 reveal statement digests"
    );

    println!("[stage0] merged batch rows: {}", hand.witnesses.len());
    println!(
        "[stage0] archive log_size: {} ({} trace rows)",
        archive.log_size,
        1usize << archive.log_size
    );
    println!("[stage0] archive num_columns: {}", archive.num_columns);
    println!("[stage0] crypto build (4 BG proves + 8 DLEq proves): {build_elapsed:?}");
    println!("[stage0] merged-batch prove: {prove_elapsed:?}");
    println!("[stage0] merged-batch STARK verify: {stark_verify_elapsed:?}");
    println!("[stage0] native shuffle-chain verify: {native_verify_elapsed:?}");
    println!(
        "[stage0] engine receipt digest: {}",
        hex(&receipt.engine_receipt_digest)
    );
}

/// Segment A0: JoinTable → StartHand → SubmitShuffle in one batch at the
/// canonical street-0 hand start (real BG proofs).
#[test]
fn stage0_table_and_shuffle_batch_prove_verify() {
    let mut rng = StdRng::seed_from_u64(0x57A6_E006);
    let Harness {
        mut builder,
        waiting_image,
    } = harness();
    let (witnesses, end_image) = table_and_shuffle_batch(&mut builder, waiting_image, &mut rng);
    assert_eq!(witnesses.len(), 9);
    assert_eq!(witnesses[4].kind, CanonicalTransitionKind::StartHand);
    assert_eq!(witnesses[8].kind, CanonicalTransitionKind::SubmitShuffle);
    assert_eq!(end_image.phase, CanonicalPhase::Revealing);
    validate_batch(&witnesses).expect("A0 batch well-formed");
    let archive = prove_canonical_tagged_batch(&witnesses).expect("A0 proof");
    verify_canonical_tagged_proof(&archive).expect("A0 verify");
    println!(
        "[stage0] A0 batch rows: {} (log {})",
        witnesses.len(),
        archive.log_size
    );
}

/// Plain betting batch (no protocol rows) for the prove-cost delta.
#[test]
fn stage0_plain_betting_batch_baseline() {
    let hand = merged_single_hand();
    // Betting-phase start image = post RevealComplete.
    let betting_start = hand.witnesses[7].post.clone();
    assert_eq!(betting_start.phase, CanonicalPhase::Betting);
    let plain = betting_rows(betting_start);
    let rows = plain.len();
    validate_batch(&plain).expect("plain batch well-formed");

    let prove_started = Instant::now();
    let archive = prove_canonical_tagged_batch(&plain).expect("plain betting batch proof");
    let prove_elapsed = prove_started.elapsed();
    let verify_started = Instant::now();
    verify_canonical_tagged_proof(&archive).expect("plain betting batch verify");
    let verify_elapsed = verify_started.elapsed();
    println!("[stage0] plain betting batch rows: {rows}");
    println!(
        "[stage0] plain batch log_size: {} ({} rows)",
        archive.log_size,
        1usize << archive.log_size
    );
    println!("[stage0] plain batch prove: {prove_elapsed:?}");
    println!("[stage0] plain batch STARK verify: {verify_elapsed:?}");
}

// ============================================================
// Negative matrix: fail-closed on every deviation
// ============================================================

fn proven_hand() -> (MergedHand, ArchivedCanonicalTaggedProof) {
    let hand = merged_single_hand();
    let rules = table_rules();
    let archive = prove_canonical_reveal_completion_batch(&hand.witnesses, &rules)
        .expect("merged single-batch proof");
    (hand, archive)
}

/// Negative 1: the deck-commitment bytes live inside the Fiat--Shamir-bound
/// endpoint images; flipping one rejects both the STARK verification and the
/// native chain verification.
#[test]
fn negative_archive_deck_commitment_tamper_rejected() {
    let (hand, archive) = proven_hand();
    let mut tampered = archive.clone();
    let offset = deck_commitment_offset(&hand.end_image);
    tampered.post_state_image_bytes[offset] ^= 1;
    assert!(verify_canonical_tagged_proof(&tampered).is_err());

    let mut sidecar = hand.sidecar.clone();
    assert!(
        verify_canonical_batch_with_shuffle_chain(&tampered, &hand.witnesses, &mut sidecar)
            .is_err()
    );
}

/// Negative 2 (route-A justification): the canonical AIR alone **cannot**
/// bind a mid-hand deck-commitment rotation to the ciphertexts — a tampered
/// non-final shuffle commitment still proves (the AIR freezes the anchor, not
/// the cipher relation). The native sidecar verification rejects it.
#[test]
fn negative_tampered_deck_commitment_passes_stark_but_native_sidecar_rejects() {
    let hand = merged_single_hand();
    let mut fixed = hand.witnesses.clone();
    assert_eq!(fixed[0].kind, CanonicalTransitionKind::SubmitShuffle);
    assert_eq!(fixed[1].kind, CanonicalTransitionKind::SubmitShuffle);
    fixed[0].post.deck_commitment[0] ^= 1;
    fixed[0].seal();
    for index in 1..fixed.len() {
        fixed[index].pre = fixed[index - 1].post.clone();
        fixed[index].seal();
    }
    validate_batch(&fixed).expect("tampered chain is still AIR-wellformed");
    // The tampered batch still proves (honest AIR gap), ...
    let rules = table_rules();
    let archive = prove_canonical_reveal_completion_batch(&fixed, &rules)
        .expect("AIR cannot see cipher tamper");
    verify_canonical_tagged_proof(&archive).expect("STARK passes");
    // ... but the native deck-chain verification rejects it.
    let mut sidecar = hand.sidecar.clone();
    let result = verify_canonical_batch_with_shuffle_chain(&archive, &fixed, &mut sidecar);
    assert!(
        result.is_err(),
        "native sidecar must reject the tampered deck chain"
    );
}

/// Negative 3: deleting a protocol row. (a) A bare deletion breaks the
/// witness chain and is rejected at prove time. (b) A re-chained deletion can
/// still prove (the AIR relation is locally consistent), but it is rejected
/// against the original archive by the batch digest, and the native sidecar
/// verification rejects it even against a fresh archive (surplus shuffle
/// material).
#[test]
fn negative_deleted_protocol_row_rejected() {
    let (hand, archive) = proven_hand();
    // (a) bare deletion of a middle row: non-contiguous state boundary.
    let mut bare = hand.witnesses.clone();
    bare.remove(1);
    assert!(prove_canonical_tagged_batch(&bare).is_err());
    // (b) whole-segment deletion (drop every shuffle row) re-chains into a
    // locally consistent batch that still proves — partial deletions are
    // caught by the pending-mask arithmetic instead.
    let mut fewer: Vec<CanonicalTransitionWitness> = hand
        .witnesses
        .iter()
        .filter(|row| row.kind != CanonicalTransitionKind::SubmitShuffle)
        .cloned()
        .collect();
    for index in 1..fewer.len() {
        fewer[index].pre = fewer[index - 1].post.clone();
        fewer[index].seal();
    }
    let rules = table_rules();
    for (index, row) in fewer.iter().enumerate() {
        row.validate_shape()
            .unwrap_or_else(|e| panic!("row {index} ({:?}): {e}", row.kind));
    }
    let fresh = prove_canonical_reveal_completion_batch(&fewer, &rules)
        .expect("re-chained deletion still proves");
    // ... is rejected against the original archive (digest mismatch), ...
    let mut sidecar = hand.sidecar.clone();
    assert!(verify_canonical_batch_with_shuffle_chain(&archive, &fewer, &mut sidecar).is_err());
    // ... and the native sidecar rejects it even against the fresh archive
    // (the four shuffle materials have no rows left to attach to).
    let mut sidecar_fresh = hand.sidecar.clone();
    assert!(verify_canonical_batch_with_shuffle_chain(&fresh, &fewer, &mut sidecar_fresh).is_err());
}

/// Negative 4: reordering is rejected twice — a swapped witness sequence no
/// longer matches the archive digest, and a swapped sidecar order no longer
/// matches the row seats.
#[test]
fn negative_reordered_rows_or_sidecar_rejected() {
    let (hand, archive) = proven_hand();
    // (a) swap two reveal rows in the witness sequence.
    let mut swapped = hand.witnesses.clone();
    swapped.swap(4, 5);
    for index in 1..swapped.len() {
        swapped[index].pre = swapped[index - 1].post.clone();
        swapped[index].seal();
    }
    let mut sidecar = hand.sidecar.clone();
    assert!(prove_canonical_tagged_batch(&swapped).is_err());
    assert!(verify_canonical_batch_with_shuffle_chain(&archive, &swapped, &mut sidecar).is_err());
    // (b) swap the sidecar materials behind two reveal rows.
    let mut misaligned = hand.sidecar.clone();
    misaligned.reveals.swap(0, 1);
    assert!(
        verify_canonical_batch_with_shuffle_chain(&archive, &hand.witnesses, &mut misaligned)
            .is_err()
    );
}

/// Negative 5: a missing or forged Bayer–Groth material fails the batch.
#[test]
fn negative_missing_or_forged_bg_proof_rejected() {
    let (hand, archive) = proven_hand();
    // (a) empty sidecar.
    let mut empty = ShuffleChainSidecar::default();
    assert!(
        verify_canonical_batch_with_shuffle_chain(&archive, &hand.witnesses, &mut empty).is_err()
    );
    // (b) a shuffle row carrying another row's proof — commitments match but
    // the BG equation fails.
    let mut forged = hand.sidecar.clone();
    let proof = forged.shuffles[1].proof.clone();
    forged.shuffles[0].proof = proof;
    assert!(
        verify_canonical_batch_with_shuffle_chain(&archive, &hand.witnesses, &mut forged).is_err()
    );
    // (c) output ciphertexts replaced by the input deck — the deck-chain
    // commitment check fails.
    let mut deck_swap = hand.sidecar.clone();
    deck_swap.shuffles[0].output_deck = deck_swap.shuffles[0].input_deck.clone();
    assert!(
        verify_canonical_batch_with_shuffle_chain(&archive, &hand.witnesses, &mut deck_swap)
            .is_err()
    );
}

/// Negative 6: a forged reveal token (wrong seat key / tampered token point)
/// fails the native DLEq verification.
#[test]
fn negative_forged_reveal_token_rejected() {
    let (hand, archive) = proven_hand();
    // (a) replace seat 1's token material with seat 2's — the seat-key
    // binding and the ledger rotation both fail.
    let mut forged = hand.sidecar.clone();
    let stolen = forged.reveals[2].revealed.clone();
    forged.reveals[1].revealed = stolen;
    assert!(
        verify_canonical_batch_with_shuffle_chain(&archive, &hand.witnesses, &mut forged).is_err()
    );
    // (b) shift the token point off the curve relation — the DLEq rejects.
    let mut tampered = hand.sidecar.clone();
    let token = tampered.reveals[0].revealed[0].revealed.reveal_token;
    tampered.reveals[0].revealed[0].revealed.reveal_token = token + DefaultCurve::base_g();
    assert!(
        verify_canonical_batch_with_shuffle_chain(&archive, &hand.witnesses, &mut tampered)
            .is_err()
    );
}

// ============================================================
// Log-size jump measurement
// ============================================================

/// Domain-jump measurement: pad a legal canonical batch past 256 rows with
/// `JoinTable`/`LeaveTable` pairs (Waiting phase, no hand boundary) and
/// measure the log 8 → log 9 prove/verify cost. A full-chain batch cannot
/// legally exceed 256 rows today — the reveal-completion street gap blocks an
/// in-batch hand boundary, and reveal-timeout kicks force a dedicated
/// cascade batch — so the full-chain log-8 cost with real crypto is measured
/// by `stage0_single_batch_full_hand_prove_verify_and_native_crypto` and the
/// jump factor comes from this shape-neutral padding. The full gate runs it
/// via `--include-ignored`.
#[ignore = "log-9 domain jump measurement (258-row STARK); full gate runs --include-ignored"]
#[test]
fn stage0_log9_jump_measurement() {
    let rules_commitment = canonical_rules_commitment(&table_rules()).expect("rules commitment");
    let mut image = base_image(rules_commitment, [2; 32]);
    let mut witnesses = Vec::new();
    // JoinTable must occupy the first empty seat — with one leave after every
    // join, that is always seat 0; every join is a fresh player (unique
    // identity commitment).
    let seat = 0u8;
    while witnesses.len() + 2 <= 258 {
        let join_seed = 50u8 + ((witnesses.len() % 190) as u8);
        let join = join_row(image.clone(), seat, join_seed);
        image = join.post.clone();
        witnesses.push(join);
        // LeaveTable: vacate the seat and refund the buy-in.
        let mut post = image.clone();
        post.call_seq += 1;
        post.chip_pool = image.chip_pool - BUY_IN;
        post.seats[usize::from(seat)] = CanonicalSeat::EMPTY;
        let leaver = [join_seed; 32];
        witnesses.push(empty_row(
            image,
            post,
            CanonicalTransitionKind::LeaveTable,
            seat,
            leaver,
            BUY_IN,
            [0; 32],
        ));
        image = witnesses.last().expect("rows").post.clone();
    }
    let rows = witnesses.len();
    assert!(
        rows > 256,
        "expected the batch to exceed the log-8 domain, got {rows}"
    );

    let prove_started = Instant::now();
    let archive = prove_canonical_tagged_batch(&witnesses).expect("log-9 domain proof");
    let prove_elapsed = prove_started.elapsed();
    let verify_started = Instant::now();
    verify_canonical_tagged_proof(&archive).expect("log-9 domain verify");
    let verify_elapsed = verify_started.elapsed();
    println!(
        "[stage0] log-9 batch rows: {rows} (join/leave pairs: {})",
        rows / 2
    );
    println!(
        "[stage0] log-9 archive log_size: {} ({} rows)",
        archive.log_size,
        1usize << archive.log_size
    );
    println!("[stage0] log-9 prove: {prove_elapsed:?}");
    println!("[stage0] log-9 STARK verify: {verify_elapsed:?}");
}

// ============================================================
// Test B: the reconstruct segment (SubmitReconstruct = 9) threaded with real
// reconstruction-V3 proofs
// ============================================================

/// Segment B: betting → flop board reveal (segment B1), the dedicated
/// reveal-timeout cascade batch (segment B2: kick → reconstruct enter), and
/// the SubmitReconstruct pair with real reconstruction-V3 proofs (segment
/// B3). Three batches, because the batch-level shape rule forces reveal-time
/// kicks into a dedicated cascade batch (first row Kick, ascending seats,
/// terminal continuation last). Every segment proves, verifies, and passes
/// the native shuffle-chain verification with its sidecar slice.
///
/// 栈说明：本用例的证明/验证链在 libtest 默认 2MiB 测试线程上深递归会栈
/// 溢出（HEAD 先在问题——git stash 验证回退工作树改动同样溢出，16MiB 栈
/// 下通过，验证记录见 out/fold-9seat-migration.md）。按
/// `src/blake3_flock.rs` `flock_pool` 的 64MiB 先例，把整个用例放大栈
/// 线程上跑，使 debug 门禁 `cargo test` 不依赖 RUST_MIN_STACK 环境变量。
#[test]
fn stage0_reconstruct_segment_single_batch() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .name("stage0-reconstruct".into())
        .spawn(stage0_reconstruct_segment_single_batch_inner)
        .expect("spawn big-stack test thread")
        .join()
        .expect("stage0 reconstruct segment test thread panicked");
}

fn stage0_reconstruct_segment_single_batch_inner() {
    let mut rng = StdRng::seed_from_u64(0x57A6_E007);
    // Fresh builder; the preflop is replayed on it so the deck lineage and
    // the sidecar stay consistent inside this test.
    let mut builder = harness().builder;
    let rules_commitment = canonical_rules_commitment(&table_rules()).expect("rules");
    let mut waiting = base_image(rules_commitment, builder.initial_deck_commitment());
    for seat in 0..SEATS {
        waiting = join_row(waiting, seat, 30 + seat).post;
    }
    let start = hand_start_image(&waiting, 2);
    let mut current = start.clone();
    builder.set_reveal_completion_blinds(SB, BB);
    for index in 0..usize::from(SEATS) {
        let row = builder
            .produce_shuffle_row(current.clone(), &mut rng, |n| {
                deterministic_permutation(n, 700 + index as u64)
            })
            .expect("shuffle row");
        current = row.post.clone();
    }
    let hole_set: Vec<usize> = (0..2 * usize::from(SEATS)).collect();
    for seat in 0..SEATS {
        let row = builder
            .produce_reveal_row(current.clone(), seat, &hole_set, &mut rng)
            .expect("reveal row");
        current = row.post.clone();
    }
    let sidecar_preflop = builder.into_sidecar();

    let mut witnesses: Vec<CanonicalTransitionWitness> = Vec::new();
    let button = current.button;
    // Dead-button first-hand blinds: SB = the button seat itself, BB = the
    // next seat, UTG = the seat after BB (mirrors `blind_seats_of`).
    let _sb = button;
    let bb = next_seat(button, 1);
    let utg = next_seat(bb, 1);

    // Betting round: call ×3 then a BB check (four live seats).
    for step in 0..4usize {
        let seat = next_seat(utg, step);
        let mut post = current.clone();
        post.call_seq += 1;
        if step == 3 {
            // BB checks a matched bet.
            post.current_turn = NO_CANONICAL_SEAT;
            post.acted_mask |= 1u16 << seat;
            post.seats[usize::from(seat)].acted = true;
            witnesses.push(empty_row(
                current.clone(),
                post,
                CanonicalTransitionKind::Check,
                seat,
                identity_of(&current, seat),
                0,
                [0; 32],
            ));
        } else {
            let owed = current.current_bet - current.seats[usize::from(seat)].bet;
            post.current_turn = next_seat(seat, 1);
            post.acted_mask |= 1u16 << seat;
            let seat_state = &mut post.seats[usize::from(seat)];
            seat_state.stack -= owed;
            seat_state.bet = current.current_bet;
            seat_state.total_bet += owed;
            seat_state.acted = true;
            witnesses.push(empty_row(
                current.clone(),
                post,
                CanonicalTransitionKind::Call,
                seat,
                identity_of(&current, seat),
                owed,
                [0; 32],
            ));
        }
        current = witnesses.last().expect("rows").post.clone();
    }

    // AdvanceRound: collect the wagers, open the flop board-reveal phase.
    {
        let mut post = current.clone();
        post.call_seq += 1;
        post.phase = CanonicalPhase::Revealing;
        post.phase_subtag = 2;
        post.street = 2;
        post.current_turn = NO_CANONICAL_SEAT;
        post.deadline_ms = 32_000;
        post.protocol_pending_mask = 0b1111;
        post.current_bet = 0;
        post.min_raise = 0;
        post.pot = current.pot + current.seats.iter().map(|seat| seat.bet).sum::<u64>();
        for seat in post.seats.iter_mut() {
            seat.bet = 0;
        }
        let assignments = {
            let mut slots = [CanonicalBoardRevealAssignment::EMPTY; 6];
            for (slot, assignment) in slots.iter_mut().take(3).enumerate() {
                *assignment = CanonicalBoardRevealAssignment {
                    present: true,
                    encrypted_card_index: 8 + slot as u8,
                    runout_index: 0,
                    board_position: slot as u8,
                    pending_mask: 0b1111,
                    submitted_mask: 0,
                };
            }
            slots
        };
        let opening = CanonicalRoundAdvanceOpening {
            pre_cards_dealt: 8,
            post_cards_dealt: 11,
            pre_board_len: 0,
            // post_board_len mirrors pre at advance time; the board commitment
            // is opened by the next advance after the reveals collect.
            post_board_len: 0,
            reveal_purpose: 2,
            assignment_count: 3,
            assignments,
            ..Default::default()
        };
        let mut witness = empty_row(
            current.clone(),
            post,
            CanonicalTransitionKind::AdvanceRound,
            NO_CANONICAL_SEAT,
            [0; 32],
            0,
            [0; 32],
        );
        witness.round_advance = opening;
        witness.seal();
        witnesses.push(witness);
        current = witnesses.last().expect("rows").post.clone();
    }

    // Street-2 board reveals: seats 0 and 1 contribute tokens for the three
    // flop cards (native DLEq material joins the sidecar).
    for seat in 0..2u8 {
        let row = builder
            .produce_reveal_row(current.clone(), seat, &[8, 9, 10], &mut rng)
            .expect("board reveal row");
        current = row.post.clone();
        witnesses.push(row);
    }

    let segment_b1 = witnesses;
    assert_eq!(
        segment_b1.len(),
        7,
        "3 calls + check + advance-round + 2 board-reveal rows"
    );
    let b1_start = segment_b1[0].pre.clone();
    let b1_end = segment_b1.last().expect("rows").post.clone();

    // Segment B2 — the dedicated reveal-timeout cascade batch: kick (p2) then
    // the reconstruct-enter terminal (p3). The batch-level shape rule demands
    // kicks start the batch, ascend by seat, and end at the terminal.
    let mut segment_b2 = Vec::new();
    {
        let mut post = current.clone();
        post.call_seq += 1;
        post.acted_mask &= !(1u16 << 2);
        post.protocol_pending_mask = current.protocol_pending_mask & !(1u16 << 2);
        let refund = current.seats[2].stack + current.seats[2].pending_addon;
        post.chip_pool = current.chip_pool - refund;
        post.pot = current.pot + current.seats[2].bet;
        post.seats[2].status = CanonicalSeatStatus::Out;
        post.seats[2].stack = 0;
        post.seats[2].acted = false;
        post.seats[2].key_commitment = [0; 32];
        post.seats[2].hole_cards_commitment = [0; 32];
        post.reveal_commitment = [0xA1; 32];
        let mut witness = empty_row(
            current.clone(),
            post,
            CanonicalTransitionKind::RevealTimeoutKick,
            2,
            [0; 32],
            refund,
            [0xA1; 32],
        );
        witness.deadline_height = 33_000;
        witness.seal();
        segment_b2.push(witness);
        current = segment_b2.last().expect("rows").post.clone();
    }
    {
        let mut post = current.clone();
        post.call_seq += 1;
        post.phase = CanonicalPhase::Reconstructing;
        post.phase_subtag =
            poker_texas_air::texas_canonical::CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG;
        post.deadline_ms = 33_000 + u64::from(current.reconstruct_timeout_ms);
        post.acted_mask &= !(1u16 << 3);
        post.protocol_pending_mask = 0b0011;
        let refund = current.seats[3].stack + current.seats[3].pending_addon;
        post.chip_pool = current.chip_pool - refund;
        post.seats[3].status = CanonicalSeatStatus::Out;
        post.seats[3].stack = 0;
        post.seats[3].acted = false;
        post.seats[3].key_commitment = [0; 32];
        post.seats[3].hole_cards_commitment = [0; 32];
        post.reconstruction_commitment = [0xB2; 32];
        let mut witness = empty_row(
            current.clone(),
            post,
            CanonicalTransitionKind::RevealTimeoutReconstruct,
            3,
            [0; 32],
            refund,
            [0xB2; 32],
        );
        witness.deadline_height = 33_000;
        witness.seal();
        segment_b2.push(witness);
        current = segment_b2.last().expect("rows").post.clone();
    }

    // Segment B3 — the two SubmitReconstruct rows with real V3 proofs.
    let deck = builder.deck().to_vec();
    // Owner-readable: subtract every other seat's share from the card. All
    // reveal materials cover the same hole set positionally (slot j = deck
    // index j), so the shares line up one-to-one.
    let readable_of = |owner: u8, indices: &[usize]| -> Vec<ElGamalCiphertext> {
        indices
            .iter()
            .map(|&index| {
                let mut card = deck[index];
                for material in &sidecar_preflop.reveals {
                    if material.seat == owner {
                        continue;
                    }
                    card.c2 -= material.revealed[index].revealed.reveal_token;
                }
                card
            })
            .collect()
    };
    let mut segment_b3 = Vec::new();
    {
        let readable = readable_of(0, &[0, 1]);
        let row = builder
            .produce_reconstruct_row(
                current.clone(),
                0,
                &readable,
                [1u8; 32],
                1,
                [2u8; 32],
                &mut rng,
            )
            .expect("reconstruct row 0");
        current = row.post.clone();
        segment_b3.push(row);
    }
    {
        let readable = readable_of(1, &[2, 3]);
        let row = builder
            .produce_reconstruct_row(
                current.clone(),
                1,
                &readable,
                [1u8; 32],
                1,
                [2u8; 32],
                &mut rng,
            )
            .expect("reconstruct completion row");
        current = row.post.clone();
        segment_b3.push(row);
    }

    assert_eq!(
        current.phase,
        CanonicalPhase::Shuffling,
        "reconstruct completion lands in the reconstruct-shuffle phase"
    );

    // Prove + verify each segment; the native shuffle-chain verification runs
    // on every segment with its sidecar slice (the cascade segment carries no
    // sidecar material: the kick rotations are authenticated by the rows
    // themselves plus the reveal-ledger opening, not this sidecar).
    let full_sidecar = builder.into_sidecar();
    let prove_started = Instant::now();
    let archive_b1 = prove_canonical_tagged_batch(&segment_b1).expect("segment B1 proof");
    let archive_b2 = prove_canonical_tagged_batch(&segment_b2).expect("segment B2 proof");
    let archive_b3 = prove_canonical_tagged_batch(&segment_b3).expect("segment B3 proof");
    let prove_elapsed = prove_started.elapsed();

    verify_canonical_tagged_proof(&archive_b1).expect("segment B1 STARK verify");
    verify_canonical_tagged_proof(&archive_b2).expect("segment B2 STARK verify");
    verify_canonical_tagged_proof(&archive_b3).expect("segment B3 STARK verify");

    // Only the two street-2 board-reveal materials belong to segment B1; the
    // four preflop materials were consumed by the (out-of-batch) preflop
    // segment replay.
    let mut sidecar_b1 = ShuffleChainSidecar {
        shuffles: Vec::new(),
        reveals: full_sidecar.reveals[4..].to_vec(),
        reconstructs: Vec::new(),
    };
    verify_canonical_batch_with_shuffle_chain(&archive_b1, &segment_b1, &mut sidecar_b1)
        .expect("segment B1 native verification");
    let mut sidecar_b2 = ShuffleChainSidecar::default();
    verify_canonical_batch_with_shuffle_chain(&archive_b2, &segment_b2, &mut sidecar_b2)
        .expect("segment B2 native verification (no sidecar material)");
    let mut sidecar_b3 = ShuffleChainSidecar {
        shuffles: Vec::new(),
        reveals: Vec::new(),
        reconstructs: full_sidecar.reconstructs.clone(),
    };
    let receipt =
        verify_canonical_batch_with_shuffle_chain(&archive_b3, &segment_b3, &mut sidecar_b3)
            .expect("segment B3 native V3 verification");

    assert_eq!(b1_start.phase, CanonicalPhase::Betting);
    assert_eq!(b1_end.phase, CanonicalPhase::Revealing);
    println!(
        "[stage0] segment B1 rows: {} (log {})",
        segment_b1.len(),
        archive_b1.log_size
    );
    println!(
        "[stage0] segment B2 rows: {} (log {})",
        segment_b2.len(),
        archive_b2.log_size
    );
    println!(
        "[stage0] segment B3 rows: {} (log {})",
        segment_b3.len(),
        archive_b3.log_size
    );
    println!("[stage0] segment B prove (3 batches): {prove_elapsed:?}");
    println!(
        "[stage0] segment B3 statement digests: {}",
        receipt.statement_digests.len()
    );
}
