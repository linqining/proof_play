//! End-to-end proving benchmark for one complete Texas Hold'em hand.
//!
//! The hand is composed of the canonical transitions the tagged AIR currently
//! admits end-to-end: the table lifecycle (create, two joins, start) and one
//! complete betting hand (bet, raise, fold, zero-rake settlement).  The
//! shuffle/reveal crypto phase is still fail-closed pending the Ristretto
//! composition, so the hand is split at that boundary into two contiguous
//! tagged batches — exactly the seams a production coordinator would prove.
//!
//! Run with `cargo run --release -p poker-hand-bench`.

use std::time::Instant;

use poker_l1::contracts::texas_poker::types::TableRules;
use poker_texas_air::canonical_rake_opening::{CanonicalBlindOpening, CanonicalRakeOpening};
use poker_texas_air::texas_canonical::{
    CanonicalActionPayload, CanonicalPhase, CanonicalRoundAdvanceOpening, CanonicalSeat,
    CanonicalSeatStatus, CanonicalStateImage, CanonicalTransitionKind, CanonicalTransitionWitness,
    MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
};
use poker_texas_air::texas_canonical_air::{
    prove_canonical_tagged_batch, verify_canonical_tagged_proof,
};

fn base_image() -> CanonicalStateImage {
    let image = CanonicalStateImage {
        abi_version: poker_texas_air::texas_canonical::CANONICAL_ABI_VERSION,
        table_id: 7,
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
        last_bb_seat: poker_texas_air::texas_canonical::NO_CANONICAL_SEAT,
        max_players: 9,
        acted_mask: 0,
        leave_after_hand_mask: 0,
        protocol_pending_mask: 0,
        board_cards_commitment: [1; 32],
        deck_commitment: [2; 32],
        reveal_commitment: [3; 32],
        reconstruction_commitment: [4; 32],
        run_it_twice_commitment: [5; 32],
        rules_commitment: [6; 32],
        governance_commitment: [7; 32],
        settlement_commitment: [8; 32],
        custody_commitment: [9; 32],
        lifecycle_root: [10; 32],
        overlay_root: [11; 32],
        state_root: [12; 32],
        seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
    };
    image
}

fn witness(
    pre: CanonicalStateImage,
    post: CanonicalStateImage,
    kind: CanonicalTransitionKind,
    actor: [u8; 32],
    seat: u8,
    amount: u64,
) -> CanonicalTransitionWitness {
    let mut value = CanonicalTransitionWitness {
        pre,
        post,
        kind,
        actor,
        action: CanonicalActionPayload {
            seat,
            amount,
            auxiliary: 0,
            flag: false,
            proof_commitment: [0; 32],
        },
        round_advance: CanonicalRoundAdvanceOpening::default(),
        protocol_completion: Default::default(),
        rake_opening: CanonicalRakeOpening::ZERO,
        blind_opening: CanonicalBlindOpening::ZERO,
        transition_commitment: [0; 32],
        nullifier: [0; 32],
        deadline_height: 0,
    };
    value.seal();
    value
}

fn active_seat(stack: u64, acted: bool, index: usize) -> CanonicalSeat {
    CanonicalSeat {
        status: CanonicalSeatStatus::Active,
        acted,
        stack,
        bet: 0,
        total_bet: 0,
        pending_addon: 0,
        time_bank_ms: 30_000,
        identity_commitment: [31 + index as u8; 32],
        key_commitment: [41 + index as u8; 32],
        hole_cards_commitment: [51 + index as u8; 32],
    }
}

/// Standard nine-seat lifecycle: CreateTable -> JoinTable x9 -> StartHand.
/// Everything up to the shuffle boundary, where the fail-closed crypto phase
/// begins.
fn lifecycle_batch() -> Vec<CanonicalTransitionWitness> {
    const SEATS: usize = 9;
    let create_pre = base_image();
    let mut create_post = create_pre.clone();
    create_post.call_seq = 1;
    let create = witness(
        create_pre,
        create_post,
        CanonicalTransitionKind::CreateTable,
        [1; 32],
        NO_CANONICAL_SEAT,
        0,
    );

    let mut rows = vec![create];
    for seat in 0..SEATS {
        let pre = rows.last().expect("chain").post.clone();
        let mut post = pre.clone();
        post.call_seq = 2 + seat as u32;
        post.chip_pool = 1_000 * (seat as u64 + 1);
        post.seats[seat] = active_seat(1_000, false, seat);
        // JoinTable creates a funded waiting seat; StartHand promotes the
        // waiting participants into the active hand.
        post.seats[seat].status = CanonicalSeatStatus::Waiting;
        post.seats[seat].hole_cards_commitment = [0; 32];
        let join = witness(
            pre,
            post,
            CanonicalTransitionKind::JoinTable,
            [2 + seat as u8; 32],
            seat as u8,
            1_000,
        );
        rows.push(join);
    }

    let start_pre = rows.last().expect("chain").post.clone();
    let mut start_post = start_pre.clone();
    start_post.call_seq = 0;
    start_post.hand_id = 2;
    start_post.button = 1;
    start_post.phase = CanonicalPhase::Shuffling;
    start_post.phase_subtag = 1;
    start_post.deadline_ms = 100;
    start_post.protocol_pending_mask = 0x1ff;
    for seat in 0..SEATS {
        start_post.seats[seat].status = CanonicalSeatStatus::Active;
    }
    let start = witness(
        start_pre,
        start_post,
        CanonicalTransitionKind::StartHand,
        [2; 32],
        NO_CANONICAL_SEAT,
        0,
    );
    rows.push(start);
    rows
}

/// One complete nine-seat preflop hand after the shuffle boundary: seat 0
/// opens, seat 1 raises, seats 2..=8 and seat 0 fold, and the single
/// survivor takes the pot without a showdown.
fn hand_batch() -> Vec<CanonicalTransitionWitness> {
    const SEATS: usize = 9;
    const BUY_IN: u64 = 1_000;
    let mut pre = base_image();
    pre.hand_id = 2;
    pre.call_seq = 0;
    pre.phase = CanonicalPhase::Betting;
    pre.phase_subtag = 1;
    pre.street = 1;
    pre.current_turn = 0;
    pre.deadline_ms = 100;
    pre.chip_pool = 9_000;
    pre.max_players = 9;
    for seat in 0..SEATS {
        pre.seats[seat] = active_seat(BUY_IN, false, seat);
    }

    let mut rows: Vec<CanonicalTransitionWitness> = Vec::new();
    let mut seq = 0u32;
    let mut step = |kind: CanonicalTransitionKind,
                    actor: [u8; 32],
                    seat: u8,
                    amount: u64,
                    edit: &dyn Fn(&mut CanonicalStateImage)| {
        seq += 1;
        let mut post = pre.clone();
        post.call_seq = seq;
        edit(&mut post);
        let row = witness(pre.clone(), post, kind, actor, seat, amount);
        pre = row.post.clone();
        rows.push(row);
    };

    // Seat 0 opens for 50; the first actionable successor is seat 1.
    step(
        CanonicalTransitionKind::Bet,
        [31; 32],
        0,
        50,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 1;
            post.current_bet = 50;
            post.min_raise = 50;
            post.seats[0].acted = true;
            post.seats[0].stack = 950;
            post.seats[0].bet = 50;
            post.seats[0].total_bet = 50;
            post.acted_mask = 1;
        },
    );

    // Seat 1 raises to 150; every other seat's acted flag resets.
    step(
        CanonicalTransitionKind::Raise,
        [32; 32],
        1,
        150,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 2;
            post.current_bet = 150;
            post.min_raise = 100;
            post.seats[0].acted = false;
            post.seats[1].acted = true;
            post.seats[1].stack = 850;
            post.seats[1].bet = 150;
            post.seats[1].total_bet = 150;
            post.acted_mask = 0b10;
        },
    );

    // Seats 2..=8 fold in turn order; each successor is the next live seat.
    for seat in 2..SEATS {
        let successor = if seat + 1 == SEATS {
            0
        } else {
            (seat + 1) as u8
        };
        step(
            CanonicalTransitionKind::Fold,
            [31 + seat as u8; 32],
            seat as u8,
            0,
            &move |post: &mut CanonicalStateImage| {
                post.current_turn = successor;
                post.seats[seat].status = CanonicalSeatStatus::Folded;
                post.seats[seat].acted = true;
                post.acted_mask |= 1 << seat;
            },
        );
    }

    // Seat 0, facing the raise with its open bet live, folds; no actionable
    // seat remains.
    step(
        CanonicalTransitionKind::Fold,
        [31; 32],
        0,
        0,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = NO_CANONICAL_SEAT;
            post.seats[0].status = CanonicalSeatStatus::Folded;
            post.seats[0].acted = true;
            post.acted_mask = 0x1ff;
        },
    );

    // Zero-rake settlement: the pot is the sum of both live bets (200).
    let amount = 50 + 150;
    step(
        CanonicalTransitionKind::EndWithoutShowdown,
        [0; 32],
        1,
        amount,
        &|post: &mut CanonicalStateImage| {
            post.phase = CanonicalPhase::Waiting;
            post.phase_subtag = 0;
            post.street = 0;
            post.deadline_ms = 0;
            post.current_bet = 0;
            post.min_raise = 0;
            post.acted_mask = 0;
            post.deck_commitment = [77; 32];
            post.board_cards_commitment = [0; 32];
            post.reveal_commitment = [0; 32];
            post.reconstruction_commitment = [0; 32];
            post.run_it_twice_commitment = [0; 32];
            for seat in 0..SEATS {
                post.seats[seat].status = CanonicalSeatStatus::Active;
                post.seats[seat].acted = false;
                post.seats[seat].bet = 0;
                post.seats[seat].total_bet = 0;
                post.seats[seat].hole_cards_commitment = [0; 32];
            }
            post.seats[1].stack += amount;
        },
    );
    let mut end = rows.pop().expect("terminal row");
    end.action.proof_commitment = [77; 32];
    end.seal();
    rows.push(end);
    rows
}

fn main() {
    if std::env::args().any(|arg| arg == "full-hand-v2-nine") {
        full_hand_v2_nine();
        return;
    }
    if std::env::args().any(|arg| arg == "full-hand-v3-dual") {
        full_hand_v3_dual();
        return;
    }
    if std::env::args().any(|arg| arg == "full-hand-v2") {
        full_hand_v2();
        return;
    }
    println!("=== poker_texas_air complete-hand proving benchmark ===");
    println!("host: {} / {}", std::env::consts::ARCH, sysctl_model());
    let lifecycle = lifecycle_batch();
    let hand = hand_batch();

    let mut total_prove = std::time::Duration::ZERO;
    let mut total_verify = std::time::Duration::ZERO;
    let mut total_bytes = 0usize;

    // The two tagged batches are independent statements; a production
    // coordinator can pipeline them on the shared rayon pool instead of
    // paying their wall clocks serially.
    let pipelined_start = Instant::now();
    let (lifecycle_archive, hand_archive) = rayon::join(
        || prove_canonical_tagged_batch(&lifecycle),
        || prove_canonical_tagged_batch(&hand),
    );
    let lifecycle_archive = lifecycle_archive.expect("lifecycle proof");
    let hand_archive = hand_archive.expect("hand proof");
    let pipelined_prove = pipelined_start.elapsed();
    for (label, rows, archive) in [
        ("lifecycle", lifecycle.len(), &lifecycle_archive),
        ("hand", hand.len(), &hand_archive),
    ] {
        let start = Instant::now();
        verify_canonical_tagged_proof(archive).expect("canonical verify");
        let verify_elapsed = start.elapsed();
        let bytes = borsh_ser(archive).len();
        total_verify += verify_elapsed;
        total_bytes += bytes;
        println!("{label} batch ({rows} rows): verify {verify_elapsed:?}, proof {bytes} bytes");
    }
    println!("pipelined canonical batches (2x prove in parallel): {pipelined_prove:?}");
    total_prove += pipelined_prove;

    // Companion Blake2b openings a finalized hand needs.  The rules and both
    // endpoint state images share one lookup STARK: the fixed per-proof cost
    // (table commitment + FRI) dominates and is independent of block count.
    let pre_image = lifecycle[0].pre.clone();
    let post_image = hand.last().expect("hand").post.clone();
    let rules = TableRules {
        max_players: 9,
        small_blind: 25,
        big_blind: 50,
        timeout_config: Default::default(),
        ante_mode: 0,
        ante_amount: 0,
        rake_mode: 1,
        rake_bps: 500,
        rake_cap: 1_000,
        rit_mode: 0,
    };
    // Complete host-zero bundle: rules + both images + both L1 SMT openings
    // (synthetic 256-deep witnesses) in one provider-batched proof.
    let smt_pre = poker_texas_air::smt_statements::synthetic_smt_witness(
        0x5a,
        [0x11; 32],
        pre_image.commitment(),
    );
    let smt_post = poker_texas_air::smt_statements::synthetic_smt_witness(
        0x3c,
        [0x22; 32],
        post_image.commitment(),
    );
    let provider = poker_texas_air::hash_prover::default_hash_provider();
    let start = Instant::now();
    let bundle = poker_texas_air::canonical_rake_opening::prove_canonical_hand_bundle(
        &provider,
        &rules,
        &pre_image,
        &post_image,
        Some(&smt_pre),
        Some(&smt_post),
    )
    .expect("hand bundle");
    let openings_prove = start.elapsed();
    let start = Instant::now();
    let authenticated = poker_texas_air::canonical_rake_opening::verify_canonical_hand_bundle(
        &provider,
        &bundle,
        &rules,
        &pre_image,
        &post_image,
    )
    .expect("hand bundle verify");
    let openings_verify = start.elapsed();
    assert_eq!(
        authenticated.rake.rake_bps, 500,
        "authenticated opening must round-trip"
    );
    let openings_bytes = borsh_ser(&bundle).len();
    total_bytes += openings_bytes;
    println!(
        "complete hand bundle (rules + 2 images + 2 SMT paths, {} statements): prove {openings_prove:?}, verify {openings_verify:?}, proof {openings_bytes} bytes",
        3 + 2 * poker_texas_air::smt_statements::SMT_PATH_STATEMENTS,
    );
    total_prove += openings_prove;
    total_verify += openings_verify;

    for record in poker_texas_air::prove_timing::take_drain() {
        println!("component {}: {:?}", record.label, record.elapsed);
    }
    println!(
        "\nTOTAL: prove {total_prove:?}, verify {total_verify:?}, tagged proof bytes {total_bytes}"
    );
}


fn sysctl_model() -> String {
    std::process::Command::new("sysctl")
        .arg("-n")
        .arg("hw.model")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn borsh_ser<T: borsh::BorshSerialize>(value: &T) -> Vec<u8> {
    borsh::to_vec(value).expect("borsh serialize")
}



/// Nine-player complete hand on the RistrettoAirV2 protocol layer, mirroring
/// the reference Move table flow (`texas_poker_move`): key registration,
/// nine sequential Bayer--Groth shuffles, hole/board dealing, a preflop
/// `fold_with_proof`, street-by-street reveals (preflop holes, flop, turn,
/// river) with betting lines between, and showdown decryption.  Clients
/// prove with the native poker_protocol stack; the server runs only the
/// AIR-side verifiers (`verify_*` / `admit_*`).
fn full_hand_v2_nine() {
    use poker_protocol::crypto::curve::{Curve, CurvePoint, RistrettoCurve};
    use poker_protocol::ristretto_air::{RistrettoAirCiphertext, RistrettoShuffleSubmission};
    use poker_texas_air::ristretto_player_proofs_air::{
        RistrettoCiphertext, prove_fold_with_proof_v2_poseidon2, prove_pk_ownership_poseidon2,
        prove_reveal_tokens_batched_poseidon2, verify_fold_with_proof_v2_poseidon2,
        verify_pk_ownership_poseidon2, verify_reveal_tokens_batched_poseidon2,
    };
    use poker_texas_air::ristretto_shuffle_air::{
        admit_ristretto_air_v2_shuffle_submission, prove_ristretto_air_v2_shuffle_poseidon2,
    };
    use poker_protocol::precompile_abi::TranscriptId;
    use rand::SeedableRng;
    use rayon::prelude::*;

    type Point = <RistrettoCurve as Curve>::Point;
    type Scalar = <RistrettoCurve as Curve>::Scalar;

    const PLAYERS: usize = 9;
    const FOLD_SEAT: usize = 1;
    let active: Vec<usize> = (0..PLAYERS).filter(|&seat| seat != FOLD_SEAT).collect();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x9E99_0001);

    let point_bytes = |point: &Point| {
        let mut out = [0u8; 32];
        out.copy_from_slice(point.compress().as_bytes());
        out
    };
    let mut client_prove = std::time::Duration::ZERO;
    let mut server_verify = std::time::Duration::ZERO;
    let mut total_bytes = 0usize;
    let hand_started = Instant::now();

    // ---- Phase 1: nine ownership proofs (client) / verifications (server)
    let started = Instant::now();
    let mut secret_keys = Vec::with_capacity(PLAYERS);
    let mut public_keys = Vec::with_capacity(PLAYERS);
    let mut ownership = Vec::with_capacity(PLAYERS);
    for seat in 0..PLAYERS {
        let sk = Scalar::random(&mut rng);
        let pk = RistrettoCurve::base_g() * sk;
        let context = format!("table9-hand1-seat{seat}");
        let (wire, proof) =
            prove_pk_ownership_poseidon2(&sk, &pk, context.as_bytes(), &mut rng)
                .expect("ownership proof");
        ownership.push((seat, context, wire, proof));
        secret_keys.push(sk);
        public_keys.push(pk);
    }
    let phase_prove = started.elapsed();
    let started = Instant::now();
    for (seat, context, wire, proof) in &ownership {
        verify_pk_ownership_poseidon2(&public_keys[*seat], context.as_bytes(), wire)
            .expect("ownership verify");
        total_bytes += borsh_ser(wire).len() + borsh_ser(proof).len();
    }
    let phase_verify = started.elapsed();
    client_prove += phase_prove;
    server_verify += phase_verify;
    println!(
        "[1] ownership x{PLAYERS}: client prove {phase_prove:?}, server verify {phase_verify:?}"
    );

    // ---- Phase 2: canonical deck + nine sequential BG shuffles -----------
    let aggregate: Point = public_keys.iter().copied().sum();
    let base =
        poker_protocol::ristretto_air::RistrettoTexasDeck::canonical_base(&aggregate)
            .expect("canonical base deck");
    let mut deck: Vec<RistrettoCiphertext> = base
        .encrypted
        .iter()
        .map(|wire| RistrettoCiphertext {
            c1: <Point as CurvePoint>::from_compressed(&wire.c1).expect("c1 decodes"),
            c2: <Point as CurvePoint>::from_compressed(&wire.c2).expect("c2 decodes"),
        })
        .collect();
    let started = Instant::now();
    let mut shuffle_archives = Vec::with_capacity(PLAYERS);
    for seat in 0..PLAYERS {
        let mut permutation: Vec<usize> = (0..52).collect();
        let mut seed = 0x9E37_79B9_7F4A_7C15u64 ^ (seat as u64 + 1);
        for index in (1..permutation.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            permutation.swap(index, (seed % (index as u64 + 1)) as usize);
        }
        let rerandomizers: Vec<Scalar> = (0..52).map(|_| Scalar::random(&mut rng)).collect();
        let output = permutation
            .iter()
            .zip(&rerandomizers)
            .map(|(&source, r)| deck[source].re_encrypt(&aggregate, r))
            .collect::<Vec<_>>();
        let submission = RistrettoShuffleSubmission {
            aggregate_pk: point_bytes(&aggregate),
            input: deck
                .iter()
                .map(|ct| RistrettoAirCiphertext {
                    c1: point_bytes(&ct.c1),
                    c2: point_bytes(&ct.c2),
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            output: output
                .iter()
                .map(|ct| RistrettoAirCiphertext {
                    c1: point_bytes(&ct.c1),
                    c2: point_bytes(&ct.c2),
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            air_proof: vec![0; 8],
        };
        let mut request = submission
            .to_verify_request_v2(format!("table9-hand1-shuffle{seat}").into_bytes())
            .expect("V2 shuffle request");
        request.transcript = TranscriptId::Poseidon2M31;
        let envelope =
            prove_ristretto_air_v2_shuffle_poseidon2(&request, &permutation, &rerandomizers, &mut rng)
                .expect("V2 shuffle proof");
        request.proof = envelope.encode_wire().expect("envelope wire");
        let request_bytes = request.encode().expect("canonical request");
        shuffle_archives.push(request_bytes);
        deck = output;
    }
    let phase_prove = started.elapsed();
    let started = Instant::now();
    let admissions: Vec<_> = shuffle_archives
        .par_iter()
        .map(|request_bytes| {
            admit_ristretto_air_v2_shuffle_submission(request_bytes)
                .map_err(|error| format!("{error}"))
        })
        .collect();
    for admission in &admissions {
        admission.clone().expect("shuffle admission");
    }
    for request_bytes in &shuffle_archives {
        total_bytes += request_bytes.len();
    }
    let phase_verify = started.elapsed();
    client_prove += phase_prove;
    server_verify += phase_verify;
    println!(
        "[2] shuffles x{PLAYERS}: client prove {phase_prove:?} ({:.0?}/shuffle), server verify {phase_verify:?} ({:.0?}/admission)",
        phase_prove / PLAYERS as u32,
        phase_verify / PLAYERS as u32
    );

    // ---- Phase 3: deal 18 hole cards + 5 board cards ----------------------
    let mut cursor = 0usize;
    let mut hole_cards: Vec<Vec<RistrettoCiphertext>> = Vec::with_capacity(PLAYERS);
    for _ in 0..PLAYERS {
        hole_cards.push(deck[cursor..cursor + 2].to_vec());
        cursor += 2;
    }
    let board = deck[cursor..cursor + 5].to_vec();
    cursor += 5;
    println!(
        "[3] dealt {} hole + 5 board cards ({} deck positions remain)",
        PLAYERS * 2,
        deck.len() - cursor
    );

    // ---- Phase 4: preflop betting; seat {FOLD_SEAT} folds with proof ------
    let started = Instant::now();
    let (folded_universe, fold_archive) = prove_fold_with_proof_v2_poseidon2(
        &secret_keys[FOLD_SEAT],
        &public_keys[FOLD_SEAT],
        &aggregate,
        &deck,
        [0xF9; 32],
        &mut rng,
    )
    .expect("fold_with_proof proof");
    let phase_prove = started.elapsed();
    let started = Instant::now();
    verify_fold_with_proof_v2_poseidon2(
        &public_keys[FOLD_SEAT],
        &aggregate,
        &deck,
        &folded_universe,
        &fold_archive,
    )
    .expect("fold verify");
    let phase_verify = started.elapsed();
    client_prove += phase_prove;
    server_verify += phase_verify;
    total_bytes += borsh_ser(&fold_archive).len();
    println!("[4] fold_with_proof x1 (seat {FOLD_SEAT}): client prove {phase_prove:?}, server verify {phase_verify:?}");

    // ---- Phase 5: street-by-street reveals + betting lines ---------------
    // Each street: every active player publishes batched reveal tokens for
    // the street's cards (client), the server verifies the batches in
    // parallel (as submissions arrive), then a betting line advances.
    let streets: [(&str, Vec<RistrettoCiphertext>); 4] = [
        (
            "preflop-holes",
            active.iter().flat_map(|&seat| hole_cards[seat].clone()).collect(),
        ),
        ("flop", board[0..3].to_vec()),
        ("turn", board[3..4].to_vec()),
        ("river", board[4..5].to_vec()),
    ];
    let mut revealed: Vec<RistrettoCiphertext> = Vec::new();
    let mut stacks = vec![10_000u64; PLAYERS];
    let mut pot = 0u64;
    for (street_index, (street_name, street_cards)) in streets.iter().enumerate() {
        let street_started = Instant::now();
        let started = Instant::now();
        let mut batches = Vec::with_capacity(active.len());
        for &seat in &active {
            let tokens: Vec<Point> = street_cards
                .iter()
                .map(|card| card.c1 * secret_keys[seat])
                .collect();
            let context = format!("table9-hand1-{street_name}-seat{seat}");
            let (wire, proof) = prove_reveal_tokens_batched_poseidon2(
                &secret_keys[seat],
                &public_keys[seat],
                street_cards,
                &tokens,
                context.as_bytes(),
                &mut rng,
            )
            .expect("batched reveal token proof");
            batches.push((seat, context, wire, proof, tokens));
        }
        let phase_prove = started.elapsed();
        let started = Instant::now();
        let results: Vec<_> = batches
            .par_iter()
            .map(|(seat, context, wire, _proof, tokens)| {
                verify_reveal_tokens_batched_poseidon2(
                    &public_keys[*seat],
                    street_cards,
                    tokens,
                    context.as_bytes(),
                    wire,
                )
                .map_err(|error| format!("seat {seat}: {error}"))
            })
            .collect();
        for result in &results {
            result.clone().expect("batched reveal verify");
        }
        let phase_verify = started.elapsed();
        for (_, _, wire, proof, _) in &batches {
            total_bytes += borsh_ser(wire).len() + borsh_ser(proof).len();
        }
        client_prove += phase_prove;
        server_verify += phase_verify;
        revealed.extend(street_cards.iter().cloned());

        // Betting line for this street (native state transitions; the
        // canonical tagged AIR covers their STARK proving separately).
        let started = Instant::now();
        if street_index == 0 {
            let blinds = 25u64 + 50u64;
            pot += blinds;
            stacks[2] -= 25;
            stacks[3] -= 50;
        }
        for &seat in &active {
            let contribution = 50u64;
            pot += contribution;
            stacks[seat] -= contribution;
        }
        let betting = started.elapsed();

        println!(
            "[5.{}] {} ({} cards, {} reveal proofs): client prove {phase_prove:?}, server verify {phase_verify:?} (parallel), betting {betting:?}, street wall {street_elapsed:?}",
            street_index + 1,
            street_name,
            street_cards.len(),
            active.len(),
            street_elapsed = street_started.elapsed()
        );
    }

    // ---- Phase 6: showdown decrypt + settlement ---------------------------
    let started = Instant::now();
    let mut plaintexts = Vec::with_capacity(revealed.len());
    for card in &revealed {
        let tokens: Point = active.iter().map(|&seat| card.c1 * secret_keys[seat]).sum();
        plaintexts.push(card.c2 - tokens);
    }
    let distinct = {
        let mut encodings: Vec<_> = plaintexts
            .iter()
            .map(|point| point.compress().as_bytes().to_vec())
            .collect();
        encodings.sort();
        encodings.dedup();
        encodings.len() == plaintexts.len()
    };
    assert!(distinct, "revealed plaintexts must be distinct cards");
    stacks[0] += pot;
    println!(
        "[6] decrypt + settlement ({} cards, pot {pot}): {:?} native",
        revealed.len(),
        started.elapsed()
    );

    let hand_wall = hand_started.elapsed();
    println!(
        "\nTOTAL nine-player hand: wall {hand_wall:?} | client native prove {client_prove:?} | server AIR verify {server_verify:?} | client proof bytes {total_bytes} ({:.1} MiB)",
        total_bytes as f64 / (1024.0 * 1024.0)
    );
}

/// Nine-player complete hand on the secp256k1 direct-sigma settlement route
/// (docs/design/DUAL_PROOF_PROTOCOL.md v2.2): the same mental-poker flow as
/// `full_hand_v2_nine` but every P proof is the curve-generic sigma suite
/// instantiated on secp256k1 with the FiatShamirSha3 transcript — the exact
/// proof batch a `PokerDualSettlement.verify_and_settle` call will carry
/// on-chain. Terminates by computing the unified `hand_binding`, the
/// settlement digest, and the Phase-1 G attestation that registers the
/// host-verified STARK commitments.
fn full_hand_v3_dual() {
    use poker_protocol::secp256k1_sigma::{SECP256K1_TEXAS_DECK_SIZE, canonical_deck};
    use poker_protocol_core::{
        Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, Secp256k1Curve,
    };
    use poker_protocol_proofs::bayer_groth::BayerGrothShuffleProof;
    use poker_protocol_proofs::dleq_proof::{DLEqProof, LeaveKind};
    use poker_protocol_proofs::pk_ownership::PKOwnershipProof;
    use poker_protocol_proofs::reveal_token_proof::RevealTokenProof;
    use poker_protocol_proofs::transcript_ext::KeccakTranscript;
    use poker_protocol_proofs::CryptoTranscript;
    use rand::SeedableRng;
    use rayon::prelude::*;
    use starknet_crypto::Felt;
    use std::collections::HashMap;

    type Point = <Secp256k1Curve as Curve>::Point;
    type Scalar = <Secp256k1Curve as Curve>::Scalar;
    type Ct = ElGamalCiphertextGeneric<Secp256k1Curve>;

    const PLAYERS: usize = 9;
    const FOLD_SEAT: usize = 1;
    let active: Vec<usize> = (0..PLAYERS).filter(|&seat| seat != FOLD_SEAT).collect();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xB254_0001);

    let transcript = |label: &'static str| KeccakTranscript::new(label.as_bytes());
    let point_bytes = |point: &Point| {
        let mut out = [0u8; 33];
        out.copy_from_slice(point.compress().as_ref());
        out
    };
    // 33-byte SEC1 point → (17-byte, 16-byte) felt pair (both < 2^136,
    // Cairo-replicable).
    let point_felts = |bytes: &[u8; 33]| {
        let mut hi = [0u8; 17];
        let mut lo = [0u8; 16];
        hi.copy_from_slice(&bytes[..17]);
        lo.copy_from_slice(&bytes[17..]);
        [
            Felt::from_bytes_be_slice(&hi),
            Felt::from_bytes_be_slice(&lo),
        ]
    };
    let deck_commitment = |deck: &[Ct]| {
        let felts: Vec<Felt> = deck
            .iter()
            .flat_map(|ct| {
                let c1 = point_bytes(&ct.c1);
                let c2 = point_bytes(&ct.c2);
                point_felts(&c1).into_iter().chain(point_felts(&c2))
            })
            .collect();
        starknet_crypto::poseidon_hash_many(&felts)
    };
    // 20-byte seat address → felt (settlement_hash.cairo convention).
    let seat_address = |seat: usize| {
        let mut addr = [0u8; 20];
        addr[16..].copy_from_slice(&(0xD1CEu32 + seat as u32).to_be_bytes());
        Felt::from_bytes_be_slice(&addr)
    };

    let mut client_prove = std::time::Duration::ZERO;
    let mut host_verify = std::time::Duration::ZERO;
    let mut total_bytes = 0usize;
    let hand_started = Instant::now();

    // ---- Phase 1: nine ownership proofs (client) / native verifies --------
    let started = Instant::now();
    let mut secret_keys = Vec::with_capacity(PLAYERS);
    let mut public_keys = Vec::with_capacity(PLAYERS);
    let mut ownership = Vec::with_capacity(PLAYERS);
    for seat in 0..PLAYERS {
        let sk = Scalar::random(&mut rng);
        let pk = Secp256k1Curve::base_g() * &sk;
        let context = format!("table9-hand1-seat{seat}");
        let proof = PKOwnershipProof::<Secp256k1Curve>::prove(&sk, &pk, &mut rng);
        ownership.push((seat, context, proof));
        secret_keys.push(sk);
        public_keys.push(pk);
    }
    let phase_prove = started.elapsed();
    let started = Instant::now();
    for (seat, _context, proof) in &ownership {
        assert!(proof.verify(&public_keys[*seat]), "ownership verify seat {seat}");
        total_bytes += point_bytes(&proof.commitment).len() + proof.response.as_bytes().len();
    }
    let phase_verify = started.elapsed();
    client_prove += phase_prove;
    host_verify += phase_verify;
    println!(
        "[1] ownership x{PLAYERS}: client prove {phase_prove:?}, host verify {phase_verify:?}"
    );

    // ---- Phase 2: canonical deck + nine sequential proven BG shuffles -----
    let aggregate: Point = public_keys.iter().copied().sum();
    let deck_points = canonical_deck();
    assert_eq!(deck_points.len(), SECP256K1_TEXAS_DECK_SIZE);
    let mut deck: Vec<Ct> = deck_points
        .iter()
        .map(|card| {
            let r = Scalar::random(&mut rng);
            Ct::encrypt(card, &aggregate, &r)
        })
        .collect();

    let mut deck_commit_chain = vec![deck_commitment(&deck)];
    let started = Instant::now();
    let mut shuffle_proofs = Vec::with_capacity(PLAYERS);
    for seat in 0..PLAYERS {
        let mut permutation: Vec<usize> = (0..52).collect();
        let mut seed = 0x9E37_79B9_7F4A_7C15u64 ^ (seat as u64 + 0xB2);
        for index in (1..permutation.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            permutation.swap(index, (seed % (index as u64 + 1)) as usize);
        }
        let rerandomizers: Vec<Scalar> = (0..52).map(|_| Scalar::random(&mut rng)).collect();
        let output: Vec<Ct> = permutation
            .iter()
            .zip(&rerandomizers)
            .map(|(&source, r)| deck[source].re_encrypt(&aggregate, r))
            .collect();

        let mut prove_transcript = transcript("bn254_bg_shuffle_v3");
        let proof = BayerGrothShuffleProof::<Secp256k1Curve>::prove(
            &deck,
            &output,
            &permutation,
            &rerandomizers,
            &aggregate,
            &mut rng,
            &mut prove_transcript,
        )
        .expect("shuffle proves");
        shuffle_proofs.push((deck.clone(), output.clone(), proof));
        deck = output;
        deck_commit_chain.push(deck_commitment(&deck));
    }
    let phase_prove = started.elapsed();
    let started = Instant::now();
    let admissions: Vec<Result<(), String>> = shuffle_proofs
        .par_iter()
        .map(|(input, output, proof)| {
            let mut verify_transcript = transcript("bn254_bg_shuffle_v3");
            proof
                .verify(input, output, &aggregate, &mut verify_transcript)
                .map_err(|error| format!("{error}"))
        })
        .collect();
    for admission in &admissions {
        admission.clone().expect("shuffle admission");
    }
    for (input, output, _proof) in &shuffle_proofs {
        total_bytes += input.len() * 64 + output.len() * 64;
    }
    let phase_verify = started.elapsed();
    client_prove += phase_prove;
    host_verify += phase_verify;
    println!(
        "[2] shuffles x{PLAYERS}: client prove {phase_prove:?} ({:.0?}/shuffle), host verify {phase_verify:?} (parallel)",
        phase_prove / PLAYERS as u32,
    );

    // ---- Phase 3: deal 18 hole cards + 5 board cards (index slices) -------
    // Slices are index ranges into the deck; the ciphertext contents are read
    // after the fold player's key layer is stripped (Phase 4), matching the
    // protocol ordering where fold_with_proof removes that layer from every
    // outstanding ciphertext.
    let mut cursor = 0usize;
    let mut hole_ranges: HashMap<usize, usize> = HashMap::new();
    for &seat in &active {
        hole_ranges.insert(seat, cursor);
        cursor += 2;
    }
    cursor += 1; // burn
    let board_range = cursor;
    cursor += 5;
    let showdown_range = cursor;

    // ---- Phase 4: fold with a 52-card batch leave DLEQ ---------------------
    let strip_fold_layer = |ct: &Ct| Ct {
        c1: ct.c1,
        c2: ct.c2 - ct.c1 * &secret_keys[FOLD_SEAT],
    };
    let started = Instant::now();
    let folded_deck: Vec<Ct> = deck.iter().map(&strip_fold_layer).collect();
    let mut fold_prove_transcript = transcript("bn254_fold_leave_v3");
    let fold_proof = DLEqProof::<Secp256k1Curve, LeaveKind>::prove(
        &deck,
        &folded_deck,
        &secret_keys[FOLD_SEAT],
        &public_keys[FOLD_SEAT],
        &mut fold_prove_transcript,
    );
    let fold_prove_elapsed = started.elapsed();
    let started = Instant::now();
    let mut fold_verify_transcript = transcript("bn254_fold_leave_v3");
    assert!(
        fold_proof.verify(
            &deck,
            &folded_deck,
            &public_keys[FOLD_SEAT],
            &mut fold_verify_transcript
        ),
        "fold leave DLEQ verifies"
    );
    let fold_verify_elapsed = started.elapsed();
    total_bytes += folded_deck.len() * 32;
    client_prove += fold_prove_elapsed;
    host_verify += fold_verify_elapsed;
    println!(
        "[4] fold_with_proof (52-card leave DLEQ): client prove {fold_prove_elapsed:?}, host verify {fold_verify_elapsed:?}"
    );

    // Deck available to remaining players has the fold player's layer removed.
    deck = folded_deck;

    // ---- Phase 5: street reveals (tokens + proofs, batched) ----------------
    let revealed: Vec<(usize, Ct)> = active
        .iter()
        .flat_map(|&seat| {
            let start = hole_ranges[&seat];
            let cards: Vec<Ct> = deck[start..start + 2]
                .to_vec()
                .into_iter()
                .chain(deck[board_range..board_range + 5].to_vec())
                .collect();
            cards.into_iter().map(move |ct| (seat, ct))
        })
        .collect();
    let started = Instant::now();
    let mut reveal_proofs = Vec::with_capacity(revealed.len());
    for (seat, ct) in &revealed {
        let token = ct.gen_reveal_token(&secret_keys[*seat]);
        let mut prove_transcript = transcript("bn254_reveal_token_v3");
        let proof = RevealTokenProof::<Secp256k1Curve>::prove(
            &secret_keys[*seat],
            &public_keys[*seat],
            ct,
            &token,
            &mut rng,
            &mut prove_transcript,
        );
        reveal_proofs.push((*seat, ct.clone(), token, proof));
    }
    let phase_prove = started.elapsed();
    let started = Instant::now();
    let reveal_admissions: Vec<Result<(), String>> = reveal_proofs
        .par_iter()
        .map(|(seat, ct, token, proof)| {
            let mut verify_transcript = transcript("bn254_reveal_token_v3");
            proof
                .verify(ct, token, &public_keys[*seat], &mut verify_transcript)
                .map_err(|error| format!("{error:?}"))
        })
        .collect();
    for admission in &reveal_admissions {
        admission.clone().expect("reveal admission");
    }
    total_bytes += reveal_proofs.len() * 96;
    let phase_verify = started.elapsed();
    client_prove += phase_prove;
    host_verify += phase_verify;
    println!(
        "[5] reveal tokens x{}: client prove {phase_prove:?}, host verify {phase_verify:?} (parallel)",
        reveal_proofs.len()
    );

    // ---- Phase 6: showdown decrypt + settlement plan ------------------------
    let started = Instant::now();
    let mut decrypted = Vec::with_capacity(reveal_proofs.len());
    for (seat, ct, token, _proof) in &reveal_proofs {
        // Decryption: subtract every active player's token — the revealer's
        // own token is carried by the proof, the rest are derived from sk.
        let mut plaintext = ct.c2 - token;
        for &other in &active {
            if other == *seat {
                continue;
            }
            plaintext = plaintext - ct.c1 * &secret_keys[other];
        }
        decrypted.push((*seat, plaintext));
    }
    for (_seat, point) in &decrypted {
        assert!(
            deck_points.iter().any(|card| card == point),
            "decrypted plaintext must be a canonical card"
        );
    }
    assert!(
        decrypted.len() >= showdown_range,
        "showdown must decrypt at least the dealt cards"
    );

    // Zero-sum settlement plan: seat 0 wins the pot, everyone else posted 50.
    let pot = 50u64 * active.len() as u64;
    let mut deltas: Vec<i128> = vec![0; PLAYERS];
    deltas[0] = pot as i128;
    for &seat in &active {
        if seat != 0 {
            deltas[seat] -= 50;
        }
    }
    let settlement_digest = {
        let mut fields = vec![Felt::from(1u64)]; // hand_id
        for (seat, delta) in deltas.iter().enumerate() {
            fields.push(seat_address(seat));
            if *delta >= 0 {
                fields.push(Felt::from(1u64));
            } else {
                fields.push(Felt::from(0u64));
            }
            fields.push(Felt::from(delta.unsigned_abs() as u64));
        }
        // #18 Phase B：与线上同公式——digest 吸收链尾词 = 动作日志哈希
        //（bench 无 game 层动作日志，取固定样例词）。
        fields.push(Felt::from(0xA11CEu64));
        starknet_crypto::poseidon_hash_many(&fields)
    };
    let decrypt_elapsed = started.elapsed();
    println!(
        "[6] decrypt + settlement plan ({} cards, pot {pot}, settlement digest computed): {decrypt_elapsed:?} native",
        decrypted.len()
    );

    // ---- Phase 7: unified hand_binding + Phase-1 G attestation -------------
    let started = Instant::now();
    let binding = poker_texas_air::hand_binding::compute_hand_binding(
        &poker_texas_air::hand_binding::HandBindingInput {
            table_id: 9,
            hand_id: 1,
            players: (0..PLAYERS).map(seat_address).collect(),
            deck_commitments: deck_commit_chain,
            reveal_commitment: starknet_crypto::poseidon_hash_many(
                &reveal_proofs
                    .iter()
                    .flat_map(|(_seat, _ct, token, _proof)| {
                        let t = point_bytes(token);
                        point_felts(&t).to_vec()
                    })
                    .collect::<Vec<_>>(),
            ),
            state_root_pre: Felt::from(0xDEAD_u64),
            state_root_post: Felt::from(0xC0DE_u64),
            settlement_digest,
        },
    )
    .expect("hand binding");
    // Phase 1 G attestation: the digest the operator registers on-chain while
    // the canonical STARK (G) itself stays host-verified (default bench mode
    // measures that STARK's prove/verify).
    let g_attestation = starknet_crypto::poseidon_hash_many(&[
        binding,
        settlement_digest,
        Felt::from(0xDEAD_u64),
        Felt::from(0xC0DE_u64),
    ]);
    let binding_elapsed = started.elapsed();

    let hand_wall = hand_started.elapsed();
    println!(
        "[7] hand_binding + G attestation: {binding_elapsed:?} native (binding 0x{:x}, attestation 0x{:x})",
        binding, g_attestation
    );
    println!(
        "\nTOTAL v3-dual nine-player hand: wall {hand_wall:?} | client native prove {client_prove:?} | host native verify {host_verify:?} | on-chain P calldata ≈ {total_bytes} bytes ({:.1} KiB)",
        total_bytes as f64 / 1024.0
    );
}

/// One complete mental-poker hand on the RistrettoAirV2 protocol layer.
///
/// Phases: N-player key registration (ownership proofs), canonical base deck
/// under the aggregate key, N sequential Bayer--Groth shuffles, hole/board
/// dealing, one mid-hand `fold_with_proof` (key layer removed from the deck
/// and the aggregate key), a betting line over the remaining seats, and a
/// showdown where every remaining player publishes reveal tokens for each
/// revealed card (plaintext = c2 - sum(tokens)).  Every proof is verified
/// with its server-side verifier; wall clocks and proof sizes are printed per
/// phase.
fn full_hand_v2() {
    use poker_protocol::crypto::curve::{Curve, CurvePoint, RistrettoCurve};
    use poker_protocol::ristretto_air::{
        RistrettoAirCiphertext, RistrettoShuffleSubmission, RistrettoTexasDeck,
    };
    use poker_texas_air::ristretto_player_proofs_air::{
        RistrettoCiphertext, prove_fold_with_proof_v2, prove_pk_ownership,
        prove_reveal_tokens_batched, verify_fold_with_proof_v2, verify_pk_ownership,
        verify_reveal_tokens_batched,
    };
    use poker_texas_air::ristretto_shuffle_air::{
        admit_ristretto_air_v2_shuffle_submission, prove_ristretto_air_v2_shuffle,
    };
    use rand::SeedableRng;
    use rayon::prelude::*;

    type Point = <RistrettoCurve as Curve>::Point;
    type Scalar = <RistrettoCurve as Curve>::Scalar;

    const PLAYERS: usize = 4;
    const HOLE_PER_PLAYER: usize = 2;
    const BOARD_CARDS: usize = 5;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE);

    let point_bytes = |point: &Point| {
        let mut out = [0u8; 32];
        out.copy_from_slice(point.compress().as_bytes());
        out
    };
    let mut total_prove = std::time::Duration::ZERO;
    let mut total_verify = std::time::Duration::ZERO;
    let mut total_bytes = 0usize;

    // ---- Phase 1: keys + ownership proofs -------------------------------
    let started = Instant::now();
    let mut secret_keys = Vec::with_capacity(PLAYERS);
    let mut public_keys = Vec::with_capacity(PLAYERS);
    let mut ownership = Vec::with_capacity(PLAYERS);
    for seat in 0..PLAYERS {
        let sk = Scalar::random(&mut rng);
        let pk = RistrettoCurve::base_g() * sk;
        let context = format!("table7-hand3-seat{seat}");
        let (wire, proof) =
            prove_pk_ownership(&sk, &pk, context.as_bytes(), &mut rng).expect("ownership proof");
        ownership.push((seat, context, wire, proof));
        secret_keys.push(sk);
        public_keys.push(pk);
    }
    let ownership_prove = started.elapsed();
    let started = Instant::now();
    for (seat, context, wire, proof) in &ownership {
        verify_pk_ownership(&public_keys[*seat], context.as_bytes(), wire, proof)
            .expect("ownership verify");
        total_bytes += borsh_ser(wire).len() + borsh_ser(proof).len();
    }
    let ownership_verify = started.elapsed();
    println!(
        "ownership x{PLAYERS}: prove {ownership_prove:?} (includes cold flock setup), verify {ownership_verify:?}"
    );
    // P1: preheat the flock setup caches once; every later phase runs warm.
    let started = Instant::now();
    poker_texas_air::blake3_flock::preheat_flock_setup().expect("flock preheat");
    println!("flock preheat: {:?}", started.elapsed());

    // ---- Phase 2: canonical base deck under the aggregate key ------------
    let aggregate: Point = public_keys.iter().copied().sum();
    let base = RistrettoTexasDeck::canonical_base(&aggregate).expect("canonical base deck");
    let mut deck: Vec<RistrettoCiphertext> = base
        .encrypted
        .iter()
        .map(|wire| RistrettoCiphertext {
            c1: <Point as CurvePoint>::from_compressed(&wire.c1).expect("c1 decodes"),
            c2: <Point as CurvePoint>::from_compressed(&wire.c2).expect("c2 decodes"),
        })
        .collect();

    // ---- Phase 3: every player shuffles (Bayer--Groth V2) ----------------
    let started = Instant::now();
    let mut shuffle_archives = Vec::with_capacity(PLAYERS);
    for seat in 0..PLAYERS {
        let mut permutation: Vec<usize> = (0..52).collect();
        let mut seed = 0x9E37_79B9_7F4A_7C15u64 ^ (seat as u64 + 1);
        for index in (1..permutation.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            permutation.swap(index, (seed % (index as u64 + 1)) as usize);
        }
        let rerandomizers: Vec<Scalar> = (0..52).map(|_| Scalar::random(&mut rng)).collect();
        let output = permutation
            .iter()
            .zip(&rerandomizers)
            .map(|(&source, r)| deck[source].re_encrypt(&aggregate, r))
            .collect::<Vec<_>>();
        let submission = RistrettoShuffleSubmission {
            aggregate_pk: point_bytes(&aggregate),
            input: deck
                .iter()
                .map(|ct| RistrettoAirCiphertext {
                    c1: point_bytes(&ct.c1),
                    c2: point_bytes(&ct.c2),
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            output: output
                .iter()
                .map(|ct| RistrettoAirCiphertext {
                    c1: point_bytes(&ct.c1),
                    c2: point_bytes(&ct.c2),
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            air_proof: vec![0; 8],
        };
        let mut request = submission
            .to_verify_request_v2(format!("shuffle-seat{seat}").into_bytes())
            .expect("V2 shuffle request");
        let envelope =
            prove_ristretto_air_v2_shuffle(&request, &permutation, &rerandomizers, &mut rng)
                .expect("V2 shuffle proof");
        request.proof = envelope.encode_wire().expect("envelope wire");
        let request_bytes = request.encode().expect("canonical request");
        shuffle_archives.push((request_bytes, envelope));
        deck = output;
    }
    let shuffle_prove = started.elapsed();
    let started = Instant::now();
    for (request_bytes, envelope) in &shuffle_archives {
        admit_ristretto_air_v2_shuffle_submission(request_bytes).expect("shuffle admission");
        total_bytes += request_bytes.len();
        let _ = envelope;
    }
    let shuffle_verify = started.elapsed();
    total_prove += shuffle_prove;
    total_verify += shuffle_verify;
    println!("shuffles x{PLAYERS}: prove {shuffle_prove:?}, verify {shuffle_verify:?}");

    // ---- Phase 4: deal hole cards and board ------------------------------
    let mut cursor = 0usize;
    let mut hole_cards: Vec<Vec<RistrettoCiphertext>> = Vec::with_capacity(PLAYERS);
    for _ in 0..PLAYERS {
        hole_cards.push(deck[cursor..cursor + HOLE_PER_PLAYER].to_vec());
        cursor += HOLE_PER_PLAYER;
    }
    let board = deck[cursor..cursor + BOARD_CARDS].to_vec();
    cursor += BOARD_CARDS;
    let remaining_deck = deck[cursor..].to_vec();
    println!(
        "dealt {} hole cards + {BOARD_CARDS} board cards, {} deck positions remain",
        PLAYERS * HOLE_PER_PLAYER,
        remaining_deck.len()
    );

    // ---- Phase 5: seat 1 folds mid-hand (fold_with_proof) -----------------
    // The folded key layer is removed from the encrypted universe and the
    // aggregate key; the seat is excluded from every later reveal token.
    let fold_seat = 1usize;
    let fold_context = [0xF0; 32];
    let started = Instant::now();
    let (folded_universe, fold_archive) = prove_fold_with_proof_v2(
        &secret_keys[fold_seat],
        &public_keys[fold_seat],
        &aggregate,
        &deck,
        fold_context,
        &mut rng,
    )
    .expect("fold_with_proof proof");
    let fold_prove = started.elapsed();
    let _new_aggregate = aggregate - public_keys[fold_seat];
    let started = Instant::now();
    verify_fold_with_proof_v2(
        &public_keys[fold_seat],
        &aggregate,
        &deck,
        &folded_universe,
        &fold_archive,
    )
    .expect("fold verify");
    let fold_verify = started.elapsed();
    total_prove += fold_prove;
    total_verify += fold_verify;
    total_bytes += borsh_ser(&fold_archive).len();
    println!("fold_with_proof x1: prove {fold_prove:?}, verify {fold_verify:?}");

    // ---- Phase 6: betting line (call around, simulated amounts) -----------
    // Monetary transitions are plain state: the canonical tagged AIR covers
    // their STARK proving (see the default benchmark mode).  Here we advance
    // the betting state natively and account only its wall clock.
    let started = Instant::now();
    let mut stacks = vec![10_000u64; PLAYERS];
    let mut bets = vec![0u64; PLAYERS];
    let blinds = [25u64, 50u64];
    for (seat, blind) in blinds.iter().enumerate() {
        bets[seat] = *blind;
        stacks[seat] -= *blind;
    }
    let pot: u64 = bets.iter().sum();
    for seat in 0..PLAYERS {
        if seat == fold_seat {
            continue; // folded seat takes no further action
        }
        let to_call = bets.iter().max().copied().unwrap_or(0) - bets[seat];
        if to_call > 0 {
            bets[seat] += to_call;
            stacks[seat] -= to_call;
        }
    }
    let final_pot: u64 = bets.iter().sum();
    let betting_elapsed = started.elapsed();
    println!("betting line (3 active calls): {betting_elapsed:?} native, pot {pot} -> {final_pot}");

    // ---- Phase 7: showdown reveal tokens ----------------------------------
    // Every remaining player publishes a reveal token for every revealed
    // card; the plaintext is c2 - sum(tokens).  The folded seat contributes
    // nothing: its key layer is already gone.
    let active: Vec<usize> = (0..PLAYERS).filter(|&seat| seat != fold_seat).collect();
    let revealed: Vec<RistrettoCiphertext> = active
        .iter()
        .flat_map(|&seat| hole_cards[seat].clone())
        .chain(board.clone())
        .collect();
    // P0: one batched DLEQ per player over every revealed card (33 -> 3
    // proofs); P3: the per-player proofs verify in parallel.
    let started = Instant::now();
    let mut token_batches = Vec::new();
    for &seat in &active {
        let tokens: Vec<Point> = revealed
            .iter()
            .map(|card| card.c1 * secret_keys[seat])
            .collect();
        let context = format!("showdown-seat{seat}");
        let (wire, proof) = prove_reveal_tokens_batched(
            &secret_keys[seat],
            &public_keys[seat],
            &revealed,
            &tokens,
            context.as_bytes(),
            &mut rng,
        )
        .expect("batched reveal token proof");
        token_batches.push((seat, context, wire, proof));
    }
    let reveal_prove = started.elapsed();
    let started = Instant::now();
    let verify_results: Vec<_> = token_batches
        .par_iter()
        .map(|(seat, context, wire, proof)| {
            let tokens: Vec<Point> = revealed
                .iter()
                .map(|card| card.c1 * secret_keys[*seat])
                .collect();
            verify_reveal_tokens_batched(
                &public_keys[*seat],
                &revealed,
                &tokens,
                context.as_bytes(),
                wire,
                proof,
            )
            .map_err(|error| format!("seat {seat}: {error}"))
        })
        .collect();
    for result in &verify_results {
        result.clone().expect("batched reveal verify");
    }
    let reveal_verify = started.elapsed();
    for (_, _, wire, proof) in &token_batches {
        total_bytes += borsh_ser(wire).len() + borsh_ser(proof).len();
    }
    total_prove += reveal_prove;
    total_verify += reveal_verify;
    println!(
        "reveal tokens (batched: {} proofs over {} cards x {} active players): prove {reveal_prove:?}, verify {reveal_verify:?} (parallel)",
        token_batches.len(),
        revealed.len(),
        active.len()
    );

    // ---- Phase 8: decrypt revealed cards and settle -----------------------
    let started = Instant::now();
    let mut plaintexts = Vec::with_capacity(revealed.len());
    for card in &revealed {
        let tokens: Point = active.iter().map(|&seat| card.c1 * secret_keys[seat]).sum();
        plaintexts.push(card.c2 - tokens);
    }
    let all_distinct = {
        let mut encodings: Vec<_> = plaintexts
            .iter()
            .map(|point| point.compress().as_bytes().to_vec())
            .collect();
        encodings.sort();
        encodings.dedup();
        encodings.len() == plaintexts.len()
    };
    assert!(all_distinct, "revealed plaintexts must be distinct cards");
    let winner = 0usize;
    let prize = final_pot;
    stacks[winner] += prize;
    let settlement_elapsed = started.elapsed();
    println!(
        "decrypt + settlement (winner seat {winner} takes {prize}): {settlement_elapsed:?} native"
    );

    println!(
        "\nTOTAL protocol layer: prove {total_prove:?}, verify {total_verify:?}, client proof bytes {total_bytes}"
    );
}
