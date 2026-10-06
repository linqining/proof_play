//! Canonical helpers for constructing tagged-seat test fixtures.

use poker_l1::signature::{SignatureScheme, StarkTxPubkey, CURRENT_VERSION};
use poker_l1::contracts::texas_poker::utils::g1_generator as g1_gen;
use poker_l1::Address;
use poker_l1::contracts::texas_poker::card::HoleCards;
use poker_l1::contracts::texas_poker::types::{EMPTY_PLAYER, PlayingSeat, Seat, SeatStatus};
use poker_protocol::crypto::curve::CurvePoint;
use poker_protocol::crypto::types::ECPoint;

/// 结构合法的会话交易公钥 fixture（Stark v1 + 32B 压缩点，非恒等元
/// ——`Seat::occupied` 的结构校验与签名路径均可用；定宽 `StarkTxPubkey`）。
pub fn well_formed_tx_pk_fixture() -> StarkTxPubkey {
    StarkTxPubkey {
        tag: poker_l1::signature::encode_tag(SignatureScheme::Stark, CURRENT_VERSION),
        raw: g1_gen()
            .compress()
            .as_ref()
            .try_into()
            .expect("stark compressed point is 32B"),
    }
}

/// Install or replace a fixture player while preserving every meaningful payload of an existing
/// live/departed variant. A vacant slot becomes an active playing seat with a deterministic key.
pub fn set_player(seat: &mut Seat, player: Address) {
    assert_ne!(player, EMPTY_PLAYER, "fixture player must be non-empty");
    match seat {
        Seat::Vacant { time_bank_ms } => {
            let time_bank_ms = *time_bank_ms;
            *seat = Seat::occupied(
                player,
                0,
                ECPoint(g1_gen()),
                well_formed_tx_pk_fixture().to_tagged(),
                SeatStatus::Active,
            )
            .expect("fixture player must create a canonical active seat");
            seat.set_time_bank_ms(time_bank_ms);
        }
        Seat::Waiting { occupied }
        | Seat::Playing {
            playing: PlayingSeat { occupied, .. },
        } => occupied.player = player,
        Seat::DepartedThisHand {
            player: current, ..
        } => *current = player,
    }
}

/// Set a fixture stack through the checked tagged-seat API.
pub fn set_stack(seat: &mut Seat, stack: u64) {
    seat.set_stack(stack)
        .expect("fixture stack requires a live occupied seat");
}

/// Set a fixture current-round wager, promoting a waiting player into the hand first.
pub fn set_bet(seat: &mut Seat, bet: u64) {
    if seat.is_waiting() {
        seat.set_status(SeatStatus::Active);
    }
    seat.set_bet(bet)
        .expect("fixture wager requires a playing seat");
}

/// Set a fixture total contribution, promoting a waiting player into the hand first.
pub fn set_total_bet(seat: &mut Seat, total_bet: u64) {
    if seat.is_waiting() {
        seat.set_status(SeatStatus::Active);
    }
    seat.set_total_bet(total_bet)
        .expect("fixture contribution requires a playing/departed seat");
}

/// Set a fixture pending addon through the checked tagged-seat API.
pub fn set_pending_addon(seat: &mut Seat, pending_addon: u64) {
    seat.set_pending_addon(pending_addon)
        .expect("fixture addon requires a live occupied seat");
}

/// Set the fixture time bank.
pub fn set_time_bank_ms(seat: &mut Seat, time_bank_ms: u32) {
    seat.set_time_bank_ms(time_bank_ms);
}

/// Replace a fixture Mental Poker key on a live occupied seat.
pub fn set_pk(seat: &mut Seat, pk: ECPoint) {
    seat.occupied_mut()
        .expect("fixture key requires a live occupied seat")
        .pk = pk;
}

/// Replace fixture hole cards, promoting a waiting player into the hand first.
pub fn set_hand(seat: &mut Seat, hand: HoleCards) {
    if seat.is_waiting() {
        seat.set_status(SeatStatus::Active);
    }
    seat.set_hand(hand)
        .expect("fixture hand requires a playing seat");
}
