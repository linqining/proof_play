//! Verifier-owned projection of a canonical native showdown settlement.
//!
//! The host verifier replays the authenticated VM dispatch and extracts the normalized
//! `SettlementPlanCommitted` event plus per-seat awards. STWO binds this compact projection; it
//! does not re-run the BLS12-381 reveal proof, hand evaluator, or side-pot planner in AIR.

use poker_l1::contracts::texas_poker::events::TexasPokerEvent;

use crate::error::{TexasAirError, TexasAirResult};

/// Fixed seat count used by the settlement AIR projection.
pub const SETTLEMENT_SEATS: usize = 9;

/// Canonical terminal-showdown projection reconstructed by the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPlanBinding {
    /// Whether this dispatch completed showdown settlement.
    pub active: bool,
    /// Domain-separated digest emitted by the native settlement planner.
    pub plan_digest: [u8; 32],
    /// Number of boards used by the plan.
    pub runout_count: u8,
    /// Pot before rake.
    pub gross_pot: u64,
    /// Rake removed from table custody.
    pub rake: u64,
    /// Total awarded to seats.
    pub total_awards: u64,
    /// Aggregate award for each fixed seat slot.
    pub awards: [u64; SETTLEMENT_SEATS],
}

impl SettlementPlanBinding {
    /// Zero projection for a non-terminal reveal submission.
    #[must_use]
    pub const fn inactive() -> Self {
        Self {
            active: false,
            plan_digest: [0; 32],
            runout_count: 0,
            gross_pot: 0,
            rake: 0,
            total_awards: 0,
            awards: [0; SETTLEMENT_SEATS],
        }
    }

    /// Select the canonical zero/terminal projection for one replayed reveal dispatch.
    ///
    /// Settlement is classified from canonical replay events. Version deltas are command
    /// sequence facts and must not double as a compound-transition discriminator.
    pub fn from_replay(events: &[TexasPokerEvent]) -> TexasAirResult<Self> {
        let has_commitment = events
            .iter()
            .any(|event| matches!(event, TexasPokerEvent::SettlementPlanCommitted { .. }));
        if has_commitment {
            return Self::from_events(events);
        }
        if events.iter().any(|event| {
            matches!(
                event,
                TexasPokerEvent::WinnerAwarded { .. }
                    | TexasPokerEvent::HandSettled { .. }
                    | TexasPokerEvent::HandEndedWithoutShowdown { .. }
                    | TexasPokerEvent::RakeCollected { .. }
                    | TexasPokerEvent::HandReset { .. }
            )
        }) {
            return Err(TexasAirError::SpecViolation(
                "reveal replay emitted settlement side events without a plan commitment".into(),
            ));
        }
        Ok(Self::inactive())
    }

    /// Reconstruct and validate the terminal settlement projection from native replay events.
    pub fn from_events(events: &[TexasPokerEvent]) -> TexasAirResult<Self> {
        let commitments = events
            .iter()
            .filter_map(|event| match event {
                TexasPokerEvent::SettlementPlanCommitted {
                    table_id,
                    plan_digest,
                    runout_count,
                    gross_pot,
                    rake,
                    total_awards,
                } => Some((
                    *table_id,
                    *plan_digest,
                    *runout_count,
                    *gross_pot,
                    *rake,
                    *total_awards,
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [(table_id, plan_digest, runout_count, gross_pot, rake, total_awards)] =
            commitments.as_slice()
        else {
            return Err(TexasAirError::SpecViolation(format!(
                "terminal showdown replay must emit exactly one settlement plan commitment, got {}",
                commitments.len()
            )));
        };
        if !matches!(runout_count, 1 | 2) {
            return Err(TexasAirError::SpecViolation(format!(
                "settlement plan has invalid runout count {runout_count}"
            )));
        }
        if gross_pot.checked_sub(*rake) != Some(*total_awards) {
            return Err(TexasAirError::SpecViolation(
                "settlement plan event violates gross = rake + awards".into(),
            ));
        }

        let mut awards = [0u64; SETTLEMENT_SEATS];
        for event in events {
            if let TexasPokerEvent::WinnerAwarded {
                table_id: award_table_id,
                seat_index,
                amount,
                ..
            } = event
            {
                if award_table_id != table_id {
                    return Err(TexasAirError::SpecViolation(
                        "settlement award table does not match plan commitment table".into(),
                    ));
                }
                let seat = usize::from(*seat_index);
                if seat >= SETTLEMENT_SEATS {
                    return Err(TexasAirError::SpecViolation(format!(
                        "settlement award targets out-of-range seat {seat}"
                    )));
                }
                awards[seat] = awards[seat].checked_add(*amount).ok_or_else(|| {
                    TexasAirError::SpecViolation("settlement seat award overflow".into())
                })?;
            }
        }
        let award_sum = awards.iter().try_fold(0u64, |sum, amount| {
            sum.checked_add(*amount)
                .ok_or_else(|| TexasAirError::SpecViolation("settlement award sum overflow".into()))
        })?;
        if award_sum != *total_awards {
            return Err(TexasAirError::SpecViolation(format!(
                "settlement award events sum to {award_sum}, expected {total_awards}"
            )));
        }

        // The plan and award events are not a complete normalized settlement
        // sequence on their own.  Require the unique terminal marker and make
        // its winner projection agree with the fixed-seat award aggregation.
        let settled = events
            .iter()
            .filter_map(|event| match event {
                TexasPokerEvent::HandSettled {
                    table_id: settled_table_id,
                    pot,
                    winners,
                } => Some((*settled_table_id, *pot, winners)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [(settled_table_id, settled_pot, winners)] = settled.as_slice() else {
            return Err(TexasAirError::SpecViolation(
                "terminal showdown replay must emit exactly one HandSettled event".into(),
            ));
        };
        if *settled_table_id != *table_id || *settled_pot != *gross_pot {
            return Err(TexasAirError::SpecViolation(
                "HandSettled event does not match settlement plan scope".into(),
            ));
        }
        let expected_winners = awards
            .iter()
            .enumerate()
            .fold(0u16, |mask, (seat, amount)| {
                if *amount > 0 {
                    mask | (1u16 << seat)
                } else {
                    mask
                }
            });
        if **winners != expected_winners {
            return Err(TexasAirError::SpecViolation(
                "HandSettled winners do not match fixed-seat awards".into(),
            ));
        }

        let rake_events = events
            .iter()
            .filter_map(|event| match event {
                TexasPokerEvent::RakeCollected {
                    table_id: rake_table_id,
                    pot_before,
                    rake_amount,
                    pot_after,
                    ..
                } => Some((*rake_table_id, *pot_before, *rake_amount, *pot_after)),
                _ => None,
            })
            .collect::<Vec<_>>();
        match (*rake, rake_events.as_slice()) {
            (0, []) => {}
            (rake, [(rake_table_id, pot_before, rake_amount, pot_after)])
                if *rake_table_id == *table_id
                    && *pot_before == *gross_pot
                    && *rake_amount == rake
                    && *pot_after == *total_awards => {}
            _ => {
                return Err(TexasAirError::SpecViolation(
                    "RakeCollected events do not match settlement plan".into(),
                ));
            }
        }

        Ok(Self {
            active: true,
            plan_digest: *plan_digest,
            runout_count: *runout_count,
            gross_pot: *gross_pot,
            rake: *rake,
            total_awards: *total_awards,
            awards,
        })
    }
}

#[cfg(test)]
mod tests {
    use poker_l1::object_model::ObjectID;

    use super::*;

    fn plan_event(
        runout_count: u8,
        gross_pot: u64,
        rake: u64,
        total_awards: u64,
    ) -> TexasPokerEvent {
        TexasPokerEvent::SettlementPlanCommitted {
            table_id: ObjectID::new([0x11; 20], 7),
            plan_digest: [0xA5; 32],
            runout_count,
            gross_pot,
            rake,
            total_awards,
        }
    }

    fn award_event(seat_index: u8, amount: u64) -> TexasPokerEvent {
        TexasPokerEvent::WinnerAwarded {
            table_id: ObjectID::new([0x11; 20], 7),
            seat_index,
            player: [seat_index; 20],
            amount,
            pot_type: 0,
            hand_rank: Some(1),
        }
    }

    fn award_event_for_other_table(seat_index: u8, amount: u64) -> TexasPokerEvent {
        TexasPokerEvent::WinnerAwarded {
            table_id: ObjectID::new([0x22; 20], 8),
            seat_index,
            player: [seat_index; 20],
            amount,
            pot_type: 0,
            hand_rank: Some(1),
        }
    }

    fn settled_event(pot: u64, winners: u16) -> TexasPokerEvent {
        TexasPokerEvent::HandSettled {
            table_id: ObjectID::new([0x11; 20], 7),
            pot,
            winners,
        }
    }

    fn rake_event(pot_before: u64, rake_amount: u64, pot_after: u64) -> TexasPokerEvent {
        TexasPokerEvent::RakeCollected {
            table_id: ObjectID::new([0x11; 20], 7),
            pot_before,
            rake_amount,
            pot_after,
            rake_mode: 1,
        }
    }

    #[test]
    fn terminal_projection_aggregates_awards_by_fixed_seat() {
        let binding = SettlementPlanBinding::from_events(&[
            plan_event(2, 200, 10, 190),
            award_event(0, 90),
            award_event(0, 5),
            award_event(4, 95),
            rake_event(200, 10, 190),
            settled_event(200, 0b10001),
        ])
        .unwrap();

        assert!(binding.active);
        assert_eq!(binding.runout_count, 2);
        assert_eq!(binding.awards[0], 95);
        assert_eq!(binding.awards[4], 95);
    }

    #[test]
    fn terminal_projection_requires_exactly_one_plan_event() {
        assert!(SettlementPlanBinding::from_events(&[award_event(0, 10)]).is_err());
        assert!(
            SettlementPlanBinding::from_events(&[plan_event(1, 10, 0, 10), award_event(0, 10),])
                .is_err()
        );
        assert!(
            SettlementPlanBinding::from_events(&[
                plan_event(1, 10, 0, 10),
                plan_event(1, 10, 0, 10),
                award_event(0, 10),
                settled_event(10, 1),
            ])
            .is_err()
        );
    }

    #[test]
    fn terminal_projection_fails_closed_on_invalid_summary_or_awards() {
        assert!(
            SettlementPlanBinding::from_events(&[
                plan_event(3, 10, 0, 10),
                award_event(0, 10),
                settled_event(10, 1),
            ])
            .is_err()
        );
        assert!(
            SettlementPlanBinding::from_events(&[
                plan_event(1, 10, 1, 10),
                award_event(0, 10),
                settled_event(10, 1),
            ])
            .is_err()
        );
        assert!(
            SettlementPlanBinding::from_events(&[
                plan_event(1, 10, 0, 10),
                award_event(SETTLEMENT_SEATS as u8, 10),
                settled_event(10, 1),
            ])
            .is_err()
        );
        assert!(
            SettlementPlanBinding::from_events(&[
                plan_event(1, 10, 0, 10),
                award_event(0, 9),
                settled_event(10, 1),
            ])
            .is_err()
        );
        assert!(
            SettlementPlanBinding::from_events(&[
                plan_event(1, 10, 0, 10),
                award_event_for_other_table(0, 10),
                settled_event(10, 1),
            ])
            .is_err()
        );
    }

    #[test]
    fn non_terminal_projection_rejects_any_settlement_event() {
        assert!(SettlementPlanBinding::from_replay(&[plan_event(1, 10, 0, 10)]).is_err());
        assert!(SettlementPlanBinding::from_replay(&[award_event(0, 10)]).is_err());
        assert_eq!(
            SettlementPlanBinding::from_replay(&[]).unwrap(),
            SettlementPlanBinding::inactive()
        );
    }

    #[test]
    fn terminal_projection_rejects_mismatched_terminal_markers() {
        assert!(
            SettlementPlanBinding::from_events(&[
                plan_event(1, 10, 0, 10),
                award_event(0, 10),
                settled_event(9, 1),
            ])
            .is_err()
        );
        assert!(
            SettlementPlanBinding::from_events(&[
                plan_event(1, 10, 0, 10),
                award_event(0, 10),
                settled_event(10, 2),
            ])
            .is_err()
        );
        assert!(
            SettlementPlanBinding::from_events(&[
                plan_event(1, 10, 1, 9),
                award_event(0, 9),
                settled_event(10, 1),
            ])
            .is_err()
        );
    }
}
