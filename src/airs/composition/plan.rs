//! Canonical verifier-side derivation of composable transition plans.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use poker_l1::contracts::texas_poker::constants::{
    FOLD_REASON_AUTO_TIMEOUT, FOLD_REASON_FORCE_ADMIN, FOLD_REASON_MANUAL, ROUND_WAITING,
};
use poker_l1::contracts::texas_poker::events::{
    RESET_REASON_LAST_PLAYER_STANDING, TexasPokerEvent,
};
use poker_l1::contracts::texas_poker::types::TexasPokerTable;

use super::bet_collection::BetCollectionPlan;
use super::round_advance::{NO_CURRENT_TURN, RoundAdvancePlan};
use super::seat_update::{COMPOSITION_SEATS, SeatUpdatePlan};
use super::settlement::{SettlementKind, SettlementStagePlan};
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::prove_task::{DispatchOutput, MethodInput, ProveTask};
use crate::public_inputs::TexasPublicInputs;
use crate::settlement_binding::SettlementPlanBinding;

/// Encoding version for the composite plan and all stage boundary commitments.
pub const COMPOSITE_PLAN_VERSION: u8 = 1;

const PLAN_DOMAIN: &[u8] = b"zchain.texas.composite-transition-plan.v1";
const TABLE_DOMAIN: &[u8] = b"zchain.texas.composite-table-image.v1";
const BOUNDARY_DOMAIN: &[u8] = b"zchain.texas.composite-stage-boundary.v1";
const NO_SHOWDOWN_DOMAIN: &[u8] = b"zchain.texas.no-showdown-settlement.v1";
const RESET_ONLY_DOMAIN: &[u8] = b"zchain.texas.reset-only.v1";

/// Whether a method is normalized through the four-stage composition pipeline.
#[must_use]
pub const fn supports_composite_proof(method_kind: MethodKind) -> bool {
    matches!(
        method_kind,
        MethodKind::Fold
            | MethodKind::Check
            | MethodKind::Call
            | MethodKind::Raise
            | MethodKind::Bet
            | MethodKind::ForceFold
            | MethodKind::AdvanceDeadline
            | MethodKind::KickPlayer
            | MethodKind::FoldWithProof
            | MethodKind::SubmitPlayerRevealTokens
    )
}

/// Canonical order of independently composable transition components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum StageKind {
    /// Acting-seat and per-round acted-flag mutation.
    SeatUpdate = 0,
    /// Fixed nine-seat wager collection into the pot.
    BetCollection = 1,
    /// Betting-round and reveal-phase advancement.
    RoundAdvance = 2,
    /// Deterministic award projection plus reset.
    Settlement = 3,
}

impl StageKind {
    /// Fixed stage index used by composition links.
    #[must_use]
    pub const fn index(self) -> u8 {
        self as u8
    }
}

/// Commitment metadata carried by every stage AIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageLink {
    /// Whether the stage changes its business projection.
    pub active: bool,
    /// Stage discriminator.
    pub stage_kind: StageKind,
    /// Fixed position in the four-stage pipeline.
    pub stage_index: u8,
    /// Digest of the complete canonical plan payload.
    pub plan_digest: [u8; 32],
    /// Commitment at the stage input boundary.
    pub input_digest: [u8; 32],
    /// Commitment at the stage output boundary.
    pub output_digest: [u8; 32],
}

/// Public statement that distinguishes one component proof inside a composite transition.
///
/// The complete value is mixed into Fiat--Shamir independently of the trusted trace row, so
/// proofs for different stages or plans cannot be exchanged even when their table roots match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentStatement {
    /// Composite plan ABI version.
    pub plan_version: u8,
    /// Component discriminator.
    pub stage_kind: StageKind,
    /// Fixed component position in the four-stage pipeline.
    pub stage_index: u8,
    /// Whether the component performs a business transition.
    pub active: bool,
    /// Digest of the complete canonical transition plan.
    pub plan_digest: [u8; 32],
    /// Input projection commitment for this component.
    pub input_digest: [u8; 32],
    /// Output projection commitment for this component.
    pub output_digest: [u8; 32],
}

impl ComponentStatement {
    /// Construct the public statement carried by one canonical stage link.
    #[must_use]
    pub const fn from_link(link: &StageLink) -> Self {
        Self {
            plan_version: COMPOSITE_PLAN_VERSION,
            stage_kind: link.stage_kind,
            stage_index: link.stage_index,
            active: link.active,
            plan_digest: link.plan_digest,
            input_digest: link.input_digest,
            output_digest: link.output_digest,
        }
    }
}

/// Verifier-owned projection of one atomic dispatch into four composable stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeTransitionPlan {
    /// Plan ABI version.
    pub version: u8,
    /// Original dispatch method.
    pub method_kind: MethodKind,
    /// Table creation nonce used by existing Texas AIR public inputs.
    pub table_id: u64,
    /// Hand sequence after the dispatch.
    pub hand_id: u32,
    /// Call sequence after the dispatch.
    pub call_seq: u32,
    /// Digest of the canonical complete pre-table image.
    pub pre_table_digest: [u8; 32],
    /// Digest of the canonical complete post-table image.
    pub post_table_digest: [u8; 32],
    /// Digest of every business-stage payload and dispatch scope field.
    pub plan_digest: [u8; 32],
    /// Acting-seat mutation projection.
    pub seat_update: SeatUpdatePlan,
    /// Bet collection projection.
    pub bet_collection: BetCollectionPlan,
    /// Round/reveal advancement projection.
    pub round_advance: RoundAdvancePlan,
    /// Settlement and reset projection.
    pub settlement: SettlementStagePlan,
    links: [StageLink; 4],
}

impl CompositeTransitionPlan {
    /// Return a stage link by its fixed kind.
    #[must_use]
    pub fn link(&self, kind: StageKind) -> &StageLink {
        &self.links[usize::from(kind.index())]
    }

    /// Return all links in canonical execution order.
    #[must_use]
    pub fn links(&self) -> &[StageLink; 4] {
        &self.links
    }

    /// Verify local plan/link invariants without replaying the VM again.
    pub fn validate_composition(&self) -> TexasAirResult<()> {
        if self.version != COMPOSITE_PLAN_VERSION {
            return Err(TexasAirError::SpecViolation(format!(
                "unsupported composite plan version {}",
                self.version
            )));
        }
        let active = [
            self.seat_update.active,
            self.bet_collection.active,
            self.round_advance.active,
            self.settlement.active,
        ];
        for (index, link) in self.links.iter().enumerate() {
            if usize::from(link.stage_index) != index
                || usize::from(link.stage_kind.index()) != index
                || link.plan_digest != self.plan_digest
                || link.active != active[index]
            {
                return Err(TexasAirError::SpecViolation(format!(
                    "composite stage link {index} does not match its payload"
                )));
            }
            if index > 0 && self.links[index - 1].output_digest != link.input_digest {
                return Err(TexasAirError::SpecViolation(format!(
                    "composite boundary between stages {} and {index} is broken",
                    index - 1
                )));
            }
        }
        Ok(())
    }
}

#[derive(BorshSerialize)]
struct CompositePlanBody {
    version: u8,
    method_kind: MethodKind,
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
    pre_table_digest: [u8; 32],
    post_table_digest: [u8; 32],
    seat_update: SeatUpdatePlan,
    bet_collection: BetCollectionPlan,
    round_advance: RoundAdvancePlan,
    settlement: SettlementStagePlan,
}

/// Derive the unique four-stage plan from canonical replayed tables and events.
///
/// `acting_seat` is required only for betting actions. Non-action dispatches use
/// `None`, producing inactive seat/collection/round stages while still allowing a
/// terminal showdown settlement stage.
pub fn derive_composite_transition_plan(
    method_kind: MethodKind,
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
    acting_seat: Option<u8>,
    events: &[TexasPokerEvent],
) -> TexasAirResult<CompositeTransitionPlan> {
    if pre.id != post.id {
        return Err(TexasAirError::SpecViolation(
            "composite transition changed table object id".into(),
        ));
    }
    if pre.seats.len() > COMPOSITION_SEATS || post.seats.len() > COMPOSITION_SEATS {
        return Err(TexasAirError::SpecViolation(
            "composite transition exceeds fixed nine-seat ABI".into(),
        ));
    }

    let seat_update = derive_seat_update(method_kind, pre, acting_seat, events)?;
    let has_round_advance = events
        .iter()
        .any(|event| matches!(event, TexasPokerEvent::RoundAdvanced { .. }));
    let has_no_showdown = events
        .iter()
        .any(|event| matches!(event, TexasPokerEvent::HandEndedWithoutShowdown { .. }));
    let has_collection_event = events
        .iter()
        .any(|event| matches!(event, TexasPokerEvent::PotCollected { .. }));
    let collection_active = has_round_advance || has_no_showdown || has_collection_event;
    let bet_collection =
        derive_bet_collection(method_kind, pre, &seat_update, collection_active, events)?;
    let round_advance = derive_round_advance(pre, post, events)?;
    let settlement = derive_settlement(pre, post, &bet_collection, method_kind, events)?;

    if round_advance.active && settlement.active {
        return Err(TexasAirError::SpecViolation(
            "one dispatch cannot both emit RoundAdvanced and settle/reset".into(),
        ));
    }
    if bet_collection.active && !round_advance.active && !settlement.active {
        return Err(TexasAirError::SpecViolation(
            "bet collection is not followed by round advance or settlement".into(),
        ));
    }
    if round_advance.active && bet_collection.post_pot != post.pot {
        return Err(TexasAirError::SpecViolation(
            "round-advance post pot does not match collection output".into(),
        ));
    }

    let pre_table_digest = hash_borsh(TABLE_DOMAIN, pre)?;
    let post_table_digest = hash_borsh(TABLE_DOMAIN, post)?;
    let body = CompositePlanBody {
        version: COMPOSITE_PLAN_VERSION,
        method_kind,
        table_id: pre.id.creation_nonce,
        hand_id: post.hand_id,
        call_seq: post.call_seq,
        pre_table_digest,
        post_table_digest,
        seat_update: seat_update.clone(),
        bet_collection: bet_collection.clone(),
        round_advance: round_advance.clone(),
        settlement: settlement.clone(),
    };
    let plan_digest = hash_borsh(PLAN_DOMAIN, &body)?;
    let boundaries: [[u8; 32]; 5] = std::array::from_fn(|boundary_index| {
        hash_bytes(
            BOUNDARY_DOMAIN,
            &borsh::to_vec(&(
                COMPOSITE_PLAN_VERSION,
                method_kind,
                pre.id.creation_nonce,
                post.hand_id,
                post.call_seq,
                plan_digest,
                u8::try_from(boundary_index).expect("five boundaries fit u8"),
            ))
            .expect("fixed composite boundary tuple serializes"),
        )
    });
    let active = [
        seat_update.active,
        bet_collection.active,
        round_advance.active,
        settlement.active,
    ];
    let kinds = [
        StageKind::SeatUpdate,
        StageKind::BetCollection,
        StageKind::RoundAdvance,
        StageKind::Settlement,
    ];
    let links = std::array::from_fn(|index| StageLink {
        active: active[index],
        stage_kind: kinds[index],
        stage_index: u8::try_from(index).expect("four stages fit u8"),
        plan_digest,
        input_digest: boundaries[index],
        output_digest: boundaries[index + 1],
    });

    let plan = CompositeTransitionPlan {
        version: COMPOSITE_PLAN_VERSION,
        method_kind,
        table_id: pre.id.creation_nonce,
        hand_id: post.hand_id,
        call_seq: post.call_seq,
        pre_table_digest,
        post_table_digest,
        plan_digest,
        seat_update,
        bet_collection,
        round_advance,
        settlement,
        links,
    };
    plan.validate_composition()?;
    Ok(plan)
}

/// Replay a canonical proof task and derive its unique composite transition plan.
pub fn derive_composite_transition_plan_from_task(
    task: &ProveTask,
) -> TexasAirResult<CompositeTransitionPlan> {
    if !supports_composite_proof(task.method_kind) {
        return Err(TexasAirError::NotImplemented(format!(
            "{} does not use the composite proof pipeline",
            task.method_kind.method_name()
        )));
    }
    crate::orchestrator::validate_full_dispatch_task(task)?;
    let mut replay = task.pre_table.clone();
    let replay_args = poker_l1::contracts::texas_poker::dispatch::replay_dispatch_args(
        task.method_kind as u8,
        &task.raw_args,
        &task.context,
        &task.pre_table,
    )
    .map_err(|error| {
        TexasAirError::SpecViolation(format!(
            "{} composite replay payload failed: {error}",
            task.method_kind.method_name()
        ))
    })?;
    let result = poker_l1::contracts::texas_poker::dispatch::dispatch(
        &task.context,
        &mut replay,
        &task.selector(),
        &replay_args,
    )
    .map_err(|error| {
        TexasAirError::SpecViolation(format!(
            "{} composite replay failed: {error}",
            task.method_kind.method_name()
        ))
    })?;
    let output: DispatchOutput = borsh::from_slice(&result.return_value).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "{} composite replay output borsh: {error}",
            task.method_kind.method_name()
        ))
    })?;
    derive_composite_transition_plan(
        task.method_kind,
        &task.pre_table,
        &task.post_table,
        acting_seat(task.method_kind, &task.method_input()?, &task.pre_table)?,
        &output.events,
    )
}

pub(crate) fn derive_composite_transition_plan_from_public_inputs(
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<CompositeTransitionPlan> {
    if !supports_composite_proof(public_inputs.kind) {
        return Err(TexasAirError::NotImplemented(format!(
            "{} does not use the composite proof pipeline",
            public_inputs.kind.method_name()
        )));
    }
    let canonical =
        crate::airs::validation::validate_canonical_dispatch(public_inputs, public_inputs.kind)?;
    derive_composite_transition_plan(
        public_inputs.kind,
        &canonical.pre,
        &canonical.post,
        acting_seat(public_inputs.kind, &canonical.method_input, &canonical.pre)?,
        &canonical.events,
    )
}

fn acting_seat(
    method_kind: MethodKind,
    input: &MethodInput,
    pre: &TexasPokerTable,
) -> TexasAirResult<Option<u8>> {
    let seat = match (method_kind, input) {
        (
            MethodKind::Fold | MethodKind::Check | MethodKind::Call | MethodKind::ForceFold,
            MethodInput::SeatOnly { seat_index },
        )
        | (MethodKind::Raise, MethodInput::Raise { seat_index, .. })
        | (MethodKind::Bet, MethodInput::Bet { seat_index, .. })
        | (MethodKind::FoldWithProof, MethodInput::FoldWithProof { seat_index, .. }) => {
            Some(*seat_index)
        }
        (MethodKind::KickPlayer, MethodInput::Kick { .. })
        | (MethodKind::SubmitPlayerRevealTokens, MethodInput::SubmitPlayerRevealTokens { .. }) => {
            None
        }
        // Tick has no seat argument. Its only SeatUpdate-compatible branch is
        // the betting-timeout auto-fold, whose actor is the canonical pre-state
        // current turn. Other Tick branches leave SeatUpdate inactive.
        (MethodKind::AdvanceDeadline, MethodInput::Empty) => pre.current_turn_option(),
        _ => {
            return Err(TexasAirError::SpecViolation(format!(
                "{} method input does not match composite-plan routing",
                method_kind.method_name()
            )));
        }
    };
    Ok(seat)
}

fn derive_seat_update(
    method_kind: MethodKind,
    pre: &TexasPokerTable,
    acting_seat: Option<u8>,
    events: &[TexasPokerEvent],
) -> TexasAirResult<SeatUpdatePlan> {
    let tick_auto_fold = method_kind == MethodKind::AdvanceDeadline
        && events.iter().any(|event| {
            matches!(
                event,
                TexasPokerEvent::PlayerFolded {
                    reason: FOLD_REASON_AUTO_TIMEOUT,
                    ..
                }
            )
        });
    let is_action = tick_auto_fold
        || matches!(
            method_kind,
            MethodKind::Fold
                | MethodKind::Check
                | MethodKind::Call
                | MethodKind::Raise
                | MethodKind::Bet
                | MethodKind::ForceFold
                | MethodKind::FoldWithProof
        );
    if !is_action {
        return Ok(SeatUpdatePlan::inactive());
    }
    let seat_index = acting_seat.ok_or_else(|| {
        TexasAirError::SpecViolation(format!(
            "{} composite plan is missing acting seat",
            method_kind.method_name()
        ))
    })?;
    let seat = pre.seats.get(usize::from(seat_index)).ok_or_else(|| {
        TexasAirError::SpecViolation("composite acting seat is outside the table".into())
    })?;
    let mut primary = Vec::new();
    for event in events {
        let candidate = match (method_kind, event) {
            (
                MethodKind::Fold
                | MethodKind::ForceFold
                | MethodKind::AdvanceDeadline
                | MethodKind::FoldWithProof,
                TexasPokerEvent::PlayerFolded {
                    table_id,
                    seat_index: event_seat,
                    reason,
                    round_state,
                },
            ) => Some((*table_id, *event_seat, 0, true, *reason, *round_state)),
            (
                MethodKind::Check,
                TexasPokerEvent::PlayerChecked {
                    table_id,
                    seat_index: event_seat,
                    round_state,
                },
            ) => Some((*table_id, *event_seat, 0, false, u8::MAX, *round_state)),
            (
                MethodKind::Call,
                TexasPokerEvent::PlayerCalled {
                    table_id,
                    seat_index: event_seat,
                    call_delta,
                    round_state,
                },
            ) => Some((
                *table_id,
                *event_seat,
                *call_delta,
                false,
                u8::MAX,
                *round_state,
            )),
            (
                MethodKind::Raise,
                TexasPokerEvent::PlayerRaised {
                    table_id,
                    seat_index: event_seat,
                    raise_delta,
                    round_state,
                    ..
                },
            ) => Some((
                *table_id,
                *event_seat,
                *raise_delta,
                false,
                u8::MAX,
                *round_state,
            )),
            (
                MethodKind::Bet,
                TexasPokerEvent::PlayerRaised {
                    table_id,
                    seat_index: event_seat,
                    raise_delta,
                    round_state,
                    ..
                },
            ) => Some((
                *table_id,
                *event_seat,
                *raise_delta,
                false,
                u8::MAX,
                *round_state,
            )),
            _ => None,
        };
        if let Some(candidate) = candidate {
            primary.push(candidate);
        }
    }
    let [(event_table, event_seat, amount, folded, reason, event_round)] = primary.as_slice()
    else {
        return Err(TexasAirError::SpecViolation(format!(
            "{} replay must emit exactly one primary betting action event",
            method_kind.method_name()
        )));
    };
    if *event_table != pre.id || *event_seat != seat_index || *event_round != pre.round_state() {
        return Err(TexasAirError::SpecViolation(
            "primary betting action event does not match dispatch scope".into(),
        ));
    }
    let expected_fold_reason = match method_kind {
        MethodKind::Fold | MethodKind::FoldWithProof => Some(FOLD_REASON_MANUAL),
        MethodKind::AdvanceDeadline => Some(FOLD_REASON_AUTO_TIMEOUT),
        MethodKind::ForceFold => Some(FOLD_REASON_FORCE_ADMIN),
        _ => None,
    };
    if expected_fold_reason.is_some() != *folded
        || expected_fold_reason.is_some_and(|expected| expected != *reason)
    {
        return Err(TexasAirError::SpecViolation(
            "primary action event kind/reason does not match method".into(),
        ));
    }
    let expected_money_kind = match method_kind {
        MethodKind::Check
        | MethodKind::Fold
        | MethodKind::ForceFold
        | MethodKind::AdvanceDeadline
        | MethodKind::FoldWithProof => *amount == 0,
        MethodKind::Call | MethodKind::Raise | MethodKind::Bet => !*folded,
        _ => false,
    };
    if !expected_money_kind {
        return Err(TexasAirError::SpecViolation(
            "primary action event amount does not match method".into(),
        ));
    }
    if method_kind == MethodKind::Bet {
        let markers = events
            .iter()
            .filter_map(|event| match event {
                TexasPokerEvent::PlayerBet {
                    table_id,
                    seat_index,
                    amount,
                    ..
                } => Some((*table_id, *seat_index, *amount)),
                _ => None,
            })
            .collect::<Vec<_>>();
        if markers.as_slice() != [(*event_table, *event_seat, *amount)] {
            return Err(TexasAirError::SpecViolation(
                "bet replay must emit one semantic PlayerBet marker matching PlayerRaised".into(),
            ));
        }
    }

    let post_stack = seat
        .stack()
        .checked_sub(*amount)
        .ok_or_else(|| TexasAirError::SpecViolation("seat-update stack debit underflow".into()))?;
    let post_bet = seat
        .bet()
        .checked_add(*amount)
        .ok_or_else(|| TexasAirError::SpecViolation("seat-update bet credit overflow".into()))?;
    let post_total_bet = seat.total_bet().checked_add(*amount).ok_or_else(|| {
        TexasAirError::SpecViolation("seat-update total_bet credit overflow".into())
    })?;
    let post_all_in = seat.is_all_in() || (*amount > 0 && post_stack == 0);
    let mut acted_before = [false; COMPOSITION_SEATS];
    let mut acted_after = [false; COMPOSITION_SEATS];
    for (index, _) in pre.seats.iter().enumerate() {
        acted_before[index] = pre.seat_acted_this_round(index as u8);
        acted_after[index] = pre.seat_acted_this_round(index as u8);
    }
    acted_after[usize::from(seat_index)] = true;
    if matches!(method_kind, MethodKind::Raise | MethodKind::Bet) {
        for (index, table_seat) in pre.seats.iter().enumerate() {
            if index != usize::from(seat_index)
                && table_seat.is_occupied()
                && !table_seat.is_folded()
                && !table_seat.is_all_in()
                && !table_seat.is_waiting()
            {
                acted_after[index] = false;
            }
        }
    }

    Ok(SeatUpdatePlan {
        active: true,
        seat_index,
        pre_stack: seat.stack(),
        post_stack,
        stack_debit: *amount,
        pre_bet: seat.bet(),
        post_bet,
        bet_credit: *amount,
        pre_total_bet: seat.total_bet(),
        post_total_bet,
        total_bet_credit: *amount,
        pre_folded: seat.is_folded(),
        post_folded: seat.is_folded() || *folded,
        pre_all_in: seat.is_all_in(),
        post_all_in,
        acted_before,
        acted_after,
    })
}

fn derive_bet_collection(
    method_kind: MethodKind,
    pre: &TexasPokerTable,
    seat_update: &SeatUpdatePlan,
    active: bool,
    events: &[TexasPokerEvent],
) -> TexasAirResult<BetCollectionPlan> {
    if !active {
        if events
            .iter()
            .any(|event| matches!(event, TexasPokerEvent::PotCollected { .. }))
        {
            return Err(TexasAirError::SpecViolation(
                "inactive collection has PotCollected event".into(),
            ));
        }
        return Ok(BetCollectionPlan::inactive());
    }
    let mut seat_bets = [0u64; COMPOSITION_SEATS];
    for (index, seat) in pre.seats.iter().enumerate() {
        seat_bets[index] = seat.bet();
    }
    if seat_update.active {
        seat_bets[usize::from(seat_update.seat_index)] = seat_update.post_bet;
    }
    let collected_bets = seat_bets.iter().try_fold(0u64, |sum, bet| {
        sum.checked_add(*bet)
            .ok_or_else(|| TexasAirError::SpecViolation("collection bet sum overflow".into()))
    })?;
    let post_pot = pre
        .pot
        .checked_add(collected_bets)
        .ok_or_else(|| TexasAirError::SpecViolation("collection pot overflow".into()))?;
    // kick_player moves the kicked seat's bet into the pot before
    // end_without_showdown invokes collect_bets_to_pot. The component still accounts for that
    // pre-state bet in the complete pot delta, while the native PotCollected event correctly
    // lists only the seats scanned by the later collection call.
    let immediately_collected_kick_seats = if matches!(
        method_kind,
        MethodKind::KickPlayer | MethodKind::AdvanceDeadline
    ) {
        let kicked = events
            .iter()
            .filter_map(|event| match event {
                TexasPokerEvent::PlayerKicked {
                    table_id,
                    seat_index,
                    ..
                } => Some((*table_id, *seat_index)),
                _ => None,
            })
            .collect::<Vec<_>>();
        if method_kind == MethodKind::KickPlayer && kicked.len() != 1 {
            return Err(TexasAirError::SpecViolation(
                "active kick collection requires exactly one PlayerKicked event".into(),
            ));
        }
        let mut seats = [false; COMPOSITION_SEATS];
        for (table_id, seat_index) in kicked {
            let index = usize::from(seat_index);
            if table_id != pre.id || index >= pre.seats.len() || seats[index] {
                return Err(TexasAirError::SpecViolation(
                    "PlayerKicked event does not match collection table scope".into(),
                ));
            }
            seats[index] = true;
        }
        seats
    } else {
        [false; COMPOSITION_SEATS]
    };
    let expected_seats = seat_bets
        .iter()
        .enumerate()
        .fold(0u16, |mask, (index, bet)| {
            if *bet > 0 && !immediately_collected_kick_seats[index] {
                mask | (1u16 << index)
            } else {
                mask
            }
        });
    let event_collected_bets = seat_bets
        .iter()
        .enumerate()
        .filter(|(index, _)| !immediately_collected_kick_seats[*index])
        .try_fold(0u64, |sum, (_, bet)| {
            sum.checked_add(*bet).ok_or_else(|| {
                TexasAirError::SpecViolation("event collection bet sum overflow".into())
            })
        })?;
    let pot_events = events
        .iter()
        .filter_map(|event| match event {
            TexasPokerEvent::PotCollected {
                table_id,
                round_state,
                pot_after,
                collected_from_seats,
            } => Some((*table_id, *round_state, *pot_after, collected_from_seats)),
            _ => None,
        })
        .collect::<Vec<_>>();
    match pot_events.as_slice() {
        [] if event_collected_bets == 0 => {}
        [(table_id, round_state, pot_after, seats)]
            if *table_id == pre.id
                && *round_state == pre.round_state()
                && *pot_after == post_pot
                && **seats == expected_seats => {}
        _ => {
            // 诊断增强：带出事件与投影的逐字段值（规约本身不变）
            return Err(TexasAirError::SpecViolation(format!(
                "PotCollected event does not match fixed-seat collection projection: events={pot_events:?}, expected_seats_mask={expected_seats:#06x}, expected_pot_after={post_pot}, pre_round={:?}, seat_bets={seat_bets:?}",
                pre.round_state()
            )));
        }
    }
    Ok(BetCollectionPlan {
        active: true,
        pre_pot: pre.pot,
        seat_bets,
        collected_bets,
        post_pot,
    })
}

fn derive_round_advance(
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
    events: &[TexasPokerEvent],
) -> TexasAirResult<RoundAdvancePlan> {
    let rounds = events
        .iter()
        .filter_map(|event| match event {
            TexasPokerEvent::RoundAdvanced {
                table_id,
                from_round,
                to_round,
                pot,
                community_cards_count,
            } => Some((
                *table_id,
                *from_round,
                *to_round,
                *pot,
                *community_cards_count,
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [] = rounds.as_slice() else {
        let [(table_id, from_round, to_round, pot, community_cards_count)] = rounds.as_slice()
        else {
            return Err(TexasAirError::SpecViolation(
                "replay emitted multiple RoundAdvanced events".into(),
            ));
        };
        if *table_id != pre.id
            || *from_round != pre.round_state()
            || *to_round != post.round_state()
            || *pot != post.pot
            || *community_cards_count != post.community_cards.len() as u64
            || post.betting_round().is_some()
            || post.current_turn() != NO_CURRENT_TURN
        {
            return Err(TexasAirError::SpecViolation(
                "RoundAdvanced event does not match canonical post table".into(),
            ));
        }
        return Ok(RoundAdvancePlan {
            active: true,
            pre_round_state: *from_round,
            post_round_state: *to_round,
            pre_reveal_phase: pre.reveal_phase(),
            post_reveal_phase: post.reveal_phase(),
            pre_current_turn: pre.current_turn(),
            post_current_turn: NO_CURRENT_TURN,
            post_pot: *pot,
            community_cards_count: *community_cards_count,
        });
    };
    Ok(RoundAdvancePlan::inactive())
}

fn derive_settlement(
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
    collection: &BetCollectionPlan,
    method_kind: MethodKind,
    events: &[TexasPokerEvent],
) -> TexasAirResult<SettlementStagePlan> {
    let reset = derive_reset_projection(pre, post, events)?;
    let has_showdown = events
        .iter()
        .any(|event| matches!(event, TexasPokerEvent::SettlementPlanCommitted { .. }));
    let no_showdown = events
        .iter()
        .filter_map(|event| match event {
            TexasPokerEvent::HandEndedWithoutShowdown {
                table_id,
                winner_seat,
                pot,
                ..
            } => Some((*table_id, *winner_seat, *pot)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if has_showdown && !no_showdown.is_empty() {
        return Err(TexasAirError::SpecViolation(
            "dispatch emitted both showdown and no-showdown settlement".into(),
        ));
    }
    if has_showdown {
        let commitment_tables = events
            .iter()
            .filter_map(|event| match event {
                TexasPokerEvent::SettlementPlanCommitted { table_id, .. } => Some(*table_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        if commitment_tables.as_slice() != [pre.id] {
            return Err(TexasAirError::SpecViolation(
                "showdown settlement commitment table mismatch".into(),
            ));
        }
        require_canonical_reset(post, events, None)?;
        let binding = SettlementPlanBinding::from_events(events)?;
        return Ok(SettlementStagePlan {
            active: true,
            kind: SettlementKind::Showdown,
            native_plan_digest: binding.plan_digest,
            runout_count: binding.runout_count,
            gross_pot: binding.gross_pot,
            rake: binding.rake,
            total_awards: binding.total_awards,
            awards: binding.awards,
            pre_chip_pool: reset.pre_chip_pool,
            post_chip_pool: reset.post_chip_pool,
            addon_credits: reset.addon_credits,
            refunds: reset.refunds,
            addon_refunds: reset.addon_refunds,
            total_addon_credits: reset.total_addon_credits,
            total_refunds: reset.total_refunds,
            total_addon_refunds: reset.total_addon_refunds,
            post_stacks: reset.post_stacks,
            post_pending_addons: reset.post_pending_addons,
            post_occupied: reset.post_occupied,
            reset_applied: true,
        });
    }
    if no_showdown.is_empty() {
        if events.iter().any(|event| {
            matches!(
                event,
                TexasPokerEvent::WinnerAwarded { .. }
                    | TexasPokerEvent::HandSettled { .. }
                    | TexasPokerEvent::RakeCollected { .. }
            )
        }) {
            return Err(TexasAirError::SpecViolation(
                "settlement side events exist without a canonical settlement event".into(),
            ));
        }
        let tick_started_hand = method_kind == MethodKind::AdvanceDeadline
            && events
                .iter()
                .any(|event| matches!(event, TexasPokerEvent::HandStarted { .. }));
        let reset_only = matches!(
            method_kind,
            MethodKind::KickPlayer | MethodKind::AdvanceDeadline
        ) && !tick_started_hand
            && post.round_state() == ROUND_WAITING
            && post.betting_round().is_none()
            && post.current_turn() == NO_CURRENT_TURN
            && post.pot == 0;
        if !reset_only {
            return Ok(SettlementStagePlan::inactive());
        }
        require_canonical_reset(post, events, None)?;
        let native_plan_digest = hash_borsh(
            RESET_ONLY_DOMAIN,
            &(
                pre.id,
                post.hand_id,
                post.call_seq,
                reset.pre_chip_pool,
                reset.post_chip_pool,
                reset.addon_credits,
                reset.refunds,
                reset.addon_refunds,
                reset.post_stacks,
                reset.post_occupied,
            ),
        )?;
        return Ok(SettlementStagePlan {
            active: true,
            kind: SettlementKind::ResetOnly,
            native_plan_digest,
            runout_count: 0,
            gross_pot: 0,
            rake: 0,
            total_awards: 0,
            awards: [0; COMPOSITION_SEATS],
            pre_chip_pool: reset.pre_chip_pool,
            post_chip_pool: reset.post_chip_pool,
            addon_credits: reset.addon_credits,
            refunds: reset.refunds,
            addon_refunds: reset.addon_refunds,
            total_addon_credits: reset.total_addon_credits,
            total_refunds: reset.total_refunds,
            total_addon_refunds: reset.total_addon_refunds,
            post_stacks: reset.post_stacks,
            post_pending_addons: reset.post_pending_addons,
            post_occupied: reset.post_occupied,
            reset_applied: true,
        });
    }
    let [(table_id, winner_seat, award)] = no_showdown.as_slice() else {
        return Err(TexasAirError::SpecViolation(
            "replay emitted multiple HandEndedWithoutShowdown events".into(),
        ));
    };
    if *table_id != pre.id || !collection.active {
        return Err(TexasAirError::SpecViolation(
            "no-showdown settlement is missing its collection stage".into(),
        ));
    }
    require_canonical_reset(post, events, Some(RESET_REASON_LAST_PLAYER_STANDING))?;
    let winner_index = usize::from(*winner_seat);
    let pre_winner = pre.seats.get(winner_index).ok_or_else(|| {
        TexasAirError::SpecViolation("no-showdown winner seat is outside table".into())
    })?;
    let post_winner = post.seats.get(winner_index).ok_or_else(|| {
        TexasAirError::SpecViolation("post-reset winner seat is outside table".into())
    })?;
    let gross_pot = collection.post_pot;
    let rake = gross_pot.checked_sub(*award).ok_or_else(|| {
        TexasAirError::SpecViolation("no-showdown award exceeds gross pot".into())
    })?;
    let winner_after_credit = pre_winner
        .stack()
        .checked_add(*award)
        .and_then(|value| value.checked_add(reset.addon_credits[winner_index]))
        .ok_or_else(|| TexasAirError::SpecViolation("winner reset stack overflow".into()))?;
    if post_winner.is_occupied() {
        if post_winner.player() != pre_winner.player() || post_winner.stack() != winner_after_credit
        {
            return Err(TexasAirError::SpecViolation(
                "no-showdown award/addon credit does not match winner post stack".into(),
            ));
        }
    } else if !pre.seat_wants_leave(winner_index as u8)
        || reset.refunds[winner_index] != winner_after_credit
    {
        return Err(TexasAirError::SpecViolation(
            "removed no-showdown winner is not bound to its complete reset refund".into(),
        ));
    }
    let rake_events = events
        .iter()
        .filter_map(|event| match event {
            TexasPokerEvent::RakeCollected {
                table_id,
                pot_before,
                rake_amount,
                pot_after,
                ..
            } => Some((*table_id, *pot_before, *rake_amount, *pot_after)),
            _ => None,
        })
        .collect::<Vec<_>>();
    match rake_events.as_slice() {
        [] if rake == 0 => {}
        [(rake_table, pot_before, rake_amount, pot_after)]
            if *rake_table == pre.id
                && *pot_before == gross_pot
                && *rake_amount == rake
                && *pot_after == *award => {}
        _ => {
            return Err(TexasAirError::SpecViolation(
                "RakeCollected event does not match no-showdown settlement".into(),
            ));
        }
    }
    let mut awards = [0u64; COMPOSITION_SEATS];
    awards[winner_index] = *award;
    let native_plan_digest = hash_borsh(
        NO_SHOWDOWN_DOMAIN,
        &(
            pre.id,
            post.hand_id,
            post.call_seq,
            *winner_seat,
            gross_pot,
            rake,
            *award,
            awards,
        ),
    )?;
    Ok(SettlementStagePlan {
        active: true,
        kind: SettlementKind::WithoutShowdown,
        native_plan_digest,
        runout_count: 0,
        gross_pot,
        rake,
        total_awards: *award,
        awards,
        pre_chip_pool: reset.pre_chip_pool,
        post_chip_pool: reset.post_chip_pool,
        addon_credits: reset.addon_credits,
        refunds: reset.refunds,
        addon_refunds: reset.addon_refunds,
        total_addon_credits: reset.total_addon_credits,
        total_refunds: reset.total_refunds,
        total_addon_refunds: reset.total_addon_refunds,
        post_stacks: reset.post_stacks,
        post_pending_addons: reset.post_pending_addons,
        post_occupied: reset.post_occupied,
        reset_applied: true,
    })
}

struct ResetProjection {
    pre_chip_pool: u64,
    post_chip_pool: u64,
    addon_credits: [u64; COMPOSITION_SEATS],
    refunds: [u64; COMPOSITION_SEATS],
    addon_refunds: [u64; COMPOSITION_SEATS],
    total_addon_credits: u64,
    total_refunds: u64,
    total_addon_refunds: u64,
    post_stacks: [u64; COMPOSITION_SEATS],
    post_pending_addons: [u64; COMPOSITION_SEATS],
    post_occupied: [bool; COMPOSITION_SEATS],
}

fn derive_reset_projection(
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
    events: &[TexasPokerEvent],
) -> TexasAirResult<ResetProjection> {
    let mut addon_credits = [0u64; COMPOSITION_SEATS];
    let mut refunds = [0u64; COMPOSITION_SEATS];
    let mut kicked = [false; COMPOSITION_SEATS];
    for event in events {
        match event {
            TexasPokerEvent::AddonCredited {
                table_id,
                seat_index,
                amount,
                ..
            } => {
                let index = usize::from(*seat_index);
                if *table_id != pre.id
                    || index >= COMPOSITION_SEATS
                    || addon_credits[index] != 0
                    || *amount == 0
                {
                    return Err(TexasAirError::SpecViolation(
                        "AddonCredited event is not a unique fixed-seat reset credit".into(),
                    ));
                }
                addon_credits[index] = *amount;
            }
            TexasPokerEvent::PlayerRefund {
                table_id,
                seat_index,
                amount,
                ..
            } => {
                let index = usize::from(*seat_index);
                if *table_id != pre.id
                    || index >= COMPOSITION_SEATS
                    || refunds[index] != 0
                    || *amount == 0
                {
                    return Err(TexasAirError::SpecViolation(
                        "PlayerRefund event is not a unique fixed-seat refund".into(),
                    ));
                }
                refunds[index] = *amount;
            }
            TexasPokerEvent::PlayerKicked {
                table_id,
                seat_index,
                ..
            } => {
                let index = usize::from(*seat_index);
                if *table_id != pre.id || index >= COMPOSITION_SEATS || kicked[index] {
                    return Err(TexasAirError::SpecViolation(
                        "PlayerKicked event is not a unique fixed-seat kick".into(),
                    ));
                }
                kicked[index] = true;
            }
            _ => {}
        }
    }
    let mut addon_refunds = [0u64; COMPOSITION_SEATS];
    for index in 0..COMPOSITION_SEATS.min(pre.seats.len()) {
        if kicked[index] && addon_credits[index] == 0 {
            addon_refunds[index] = pre.seats[index].pending_addon();
        }
    }
    let sum = |values: &[u64; COMPOSITION_SEATS], name: &str| {
        values.iter().try_fold(0u64, |total, value| {
            total
                .checked_add(*value)
                .ok_or_else(|| TexasAirError::SpecViolation(format!("reset {name} sum overflow")))
        })
    };
    let total_addon_credits = sum(&addon_credits, "addon credit")?;
    let total_refunds = sum(&refunds, "refund")?;
    let total_addon_refunds = sum(&addon_refunds, "addon refund")?;
    let rake = events
        .iter()
        .filter_map(|event| match event {
            TexasPokerEvent::RakeCollected { rake_amount, .. } => Some(*rake_amount),
            _ => None,
        })
        .try_fold(0u64, |total, value| {
            total
                .checked_add(value)
                .ok_or_else(|| TexasAirError::SpecViolation("reset rake sum overflow".into()))
        })?;
    if post
        .chip_pool
        .checked_add(total_refunds)
        .and_then(|value| value.checked_add(rake))
        != Some(pre.chip_pool)
    {
        return Err(TexasAirError::SpecViolation(
            "reset TableVault conservation does not match refunds plus rake".into(),
        ));
    }
    let pending_total = |table: &TexasPokerTable| {
        table.seats.iter().try_fold(0u64, |total, seat| {
            total.checked_add(seat.pending_addon()).ok_or_else(|| {
                TexasAirError::SpecViolation("reset pending-addon sum overflow".into())
            })
        })
    };
    let pre_pending_total = pending_total(pre)?;
    let post_pending_total = pending_total(post)?;
    if post_pending_total
        .checked_add(total_addon_credits)
        .and_then(|value| value.checked_add(total_addon_refunds))
        != Some(pre_pending_total)
    {
        return Err(TexasAirError::SpecViolation(
            "reset addon-pool conservation does not match credits/refunds".into(),
        ));
    }
    let mut post_stacks = [0u64; COMPOSITION_SEATS];
    let mut post_pending_addons = [0u64; COMPOSITION_SEATS];
    let mut post_occupied = [false; COMPOSITION_SEATS];
    for (index, seat) in post.seats.iter().enumerate() {
        post_stacks[index] = seat.stack();
        post_pending_addons[index] = seat.pending_addon();
        post_occupied[index] = seat.is_occupied();
    }
    Ok(ResetProjection {
        pre_chip_pool: pre.chip_pool,
        post_chip_pool: post.chip_pool,
        addon_credits,
        refunds,
        addon_refunds,
        total_addon_credits,
        total_refunds,
        total_addon_refunds,
        post_stacks,
        post_pending_addons,
        post_occupied,
    })
}

fn require_canonical_reset(
    post: &TexasPokerTable,
    events: &[TexasPokerEvent],
    expected_reason: Option<u8>,
) -> TexasAirResult<()> {
    if post.round_state() != ROUND_WAITING
        || post.betting_round().is_some()
        || post.current_turn() != NO_CURRENT_TURN
        || post.pot != 0
    {
        return Err(TexasAirError::SpecViolation(
            "settlement did not reset table to WAITING".into(),
        ));
    }
    let resets = events
        .iter()
        .filter_map(|event| match event {
            TexasPokerEvent::HandReset {
                table_id,
                reason,
                round_state,
            } => Some((*table_id, *reason, *round_state)),
            _ => None,
        })
        .collect::<Vec<_>>();
    match resets.as_slice() {
        [] => {
            // Normal settle_hand/end_without_showdown call reset_for_next_hand
            // directly and do not emit a separate HandReset indexer event.
            // The complete canonical post image above is the reset authority.
        }
        [(table_id, reason, round_state)]
            if *table_id == post.id
                && *round_state == ROUND_WAITING
                && !expected_reason.is_some_and(|expected| expected != *reason) => {}
        _ => {
            return Err(TexasAirError::SpecViolation(
                "HandReset event does not match settlement output".into(),
            ));
        }
    }
    Ok(())
}

fn hash_borsh<T: BorshSerialize>(domain: &[u8], value: &T) -> TexasAirResult<[u8; 32]> {
    let encoded = borsh::to_vec(value).map_err(|error| {
        TexasAirError::SpecViolation(format!("composite plan serialization failed: {error}"))
    })?;
    Ok(hash_bytes(domain, &encoded))
}

fn hash_bytes(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= Blake2b maximum output");
    hasher.update(domain);
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("configured Blake2b output length is valid");
    digest
}

#[cfg(test)]
mod tests {
    use crate::test_support as seat_fixture;
    use poker_l1::object_model::ObjectID;
    use poker_l1::contracts::texas_poker::betting::BettingRound;
    use poker_l1::contracts::texas_poker::constants::{ROUND_FLOP, ROUND_PREFLOP};
    use poker_l1::contracts::texas_poker::events::TexasPokerEvent;
    use poker_l1::contracts::texas_poker::types::{RevealTokenState, SeatStatus};

    use super::*;

    fn table() -> TexasPokerTable {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0x11; 20], 7),
            [0x22; 20],
            2,
            50,
            100,
        );
        let seat_count = usize::from(table.max_players);
        for (index, seat) in table.seats.iter_mut().take(seat_count).enumerate() {
            seat_fixture::set_player(seat, [index as u8 + 1; 20]);
            seat_fixture::set_stack(seat, 1_000);
            seat.set_status(SeatStatus::Active);
        }
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 1)
            .unwrap();
        table.hand_id = 3;
        table.call_seq = 8;
        table
    }

    #[test]
    fn mid_round_action_has_only_seat_stage_active() {
        let pre = table();
        let mut post = pre.clone();
        post.set_seat_acted_this_round(0, true);
        post.set_betting_turn(1).unwrap();
        post.arm_betting_deadline(1).unwrap();
        post.call_seq += 1;
        let events = vec![TexasPokerEvent::PlayerChecked {
            table_id: pre.id,
            seat_index: 0,
            round_state: ROUND_PREFLOP,
        }];
        let plan =
            derive_composite_transition_plan(MethodKind::Check, &pre, &post, Some(0), &events)
                .unwrap();
        assert!(plan.seat_update.active);
        assert!(!plan.bet_collection.active);
        assert!(!plan.round_advance.active);
        assert!(!plan.settlement.active);
        plan.validate_composition().unwrap();
    }

    #[test]
    fn zero_bet_round_advance_still_has_collection_stage() {
        let mut pre = table();
        pre.enter_betting(ROUND_FLOP, BettingRound::new(100, 0), 0, 1)
            .unwrap();
        pre.set_seat_acted_this_round(1, true);
        let mut post = pre.clone();
        post.set_seat_acted_this_round(0, true);
        post.enter_revealing(
            poker_l1::contracts::texas_poker::constants::ROUND_TURN,
            RevealTokenState {
                purpose: poker_l1::contracts::texas_poker::types::RevealPurpose::Board,
                assignments: vec![],
            },
            1,
        )
        .unwrap();
        post.call_seq += 1;
        let events = vec![
            TexasPokerEvent::PlayerChecked {
                table_id: pre.id,
                seat_index: 0,
                round_state: ROUND_FLOP,
            },
            TexasPokerEvent::RoundAdvanced {
                table_id: pre.id,
                from_round: ROUND_FLOP,
                to_round: post.round_state(),
                pot: 0,
                community_cards_count: 0,
            },
        ];
        let plan =
            derive_composite_transition_plan(MethodKind::Check, &pre, &post, Some(0), &events)
                .unwrap();
        assert!(plan.bet_collection.active);
        assert_eq!(plan.bet_collection.collected_bets, 0);
        assert!(plan.round_advance.active);
        assert_eq!(
            plan.link(StageKind::BetCollection).output_digest,
            plan.link(StageKind::RoundAdvance).input_digest
        );
    }

    #[test]
    fn native_terminal_fold_splits_collection_and_settlement() {
        let mut pre = table();
        pre.pot = 50;
        seat_fixture::set_bet(&mut pre.seats[0], 25);
        seat_fixture::set_total_bet(&mut pre.seats[0], 25);
        seat_fixture::set_bet(&mut pre.seats[1], 25);
        seat_fixture::set_total_bet(&mut pre.seats[1], 25);
        *pre.active_betting_round_mut().unwrap() = BettingRound::new(100, 25);
        pre.chip_pool = pre
            .seats
            .iter()
            .map(|seat| seat.stack() + seat.bet())
            .sum::<u64>()
            + pre.pot;
        let mut post = pre.clone();
        let mut events = Vec::new();
        poker_l1::contracts::texas_poker::state_machine::apply_fold(&mut post, 0, &mut events)
            .unwrap();
        post.call_seq += 1;

        let plan =
            derive_composite_transition_plan(MethodKind::Fold, &pre, &post, Some(0), &events)
                .unwrap();
        assert!(plan.seat_update.active);
        assert!(plan.bet_collection.active);
        assert_eq!(plan.bet_collection.collected_bets, 50);
        assert!(!plan.round_advance.active);
        assert_eq!(plan.settlement.kind, SettlementKind::WithoutShowdown);
        assert_eq!(plan.settlement.gross_pot, 100);
        assert_eq!(plan.settlement.total_awards, 100);
        assert_eq!(plan.settlement.awards[1], 100);
        plan.validate_composition().unwrap();
    }


}
