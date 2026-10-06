//! Independent STARK AIR wrappers for the four composable transition stages.

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use super::bet_collection::{BetCollectionPlan, BetCollectionRow};
use super::round_advance::{RoundAdvancePlan, RoundAdvanceRow};
use super::seat_update::{SeatUpdatePlan, SeatUpdateRow};
use super::settlement::{SettlementRow, SettlementStagePlan};
use super::{ComponentStatement, StageKind, StageLink};
use crate::airs::{AirStatement, TexasAir};
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::public_inputs::TexasPublicInputs;

pub(crate) trait ComponentTexasAir: TexasAir {
    fn canonical_row(&self) -> Vec<M31>;
}

#[derive(Debug, Clone)]
struct ComponentScope {
    method_kind: MethodKind,
    pre_state_root: [M31; 4],
    post_state_root: [M31; 4],
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
    pre_version: u64,
    post_version: u64,
}

impl ComponentScope {
    fn statement(&self, link: &StageLink) -> AirStatement {
        AirStatement {
            kind: self.method_kind,
            pre_state_root: self.pre_state_root,
            post_state_root: self.post_state_root,
            table_id: self.table_id,
            hand_id: self.hand_id,
            call_seq: self.call_seq,
            pre_version: self.pre_version,
            post_version: self.post_version,
            component: Some(ComponentStatement::from_link(link)),
        }
    }
}

macro_rules! define_component_air {
    (
        $name:ident,
        $plan_ty:ty,
        $row_ty:ty,
        $kind:expr,
        $columns:path,
        $evaluate:path,
        $select:ident
    ) => {
        #[derive(Debug, Clone)]
        pub(crate) struct $name {
            log_size: u32,
            scope: ComponentScope,
            plan: $plan_ty,
            link: StageLink,
        }

        impl $name {
            pub(crate) fn new(
                log_size: u32,
                method_kind: MethodKind,
                public_inputs: &TexasPublicInputs,
                plan: $plan_ty,
                link: StageLink,
            ) -> Self {
                Self {
                    log_size,
                    scope: ComponentScope {
                        method_kind,
                        pre_state_root: crate::state_root::state_root_to_air_limbs(
                            public_inputs.pre_state_root,
                        ),
                        post_state_root: crate::state_root::state_root_to_air_limbs(
                            public_inputs.post_state_root,
                        ),
                        table_id: public_inputs.table_id,
                        hand_id: public_inputs.hand_id,
                        call_seq: public_inputs.call_seq,
                        pre_version: public_inputs.pre_version,
                        post_version: public_inputs.post_version,
                    },
                    plan,
                    link,
                }
            }

            pub(crate) fn row(&self) -> Vec<M31> {
                <$row_ty>::new(&self.plan, &self.link).to_vec()
            }
        }

        impl FrameworkEval for $name {
            fn log_size(&self) -> u32 {
                self.log_size
            }

            fn max_constraint_log_degree_bound(&self) -> u32 {
                self.log_size + 1
            }

            fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
                $evaluate(&mut eval, &self.plan, &self.link);
                eval
            }
        }

        impl TexasAir for $name {
            fn statement(&self) -> AirStatement {
                self.scope.statement(&self.link)
            }

            fn trace_num_columns(&self) -> usize {
                $columns
            }

            fn validate_public_inputs(
                &self,
                public_inputs: &TexasPublicInputs,
            ) -> TexasAirResult<()> {
                let canonical = super::plan::derive_composite_transition_plan_from_public_inputs(
                    public_inputs,
                )?;
                if self.plan != canonical.$select
                    || self.link != *canonical.link($kind)
                    || public_inputs.component
                        != Some(ComponentStatement::from_link(canonical.link($kind)))
                {
                    return Err(TexasAirError::SpecViolation(format!(
                        "{} component AIR does not match canonical replay",
                        stringify!($name)
                    )));
                }
                let expected = <$row_ty>::new(&self.plan, &self.link).to_vec();
                crate::airs::validation::validate_row(public_inputs, &expected, stringify!($name))
            }
        }

        impl ComponentTexasAir for $name {
            fn canonical_row(&self) -> Vec<M31> {
                self.row()
            }
        }
    };
}

define_component_air!(
    SeatUpdateAir,
    SeatUpdatePlan,
    SeatUpdateRow,
    StageKind::SeatUpdate,
    super::seat_update::NUM_COLUMNS,
    super::seat_update::evaluate,
    seat_update
);
define_component_air!(
    BetCollectionAir,
    BetCollectionPlan,
    BetCollectionRow,
    StageKind::BetCollection,
    super::bet_collection::NUM_COLUMNS,
    super::bet_collection::evaluate,
    bet_collection
);
define_component_air!(
    RoundAdvanceAir,
    RoundAdvancePlan,
    RoundAdvanceRow,
    StageKind::RoundAdvance,
    super::round_advance::NUM_COLUMNS,
    super::round_advance::evaluate,
    round_advance
);
define_component_air!(
    SettlementAir,
    SettlementStagePlan,
    SettlementRow,
    StageKind::Settlement,
    super::settlement::NUM_COLUMNS,
    super::settlement::evaluate,
    settlement
);
