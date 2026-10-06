//! Generic binding between a method AIR's original trace columns and a
//! verifier-supplied business row.
//!
//! Method-specific AIRs historically constrained only selected business
//! columns.  A prover could therefore combine honest state roots with forged
//! values in an unconstrained column.  [`BoundAir`] closes that generic gap by
//! wrapping any [`super::TexasAir`] and adding one equality constraint for
//! every value read from every original trace column.

use std::ops::Mul;

use stwo::core::Fraction;
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkEval, ORIGINAL_TRACE_IDX, Relation, RelationEntry,
};

use super::{AirStatement, TexasAir};

/// A method AIR augmented with a complete verifier-trusted original trace row.
#[derive(Debug, Clone)]
pub struct BoundAir<A> {
    air: A,
    expected_trace_row: Vec<M31>,
}

impl<A: TexasAir> BoundAir<A> {
    /// Construct a bound AIR.
    ///
    /// The caller must validate the row width with
    /// [`crate::public_inputs::TexasPublicInputs::require_expected_trace_row`]
    /// before calling this constructor.
    #[must_use]
    pub fn new(air: A, expected_trace_row: Vec<M31>) -> Self {
        debug_assert_eq!(expected_trace_row.len(), air.trace_num_columns());
        Self {
            air,
            expected_trace_row,
        }
    }
}

impl<A: TexasAir> FrameworkEval for BoundAir<A> {
    fn log_size(&self) -> u32 {
        self.air.log_size()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.air.max_constraint_log_degree_bound()
    }

    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        let mut bound = self.air.evaluate(BoundEval {
            inner: eval,
            expected_trace_row: &self.expected_trace_row,
            next_original_column: 0,
        });

        // A malformed AIR that declares more columns than it reads must not
        // leave the tail unconstrained. Consume and bind every remaining
        // original column. All current Texas traces replicate one trusted row
        // over the whole domain, so offset 0 is the complete statement.
        while bound.next_original_column < bound.expected_trace_row.len() {
            let _ = bound.next_trace_mask();
        }
        assert_eq!(
            bound.next_original_column,
            bound.expected_trace_row.len(),
            "Texas AIR read more original columns than it declared"
        );
        bound.inner
    }
}

impl<A: TexasAir> TexasAir for BoundAir<A> {
    fn statement(&self) -> AirStatement {
        self.air.statement()
    }

    fn trace_num_columns(&self) -> usize {
        self.air.trace_num_columns()
    }
}

/// Evaluator proxy that binds each original trace mask before forwarding the
/// method-specific constraints to Stwo.
struct BoundEval<'a, E: EvalAtRow> {
    inner: E,
    expected_trace_row: &'a [M31],
    next_original_column: usize,
}

impl<E: EvalAtRow> EvalAtRow for BoundEval<'_, E> {
    type F = E::F;
    type EF = E::EF;

    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::F; N] {
        let values = self.inner.next_interaction_mask(interaction, offsets);
        if interaction == ORIGINAL_TRACE_IDX {
            let expected = *self
                .expected_trace_row
                .get(self.next_original_column)
                .expect("Texas AIR read more original columns than it declared");
            self.next_original_column += 1;
            for value in &values {
                let expected_value: Self::F = expected.into();
                self.inner.add_constraint(value.clone() - expected_value);
            }
        }
        values
    }

    fn get_preprocessed_column(
        &mut self,
        column: stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId,
    ) -> Self::F {
        self.inner.get_preprocessed_column(column)
    }

    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: Mul<G, Output = Self::EF> + From<G>,
    {
        self.inner.add_constraint(constraint);
    }

    fn add_intermediate(&mut self, val: Self::F) -> Self::F {
        self.inner.add_intermediate(val)
    }

    fn add_extension_intermediate(&mut self, val: Self::EF) -> Self::EF {
        self.inner.add_extension_intermediate(val)
    }

    fn combine_ef(values: [Self::F; 4]) -> Self::EF {
        E::combine_ef(values)
    }

    fn add_to_relation<R: Relation<Self::F, Self::EF>>(
        &mut self,
        entry: RelationEntry<'_, Self::F, Self::EF, R>,
    ) {
        self.inner.add_to_relation(entry);
    }

    fn write_logup_frac(&mut self, fraction: Fraction<Self::EF, Self::EF>) {
        self.inner.write_logup_frac(fraction);
    }

    fn finalize_logup_batched(&mut self, batching: &Vec<usize>) {
        self.inner.finalize_logup_batched(batching);
    }

    fn finalize_logup(&mut self) {
        self.inner.finalize_logup();
    }

    fn finalize_logup_in_pairs(&mut self) {
        self.inner.finalize_logup_in_pairs();
    }
}
