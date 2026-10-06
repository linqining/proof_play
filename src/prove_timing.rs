//! Optional per-proof timing instrumentation.
//!
//! A process-wide recorder, enabled at runtime by setting the
//! `TEXAS_PROVE_TIMING` environment variable, records the wall-clock cost of
//! every individual `prove_method` / `verify_method` call. Composite tasks end
//! up with one legacy method record plus up to four component records, letting
//! a harness attribute the total prove time to its real contributors without
//! changing any production signature.
//!
//! The recorder is inert (the `enabled` check is a single relaxed atomic read
//! behind a `Once`) when the env var is absent, so library consumers pay no
//! measurable cost. A process-wide buffer is required because component proofs
//! execute on Rayon worker threads; [`take_drain`] collects all completed spans.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};

/// One timed prove/verify span.
#[derive(Debug, Clone)]
pub struct TimingRecord {
    /// Human-readable discriminator (e.g. `method:Check`, `stage:SeatUpdate`).
    pub label: String,
    /// What this span measured.
    pub kind: TimingKind,
    /// Elapsed wall-clock time.
    pub elapsed: Duration,
    /// Trace column count committed by this proof, if known.
    pub num_columns: Option<usize>,
}

/// Which side of the prover/verifier pair this record covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingKind {
    /// `prove_method` — Stwo prover side.
    Prove,
    /// `verify_method` / `verify_method_against` — Stwo verifier side.
    Verify,
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static INIT: Once = Once::new();
static RECORDS: Mutex<Vec<TimingRecord>> = Mutex::new(Vec::new());

fn ensure_init() {
    INIT.call_once(|| {
        let on = std::env::var_os("TEXAS_PROVE_TIMING").is_some();
        ENABLED.store(on, Ordering::Relaxed);
    });
}

/// Returns `true` only when the `TEXAS_PROVE_TIMING` env var is set.
#[must_use]
pub fn enabled() -> bool {
    ensure_init();
    ENABLED.load(Ordering::Relaxed)
}

/// Record one completed span if timing is enabled.
pub fn record(
    label: impl Into<String>,
    kind: TimingKind,
    start: Instant,
    num_columns: Option<usize>,
) {
    if !enabled() {
        return;
    }
    let record = TimingRecord {
        label: label.into(),
        kind,
        elapsed: start.elapsed(),
        num_columns,
    };
    RECORDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(record);
}

/// Drain and return all records accumulated across prover worker threads.
#[must_use]
pub fn take_drain() -> Vec<TimingRecord> {
    if !enabled() {
        return Vec::new();
    }
    let mut records = RECORDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::mem::take(&mut *records)
}

/// Build a human-readable label for a `prove_method` / verify span from its
/// public inputs: `method:<name>` for legacy proofs and
/// `stage:<StageKind>@<method>` for composite component proofs.
#[must_use]
pub fn method_label(public_inputs: &crate::public_inputs::TexasPublicInputs) -> String {
    let method = public_inputs.kind.method_name();
    match public_inputs.component.as_ref() {
        Some(component) => format!("stage:{:?}@{}", component.stage_kind, method),
        None => format!("method:{method}"),
    }
}
