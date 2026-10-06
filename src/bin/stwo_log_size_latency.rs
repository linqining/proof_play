//! Compare end-to-end Stwo proving latency for small trace domains.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p poker_texas_air --release --bin stwo_log_size_latency
//! ```
//!
//! Each log size is measured in its own process. `cold_ms` therefore includes
//! process-local Rayon initialization and the first invocation of the prover;
//! `warm_*` is measured from subsequent invocations in that same process.

use std::env;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use bincode::Options;
use poker_l1::object_model::ObjectID;
use poker_l1::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};
use poker_texas_air::airs::lifecycle::create_table::{
    CreateTableAir, CreateTableInput, CreateTableRow,
};
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::prover::prove_method;
use poker_texas_air::public_inputs::TexasPublicInputs;
use poker_texas_air::state_root::{compute_state_root, state_root_to_air_limbs};
use poker_texas_air::trace_gen::MethodTrace;
use poker_texas_air::verifier::verify_method_against;

const WARM_SAMPLES: usize = 9;

type Fixture = (MethodTrace, CreateTableAir, TexasPublicInputs);

fn main() -> ExitCode {
    let args = env::args().collect::<Vec<_>>();
    if let Some(log_size) = args
        .windows(2)
        .find(|pair| pair[0] == "--single-log-size")
        .and_then(|pair| pair[1].parse::<u32>().ok())
    {
        return run_single(log_size);
    }

    println!(
        "log_size,trace_rows,cold_ms,warm_median_ms,warm_mean_ms,verify_ms,proof_bytes,status"
    );
    for log_size in 5..=10 {
        let output = Command::new(env::current_exe().expect("current executable"))
            .arg("--single-log-size")
            .arg(log_size.to_string())
            .output()
            .expect("spawn benchmark child");
        print!("{}", String::from_utf8_lossy(&output.stdout));
        if !output.status.success() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
    }
    ExitCode::SUCCESS
}

fn run_single(log_size: u32) -> ExitCode {
    let result = catch_unwind(AssertUnwindSafe(|| measure(log_size)));
    match result {
        Ok(Ok(row)) => {
            println!("{row}");
            ExitCode::SUCCESS
        }
        Ok(Err(error)) => {
            println!(
                "{log_size},{},,,,error:{}",
                1usize << log_size,
                error.replace(',', ";")
            );
            ExitCode::SUCCESS
        }
        Err(_) => {
            println!("{log_size},{},,,,panic", 1usize << log_size);
            ExitCode::SUCCESS
        }
    }
}

fn measure(log_size: u32) -> Result<String, String> {
    let fixture = fixture(log_size)?;

    let cold_start = Instant::now();
    let cold_proof = prove(&fixture)?;
    let cold = cold_start.elapsed();

    let mut warm = Vec::with_capacity(WARM_SAMPLES);
    let mut final_proof = cold_proof;
    for _ in 0..WARM_SAMPLES {
        let start = Instant::now();
        final_proof = prove(&fixture)?;
        warm.push(start.elapsed());
    }

    let verify_start = Instant::now();
    verify_method_against(final_proof.clone(), fixture.1.clone(), &fixture.2)
        .map_err(|error| format!("verification failed: {error}"))?;
    let verify = verify_start.elapsed();
    let proof_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&final_proof.stark_proof)
        .map_err(|error| format!("proof serialization failed: {error}"))?
        .len();

    warm.sort_unstable();
    let median = warm[warm.len() / 2];
    let mean = warm.iter().sum::<Duration>() / u32::try_from(warm.len()).unwrap();
    Ok(format!(
        "{log_size},{},{:.3},{:.3},{:.3},{:.3},{proof_bytes},ok",
        1usize << log_size,
        millis(cold),
        millis(median),
        millis(mean),
        millis(verify),
    ))
}

fn prove(
    fixture: &Fixture,
) -> Result<poker_texas_air::prover::MethodProof<CreateTableAir>, String> {
    prove_method(
        &fixture.0,
        fixture.1.clone(),
        CreateTableAir::num_columns(),
        fixture.2.clone(),
    )
    .map_err(|error| error.to_string())
}

fn fixture(log_size: u32) -> Result<Fixture, String> {
    let pre_table = TexasPokerTable::new(
        ObjectID::new([0xAA; 20], 42),
        EMPTY_PLAYER,
        2,
        1,
        1,
    );
    let mut post_table = TexasPokerTable::new(
        ObjectID::new([0xAA; 20], 42),
        [0xCC; 20],
        6,
        10,
        20,
    );
    post_table.call_seq = 1;

    // Build the active statement row directly from the canonical row ABI,
    // exactly as the orchestrator's create_table path does.
    let input = CreateTableInput {
        max_players: 6,
        small_blind: 10,
        big_blind: 20,
        rit_mode: 0, // RIT_MODE_DISABLED
    };
    let pre_root = compute_state_root(&pre_table)
        .map_err(|error| format!("pre state root failed: {error}"))?;
    let post_root = compute_state_root(&post_table)
        .map_err(|error| format!("post state root failed: {error}"))?;
    let pre_limbs = state_root_to_air_limbs(pre_root);
    let post_limbs = state_root_to_air_limbs(post_root);
    let pre_version = u64::from(pre_table.call_seq);
    let post_version = u64::from(post_table.call_seq);

    let row = CreateTableRow::active(
        &input,
        pre_limbs,
        post_limbs,
        42,
        0,
        1,
        pre_version,
        post_version,
    )
    .to_vec();
    let mut trace = MethodTrace::new(log_size, CreateTableAir::num_columns());
    trace
        .write_active_with_padding(&row, &row)
        .map_err(|error| format!("trace construction failed: {error}"))?;
    let air = CreateTableAir::new(
        log_size,
        input,
        pre_limbs,
        post_limbs,
        42,
        0,
        1,
        pre_version,
        post_version,
    );
    let mut public_inputs =
        TexasPublicInputs::from_tables(&pre_table, &post_table, MethodKind::CreateTable, 42, 0, 1)
            .map_err(|error| format!("public-input construction failed: {error}"))?;
    public_inputs
        .bind_expected_trace_row(&row)
        .map_err(|error| format!("trusted-row binding failed: {error}"))?;
    Ok((trace, air, public_inputs))
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
