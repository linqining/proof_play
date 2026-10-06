//! Trace-run a Cairo1 Executable step by step to debug control flow.
//! Usage: trace_exec --program path/to/executable.json
use std::fs::File;

use anyhow::Result;
use cairo_lang_executable::executable::{EntryPointKind, Executable};
use cairo_lang_runner::{Arg, CairoHintProcessor, build_hints_dict};
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use clap::Parser;
use serde_json::from_reader;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    program: String,
    /// max steps to trace
    #[arg(long, default_value = "400")]
    max_steps: usize,
    /// start printing after this many steps
    #[arg(long, default_value = "0")]
    from_step: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let executable: Executable = from_reader(File::open(&args.program)?)?;
    let data: Vec<MaybeRelocatable> =
        executable.program.bytecode.iter().map(|f| cairo_vm::Felt252::from(f.clone())).map(MaybeRelocatable::from).collect();
    let (hints, string_to_hint) = build_hints_dict(&executable.program.hints);
    let entrypoint = executable
        .entrypoints
        .iter()
        .find(|e| matches!(e.kind, EntryPointKind::Standalone))
        .expect("entrypoint");
    let program = Program::new_for_proof(
        entrypoint.builtins.clone(),
        data,
        entrypoint.offset,
        entrypoint.offset + 4,
        hints,
        Default::default(),
        Default::default(),
        vec![],
        None,
    )?;
    let hint_processor = CairoHintProcessor {
        runner: None,
        user_args: vec![vec![Arg::Array(vec![])]],
        string_to_hint,
        starknet_state: Default::default(),
        run_resources: Default::default(),
        syscalls_used_resources: Default::default(),
        no_temporary_segments: false,
        markers: Default::default(),
        panic_traceback: Default::default(),
    };
    let mut runner = CairoRunner::new(
        &program,
        LayoutName::all_cairo_stwo,
        Default::default(),
        true,
        true,
        true,
    )?;
    let mut exec_scopes = ExecutionScopes::new();
    let _ = &mut exec_scopes;
    let mut hint_processor = hint_processor;
    let end = runner.initialize(true)?;
    println!("initial pc={:?} ap={:?} fp={:?} end={:?}", runner.vm.get_pc(), runner.vm.get_ap(), runner.vm.get_fp(), end);
    let references = program.shared_program_data.reference_manager.clone();
    let mut hint_data = runner.get_hint_data(&references, &mut hint_processor)?;
    let mut hint_ranges = program.shared_program_data.hints_collection.hints_ranges.clone();
    for i in 0..args.max_steps {
        // decode current instruction
        let pc = runner.vm.get_pc();
        let encoded: u128 = runner
            .vm
            .get_integer(pc)
            .ok()
            .map(|v| u128::from_be_bytes(v.to_bytes_be()[16..32].try_into().unwrap()))
            .unwrap_or(0);
        if i + 1 >= args.from_step {
            match cairo_vm::vm::decoding::decoder::decode_instruction(encoded) {
                Ok(inst) => println!(
                    "step {} pc={} ap={} fp={} inst={}",
                    i,
                    pc,
                    runner.vm.get_ap(),
                    runner.vm.get_fp(),
                    inst.off0
                ),
                Err(e) => println!("step {} pc={} decode err {:?}", i, pc, e),
            }
        }
        match runner.vm.step(
            &mut hint_processor,
            &mut runner.exec_scopes,
            &mut hint_data,
            &mut hint_ranges,
        ) {
            Ok(()) => {}
            Err(e) => {
                println!("step {} error: {:?} at pc={:?}", i, e, runner.vm.get_pc());
                break;
            }
        }
    }
    println!("final pc={:?} ap={:?}", runner.vm.get_pc(), runner.vm.get_ap());
    let mem = runner.get_relocatable_memory();
    for (si, seg) in mem.iter().enumerate().take(4) {
        println!("--- segment {} (len {})", si, seg.len());
        for (i, cell) in seg.iter().enumerate().take(if si == 1 { 70 } else { 8 }) {
            if let Some(v) = cell {
                println!("  {}:{} = {:?}", si, i, v);
            }
        }
    }
    Ok(())
}
