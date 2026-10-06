//! Compile a standalone Cairo1 .cairo file to Executable JSON.
//! Usage: compile_cairo1 --src path/to/prog.cairo --out out.json

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use stwo_cairo_dev_utils::cairo1_compile::compile_cairo1_to_file;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    src: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value = None)]
    corelib: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    compile_cairo1_to_file(&args.src, args.corelib.as_deref(), &args.out)?;
    println!("wrote {}", args.out.display());
    Ok(())
}
