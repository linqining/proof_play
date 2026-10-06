//! Compilation of standalone Cairo1 `.cairo` sources into [`Executable`] JSON.
//!
//! Lib counterpart of the `compile_cairo1` bin, so that wrapping tools can reuse the exact
//! compiler configuration the standalone Executable runner requires: gas must be disabled
//! (`with_cfg(gas=disabled)` + `skip_auto_withdraw_gas()`). With gas enabled, corelib code such
//! as `poseidon_hash_span` compiles in gas withdrawal / `BuiltinCosts` logic that the standalone
//! runner never wires up, and control flow falls off the end of the bytecode (the "jump anomaly").

use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use cairo_lang_compiler::db::RootDatabase;
use cairo_lang_compiler::diagnostics::DiagnosticsReporter;
use cairo_lang_compiler::ensure_diagnostics;
use cairo_lang_compiler::project::setup_project;
use cairo_lang_executable::compile::{ExecutableConfig, compile_executable};
use cairo_lang_executable::executable::Executable;
use cairo_lang_filesystem::cfg::{Cfg, CfgSet};

/// Builds the compiler database for a standalone (gas-disabled) Cairo1 program.
///
/// `corelib` points at a corelib `src`-rooted crate directory (e.g. `<cairo repo>/corelib`).
/// When `None`, the compiler's `detect_corelib()` fallback is used.
pub fn build_standalone_db(corelib: Option<&Path>) -> Result<RootDatabase> {
    // Keep the compiler single-threaded; it is faster at this scale and avoids oversubscribing
    // rayon when invoked from a parallel harness.
    unsafe { std::env::set_var("RAYON_NUM_THREADS", "1") };
    let mut builder = RootDatabase::builder();
    builder
        .skip_auto_withdraw_gas()
        .with_cfg(CfgSet::from_iter([Cfg::kv("gas", "disabled")]))
        .with_default_plugin_suite(cairo_lang_executable_plugin::executable_plugin_suite());
    match corelib {
        Some(corelib) => {
            let mut db = builder.build()?;
            cairo_lang_filesystem::db::init_dev_corelib(&mut db, corelib.to_path_buf());
            Ok(db)
        }
        None => {
            builder.detect_corelib();
            Ok(builder.build()?)
        }
    }
}

/// Compiles the standalone Cairo1 program at `src` into an [`Executable`].
pub fn compile_cairo1_executable(src: &Path, corelib: Option<&Path>) -> Result<Executable> {
    let mut db = build_standalone_db(corelib)?;
    let _ = setup_project(&mut db, src)?;
    ensure_diagnostics(&db, &mut DiagnosticsReporter::default())?;
    let result = compile_executable(
        &mut db,
        src,
        None,
        DiagnosticsReporter::default(),
        ExecutableConfig::default(),
    )?;
    Ok(Executable::new(result.compiled_function))
}

/// Compiles the standalone Cairo1 program at `src` and serializes the [`Executable`] to `out`.
pub fn compile_cairo1_to_file(src: &Path, corelib: Option<&Path>, out: &Path) -> Result<()> {
    let executable = compile_cairo1_executable(src, corelib)?;
    let mut f = File::create(out)?;
    serde_json::to_writer(&mut f, &executable)?;
    f.flush()?;
    Ok(())
}
