// Crate-root module shim for `combined.cairo`: mirrors `src/dual.cairo` so
// the combined envelope shares the exact `src/dual/` verifier sources (via
// the `dual -> ../dual` symlink) without duplicating them. Only the modules
// the envelope needs are declared.
mod bg_stark;
mod hand_batch_stark;
mod hand_verify;
