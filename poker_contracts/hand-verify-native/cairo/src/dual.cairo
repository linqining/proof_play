// Single-sourced from poker_contracts/src/dual: bg_stark / hand_batch_stark
// / hand_verify are relative symlinks to the contract tree (the contract
// copy is the only editable one). Only the modules hand_verify needs are
// declared here — keccak/secp/fr/hand_batch stay out so the deprecated
// corelib-internal-use warnings never enter the executable.
mod bg_stark;
mod hand_batch_stark;
mod hand_verify;
