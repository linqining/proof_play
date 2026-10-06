//! Lookup-backed Blake2b compression scheduler.
//!
//! The Blake2b `G` relation is proved by [`crate::blake2b_lookup_g`].  This
//! component proves the part which must not be left to the host: fixed sigma
//! wiring, message selection, chaining-state transitions, and the final
//! `h[i] = initial_h[i] XOR v[i] XOR v[i + 8]` digest relation.  The public scope is
//! reconstructed by the verifier, so a scheduler proof cannot be detached
//! from the G-call proof or from the message/digest statement.

#![allow(missing_docs)]

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::{VerificationError, verify};
use stwo::prover::backend::Column;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, N_LANES};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::{SimdBackend, m31::PackedBaseField};
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::{ComponentProver, ProvingError, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, ORIGINAL_TRACE_IDX,
    Relation, TraceLocationAllocator, relation,
};

use crate::blake2b_lookup_g::{
    ArchivedBlake2bGProof, Blake2bGCall, prove_blake2b_g, verify_blake2b_g,
};
use crate::blake2b_smt_witness::{
    BLAKE2B_256_PARAMETER_WORD, BLAKE2B_IV, BLAKE2B_SIGMA, Blake2bSmtFixedValuePathWitness,
    Blake2bSmtSingleBlock, SMT_FIXED_VALUE_OPENING_COMPRESSIONS,
    SMT_SINGLE_BLOCK_INPUT_BYTES,
};
use crate::error::{TexasAirError, TexasAirResult};

const MIN_LOG_SIZE: u32 = 4;
const WORD_BYTES: usize = 8;
const STATE_WORDS: usize = 16;
const MESSAGE_WORDS: usize = 16;
const G_ROWS: usize = 12 * 8;
const INPUT_WORDS: usize = 6;
const G_OUTPUT_WORDS: usize = 4;
/// Blake2b's internal chaining value has eight 64-bit words.  The L1 sparse
/// Merkle tree truncates it to the first four words (Blake2b-256), but a
/// multi-block hash must authenticate all eight words: the second half feeds
/// the next compression's initial state.
const HASH_WORDS: usize = 8;
/// The externally visible Blake2b-256 output width.
const DIGEST_WORDS: usize = 4;
const SELECTOR_GROUPS: usize = 6;
const XOR_LOOKUPS: usize = 2 * HASH_WORDS * WORD_BYTES;
const INTERACTION_COLUMNS: usize = XOR_LOOKUPS.div_ceil(2);
const XOR_LOG_SIZE: u32 = 16;
const XOR_ROWS: usize = 1 << XOR_LOG_SIZE;

const STATE_BASE: usize = 0;
const DIGEST_MID_BASE: usize = STATE_BASE + STATE_WORDS * WORD_BYTES;
const ACTIVE_COLUMN: usize = DIGEST_MID_BASE + HASH_WORDS * WORD_BYTES;
// Each row materializes the complete state after its G call.  This both
// supplies the final compression state to the digest lookups and binds the
// next active row to the preceding G output.
const NEXT_STATE_BASE: usize = ACTIVE_COLUMN + 1;
const NEXT_ACTIVE_COLUMN: usize = NEXT_STATE_BASE + STATE_WORDS * WORD_BYTES;
const NUM_TRACE_COLUMNS: usize = NEXT_ACTIVE_COLUMN + 1;

const SCOPE_ACTIVE: usize = 0;
const SCOPE_FIRST: usize = 1;
const SCOPE_LAST: usize = 2;
const SCOPE_ADVANCE: usize = 3;
const SCOPE_INITIAL_BASE: usize = 4;
const SCOPE_MESSAGE_BASE: usize = SCOPE_INITIAL_BASE + STATE_WORDS * WORD_BYTES;
const SCOPE_DIGEST_BASE: usize = SCOPE_MESSAGE_BASE + MESSAGE_WORDS * WORD_BYTES;
const SCOPE_HASH_BASE: usize = SCOPE_DIGEST_BASE + DIGEST_WORDS * WORD_BYTES;
/// One verifier-derived bit per block boundary.  When set on a final G row,
/// the eight following words are the next compression's chaining value.
const SCOPE_CHAIN_TO_NEXT: usize = SCOPE_HASH_BASE + HASH_WORDS * WORD_BYTES;
const SCOPE_NEXT_HASH_BASE: usize = SCOPE_CHAIN_TO_NEXT + 1;
const SCOPE_SELECTOR_BASE: usize = SCOPE_NEXT_HASH_BASE + HASH_WORDS * WORD_BYTES;
const SCOPE_CALL_BASE: usize = SCOPE_SELECTOR_BASE + SELECTOR_GROUPS * STATE_WORDS;
const SCOPE_COLUMNS: usize = SCOPE_CALL_BASE + (INPUT_WORDS + G_OUTPUT_WORDS) * WORD_BYTES;

relation!(Blake2bCompressionByteXor, 3);

#[derive(Clone)]
struct SchedulerAir {
    log_size: u32,
    xor: Blake2bCompressionByteXor,
}

#[derive(Clone)]
struct XorTableAir {
    elements: Blake2bCompressionByteXor,
}

/// A self-contained lookup-backed proof for one or more fixed-size Blake2b
/// compression blocks.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedBlake2bLookupCompressionProof {
    /// Zero-padded 128-byte messages, one per compression block.
    pub messages: Vec<[u8; 128]>,
    /// Public 32-byte digest expected from each block.
    pub digests: Vec<[u8; 32]>,
    /// Full eight-word initial `v` state for each compression block.  The
    /// fixed-SMT wrappers use the standard Blake2b-256 initial state; the
    /// multi-block wrapper uses the preceding block's full chaining value.
    pub initial_states: Vec<[u64; STATE_WORDS]>,
    /// The complete `h[0..8]` result of every compression.  These values are
    /// AIR-constrained through the final XOR relation; only their first four
    /// words are exposed by `digests`.
    pub hash_states: Vec<[u64; HASH_WORDS]>,
    /// Whether this block's full chaining value must equal the next block's
    /// initial `h` words.  This is verifier-reconstructed scope, not a host
    /// success flag.
    pub chain_to_next: Vec<bool>,
    /// The exact six-input/four-output G calls used by both AIR components.
    pub calls: Vec<Blake2bGCall>,
    /// Serialized lookup-backed G proof.
    pub g_proof_bytes: Vec<u8>,
    /// Serialized scheduler proof.
    pub schedule_proof_bytes: Vec<u8>,
}

/// A complete lookup-backed Blake2b-256 hash of an arbitrary-length byte
/// string.  Its compression proof binds every padded block, counter/final flag
/// state, and all eight chaining words.  Verification never invokes native
/// Blake2b.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedBlake2bLookupHashProof {
    /// Exact unpadded message bytes.  They are public proof statement data.
    pub message: Vec<u8>,
    /// Blake2b-256 digest (the first 32 bytes of the final chaining value).
    pub digest: [u8; 32],
    /// Shared G, scheduler, and byte-XOR proofs for all message blocks.
    pub compression: ArchivedBlake2bLookupCompressionProof,
}

/// One public standard Blake2b-256 statement in a shared hash batch.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Blake2bLookupHashStatement {
    /// Exact unpadded message bytes.
    pub message: Vec<u8>,
    /// Standard 32-byte Blake2b-256 digest of `message`.
    pub digest: [u8; 32],
}

/// Several independent standard Blake2b-256 hashes proved through one shared
/// G relation, scheduler, and byte-XOR table.  Each statement's final block
/// has `chain_to_next = false`, so no chaining value may cross from one public
/// message into the next.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedBlake2bLookupHashesProof {
    pub statements: Vec<Blake2bLookupHashStatement>,
    pub compression: ArchivedBlake2bLookupCompressionProof,
}

/// Fixed-value SMT opening authenticated by 257 Blake2b compression blocks.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedBlake2bLookupSmtFixedValuePathProof {
    pub witness: Blake2bSmtFixedValuePathWitness,
    pub compression: ArchivedBlake2bLookupCompressionProof,
}

/// A shared lookup-backed compression proof for several fixed-value SMT
/// openings.
///
/// Each opening still has its own key, value, siblings and root endpoint, but
/// all 257-compression paths share one `G` proof and one scheduler proof.  It
/// is the intended form for a Texas transition's pre/post state-object
/// openings, avoiding two independent lookup-table commitments.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedBlake2bLookupSmtFixedValuePathsProof {
    pub paths: Vec<Blake2bSmtFixedValuePathWitness>,
    pub compression: ArchivedBlake2bLookupCompressionProof,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(64 * 1024 * 1024)
}

fn word_base(word: usize) -> usize {
    STATE_BASE + word * WORD_BYTES
}

fn next_word_base(word: usize) -> usize {
    NEXT_STATE_BASE + word * WORD_BYTES
}

fn fixed_smt_initial_v() -> [u64; STATE_WORDS] {
    let mut h = BLAKE2B_IV;
    h[0] ^= BLAKE2B_256_PARAMETER_WORD;
    let mut v = [0u64; STATE_WORDS];
    v[..8].copy_from_slice(&h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= SMT_SINGLE_BLOCK_INPUT_BYTES as u64;
    v[14] = !v[14];
    v
}

fn standard_initial_h() -> [u64; HASH_WORDS] {
    let mut h = BLAKE2B_IV;
    h[0] ^= BLAKE2B_256_PARAMETER_WORD;
    h
}

/// Construct the complete Blake2b `v` input for one canonical hash block.
///
/// The implementation supports byte lengths below 2^64, which is far above
/// the fixed-width Texas state-image ABI.  `counter` is the cumulative number
/// of message bytes consumed by this block; `final_block` sets Blake2b's f0.
fn hash_initial_v(h: [u64; HASH_WORDS], counter: u64, final_block: bool) -> [u64; STATE_WORDS] {
    let mut v = [0u64; STATE_WORDS];
    v[..HASH_WORDS].copy_from_slice(&h);
    v[HASH_WORDS..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= counter;
    if final_block {
        v[14] = !v[14];
    }
    v
}

fn full_hash_state(
    initial: &[u64; STATE_WORDS],
    final_v: &[u64; STATE_WORDS],
) -> [u64; HASH_WORDS] {
    std::array::from_fn(|index| initial[index] ^ final_v[index] ^ final_v[index + HASH_WORDS])
}

fn digest_from_hash_state(hash_state: &[u64; HASH_WORDS]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    for (index, word) in hash_state[..DIGEST_WORDS].iter().copied().enumerate() {
        digest[index * WORD_BYTES..(index + 1) * WORD_BYTES].copy_from_slice(&word.to_le_bytes());
    }
    digest
}

fn u64_bytes(value: u64) -> [M31; WORD_BYTES] {
    value.to_le_bytes().map(u32::from).map(M31::from)
}

fn add_with_carries(a: u64, b: u64, extra: u64) -> u64 {
    a.wrapping_add(b).wrapping_add(extra)
}

fn g_outputs(a: u64, b: u64, c: u64, d: u64, x: u64, y: u64) -> [u64; 4] {
    let a1 = add_with_carries(a, b, x);
    let d1 = (d ^ a1).rotate_right(32);
    let c1 = add_with_carries(c, d1, 0);
    let b1 = (b ^ c1).rotate_right(24);
    let a2 = add_with_carries(a1, b1, y);
    let d2 = (d1 ^ a2).rotate_right(16);
    let c2 = add_with_carries(c1, d2, 0);
    let b2 = (b1 ^ c2).rotate_left(1);
    [a2, b2, c2, d2]
}

fn schedule(row: usize) -> ([usize; 4], usize, usize) {
    let round = row / 8;
    let g = row % 8;
    let sigma = BLAKE2B_SIGMA[round];
    let lanes = match g {
        0 => [0, 4, 8, 12],
        1 => [1, 5, 9, 13],
        2 => [2, 6, 10, 14],
        3 => [3, 7, 11, 15],
        4 => [0, 5, 10, 15],
        5 => [1, 6, 11, 12],
        6 => [2, 7, 8, 13],
        _ => [3, 4, 9, 14],
    };
    (lanes, sigma[g * 2], sigma[g * 2 + 1])
}

fn message_words(message: &[u8; 128]) -> [u64; MESSAGE_WORDS] {
    std::array::from_fn(|index| {
        u64::from_le_bytes(
            message[index * WORD_BYTES..(index + 1) * WORD_BYTES]
                .try_into()
                .unwrap(),
        )
    })
}

fn compression_calls(
    messages: &[[u8; 128]],
    initial_states: &[[u64; STATE_WORDS]],
) -> TexasAirResult<(Vec<Blake2bGCall>, Vec<[u64; HASH_WORDS]>)> {
    if messages.is_empty() || messages.len() != initial_states.len() {
        return Err(TexasAirError::SpecViolation(
            "Blake2b compression initial-state count mismatch".into(),
        ));
    }
    let mut calls = Vec::with_capacity(messages.len() * G_ROWS);
    let mut hash_states = Vec::with_capacity(messages.len());
    for (message, initial) in messages.iter().zip(initial_states) {
        let words = message_words(message);
        let mut state = *initial;
        for row in 0..G_ROWS {
            let (lanes, x_index, y_index) = schedule(row);
            let [a, b, c, d] = lanes;
            let output = g_outputs(
                state[a],
                state[b],
                state[c],
                state[d],
                words[x_index],
                words[y_index],
            );
            calls.push(Blake2bGCall {
                input: [
                    state[a],
                    state[b],
                    state[c],
                    state[d],
                    words[x_index],
                    words[y_index],
                ],
                output,
            });
            state[a] = output[0];
            state[b] = output[1];
            state[c] = output[2];
            state[d] = output[3];
        }
        hash_states.push(full_hash_state(initial, &state));
    }
    Ok((calls, hash_states))
}

/// Validate the public, full-width Blake2b chaining ABI before spending time
/// on proof verification.  This is defense in depth only: `SchedulerAir`
/// repeats the equality as an AIR constraint on every chained block boundary.
fn validate_chaining_links(
    initial_states: &[[u64; STATE_WORDS]],
    hash_states: &[[u64; HASH_WORDS]],
    chain_to_next: &[bool],
) -> TexasAirResult<()> {
    if initial_states.is_empty()
        || initial_states.len() != hash_states.len()
        || initial_states.len() != chain_to_next.len()
        || chain_to_next.last().copied().unwrap_or(true)
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Blake2b chaining-value statement shape is invalid".into(),
        ));
    }
    for index in 0..initial_states.len() {
        if chain_to_next[index]
            && (index + 1 == initial_states.len()
                || initial_states[index + 1][..HASH_WORDS] != hash_states[index])
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Blake2b chaining value is detached from its successor compression".into(),
            ));
        }
    }
    Ok(())
}

fn log_size_for_calls(calls: &[Blake2bGCall]) -> TexasAirResult<u32> {
    if calls.is_empty() || !calls.len().is_multiple_of(G_ROWS) {
        return Err(TexasAirError::SpecViolation(
            "Blake2b compression calls must contain complete blocks".into(),
        ));
    }
    Ok(calls.len().next_power_of_two().ilog2().max(MIN_LOG_SIZE))
}

fn preprocessed_ids() -> &'static [PreProcessedColumnId] {
    static IDS: std::sync::OnceLock<Vec<PreProcessedColumnId>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| {
        let mut ids = Vec::with_capacity(SCOPE_COLUMNS + 3);
        for column in 0..SCOPE_COLUMNS {
            ids.push(PreProcessedColumnId {
                id: format!("preprocessed.blake2b.lookup.compression.scope.{column}.v1").into(),
            });
        }
        for column in 0..3 {
            ids.push(PreProcessedColumnId {
                id: format!("preprocessed.blake2b.lookup.compression.xor.table.{column}.v1").into(),
            });
        }
        ids
    })
    .as_slice()
}

fn scope_columns(
    messages: &[[u8; 128]],
    digests: &[[u8; 32]],
    initial_states: &[[u64; STATE_WORDS]],
    hash_states: &[[u64; HASH_WORDS]],
    chain_to_next: &[bool],
    calls: &[Blake2bGCall],
    log_size: u32,
) -> TexasAirResult<Vec<BaseColumn>> {
    if messages.is_empty()
        || messages.len() != digests.len()
        || messages.len() != initial_states.len()
        || messages.len() != hash_states.len()
        || messages.len() != chain_to_next.len()
        || calls.len() != messages.len() * G_ROWS
        || calls.len() > (1usize << log_size)
    {
        return Err(TexasAirError::SpecViolation(
            "invalid Blake2b compression scope shape".into(),
        ));
    }
    let rows = 1usize << log_size;
    let mut columns = vec![vec![M31::from(0u32); rows]; SCOPE_COLUMNS];
    for step in 0..calls.len() {
        let block = step / G_ROWS;
        let local = step % G_ROWS;
        let physical = step;
        let active = M31::from(1u32);
        columns[SCOPE_ACTIVE][physical] = active;
        columns[SCOPE_FIRST][physical] = M31::from(u32::from(local == 0));
        columns[SCOPE_LAST][physical] = M31::from(u32::from(local + 1 == G_ROWS));
        columns[SCOPE_ADVANCE][physical] = M31::from(u32::from(local + 1 < G_ROWS));
        {
            let mut write_word = |base: usize, word: usize, value: u64| {
                for (byte, value) in u64_bytes(value).into_iter().enumerate() {
                    columns[base + word * WORD_BYTES + byte][physical] = value;
                }
            };
            for (word, value) in initial_states[block].into_iter().enumerate() {
                write_word(SCOPE_INITIAL_BASE, word, value);
            }
            for (word, value) in message_words(&messages[block]).into_iter().enumerate() {
                write_word(SCOPE_MESSAGE_BASE, word, value);
            }
            if local + 1 == G_ROWS {
                for (word, chunk) in digests[block].chunks_exact(WORD_BYTES).enumerate() {
                    write_word(
                        SCOPE_DIGEST_BASE,
                        word,
                        u64::from_le_bytes(chunk.try_into().unwrap()),
                    );
                }
                for (word, value) in hash_states[block].into_iter().enumerate() {
                    write_word(SCOPE_HASH_BASE, word, value);
                }
                if chain_to_next[block] {
                    if block + 1 == messages.len() {
                        return Err(TexasAirError::SpecViolation(
                            "final Blake2b block cannot chain to a successor".into(),
                        ));
                    }
                    for (word, value) in initial_states[block + 1][..HASH_WORDS]
                        .iter()
                        .copied()
                        .enumerate()
                    {
                        write_word(SCOPE_NEXT_HASH_BASE, word, value);
                    }
                }
            }
            for (word, value) in calls[step]
                .input
                .into_iter()
                .chain(calls[step].output)
                .enumerate()
            {
                write_word(SCOPE_CALL_BASE, word, value);
            }
        }
        if local + 1 == G_ROWS && chain_to_next[block] {
            columns[SCOPE_CHAIN_TO_NEXT][physical] = M31::from(1u32);
        }
        let (lanes, x, y) = schedule(local);
        for (group, lane) in lanes.into_iter().enumerate() {
            columns[SCOPE_SELECTOR_BASE + group * STATE_WORDS + lane][physical] = active;
        }
        columns[SCOPE_SELECTOR_BASE + 4 * STATE_WORDS + x][physical] = active;
        columns[SCOPE_SELECTOR_BASE + 5 * STATE_WORDS + y][physical] = active;
    }
    // Stwo's transition offsets and LogUp prefix sums operate in bit-reversed
    // CircleDomain order.  The witness above is assembled in the natural
    // Blake2b call (coset) order, so convert every scheduler scope column
    // once at the trace boundary.
    for column in &mut columns {
        bit_reverse_coset_to_circle_domain_order(column);
    }
    Ok(columns
        .into_iter()
        .map(|column| BaseColumn::from_cpu(&column))
        .collect())
}

fn trace_columns(
    messages: &[[u8; 128]],
    initial_states: &[[u64; STATE_WORDS]],
    calls: &[Blake2bGCall],
    log_size: u32,
) -> TexasAirResult<Vec<BaseColumn>> {
    if messages.len() != initial_states.len() || calls.len() != messages.len() * G_ROWS {
        return Err(TexasAirError::SpecViolation(
            "invalid Blake2b compression trace shape".into(),
        ));
    }
    let rows = 1usize << log_size;
    let mut columns = vec![vec![M31::from(0u32); rows]; NUM_TRACE_COLUMNS];
    let mut call_index = 0;
    for initial in initial_states {
        let mut state = *initial;
        for local in 0..G_ROWS {
            let call = &calls[call_index];
            let physical = call_index;
            for (word, value) in state.iter().copied().enumerate() {
                for (byte, value) in u64_bytes(value).into_iter().enumerate() {
                    columns[word_base(word) + byte][physical] = value;
                }
            }
            let (lanes, _, _) = schedule(local);
            let mut next_state = state;
            next_state[lanes[0]] = call.output[0];
            next_state[lanes[1]] = call.output[1];
            next_state[lanes[2]] = call.output[2];
            next_state[lanes[3]] = call.output[3];
            if local + 1 == G_ROWS {
                for word in 0..HASH_WORDS {
                    for (byte, value) in u64_bytes(initial[word] ^ next_state[word])
                        .into_iter()
                        .enumerate()
                    {
                        columns[DIGEST_MID_BASE + word * WORD_BYTES + byte][physical] = value;
                    }
                }
            }
            columns[ACTIVE_COLUMN][physical] = M31::from(1u32);
            for (word, value) in next_state.iter().copied().enumerate() {
                for (byte, value) in u64_bytes(value).into_iter().enumerate() {
                    columns[next_word_base(word) + byte][physical] = value;
                }
            }
            let next_active = local + 1 < G_ROWS;
            if next_active {
                columns[NEXT_ACTIVE_COLUMN][physical] = M31::from(1u32);
            }
            state = next_state;
            call_index += 1;
        }
    }
    // Keep state, its materialized post-G image, and the scope on the same
    // logical ordering so `[0, 1]` masks link consecutive G calls.
    for column in &mut columns {
        bit_reverse_coset_to_circle_domain_order(column);
    }
    Ok(columns
        .into_iter()
        .map(|column| BaseColumn::from_cpu(&column))
        .collect())
}

fn xor_table() -> Vec<BaseColumn> {
    static TABLE: std::sync::OnceLock<Vec<BaseColumn>> = std::sync::OnceLock::new();
    TABLE
        .get_or_init(|| {
            let mut columns = vec![Vec::with_capacity(XOR_ROWS); 3];
            for index in 0..XOR_ROWS {
                let a = (index >> 8) as u32;
                let b = (index & 0xff) as u32;
                columns[0].push(M31::from(a));
                columns[1].push(M31::from(b));
                columns[2].push(M31::from(a ^ b));
            }
            columns
                .into_iter()
                .map(|column| BaseColumn::from_cpu(&column))
                .collect()
        })
        .clone()
}

fn circle_evals(
    log_size: u32,
    columns: Vec<BaseColumn>,
) -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
    let domain = stwo::core::poly::circle::CanonicCoset::new(log_size).circle_domain();
    columns
        .into_iter()
        .map(|column| CircleEvaluation::<SimdBackend, M31, BitReversedOrder>::new(domain, column))
        .collect()
}

fn pack_column(column: &BaseColumn, vector_row: usize) -> PackedBaseField {
    column.data[vector_row]
}

fn scope_pack(scope: &[BaseColumn], column: usize, vector_row: usize) -> PackedBaseField {
    pack_column(&scope[column], vector_row)
}

fn scheduler_interaction_trace(
    trace: &[BaseColumn],
    scope: &[BaseColumn],
    elements: &Blake2bCompressionByteXor,
    log_size: u32,
) -> (
    Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>>,
    SecureField,
) {
    let mut generator = LogupTraceGenerator::new(log_size);
    for pair in 0..INTERACTION_COLUMNS {
        let mut column = generator.new_col();
        for vector_row in 0..(1usize << (log_size - LOG_N_LANES)) {
            let (d0_tuple, d1_tuple) = scheduler_pair_tuples(trace, scope, vector_row, pair);
            let active = PackedSecureField::from(scope_pack(scope, SCOPE_LAST, vector_row));
            let d0: PackedSecureField = elements.combine(&d0_tuple);
            let d1: PackedSecureField = elements.combine(&d1_tuple);
            column.write_frac(vector_row, active * (d0 + d1), d0 * d1);
        }
        column.finalize_col();
    }
    generator.finalize_last()
}

/// Returns the two [`PackedBaseField`] tuples for one `(pair, vector_row)`.
/// Builds only the two tuples consumed by one interaction pair.  The previous
/// implementation rebuilt all 128 tuples per (pair, row), then discarded all
/// but `pair*2` and `pair*2+1`.
#[inline]
fn scheduler_pair_tuples(
    trace: &[BaseColumn],
    scope: &[BaseColumn],
    vector_row: usize,
    pair: usize,
) -> ([PackedBaseField; 3], [PackedBaseField; 3]) {
    let word = pair / WORD_BYTES;
    let byte = pair % WORD_BYTES;
    let mid = pack_column(
        &trace[DIGEST_MID_BASE + word * WORD_BYTES + byte],
        vector_row,
    );
    let d0 = [
        scope_pack(
            scope,
            SCOPE_INITIAL_BASE + word * WORD_BYTES + byte,
            vector_row,
        ),
        pack_column(&trace[next_word_base(word) + byte], vector_row),
        mid,
    ];
    let d1 = [
        mid,
        pack_column(&trace[next_word_base(word + 8) + byte], vector_row),
        scope_pack(
            scope,
            SCOPE_HASH_BASE + word * WORD_BYTES + byte,
            vector_row,
        ),
    ];
    (d0, d1)
}

fn scheduler_scalar_tuples(
    trace: &[BaseColumn],
    scope: &[BaseColumn],
    row: usize,
) -> Vec<[usize; 3]> {
    let mut tuples = Vec::with_capacity(XOR_LOOKUPS);
    for word in 0..HASH_WORDS {
        for byte in 0..WORD_BYTES {
            let mid = trace[DIGEST_MID_BASE + word * WORD_BYTES + byte].at(row).0 as usize;
            tuples.push([
                scope[SCOPE_INITIAL_BASE + word * WORD_BYTES + byte]
                    .at(row)
                    .0 as usize,
                trace[next_word_base(word) + byte].at(row).0 as usize,
                mid,
            ]);
            tuples.push([
                mid,
                // Must match the in-AIR tuple: Blake2b's second final-state
                // operand is v[word + 8], not v[word + digest_words].
                trace[next_word_base(word + 8) + byte].at(row).0 as usize,
                scope[SCOPE_HASH_BASE + word * WORD_BYTES + byte].at(row).0 as usize,
            ]);
        }
    }
    tuples
}

fn xor_multiplicity_column(trace: &[BaseColumn], scope: &[BaseColumn]) -> BaseColumn {
    let mut multiplicity = vec![M31::from(0u32); XOR_ROWS];
    for row in 0..trace[ACTIVE_COLUMN].len() {
        if scope[SCOPE_LAST].at(row) == M31::from(1u32) {
            for tuple in scheduler_scalar_tuples(trace, scope, row) {
                multiplicity[(tuple[0] << 8) | tuple[1]] += M31::from(1u32);
            }
        }
    }
    BaseColumn::from_cpu(&multiplicity)
}

fn table_interaction_trace(
    multiplicity: &BaseColumn,
    elements: &Blake2bCompressionByteXor,
) -> (
    Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>>,
    SecureField,
) {
    let table = xor_table();
    let mut generator = LogupTraceGenerator::new(XOR_LOG_SIZE);
    let mut column = generator.new_col();
    for vector_row in 0..(XOR_ROWS / N_LANES) {
        let tuple = [
            pack_column(&table[0], vector_row),
            pack_column(&table[1], vector_row),
            pack_column(&table[2], vector_row),
        ];
        let denominator = elements.combine(&tuple);
        let numerator = PackedSecureField::from(-multiplicity.data[vector_row]);
        column.write_frac(vector_row, numerator, denominator);
    }
    column.finalize_col();
    generator.finalize_last()
}

fn mix_statement(
    channel: &mut Poseidon252Channel,
    messages: &[[u8; 128]],
    digests: &[[u8; 32]],
    initial_states: &[[u64; STATE_WORDS]],
    hash_states: &[[u64; HASH_WORDS]],
    chain_to_next: &[bool],
    calls: &[Blake2bGCall],
) {
    channel.mix_u64(messages.len() as u64);
    for message in messages {
        for word in message.chunks_exact(WORD_BYTES) {
            channel.mix_u64(u64::from_le_bytes(word.try_into().unwrap()));
        }
    }
    for digest in digests {
        for word in digest.chunks_exact(WORD_BYTES) {
            channel.mix_u64(u64::from_le_bytes(word.try_into().unwrap()));
        }
    }
    for initial in initial_states {
        for word in initial {
            channel.mix_u64(*word);
        }
    }
    for hash_state in hash_states {
        for word in hash_state {
            channel.mix_u64(*word);
        }
    }
    for chain in chain_to_next {
        channel.mix_u64(u64::from(*chain));
    }
    channel.mix_u64(calls.len() as u64);
    for call in calls {
        for value in call.input.into_iter().chain(call.output) {
            channel.mix_u64(value);
        }
    }
}

fn pcs_config() -> stwo::core::pcs::PcsConfig {
    crate::prover_context::protocol_pcs_config()
}

fn build_schedule_proof(
    messages: &[[u8; 128]],
    digests: &[[u8; 32]],
    initial_states: &[[u64; STATE_WORDS]],
    hash_states: &[[u64; HASH_WORDS]],
    chain_to_next: &[bool],
    calls: &[Blake2bGCall],
) -> TexasAirResult<Vec<u8>> {
    let log_size = log_size_for_calls(calls)?;
    let scope = scope_columns(
        messages,
        digests,
        initial_states,
        hash_states,
        chain_to_next,
        calls,
        log_size,
    )?;
    let trace = trace_columns(messages, initial_states, calls, log_size)?;
    let multiplicity = xor_multiplicity_column(&trace, &scope);
    let config = pcs_config();
    let max_log = XOR_LOG_SIZE.max(log_size);
    let twiddles =
        crate::prover_context::simd_twiddles(max_log + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_statement(
        &mut channel,
        messages,
        digests,
        initial_states,
        hash_states,
        chain_to_next,
        calls,
    );
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    scheme.set_store_polynomials_coefficients();
    {
        let mut tree = scheme.tree_builder();
        let mut preprocessed = circle_evals(log_size, scope.clone());
        preprocessed.extend(circle_evals(XOR_LOG_SIZE, xor_table()));
        tree.extend_evals(preprocessed);
        tree.commit(&mut channel);
    }
    {
        let mut tree = scheme.tree_builder();
        let mut original = circle_evals(log_size, trace.clone());
        original.extend(circle_evals(XOR_LOG_SIZE, vec![multiplicity.clone()]));
        tree.extend_evals(original);
        tree.commit(&mut channel);
    }
    let xor = Blake2bCompressionByteXor::draw(&mut channel);
    let (scheduler_interaction, scheduler_sum) =
        scheduler_interaction_trace(&trace, &scope, &xor, log_size);
    let (table_interaction, table_sum) = table_interaction_trace(&multiplicity, &xor);
    debug_assert_eq!(
        scheduler_sum + table_sum,
        SecureField::from_u32_unchecked(0, 0, 0, 0)
    );
    channel.mix_felts(&[scheduler_sum, table_sum]);
    {
        let mut tree = scheme.tree_builder();
        let mut interactions = scheduler_interaction;
        interactions.extend(table_interaction);
        tree.extend_evals(interactions);
        tree.commit(&mut channel);
    }
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let scheduler = FrameworkComponent::new(
        &mut allocator,
        SchedulerAir {
            log_size,
            xor: xor.clone(),
        },
        scheduler_sum,
    );
    let table = FrameworkComponent::new(&mut allocator, XorTableAir { elements: xor }, table_sum);
    let proof = prove(
        &[
            &scheduler as &dyn ComponentProver<SimdBackend>,
            &table as &dyn ComponentProver<SimdBackend>,
        ],
        &mut channel,
        scheme,
    )
    .map_err(|error: ProvingError| TexasAirError::StwoProverError(error.to_string()))?;
    options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))
}

fn verify_schedule_proof(
    messages: &[[u8; 128]],
    digests: &[[u8; 32]],
    initial_states: &[[u64; STATE_WORDS]],
    hash_states: &[[u64; HASH_WORDS]],
    chain_to_next: &[bool],
    calls: &[Blake2bGCall],
    bytes: &[u8],
) -> TexasAirResult<()> {
    let log_size = log_size_for_calls(calls)?;
    let rebuild_timing = std::time::Instant::now();
    let scope = scope_columns(
        messages,
        digests,
        initial_states,
        hash_states,
        chain_to_next,
        calls,
        log_size,
    )?;
    let trace = trace_columns(messages, initial_states, calls, log_size)?;
    let multiplicity = xor_multiplicity_column(&trace, &scope);
    crate::prove_timing::record(
        "blake2b:schedule-verify-rebuild",
        crate::prove_timing::TimingKind::Verify,
        rebuild_timing,
        None,
    );
    let proof: StarkProof<Poseidon252MerkleHasher> = options()
        .deserialize(bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let config = pcs_config();
    let max_log = XOR_LOG_SIZE.max(log_size);
    let twiddles =
        crate::prover_context::simd_twiddles(max_log + config.fri_config.log_blowup_factor);
    let mut trusted =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    let mut scope_channel = Poseidon252Channel::default();
    {
        let mut tree = trusted.tree_builder();
        let mut preprocessed = circle_evals(log_size, scope);
        preprocessed.extend(circle_evals(XOR_LOG_SIZE, xor_table()));
        tree.extend_evals(preprocessed);
        tree.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Blake2b scheduler public scope commitment mismatch".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_statement(
        &mut channel,
        messages,
        digests,
        initial_states,
        hash_states,
        chain_to_next,
        calls,
    );
    let mut scheme =
        stwo::core::pcs::CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    let ids = preprocessed_ids();
    let mut pre_sizes = vec![log_size; SCOPE_COLUMNS];
    pre_sizes.extend([XOR_LOG_SIZE; 3]);
    scheme.commit(proof.commitments[0], &pre_sizes, &mut channel);
    let mut original_sizes = vec![log_size; NUM_TRACE_COLUMNS];
    original_sizes.push(XOR_LOG_SIZE);
    scheme.commit(proof.commitments[1], &original_sizes, &mut channel);
    let xor = Blake2bCompressionByteXor::draw(&mut channel);
    let (scheduler_interaction, scheduler_sum) = scheduler_interaction_trace(
        &trace,
        &scope_columns(
            messages,
            digests,
            initial_states,
            hash_states,
            chain_to_next,
            calls,
            log_size,
        )?,
        &xor,
        log_size,
    );
    let (table_interaction, table_sum) = table_interaction_trace(&multiplicity, &xor);
    let _ = (scheduler_interaction, table_interaction);
    channel.mix_felts(&[scheduler_sum, table_sum]);
    // Every secure-field interaction column is serialized as four M31
    // columns in the commitment scheme, matching the G component verifier.
    let mut interaction_sizes = vec![log_size; INTERACTION_COLUMNS * 4];
    interaction_sizes.extend([XOR_LOG_SIZE; 4]);
    scheme.commit(proof.commitments[2], &interaction_sizes, &mut channel);
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let scheduler = FrameworkComponent::new(
        &mut allocator,
        SchedulerAir {
            log_size,
            xor: xor.clone(),
        },
        scheduler_sum,
    );
    let table = FrameworkComponent::new(&mut allocator, XorTableAir { elements: xor }, table_sum);
    verify(&[&scheduler, &table], &mut channel, &mut scheme, proof)
        .map_err(|error: VerificationError| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

impl FrameworkEval for SchedulerAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Both the ordinary transition gates and paired LogUp constraints are
        // cubic after the post-G state is materialized in the trace.  Their
        // quotients therefore fit below 2 * |H|.
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let state_with_successor: Vec<[E::F; 2]> = (0..STATE_WORDS * WORD_BYTES)
            .map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]))
            .collect();
        let state: Vec<E::F> = state_with_successor
            .iter()
            .map(|values| values[0].clone())
            .collect();
        let successor_state: Vec<E::F> = state_with_successor
            .iter()
            .map(|values| values[1].clone())
            .collect();
        let digest_mid: Vec<E::F> = (0..HASH_WORDS * WORD_BYTES)
            .map(|_| eval.next_trace_mask())
            .collect();
        let active_trace = eval.next_trace_mask();
        let next_state: Vec<E::F> = (0..STATE_WORDS * WORD_BYTES)
            .map(|_| eval.next_trace_mask())
            .collect();
        let next_active = eval.next_trace_mask();
        let ids = preprocessed_ids();
        let active = eval.get_preprocessed_column(ids[SCOPE_ACTIVE].clone());
        let first = eval.get_preprocessed_column(ids[SCOPE_FIRST].clone());
        let last = eval.get_preprocessed_column(ids[SCOPE_LAST].clone());
        let advance = eval.get_preprocessed_column(ids[SCOPE_ADVANCE].clone());
        let one: E::F = M31::from(1u32).into();
        let zero: E::F = M31::from(0u32).into();
        eval.add_constraint(active_trace.clone() - active.clone());
        eval.add_constraint(active.clone() * (active.clone() - one.clone()));
        eval.add_constraint(first.clone() * (first.clone() - one.clone()));
        eval.add_constraint(last.clone() * (last.clone() - one.clone()));
        eval.add_constraint(advance.clone() * (advance.clone() - one.clone()));
        eval.add_constraint(last.clone() + advance.clone() - active.clone());
        eval.add_constraint(first.clone() * (one.clone() - active.clone()));
        eval.add_constraint(next_active.clone() - active.clone() * advance.clone());
        eval.add_constraint(next_active.clone() * (next_active.clone() - one.clone()));
        for value in &state {
            eval.add_constraint((one.clone() - active.clone()) * value.clone());
        }
        for value in &digest_mid {
            eval.add_constraint((one.clone() - active.clone()) * value.clone());
        }
        for value in &next_state {
            eval.add_constraint((one.clone() - active.clone()) * value.clone());
        }
        let initial: Vec<E::F> = (0..STATE_WORDS * WORD_BYTES)
            .map(|column| eval.get_preprocessed_column(ids[SCOPE_INITIAL_BASE + column].clone()))
            .collect();
        let message: Vec<E::F> = (0..MESSAGE_WORDS * WORD_BYTES)
            .map(|column| eval.get_preprocessed_column(ids[SCOPE_MESSAGE_BASE + column].clone()))
            .collect();
        let digest: Vec<E::F> = (0..DIGEST_WORDS * WORD_BYTES)
            .map(|column| eval.get_preprocessed_column(ids[SCOPE_DIGEST_BASE + column].clone()))
            .collect();
        let hash_state: Vec<E::F> = (0..HASH_WORDS * WORD_BYTES)
            .map(|column| eval.get_preprocessed_column(ids[SCOPE_HASH_BASE + column].clone()))
            .collect();
        // `EvalAtRow::get_preprocessed_column` consumes columns in physical
        // commitment order.  Keep this read precisely between `hash_state`
        // and `next_hash`, matching `SCOPE_CHAIN_TO_NEXT`; the column id is
        // metadata and is deliberately ignored by the assertion evaluator.
        let chain_to_next = eval.get_preprocessed_column(ids[SCOPE_CHAIN_TO_NEXT].clone());
        let next_hash: Vec<E::F> = (0..HASH_WORDS * WORD_BYTES)
            .map(|column| eval.get_preprocessed_column(ids[SCOPE_NEXT_HASH_BASE + column].clone()))
            .collect();
        let selectors: Vec<Vec<E::F>> = (0..SELECTOR_GROUPS)
            .map(|group| {
                (0..STATE_WORDS)
                    .map(|lane| {
                        eval.get_preprocessed_column(
                            ids[SCOPE_SELECTOR_BASE + group * STATE_WORDS + lane].clone(),
                        )
                    })
                    .collect()
            })
            .collect();
        let calls: Vec<E::F> = (0..(INPUT_WORDS + G_OUTPUT_WORDS) * WORD_BYTES)
            .map(|column| eval.get_preprocessed_column(ids[SCOPE_CALL_BASE + column].clone()))
            .collect();
        for lane in 0..STATE_WORDS {
            for byte in 0..WORD_BYTES {
                let index = word_base(lane) + byte;
                eval.add_constraint(
                    first.clone() * (state[index].clone() - initial[index].clone()),
                );
                for group in 0..4 {
                    let call = calls[(group) * WORD_BYTES + byte].clone();
                    eval.add_constraint(
                        active.clone()
                            * selectors[group][lane].clone()
                            * (call - state[index].clone()),
                    );
                }
                if lane < HASH_WORDS {
                    // The digest uses v[i + 8], independently of the digest
                    // width (which is only four words in this fixed ABI).
                    let right_index = word_base(lane + 8) + byte;
                    let mid = digest_mid[lane * WORD_BYTES + byte].clone();
                    eval.add_to_relation(stwo_constraint_framework::RelationEntry::new(
                        &self.xor,
                        E::EF::from(last.clone()),
                        &[
                            initial[index].clone(),
                            next_state[index].clone(),
                            mid.clone(),
                        ],
                    ));
                    eval.add_to_relation(stwo_constraint_framework::RelationEntry::new(
                        &self.xor,
                        E::EF::from(last.clone()),
                        &[
                            mid,
                            next_state[right_index].clone(),
                            hash_state[lane * WORD_BYTES + byte].clone(),
                        ],
                    ));
                    if lane < DIGEST_WORDS {
                        eval.add_constraint(
                            last.clone()
                                * (hash_state[lane * WORD_BYTES + byte].clone()
                                    - digest[lane * WORD_BYTES + byte].clone()),
                        );
                    }
                    eval.add_constraint(
                        chain_to_next.clone()
                            * (hash_state[lane * WORD_BYTES + byte].clone()
                                - next_hash[lane * WORD_BYTES + byte].clone()),
                    );
                }
            }
        }
        for group in 0..4 {
            for byte in 0..WORD_BYTES {
                eval.add_constraint(
                    active.clone()
                        * (calls[group * WORD_BYTES + byte].clone()
                            - selectors[group]
                                .iter()
                                .enumerate()
                                .map(|(lane, selector)| {
                                    selector.clone() * state[word_base(lane) + byte].clone()
                                })
                                .fold(zero.clone(), |acc, value| acc + value)),
                );
            }
        }
        for byte in 0..WORD_BYTES {
            for group in 0..2 {
                let selected = selectors[4 + group]
                    .iter()
                    .enumerate()
                    .map(|(word, selector)| {
                        selector.clone() * message[word * WORD_BYTES + byte].clone()
                    })
                    .fold(zero.clone(), |acc, value| acc + value);
                eval.add_constraint(
                    active.clone() * (calls[(4 + group) * WORD_BYTES + byte].clone() - selected),
                );
            }
        }
        for lane in 0..STATE_WORDS {
            for byte in 0..WORD_BYTES {
                let index = word_base(lane) + byte;
                let mut updated = state[index].clone();
                for group in 0..4 {
                    let output = calls[(INPUT_WORDS + group) * WORD_BYTES + byte].clone();
                    updated += selectors[group][lane].clone() * (output - state[index].clone());
                }
                eval.add_constraint(active.clone() * (next_state[index].clone() - updated));
                eval.add_constraint(
                    advance.clone() * (successor_state[index].clone() - next_state[index].clone()),
                );
            }
        }
        eval.finalize_logup_in_pairs();
        eval
    }
}

impl FrameworkEval for XorTableAir {
    fn log_size(&self) -> u32 {
        XOR_LOG_SIZE
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        XOR_LOG_SIZE + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let ids = preprocessed_ids();
        let tuple = [
            eval.get_preprocessed_column(ids[SCOPE_COLUMNS].clone()),
            eval.get_preprocessed_column(ids[SCOPE_COLUMNS + 1].clone()),
            eval.get_preprocessed_column(ids[SCOPE_COLUMNS + 2].clone()),
        ];
        let multiplicity = eval.next_trace_mask();
        eval.add_to_relation(stwo_constraint_framework::RelationEntry::new(
            &self.elements,
            -E::EF::from(multiplicity),
            &tuple,
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

/// Prove the optimized Blake2b compression relation for fixed 128-byte blocks.
pub fn prove_blake2b_lookup_compression(
    messages: &[[u8; 128]],
    digests: &[[u8; 32]],
) -> TexasAirResult<ArchivedBlake2bLookupCompressionProof> {
    let initial_states = vec![fixed_smt_initial_v(); messages.len()];
    let chain_to_next = vec![false; messages.len()];
    prove_blake2b_lookup_compression_with_initial_states(
        messages,
        digests,
        &initial_states,
        &chain_to_next,
    )
}

/// Prove fixed-size Blake2b compressions with explicit initial states and
/// optional full-chaining links.
///
/// This is the common engine for L1's independent fixed-node compressions and
/// for a standard multi-block Blake2b hash.  The scheduler constrains all
/// eight final `h` words and, wherever `chain_to_next` is set, binds them to
/// the next block's initial `h` words.  `digests` remain the standard
/// 32-byte truncation of each block result.
pub fn prove_blake2b_lookup_compression_with_initial_states(
    messages: &[[u8; 128]],
    digests: &[[u8; 32]],
    initial_states: &[[u64; STATE_WORDS]],
    chain_to_next: &[bool],
) -> TexasAirResult<ArchivedBlake2bLookupCompressionProof> {
    if messages.is_empty() || messages.len() != digests.len() {
        return Err(TexasAirError::SpecViolation(
            "Blake2b compression messages/digests length mismatch".into(),
        ));
    }
    if messages.len() != initial_states.len() || messages.len() != chain_to_next.len() {
        return Err(TexasAirError::SpecViolation(
            "Blake2b compression chain statement length mismatch".into(),
        ));
    }
    if chain_to_next.last().copied().unwrap_or(true) {
        return Err(TexasAirError::SpecViolation(
            "final Blake2b compression cannot chain to a successor".into(),
        ));
    }
    let (calls, hash_states) = compression_calls(messages, initial_states)?;
    validate_chaining_links(initial_states, &hash_states, chain_to_next)?;
    // The G and scheduler STARKs are independent statements over the same
    // calls; proving them concurrently halves the fixed per-proof wall clock
    // (table commitment + FRI dominate and do not scale with block count).
    let timing_start = std::time::Instant::now();
    let schedule_messages = messages;
    let schedule_digests = digests;
    let schedule_initial_states = initial_states;
    let schedule_chain = chain_to_next;
    let (g_proof, schedule_proof_bytes) = rayon::join(
        || prove_blake2b_g(&calls),
        || {
            build_schedule_proof(
                schedule_messages,
                schedule_digests,
                schedule_initial_states,
                &hash_states,
                schedule_chain,
                &calls,
            )
        },
    );
    let g_proof = g_proof?;
    let schedule_proof_bytes = schedule_proof_bytes?;
    crate::prove_timing::record(
        "blake2b:g+schedule-parallel",
        crate::prove_timing::TimingKind::Prove,
        timing_start,
        None,
    );
    Ok(ArchivedBlake2bLookupCompressionProof {
        messages: messages.to_vec(),
        digests: digests.to_vec(),
        initial_states: initial_states.to_vec(),
        hash_states,
        chain_to_next: chain_to_next.to_vec(),
        calls,
        g_proof_bytes: borsh::to_vec(&g_proof)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?,
        schedule_proof_bytes,
    })
}

/// Verify the optimized Blake2b compression relation without native hashing.
pub fn verify_blake2b_lookup_compression(
    archive: &ArchivedBlake2bLookupCompressionProof,
) -> TexasAirResult<()> {
    if archive.messages.is_empty()
        || archive.messages.len() != archive.digests.len()
        || archive.messages.len() != archive.initial_states.len()
        || archive.messages.len() != archive.hash_states.len()
        || archive.messages.len() != archive.chain_to_next.len()
        || archive.calls.len() != archive.messages.len() * G_ROWS
        || archive.chain_to_next.last().copied().unwrap_or(true)
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Blake2b compression archive shape mismatch".into(),
        ));
    }
    validate_chaining_links(
        &archive.initial_states,
        &archive.hash_states,
        &archive.chain_to_next,
    )?;
    let g_archive = ArchivedBlake2bGProof::try_from_slice(&archive.g_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    if g_archive.calls != archive.calls {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Blake2b G proof call scope mismatch".into(),
        ));
    }
    // The G and scheduler STARK verifications are independent; run them
    // concurrently to halve the fixed verifier wall clock.
    let g_timing = std::time::Instant::now();
    let (g_result, schedule_result) = rayon::join(
        || {
            let start = std::time::Instant::now();
            let result = verify_blake2b_g(&g_archive);
            crate::prove_timing::record(
                "blake2b:g-verify",
                crate::prove_timing::TimingKind::Verify,
                start,
                None,
            );
            result
        },
        || {
            let start = std::time::Instant::now();
            let result = verify_schedule_proof(
                &archive.messages,
                &archive.digests,
                &archive.initial_states,
                &archive.hash_states,
                &archive.chain_to_next,
                &archive.calls,
                &archive.schedule_proof_bytes,
            );
            crate::prove_timing::record(
                "blake2b:schedule-verify",
                crate::prove_timing::TimingKind::Verify,
                start,
                None,
            );
            result
        },
    );
    g_result?;
    let schedule_result = schedule_result?;
    crate::prove_timing::record(
        "blake2b:g+schedule-verify-parallel",
        crate::prove_timing::TimingKind::Verify,
        g_timing,
        None,
    );
    Ok(schedule_result)
}

fn hash_messages(message: &[u8]) -> Vec<[u8; 128]> {
    let blocks = message.len().max(1).div_ceil(128);
    (0..blocks)
        .map(|index| {
            let start = index * 128;
            let end = message.len().min(start + 128);
            let mut block = [0u8; 128];
            if start < end {
                block[..end - start].copy_from_slice(&message[start..end]);
            }
            block
        })
        .collect()
}

fn hash_chain_plan(
    message: &[u8],
) -> TexasAirResult<(
    Vec<[u8; 128]>,
    Vec<[u64; STATE_WORDS]>,
    Vec<[u8; 32]>,
    Vec<bool>,
)> {
    let messages = hash_messages(message);
    let mut initial_states = Vec::with_capacity(messages.len());
    let mut digests = Vec::with_capacity(messages.len());
    let mut h = standard_initial_h();
    for (index, block) in messages.iter().enumerate() {
        let counter = message.len().min((index + 1) * 128) as u64;
        let initial = hash_initial_v(h, counter, index + 1 == messages.len());
        let (_, hash_state) = compression_calls(std::slice::from_ref(block), &[initial])?;
        h = hash_state[0];
        initial_states.push(initial);
        digests.push(digest_from_hash_state(&h));
    }
    let mut chain_to_next = vec![true; messages.len()];
    *chain_to_next
        .last_mut()
        .expect("Blake2b hash has at least one block") = false;
    Ok((messages, initial_states, digests, chain_to_next))
}

fn validate_hash_chain_abi(archive: &ArchivedBlake2bLookupHashProof) -> TexasAirResult<()> {
    let messages = hash_messages(&archive.message);
    let compression = &archive.compression;
    if compression.messages != messages
        || compression.initial_states.len() != messages.len()
        || compression.chain_to_next.len() != messages.len()
        || compression.digests.len() != messages.len()
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Blake2b hash archive has an invalid block layout".into(),
        ));
    }
    for index in 0..messages.len() {
        let counter = archive.message.len().min((index + 1) * 128) as u64;
        let expected_tail =
            hash_initial_v([0u64; HASH_WORDS], counter, index + 1 == messages.len());
        if compression.initial_states[index][HASH_WORDS..] != expected_tail[HASH_WORDS..]
            || compression.chain_to_next[index] != (index + 1 < messages.len())
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Blake2b hash counter, final flag, or chain layout is invalid".into(),
            ));
        }
    }
    if compression.initial_states[0][..HASH_WORDS] != standard_initial_h()
        || compression.digests.last().copied() != Some(archive.digest)
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Blake2b hash initial state or final digest is detached".into(),
        ));
    }
    Ok(())
}

/// Prove a standard Blake2b-256 hash over an arbitrary-length byte string.
///
/// All block padding, byte counters, final-block flags, and eight-word
/// chaining-value links are verifier-reconstructed or AIR-constrained.  The
/// native prover only materializes witness columns; no native hash result is
/// consumed during verification.
pub fn prove_blake2b_lookup_hash(message: &[u8]) -> TexasAirResult<ArchivedBlake2bLookupHashProof> {
    let (messages, initial_states, digests, chain_to_next) = hash_chain_plan(message)?;
    let compression = prove_blake2b_lookup_compression_with_initial_states(
        &messages,
        &digests,
        &initial_states,
        &chain_to_next,
    )?;
    let digest = *digests.last().expect("Blake2b hash has a final digest");
    Ok(ArchivedBlake2bLookupHashProof {
        message: message.to_vec(),
        digest,
        compression,
    })
}

/// Verify an arbitrary-length Blake2b-256 hash using only the archived Stwo
/// proofs and its public byte statement.  This intentionally performs no
/// native Blake2b computation.
pub fn verify_blake2b_lookup_hash(archive: &ArchivedBlake2bLookupHashProof) -> TexasAirResult<()> {
    validate_hash_chain_abi(archive)?;
    verify_blake2b_lookup_compression(&archive.compression)
}

/// Prove one fixed-value SMT path using 257 optimized compression blocks.
pub fn prove_blake2b_lookup_smt_fixed_value_path(
    witness: &Blake2bSmtFixedValuePathWitness,
) -> TexasAirResult<ArchivedBlake2bLookupSmtFixedValuePathProof> {
    if !witness.terminal_node_matches_root() {
        return Err(TexasAirError::SpecViolation(
            "SMT witness terminal node does not match public root".into(),
        ));
    }
    let blocks = witness.compression_blocks();
    let messages = blocks.map(|block| *block.message());
    let digests = witness.nodes;
    let compression = prove_blake2b_lookup_compression(&messages, &digests)?;
    Ok(ArchivedBlake2bLookupSmtFixedValuePathProof {
        witness: witness.clone(),
        compression,
    })
}

/// Verify a fixed-value SMT path using only the two AIR proofs and public ABI.
pub fn verify_blake2b_lookup_smt_fixed_value_path(
    archive: &ArchivedBlake2bLookupSmtFixedValuePathProof,
) -> TexasAirResult<()> {
    let blocks = archive.witness.compression_blocks();
    let messages = blocks.map(|block| *block.message());
    let digests = archive.witness.nodes;
    if archive.compression.messages != messages || archive.compression.digests != digests {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "SMT compression proof is detached from its path witness".into(),
        ));
    }
    if archive.witness.nodes[SMT_FIXED_VALUE_OPENING_COMPRESSIONS - 1] != archive.witness.root {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "SMT path root endpoint mismatch".into(),
        ));
    }
    verify_blake2b_lookup_compression(&archive.compression)
}

fn paths_messages_and_digests(
    paths: &[Blake2bSmtFixedValuePathWitness],
) -> TexasAirResult<(Vec<[u8; 128]>, Vec<[u8; 32]>)> {
    if paths.is_empty() {
        return Err(TexasAirError::SpecViolation(
            "Blake2b fixed-value SMT path batch must not be empty".into(),
        ));
    }
    let mut messages = Vec::with_capacity(paths.len() * SMT_FIXED_VALUE_OPENING_COMPRESSIONS);
    let mut digests = Vec::with_capacity(paths.len() * SMT_FIXED_VALUE_OPENING_COMPRESSIONS);
    for path in paths {
        if !path.terminal_node_matches_root() {
            return Err(TexasAirError::SpecViolation(
                "SMT witness terminal node does not match public root".into(),
            ));
        }
        messages.extend(
            path.compression_blocks()
                .into_iter()
                .map(|block| *block.message()),
        );
        digests.extend(path.nodes);
    }
    Ok((messages, digests))
}

/// Prove several fixed-value SMT paths in a shared lookup-backed Blake2b
/// compression batch.
pub fn prove_blake2b_lookup_smt_fixed_value_paths(
    paths: &[Blake2bSmtFixedValuePathWitness],
) -> TexasAirResult<ArchivedBlake2bLookupSmtFixedValuePathsProof> {
    let (messages, digests) = paths_messages_and_digests(paths)?;
    Ok(ArchivedBlake2bLookupSmtFixedValuePathsProof {
        paths: paths.to_vec(),
        compression: prove_blake2b_lookup_compression(&messages, &digests)?,
    })
}

/// Verify several fixed-value SMT paths using one shared pair of lookup
/// proofs. No native hash or native sparse-Merkle verifier is called.
pub fn verify_blake2b_lookup_smt_fixed_value_paths(
    archive: &ArchivedBlake2bLookupSmtFixedValuePathsProof,
) -> TexasAirResult<()> {
    let (messages, digests) = paths_messages_and_digests(&archive.paths)?;
    if archive.compression.messages != messages || archive.compression.digests != digests {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "batched SMT compression proof is detached from its path statements".into(),
        ));
    }
    verify_blake2b_lookup_compression(&archive.compression)
}

/// Prove one fixed-size Blake2b block.  The caller supplies the public digest
/// statement; computing that digest is intentionally outside verification.
pub fn prove_blake2b_lookup_smt_single_block(
    block: &Blake2bSmtSingleBlock,
    digest: [u8; 32],
) -> TexasAirResult<ArchivedBlake2bLookupCompressionProof> {
    prove_blake2b_lookup_compression(&[*block.message()], &[digest])
}

#[cfg(test)]
mod tests {
    use crate::blake2b_smt_witness::SMT_PATH_SIBLINGS;
    use super::*;
    use stwo::core::pcs::TreeVec;
    use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
    use stwo_constraint_framework::assert_constraints_on_trace;
    use stwo_constraint_framework::expr::ExprEvaluator;

    fn fixed_smt_statement(
        messages: &[[u8; 128]],
    ) -> (
        Vec<[u64; STATE_WORDS]>,
        Vec<[u64; HASH_WORDS]>,
        Vec<Blake2bGCall>,
        Vec<bool>,
    ) {
        let initial_states = vec![fixed_smt_initial_v(); messages.len()];
        let (calls, hash_states) = compression_calls(messages, &initial_states).unwrap();
        let chain_to_next = vec![false; messages.len()];
        (initial_states, hash_states, calls, chain_to_next)
    }

    fn assert_scheduler_trace_satisfies_air(
        messages: &[[u8; 128]],
        digests: &[[u8; 32]],
        initial_states: &[[u64; STATE_WORDS]],
        hash_states: &[[u64; HASH_WORDS]],
        chain_to_next: &[bool],
        calls: &[Blake2bGCall],
    ) {
        let log_size = log_size_for_calls(calls).unwrap();
        let scope = scope_columns(
            messages,
            digests,
            initial_states,
            hash_states,
            chain_to_next,
            calls,
            log_size,
        )
        .unwrap();
        let trace = trace_columns(messages, initial_states, calls, log_size).unwrap();
        let xor = Blake2bCompressionByteXor::dummy();
        let (interaction, sum) = scheduler_interaction_trace(&trace, &scope, &xor, log_size);
        let evals: TreeVec<Vec<Vec<M31>>> = TreeVec::new(vec![
            scope.iter().map(|column| column.to_cpu()).collect(),
            trace.iter().map(|column| column.to_cpu()).collect(),
            interaction
                .iter()
                .map(|evaluation| evaluation.values.to_cpu())
                .collect(),
        ]);
        let borrowed: TreeVec<Vec<&Vec<M31>>> = (&evals).into();
        assert_constraints_on_trace(
            &borrowed,
            log_size,
            |eval| {
                let _ = SchedulerAir {
                    log_size,
                    xor: xor.clone(),
                }
                .evaluate(eval);
            },
            sum,
        );
    }

    #[test]
    fn scheduler_materialized_state_keeps_constraints_cubic() {
        let air = SchedulerAir {
            log_size: MIN_LOG_SIZE,
            xor: Blake2bCompressionByteXor::dummy(),
        };
        let evaluated = air.evaluate(ExprEvaluator::new());
        assert_eq!(
            evaluated.constraint_degree_bounds().into_iter().max(),
            Some(3)
        );
        assert_eq!(air.max_constraint_log_degree_bound(), MIN_LOG_SIZE + 1);
    }

    #[test]
    fn scheduler_constraints_accept_a_known_g_call_sequence() {
        let block = Blake2bSmtSingleBlock::leaf([0x11; 32], [0x22; 32]);
        let messages = [*block.message()];
        let (initial_states, hash_states, calls, chain_to_next) = fixed_smt_statement(&messages);
        let log_size = log_size_for_calls(&calls).unwrap();
        let scope = scope_columns(
            &messages,
            &[block.native_digest()],
            &initial_states,
            &hash_states,
            &chain_to_next,
            &calls,
            log_size,
        )
        .unwrap();
        let trace = trace_columns(&messages, &initial_states, &calls, log_size).unwrap();
        for step in 0..calls.len() {
            let row =
                bit_reverse_index(coset_index_to_circle_domain_index(step, log_size), log_size);
            if scope[SCOPE_FIRST].at(row) == M31::from(1u32) {
                for lane in 0..STATE_WORDS {
                    for byte in 0..WORD_BYTES {
                        assert_eq!(
                            trace[word_base(lane) + byte].at(row),
                            scope[SCOPE_INITIAL_BASE + lane * WORD_BYTES + byte].at(row),
                            "first G state must use the scoped initial state at lane {lane}",
                        );
                    }
                }
            }
            if scope[SCOPE_ADVANCE].at(row) == M31::from(1u32) {
                let next = bit_reverse_index(
                    coset_index_to_circle_domain_index(step + 1, log_size),
                    log_size,
                );
                for lane in 0..STATE_WORDS {
                    for byte in 0..WORD_BYTES {
                        let current = trace[word_base(lane) + byte].at(row);
                        let mut updated = current;
                        for group in 0..4 {
                            if scope[SCOPE_SELECTOR_BASE + group * STATE_WORDS + lane].at(row)
                                == M31::from(1u32)
                            {
                                updated = scope
                                    [SCOPE_CALL_BASE + (INPUT_WORDS + group) * WORD_BYTES + byte]
                                    .at(row);
                            }
                        }
                        assert_eq!(
                            updated,
                            trace[next_word_base(lane) + byte].at(row),
                            "materialized post-G state at step {step}, lane {lane}, byte {byte}"
                        );
                        assert_eq!(
                            updated,
                            trace[word_base(lane) + byte].at(next),
                            "logical step {step}, lane {lane}, byte {byte}"
                        );
                    }
                }
            }
            for group in 0..4 {
                let lane = schedule(step).0[group];
                for byte in 0..WORD_BYTES {
                    assert_eq!(
                        scope[SCOPE_CALL_BASE + group * WORD_BYTES + byte].at(row),
                        trace[word_base(lane) + byte].at(row),
                        "G input {group} must select lane {lane} at step {step}",
                    );
                }
            }
        }
        let xor = Blake2bCompressionByteXor::dummy();
        let (interaction, sum) = scheduler_interaction_trace(&trace, &scope, &xor, log_size);
        let evals: TreeVec<Vec<Vec<M31>>> = TreeVec::new(vec![
            scope.iter().map(|column| column.to_cpu()).collect(),
            trace.iter().map(|column| column.to_cpu()).collect(),
            interaction
                .iter()
                .map(|evaluation| evaluation.values.to_cpu())
                .collect(),
        ]);
        let borrowed: TreeVec<Vec<&Vec<M31>>> = (&evals).into();
        assert_constraints_on_trace(
            &borrowed,
            log_size,
            |eval| {
                let _ = SchedulerAir {
                    log_size,
                    xor: xor.clone(),
                }
                .evaluate(eval);
            },
            sum,
        );
    }

    #[test]
    fn multi_block_hash_plan_matches_blake2b_256_known_answer_and_binds_all_chaining_words() {
        // This crosses the 128-byte compression boundary.  The expected
        // digest is the standard BLAKE2b-256 test vector for bytes 0..=128,
        // independently produced by `b2sum -l 256`.
        let message: Vec<u8> = (0..=128).map(|value| value as u8).collect();
        let (messages, initial_states, digests, chain_to_next) = hash_chain_plan(&message).unwrap();
        let (calls, hash_states) = compression_calls(&messages, &initial_states).unwrap();
        let expected = [
            0xf7, 0xf3, 0xc4, 0x6b, 0xa2, 0x56, 0x4f, 0xf4, 0xc4, 0xc1, 0x62, 0xda, 0x1f, 0x5b,
            0x60, 0x5f, 0x9f, 0x1c, 0x4a, 0xa6, 0xa2, 0x06, 0x52, 0xa9, 0xf9, 0xa3, 0x37, 0xc1,
            0xa2, 0xf5, 0xb9, 0xc9,
        ];

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[1][1..], [0; 127]);
        assert_eq!(chain_to_next, [true, false]);
        assert_eq!(digests.last().copied(), Some(expected));
        assert_eq!(digest_from_hash_state(&hash_states[1]), expected);
        assert_eq!(
            initial_states[1][..HASH_WORDS],
            hash_states[0],
            "the successor compression must receive all eight h words"
        );

        // The scheduler AIR must accept the authentic all-eight-word link.
        assert_scheduler_trace_satisfies_air(
            &messages,
            &digests,
            &initial_states,
            &hash_states,
            &chain_to_next,
            &calls,
        );

        // In particular, changing a word that is not part of the 32-byte
        // digest must still fail: h[7] feeds the next compression but is not
        // externally emitted by Blake2b-256.  The verifier's public ABI
        // guard mirrors the scheduler's chain equality, so this can reject
        // before allocating any LogUp assertion state.
        let mut tampered_initial_states = initial_states.clone();
        tampered_initial_states[1][HASH_WORDS - 1] ^= 1;
        let (tampered_calls, tampered_hash_states) =
            compression_calls(&messages, &tampered_initial_states).unwrap();
        assert_eq!(tampered_calls.len(), calls.len());
        assert!(
            validate_chaining_links(
                &tampered_initial_states,
                &tampered_hash_states,
                &chain_to_next,
            )
            .is_err()
        );
    }

    #[ignore = "slow prove (~27s); full gate runs `--include-ignored`"]
    #[test]
    fn multi_block_hash_proof_roundtrip_rejects_a_second_half_chain_mutation() {
        let message: Vec<u8> = (0..=128).map(|value| value as u8).collect();
        let archive = prove_blake2b_lookup_hash(&message).unwrap();
        assert_eq!(
            archive.digest,
            [
                0xf7, 0xf3, 0xc4, 0x6b, 0xa2, 0x56, 0x4f, 0xf4, 0xc4, 0xc1, 0x62, 0xda, 0x1f, 0x5b,
                0x60, 0x5f, 0x9f, 0x1c, 0x4a, 0xa6, 0xa2, 0x06, 0x52, 0xa9, 0xf9, 0xa3, 0x37, 0xc1,
                0xa2, 0xf5, 0xb9, 0xc9,
            ]
        );
        verify_blake2b_lookup_hash(&archive).unwrap();

        let mut tampered = archive;
        // h[7] is outside Blake2b-256's 32-byte result, but it is consumed
        // by the second compression and therefore must be fail-closed.
        tampered.compression.initial_states[1][HASH_WORDS - 1] ^= 1;
        assert!(verify_blake2b_lookup_hash(&tampered).is_err());
    }
    #[test]
    fn xor_table_constraints_accept_scheduler_multiplicity() {
        let block = Blake2bSmtSingleBlock::leaf([0x11; 32], [0x22; 32]);
        let messages = [*block.message()];
        let (initial_states, hash_states, calls, chain_to_next) = fixed_smt_statement(&messages);
        let log_size = log_size_for_calls(&calls).unwrap();
        let scope = scope_columns(
            &messages,
            &[block.native_digest()],
            &initial_states,
            &hash_states,
            &chain_to_next,
            &calls,
            log_size,
        )
        .unwrap();
        let trace = trace_columns(&messages, &initial_states, &calls, log_size).unwrap();
        let multiplicity = xor_multiplicity_column(&trace, &scope);
        let xor = Blake2bCompressionByteXor::dummy();
        let (interaction, sum) = table_interaction_trace(&multiplicity, &xor);
        let pre = circle_evals(XOR_LOG_SIZE, xor_table())
            .into_iter()
            .map(|evaluation| evaluation.values.to_cpu())
            .collect::<Vec<_>>();
        let original = circle_evals(XOR_LOG_SIZE, vec![multiplicity])
            .into_iter()
            .map(|evaluation| evaluation.values.to_cpu())
            .collect::<Vec<_>>();
        let evals: TreeVec<Vec<Vec<M31>>> = TreeVec::new(vec![
            pre,
            original,
            interaction
                .iter()
                .map(|evaluation| evaluation.values.to_cpu())
                .collect(),
        ]);
        let borrowed: TreeVec<Vec<&Vec<M31>>> = (&evals).into();
        assert_constraints_on_trace(
            &borrowed,
            XOR_LOG_SIZE,
            |eval| {
                let _ = XorTableAir {
                    elements: xor.clone(),
                }
                .evaluate(eval);
            },
            sum,
        );
    }

    #[ignore = "slow prove (~20s); full gate runs `--include-ignored`"]
    #[test]
    fn scheduler_stark_proof_roundtrip() {
        let block = Blake2bSmtSingleBlock::leaf([0x11; 32], [0x22; 32]);
        let messages = [*block.message()];
        let (initial_states, hash_states, calls, chain_to_next) = fixed_smt_statement(&messages);
        let bytes = build_schedule_proof(
            &messages,
            &[block.native_digest()],
            &initial_states,
            &hash_states,
            &chain_to_next,
            &calls,
        )
        .unwrap();
        verify_schedule_proof(
            &messages,
            &[block.native_digest()],
            &initial_states,
            &hash_states,
            &chain_to_next,
            &calls,
            &bytes,
        )
        .unwrap();
    }

    #[ignore = "slow prove (~5s); full gate runs `--include-ignored`"]
    #[test]
    fn scheduler_component_proves_without_the_lookup_table_component() {
        // This isolates the scheduler's trace/LogUp ordering from the larger
        // 2^16 XOR-table component.  Its nonzero claimed sum is intentional:
        // the table component is what cancels it in the production proof.
        let block = Blake2bSmtSingleBlock::leaf([0x11; 32], [0x22; 32]);
        let messages = [*block.message()];
        let (initial_states, hash_states, calls, chain_to_next) = fixed_smt_statement(&messages);
        let log_size = log_size_for_calls(&calls).unwrap();
        let scope = scope_columns(
            &messages,
            &[block.native_digest()],
            &initial_states,
            &hash_states,
            &chain_to_next,
            &calls,
            log_size,
        )
        .unwrap();
        let trace = trace_columns(&messages, &initial_states, &calls, log_size).unwrap();
        // Without the 2^16-row XOR table this test's scheduler trace is the
        // largest committed tree.  Its cubic quotient is one log-degree bit
        // larger, so explicitly lift that small trace to the
        // composition commitment domain; the production proof obtains the
        // same lift from its XOR-table tree.
        let mut config = pcs_config();
        config.lifting_log_size = Some(log_size + 1 + config.fri_config.log_blowup_factor);
        let twiddles = crate::prover_context::simd_twiddles(
            (log_size + 3) + config.fri_config.log_blowup_factor,
        );
        let mut channel = Poseidon252Channel::default();
        mix_statement(
            &mut channel,
            &messages,
            &[block.native_digest()],
            &initial_states,
            &hash_states,
            &chain_to_next,
            &calls,
        );
        let mut scheme =
            CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
                config,
                &twiddles,
                crate::prover_context::simd_base_column_pool(),
            );
        scheme.set_store_polynomials_coefficients();
        {
            let mut tree = scheme.tree_builder();
            tree.extend_evals(circle_evals(log_size, scope.clone()));
            tree.commit(&mut channel);
        }
        {
            let mut tree = scheme.tree_builder();
            tree.extend_evals(circle_evals(log_size, trace.clone()));
            tree.commit(&mut channel);
        }
        let xor = Blake2bCompressionByteXor::draw(&mut channel);
        let (interaction, sum) = scheduler_interaction_trace(&trace, &scope, &xor, log_size);
        channel.mix_felts(&[sum]);
        {
            let mut tree = scheme.tree_builder();
            tree.extend_evals(interaction);
            tree.commit(&mut channel);
        }
        let ids = preprocessed_ids();
        let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
        let scheduler =
            FrameworkComponent::new(&mut allocator, SchedulerAir { log_size, xor }, sum);
        prove(
            &[&scheduler as &dyn ComponentProver<SimdBackend>],
            &mut channel,
            scheme,
        )
        .expect("scheduler component should prove on its native domain");
    }

    #[ignore = "slow prove (~90s); full gate runs `--include-ignored`"]
    #[test]
    fn compression_proof_roundtrip_binds_digest() {
        let block = Blake2bSmtSingleBlock::leaf([0x11; 32], [0x22; 32]);
        let archive = prove_blake2b_lookup_smt_single_block(&block, block.native_digest()).unwrap();
        verify_blake2b_lookup_compression(&archive).unwrap();
        let mut bad = archive.clone();
        bad.digests[0][0] ^= 1;
        assert!(verify_blake2b_lookup_compression(&bad).is_err());
    }

    fn valid_fixed_value_path() -> Blake2bSmtFixedValuePathWitness {
        let key = [0xa5; 32];
        let value = [0x5a; 32];
        let siblings = std::array::from_fn(|height| [height as u8; 32]);
        let mut witness = Blake2bSmtFixedValuePathWitness {
            key,
            value,
            siblings,
            nodes: [[0; 32]; SMT_FIXED_VALUE_OPENING_COMPRESSIONS],
            root: [0; 32],
        };
        witness.nodes[0] = Blake2bSmtSingleBlock::leaf(key, value).native_digest();
        for parent_height in 1..=SMT_PATH_SIBLINGS {
            let child = witness.nodes[parent_height - 1];
            let sibling = witness.siblings[parent_height - 1];
            witness.nodes[parent_height] = if witness.direction_bit(parent_height) {
                Blake2bSmtSingleBlock::internal(sibling, child).native_digest()
            } else {
                Blake2bSmtSingleBlock::internal(child, sibling).native_digest()
            };
        }
        witness.root = witness.nodes[SMT_PATH_SIBLINGS];
        witness
    }

    #[test]
    #[ignore = "proves the shared lookup batch for a full 257-compression fixed-value SMT path"]
    fn batched_fixed_value_smt_path_roundtrip_binds_root_and_siblings() {
        let witness = valid_fixed_value_path();
        let archive = prove_blake2b_lookup_smt_fixed_value_paths(&[witness]).unwrap();
        verify_blake2b_lookup_smt_fixed_value_paths(&archive).unwrap();
        let mut bad = archive;
        bad.paths[0].siblings[0][0] ^= 1;
        assert!(verify_blake2b_lookup_smt_fixed_value_paths(&bad).is_err());
    }

    #[test]
    fn batched_fixed_value_paths_reject_empty_or_detached_endpoints_before_proving() {
        assert!(prove_blake2b_lookup_smt_fixed_value_paths(&[]).is_err());

        let mut witness = valid_fixed_value_path();
        witness.root[0] ^= 1;
        assert!(prove_blake2b_lookup_smt_fixed_value_paths(&[witness]).is_err());
    }

    // =========================================================================
    // 性能扫描(#42 裁决支撑,2026-09-10):Blake2b lookup STARK vs
    // Poseidon252 v2 在同一 preimage 字节规模下的对比。用例与
    // `poseidon252_v2::tests::v2_perf_sweep_scaling_curve` 的 felt 规模对齐
    // (31 字节/felt):64B≈rules opening;1488B≈48 felts(轻热态真实桌);
    // 5952B≈192 felts;13888B≈448 felts(≈生产热态满牌组)。运行:
    //   cargo test -p poker_texas_air --release --lib blake2b_perf_sweep \
    //     -- --include-ignored --nocapture
    // =========================================================================

    #[test]
    #[ignore = "perf sweep (~2-4 min at --release); run with --include-ignored --nocapture"]
    fn blake2b_perf_sweep_vs_poseidon_scale() {
        use std::time::Instant;

        let cases: Vec<(&str, usize)> = vec![
            ("rules_64B", 64),
            ("table48f_1488B", 1488),
            ("table192f_5952B", 5952),
            ("table448f_13888B", 13888),
        ];
        println!(
            "{:<22} {:>8} {:>8} {:>10} {:>10} {:>10}",
            "case", "bytes", "blocks", "prove_ms", "verify_ms", "proof_kb"
        );
        for (name, len) in cases {
            let message: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

            let prove_start = Instant::now();
            let archive = prove_blake2b_lookup_hash(&message)
                .unwrap_or_else(|e| panic!("{name}: prove failed: {e}"));
            let prove_ms = prove_start.elapsed().as_secs_f64() * 1e3;

            let verify_start = Instant::now();
            verify_blake2b_lookup_hash(&archive)
                .unwrap_or_else(|e| panic!("{name}: verify failed: {e}"));
            let verify_ms = verify_start.elapsed().as_secs_f64() * 1e3;

            let blocks = archive.compression.messages.len();
            let proof_kb = borsh::to_vec(&archive)
                .map(|bytes| bytes.len() as f64 / 1024.0)
                .unwrap_or(f64::NAN);
            println!(
                "{:<22} {:>8} {:>8} {:>10.1} {:>10.1} {:>10.1}",
                name,
                len,
                blocks,
                prove_ms,
                verify_ms,
                proof_kb
            );
        }
    }
}
