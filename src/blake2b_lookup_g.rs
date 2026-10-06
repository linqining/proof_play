//! Lookup-backed Blake2b `G` AIR for the host-zero path.
//!
//! This component keeps the public six-input/four-output `G` statement in a
//! verifier-reconstructed scope and moves the byte XORs into LogUp relations.
//! It is deliberately independent of Cairo's generated AIR so it can be used
//! by the Stwo 2.3 compression scheduler in this workspace.  The component is
//! a real prove/verify boundary; the host only supplies the witness columns and
//! the public `G` statement, while the verifier reconstructs the scope and the
//! 2^16 XOR / 2^10 rotate tables.

#![allow(missing_docs)]

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::{VerificationError, verify};
use stwo::prover::backend::Column;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, PackedBaseField};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::{ComponentProver, ProvingError, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
    TraceLocationAllocator, relation,
};

use crate::error::{TexasAirError, TexasAirResult};

const MIN_LOG_SIZE: u32 = 4;
const XOR_LOG_SIZE: u32 = 16;
const ROTATE_LOG_SIZE: u32 = 10;
const XOR_ROWS: usize = 1 << XOR_LOG_SIZE;
const ROTATE_ROWS: usize = 1 << ROTATE_LOG_SIZE;
const WORD_BYTES: usize = 8;
const WORDS: usize = 14;
const INPUT_WORDS: usize = 6;
const OUTPUT_WORDS: usize = 4;
const XOR_LOOKUPS: usize = 40;
const INTERACTION_COLUMNS: usize = XOR_LOOKUPS.div_ceil(2);
const WORD_COLUMNS: usize = WORDS * WORD_BYTES;
const CARRY_BASE: usize = WORD_COLUMNS;
const CARRY_BIT_BASE: usize = CARRY_BASE + 4 * WORD_BYTES;
const CARRY_BIT_STRIDE: usize = 2 * WORD_BYTES;
const ROTATE_XOR_BASE: usize = CARRY_BIT_BASE + 4 * CARRY_BIT_STRIDE;
const ROTATE_CARRY_IN_BASE: usize = ROTATE_XOR_BASE + WORD_BYTES;
const ROTATE_CARRY_OUT_BASE: usize = ROTATE_CARRY_IN_BASE + WORD_BYTES;
const ACTIVE_COLUMN: usize = ROTATE_CARRY_OUT_BASE + WORD_BYTES;
const NUM_TRACE_COLUMNS: usize = ACTIVE_COLUMN + 1;
const SCOPE_ACTIVE_COLUMN: usize = 0;
const SCOPE_WORD_BASE: usize = 1;
const SCOPE_COLUMNS: usize = SCOPE_WORD_BASE + (INPUT_WORDS + OUTPUT_WORDS) * WORD_BYTES;

relation!(Blake2bByteXor, 3);
relation!(Blake2bRotateLeftOne, 4);

/// The six input words and four output words of one Blake2b G invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Blake2bGCall {
    pub input: [u64; INPUT_WORDS],
    pub output: [u64; OUTPUT_WORDS],
}

/// A serialized lookup-backed G proof.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedBlake2bGProof {
    pub log_size: u32,
    pub calls: Vec<Blake2bGCall>,
    pub stark_proof_bytes: Vec<u8>,
}

#[derive(Clone)]
struct Blake2bGUseAir {
    log_size: u32,
    xor: Blake2bByteXor,
    rotate: Blake2bRotateLeftOne,
}

#[derive(Clone)]
struct Blake2bXorTableAir {
    elements: Blake2bByteXor,
}

#[derive(Clone)]
struct Blake2bRotateTableAir {
    elements: Blake2bRotateLeftOne,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

fn word_base(word: usize) -> usize {
    word * WORD_BYTES
}

fn carry_base(addition: usize) -> usize {
    CARRY_BASE + addition * WORD_BYTES
}

fn carry_bit_base(addition: usize, byte: usize, bit: usize) -> usize {
    CARRY_BIT_BASE + addition * CARRY_BIT_STRIDE + byte * 2 + bit
}

fn u64_bytes(value: u64) -> [M31; WORD_BYTES] {
    value.to_le_bytes().map(u32::from).map(M31::from)
}

fn add_with_carries(a: u64, b: u64, extra: u64) -> (u64, [u8; WORD_BYTES]) {
    let aa = a.to_le_bytes();
    let bb = b.to_le_bytes();
    let xx = extra.to_le_bytes();
    let mut out = [0u8; WORD_BYTES];
    let mut carries = [0u8; WORD_BYTES];
    let mut carry = 0u16;
    for i in 0..WORD_BYTES {
        let sum = u16::from(aa[i]) + u16::from(bb[i]) + u16::from(xx[i]) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
        carries[i] = carry as u8;
    }
    (u64::from_le_bytes(out), carries)
}

fn make_call_row(call: &Blake2bGCall) -> Vec<M31> {
    let [a, b, c, d, x, y] = call.input;
    let (a1, carry0) = add_with_carries(a, b, x);
    let d1 = (d ^ a1).rotate_right(32);
    let (c1, carry1) = add_with_carries(c, d1, 0);
    let b1 = (b ^ c1).rotate_right(24);
    let (a2, carry2) = add_with_carries(a1, b1, y);
    let d2 = (d1 ^ a2).rotate_right(16);
    let (c2, carry3) = add_with_carries(c1, d2, 0);
    let z = b1 ^ c2;
    let b2 = z.rotate_left(1);

    debug_assert_eq!(call.output, [a2, b2, c2, d2]);
    let words = [a, b, c, d, x, y, a1, d1, c1, b1, a2, d2, c2, b2];
    let mut row = vec![M31::from(0u32); NUM_TRACE_COLUMNS];
    for (word, value) in words.into_iter().enumerate() {
        row[word_base(word)..word_base(word) + WORD_BYTES].copy_from_slice(&u64_bytes(value));
    }
    for (set, carries) in [carry0, carry1, carry2, carry3].into_iter().enumerate() {
        for (byte, carry) in carries.into_iter().enumerate() {
            row[carry_base(set) + byte] = M31::from(u32::from(carry));
            row[carry_bit_base(set, byte, 0)] = M31::from(u32::from(carry & 1));
            row[carry_bit_base(set, byte, 1)] = M31::from(u32::from((carry >> 1) & 1));
        }
    }
    row[ROTATE_XOR_BASE..ROTATE_XOR_BASE + WORD_BYTES].copy_from_slice(&u64_bytes(z));
    let z_bytes = z.to_le_bytes();
    let mut carry_in = [0u8; WORD_BYTES];
    let mut carry_out = [0u8; WORD_BYTES];
    for byte in 0..WORD_BYTES {
        carry_in[byte] = z_bytes[(byte + WORD_BYTES - 1) % WORD_BYTES] >> 7;
        carry_out[byte] = ((u16::from(z_bytes[byte]) * 2 + u16::from(carry_in[byte])) >> 8) as u8;
    }
    for byte in 0..WORD_BYTES {
        row[ROTATE_CARRY_IN_BASE + byte] = M31::from(u32::from(carry_in[byte]));
        row[ROTATE_CARRY_OUT_BASE + byte] = M31::from(u32::from(carry_out[byte]));
    }
    row[ACTIVE_COLUMN] = M31::from(1u32);
    row
}

fn make_trace(calls: &[Blake2bGCall], log_size: u32) -> Vec<BaseColumn> {
    let rows = 1usize << log_size;
    let mut columns = vec![vec![M31::from(0u32); rows]; NUM_TRACE_COLUMNS];
    for (row, call) in calls.iter().enumerate() {
        let values = make_call_row(call);
        for (column, value) in values.into_iter().enumerate() {
            columns[column][row] = value;
        }
    }
    columns
        .into_iter()
        .map(|values| BaseColumn::from_cpu(&values))
        .collect()
}

fn scope_columns(calls: &[Blake2bGCall], log_size: u32) -> Vec<BaseColumn> {
    let rows = 1usize << log_size;
    let mut columns = vec![vec![M31::from(0u32); rows]; SCOPE_COLUMNS];
    for (row, call) in calls.iter().enumerate() {
        columns[SCOPE_ACTIVE_COLUMN][row] = M31::from(1u32);
        let words = [
            call.input[0],
            call.input[1],
            call.input[2],
            call.input[3],
            call.input[4],
            call.input[5],
            call.output[0],
            call.output[1],
            call.output[2],
            call.output[3],
        ];
        for (word, value) in words.into_iter().enumerate() {
            for (byte, value) in u64_bytes(value).into_iter().enumerate() {
                columns[SCOPE_WORD_BASE + word * WORD_BYTES + byte][row] = value;
            }
        }
    }
    columns
        .into_iter()
        .map(|values| BaseColumn::from_cpu(&values))
        .collect()
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
                .map(|values| BaseColumn::from_cpu(&values))
                .collect()
        })
        .clone()
}

fn rotate_table() -> Vec<BaseColumn> {
    let mut columns = vec![Vec::with_capacity(ROTATE_ROWS); 4];
    for index in 0..ROTATE_ROWS {
        let z = (index & 0xff) as u32;
        let carry_in = ((index >> 8) & 1) as u32;
        let value = 2 * z + carry_in;
        let out = value & 0xff;
        let carry_out = value >> 8;
        columns[0].push(M31::from(z));
        columns[1].push(M31::from(carry_in));
        columns[2].push(M31::from(out));
        columns[3].push(M31::from(carry_out));
    }
    columns
        .into_iter()
        .map(|values| BaseColumn::from_cpu(&values))
        .collect()
}

fn circle_evals(
    log_size: u32,
    columns: Vec<BaseColumn>,
) -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
    let domain = stwo::core::poly::circle::CanonicCoset::new(log_size).circle_domain();
    columns
        .into_iter()
        // `BaseColumn` is consumed in the same packed row order as
        // `LogupTraceGenerator`; that generator already emits evaluations
        // tagged as `BitReversedOrder`.  Reversing here would desynchronise
        // table/multiplicity rows from the interaction trace.
        .map(|column| CircleEvaluation::<SimdBackend, M31, BitReversedOrder>::new(domain, column))
        .collect()
}

fn preprocessed_ids() -> &'static [PreProcessedColumnId] {
    static IDS: std::sync::OnceLock<Vec<PreProcessedColumnId>> = std::sync::OnceLock::new();
    IDS.get_or_init(build_preprocessed_ids).as_slice()
}

fn build_preprocessed_ids() -> Vec<PreProcessedColumnId> {
    let mut ids = Vec::with_capacity(SCOPE_COLUMNS + 7);
    ids.push(PreProcessedColumnId {
        id: "blake2b.g.scope.active.v1".into(),
    });
    for column in 0..SCOPE_COLUMNS - 1 {
        ids.push(PreProcessedColumnId {
            id: format!("blake2b.g.scope.word.{column}.v1").into(),
        });
    }
    for column in 0..3 {
        ids.push(PreProcessedColumnId {
            id: format!("blake2b.g.xor.table.{column}.v1").into(),
        });
    }
    for column in 0..4 {
        ids.push(PreProcessedColumnId {
            id: format!("blake2b.g.rotate.table.{column}.v1").into(),
        });
    }
    ids
}

fn preprocessed_trace(
    calls: &[Blake2bGCall],
    log_size: u32,
) -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
    let mut evals = circle_evals(log_size, scope_columns(calls, log_size));
    evals.extend(circle_evals(XOR_LOG_SIZE, xor_table()));
    evals.extend(circle_evals(ROTATE_LOG_SIZE, rotate_table()));
    evals
}

fn add_u8_sum<E: EvalAtRow>(
    eval: &mut E,
    gate: &E::F,
    a: &E::F,
    b: &E::F,
    extra: &E::F,
    out: &E::F,
    carry_in: &E::F,
    carry_out: &E::F,
    carry_bit0: &E::F,
    carry_bit1: &E::F,
) {
    let one: E::F = M31::from(1u32).into();
    let base: E::F = M31::from(256u32).into();
    let two: E::F = M31::from(2u32).into();
    eval.add_constraint(carry_bit0.clone() * (carry_bit0.clone() - one.clone()));
    eval.add_constraint(carry_bit1.clone() * (carry_bit1.clone() - one.clone()));
    eval.add_constraint(carry_out.clone() - carry_bit0.clone() - two * carry_bit1.clone());
    eval.add_constraint(
        gate.clone()
            * (a.clone() + b.clone() + extra.clone() + carry_in.clone()
                - out.clone()
                - base * carry_out.clone()),
    );
}

impl FrameworkEval for Blake2bGUseAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let columns: Vec<E::F> = (0..NUM_TRACE_COLUMNS)
            .map(|_| eval.next_trace_mask())
            .collect();
        let active = columns[ACTIVE_COLUMN].clone();
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(active.clone() * (active.clone() - one.clone()));
        let inactive = one - active.clone();
        for column in &columns[..ACTIVE_COLUMN] {
            eval.add_constraint(inactive.clone() * column.clone());
        }

        let ids = preprocessed_ids();
        let scope_active = eval.get_preprocessed_column(ids[SCOPE_ACTIVE_COLUMN].clone());
        eval.add_constraint(active.clone() * (scope_active - active.clone()));
        for word in 0..INPUT_WORDS {
            for byte in 0..WORD_BYTES {
                let scope = eval.get_preprocessed_column(
                    ids[SCOPE_WORD_BASE + word * WORD_BYTES + byte].clone(),
                );
                eval.add_constraint(
                    active.clone() * (columns[word_base(word) + byte].clone() - scope),
                );
            }
        }
        let output_words = [10usize, 13, 12, 11];
        for (output, &word) in output_words.iter().enumerate() {
            for byte in 0..WORD_BYTES {
                let scope = eval.get_preprocessed_column(
                    ids[SCOPE_WORD_BASE + (INPUT_WORDS + output) * WORD_BYTES + byte].clone(),
                );
                eval.add_constraint(
                    active.clone() * (columns[word_base(word) + byte].clone() - scope),
                );
            }
        }

        let zero: E::F = M31::from(0u32).into();
        let add_specs = [
            (0usize, 1usize, Some(4usize), 6usize, 0usize),
            (2usize, 7usize, None, 8usize, 1usize),
            (6usize, 9usize, Some(5usize), 10usize, 2usize),
            (8usize, 11usize, None, 12usize, 3usize),
        ];
        for &(a, b, extra, out, carry_set) in &add_specs {
            for byte in 0..WORD_BYTES {
                let extra_value = extra.map_or_else(
                    || zero.clone(),
                    |word| columns[word_base(word) + byte].clone(),
                );
                add_u8_sum(
                    &mut eval,
                    &active,
                    &columns[word_base(a) + byte],
                    &columns[word_base(b) + byte],
                    &extra_value,
                    &columns[word_base(out) + byte],
                    if byte == 0 {
                        &zero
                    } else {
                        &columns[carry_base(carry_set) + byte - 1]
                    },
                    &columns[carry_base(carry_set) + byte],
                    &columns[carry_bit_base(carry_set, byte, 0)],
                    &columns[carry_bit_base(carry_set, byte, 1)],
                );
            }
        }

        let xor_specs = [
            (6usize, 3usize, 7usize, 32usize),
            (1usize, 8usize, 9usize, 24usize),
        ];
        for &(a, b, out, rotation) in &xor_specs {
            let shift = rotation / WORD_BYTES;
            for byte in 0..WORD_BYTES {
                let source = (byte + shift) % WORD_BYTES;
                eval.add_to_relation(RelationEntry::new(
                    &self.xor,
                    E::EF::from(active.clone()),
                    &[
                        columns[word_base(a) + source].clone(),
                        columns[word_base(b) + source].clone(),
                        columns[word_base(out) + byte].clone(),
                    ],
                ));
            }
        }
        // d2 = ROTR16(d1 XOR a2).
        for byte in 0..WORD_BYTES {
            let source = (byte + 2) % WORD_BYTES;
            eval.add_to_relation(RelationEntry::new(
                &self.xor,
                E::EF::from(active.clone()),
                &[
                    columns[word_base(7) + source].clone(),
                    columns[word_base(10) + source].clone(),
                    columns[word_base(11) + byte].clone(),
                ],
            ));
        }
        // b2 = ROTL1(b1 XOR c2).  The XOR is looked up first; the rotate
        // table then constrains the carry between adjacent bytes.
        for byte in 0..WORD_BYTES {
            eval.add_to_relation(RelationEntry::new(
                &self.xor,
                E::EF::from(active.clone()),
                &[
                    columns[word_base(9) + byte].clone(),
                    columns[word_base(12) + byte].clone(),
                    columns[ROTATE_XOR_BASE + byte].clone(),
                ],
            ));
        }
        for byte in 0..WORD_BYTES {
            eval.add_to_relation(RelationEntry::new(
                &self.rotate,
                E::EF::from(active.clone()),
                &[
                    columns[ROTATE_XOR_BASE + byte].clone(),
                    columns[ROTATE_CARRY_IN_BASE + byte].clone(),
                    columns[word_base(13) + byte].clone(),
                    columns[ROTATE_CARRY_OUT_BASE + byte].clone(),
                ],
            ));
            eval.add_constraint(
                active.clone()
                    * (columns[ROTATE_CARRY_IN_BASE + ((byte + 1) % WORD_BYTES)].clone()
                        - columns[ROTATE_CARRY_OUT_BASE + byte].clone()),
            );
        }
        eval.finalize_logup_in_pairs();
        eval
    }
}

impl FrameworkEval for Blake2bXorTableAir {
    fn log_size(&self) -> u32 {
        XOR_LOG_SIZE
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        XOR_LOG_SIZE + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let ids = preprocessed_ids();
        let a = eval.get_preprocessed_column(ids[SCOPE_COLUMNS].clone());
        let b = eval.get_preprocessed_column(ids[SCOPE_COLUMNS + 1].clone());
        let c = eval.get_preprocessed_column(ids[SCOPE_COLUMNS + 2].clone());
        let multiplicity = eval.next_trace_mask();
        eval.add_to_relation(RelationEntry::new(
            &self.elements,
            -E::EF::from(multiplicity),
            &[a, b, c],
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

impl FrameworkEval for Blake2bRotateTableAir {
    fn log_size(&self) -> u32 {
        ROTATE_LOG_SIZE
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        ROTATE_LOG_SIZE + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let ids = preprocessed_ids();
        let base = SCOPE_COLUMNS + 3;
        let tuple = [
            eval.get_preprocessed_column(ids[base].clone()),
            eval.get_preprocessed_column(ids[base + 1].clone()),
            eval.get_preprocessed_column(ids[base + 2].clone()),
            eval.get_preprocessed_column(ids[base + 3].clone()),
        ];
        let multiplicity = eval.next_trace_mask();
        eval.add_to_relation(RelationEntry::new(
            &self.elements,
            -E::EF::from(multiplicity),
            &tuple,
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

fn pack_column(column: &BaseColumn, vector_row: usize) -> PackedBaseField {
    let mut values = [M31::from(0u32); stwo::prover::backend::simd::m31::N_LANES];
    for (lane, value) in values.iter_mut().enumerate() {
        *value = column.at(vector_row * stwo::prover::backend::simd::m31::N_LANES + lane);
    }
    PackedBaseField::from_array(values)
}

enum PackedLookup {
    Xor([PackedBaseField; 3]),
    Rotate([PackedBaseField; 4]),
}

fn g_lookup_tuples(columns: &[BaseColumn], vector_row: usize) -> Vec<PackedLookup> {
    let p = |column: usize| pack_column(&columns[column], vector_row);
    let mut result = Vec::with_capacity(XOR_LOOKUPS);
    let normal = [
        (6usize, 3usize, 7usize, 4usize),
        (1usize, 8usize, 9usize, 3usize),
        (7usize, 10usize, 11usize, 2usize),
    ];
    for (a, b, out, shift) in normal {
        for byte in 0..WORD_BYTES {
            let source = (byte + shift) % WORD_BYTES;
            result.push(PackedLookup::Xor([
                p(word_base(a) + source),
                p(word_base(b) + source),
                p(word_base(out) + byte),
            ]));
        }
    }
    for byte in 0..WORD_BYTES {
        result.push(PackedLookup::Xor([
            p(word_base(9) + byte),
            p(word_base(12) + byte),
            p(ROTATE_XOR_BASE + byte),
        ]));
    }
    for byte in 0..WORD_BYTES {
        result.push(PackedLookup::Rotate([
            p(ROTATE_XOR_BASE + byte),
            p(ROTATE_CARRY_IN_BASE + byte),
            p(word_base(13) + byte),
            p(ROTATE_CARRY_OUT_BASE + byte),
        ]));
    }
    result
}

fn g_interaction_trace(
    columns: &[BaseColumn],
    xor: &Blake2bByteXor,
    rotate: &Blake2bRotateLeftOne,
    log_size: u32,
) -> (
    Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>>,
    SecureField,
) {
    let mut generator = LogupTraceGenerator::new(log_size);
    for pair in 0..INTERACTION_COLUMNS {
        let mut col = generator.new_col();
        for vector_row in 0..(1usize << (log_size - LOG_N_LANES)) {
            let tuples = g_lookup_tuples(columns, vector_row);
            let active = PackedSecureField::from(pack_column(&columns[ACTIVE_COLUMN], vector_row));
            let d0: PackedSecureField = match &tuples[pair * 2] {
                PackedLookup::Xor(tuple) => xor.combine(tuple),
                PackedLookup::Rotate(tuple) => rotate.combine(tuple),
            };
            let d1: PackedSecureField = match &tuples[pair * 2 + 1] {
                PackedLookup::Xor(tuple) => xor.combine(tuple),
                PackedLookup::Rotate(tuple) => rotate.combine(tuple),
            };
            col.write_frac(vector_row, active * (d0 + d1), d0 * d1);
        }
        col.finalize_col();
    }
    generator.finalize_last()
}

fn table_interaction_trace(
    columns: &[BaseColumn],
    elements: &Blake2bByteXor,
    log_size: u32,
) -> (
    Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>>,
    SecureField,
) {
    let mut multiplicity = vec![M31::from(0u32); XOR_ROWS];
    for row in 0..(1usize << log_size) {
        if columns[ACTIVE_COLUMN].at(row) == M31::from(1u32) {
            for tuple in g_lookup_tuples_scalar(columns, row).into_iter() {
                let PackedLookup::Xor(tuple) = tuple else {
                    continue;
                };
                let a = tuple[0].to_array()[0].0 as usize;
                let b = tuple[1].to_array()[0].0 as usize;
                multiplicity[(a << 8) | b] += M31::from(1u32);
            }
        }
    }
    let table = xor_table();
    let multiplicity_column = BaseColumn::from_cpu(&multiplicity);
    let mut generator = LogupTraceGenerator::new(XOR_LOG_SIZE);
    let mut col = generator.new_col();
    for vector_row in 0..(XOR_ROWS / stwo::prover::backend::simd::m31::N_LANES) {
        let tuple = [
            pack_column(&table[0], vector_row),
            pack_column(&table[1], vector_row),
            pack_column(&table[2], vector_row),
        ];
        let denominator = elements.combine(&tuple);
        let numerator = PackedSecureField::from(-multiplicity_column.data[vector_row]);
        col.write_frac(vector_row, numerator, denominator);
    }
    col.finalize_col();
    generator.finalize_last()
}

fn rotate_table_interaction_trace(
    columns: &[BaseColumn],
    elements: &Blake2bRotateLeftOne,
) -> (
    Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>>,
    SecureField,
) {
    let mut multiplicity = vec![M31::from(0u32); ROTATE_ROWS];
    for row in 0..columns[ACTIVE_COLUMN].len() {
        if columns[ACTIVE_COLUMN].at(row) == M31::from(1u32) {
            for tuple in g_lookup_tuples_scalar(columns, row).into_iter() {
                let PackedLookup::Rotate(tuple) = tuple else {
                    continue;
                };
                let z = tuple[0].to_array()[0].0 as usize;
                let cin = tuple[1].to_array()[0].0 as usize;
                multiplicity[z | (cin << 8)] += M31::from(1u32);
            }
        }
    }
    let table = rotate_table();
    let multiplicity_column = BaseColumn::from_cpu(&multiplicity);
    let mut generator = LogupTraceGenerator::new(ROTATE_LOG_SIZE);
    let mut col = generator.new_col();
    for vector_row in 0..(ROTATE_ROWS / stwo::prover::backend::simd::m31::N_LANES) {
        let tuple = [
            pack_column(&table[0], vector_row),
            pack_column(&table[1], vector_row),
            pack_column(&table[2], vector_row),
            pack_column(&table[3], vector_row),
        ];
        let denominator = elements.combine(&tuple);
        let numerator = PackedSecureField::from(-multiplicity_column.data[vector_row]);
        col.write_frac(vector_row, numerator, denominator);
    }
    col.finalize_col();
    generator.finalize_last()
}

fn g_lookup_tuples_scalar(columns: &[BaseColumn], row: usize) -> Vec<PackedLookup> {
    let p = |column: usize| {
        PackedBaseField::from_array(
            [columns[column].at(row); stwo::prover::backend::simd::m31::N_LANES],
        )
    };
    let mut result = Vec::with_capacity(XOR_LOOKUPS);
    let normal = [
        (6usize, 3usize, 7usize, 4usize),
        (1usize, 8usize, 9usize, 3usize),
        (7usize, 10usize, 11usize, 2usize),
    ];
    for (a, b, out, shift) in normal {
        for byte in 0..WORD_BYTES {
            let source = (byte + shift) % WORD_BYTES;
            result.push(PackedLookup::Xor([
                p(word_base(a) + source),
                p(word_base(b) + source),
                p(word_base(out) + byte),
            ]));
        }
    }
    for byte in 0..WORD_BYTES {
        result.push(PackedLookup::Xor([
            p(word_base(9) + byte),
            p(word_base(12) + byte),
            p(ROTATE_XOR_BASE + byte),
        ]));
    }
    for byte in 0..WORD_BYTES {
        result.push(PackedLookup::Rotate([
            p(ROTATE_XOR_BASE + byte),
            p(ROTATE_CARRY_IN_BASE + byte),
            p(word_base(13) + byte),
            p(ROTATE_CARRY_OUT_BASE + byte),
        ]));
    }
    result
}

fn mix_calls(channel: &mut Poseidon252Channel, calls: &[Blake2bGCall]) {
    channel.mix_u64(calls.len() as u64);
    for call in calls {
        for value in call.input {
            channel.mix_u64(value);
        }
        for value in call.output {
            channel.mix_u64(value);
        }
    }
}

fn log_size_for_calls(calls: &[Blake2bGCall]) -> TexasAirResult<u32> {
    if calls.is_empty() {
        return Err(TexasAirError::SpecViolation(
            "Blake2b G batch must not be empty".into(),
        ));
    }
    let rows = calls.len().next_power_of_two();
    Ok(rows.ilog2().max(MIN_LOG_SIZE))
}

fn pcs_config() -> stwo::core::pcs::PcsConfig {
    crate::prover_context::protocol_pcs_config()
}

/// Prove a batch of lookup-constrained Blake2b G calls.
pub fn prove_blake2b_g(calls: &[Blake2bGCall]) -> TexasAirResult<ArchivedBlake2bGProof> {
    let log_size = log_size_for_calls(calls)?;
    let trace = make_trace(calls, log_size);
    let preprocessed = preprocessed_trace(calls, log_size);
    let config = pcs_config();
    let max_log = XOR_LOG_SIZE.max(ROTATE_LOG_SIZE.max(log_size));
    let twiddles =
        crate::prover_context::simd_twiddles(max_log + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_calls(&mut channel, calls);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    // G, table, and rotate components intentionally use mixed trace domains
    // (4, 2^16, and 2^10).  Stwo therefore selects `ExtendToEvalDomain`; keep
    // coefficients for the extension step instead of relying on subdomains.
    scheme.set_store_polynomials_coefficients();
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(preprocessed);
        tree.commit(&mut channel);
    }
    {
        let mut tree = scheme.tree_builder();
        let mut evals = circle_evals(log_size, trace.clone());
        let mut xor_mult = vec![M31::from(0u32); XOR_ROWS];
        let mut rotate_mult = vec![M31::from(0u32); ROTATE_ROWS];
        for row in 0..calls.len() {
            for tuple in g_lookup_tuples_scalar(&trace, row).into_iter() {
                match tuple {
                    PackedLookup::Xor(tuple) => {
                        let a = tuple[0].to_array()[0].0 as usize;
                        let b = tuple[1].to_array()[0].0 as usize;
                        xor_mult[(a << 8) | b] += M31::from(1u32);
                    }
                    PackedLookup::Rotate(tuple) => {
                        let z = tuple[0].to_array()[0].0 as usize;
                        let cin = tuple[1].to_array()[0].0 as usize;
                        rotate_mult[z | (cin << 8)] += M31::from(1u32);
                    }
                }
            }
        }
        evals.extend(circle_evals(
            XOR_LOG_SIZE,
            vec![BaseColumn::from_cpu(&xor_mult)],
        ));
        evals.extend(circle_evals(
            ROTATE_LOG_SIZE,
            vec![BaseColumn::from_cpu(&rotate_mult)],
        ));
        tree.extend_evals(evals);
        tree.commit(&mut channel);
    }
    let xor = Blake2bByteXor::draw(&mut channel);
    let rotate = Blake2bRotateLeftOne::draw(&mut channel);
    let (g_interaction, g_sum) = g_interaction_trace(&trace, &xor, &rotate, log_size);
    let (xor_interaction, xor_sum) = table_interaction_trace(&trace, &xor, log_size);
    let (rotate_interaction, rotate_sum) = rotate_table_interaction_trace(&trace, &rotate);
    channel.mix_felts(&[g_sum, xor_sum, rotate_sum]);
    {
        let mut tree = scheme.tree_builder();
        let mut interactions = g_interaction;
        interactions.extend(xor_interaction);
        interactions.extend(rotate_interaction);
        tree.extend_evals(interactions);
        tree.commit(&mut channel);
    }
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let g_component = FrameworkComponent::new(
        &mut allocator,
        Blake2bGUseAir {
            log_size,
            xor: xor.clone(),
            rotate: rotate.clone(),
        },
        g_sum,
    );
    let xor_component = FrameworkComponent::new(
        &mut allocator,
        Blake2bXorTableAir {
            elements: xor.clone(),
        },
        xor_sum,
    );
    let rotate_component = FrameworkComponent::new(
        &mut allocator,
        Blake2bRotateTableAir { elements: rotate },
        rotate_sum,
    );
    let proof = prove(
        &[
            &g_component as &dyn ComponentProver<SimdBackend>,
            &xor_component as &dyn ComponentProver<SimdBackend>,
            &rotate_component as &dyn ComponentProver<SimdBackend>,
        ],
        &mut channel,
        scheme,
    )
    .map_err(|error: ProvingError| TexasAirError::StwoProverError(error.to_string()))?;
    Ok(ArchivedBlake2bGProof {
        log_size,
        calls: calls.to_vec(),
        stark_proof_bytes: options()
            .serialize(&proof)
            .map_err(|e| TexasAirError::SerializationError(e.to_string()))?,
    })
}

/// Verify a lookup-backed Blake2b G batch from its public scope only.
pub fn verify_blake2b_g(archive: &ArchivedBlake2bGProof) -> TexasAirResult<()> {
    let expected_log = log_size_for_calls(&archive.calls)?;
    if expected_log != archive.log_size {
        return Err(TexasAirError::SpecViolation(
            "Blake2b G archive log size mismatch".into(),
        ));
    }
    let proof: StarkProof<Poseidon252MerkleHasher> = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    let config = pcs_config();
    let preprocessed = preprocessed_trace(&archive.calls, archive.log_size);
    let max_log = XOR_LOG_SIZE.max(ROTATE_LOG_SIZE.max(archive.log_size));
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
        tree.extend_evals(preprocessed);
        tree.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Blake2b G public scope commitment mismatch".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_calls(&mut channel, &archive.calls);
    let mut scheme =
        stwo::core::pcs::CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    let ids = preprocessed_ids();
    let mut pre_sizes = vec![archive.log_size; SCOPE_COLUMNS];
    pre_sizes.extend([XOR_LOG_SIZE; 3]);
    pre_sizes.extend([ROTATE_LOG_SIZE; 4]);
    scheme.commit(proof.commitments[0], &pre_sizes, &mut channel);
    let mut original_sizes = vec![archive.log_size; NUM_TRACE_COLUMNS];
    original_sizes.extend([XOR_LOG_SIZE, ROTATE_LOG_SIZE]);
    scheme.commit(proof.commitments[1], &original_sizes, &mut channel);
    let xor = Blake2bByteXor::draw(&mut channel);
    let rotate = Blake2bRotateLeftOne::draw(&mut channel);
    // Reconstruct the original trace only for its multiplicity-column sizes;
    // the proof itself supplies the committed values.
    let trace = make_trace(&archive.calls, archive.log_size);
    let (g_interaction, g_sum) = g_interaction_trace(&trace, &xor, &rotate, archive.log_size);
    let (xor_interaction, xor_sum) = table_interaction_trace(&trace, &xor, archive.log_size);
    let (rotate_interaction, rotate_sum) = rotate_table_interaction_trace(&trace, &rotate);
    let _ = (g_interaction, xor_interaction, rotate_interaction);
    channel.mix_felts(&[g_sum, xor_sum, rotate_sum]);
    let mut interaction_sizes = vec![archive.log_size; INTERACTION_COLUMNS * 4];
    interaction_sizes.extend([XOR_LOG_SIZE; 4]);
    interaction_sizes.extend([ROTATE_LOG_SIZE; 4]);
    scheme.commit(proof.commitments[2], &interaction_sizes, &mut channel);
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let g_component = FrameworkComponent::new(
        &mut allocator,
        Blake2bGUseAir {
            log_size: archive.log_size,
            xor: xor.clone(),
            rotate: rotate.clone(),
        },
        g_sum,
    );
    let xor_component = FrameworkComponent::new(
        &mut allocator,
        Blake2bXorTableAir {
            elements: xor.clone(),
        },
        xor_sum,
    );
    let rotate_component = FrameworkComponent::new(
        &mut allocator,
        Blake2bRotateTableAir { elements: rotate },
        rotate_sum,
    );
    verify(
        &[&g_component, &xor_component, &rotate_component],
        &mut channel,
        &mut scheme,
        proof,
    )
    .map_err(|error: VerificationError| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    const INPUT: [u64; INPUT_WORDS] = [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
    ];

    const OUTPUT: [u64; OUTPUT_WORDS] = [
        0x2133_0908_09c4_3c88,
        0xd625_5124_4d4a_7047,
        0xe4bf_119c_9eb2_e576,
        0x2edf_5843_cced_daf4,
    ];

    #[test]
    fn g_trace_satisfies_each_air_constraint() {
        let call = Blake2bGCall {
            input: INPUT,
            output: OUTPUT,
        };
        let log_size = log_size_for_calls(&[call]).unwrap();
        let trace = make_trace(&[call], log_size);
        let xor = Blake2bByteXor::dummy();
        let rotate = Blake2bRotateLeftOne::dummy();
        let (interaction, sum) = g_interaction_trace(&trace, &xor, &rotate, log_size);
        let evals: TreeVec<Vec<Vec<M31>>> = TreeVec::new(vec![
            scope_columns(&[call], log_size)
                .iter()
                .map(|column| column.to_cpu())
                .collect::<Vec<_>>(),
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
                let _ = Blake2bGUseAir {
                    log_size,
                    xor: xor.clone(),
                    rotate: rotate.clone(),
                }
                .evaluate(eval);
            },
            sum,
        );
    }

    #[test]
    fn xor_table_trace_satisfies_each_air_constraint() {
        let call = Blake2bGCall {
            input: INPUT,
            output: OUTPUT,
        };
        let log_size = log_size_for_calls(&[call]).unwrap();
        let trace = make_trace(&[call], log_size);
        let xor = Blake2bByteXor::dummy();
        let rotate = Blake2bRotateLeftOne::dummy();
        let (interaction, sum) = table_interaction_trace(&trace, &xor, log_size);
        let mut multiplicity = vec![M31::from(0u32); XOR_ROWS];
        for row in 0..(1usize << log_size) {
            if trace[ACTIVE_COLUMN].at(row) == M31::from(1u32) {
                for tuple in g_lookup_tuples_scalar(&trace, row) {
                    let PackedLookup::Xor(tuple) = tuple else {
                        continue;
                    };
                    let a = tuple[0].to_array()[0].0 as usize;
                    let b = tuple[1].to_array()[0].0 as usize;
                    multiplicity[(a << 8) | b] += M31::from(1u32);
                }
            }
        }
        let pre = circle_evals(XOR_LOG_SIZE, xor_table())
            .into_iter()
            .map(|evaluation| evaluation.values.to_cpu())
            .collect::<Vec<_>>();
        let original = circle_evals(XOR_LOG_SIZE, vec![BaseColumn::from_cpu(&multiplicity)])
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
                let _ = Blake2bXorTableAir {
                    elements: xor.clone(),
                }
                .evaluate(eval);
            },
            sum,
        );
        let _ = rotate;
    }

    #[ignore = "slow prove (~20s); full gate runs `--include-ignored`"]
    #[test]
    fn g_call_known_answer_and_proof_roundtrip() {
        let call = Blake2bGCall {
            input: INPUT,
            output: OUTPUT,
        };
        assert_eq!(
            make_call_row(&call)[word_base(10)..word_base(10) + WORD_BYTES],
            u64_bytes(OUTPUT[0])
        );
        let archive = prove_blake2b_g(&[call]).expect("G witness should prove");
        verify_blake2b_g(&archive).expect("G proof should verify");

        let mut tampered = archive.clone();
        tampered.calls[0].output[0] ^= 1;
        assert!(verify_blake2b_g(&tampered).is_err());
    }
}
