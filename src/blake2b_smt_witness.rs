//! Fixed-width inputs for the production Blake2b sparse-Merkle compression AIR.
//!
//! `poker_l1` hashes an internal node as `H(0x01 || left || right)` and a
//! fixed 32-byte leaf value as `H(0x00 || key || value)`.  Both are a single
//! final 65-byte Blake2b-256 block.  This module fixes the byte order and
//! BLAKE2b compression flags for that common case before the optimized
//! multi-component AIR is wired into admission.
//!
//! This is deliberately only a witness ABI and native test oracle.  Calling
//! [`Blake2bSmtSingleBlock::native_digest`] is never a host-zero verification
//! step; the future AIR must constrain the same compression input and expose
//! its digest as a public statement limb sequence.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

/// Blake2b's byte block size.
pub const BLAKE2B_BLOCK_BYTES: usize = 128;
/// Digest size used by the L1 sparse-Merkle tree.
pub const BLAKE2B_256_DIGEST_BYTES: usize = 32;
/// Encoded byte length of a non-empty fixed-width SMT leaf or internal node.
pub const SMT_SINGLE_BLOCK_INPUT_BYTES: usize = 65;
/// One non-empty fixed-value leaf plus all 256 internal hashes in an L1 SMT
/// inclusion opening.
pub const SMT_FIXED_VALUE_OPENING_COMPRESSIONS: usize = 257;
/// Number of internal sibling values in a complete L1 SMT path.
pub const SMT_PATH_SIBLINGS: usize = 256;

/// Domain byte used by an L1 non-empty sparse-Merkle leaf.
pub const SMT_LEAF_DOMAIN: u8 = 0x00;
/// Domain byte used by an L1 sparse-Merkle internal node.
pub const SMT_INTERNAL_DOMAIN: u8 = 0x01;

/// BLAKE2b IV words in the little-endian word order used by its compression
/// function.
pub const BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// Blake2b-256's unkeyed parameter word (`digest_length=32`, `fanout=1`,
/// `depth=1`), XORed into the first IV word before the first compression.
pub const BLAKE2B_256_PARAMETER_WORD: u64 = 0x0000_0000_0101_0020;

/// BLAKE2b's twelve message-word permutations, one per compression round.
///
/// The optimized AIR component must use this table as a fixed/preprocessed
/// relation.  It is public here so the trace generator, component and test
/// vectors cannot silently disagree about the round order.
pub const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Fixed compression shape used by the L1 sparse-Merkle domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blake2bSmtSingleBlockKind {
    /// `H(0x00 || key || value)` for a 32-byte non-empty leaf value.
    Leaf,
    /// `H(0x01 || left || right)` for an internal sparse-Merkle node.
    Internal,
}

/// One final, unkeyed Blake2b-256 compression input suitable for a fixed-width
/// AIR trace row.
///
/// The `message` is zero-padded to 128 bytes.  `input_len` is always 65,
/// `counter` is therefore 65, and `is_last_block` is always true.  Exposing
/// all of those fields prevents an AIR prover from changing Blake2b padding or
/// counter semantics while keeping the visible domain bytes unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blake2bSmtSingleBlock {
    kind: Blake2bSmtSingleBlockKind,
    message: [u8; BLAKE2B_BLOCK_BYTES],
}

/// Fixed-width witness layout for a non-empty, 32-byte-valued L1 SMT opening.
///
/// This is a *trace witness*, not a host verifier.  The `nodes` values are
/// deliberately prover supplied: the future Blake2b AIR must prove that node
/// zero is the leaf compression and that every following node is the correctly
/// ordered internal compression.  The final entry is merely tied to the public
/// `root` here so it cannot drift from the statement passed to that AIR.
///
/// The current L1 hot-table object is variable-length and therefore cannot use
/// this layout.  It is intended for the fixed-width table-commitment leaf of a
/// new host-zero epoch, and for fixed 32-byte receipt/transaction leaves.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Blake2bSmtFixedValuePathWitness {
    /// Sparse-Merkle key, in the exact big-endian bit order used by L1.
    pub key: [u8; BLAKE2B_256_DIGEST_BYTES],
    /// Fixed-width leaf value authenticated at `key`.
    pub value: [u8; BLAKE2B_256_DIGEST_BYTES],
    /// Siblings from leaf height zero through root height 255.
    pub siblings: [[u8; BLAKE2B_256_DIGEST_BYTES]; SMT_PATH_SIBLINGS],
    /// Leaf hash followed by each successive parent hash.  These values must
    /// be constrained by the AIR and are not native validation results.
    pub nodes: [[u8; BLAKE2B_256_DIGEST_BYTES]; SMT_FIXED_VALUE_OPENING_COMPRESSIONS],
    /// Public L1 state root that must equal `nodes[256]`.
    pub root: [u8; BLAKE2B_256_DIGEST_BYTES],
}

impl Blake2bSmtFixedValuePathWitness {
    /// Return the L1 path-direction bit for a parent at height `1..=256`.
    ///
    /// L1 stores siblings bottom-up, while its key-bit convention is
    /// big-endian (`bit 0 = key[0]` MSB).  Consequently the first parent uses
    /// bit 255 and the final root parent uses bit 0.
    #[must_use]
    pub const fn direction_bit(&self, parent_height: usize) -> bool {
        assert!(parent_height > 0 && parent_height <= SMT_PATH_SIBLINGS);
        let bit_index = SMT_PATH_SIBLINGS - parent_height;
        let byte_index = bit_index / 8;
        let bit_in_byte = 7 - (bit_index % 8);
        ((self.key[byte_index] >> bit_in_byte) & 1) == 1
    }

    /// Return the 257 fixed Blake2b compression blocks that the AIR must
    /// constrain for this opening.
    ///
    /// This method only expands fixed bytes and selects left/right order from
    /// the key. It performs no hash computation and must not be confused with
    /// proof verification.
    #[must_use]
    pub fn compression_blocks(
        &self,
    ) -> [Blake2bSmtSingleBlock; SMT_FIXED_VALUE_OPENING_COMPRESSIONS] {
        std::array::from_fn(|index| {
            if index == 0 {
                Blake2bSmtSingleBlock::leaf(self.key, self.value)
            } else {
                let child = self.nodes[index - 1];
                let sibling = self.siblings[index - 1];
                if self.direction_bit(index) {
                    Blake2bSmtSingleBlock::internal(sibling, child)
                } else {
                    Blake2bSmtSingleBlock::internal(child, sibling)
                }
            }
        })
    }

    /// Whether the terminal trace node matches the public root endpoint.
    ///
    /// This is a cheap structural assertion useful before allocating a trace.
    /// It does **not** authenticate any hash relation; only the Blake2b AIR
    /// can establish that the nodes actually lead to this root.
    #[must_use]
    pub fn terminal_node_matches_root(&self) -> bool {
        self.nodes[SMT_PATH_SIBLINGS] == self.root
    }
}

impl Blake2bSmtSingleBlock {
    /// Construct `H(0x00 || key || value)` for a fixed 32-byte leaf value.
    #[must_use]
    pub fn leaf(key: [u8; 32], value: [u8; 32]) -> Self {
        let mut message = [0u8; BLAKE2B_BLOCK_BYTES];
        message[0] = SMT_LEAF_DOMAIN;
        message[1..33].copy_from_slice(&key);
        message[33..65].copy_from_slice(&value);
        Self {
            kind: Blake2bSmtSingleBlockKind::Leaf,
            message,
        }
    }

    /// Construct `H(0x01 || left || right)` for an internal node.
    #[must_use]
    pub fn internal(left: [u8; 32], right: [u8; 32]) -> Self {
        let mut message = [0u8; BLAKE2B_BLOCK_BYTES];
        message[0] = SMT_INTERNAL_DOMAIN;
        message[1..33].copy_from_slice(&left);
        message[33..65].copy_from_slice(&right);
        Self {
            kind: Blake2bSmtSingleBlockKind::Internal,
            message,
        }
    }

    /// Return the L1 domain represented by this row.
    #[must_use]
    pub const fn kind(&self) -> Blake2bSmtSingleBlockKind {
        self.kind
    }

    /// Return the complete 128-byte zero-padded Blake2b message block.
    #[must_use]
    pub const fn message(&self) -> &[u8; BLAKE2B_BLOCK_BYTES] {
        &self.message
    }

    /// Return the semantic input length used in the final Blake2b counter.
    #[must_use]
    pub const fn input_len(&self) -> u8 {
        SMT_SINGLE_BLOCK_INPUT_BYTES as u8
    }

    /// Return the total-byte counter entering this final compression.
    #[must_use]
    pub const fn counter(&self) -> u128 {
        SMT_SINGLE_BLOCK_INPUT_BYTES as u128
    }

    /// This witness is exactly one final block.
    #[must_use]
    pub const fn is_last_block(&self) -> bool {
        true
    }

    /// Return the little-endian message words consumed by BLAKE2b's `G`
    /// rounds.  This is the word layout an AIR compression component must use.
    #[must_use]
    pub fn message_words(&self) -> [u64; 16] {
        std::array::from_fn(|index| {
            let start = index * 8;
            u64::from_le_bytes(
                self.message[start..start + 8]
                    .try_into()
                    .expect("128-byte message always has sixteen words"),
            )
        })
    }

    /// Return BLAKE2b-256's initialized chaining value before this block.
    #[must_use]
    pub fn initial_state_words(&self) -> [u64; 8] {
        let mut state = BLAKE2B_IV;
        state[0] ^= BLAKE2B_256_PARAMETER_WORD;
        state
    }

    /// Compute the expected digest with the native reference implementation.
    ///
    /// This exists only for trace generation tests.  Admission must verify the
    /// equivalent compression relation through a STARK, not by calling this
    /// method.
    #[must_use]
    pub fn native_digest(&self) -> [u8; BLAKE2B_256_DIGEST_BYTES] {
        let mut hasher =
            Blake2bVar::new(BLAKE2B_256_DIGEST_BYTES).expect("32-byte Blake2b output is valid");
        hasher.update(&self.message[..SMT_SINGLE_BLOCK_INPUT_BYTES]);
        let mut output = [0u8; BLAKE2B_256_DIGEST_BYTES];
        hasher
            .finalize_variable(&mut output)
            .expect("32-byte Blake2b output is valid");
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::object_model::{SparseMerkleTree, internal_hash, leaf_hash};

    /// The BLAKE2b compression function used only to validate the *witness
    /// ABI*.  It intentionally has no production caller: a native result
    /// cannot be used to admit an AIR transition.
    fn reference_compress_256(
        message: [u8; BLAKE2B_BLOCK_BYTES],
        counter: u128,
        last_block: bool,
    ) -> [u8; BLAKE2B_256_DIGEST_BYTES] {
        fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(63);
        }

        let message_words: [u64; 16] = std::array::from_fn(|index| {
            let start = index * 8;
            u64::from_le_bytes(message[start..start + 8].try_into().unwrap())
        });
        let mut h = BLAKE2B_IV;
        h[0] ^= BLAKE2B_256_PARAMETER_WORD;
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&h);
        v[8..].copy_from_slice(&BLAKE2B_IV);
        v[12] ^= counter as u64;
        v[13] ^= (counter >> 64) as u64;
        if last_block {
            v[14] = !v[14];
        }
        for sigma in BLAKE2B_SIGMA {
            g(
                &mut v,
                0,
                4,
                8,
                12,
                message_words[sigma[0]],
                message_words[sigma[1]],
            );
            g(
                &mut v,
                1,
                5,
                9,
                13,
                message_words[sigma[2]],
                message_words[sigma[3]],
            );
            g(
                &mut v,
                2,
                6,
                10,
                14,
                message_words[sigma[4]],
                message_words[sigma[5]],
            );
            g(
                &mut v,
                3,
                7,
                11,
                15,
                message_words[sigma[6]],
                message_words[sigma[7]],
            );
            g(
                &mut v,
                0,
                5,
                10,
                15,
                message_words[sigma[8]],
                message_words[sigma[9]],
            );
            g(
                &mut v,
                1,
                6,
                11,
                12,
                message_words[sigma[10]],
                message_words[sigma[11]],
            );
            g(
                &mut v,
                2,
                7,
                8,
                13,
                message_words[sigma[12]],
                message_words[sigma[13]],
            );
            g(
                &mut v,
                3,
                4,
                9,
                14,
                message_words[sigma[14]],
                message_words[sigma[15]],
            );
        }
        for index in 0..8 {
            h[index] ^= v[index] ^ v[index + 8];
        }
        let mut out = [0u8; BLAKE2B_256_DIGEST_BYTES];
        for (index, word) in h[..4].iter().enumerate() {
            out[index * 8..(index + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[test]
    fn compression_rounds_match_the_rfc_7693_blake2b_256_known_answer() {
        // RFC 7693's `abc` input with the BLAKE2b-256 parameter block.  The
        // expected digest is intentionally hard-coded rather than computed by
        // `Blake2bVar`, so this catches sigma/rotation/counter/final-flag and
        // word-endianness mistakes in the AIR witness layout.
        let mut block = [0u8; BLAKE2B_BLOCK_BYTES];
        block[..3].copy_from_slice(b"abc");
        let expected = [
            0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98,
            0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0,
            0x68, 0xd5, 0x23, 0x19,
        ];
        assert_eq!(reference_compress_256(block, 3, true), expected);
    }

    #[test]
    fn fixed_smt_witnesses_match_independent_compression_known_answers() {
        let leaf = Blake2bSmtSingleBlock::leaf([0x11; 32], [0x22; 32]);
        let internal = Blake2bSmtSingleBlock::internal([0x33; 32], [0x44; 32]);
        assert_eq!(
            reference_compress_256(*leaf.message(), leaf.counter(), leaf.is_last_block()),
            [
                0x2b, 0x0c, 0xa7, 0x30, 0xfe, 0xc4, 0xc4, 0xac, 0xa7, 0x95, 0x0c, 0x9c, 0xa8, 0x89,
                0x9e, 0x6a, 0xea, 0xff, 0x4b, 0x38, 0x27, 0xc6, 0x12, 0xdc, 0x4e, 0x7e, 0xb0, 0x45,
                0x33, 0x46, 0xfb, 0x02,
            ]
        );
        assert_eq!(
            reference_compress_256(
                *internal.message(),
                internal.counter(),
                internal.is_last_block()
            ),
            [
                0x94, 0x53, 0xa1, 0xc0, 0x44, 0x59, 0x36, 0xaa, 0x97, 0x93, 0x79, 0x5c, 0x9e, 0xa8,
                0xed, 0xad, 0x70, 0xb8, 0xaf, 0xb3, 0xc6, 0x80, 0x4b, 0x77, 0xb3, 0x3e, 0xed, 0x4f,
                0x40, 0x43, 0x44, 0x7a,
            ]
        );
    }

    #[test]
    fn fixed_leaf_witness_matches_production_l1_hash_and_word_order() {
        let key = [0x11; 32];
        let value = [0x22; 32];
        let witness = Blake2bSmtSingleBlock::leaf(key, value);

        assert_eq!(witness.kind(), Blake2bSmtSingleBlockKind::Leaf);
        assert_eq!(witness.input_len(), 65);
        assert_eq!(witness.counter(), 65);
        assert!(witness.is_last_block());
        assert_eq!(witness.message()[0], SMT_LEAF_DOMAIN);
        assert_eq!(&witness.message()[1..33], &key);
        assert_eq!(&witness.message()[33..65], &value);
        assert!(witness.message()[65..].iter().all(|byte| *byte == 0));
        assert_eq!(witness.message_words()[0], 0x1111_1111_1111_1100);
        assert_eq!(witness.native_digest(), leaf_hash(&key, &value));
    }

    #[test]
    fn internal_witness_matches_production_l1_hash() {
        let left = [0x33; 32];
        let right = [0x44; 32];
        let witness = Blake2bSmtSingleBlock::internal(left, right);

        assert_eq!(witness.kind(), Blake2bSmtSingleBlockKind::Internal);
        assert_eq!(witness.message()[0], SMT_INTERNAL_DOMAIN);
        assert_eq!(&witness.message()[1..33], &left);
        assert_eq!(&witness.message()[33..65], &right);
        assert_eq!(witness.native_digest(), internal_hash(&left, &right));
    }

    #[test]
    fn fixed_value_leaf_is_the_same_leaf_used_by_l1_inclusion_verification() {
        let key = [0x55; 32];
        let value = [0x66; 32];
        let witness = Blake2bSmtSingleBlock::leaf(key, value);
        let mut tree = SparseMerkleTree::new();
        tree.upsert(key, &value);
        let path = tree.prove(&key);

        assert!(SparseMerkleTree::verify(
            &tree.root(),
            &key,
            Some(&value),
            &path
        ));
        assert_eq!(witness.native_digest(), leaf_hash(&key, &value));
    }

    #[test]
    fn fixed_value_path_expands_the_exact_l1_leaf_to_root_compression_chain() {
        let key = [0x55; 32];
        let value = [0x66; 32];
        let mut tree = SparseMerkleTree::new();
        tree.upsert(key, &value);
        let path = tree.prove(&key);
        let siblings: [[u8; 32]; SMT_PATH_SIBLINGS] = path
            .siblings
            .try_into()
            .expect("L1 path is exactly 256 siblings");
        let mut witness = Blake2bSmtFixedValuePathWitness {
            key,
            value,
            siblings,
            nodes: [[0; 32]; SMT_FIXED_VALUE_OPENING_COMPRESSIONS],
            root: tree.root(),
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

        assert!(witness.terminal_node_matches_root());
        let blocks = witness.compression_blocks();
        assert_eq!(blocks[0].kind(), Blake2bSmtSingleBlockKind::Leaf);
        for (index, block) in blocks.iter().enumerate() {
            assert_eq!(block.native_digest(), witness.nodes[index]);
        }
    }

    #[test]
    fn fixed_value_path_uses_l1s_bottom_up_big_endian_key_bit_order() {
        let witness = Blake2bSmtFixedValuePathWitness {
            // Set key bit zero (first byte's MSB) and bit 255 (last byte's
            // LSB), so the first and last parent directions are unambiguous.
            key: [
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0x01,
            ],
            value: [0; 32],
            siblings: [[0; 32]; SMT_PATH_SIBLINGS],
            nodes: [[0; 32]; SMT_FIXED_VALUE_OPENING_COMPRESSIONS],
            root: [0; 32],
        };
        assert!(witness.direction_bit(1));
        assert!(witness.direction_bit(SMT_PATH_SIBLINGS));
        assert!(!witness.direction_bit(2));
        assert!(!witness.direction_bit(SMT_PATH_SIBLINGS - 1));
    }
}
