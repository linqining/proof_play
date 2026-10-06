//! Sparse Merkle Tree（IMPL-SEC-3 修复实现）
//!
//! 严格遵循 spec.md IMPL-SEC-3 规范：
//! - 哈希函数：blake2b_256（与地址派生一致）
//! - domain separation：叶子 `H(0x00 || key || value)`，内部 `H(0x01 || left || right)`
//! - depth = 256（keyed by blake2b_256(ObjectID)）
//! - 强制空子树缓存（每层默认哈希预计算），单次更新 O(log n) = 256 次哈希
//! - 空叶值统一 = 空字节串 `b""`
//!
//! ## 关于空叶哈希的工程决策
//!
//! spec 文字表述为"默认空叶 H(0x00 || key || b"")"，但若空叶哈希依赖 key（position-dependent），
//! 则空子树哈希也依赖位置，无法按层缓存，单次更新将退化为 O(2^256) — 与 spec 强制要求
//! "O(log n) = 256 次哈希"矛盾。因此本实现采用标准 sparse Merkle tree 构造（同 Diem/Starcoin）：
//! - 非空叶（key k, value v）：`H(0x00 || k || v)`（key 参与哈希，防 leaf substitution）
//! - 空叶：sentinel `empty_leaf_hash() = H(0x00 || b"")`（位置无关，启用按层缓存）
//! - 空子树按层预计算：`empty_hashes()[h]`，h ∈ [0, 256]
//!
//! 这样空叶的"默认值"仍为 b""，且空子树哈希按层缓存实现 O(log n) 更新。
//! 轻客户端验证空叶证明时，校验 leaf_hash == empty_leaf_hash() 即可。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use std::collections::HashMap;
use std::sync::OnceLock;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::Hash;

/// Merkle 树深度（spec：depth = 256，keyed by blake2b_256(ObjectID)）。
pub const TREE_DEPTH: u32 = 256;

/// 内部节点 domain separation 前缀。
const LEAF_DOMAIN: u8 = 0x00;
const INTERNAL_DOMAIN: u8 = 0x01;

/// 256-bit Merkle 路径（非包含证明 / 包含证明）。
///
/// `siblings[h]` = 高度 h 处的兄弟节点哈希（h ∈ [0, TREE_DEPTH-1]）。
/// 验证时从叶到根逐层合并。
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct MerklePath {
    /// 从叶（height 0）到根（height 255）的兄弟哈希，共 256 个。
    pub siblings: Vec<Hash>,
    /// 叶子是否为空（用于空证明）。
    pub is_empty_leaf: bool,
}

/// Sparse Merkle Tree 主结构。
///
/// 内存版（Phase 1）。Phase 4 将扩展 rocksdb 后端。
///
/// `Clone` 用于 `ObjectDbSnapshot` 创建 fork：复制 SMT 内部 HashMap，
/// 使 snapshot 可独立计算 state_root 并记录 mutation log 供回放。
#[derive(Clone)]
pub struct SparseMerkleTree {
    /// 非空叶：key -> value_hash（H(0x00 || key || value)）
    leaves: HashMap<Hash, Hash>,
    /// 内部节点缓存：(height, node_path) -> hash。
    /// node_path = key 的低 `height` 位清零（同高度同子树的 key 共享 path）。
    nodes: HashMap<(u32, Hash), Hash>,
    /// 当前根哈希。
    root: Hash,
}

/// 预计算的空子树哈希表：`empty_hashes()[h]` = 高度 h 的空子树哈希。
///
/// `empty_hashes()[0] = H(0x00 || b"")`（空叶 sentinel，位置无关）
/// `empty_hashes()[h] = H(0x01 || empty_at(h-1) || empty_at(h-1))`
///
/// 使用 `OnceLock` 在首次访问时初始化一次（线程安全）。
static EMPTY_HASHES: OnceLock<Vec<Hash>> = OnceLock::new();

/// 空叶 sentinel 哈希 = H(0x00 || b"")。位置无关，启用按层缓存。
pub fn empty_leaf_hash() -> Hash {
    empty_at(0)
}

/// 访问预计算的空子树哈希表。
pub fn empty_hashes() -> &'static [Hash] {
    EMPTY_HASHES.get_or_init(|| {
        let mut v = Vec::with_capacity((TREE_DEPTH + 1) as usize);
        // 空叶 sentinel：H(0x00 || b"")（不含 key，位置无关）
        v.push(compute_empty_leaf_sentinel());
        for h in 1..=TREE_DEPTH {
            let child = v[(h - 1) as usize];
            v.push(internal_hash(&child, &child));
        }
        v
    })
}

/// 计算空叶 sentinel：H(0x00 || b"")（不含 key，位置无关）。
fn compute_empty_leaf_sentinel() -> Hash {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[LEAF_DOMAIN]);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 索引访问空子树哈希。
#[inline]
fn empty_at(h: u32) -> Hash {
    empty_hashes()[h as usize]
}

/// 计算叶哈希：`H(0x00 || key || value)`。
pub fn leaf_hash(key: &Hash, value: &[u8]) -> Hash {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[LEAF_DOMAIN]);
    h.update(key);
    h.update(value);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 计算内部节点哈希：`H(0x01 || left || right)`。
pub fn internal_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[INTERNAL_DOMAIN]);
    h.update(left);
    h.update(right);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 将 key 的低 `num_bits` 位置零，返回节点路径。
fn zero_lower_bits(key: &Hash, num_bits: u32) -> Hash {
    if num_bits == 0 {
        return *key;
    }
    let mut path = *key;
    let full_bytes = (num_bits / 8) as usize;
    let partial_bits = num_bits % 8;
    // 末尾整字节置零（LSB 端）
    if full_bytes > 0 {
        for byte in path.iter_mut().take(32).skip(32 - full_bytes) {
            *byte = 0;
        }
    }
    // 部分字节：清低 `partial_bits` 位
    if partial_bits > 0 && full_bytes < 32 {
        let idx = 32 - full_bytes - 1;
        let mask = !((1u8 << partial_bits) - 1);
        path[idx] &= mask;
    }
    path
}

/// 取 key 的第 `bit_idx` 位（bit 0 = byte[0] 的 MSB，bit 255 = byte[31] 的 LSB）。
const fn get_bit(key: &Hash, bit_idx: u32) -> u8 {
    let byte_idx = (bit_idx / 8) as usize;
    let bit_in_byte = 7 - (bit_idx % 8);
    (key[byte_idx] >> bit_in_byte) & 1
}

/// 翻转 key 的第 `bit_idx` 位。
const fn flip_bit(key: &Hash, bit_idx: u32) -> Hash {
    let mut path = *key;
    let byte_idx = (bit_idx / 8) as usize;
    let bit_in_byte = 7 - (bit_idx % 8);
    path[byte_idx] ^= 1 << bit_in_byte;
    path
}

impl SparseMerkleTree {
    /// 创建空树。根 = `empty_at(TREE_DEPTH)`。
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            root: empty_at(TREE_DEPTH),
        }
    }

    /// 当前根哈希。
    pub const fn root(&self) -> Hash {
        self.root
    }

    /// 查询 key 对应的 value_hash（叶哈希），None 表示空叶。
    pub fn get(&self, key: &Hash) -> Option<&Hash> {
        self.leaves.get(key)
    }

    /// 插入 / 更新 key 对应的 value，重新计算从叶到根的路径哈希。O(log n) = 256 次哈希。
    pub fn upsert(&mut self, key: Hash, value: &[u8]) {
        let new_leaf = leaf_hash(&key, value);
        self.leaves.insert(key, new_leaf);
        self.recompute_path(&key, new_leaf);
    }

    /// 删除 key（置为空叶）。O(log n)。
    pub fn remove(&mut self, key: &Hash) {
        self.leaves.remove(key);
        // 空叶哈希 = EMPTY_HASHES[0]，从叶到根重算
        self.recompute_path_remove(key);
    }

    /// 生成 key 的 Merkle 包含 / 非包含证明。
    pub fn prove(&self, key: &Hash) -> MerklePath {
        let mut siblings = Vec::with_capacity(TREE_DEPTH as usize);
        let leaf_val = self.leaves.get(key).copied();
        let is_empty_leaf = leaf_val.is_none();

        // 从 height 1 走到 height TREE_DEPTH，收集每层兄弟哈希
        for h in 1..=TREE_DEPTH {
            let bit_idx = TREE_DEPTH - h;
            let sibling_path = flip_bit(&zero_lower_bits(key, h - 1), bit_idx);
            let sibling_hash = self
                .nodes
                .get(&(h - 1, sibling_path))
                .copied()
                .unwrap_or_else(|| empty_at(h - 1));
            siblings.push(sibling_hash);
        }

        MerklePath {
            siblings,
            is_empty_leaf,
        }
    }

    /// 验证 Merkle 证明（给定 root / key / value / path，校验一致性）。
    pub fn verify(root: &Hash, key: &Hash, value: Option<&[u8]>, path: &MerklePath) -> bool {
        if path.siblings.len() != TREE_DEPTH as usize {
            return false;
        }
        // 计算叶哈希：空叶用 sentinel，非空用 H(0x00||key||value)
        let mut current = match (value, path.is_empty_leaf) {
            (Some(v), false) => leaf_hash(key, v),
            (None, true) => empty_leaf_hash(),
            _ => return false, // value 与 is_empty_leaf 不一致
        };

        for h in 1..=TREE_DEPTH {
            let bit_idx = TREE_DEPTH - h;
            let bit = get_bit(key, bit_idx);
            let sibling = &path.siblings[(h - 1) as usize];
            // bit=0 → current 是左子；bit=1 → current 是右子
            current = if bit == 0 {
                internal_hash(&current, sibling)
            } else {
                internal_hash(sibling, &current)
            };
        }

        &current == root
    }

    /// 重算从叶（height 0）到根（height TREE_DEPTH）的路径。
    fn recompute_path(&mut self, key: &Hash, leaf_value_hash: Hash) {
        let mut current_hash = leaf_value_hash;
        let mut current_path = *key; // height 0 的 path = key 本身

        for h in 1..=TREE_DEPTH {
            let bit_idx = TREE_DEPTH - h;
            let bit = get_bit(key, bit_idx);
            // 兄弟在 height h-1，path = 当前 path（height h-1）翻转 bit_idx
            let sibling_path = flip_bit(&current_path, bit_idx);
            let sibling_hash = self
                .nodes
                .get(&(h - 1, sibling_path))
                .copied()
                .unwrap_or_else(|| empty_at(h - 1));

            let (left, right) = if bit == 0 {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };
            current_hash = internal_hash(&left, &right);
            // height h 的 path = key 低 h 位清零
            current_path = zero_lower_bits(key, h);
            self.nodes.insert((h, current_path), current_hash);
        }

        self.root = current_hash;
    }

    /// 重算路径（删除场景）：若兄弟也为空，则父节点退化为空子树（从缓存移除）。
    fn recompute_path_remove(&mut self, key: &Hash) {
        let mut current_hash = empty_leaf_hash();
        let mut current_path = *key;

        for h in 1..=TREE_DEPTH {
            let bit_idx = TREE_DEPTH - h;
            let bit = get_bit(key, bit_idx);
            let sibling_path = flip_bit(&current_path, bit_idx);
            let sibling_hash = self
                .nodes
                .get(&(h - 1, sibling_path))
                .copied()
                .unwrap_or_else(|| empty_at(h - 1));

            // 若 current 与 sibling 均为空子树，则父节点 = empty_at(h)（移除缓存）
            if current_hash == empty_at(h - 1) && sibling_hash == empty_at(h - 1) {
                current_hash = empty_at(h);
                let node_path = zero_lower_bits(key, h);
                self.nodes.remove(&(h, node_path));
                current_path = node_path;
                continue;
            }

            let (left, right) = if bit == 0 {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };
            current_hash = internal_hash(&left, &right);
            current_path = zero_lower_bits(key, h);
            self.nodes.insert((h, current_path), current_hash);
        }

        self.root = current_hash;
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_leaf_hash_matches_blake2b() {
        // 验证空叶 sentinel = H(0x00 || b"")
        let mut h = Blake2bVar::new(32).unwrap();
        h.update(&[LEAF_DOMAIN]);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).unwrap();
        assert_eq!(out, empty_leaf_hash(), "empty_leaf_hash 必须等于 H(0x00)");
    }

    #[test]
    fn empty_tree_root_is_empty_subtree_at_depth() {
        let t = SparseMerkleTree::new();
        assert_eq!(t.root(), empty_at(TREE_DEPTH));
    }

    #[test]
    fn single_insert_updates_root() {
        let mut t = SparseMerkleTree::new();
        let key = [7u8; 32];
        let value = b"hello world";
        t.upsert(key, value);

        let leaf = leaf_hash(&key, value);
        // 手动重算 root：从叶到根，兄弟均为空子树
        let mut current = leaf;
        for h in 1..=TREE_DEPTH {
            let bit = get_bit(&key, TREE_DEPTH - h);
            let empty = empty_at(h - 1);
            current = if bit == 0 {
                internal_hash(&current, &empty)
            } else {
                internal_hash(&empty, &current)
            };
        }
        assert_eq!(t.root(), current);
    }

    #[test]
    fn insert_and_prove_inclusion() {
        let mut t = SparseMerkleTree::new();
        let key = [3u8; 32];
        let value = b"v1";
        t.upsert(key, value);

        let path = t.prove(&key);
        assert!(!path.is_empty_leaf);
        assert!(
            SparseMerkleTree::verify(&t.root(), &key, Some(value), &path),
            "包含证明必须验证通过"
        );
    }

    #[test]
    fn prove_non_inclusion() {
        let mut t = SparseMerkleTree::new();
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        t.upsert(k1, b"present");

        let path = t.prove(&k2);
        assert!(path.is_empty_leaf, "k2 不存在，应返回空叶证明");
        assert!(
            SparseMerkleTree::verify(&t.root(), &k2, None, &path),
            "非包含证明必须验证通过"
        );
    }

    #[test]
    fn update_changes_root() {
        let mut t = SparseMerkleTree::new();
        let key = [5u8; 32];
        t.upsert(key, b"v1");
        let root1 = t.root();
        t.upsert(key, b"v2");
        let root2 = t.root();
        assert_ne!(root1, root2, "更新 value 必须改变 root");

        // 验证新 root 下的包含证明
        let path = t.prove(&key);
        assert!(SparseMerkleTree::verify(
            &t.root(),
            &key,
            Some(b"v2"),
            &path
        ));
        assert!(!SparseMerkleTree::verify(
            &t.root(),
            &key,
            Some(b"v1"),
            &path
        ));
    }

    #[test]
    fn delete_restores_empty_root() {
        let mut t = SparseMerkleTree::new();
        let empty_root = t.root();
        let key = [9u8; 32];
        t.upsert(key, b"temp");
        assert_ne!(t.root(), empty_root);
        t.remove(&key);
        assert_eq!(t.root(), empty_root, "删除最后一个叶后应恢复空树根");
    }

    #[test]
    fn multiple_inserts_root_deterministic() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let keys: Vec<([u8; 32], &[u8])> = vec![
            ([1u8; 32], b"a"),
            ([2u8; 32], b"bb"),
            ([3u8; 32], b"ccc"),
            ([255u8; 32], b"dddd"),
        ];
        // 任意顺序插入都应得到同一 root
        for (k, v) in &keys {
            t1.upsert(*k, v);
        }
        for (k, v) in keys.iter().rev() {
            t2.upsert(*k, v);
        }
        assert_eq!(t1.root(), t2.root(), "root 必须与插入顺序无关");
    }

    #[test]
    fn verify_rejects_tampered_value() {
        let mut t = SparseMerkleTree::new();
        let key = [42u8; 32];
        t.upsert(key, b"real");
        let path = t.prove(&key);
        assert!(!SparseMerkleTree::verify(
            &t.root(),
            &key,
            Some(b"fake"),
            &path
        ));
    }

    #[test]
    fn verify_rejects_tampered_root() {
        let mut t = SparseMerkleTree::new();
        let key = [42u8; 32];
        t.upsert(key, b"real");
        let path = t.prove(&key);
        let fake_root = [0xff; 32];
        assert!(!SparseMerkleTree::verify(
            &fake_root,
            &key,
            Some(b"real"),
            &path
        ));
    }
}
