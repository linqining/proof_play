//! 批量聚合（实现 C）：同一 WrapCircuit 的 N 实例批量化 + 批次根两算。
//!
//! # 电路
//! [`crate::batch_circuit::BatchCircuit`]：K 份单手语句并列共享 program_hash
//! 绑定，一次 setup / 一个证明 / 一次配对验证。N 的编译期口径：
//! - 默认 `BATCH_N = 16`（feature `n8` → 8，`n64` → 64）。
//! - 生产口径（wrapPath 方案）：64 手 = 4 × N=16 证明 + 一笔链上 tx；
//!   N=64 单证明被内存/时长否决（实测单手 4.58M 约束 → N=64 ≈ 2.9 亿约束）。
//!   本机（36GB）金向量缩样用 N=8；N=16/64 在更大内存机器生成
//!   （`cargo run --release --bin gen-sol-batch -- --batch-n 16`）。
//!
//! # 批次根（两算，如实区分）
//! 1. **appchain 批根**：复刻 poker-appchain `pipeline.rs::batch_root`
//!    （docs/ABI.md §「批次根」）：binding 32B hi/lo 拆分后 Poseidon 折叠 +
//!    域标签，冻结金向量 0x00f6fae9… 钉死（本模块测试对拍）。链上验不了
//!    ——Monad 无 Poseidon 预编译——对应关系由 operator 在提交前离线对拍。
//! 2. **keccak 批根**：leaf_i = keccak256(index ‖ program_hash ‖
//!    hand_binding ‖ fact)，两两折叠（条数为 2 的幂）。这是 SettleBatch
//!    链上校验并登记的根：其输入恰好是电路公开输入（Groth16 已验证），
//!    故链上根锚定的是「已验证语句集合」本身。

use ark_ff::{PrimeField, Zero};
use crate::felt::{felt_to_be_bytes, Felt252};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// 批内单条语句（= 电路 3 公开输入；链上叶子载荷）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchStatement {
    pub program_hash: Felt252,
    pub hand_binding: Felt252,
    pub fact: Felt252,
}

/// 批量电路的语句条数（编译期口径；feature `n8`/`n64` 覆写）。
pub const BATCH_N: usize = BATCH_N_DEFAULT;

#[cfg(feature = "n8")]
const BATCH_N_DEFAULT: usize = 8;
#[cfg(feature = "n64")]
const BATCH_N_DEFAULT: usize = 64;
#[cfg(not(any(feature = "n8", feature = "n64")))]
const BATCH_N_DEFAULT: usize = 16;

/// 32B → (hi, lo)（各 16 字节大端入域；poker-appchain src/felt.rs:20 同式）。
fn split32_hi_lo(bytes: &[u8; 32]) -> (Felt252, Felt252) {
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&bytes[0..16]);
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&bytes[16..32]);
    (
        Felt252::from_be_bytes_mod_order(&hi),
        Felt252::from_be_bytes_mod_order(&lo),
    )
}

/// blake2s-256（poker-appchain src/keys.rs:22 同式：逐段 update，无前缀）。
fn blake2s32(parts: &[&[u8]]) -> [u8; 32] {
    use blake2::Digest as _;
    let mut h = blake2::Blake2s256::new();
    for p in parts {
        blake2::Digest::update(&mut h, p);
    }
    h.finalize().into()
}

/// 域标签（poker-appchain src/felt.rs:50 同式：blake2s32 后 hi/lo 入域折叠）。
fn domain_felt(domain: &[u8]) -> Felt252 {
    let (hi, lo) = split32_hi_lo(&blake2s32(&[domain]));
    crate::poseidon::poseidon_hash_many(&[hi, lo])
}

/// poker-appchain 批次根（`pipeline.rs::batch_root` 同式，见模块注释）。
///
/// bindings 顺序敏感（折叠序 = 帧序，appchain 冻结测试有反例断言）。
#[must_use]
pub fn appchain_batch_root(bindings: &[[u8; 32]]) -> [u8; 32] {
    const DOMAIN: &[u8] = b"poker-appchain.batch_root.v1";
    let mut fold = Felt252::zero();
    for b in bindings {
        let (hi, lo) = split32_hi_lo(b);
        fold = crate::poseidon::poseidon_hash_many(&[fold, hi, lo]);
    }
    let d = domain_felt(DOMAIN);
    let root = crate::poseidon::poseidon_hash_many(&[d, fold]);
    felt_to_be_bytes(&root)
}

/// keccak 批根：leaf_i = keccak256(index_be32 ‖ program_hash ‖ hand_binding
/// ‖ fact)（4×32 = 128B），两两折叠至单根；条数必须为 2 的幂。
///
/// # Errors
/// 条数非 2 的幂（SettleBatch 同一约束：64/16/8 均满足）。
pub fn keccak_batch_root(statements: &[BatchStatement]) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(!statements.is_empty(), "empty batch");
    anyhow::ensure!(
        statements.len().is_power_of_two(),
        "statement count must be a power of two, got {}",
        statements.len()
    );
    let mut level: Vec<[u8; 32]> = statements
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut h = Keccak256::new();
            Digest::update(&mut h, (i as u32).to_be_bytes());
            Digest::update(&mut h, felt_to_be_bytes(&s.program_hash));
            Digest::update(&mut h, felt_to_be_bytes(&s.hand_binding));
            Digest::update(&mut h, felt_to_be_bytes(&s.fact));
            h.finalize().into()
        })
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut h = Keccak256::new();
            Digest::update(&mut h, pair[0]);
            Digest::update(&mut h, pair[1]);
            next.push(h.finalize().into());
        }
        level = next;
    }
    Ok(level[0])
}

/// 批量金向量 JSON（gen-sol-batch 产物；Solidity 常量的来源）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchGoldenJson {
    /// 单证明覆盖语句数（sub_n）。
    pub batch_n: usize,
    /// 证明个数（sub_count）；总语句 = batch_n × sub_count。
    pub sub_count: usize,
    pub program_hash: String,
    /// 批内 hand_binding（0x…，64 位 hex）。
    pub hand_bindings: Vec<String>,
    pub facts: Vec<String>,
    /// keccak 批根（SettleBatch 链上登记；覆盖全部语句）。
    pub keccak_root: String,
    /// appchain 批根（离线对拍用；Monad 链上验不了 Poseidon 折叠）。
    pub appchain_root: String,
    /// Groth16 证明（b_evm 为 calldata 字序）。
    pub proofs: Vec<crate::ProofJson>,
    /// 各证明的电路公开输入（各 2N+1）。
    pub publics: Vec<Vec<String>>,
}

/// 批量语句构造：program_hash 共享，hand_binding = base + i，output 槽位
/// 同步改写并重算 fact（与 bench-verify 的批量口径一致）。
#[must_use]
pub fn derive_batch_statements(
    program_hash: &Felt252,
    base_binding: &Felt252,
    segment: &[Felt252],
    n: usize,
) -> Vec<(BatchStatement, crate::wrap_circuit::WrapWitness)> {
    use crate::wrap_circuit::{WrapWitness, HAND_BINDING_INDEX};
    (0..n)
        .map(|i| {
            let hb = *base_binding + Felt252::from(i as u64);
            let mut out = segment.to_vec();
            out[HAND_BINDING_INDEX] = hb;
            let witness = WrapWitness { output: out };
            let fact = witness.expected_fact(program_hash);
            (
                BatchStatement {
                    program_hash: *program_hash,
                    hand_binding: hb,
                    fact,
                },
                witness,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt::felt_from_hex;

    /// 对拍 poker-appchain 冻结金向量（pipeline.rs:1383
    /// batch_root_golden_vector：batch_root([0xAA;32],[0xBB;32])）。
    #[test]
    fn appchain_batch_root_matches_frozen_vector() {
        let b1 = [0xAAu8; 32];
        let b2 = [0xBBu8; 32];
        let root = appchain_batch_root(&[b1, b2]);
        assert_eq!(
            hex::encode(root),
            "00f6fae93ff03c440c1136a5d8b5eab742f07c268c52536d4932ce4171933c52",
            "appchain 批根复刻必须与 poker-appchain 冻结向量逐字节一致"
        );
        // 绑定序敏感（帧序）
        assert_ne!(appchain_batch_root(&[b2, b1]), root);
    }

    #[test]
    fn keccak_root_shape() {
        let ph = felt_from_hex("0x744d").unwrap();
        let mk = |i: u64| BatchStatement {
            program_hash: ph,
            hand_binding: Felt252::from(i),
            fact: Felt252::from(i * 2),
        };
        let r8 = keccak_batch_root(&[mk(1), mk(2), mk(3), mk(4), mk(5), mk(6), mk(7), mk(8)]).unwrap();
        assert!(r8 != [0u8; 32]);
        // 条数非 2 的幂拒绝
        assert!(keccak_batch_root(&[mk(1), mk(2)]).is_ok());
        assert!(keccak_batch_root(&[mk(1), mk(2), mk(3)]).is_err());
        // 顺序敏感
        assert_ne!(
            keccak_batch_root(&[mk(1), mk(2)]).unwrap(),
            keccak_batch_root(&[mk(2), mk(1)]).unwrap()
        );
    }

    #[test]
    fn batch_n_default_is_16() {
        #[cfg(not(any(feature = "n8", feature = "n64")))]
        assert_eq!(BATCH_N, 16);
        #[cfg(feature = "n8")]
        assert_eq!(BATCH_N, 8);
        #[cfg(feature = "n64")]
        assert_eq!(BATCH_N, 64);
    }
}
