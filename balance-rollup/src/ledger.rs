//! escape-ledger——边界转换器（推荐形态，2026-10-02 定稿）：poker 结算
//! 负债面（钱包 felt / i128 wei / Poseidon）→ 账本面（bytes20 / u64 /
//! SHA-256）。
//!
//! **规格镜像声明**：哈希/域/编码逐字节镜像 zchain
//! `contracts/monad/src/EscapeHatch.sol`（DOMAIN、LEAF_PREFIX=0x00、
//! INTERNAL_PREFIX=0x01、amount u64 小端、不平衡树以空叶补齐到 2 的幂、
//! 索引式逃生证明、leafCount 约束 leafIndex）——该合约是**冻结规格锚，
//! 本模块只实现规格、不拥有规格**：改哈希/域/编码须先改合约并跨仓
//! 同步。哈希各自原生的理由（docs/design/PRIVACY_PROFILE.md §3 附注）：
//! Cairo/STARK 里 Poseidon 是 builtin、SHA-256 为外来苦役（全树
//! ~3–12M steps，fold 批 431k steps 的 10–30×）；EVM/Groth16 里
//! SHA-256 是标准件。转换器零证明成本，信任分阶段（authority 登记 +
//! DA 语料离线复核）。
//!
//! ## 登记语义（与 EscapeHatch 对齐）
//!
//! - 每批一个**增量根**（`seal_batch`，ledger_index 单调递增——链上
//!   registerBalanceRoot 按 batchIndex 顺序消费）；
//! - 叶集 = 非零余额地址，**按 address 升序**（规范序——逃生者以本模块
//!   落盘工件里的 leaf_index/叶数据重算兄弟证明）；
//! - 空账本根 = 空叶哈希（合约 Deploy genesis 同值）；
//! - 单位换算：poker wei ÷ divisor → 账本单位（生产 = chips，
//!   [`PROD_WEI_PER_LEDGER_UNIT`] 与 texas `config::WEI_PER_CHIP` 同值，
//!   双仓对齐锚）；非整除 = 尘额 fail-closed（不静默截断）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::RollupError;

/// 规格域标签（EscapeHatch.sol `_domain` 冻结值）。
pub const LEDGER_DOMAIN: &[u8] = b"zchain.vault.balance_root.v1";
/// 叶前缀（EscapeHatch.sol `LEAF_PREFIX`）。
pub const LEAF_PREFIX: u8 = 0x00;
/// 内部节点前缀（EscapeHatch.sol `INTERNAL_PREFIX`）。
pub const INTERNAL_PREFIX: u8 = 0x01;
/// 生产单位换算除数：poker wei → 账本单位（chips）。与 texas
/// `config::WEI_PER_CHIP`（1e15）同值——双仓对齐锚，勿单侧改。
pub const PROD_WEI_PER_LEDGER_UNIT: u128 = 1_000_000_000_000_000;
/// 树高上限（EscapeHatch.sol `MAX_PROOF_LEN = 63`）。
pub const MAX_TREE_HEIGHT: usize = 63;
/// state/工件版本（规格变更须升版并跨仓同步）。
pub const SPEC_VERSION: u32 = 1;

/// 叶哈希：`sha256(DOMAIN ‖ 0x00 ‖ bytes20(player) ‖ u64 小端 amount)`。
#[must_use]
pub fn leaf_hash(address: &[u8; 20], amount: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEDGER_DOMAIN);
    h.update([LEAF_PREFIX]);
    h.update(address);
    h.update(amount.to_le_bytes());
    h.finalize().into()
}

/// 内部节点：`sha256(DOMAIN ‖ 0x01 ‖ l ‖ r)`。
#[must_use]
pub fn internal_hash(l: [u8; 32], r: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEDGER_DOMAIN);
    h.update([INTERNAL_PREFIX]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// 空叶哈希（补齐位；= 空账本规范根 = 合约 Deploy genesis 根）。
#[must_use]
pub fn empty_leaf_hash() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEDGER_DOMAIN);
    h.update([LEAF_PREFIX]);
    h.finalize().into()
}

/// 钱包 felt（32B 大端）→ 账本地址（低 20 字节截断；poker_l1
/// `wallet_to_address` 同式——vault 记账/结算 calldata 的既定映射）。
#[must_use]
pub fn wallet_felt_to_address(wallet_felt: &[u8; 32]) -> [u8; 20] {
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&wallet_felt[12..32]);
    addr
}

/// 账本叶（工件/规范序：按 address 升序；leaf_index 即该序下的下标）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerLeaf {
    /// 0x + 40 hex。
    pub address: String,
    pub amount: u64,
    pub leaf_index: u64,
}

/// 批封印工件（`<batch_key>.ledger-root.json`；`seal_batch` 产出）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRootArtifact {
    pub spec_version: u32,
    /// 批键 = keccak_root（与信封/ statements 工件同键域关联读）。
    pub batch_key: String,
    /// 账本根序号（单调递增；链上 registerBalanceRoot 按 batchIndex
    /// 顺序消费——与链上序的对齐归 M4 登记腿）。
    pub ledger_index: u64,
    /// 0x + 64 hex。
    pub root: String,
    pub leaf_count: u32,
    /// 规格自述（离线复核/逃生证明重算口径，随工件走）。
    pub hash_spec: String,
    /// 规范序叶全量（逃生者取自己的 address/amount/leaf_index，兄弟
    /// 证明由本叶集离线重算）。
    pub leaves: Vec<LedgerLeaf>,
    pub at: u64,
}

/// state 持久化 DTO（地址 hex 化——serde 数组键可读性差且跨语言不稳）。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerState {
    version: u32,
    ledger_index: u64,
    balances: BTreeMap<String, u64>,
    updated_at: u64,
}

/// 转换器错误（fail-closed 全集——与 rollup 同纪律：账本面与链上事实
/// 分歧绝不静默）。
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("state 版本 {found} 未知（本实现支持 ≤{SPEC_VERSION}）")]
    Version { found: u32 },
    #[error("非零增量非 {divisor} 整除（尘额 {remainder} wei）——拒绝静默截断")]
    Dust { remainder: u128, divisor: u128 },
    #[error("地址 {address} 余额下穿（{balance} {delta:+} < 0）")]
    Underflow {
        address: String,
        balance: u64,
        delta: i64,
    },
    #[error("地址 {address} 余额上溢 u64")]
    Overflow { address: String },
    #[error("players/deltas 长度不符（{p} vs {d}）")]
    LengthMismatch { p: usize, d: usize },
    #[error("地址重复：{0}")]
    DuplicateAddress(String),
    #[error("player hex 非法：{0}")]
    BadPlayerHex(String),
    #[error("配置非法：{0}")]
    Config(String),
    #[error("种子仅限创世（账本已有 {ledger_index} 批）")]
    NotGenesis { ledger_index: u64 },
}

/// 账本镜像（poker 结算负债面 → 账本面的增量折算 + 每批增量根）。
pub struct LedgerMirror {
    divisor: u128,
    state_path: PathBuf,
    balances: BTreeMap<[u8; 20], u64>,
    ledger_index: u64,
    updated_at: u64,
}

impl LedgerMirror {
    /// 打开（存在则恢复，缺失则空账本）。`divisor`：wei → 账本单位除数
    /// （生产 [`PROD_WEI_PER_LEDGER_UNIT`]；测试 1）。
    pub fn open(state_path: impl Into<PathBuf>, divisor: u128) -> Result<Self, LedgerError> {
        if divisor == 0 {
            return Err(LedgerError::Config("divisor 不得为 0".into()));
        }
        let state_path = state_path.into();
        let (balances, ledger_index, updated_at) = if state_path.exists() {
            let st: LedgerState =
                serde_json::from_str(&std::fs::read_to_string(&state_path)?)?;
            if st.version > SPEC_VERSION {
                return Err(LedgerError::Version { found: st.version });
            }
            let mut map = BTreeMap::new();
            for (hex_addr, amount) in st.balances {
                let addr = parse_address(&hex_addr)?;
                map.insert(addr, amount);
            }
            (map, st.ledger_index, st.updated_at)
        } else {
            (BTreeMap::new(), 0, 0)
        };
        Ok(Self {
            divisor,
            state_path,
            balances,
            ledger_index,
            updated_at,
        })
    }

    /// 创世种子（vault 快照形态；仅空账本可用）。amounts 为**账本单位**
    /// （已换算——种子源若为 wei，调用方先按 divisor 折算）。
    pub fn seed(&mut self, entries: &[([u8; 20], u64)], at: u64) -> Result<(), LedgerError> {
        if self.ledger_index != 0 || !self.balances.is_empty() {
            return Err(LedgerError::NotGenesis {
                ledger_index: self.ledger_index,
            });
        }
        for (addr, amount) in entries {
            if *amount == 0 {
                continue;
            }
            self.balances.insert(*addr, *amount);
        }
        self.updated_at = at;
        self.persist()?;
        Ok(())
    }

    /// 应用一手增量（players = 钱包 felt 32B 大端；deltas = wei，零和；
    /// 幂等性由调用方保证——本层随 rollup 回执路径同点调用，rollup 的
    /// applied 集合是唯一幂等源，本层只跟随）。
    pub fn apply_entry(
        &mut self,
        players: &[[u8; 32]],
        deltas_wei: &[i128],
    ) -> Result<(), LedgerError> {
        if players.len() != deltas_wei.len() {
            return Err(LedgerError::LengthMismatch {
                p: players.len(),
                d: deltas_wei.len(),
            });
        }
        // 先全量换算（尘额/溢出早失败），后落状态。
        let mut updates: Vec<([u8; 20], i64)> = Vec::with_capacity(players.len());
        let mut seen = std::collections::BTreeSet::new();
        for (felt, delta) in players.iter().zip(deltas_wei) {
            let addr = wallet_felt_to_address(felt);
            if !seen.insert(addr) {
                return Err(LedgerError::DuplicateAddress(addr_hex(&addr)));
            }
            let mag = delta.unsigned_abs();
            let rem = mag % self.divisor;
            if rem != 0 {
                return Err(LedgerError::Dust {
                    remainder: rem,
                    divisor: self.divisor,
                });
            }
            let units = (mag / self.divisor) as i64;
            updates.push((addr, if *delta >= 0 { units } else { -units }));
        }
        for (addr, units) in updates {
            let old = self.balances.get(&addr).copied().unwrap_or(0);
            let new = if units >= 0 {
                old.checked_add(units as u64).ok_or_else(|| LedgerError::Overflow {
                    address: addr_hex(&addr),
                })?
            } else {
                old.checked_sub(units.unsigned_abs()).ok_or_else(|| {
                    LedgerError::Underflow {
                        address: addr_hex(&addr),
                        balance: old,
                        delta: units,
                    }
                })?
            };
            if new == 0 {
                self.balances.remove(&addr);
            } else {
                self.balances.insert(addr, new);
            }
        }
        Ok(())
    }

    /// 批封印：账本根序号推进 + 规范序叶全量工件（根重算 + state 落盘）。
    pub fn seal_batch(&mut self, batch_key: &str, at: u64) -> Result<LedgerRootArtifact, LedgerError> {
        self.ledger_index += 1;
        let (root, leaves) = self.compute_root();
        self.updated_at = at;
        let artifact = LedgerRootArtifact {
            spec_version: SPEC_VERSION,
            batch_key: batch_key.to_string(),
            ledger_index: self.ledger_index,
            root: format!("0x{}", hex::encode(root)),
            leaf_count: leaves.len() as u32,
            hash_spec: HASH_SPEC.into(),
            leaves,
            at,
        };
        self.persist()?;
        Ok(artifact)
    }

    /// 当前根（hex，0x + 64）。
    #[must_use]
    pub fn root_hex(&self) -> String {
        format!("0x{}", hex::encode(self.compute_root().0))
    }

    #[must_use]
    pub fn ledger_index(&self) -> u64 {
        self.ledger_index
    }

    /// 根重算（规格：叶集按 address 升序，空叶补齐到 2 的幂折叠；
    /// 空账本 = 空叶哈希——合约 genesis 同值）。
    fn compute_root(&self) -> ([u8; 32], Vec<LedgerLeaf>) {
        let leaves: Vec<LedgerLeaf> = self
            .balances
            .iter()
            .filter(|(_, amount)| **amount != 0)
            .enumerate()
            .map(|(i, (addr, amount))| LedgerLeaf {
                address: addr_hex(addr),
                amount: *amount,
                leaf_index: i as u64,
            })
            .collect();
        if leaves.is_empty() {
            return (empty_leaf_hash(), leaves);
        }
        let mut level: Vec<[u8; 32]> = leaves
            .iter()
            .map(|l| {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&hex::decode(&l.address[2..]).expect("自产 hex"));
                leaf_hash(&addr, l.amount)
            })
            .collect();
        // 补齐到 2 的幂（空叶）。
        let mut width = 1usize;
        while width < level.len() {
            width *= 2;
        }
        debug_assert!(width <= 1 << MAX_TREE_HEIGHT, "树高超 EscapeHatch 上限");
        level.resize(width, empty_leaf_hash());
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                next.push(internal_hash(pair[0], pair[1]));
            }
            level = next;
        }
        (level[0], leaves)
    }

    fn persist(&self) -> Result<(), LedgerError> {
        let st = LedgerState {
            version: SPEC_VERSION,
            ledger_index: self.ledger_index,
            balances: self
                .balances
                .iter()
                .map(|(addr, amount)| (addr_hex(addr), *amount))
                .collect(),
            updated_at: self.updated_at,
        };
        atomic_write_json(&self.state_path, &st)?;
        Ok(())
    }
}

/// 规格自述常量（随工件走——离线复核口径与实现单一来源）。
pub const HASH_SPEC: &str = "sha256; domain=zchain.vault.balance_root.v1; \
leaf=sha256(DOMAIN||0x00||addr20||u64le(amount)); \
node=sha256(DOMAIN||0x01||l||r); indexed; zero-balances excluded; \
leaves sorted by address asc; zero-padded to power-of-two with empty leaf";

fn addr_hex(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}

fn parse_address(s: &str) -> Result<[u8; 20], LedgerError> {
    let raw = hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|_| LedgerError::BadPlayerHex(s.to_string()))?;
    raw.try_into()
        .map_err(|_| LedgerError::BadPlayerHex(s.to_string()))
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), LedgerError> {
    let body = serde_json::to_vec_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json: {e}")))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("escape-ledger-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn felt(v: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&v.to_be_bytes());
        b
    }

    fn addr_of(v: u64) -> [u8; 20] {
        wallet_felt_to_address(&felt(v))
    }

    /// 哈希公式逐字节 golden：叶 = sha256(DOMAIN‖0x00‖addr‖u64le)、节点
    /// = sha256(DOMAIN‖0x01‖l‖r)、空叶 = sha256(DOMAIN‖0x00)——独立重算
    /// 钉死（公式漂移即失败；跨仓真锚 = EscapeHatch.t.sol 的 forge 向量，
    /// M4 登记腿对拍）。
    #[test]
    fn hash_formulas_match_spec() {
        let domain = b"zchain.vault.balance_root.v1";
        let addr = [0x44u8; 20];
        let mut expect_leaf = Sha256::new();
        expect_leaf.update(domain);
        expect_leaf.update([0x00]);
        expect_leaf.update(addr);
        expect_leaf.update(7u64.to_le_bytes());
        let expect_leaf: [u8; 32] = expect_leaf.finalize().into();
        assert_eq!(leaf_hash(&addr, 7), expect_leaf);

        let l = [1u8; 32];
        let r = [2u8; 32];
        let mut expect_node = Sha256::new();
        expect_node.update(domain);
        expect_node.update([0x01]);
        expect_node.update(l);
        expect_node.update(r);
        let expect_node: [u8; 32] = expect_node.finalize().into();
        assert_eq!(internal_hash(l, r), expect_node);

        let mut expect_empty = Sha256::new();
        expect_empty.update(domain);
        expect_empty.update([0x00]);
        let expect_empty: [u8; 32] = expect_empty.finalize().into();
        assert_eq!(empty_leaf_hash(), expect_empty);
    }

    /// felt→address：低 20 字节截断（poker_l1 wallet_to_address 同式）。
    #[test]
    fn felt_truncates_to_low_20_bytes() {
        let mut f = [0u8; 32];
        for (i, b) in f[12..].iter_mut().enumerate() {
            *b = (i as u8) + 1;
        }
        assert_eq!(wallet_felt_to_address(&f)[..], f[12..]);
    }

    /// 空账本根 = 空叶哈希（genesis 同值）；3 叶补齐到 4 折叠；工件
    /// leaf_index 规范序（address 升序）。
    #[test]
    fn tree_shape_and_canonical_order() {
        let dir = tmp("tree");
        let mut m = LedgerMirror::open(dir.join("state.json"), 1).unwrap();
        assert_eq!(m.root_hex(), format!("0x{}", hex::encode(empty_leaf_hash())));

        // 地址升序插入乱序增量（0x02 < 0x44 < 0xAA），规范序由 root 计算定。
        for (felt_v, d) in [(0xAAu64, 30i128), (0x02, 10), (0x44, 20)] {
            m.apply_entry(&[felt(felt_v)], &[d]).unwrap();
        }
        let artifact = m.seal_batch("0xfeed", 100).unwrap();
        assert_eq!(artifact.leaf_count, 3);
        assert_eq!(artifact.ledger_index, 1);
        for (w, leaf) in artifact.leaves.iter().enumerate() {
            assert_eq!(leaf.leaf_index, w as u64, "规范序 = address 升序");
        }
        let hexes: Vec<&str> = artifact.leaves.iter().map(|l| l.address.as_str()).collect();
        assert!(hexes.windows(2).all(|w| w[0] < w[1]), "升序: {hexes:?}");

        // 根 = 补齐到 4 的折叠（独立重算）。
        let mut level: Vec<[u8; 32]> = artifact
            .leaves
            .iter()
            .map(|l| {
                let mut a = [0u8; 20];
                a.copy_from_slice(&hex::decode(&l.address[2..]).unwrap());
                leaf_hash(&a, l.amount)
            })
            .collect();
        level.push(empty_leaf_hash());
        while level.len() > 1 {
            let mut next = Vec::new();
            for p in level.chunks(2) {
                next.push(internal_hash(p[0], p[1]));
            }
            level = next;
        }
        assert_eq!(artifact.root, format!("0x{}", hex::encode(level[0])));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 换算与 fail-closed：尘额拒绝（不静默截断）、下穿拒绝、状态零污染；
    /// 归零地址移出叶集。
    #[test]
    fn conversion_and_fail_closed() {
        let dir = tmp("conv");
        let mut m = LedgerMirror::open(dir.join("state.json"), 1_000).unwrap();
        m.seed(&[(addr_of(1), 500)], 0).unwrap();
        // 尘额（非 1000 整除）。
        assert!(matches!(
            m.apply_entry(&[felt(1), felt(2)], &[1_500, -1_500]),
            Err(LedgerError::Dust { remainder: 500, .. })
        ));
        // 下穿（零余额方付 1 单位——1 号有种子 500，付不起的是 2 号）。
        assert!(matches!(
            m.apply_entry(&[felt(2), felt(1)], &[-1_000, 1_000]),
            Err(LedgerError::Underflow { .. })
        ));
        // 合规手：1 单位换手（1 号 500→499、2 号 0→1）→ 双叶、规范序。
        m.apply_entry(&[felt(2), felt(1)], &[1_000, -1_000]).unwrap();
        let artifact = m.seal_batch("0x1", 1).unwrap();
        assert_eq!(artifact.leaf_count, 2);
        assert_eq!(artifact.leaves[0].address, addr_hex(&addr_of(1)));
        assert_eq!(artifact.leaves[0].amount, 499);
        assert_eq!(artifact.leaves[1].amount, 1);
        // 非创世种子拒绝。
        assert!(matches!(
            m.seed(&[(addr_of(9), 1)], 2),
            Err(LedgerError::NotGenesis { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 持久化：重开恢复账本（根/序号一致）。
    #[test]
    fn reopen_roundtrip() {
        let dir = tmp("reopen");
        let path = dir.join("state.json");
        let mut m = LedgerMirror::open(&path, 1).unwrap();
        m.apply_entry(&[felt(7)], &[42]).unwrap();
        let a1 = m.seal_batch("0x2", 5).unwrap();
        let m2 = LedgerMirror::open(&path, 1).unwrap();
        assert_eq!(m2.ledger_index(), 1);
        assert_eq!(m2.root_hex(), a1.root);
        std::fs::remove_dir_all(&dir).ok();
    }
}
