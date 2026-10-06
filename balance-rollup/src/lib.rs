//! balance-rollup——全体玩家余额 Merkle 根随批推进（escape 地基）。
//!
//! 设计定稿：docs/design/PRIVACY_PROFILE.md §3/§4（M2 工作项）。链中立：
//! 玩家身份 = 钱包 felt（与 vault 键域一致），金额 = wei（i128），无链类型。
//!
//! ## 树规格（确定性，链上可复算）
//!
//! - 叶集 = 当前**非零**余额玩家（余额归零即移出叶集——零负债不占叶），
//!   按 player felt 升序（`Felt` 的 Ord = 数值序）；
//! - 域分隔常量：叶(plain)=1、叶(shield)=2、承诺=3、内部节点=4、
//!   blind 派生种子=5；
//! - plain 叶 = `poseidon([1, player, balance_felt])`；
//!   shield 叶 = `poseidon([2, player, commit])`，
//!   `commit = poseidon([3, player, balance_felt, blind])`；
//! - `balance_felt` = i128 的域内编码：b≥0 → `Felt(b)`；b<0 → `-Felt(|b|)`
//!   （模 P 补码）；
//! - 折叠 = `poseidon([4, l, r])`，奇数最后一片直升；单叶 = 叶本身；
//!   空树 = `Felt::ZERO`。
//!
//! ## 一致性模型（崩溃安全）
//!
//! - `apply` 以 `(table_id, hand_id)` 幂等（applied 集合持久化在 state）：
//!   回执先 apply 并落盘、后写 receipt；崩溃后重放 receipt 不会重复入树，
//!   反向序（state 落盘后崩溃、receipt 未写）也只会 Skipped；
//! - 应用即 checkpoint 追加（JSONL 审计语料）+ state 原子重写；
//! - 零和/余额下穿/玩家重复 fail-closed 拒绝——余额树与链上事实分歧
//!   绝不静默（逃生地基）。
//!
//! ## shielded 叶的 blind（M2 边界，诚实声明）
//!
//! M2 的 blind 为**占位派生**（`poseidon([5, player])`，见
//! [`BalanceRollup::blind_for`]）：只保证格式与根确定性，**不构成对爆破
//! 的隐藏承诺**（可推导的 blind = 无盐承诺）。真随机盲化因子 + 玩家持有
//! /交接协议是 M5 逃生合约窗口的设计项（docs §4 L4/blind 行）；shielded-v0
//! 本就不得以真链 REAL 开跑（docs §2 时限）。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub mod ledger;

use serde::{Deserialize, Serialize};
use starknet_crypto::poseidon_hash_many;
use starknet_types_core::felt::Felt;

/// state 文件版本（不兼容变更须升版并写迁移）。
pub const STATE_VERSION: u32 = 1;

// 域分隔常量（见模块文档树规格；小整数 felt，公式的一部分——链上复算
// 必须逐字一致，变更 = 树换根，需升 STATE_VERSION 并迁移）。
const DOMAIN_LEAF_PLAIN: u64 = 1;
const DOMAIN_LEAF_SHIELD: u64 = 2;
const DOMAIN_COMMIT: u64 = 3;
const DOMAIN_NODE: u64 = 4;
const DOMAIN_BLIND_SEED: u64 = 5;

/// 叶子格式（privacy-profile::BalanceLeafFormat 的本 crate 镜像——不引
/// 依赖，构造处逐字对拍）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafFormat {
    Plain,
    Commitment,
}

/// rollup 错误（fail-closed 全集；任何一态都不得被调用方吞掉——余额树
/// 与链上事实分歧 = 逃生地基破损）。
#[derive(Debug, thiserror::Error)]
pub enum RollupError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("state 版本 {found} 未知（本实现支持 ≤{STATE_VERSION}）")]
    Version { found: u32 },
    #[error("({table_id}-{hand_id}) players/deltas 长度不符（{p} vs {d}）")]
    LengthMismatch {
        table_id: u32,
        hand_id: u32,
        p: usize,
        d: usize,
    },
    #[error("({table_id}-{hand_id}) 空增量（无参与者）")]
    Empty { table_id: u32, hand_id: u32 },
    #[error("({table_id}-{hand_id}) 玩家重复：{player}")]
    DuplicatePlayer {
        table_id: u32,
        hand_id: u32,
        player: String,
    },
    #[error("({table_id}-{hand_id}) 增量非零和（Σ={sum}）")]
    ZeroSum {
        table_id: u32,
        hand_id: u32,
        sum: i128,
    },
    #[error("({table_id}-{hand_id}) 玩家 {player} 余额下穿（{balance} {delta:+} < 0）——\
             买入托管不足以覆盖该手支出，拒绝入树")]
    Underflow {
        table_id: u32,
        hand_id: u32,
        player: String,
        balance: i128,
        delta: i128,
    },
    #[error("player hex 非法：{0}")]
    BadPlayerHex(String),
}

/// 一手增量应用后的 checkpoint（JSONL 审计语料逐行追加）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceCheckpoint {
    /// 单调序号 = 应用完成后的累计手数。
    pub seq: u64,
    /// 应用时刻（unix 秒，调用方注入）。
    pub at: u64,
    pub table_id: u32,
    pub hand_id: u32,
    /// fold 批成员回执时携带批键（批伴随工件按批键引用本 checkpoint 面）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_key: Option<String>,
    pub prev_root: String,
    pub new_root: String,
}

/// 持久化 state（原子重写；重启后 `open` 恢复）。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RollupState {
    version: u32,
    /// 当前树根（0x + 64 hex）。
    root: String,
    /// 玩家（0x + 64 hex）→ 余额（wei；仅非零项）。
    balances: BTreeMap<String, i128>,
    /// 已应用手键 `"table-hand"`（幂等集合；压实策略后置——M2 体量可忽略）。
    applied: BTreeSet<String>,
    /// shielded 叶盲化因子（player hex → blind hex；v0 占位派生见
    /// [`BalanceRollup::blind_for`]，真随机注入走 [`BalanceRollup::set_blind`]）。
    blinds: BTreeMap<String, String>,
    applied_hands: u64,
    updated_at: u64,
    /// 最近 checkpoint 副本（JSONL 是权威语料，这里供 head() 直读）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    head: Option<BalanceCheckpoint>,
}

impl RollupState {
    fn genesis() -> Self {
        Self {
            version: STATE_VERSION,
            root: root_hex(Felt::ZERO),
            balances: BTreeMap::new(),
            applied: BTreeSet::new(),
            blinds: BTreeMap::new(),
            applied_hands: 0,
            updated_at: 0,
            head: None,
        }
    }
}

/// 应用结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// 新增量入树（幂等键首见）。
    Applied { prev_root: String, new_root: String },
    /// 幂等跳过（该手已在树中——崩溃重放/重复回执）。
    SkippedAlreadyApplied,
}

/// 余额 rollup（state + checkpoint JSONL 双持久化）。
pub struct BalanceRollup {
    state_path: PathBuf,
    checkpoint_path: PathBuf,
    leaf_format: LeafFormat,
    state: RollupState,
}

impl BalanceRollup {
    /// 打开（存在则恢复，缺失则 genesis）。两路径同目录时互不干扰
    /// （state 原子重写 / checkpoint 追加）。
    pub fn open(
        state_path: impl Into<PathBuf>,
        checkpoint_path: impl Into<PathBuf>,
        leaf_format: LeafFormat,
    ) -> Result<Self, RollupError> {
        let state_path = state_path.into();
        let checkpoint_path = checkpoint_path.into();
        let state = if state_path.exists() {
            let raw = std::fs::read_to_string(&state_path)?;
            let st: RollupState = serde_json::from_str(&raw)?;
            if st.version > STATE_VERSION {
                return Err(RollupError::Version { found: st.version });
            }
            st
        } else {
            RollupState::genesis()
        };
        Ok(Self {
            state_path,
            checkpoint_path,
            leaf_format,
            state,
        })
    }

    /// 当前树根（hex）。
    pub fn root_hex(&self) -> String {
        self.state.root.clone()
    }

    /// 累计已应用手数（checkpoint 单调序号的当前值）。
    pub fn applied_hands(&self) -> u64 {
        self.state.applied_hands
    }

    /// 最近 checkpoint（state 内副本；JSONL 为权威审计语料）。
    pub fn head(&self) -> Option<&BalanceCheckpoint> {
        self.state.head.as_ref()
    }

    pub fn leaf_format(&self) -> LeafFormat {
        self.leaf_format
    }

    /// 注入玩家盲化因子（shielded 叶；v0 占位派生的显式覆盖——M5 起由
    /// 真随机生成并交玩家持有）。已应用过的玩家改盲不改历史叶（树根只
    /// 在下一次该玩家余额变动时重算）——调用方应在首笔增量前注入。
    pub fn set_blind(&mut self, player: &Felt, blind: &Felt) {
        self.state
            .blinds
            .insert(player_hex(player), felt_hex(blind));
    }

    /// 创世余额种子（仅 `applied_hands == 0` 时可用——树已推进后禁止，
    /// 否则根会无 checkpoint 地跳变）。用途：M4 真链启用时以 vault 快照
    /// 播种开局面（buy-in 腿尚未进树，见模块文档 M2 边界）。
    pub fn seed_balances(
        &mut self,
        seeds: &[(Felt, i128)],
        at: u64,
    ) -> Result<(), RollupError> {
        if self.state.applied_hands != 0 {
            return Err(RollupError::Io(std::io::Error::other(
                "seed_balances 仅限创世（applied_hands == 0）",
            )));
        }
        let mut seen = BTreeSet::new();
        for (player, balance) in seeds {
            let hex_key = player_hex(player);
            if !seen.insert(hex_key.clone()) {
                return Err(RollupError::DuplicatePlayer {
                    table_id: 0,
                    hand_id: 0,
                    player: hex_key,
                });
            }
            if *balance < 0 {
                return Err(RollupError::Underflow {
                    table_id: 0,
                    hand_id: 0,
                    player: hex_key,
                    balance: 0,
                    delta: *balance,
                });
            }
            if *balance == 0 {
                continue; // 零余额不占叶（与树规格一致）。
            }
            self.state.balances.insert(hex_key, *balance);
        }
        self.state.root = root_hex(self.compute_root()?);
        self.state.updated_at = at;
        self.persist()?;
        Ok(())
    }

    /// 玩家盲化因子：显式注入优先；否则 v0 占位派生 `poseidon([5, player])`
    /// （可推导 = 不隐藏——诚实边界见模块文档，M5 换真随机 + 玩家持有）。
    pub fn blind_for(&self, player: &Felt) -> Felt {
        let key = player_hex(player);
        match self.state.blinds.get(&key) {
            Some(hex_str) => parse_felt(hex_str).unwrap_or_else(|_| placeholder_blind(player)),
            None => placeholder_blind(player),
        }
    }

    /// 应用一手增量（幂等；零和/下穿/重复玩家 fail-closed）。
    ///
    /// `batch_key`：fold 批成员回执时携带（checkpoint 与批伴随工件关联）。
    #[allow(clippy::too_many_arguments)]
    pub fn apply(
        &mut self,
        table_id: u32,
        hand_id: u32,
        players: &[Felt],
        deltas_wei: &[i128],
        batch_key: Option<&str>,
        at: u64,
    ) -> Result<ApplyOutcome, RollupError> {
        let applied_key = format!("{table_id}-{hand_id}");
        if self.state.applied.contains(&applied_key) {
            return Ok(ApplyOutcome::SkippedAlreadyApplied);
        }
        if players.is_empty() {
            return Err(RollupError::Empty { table_id, hand_id });
        }
        if players.len() != deltas_wei.len() {
            return Err(RollupError::LengthMismatch {
                table_id,
                hand_id,
                p: players.len(),
                d: deltas_wei.len(),
            });
        }
        // 校验面：零和（先于下穿——非零和根本不是合法手）→ 唯一性 → 下穿
        //（先全量校验后落状态）。
        let mut sum: i128 = 0;
        for d in deltas_wei {
            sum = sum
                .checked_add(*d)
                .ok_or(RollupError::ZeroSum {
                    table_id,
                    hand_id,
                    sum: i128::MAX,
                })?;
        }
        if sum != 0 {
            return Err(RollupError::ZeroSum {
                table_id,
                hand_id,
                sum,
            });
        }
        let mut seen = BTreeSet::new();
        for (p, d) in players.iter().zip(deltas_wei) {
            let hex_key = player_hex(p);
            if !seen.insert(hex_key.clone()) {
                return Err(RollupError::DuplicatePlayer {
                    table_id,
                    hand_id,
                    player: hex_key,
                });
            }
            let old = self.state.balances.get(&hex_key).copied().unwrap_or(0);
            let new = old.checked_add(*d).ok_or(RollupError::ZeroSum {
                table_id,
                hand_id,
                sum: i128::MAX,
            })?;
            if new < 0 {
                return Err(RollupError::Underflow {
                    table_id,
                    hand_id,
                    player: hex_key,
                    balance: old,
                    delta: *d,
                });
            }
        }

        let prev_root = self.state.root.clone();
        // 落状态：余额更新（零余额移出叶集）。
        for (p, d) in players.iter().zip(deltas_wei) {
            let hex_key = player_hex(p);
            let new = self.state.balances.get(&hex_key).copied().unwrap_or(0) + *d;
            if new == 0 {
                self.state.balances.remove(&hex_key);
            } else {
                self.state.balances.insert(hex_key, new);
            }
        }
        self.state.applied.insert(applied_key);
        self.state.applied_hands += 1;
        let new_root_hex = root_hex(self.compute_root()?);
        self.state.root = new_root_hex.clone();
        self.state.updated_at = at;

        let checkpoint = BalanceCheckpoint {
            seq: self.state.applied_hands,
            at,
            table_id,
            hand_id,
            batch_key: batch_key.map(str::to_string),
            prev_root: prev_root.clone(),
            new_root: new_root_hex.clone(),
        };
        append_checkpoint(&self.checkpoint_path, &checkpoint)?;
        self.state.head = Some(checkpoint.clone());
        self.persist()?;
        Ok(ApplyOutcome::Applied {
            prev_root,
            new_root: checkpoint.new_root,
        })
    }

    /// 树根重算（规格见模块文档；确定性——同状态同根）。state 内的
    /// player hex 均出自本结构落盘（自产自销），解析失败 = state 损坏，
    /// fail-closed 不静默。
    fn compute_root(&self) -> Result<Felt, RollupError> {
        let mut level: Vec<Felt> = self
            .state
            .balances
            .iter()
            .map(|(player_hex, balance)| {
                let player = parse_felt(player_hex)?;
                Ok(self.leaf_hash(&player, *balance))
            })
            .collect::<Result<_, RollupError>>()?;
        if level.is_empty() {
            return Ok(Felt::ZERO);
        }
        while level.len() > 1 {
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for pair in level.chunks(2) {
                let node = match pair {
                    [l, r] => poseidon_hash_many(&[
                        Felt::from(DOMAIN_NODE),
                        *l,
                        *r,
                    ]),
                    [only] => *only,
                    _ => unreachable!("chunks(2) 不产生空片"),
                };
                next.push(node);
            }
            level = next;
        }
        Ok(level[0])
    }

    fn leaf_hash(&self, player: &Felt, balance: i128) -> Felt {
        let balance_felt = balance_to_felt(balance);
        match self.leaf_format {
            LeafFormat::Plain => poseidon_hash_many(&[
                Felt::from(DOMAIN_LEAF_PLAIN),
                *player,
                balance_felt,
            ]),
            LeafFormat::Commitment => {
                let commit = poseidon_hash_many(&[
                    Felt::from(DOMAIN_COMMIT),
                    *player,
                    balance_felt,
                    self.blind_for(player),
                ]);
                poseidon_hash_many(&[
                    Felt::from(DOMAIN_LEAF_SHIELD),
                    *player,
                    commit,
                ])
            }
        }
    }

    fn persist(&self) -> Result<(), RollupError> {
        atomic_write_json(&self.state_path, &self.state)?;
        Ok(())
    }
}

/// v0 占位 blind：`poseidon([5, player])`（可推导——不构成隐藏，见模块文档）。
fn placeholder_blind(player: &Felt) -> Felt {
    poseidon_hash_many(&[Felt::from(DOMAIN_BLIND_SEED), *player])
}

/// i128 → 域内 felt（b<0 → 模 P 补码）。
fn balance_to_felt(balance: i128) -> Felt {
    if balance >= 0 {
        Felt::from(balance.unsigned_abs())
    } else {
        Felt::ZERO - Felt::from(balance.unsigned_abs())
    }
}

fn player_hex(player: &Felt) -> String {
    felt_hex(player)
}

fn felt_hex(f: &Felt) -> String {
    format!("0x{}", hex::encode(f.to_bytes_be()))
}

fn parse_felt(s: &str) -> Result<Felt, RollupError> {
    Felt::from_hex(s.trim().trim_start_matches("0x"))
        .map_err(|_| RollupError::BadPlayerHex(s.to_string()))
}

fn root_hex(root: Felt) -> String {
    felt_hex(&root)
}

/// 原子写（tmp + rename + sync；settle-queue sidecar 同式——独立实现避免
/// 反向依赖）。
fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
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
    std::fs::rename(&tmp, path)
}

/// checkpoint 追加（JSONL 审计语料；逐行落盘 + sync）。
fn append_checkpoint<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let mut line = serde_json::to_vec(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json: {e}")))?;
    line.push(b'\n');
    f.write_all(&line)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felt(v: u64) -> Felt {
        Felt::from(v)
    }

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "balance-rollup-{tag}-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// genesis 根 = ZERO；创世种子 + 首笔应用改根、checkpoint 追加、
    /// state 落盘；重开恢复同根（崩溃安全面）；种子仅限创世。
    #[test]
    fn open_apply_reopen_roundtrip() {
        let dir = tmp("roundtrip");
        let state = dir.join("state.json");
        let log = dir.join("checkpoints.jsonl");
        let mut r = BalanceRollup::open(&state, &log, LeafFormat::Plain).unwrap();
        assert_eq!(r.root_hex(), felt_hex(&Felt::ZERO));
        assert_eq!(r.applied_hands(), 0);

        // 创世种子（vault 快照形态）：输家先有买入余额。
        r.seed_balances(&[(felt(0xB), 500)], 99).unwrap();
        assert_ne!(r.root_hex(), felt_hex(&Felt::ZERO), "种子即入叶集");
        // 已推进后种子禁止（独立文件，避免与主流程共享状态互踩）。
        {
            let mut rx = BalanceRollup::open(
                dir.join("state-x.json"),
                dir.join("cp-x.jsonl"),
                LeafFormat::Plain,
            )
            .unwrap();
            rx.seed_balances(&[(felt(0xD), 7)], 0).unwrap();
            rx.apply(1, 1, &[felt(0xA), felt(0xD)], &[1, -1], None, 1)
                .unwrap();
            assert!(rx.seed_balances(&[(felt(0xE), 1)], 2).is_err());
        }

        let out = r
            .apply(1, 10, &[felt(0xA), felt(0xB)], &[500, -500], None, 100)
            .unwrap();
        let ApplyOutcome::Applied { prev_root, new_root } = &out else {
            panic!("首笔必须 Applied");
        };
        assert_ne!(*new_root, felt_hex(&Felt::ZERO));
        assert_eq!(r.root_hex(), *new_root);
        assert_eq!(r.applied_hands(), 1);

        // 重开：根/计数恢复（state 落盘生效）。
        let r3 = BalanceRollup::open(&state, &log, LeafFormat::Plain).unwrap();
        assert_eq!(r3.root_hex(), *new_root);
        assert_eq!(r3.applied_hands(), 1);
        // checkpoint 语料在案（JSONL 一行）。
        let lines = std::fs::read_to_string(&log).unwrap();
        assert_eq!(lines.lines().count(), 1);
        assert!(lines.contains("\"new_root\""));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 幂等：同手重复应用 Skipped（根不变、计数不变）。
    #[test]
    fn apply_is_idempotent_per_hand() {
        let dir = tmp("idempotent");
        let mut r = BalanceRollup::open(
            dir.join("state.json"),
            dir.join("cp.jsonl"),
            LeafFormat::Plain,
        )
        .unwrap();
        r.seed_balances(&[(felt(0xD), 7)], 0).unwrap();
        let first = r
            .apply(2, 3, &[felt(0xC), felt(0xD)], &[7, -7], None, 1)
            .unwrap();
        assert!(matches!(first, ApplyOutcome::Applied { .. }));
        let root = r.root_hex();
        let second = r
            .apply(2, 3, &[felt(0xC), felt(0xD)], &[7, -7], None, 2)
            .unwrap();
        assert_eq!(second, ApplyOutcome::SkippedAlreadyApplied);
        assert_eq!(r.root_hex(), root, "重复应用不改根");
        assert_eq!(r.applied_hands(), 1, "重复应用不计数");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// fail-closed 全集：零和 / 下穿 / 玩家重复 / 长度 / 空。
    #[test]
    fn invalid_entries_rejected() {
        let dir = tmp("invalid");
        let mut r = BalanceRollup::open(
            dir.join("state.json"),
            dir.join("cp.jsonl"),
            LeafFormat::Plain,
        )
        .unwrap();
        // 非零和（先于下穿校验——非零和根本不是合法手）。
        assert!(matches!(
            r.apply(1, 1, &[felt(1), felt(2)], &[100, -99], None, 1),
            Err(RollupError::ZeroSum { sum: 1, .. })
        ));
        // 下穿（零和面内：玩家 4 无余额却要付 1——买入托管不足以覆盖）。
        assert!(matches!(
            r.apply(1, 2, &[felt(3), felt(4)], &[1, -1], None, 1),
            Err(RollupError::Underflow { .. })
        ));
        // 下穿后状态未变（先校验后落状态）。
        assert!(r.state.balances.is_empty());
        // 玩家重复。
        assert!(matches!(
            r.apply(1, 3, &[felt(4), felt(4)], &[5, -5], None, 1),
            Err(RollupError::DuplicatePlayer { .. })
        ));
        // 长度不符 / 空。
        assert!(matches!(
            r.apply(1, 4, &[felt(5)], &[5, -5], None, 1),
            Err(RollupError::LengthMismatch { .. })
        ));
        assert!(matches!(
            r.apply(1, 5, &[], &[], None, 1),
            Err(RollupError::Empty { .. })
        ));
        assert_eq!(r.applied_hands(), 0, "全部拒绝后零入树");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 链式：prev→new 逐笔咬合；余额归零玩家移出叶集（回到空树根）。
    #[test]
    fn chain_prev_new_and_zero_balance_pruned() {
        let dir = tmp("chain");
        let mut r = BalanceRollup::open(
            dir.join("state.json"),
            dir.join("cp.jsonl"),
            LeafFormat::Plain,
        )
        .unwrap();
        // 输家先播种（vault 快照形态），一手出入后净额换手。
        r.seed_balances(&[(felt(8), 42)], 0).unwrap();
        let o1 = r
            .apply(1, 1, &[felt(9), felt(8)], &[42, -42], None, 1)
            .unwrap();
        let ApplyOutcome::Applied { new_root: r1, .. } = o1 else {
            panic!()
        };
        // 反向一手：净额换手回 8（9 归零出叶、8 回 42）。
        let o2 = r
            .apply(1, 2, &[felt(9), felt(8)], &[-42, 42], None, 2)
            .unwrap();
        let ApplyOutcome::Applied { prev_root, new_root } = o2 else {
            panic!()
        };
        assert_eq!(prev_root, r1, "checkpoint prev = 上根（链式咬合）");
        // 同终态同根：与「新开实例直接种子 [(8,42)]」逐字节一致——路径无关
        // （确定性树，链上可复算的关键性质）。
        let dir2 = tmp("chain-fresh");
        let mut fresh = BalanceRollup::open(
            dir2.join("state.json"),
            dir2.join("cp.jsonl"),
            LeafFormat::Plain,
        )
        .unwrap();
        fresh.seed_balances(&[(felt(8), 42)], 0).unwrap();
        assert_eq!(new_root, fresh.root_hex());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 叶格式决定根：同状态 plain ≠ commitment；确定性（同状态同根）。
    #[test]
    fn leaf_format_changes_root_deterministically() {
        let root_of = |fmt: LeafFormat| {
            let dir = tmp(&format!("fmt-{:?}", fmt));
            let mut r = BalanceRollup::open(
                dir.join("state.json"),
                dir.join("cp.jsonl"),
                fmt,
            )
            .unwrap();
            r.seed_balances(&[(felt(0xB), 700)], 0).unwrap();
            r.apply(1, 1, &[felt(0xA), felt(0xB)], &[700, -700], None, 1)
                .unwrap();
            let root = r.root_hex();
            // 同状态重算确定性（A 出 1 回 1，净额回种子终态）。
            r.apply(1, 2, &[felt(0xA), felt(0xB)], &[-1, 1], None, 2)
                .unwrap();
            r.apply(1, 3, &[felt(0xA), felt(0xB)], &[1, -1], None, 3)
                .unwrap();
            assert_eq!(r.root_hex(), root, "过手归零后根复原（确定性）");
            std::fs::remove_dir_all(&dir).ok();
            root
        };
        let plain = root_of(LeafFormat::Plain);
        let shield = root_of(LeafFormat::Commitment);
        assert_ne!(plain, shield, "叶公式是根公式的一部分");
    }

    /// balance_felt 负数编码：模 P 补码（正负不同叶；极端 i128 不 panic）。
    #[test]
    fn negative_balance_encoding() {
        let pos = balance_to_felt(5);
        let neg = balance_to_felt(-5);
        assert_ne!(pos, neg);
        let _ = balance_to_felt(i128::MIN);
        let _ = balance_to_felt(i128::MAX);
    }
}
