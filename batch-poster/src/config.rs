//! poster 运营配置——**不绑任何现状 env**（STARKNET_* 是 texas 的面；
//! poster 用 TEXAS_POSTER_* 自有命名空间，避免与游戏服务器共用进程环境
//! 语义）。

use std::path::PathBuf;
use std::time::Duration;

use starknet_txmgr::TxManagerConfig;
use starknet_types_core::felt::Felt;

/// Monad 工件落盘目录 env（跨仓工件：zchain 侧 monad_settlementd
/// `--mode settle` 经 `--settle-inbox` 从此目录消费 MonadProofEnvelope；
/// 消费方界定见 monad.rs 模块文档）。
pub const ENV_MONAD_SPOOL_DIR: &str = "TEXAS_MONAD_SPOOL_DIR";

/// balance rollup state 路径 env（escape 地基：非空即启用 rollup——
/// docs/design/PRIVACY_PROFILE.md §4 M2 行；fold 攒批启用时 rollup
/// 强制，见 [`PosterConfig::validate`]）。
pub const ENV_BALANCE_ROLLUP_STATE: &str = "TEXAS_BALANCE_ROLLUP_STATE";

/// balance rollup 配置。
#[derive(Debug, Clone)]
pub struct BalanceRollupConfig {
    /// state 路径非空 = 启用（缺省关——纯 linear dev 面可不带树）。
    pub enabled: bool,
    /// 余额 state（JSON，原子重写）。
    pub state_path: PathBuf,
    /// checkpoint 审计语料（JSONL 追加）。
    pub checkpoint_path: PathBuf,
    /// 账本镜像 state（escape-ledger：每批增量根的持久化面——规格
    /// 镜像与工件形态见 balance-rollup/src/ledger.rs 模块文档）。
    pub ledger_state_path: PathBuf,
    /// wei → 账本单位除数（生产 = chips；balance-rollup::
    /// ledger::PROD_WEI_PER_LEDGER_UNIT 同值锚，勿单侧改）。
    pub ledger_unit_divisor: u128,
}

impl Default for BalanceRollupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            state_path: PathBuf::from("poster-sidecar/balance-state.json"),
            checkpoint_path: PathBuf::from("poster-sidecar/balance-checkpoints.jsonl"),
            ledger_state_path: PathBuf::from("poster-sidecar/ledger-state.json"),
            ledger_unit_divisor: balance_rollup::ledger::PROD_WEI_PER_LEDGER_UNIT,
        }
    }
}

/// cadence（op-batcher max-channel-duration 式触发节奏）。
#[derive(Debug, Clone)]
pub struct CadenceConfig {
    /// 批手数上限 K（政策上限 64——stark-recursion/src/chain.rs:63
    /// MAX_HANDS_PER_LEAF；且批尺寸须为 2 的幂，chain.rs:165-175 校验）。
    pub max_batch_hands: usize,
    /// 攒批时间窗（最老候选等待超过此时长即触发——不满 max 也发）。
    pub max_wait_secs: u64,
    /// 触发下限（时间窗到期也至少攒够这么多手才成批；1 = 单手可成批）。
    pub min_batch_hands: usize,
}

impl Default for CadenceConfig {
    /// 运营默认值（2026-10-01 定版）：K=64（政策上限，摊薄 ~52s/批的出证
    /// 成本）、时间窗 300s（op-batcher max-channel-duration 量级——批延迟
    /// 上界 5 分钟）、min=1（窗到期单手也发，保 liveness；想进一步摊薄
    /// 出证成本的部署可调 2/4——经 `TEXAS_POSTER_MIN_BATCH_HANDS`）。
    fn default() -> Self {
        Self {
            max_batch_hands: 64,
            max_wait_secs: 300,
            min_batch_hands: 1,
        }
    }
}

/// fold 攒批开关（poster 运营配置；现状无 fold env——`SettleMode` 仅
/// {Linear, Proved}，`texas/src/starknet/config.rs:24-39`）。
#[derive(Debug, Clone)]
pub struct FoldConfig {
    pub enabled: bool,
    /// program_hash 对拍锚（prove-batch.sh EXPECTED_PH 行 同值）。
    pub expected_program_hash: String,
    /// prove-batch.sh 脚本路径（两阶段腿入口）。
    pub script: PathBuf,
    /// 基础手输入 JSON（prove-batch.sh 用法：`<K> <base> <out> [acc]`）。
    pub base_input: PathBuf,
    /// 出证工作目录。
    pub work_dir: PathBuf,
    /// 出证有界重试。
    pub max_proof_attempts: u32,
}

impl Default for FoldConfig {
    /// 运营默认值（2026-10-01 定版）：enabled=false（缺省关闭——fold 依赖
    /// prove-batch.sh 真机出证 ~52s/批与 K=64 内存余量，上线前必须过
    /// `scripts/batch-poster-smoke.sh` 干跑 + 手动真跑验收，见
    /// docs/BATCH_POSTER_OPS.md §6）；program_hash 钉 prove-batch.sh EXPECTED_PH 行
    /// EXPECTED_PH（9 人桌 2026-09-30 迁移后）；script 相对路径沿仓布局；
    /// base_input 空 = 运营必填（ScriptProofSource 把路径传给脚本，脚本
    /// 对缺失文件 fail-closed 报错——不给语料缺省是刻意的）；work_dir 落
    /// /tmp（K=64 峰值 ~3.7GiB，勿与系统共用小盘）；重试 3 次有界。
    fn default() -> Self {
        Self {
            enabled: false,
            // prove-batch.sh EXPECTED_PH 行的钉扎值（9 人桌 2026-09-30 迁移后）。
            expected_program_hash:
                "0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d".into(),
            script: PathBuf::from("../proving-tool/prove-batch.sh"),
            base_input: PathBuf::new(),
            work_dir: PathBuf::from("/tmp/zgame-batch-poster"),
            max_proof_attempts: 3,
        }
    }
}

/// poster 配置。
#[derive(Debug, Clone)]
pub struct PosterConfig {
    /// settle-queue WAL 路径（只读）。
    pub queue_wal: PathBuf,
    /// poster sidecar 目录（独占写）。
    pub sidecar_dir: PathBuf,
    /// Monad 工件落盘目录（env TEXAS_MONAD_SPOOL_DIR）。
    pub monad_spool_dir: PathBuf,
    /// 操作员账户（nonce 租约主体）。
    pub operator_account: Felt,
    /// PokerSettlement（legacy 两笔 + settlement_digest 可见性 view）。
    pub legacy_settlement: Felt,
    /// PokerDualSettlement（dual 两笔 + fold 批入口）。
    pub dual_settlement: Felt,
    pub cadence: CadenceConfig,
    pub fold: FoldConfig,
    /// Dual 腿投递重试上限（耗尽 → 投递期死信 → 等 texas 降级）。
    pub dual_max_attempts: u32,
    /// Legacy 腿投递重试上限（耗尽 → 终态死信，停发观察）。
    pub legacy_max_attempts: u32,
    /// daemon 轮询间隔。
    pub poll_interval: Duration,
    /// 交易管理层配置。
    pub txmgr: TxManagerConfig,
    /// 可见性轮询策略（Legacy register 腿；txmgr 层）。
    pub visible: starknet_txmgr::VisiblePolicy,
    /// balance rollup（escape 地基；fold 攒批启用时强制——validate）。
    pub balance: BalanceRollupConfig,
    /// 隐私档位（docs/design/PRIVACY_PROFILE.md §5；决定余额叶格式）。
    /// None 且 [`Self::privacy_error`] 有值 = 解析失败（validate
    /// fail-closed 拒启）。
    pub privacy: Option<privacy_profile::PrivacyPlan>,
    pub privacy_error: Option<String>,
}

impl PosterConfig {
    /// 从 env 装配（运营配置；全部有缺省，dev 空值即全零地址）。
    pub fn from_env() -> Self {
        let fold = FoldConfig::default();
        // 隐私档位（链中立键 + 历史语句面值别名；解析失败不 panic——
        // validate fail-closed 拒启）。
        let (privacy, privacy_error) =
            match privacy_profile::resolve(
                std::env::var("PRIVACY_PROFILE").ok().as_deref(),
                std::env::var("STARKNET_SETTLEMENT_MODE").ok().as_deref(),
                std::env::var("CUSTODY_FLOW_MODE").ok().as_deref(),
                std::env::var("PRIVACY_SHIELDED_LEVEL").ok().as_deref(),
            ) {
                Ok(plan) => (Some(plan), None),
                Err(e) => {
                    eprintln!("[batch-poster] 隐私档位解析失败: {e}");
                    (None, Some(e))
                }
            };
        Self {
            queue_wal: env_path("TEXAS_POSTER_QUEUE_WAL", "settle-queue/queue.jsonl"),
            sidecar_dir: env_path("TEXAS_POSTER_SIDECAR_DIR", "poster-sidecar"),
            monad_spool_dir: std::env::var(ENV_MONAD_SPOOL_DIR)
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("poster-sidecar/monad-spool")),
            operator_account: env_felt("TEXAS_POSTER_OPERATOR").unwrap_or_default(),
            legacy_settlement: env_felt("TEXAS_POSTER_LEGACY_SETTLEMENT").unwrap_or_default(),
            dual_settlement: env_felt("TEXAS_POSTER_DUAL_SETTLEMENT").unwrap_or_default(),
            // cadence：Default 为运营默认值，env 逐项覆盖（min 也开 env——
            // 此前硬编码 1，运营无法在不重编译下调）。
            cadence: {
                let d = CadenceConfig::default();
                CadenceConfig {
                    max_batch_hands: std::env::var("TEXAS_POSTER_MAX_BATCH_HANDS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(d.max_batch_hands),
                    max_wait_secs: std::env::var("TEXAS_POSTER_MAX_WAIT_SECS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(d.max_wait_secs),
                    min_batch_hands: std::env::var("TEXAS_POSTER_MIN_BATCH_HANDS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(d.min_batch_hands),
                }
            },
            fold: FoldConfig {
                enabled: std::env::var("TEXAS_POSTER_FOLD_ENABLED")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false),
                script: env_path(
                    "TEXAS_POSTER_PROVE_SCRIPT",
                    "../proving-tool/prove-batch.sh",
                ),
                base_input: env_path(
                    "TEXAS_POSTER_PROVE_BASE_INPUT",
                    &fold.base_input.to_string_lossy(),
                ),
                work_dir: env_path(
                    "TEXAS_POSTER_PROVE_WORK_DIR",
                    &fold.work_dir.to_string_lossy(),
                ),
                max_proof_attempts: std::env::var("TEXAS_POSTER_MAX_PROVE_ATTEMPTS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(fold.max_proof_attempts),
                ..fold
            },
            dual_max_attempts: 8,
            legacy_max_attempts: 8,
            poll_interval: Duration::from_secs(3),
            txmgr: TxManagerConfig::default(),
            visible: starknet_txmgr::VisiblePolicy::default(),
            balance: {
                let d = BalanceRollupConfig::default();
                let state_path = env_path(ENV_BALANCE_ROLLUP_STATE, &d.state_path.to_string_lossy());
                let enabled = std::env::var(ENV_BALANCE_ROLLUP_STATE)
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false);
                BalanceRollupConfig {
                    enabled,
                    state_path,
                    checkpoint_path: env_path(
                        "TEXAS_BALANCE_ROLLUP_CHECKPOINTS",
                        &d.checkpoint_path.to_string_lossy(),
                    ),
                    ledger_state_path: env_path(
                        "TEXAS_BALANCE_LEDGER_STATE",
                        &d.ledger_state_path.to_string_lossy(),
                    ),
                    ledger_unit_divisor: std::env::var("TEXAS_BALANCE_LEDGER_UNIT_WEI")
                        .ok()
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(d.ledger_unit_divisor),
                }
            },
            // 隐私档位（链中立键 + 历史语句面值别名；解析失败不 panic——
            // validate fail-closed 拒启）。
            privacy,
            privacy_error,
        }
    }

    /// K 政策校验（构造期 fail-closed：批上限不得超过
    /// stark_recursion::chain::MAX_HANDS_PER_LEAF 且 ≥1）+ 隐私档位 +
    /// rollup 硬门槛（fold 攒批必须带 balance rollup——escape 无地基
    /// 不得真上链，docs/design/PRIVACY_PROFILE.md §4 M2 行）。
    pub fn validate(&self) -> Result<(), String> {
        let cap = stark_recursion::chain::MAX_HANDS_PER_LEAF;
        if self.cadence.max_batch_hands == 0 || self.cadence.max_batch_hands > cap {
            return Err(format!(
                "max_batch_hands {} 越界（1..={cap}，chain.rs:63 政策）",
                self.cadence.max_batch_hands
            ));
        }
        if self.cadence.min_batch_hands < 1
            || self.cadence.min_batch_hands > self.cadence.max_batch_hands
        {
            return Err("min_batch_hands 须在 1..=max_batch_hands".into());
        }
        // 隐私档位：显式未知值/非法组合 fail-closed（解析错误由 from_env
        // 捕获到此）。
        if let Some(e) = &self.privacy_error {
            return Err(format!("隐私档位解析失败——{e}"));
        }
        if self.privacy.is_none() {
            return Err("隐私档位未解析（内部不变量：from_env 必须产出 plan 或 error）".into());
        }
        // M2 硬门槛：fold 攒批 ⇒ balance rollup。
        if self.fold.enabled && !self.balance.enabled {
            return Err(format!(
                "fold 攒批必须启用 balance rollup（escape 地基随批，否则逃生验证无地基）\
                 ——设 {ENV_BALANCE_ROLLUP_STATE}=<state 路径>"
            ));
        }
        // 隐式档位告警（REAL 桌面必须显式声明——docs §5；此处告警不拒启，
        // REAL 的强制属 venue 政策接线，M5 窗口落地）。
        if let Some(plan) = &self.privacy
            && plan.implicit
        {
            eprintln!(
                "[batch-poster] PRIVACY_PROFILE 未显式声明，隐式推导 {}（REAL 桌面必须显式）",
                plan.profile.as_str()
            );
        }
        Ok(())
    }
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var(name)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(default))
}

fn env_felt(name: &str) -> Option<Felt> {
    std::env::var(name).ok().and_then(|s| parse_felt_hex(&s))
}

/// hex（0x 前缀可选）→ Felt。
pub fn parse_felt_hex(s: &str) -> Option<Felt> {
    Felt::from_hex(s.trim().trim_start_matches("0x")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// K 政策校验：上限 64（chain.rs:63），越界 fail-closed。
    #[test]
    fn cadence_bounds_enforced() {
        let mut cfg = PosterConfig {
            queue_wal: PathBuf::new(),
            sidecar_dir: PathBuf::new(),
            monad_spool_dir: PathBuf::new(),
            operator_account: Felt::default(),
            legacy_settlement: Felt::default(),
            dual_settlement: Felt::default(),
            cadence: CadenceConfig::default(),
            fold: FoldConfig::default(),
            dual_max_attempts: 8,
            legacy_max_attempts: 8,
            poll_interval: Duration::from_secs(1),
            txmgr: TxManagerConfig::default(),
            visible: starknet_txmgr::VisiblePolicy::default(),
            balance: BalanceRollupConfig::default(),
            privacy: Some(privacy_profile::resolve(None, None, None, None).unwrap()),
            privacy_error: None,
        };
        assert!(cfg.validate().is_ok());
        cfg.cadence.max_batch_hands = 65;
        assert!(cfg.validate().is_err(), "K=65 > MAX_HANDS_PER_LEAF=64");
        cfg.cadence.max_batch_hands = 0;
        assert!(cfg.validate().is_err());
        // M2 硬门槛：fold 开 ⇒ rollup 必开。
        cfg.cadence.max_batch_hands = 64;
        cfg.fold.enabled = true;
        assert!(
            cfg.validate().is_err(),
            "fold 攒批无 balance rollup 必须拒启"
        );
        cfg.balance.enabled = true;
        assert!(cfg.validate().is_ok());
        // 隐私档位解析失败 fail-closed。
        cfg.privacy = None;
        cfg.privacy_error = Some("PRIVACY_PROFILE=x 未知".into());
        assert!(cfg.validate().is_err());
    }

    /// 运营默认值（条目 8 定版）：fold 缺省关闭、钉扎哈希形态合法、
    /// cadence 缺省 = K 政策上限 64（勿在此重复 batch.rs 的校验逻辑——
    /// 那是 MAX_HANDS_PER_LEAF 单源，这里只对拍缺省值）。
    #[test]
    fn operational_defaults() {
        let fold = FoldConfig::default();
        assert!(!fold.enabled, "fold 缺省关闭（真机出证 ~52s/批，须先过冒烟）");
        assert_eq!(fold.expected_program_hash.len(), 66, "0x + 64 hex");
        assert!(fold.expected_program_hash.starts_with("0x"));
        assert_eq!(fold.max_proof_attempts, 3);
        let cadence = CadenceConfig::default();
        assert_eq!(cadence.max_batch_hands, stark_recursion::chain::MAX_HANDS_PER_LEAF);
        assert_eq!(cadence.max_wait_secs, 300);
        assert_eq!(cadence.min_batch_hands, 1);
    }
}
