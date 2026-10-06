//! Starknet 环境配置。
//!
//! 所有地址留空时进入 dev 模式（跳过链上校验/提交，仅记账 + 生成 calldata），
//! 保证本地无 RPC 也能跑完整牌局流程。

use starknet_crypto::Felt;

/// 1 STRK = 10^18 wei，1 STRK = 1000 chips → 1 chip = 10^15 wei。
/// pSTRK/swap 已下线，筹码直接锚定原生 STRK。
pub const WEI_PER_CHIP: u128 = 1_000_000_000_000_000;

/// Hand-batch（DAPV）上链形态（`STARKNET_SETTLE_MODE`）：
///
/// - `Linear`（默认）：现状行为——p_batch 全文上链，链上做 ρ 折叠校验。
///   除非显式配置，什么都不变。
/// - `Proved`：p_batch 不上链；register/settle 换用 proved 入口
///   （`register_hand_proved` / `verify_and_settle_dapv_proved`），settle
///   只携带 `p_batch_commitment = poseidon(hand_binding,
///   poseidon(p_batch words))`。链上接受条件 = 调用者在合约 prover
///   白名单内（临时 prover-attestation 模型）。服务器侧需外部 prover
///   出具 attestation——当前 HTTP 客户端是必然报错的存根，所以 proved
///   模式实际总是自动回退 linear（结算绝不因 prover 阻塞）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SettleMode {
    #[default]
    Linear,
    Proved,
}

impl SettleMode {
    /// 大小写不敏感解析；未设置/未知值一律回到 Linear（默认路径，
    /// 行为与改造前逐字节一致）。
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "proved" => SettleMode::Proved,
            _ => SettleMode::Linear,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct StarknetConfig {
    /// JSON-RPC 端点（如 https://starknet-sepolia-rpc.publicnode.com）。
    pub rpc_url: String,
    /// 结算操作员账户地址（调用 register_aggregate / settle_hand 的 prover）。
    pub operator_address: String,
    /// 操作员签名私钥（hex，含或不含 0x 前缀均可）。
    pub operator_private_key: String,
    /// PokerVault 合约地址。留空跳过筹码余额/买入校验。
    pub vault_address: String,
    /// PokerSettlement 合约地址。留空只生成 calldata 不提交交易。
    pub settlement_address: String,
    /// PokerDualSettlement 合约地址（Hand-batch 路径：P 层 ρ 折叠残差链上验证）。
    /// 留空时 Hand-batch 路径不可用。
    pub dual_settlement_address: String,
    /// 结算模式：`dapv`（仅 DAPV，失败报错）| `legacy`（仅 register_aggregate/
    /// settle_hand）| `auto`（优先 DAPV，任一步失败自动回退 legacy）。
    /// 2026-09-06 起固定为 `legacy`（见 `from_env`）：结算期收集 endorsement
    /// 的 liveness 缺口在开局期铸造（DAPV §9 L2 注册期语义）落地前不可接受。
    pub settlement_mode: String,
    /// Hand-batch 上链形态（`STARKNET_SETTLE_MODE`，默认 Linear）。
    pub settle_mode: SettleMode,
    /// DAPV settle 上链入口（`STARKNET_DAPV_SETTLE_ENTRY`）：
    /// `v2`（默认）= `verify_and_settle_dapv_stark_private_v2`——零明文结算，
    /// fact-registry 单证明锚（settlement_private 电路），**可随时回退的
    /// 稳定入口**；`proved_private` = `verify_and_settle_dapv_proved_private`
    /// ——hand_verify + stark verify 双 fact 认证（P2-M4，dual v4）；
    /// `snip36` = `verify_and_settle_dapv_stark_private_v3`——SNIP-36
    /// proof_facts 优先 + fact-registry 降级双门（**合约侧随 cairo ≥2.12
    /// 迁移上链后生效**，选中现网会 revert，属预期）；`combined` =
    /// `verify_and_settle_dapv_combined_private`——P 层 + settlement 合并
    /// 信封（combined.cairo 一次出证），17 词公开段（v2 16 词段前置
    /// chain_acc）、单 fact 门 `fact = poseidon([combined_program_hash ‖
    /// 段17])`。
    /// 未知值一律回退 v2。
    pub dapv_settle_entry: String,
    /// combined 入口的程序哈希（`STARKNET_COMBINED_PROGRAM_HASH`，hex，
    /// 默认空）。空 = 读链上 `combined_program_hash` 视图（owner 经
    /// `set_combined_program_hash` 钉扎）；非空时优先（fact 计算与哈希
    /// 一致性校验的本地真源）。
    pub combined_program_hash: String,
    /// hand-verify-native 可执行路径（`STARKNET_COMBINED_NATIVE_BIN`，
    /// 默认空 = 自动发现：仓根 target/release/hand-verify-native，
    /// 见 settlement_prover::discover_combined_native_bin）。空且发现
    /// 失败 → combined 证明腿报错回退，不阻塞结算。
    pub combined_native_bin: String,
    /// 外部 batch-prover 服务端点（`STARKNET_PROVER_URL`）。proved 模式的
    /// attestation 来源；服务器只提交 workload、接收 attestation，绝不
    /// 进程内跑 prover。当前 HTTP 客户端为存根（必然报错 → 回退 linear），
    /// 变量先解析存储，待 prover 工具落地后启用。
    pub prover_url: Option<String>,
    /// proved 模式 workload JSON 导出目录（`STARKNET_PROVER_WORK_DIR`，
    /// 默认 `/tmp/zgame-prover`）——未来独立 prover CLI 消费的输入文件。
    pub prover_work_dir: String,
    /// SNIP-36 自托管 prover 端点（`STARKNET_SNIP36_PROVER_URL`，即
    /// starknet_transaction_prover 容器的 JSON-RPC）。仅
    /// dapv_settle_entry=snip36 时需要；服务无鉴权，务必内网/反代部署。
    pub snip36_prover_url: Option<String>,
    /// SNIP-36 证明交易的 l2_gas.max_amount（`STARKNET_SNIP36_L2_GAS`，
    /// 默认 0x5f5e100 = 100M ≈ 100 万 Cairo 步，prover README 锚点）——
    /// 即 OS 执行 gas 上限，非 0 是 prover 输入校验的硬要求。
    pub snip36_l2_gas: u64,
    /// true = 钱包签名必须通过 isValidSignature 链上验证；false = dev 模式放行。
    pub auth_strict: bool,
    /// 平台 treasury 地址（抽水接收方，`STARKNET_TREASURY_ADDRESS`）。
    /// 留空回退 operator 地址。
    pub treasury_address: String,
    /// 平台 owner 账户地址（`STARKNET_OWNER_ADDRESS`）。密钥分级（survey
    /// §9.4 建议 4 的代码级部分）：owner 是钉扎 combined_program_hash、
    /// 合约升级/程序哈希发布类操作的离线身份，operator 只发
    /// register/settle 热流。留空 = 未配置（行为与改造前逐字节一致）；
    /// 配置后经 [`StarknetConfig::validate`] 强制 owner ≠ operator
    /// （fail-closed，`from_env` 违例即拒绝启动）。
    pub owner_address: String,
    /// owner 签名私钥（hex，`STARKNET_OWNER_PRIVATE_KEY`）。必须与
    /// `owner_address` 成对配置；与 operator 私钥相同 → validate 拒绝。
    /// 注意本槽位是离线操作身份，当前无合约侧 operator 白名单（本轮
    /// 不动合约）， owner 私钥不应常驻服务器环境。
    pub owner_private_key: String,
    /// PokerTableRegistry 合约地址（`STARKNET_TABLE_REGISTRY_ADDRESS`）。
    /// 留空 = 纯链下模式（不建链上桌台锚点）。
    pub table_registry_address: String,
    /// B6：结算出口（`STARKNET_SETTLEMENT_EXIT`，默认 `appchain` 供 dev）。
    /// `appchain` = 嵌入式 sequencer 软确认链 + 本地出证（失败回退本枚举
    /// 的另一侧）；`starknet` = 遗留路径（行为与改造前逐字节一致）。
    pub settlement_exit: String,
    /// explorer gateway 基址（D4：`/api/v1/settlement/{binding}` 详情与
    /// `/api/v1/proof/{binding_hex}` attestation 的前缀；空 = 未部署不下发）。
    pub gateway_base_url: String,
    // 抽水参数不在本结构：链上/链下同一来源
    // `crate::pokergame::rake::rake_params`（STARKNET_RAKE_BPS/CAP）。
}

impl StarknetConfig {
    pub fn from_env() -> Self {
        let cfg = Self {
            rpc_url: std::env::var("STARKNET_RPC_URL").unwrap_or_default(),
            operator_address: std::env::var("STARKNET_OPERATOR_ADDRESS").unwrap_or_default(),
            operator_private_key: std::env::var("STARKNET_OPERATOR_PRIVATE_KEY")
                .unwrap_or_default(),
            vault_address: std::env::var("STARKNET_VAULT_ADDRESS").unwrap_or_default(),
            settlement_address: std::env::var("STARKNET_SETTLEMENT_ADDRESS").unwrap_or_default(),
            dual_settlement_address: std::env::var("STARKNET_DUAL_SETTLEMENT_ADDRESS")
                .unwrap_or_default(),
            // 2026-09-06：endorsement 收集通道删除后 DAPV 旧模式（dapv/auto）
            // 的前提已不存在，但动作签名（zgame.action-sig.v3）已成为每手
            // 必然的参与背书材料——`snip36` 模式据此启用：牌局结束异步出
            // 递归证明（action-sig 批次）后提交。除 snip36 外仍钉 legacy
            // （v2 结算不启动证明）。
            settlement_mode: {
                let requested = std::env::var("STARKNET_SETTLEMENT_MODE").unwrap_or_default();
                match requested.trim() {
                    "snip36" => "snip36".to_string(),
                    other => {
                        if !other.is_empty() && other != "legacy" {
                            eprintln!(
                                "[starknet-config] STARKNET_SETTLEMENT_MODE={other} ignored — \
                                 pinned to legacy (available: legacy | snip36)"
                            );
                        }
                        "legacy".to_string()
                    }
                }
            },
            settle_mode: SettleMode::parse(
                &std::env::var("STARKNET_SETTLE_MODE").unwrap_or_default(),
            ),
            dapv_settle_entry: std::env::var("STARKNET_DAPV_SETTLE_ENTRY").unwrap_or_default(),
            combined_program_hash: std::env::var("STARKNET_COMBINED_PROGRAM_HASH")
                .unwrap_or_default(),
            combined_native_bin: std::env::var("STARKNET_COMBINED_NATIVE_BIN").unwrap_or_default(),
            prover_url: std::env::var("STARKNET_PROVER_URL")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            prover_work_dir: std::env::var("STARKNET_PROVER_WORK_DIR")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/tmp/zgame-prover".to_string()),
            snip36_prover_url: std::env::var("STARKNET_SNIP36_PROVER_URL")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            snip36_l2_gas: std::env::var("STARKNET_SNIP36_L2_GAS")
                .ok()
                .and_then(|s| super::chain::parse_felt(&s))
                .and_then(|f| u64::try_from(f).ok())
                .unwrap_or(0x5f5e100),
            auth_strict: std::env::var("STARKNET_AUTH_STRICT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(false),
            treasury_address: std::env::var("STARKNET_TREASURY_ADDRESS").unwrap_or_default(),
            owner_address: std::env::var("STARKNET_OWNER_ADDRESS").unwrap_or_default(),
            owner_private_key: std::env::var("STARKNET_OWNER_PRIVATE_KEY").unwrap_or_default(),
            table_registry_address: std::env::var("STARKNET_TABLE_REGISTRY_ADDRESS")
                .unwrap_or_default(),
            settlement_exit: std::env::var("STARKNET_SETTLEMENT_EXIT").unwrap_or_default(),
            gateway_base_url: std::env::var("STARKNET_GATEWAY_URL").unwrap_or_default(),
        };
        // 密钥分级 fail-closed：owner/operator 同键属配置错误，构造期即
        // 拒绝启动（exit 2）——未配置 owner 槽位时此处恒通过，dev 行为不变。
        if let Err(e) = cfg.validate() {
            eprintln!("[starknet-config] fatal: {e}");
            std::process::exit(2);
        }
        cfg
    }

    /// 密钥分级校验（survey §9.4 建议 4 代码级；fail-closed）：
    ///
    /// - `STARKNET_OWNER_ADDRESS` / `STARKNET_OWNER_PRIVATE_KEY` 必须成对
    ///   配置（同空同有）；
    /// - owner 与 operator 不得同地址、不得同私钥（felt 归一化后比较）——
    ///   同一把钥匙既发结算热流又掌程序哈希钉扎/升级身份 = 分级失效。
    pub fn validate(&self) -> Result<(), String> {
        // 隐私档位校验（docs/design/PRIVACY_PROFILE.md §5）：显式未知值 /
        // 非法组合 fail-closed；档位缺失时按语句面旧值别名推导（隐式
        // transparent 允许——REAL 桌面的显式强制属 venue 政策，M5 窗口）。
        privacy_profile::resolve(
            std::env::var("PRIVACY_PROFILE").ok().as_deref(),
            Some(self.settlement_mode.as_str()),
            std::env::var("CUSTODY_FLOW_MODE").ok().as_deref(),
            std::env::var("PRIVACY_SHIELDED_LEVEL").ok().as_deref(),
        )
        .map(|plan| {
            if plan.implicit {
                // 告警不拒启（dev/测试网保持零配置可用）。
                eprintln!(
                    "[starknet-config] PRIVACY_PROFILE 未显式声明，隐式推导 {}（REAL 桌面必须显式）",
                    plan.profile.as_str()
                );
            }
        })?;
        let owner_addr_set = !self.owner_address.trim().is_empty();
        let owner_key_set = !self.owner_private_key.trim().is_empty();
        if owner_addr_set != owner_key_set {
            return Err(
                "STARKNET_OWNER_ADDRESS / STARKNET_OWNER_PRIVATE_KEY 必须成对配置（同空同有）"
                    .into(),
            );
        }
        if !owner_addr_set {
            return Ok(()); // owner 未配置：现状行为，无分级约束可查。
        }
        let owner_addr = super::chain::parse_felt(&self.owner_address)
            .ok_or_else(|| format!("STARKNET_OWNER_ADDRESS 非法 hex: {}", self.owner_address))?;
        let owner_key = super::chain::parse_felt(&self.owner_private_key)
            .ok_or_else(|| "STARKNET_OWNER_PRIVATE_KEY 非法 hex（拒绝启动）".to_string())?;
        if !self.operator_address.trim().is_empty()
            && super::chain::parse_felt(&self.operator_address) == Some(owner_addr)
        {
            return Err(
                "owner 地址 == operator 地址：密钥分级失效（survey §9.4 建议 4），拒绝启动".into(),
            );
        }
        if !self.operator_private_key.trim().is_empty()
            && super::chain::parse_felt(&self.operator_private_key) == Some(owner_key)
        {
            return Err(
                "owner 私钥 == operator 私钥：密钥分级失效（survey §9.4 建议 4），拒绝启动".into(),
            );
        }
        Ok(())
    }

    /// B6：结算出口是否为嵌入式 appchain（默认；`starknet` 显式回旧路）。
    pub fn settlement_exit_appchain(&self) -> bool {
        super::appchain::SettlementExit::parse(&self.settlement_exit)
            == super::appchain::SettlementExit::Appchain
    }

    /// 归一化的出口值（观测/日志用）。
    pub fn settlement_exit_name(&self) -> &'static str {
        if self.settlement_exit_appchain() {
            "appchain"
        } else {
            "starknet"
        }
    }

    /// RPC 是否可用（决定买入校验/上链提交是否真正执行）。
    pub fn rpc_enabled(&self) -> bool {
        !self.rpc_url.is_empty()
    }

    /// 桌台注册表是否启用（`STARKNET_TABLE_REGISTRY_ADDRESS` 配置即开启）。
    /// 开启后：建桌写注册表拿合约分配 id、关桌写链、开局前可读回状态；
    /// 未开启 = 纯链下模式（table_id 用服务端本地分配，行为不变）。
    pub fn table_registry_enabled(&self) -> bool {
        !self.table_registry_address.is_empty()
    }

    /// 是否启用 snip36 递归证明结算模式（牌局结束异步证明后提交；
    /// 非 snip36 模式（v2/legacy）不启动任何证明进程）。
    pub fn settlement_mode_snip36(&self) -> bool {
        self.settlement_mode.trim() == "snip36"
    }

    /// 归一化的 settle 入口值（trim 后；空/未知 → "v2"）。
    pub fn dapv_settle_entry(&self) -> &str {
        match self.dapv_settle_entry.trim() {
            "proved_private" => "proved_private",
            "snip36" => "snip36",
            "combined" => "combined",
            _ => "v2",
        }
    }

    /// combined 入口程序哈希（felt 形态；空/非法 hex → None，调用方回退
    /// 链上 `combined_program_hash` 视图）。
    pub fn combined_program_hash_felt(&self) -> Option<Felt> {
        let t = self.combined_program_hash.trim();
        if t.is_empty() {
            return None;
        }
        Felt::from_hex(t.trim_start_matches("0x").trim_start_matches("0X")).ok()
    }

    /// 结算上链是否可用（需要 RPC + settlement 合约 + 操作员密钥）。
    pub fn settlement_enabled(&self) -> bool {
        self.rpc_enabled()
            && !self.settlement_address.is_empty()
            && !self.operator_address.is_empty()
            && !self.operator_private_key.is_empty()
    }
}

#[cfg(test)]
mod wei_tests {
    /// 2026-09-04 回归：结算腿（submit.rs / dual_settle.rs 的 deltas 放大）
    /// 与买入记账（client WEI_PER_CHIP 同值）必须用同一常量。曾出现局部
    /// 定义 1e14 与全局 1e15 差 10 倍 → 链上余额与游戏输赢每手漂移 9/10。
    /// 客户端对应 client/src/starknet/config.ts（1 chip = 1e15 wei = 0.001 STRK）。
    #[test]
    fn wei_per_chip_is_locked_to_client_parity() {
        assert_eq!(super::WEI_PER_CHIP, 1_000_000_000_000_000u128);
    }

    /// 密钥分级（条目 5）：owner/operator 槽位 fail-closed 校验矩阵。
    #[test]
    fn owner_operator_key_separation_enforced() {
        let mut cfg = super::StarknetConfig::default();
        // owner 未配置 = 现状行为，通过。
        assert!(cfg.validate().is_ok());
        // 槽位必须成对。
        cfg.owner_address = "0x1234".into();
        assert!(cfg.validate().is_err(), "只配 address 不配 key 须拒绝");
        // 合法配置（owner 与 operator 完全分离）。
        cfg.owner_private_key = "0xaa".into();
        cfg.operator_address = "0x1".into();
        cfg.operator_private_key = "0xbb".into();
        assert!(cfg.validate().is_ok());
        // 同地址（0x 前缀/大小写差异归一化后仍判等）。
        cfg.owner_address = "0x0001".into();
        assert!(cfg.validate().is_err(), "owner==operator 地址须拒绝");
        cfg.owner_address = "0x1234".into();
        // 同私钥。
        cfg.owner_private_key = "0xbb".into();
        assert!(cfg.validate().is_err(), "owner==operator 私钥须拒绝");
        // 非法 hex fail-closed。
        cfg.owner_private_key = "0xzz".into();
        assert!(cfg.validate().is_err(), "owner 私钥非法 hex 须拒绝");
    }
}
