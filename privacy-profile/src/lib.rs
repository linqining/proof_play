//! PRIVACY_PROFILE——隐私分档与三层选择面（docs/design/PRIVACY_PROFILE.md 定稿）。
//!
//! **链中立**：本 crate 零依赖、词汇表不含任何链名；历史 env 旧值
//! （`legacy`/`snip36` 等语句面旧值）的别名映射由调用方以 raw 值参数传入
//! [`resolve`]——本 crate 自身的词汇只有 `plaintext|committed`（语句面）、
//! `direct|shielded`（资金腿）、`plain|commitment`（余额叶）与档位名。
//!
//! 组合封闭（docs §6 纪律 2）：只接受具名档位推导的三层组合，非法组合
//! fail-closed（[`resolve`] 返回 Err）。解析顺序（docs §5）：
//!
//! 1. 显式 `PRIVACY_PROFILE`（transparent|shielded）优先；未知值 = Err。
//! 2. 缺失时按语句面旧值别名：`snip36` → shielded-v0、`legacy` →
//!    transparent（其余旧值钉 legacy 的语义镜像为 transparent——
//!    texas config.rs「未知值钉 legacy 并告警」同口径）。
//! 3. 两者皆缺 → 隐式 transparent（[`PrivacyPlan::implicit`] = true——
//!    REAL 桌面必须显式声明，调用方负责把 implicit 当告警/拒绝条件）。
//!
//! shielded 档级别（[`ShieldedLevel`]）：v0 = 过渡态（语句面 L2/L4 未加固、
//! 资金腿允许 direct——仅测试网，真链 REAL 不得以 v0 开跑）；v1 = 电路加固
//! （M5）+ 资金腿 shielded 强制。

/// 语句面：plaintext = legacy 明文 calldata；committed = v2 承诺语句。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementMode {
    Plaintext,
    Committed,
}

impl StatementMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Committed => "committed",
        }
    }
}

/// 资金腿：direct = 1:1 托管直进直出；shielded = 池/note 匿名腿。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyFlow {
    Direct,
    Shielded,
}

impl CustodyFlow {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Shielded => "shielded",
        }
    }
}

/// balance_root 叶子格式（随档位决定，不设独立配置键——docs §3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceLeafFormat {
    /// 明文叶：`poseidon([DOMAIN_LEAF_PLAIN, player, balance])`。
    Plain,
    /// 承诺叶：`poseidon([DOMAIN_LEAF_SHIELD, player, commit(player, balance, blind)])`。
    Commitment,
}

impl BalanceLeafFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Commitment => "commitment",
        }
    }
}

/// shielded 档的加固级别（v1 = M5 电路加固 + 资金腿强制之后）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShieldedLevel {
    V0,
    V1,
}

/// 隐私档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyProfile {
    Transparent,
    Shielded(ShieldedLevel),
}

impl PrivacyProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transparent => "transparent",
            Self::Shielded(_) => "shielded",
        }
    }

    pub fn shielded_level(self) -> Option<ShieldedLevel> {
        match self {
            Self::Transparent => None,
            Self::Shielded(level) => Some(level),
        }
    }
}

/// 解析结果：具名组合 + 来源标记。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyPlan {
    pub profile: PrivacyProfile,
    pub statement_mode: StatementMode,
    pub custody_flow: CustodyFlow,
    pub leaf_format: BalanceLeafFormat,
    /// true = 未显式声明 PRIVACY_PROFILE（别名/缺省推导）——REAL 桌调用方
    /// 应告警或拒绝。
    pub implicit: bool,
    /// true = shielded-v0 的资金腿过渡态（direct）——真链 REAL 不得以
    /// 此形态开跑（docs §2 shielded-v0 时限）。
    pub transitional: bool,
}

/// 语句面旧值 → [`StatementMode`]（`legacy`/`snip36` 为历史 env 值；其余
/// 非空旧值按 texas config 的「钉 legacy」语义归 Plaintext；空 = 未设）。
fn statement_mode_from_raw(raw: Option<&str>) -> Option<StatementMode> {
    match raw.map(str::trim) {
        None | Some("") => None,
        Some("plaintext") | Some("legacy") => Some(StatementMode::Plaintext),
        Some("committed") | Some("snip36") => Some(StatementMode::Committed),
        // 其余旧值钉 legacy（config.rs「未知值钉 legacy」镜像）。
        Some(_) => Some(StatementMode::Plaintext),
    }
}

fn custody_from_raw(raw: Option<&str>) -> Result<Option<CustodyFlow>, String> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some("direct") => Ok(Some(CustodyFlow::Direct)),
        Some("shielded") => Ok(Some(CustodyFlow::Shielded)),
        Some(other) => Err(format!(
            "CUSTODY_FLOW_MODE={other} 未知（可用 direct | shielded）——fail-closed"
        )),
    }
}

/// 解析隐私分档（docs/design/PRIVACY_PROFILE.md §2/§5）。
///
/// 参数均为 raw env 值（`None`/空串 = 未设置）：
/// - `profile_raw`：`PRIVACY_PROFILE`（transparent | shielded）；
/// - `statement_mode_raw`：语句面（新值 plaintext|committed，或历史值
///   legacy|snip36——别名映射见模块文档）；
/// - `custody_raw`：`CUSTODY_FLOW_MODE`（direct | shielded）；
/// - `shielded_level_raw`：`PRIVACY_SHIELDED_LEVEL`（v0 | v1；仅
///   shielded 档消费，缺省 v0）。
///
/// 非法组合（具名组合封闭）与未知显式值一律 Err——调用方 fail-closed
/// 拒启，不落缺省。
pub fn resolve(
    profile_raw: Option<&str>,
    statement_mode_raw: Option<&str>,
    custody_raw: Option<&str>,
    shielded_level_raw: Option<&str>,
) -> Result<PrivacyPlan, String> {
    // 1) 档位：显式优先，未知值 fail-closed；缺失按语句面旧值别名。
    let explicit = match profile_raw.map(str::trim) {
        None | Some("") => None,
        Some("transparent") => Some(PrivacyProfile::Transparent),
        Some("shielded") => {
            let level = match shielded_level_raw.map(str::trim) {
                None | Some("") | Some("v0") => ShieldedLevel::V0,
                Some("v1") => ShieldedLevel::V1,
                Some(other) => {
                    return Err(format!(
                        "PRIVACY_SHIELDED_LEVEL={other} 未知（可用 v0 | v1）——fail-closed"
                    ));
                }
            };
            Some(PrivacyProfile::Shielded(level))
        }
        Some(other) => {
            return Err(format!(
                "PRIVACY_PROFILE={other} 未知（可用 transparent | shielded）——fail-closed"
            ));
        }
    };
    let statement = statement_mode_from_raw(statement_mode_raw);
    let (profile, implicit) = match explicit {
        Some(p) => (p, false),
        None => match statement {
            // 别名：snip36（committed 语句面）→ shielded-v0 过渡态。
            Some(StatementMode::Committed) => (PrivacyProfile::Shielded(ShieldedLevel::V0), true),
            // legacy / 未知旧值 / 全缺 → transparent。
            _ => (PrivacyProfile::Transparent, true),
        },
    };

    // 2) 语句面：显式值优先；缺省随档位（transparent→plaintext、
    //    shielded→committed）。
    let statement_mode = match statement {
        Some(m) => m,
        None => match profile {
            PrivacyProfile::Transparent => StatementMode::Plaintext,
            PrivacyProfile::Shielded(_) => StatementMode::Committed,
        },
    };

    // 3) 资金腿：显式值优先；缺省随档位（shielded-v1 强制 shielded）。
    let custody = custody_from_raw(custody_raw)?;
    let (custody_flow, transitional) = match custody {
        Some(c) => {
            let transitional = matches!(
                profile,
                PrivacyProfile::Shielded(ShieldedLevel::V0)
            ) && c == CustodyFlow::Direct;
            (c, transitional)
        }
        None => match profile {
            PrivacyProfile::Transparent => (CustodyFlow::Direct, false),
            PrivacyProfile::Shielded(ShieldedLevel::V0) => (CustodyFlow::Direct, true),
            PrivacyProfile::Shielded(ShieldedLevel::V1) => (CustodyFlow::Shielded, false),
        },
    };

    // 4) 具名组合封闭（docs §2/§6）。
    match profile {
        PrivacyProfile::Transparent => {
            if statement_mode != StatementMode::Plaintext {
                return Err(format!(
                    "PRIVACY_PROFILE=transparent 要求语句面 plaintext，得到 {}——\
                     非法组合 fail-closed（committed 语句面属 shielded 档）",
                    statement_mode.as_str()
                ));
            }
            if custody_flow != CustodyFlow::Direct {
                return Err(
                    "PRIVACY_PROFILE=transparent 要求资金腿 direct——非法组合 fail-closed"
                        .into(),
                );
            }
        }
        PrivacyProfile::Shielded(level) => {
            if statement_mode != StatementMode::Committed {
                return Err(format!(
                    "PRIVACY_PROFILE=shielded 要求语句面 committed，得到 {}——\
                     非法组合 fail-closed（plaintext 明文 calldata 属 transparent 档）",
                    statement_mode.as_str()
                ));
            }
            if level == ShieldedLevel::V1 && custody_flow != CustodyFlow::Shielded {
                return Err(
                    "shielded-v1 要求资金腿 shielded（匿名腿强制）——\
                     direct 仅 v0 过渡态可用，fail-closed"
                        .into(),
                );
            }
        }
    }

    let leaf_format = match profile {
        PrivacyProfile::Transparent => BalanceLeafFormat::Plain,
        PrivacyProfile::Shielded(_) => BalanceLeafFormat::Commitment,
    };
    Ok(PrivacyPlan {
        profile,
        statement_mode,
        custody_flow,
        leaf_format,
        implicit,
        transitional,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 显式档位 + 各轴缺省：transparent 三层全明文/direct。
    #[test]
    fn explicit_transparent_defaults() {
        let plan = resolve(Some("transparent"), None, None, None).unwrap();
        assert_eq!(plan.profile, PrivacyProfile::Transparent);
        assert_eq!(plan.statement_mode, StatementMode::Plaintext);
        assert_eq!(plan.custody_flow, CustodyFlow::Direct);
        assert_eq!(plan.leaf_format, BalanceLeafFormat::Plain);
        assert!(!plan.implicit);
        assert!(!plan.transitional);
    }

    /// shielded 缺省 v0 过渡态（direct 允许）；v1 缺省强制 shielded 腿。
    #[test]
    fn explicit_shielded_levels() {
        let v0 = resolve(Some("shielded"), None, None, None).unwrap();
        assert_eq!(v0.profile, PrivacyProfile::Shielded(ShieldedLevel::V0));
        assert_eq!(v0.statement_mode, StatementMode::Committed);
        assert_eq!(v0.custody_flow, CustodyFlow::Direct);
        assert!(v0.transitional, "v0 + direct = 过渡态");
        assert_eq!(v0.leaf_format, BalanceLeafFormat::Commitment);

        let v1 = resolve(Some("shielded"), None, None, Some("v1")).unwrap();
        assert_eq!(v1.profile, PrivacyProfile::Shielded(ShieldedLevel::V1));
        assert_eq!(v1.custody_flow, CustodyFlow::Shielded);
        assert!(!v1.transitional);
    }

    /// 显式档位未知值 / 级别未知值 / 资金腿未知值 = fail-closed。
    #[test]
    fn unknown_explicit_values_rejected() {
        assert!(resolve(Some("private"), None, None, None).is_err());
        assert!(resolve(Some("SHIELDED"), None, None, None).is_err(), "精确匹配");
        assert!(resolve(Some("shielded"), None, None, Some("v2")).is_err());
        assert!(resolve(None, None, Some("mixed"), None).is_err());
    }

    /// 别名推导：snip36 → shielded-v0（implicit + transitional）；
    /// legacy / 未知旧值 / 全缺 → transparent（implicit）。
    #[test]
    fn alias_derivation_marks_implicit() {
        let alias = resolve(None, Some("snip36"), None, None).unwrap();
        assert_eq!(alias.profile, PrivacyProfile::Shielded(ShieldedLevel::V0));
        assert_eq!(alias.statement_mode, StatementMode::Committed);
        assert!(alias.implicit);
        assert!(alias.transitional);

        for raw in [Some("legacy"), Some("auto"), None] {
            let plan = resolve(None, raw, None, None).unwrap();
            assert_eq!(plan.profile, PrivacyProfile::Transparent, "{raw:?}");
            assert_eq!(plan.statement_mode, StatementMode::Plaintext);
            assert!(plan.implicit);
            assert!(!plan.transitional);
        }
    }

    /// 非法组合：transparent + committed / transparent + shielded 腿 /
    /// shielded + plaintext / v1 + direct 全部 fail-closed。
    #[test]
    fn illegal_combos_rejected() {
        assert!(resolve(Some("transparent"), Some("committed"), None, None).is_err());
        assert!(resolve(Some("transparent"), None, Some("shielded"), None).is_err());
        assert!(resolve(Some("shielded"), Some("plaintext"), None, None).is_err());
        assert!(resolve(Some("shielded"), None, Some("direct"), Some("v1")).is_err());
    }

    /// 合法显式组合：shielded-v0 + 显式 shielded 腿（非过渡）；
    /// shielded-v0 + 显式 direct（过渡）。
    #[test]
    fn explicit_custody_flags_transitional() {
        let hard = resolve(Some("shielded"), None, Some("shielded"), Some("v0")).unwrap();
        assert!(!hard.transitional);
        let soft = resolve(Some("shielded"), None, Some("direct"), Some("v0")).unwrap();
        assert!(soft.transitional);
    }
}
