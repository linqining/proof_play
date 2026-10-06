mod poker_vault;
/// STRK20 privacy-pool anonymizer (Plan B): private buy-ins via privacy_invoke.
mod poker_vault_anonymizer;
mod poker_settlement;
mod settlement_hash;

/// Dual-proof settlement (docs/design/DUAL_PROOF_PROTOCOL.md): on-chain BN254 sigma
/// verification for the P track + Phase-1 G registration.
mod dual;
mod poker_dual_settlement;

/// Part A Phase 1 (docs/design/SETTLEMENT_PRIVACY_PLAN.md): winners claim escrowed
/// payouts privately via secp256k1-signed STRK20 pool claims.
mod settlement_payout_anonymizer;

/// 桌台注册表：合约分配 table_id + 不可变 params_hash + 只追加的
/// Open→Closed 生命周期。"关桌后不开新手"的链上权威信号源。
mod poker_table_registry;
// 已退役并删除（2026-09-19）：poker_token（pSTRK 下线，筹码锚定规范 STRK）、
// cashout_unshield_helper（被 anonymizer v4 的 withdraw_to 守恒出金取代）。
// 历史地址见 strk20.json retired_contracts 与 DEPLOYMENTS.md。
