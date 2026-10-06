//! 洗牌证明留存（D1 证明通道数据层，`design/table/data-gaps-onchain.md`）。
//!
//! 现状（改造前）：`submit_verified_shuffle` / `join_player_and_shuffle`
//! 把 `ShuffleProofJson` 解析→验证后即弃，`ShuffleState` 无 proof 字段——
//! G2 证明面板 / T6 凭证第三段拿不到证明本体。本模块在验证点顺手留存：
//!
//! - 每层一条 [`ShuffleLayerRecord`]（seat / playerPk / 证明本体 JSON /
//!   verified / txDigest / ts / V2 transcript challenge）；
//! - 按手聚合为 [`HandProofLedgerEntry`]（hand_id 键，含 aggregate_pk 与
//!   deck_size），挂在 `Table.proof_ledger`（有界 FIFO，见
//!   [`PROOF_LEDGER_CAPACITY`]）；
//! - **方案 b 投影**（设计稿决策 2026-09-24）：G2 保持 V1 行名布局，V2
//!   证明由服务端投影出 `display` 字段——Σc1/Σc2 为牌组派生摘要（诚实
//!   标注 `derived: true`），Schnorr 行 V2 无对应物置 null；证明本体
//!   （`proof`）原样保留，V1/V2 两种形状都能渲染。
//!
//! 防重放口径（G2「本手 nonce」）：V1 层用证明自带 `nonce_hex`；V2 层的
//! 重放约束是 transcript statement（吸收输入牌组 + 聚合公钥），验证成功
//! 后从同一 transcript squeeze 出 `global_challenge` 作为展示值——它是
//! 「本层证明绑定到的完整语句」的确定性摘要，非协议独立字段。

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use poker_protocol::crypto::{EcPoint, ElGamalCiphertext};

use crate::pokergame::game_state::ShuffleProofJson;

/// 每桌保留的手数（FIFO 淘汰；证明 JSON 每层约 10–20 KB，20 手 × 9 层
/// 上界约 3.6 MB 内存，与 history store 100 条同级可接受）。
pub const PROOF_LEDGER_CAPACITY: usize = 20;

/// V1 布局展示投影（方案 b）。V2 证明的行是派生摘要或显式缺失。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ShuffleProofDisplay {
    /// V1: proof.sum_c1_commit_hex；V2: 派生 = Σ 输出牌组 c1。
    pub sum_c1_commit: Option<String>,
    /// V1: proof.sum_c2_commit_hex；V2: 派生 = Σ 输出牌组 c2。
    pub sum_c2_commit: Option<String>,
    /// V1: combined_schnorr_proof 承诺点 hex；V2: null（无对应子证明）。
    pub combined_schnorr_proof: Option<String>,
    /// V1: sum_c1_schnorr_proof 承诺点 hex；V2: null。
    pub sum_c1_schnorr_proof: Option<String>,
    /// V1: sum_c2_schnorr_proof 承诺点 hex；V2: null。
    pub sum_c2_schnorr_proof: Option<String>,
    /// V1: 证明自带 anti-replay nonce；V2: null（防重放 = transcript 绑定）。
    pub nonce: Option<String>,
    /// true = 上面的承诺行是服务端从牌组/证明派生的摘要，非证明原生字段。
    pub derived: bool,
}

/// 单层洗牌证明留存记录（一个玩家一次 shuffle/join 提交）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShuffleLayerRecord {
    /// 手内轮次（1 起；含开局洗牌与 reconstruct 后重加密轮）。
    pub round: u32,
    /// 提交者座位号（0 = 未入座/异常快照）。
    pub seat: u32,
    /// 提交者玩家公钥（hex）。
    pub player_pk: String,
    /// 提交者展示名（留存时快照，防止后续换座漂移）。
    pub player_name: String,
    /// 证明 wire 版本：1 = LegacyV1，2 = Bayer-Groth V2。
    pub proof_version: u8,
    /// 证明本体（服务端原样结构，untagged V1/V2 形状都保留）。
    pub proof: ShuffleProofJson,
    /// V1 布局展示投影（方案 b）。
    pub display: ShuffleProofDisplay,
    /// V2：验证后从生产域 transcript squeeze 的全局挑战（hex）；
    /// V1：None。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_challenge: Option<String>,
    /// 服务端验证结果。
    pub verified: bool,
    /// 链上交易 digest（洗牌验证当前链下完成 → null = 待上链态）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_digest: Option<String>,
    /// 留存时间（epoch ms）。
    pub ts: u64,
}

/// 一手牌的全部洗牌证明层。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandProofLedgerEntry {
    /// 本手 id（动作签名域 / 结算记账同源；0 = 开局前 pending 桶）。
    pub hand_id: u32,
    pub table_id: u32,
    /// 本手聚合公钥（hex，快照自洗牌终局时刻之前的首层留存点）。
    pub aggregate_pk: String,
    pub deck_size: usize,
    pub layers: Vec<ShuffleLayerRecord>,
}

/// Σ 点加法（空牌组 → None，调用方以 deck 常量兜底）。
pub fn sum_points(points: impl Iterator<Item = EcPoint>) -> Option<EcPoint> {
    points.reduce(|acc, p| acc + p)
}

/// 由输出牌组派生 V2 展示摘要：Σc1 / Σc2 的 hex（无牌组时 None）。
pub fn deck_digests(deck: &[ElGamalCiphertext]) -> (Option<String>, Option<String>) {
    let sum_c1 = sum_points(deck.iter().map(|c| c.c1));
    let sum_c2 = sum_points(deck.iter().map(|c| c.c2));
    (
        sum_c1.map(|p| poker_protocol::z_poker::convert::ecpoint_to_hex(&p)),
        sum_c2.map(|p| poker_protocol::z_poker::convert::ecpoint_to_hex(&p)),
    )
}

/// 构造 V1 布局投影（方案 b）。
///
/// - V1：字段直取证明本体，`derived = false`；
/// - V2：Σc1/Σc2 来自输出牌组派生摘要，Schnorr 行无对应物置 null，
///   `derived = true`（前端必须诚实标注派生）。
pub fn build_display(proof: &ShuffleProofJson, output_deck: &[ElGamalCiphertext]) -> ShuffleProofDisplay {
    use crate::pokergame::game_state::ShuffleProofJson as P;
    match proof {
        P::LegacyV1(v1) => ShuffleProofDisplay {
            sum_c1_commit: Some(v1.sum_c1_commit_hex.clone()),
            sum_c2_commit: Some(v1.sum_c2_commit_hex.clone()),
            combined_schnorr_proof: Some(v1.combined_schnorr_proof.commitment_hex.clone()),
            sum_c1_schnorr_proof: Some(v1.sum_c1_schnorr_proof.commitment_hex.clone()),
            sum_c2_schnorr_proof: Some(v1.sum_c2_schnorr_proof.commitment_hex.clone()),
            nonce: Some(v1.nonce_hex.clone()),
            derived: false,
        },
        P::BayerGrothV2(_) => {
            let (sum_c1, sum_c2) = deck_digests(output_deck);
            ShuffleProofDisplay {
                sum_c1_commit: sum_c1,
                sum_c2_commit: sum_c2,
                combined_schnorr_proof: None,
                sum_c1_schnorr_proof: None,
                sum_c2_schnorr_proof: None,
                nonce: None,
                derived: true,
            }
        }
    }
}

/// 有界留存缓冲：手数超容量淘汰最旧。
#[derive(Debug, Clone, Default)]
pub struct ProofLedger {
    entries: VecDeque<HandProofLedgerEntry>,
}

impl ProofLedger {
    /// 追加一层证明。`hand_id == 0` 进 pending 桶（开局前 join 洗牌层），
    /// 下一个非零手条目创建时被整体收编为该手的首批层。
    pub fn push_layer(&mut self, table_id: u32, hand_id: u32, aggregate_pk: &str, deck_size: usize, layer: ShuffleLayerRecord) {
        if hand_id == 0 {
            let entry = self.ensure_pending(table_id, aggregate_pk, deck_size);
            entry.layers.push(layer);
            return;
        }
        // 收编 pending 桶：开局前 join 洗的牌层属于即将开始的这手。
        let adopted_pending = self
            .entries
            .iter_mut()
            .find(|e| e.hand_id == 0)
            .map(|e| std::mem::take(&mut e.layers))
            .unwrap_or_default();
        if let Some(entry) = self.entries.iter_mut().find(|e| e.hand_id == hand_id) {
            entry.layers.push(layer);
            return;
        }
        let mut layers = adopted_pending;
        layers.push(layer);
        // 洗牌中聚合公钥会随入座玩家增长；取最新留存值，未变更时保持。
        let aggregate_pk = if aggregate_pk.is_empty() {
            self.entries
                .back()
                .map(|e| e.aggregate_pk.clone())
                .unwrap_or_default()
        } else {
            aggregate_pk.to_owned()
        };
        self.entries.push_back(HandProofLedgerEntry {
            hand_id,
            table_id,
            aggregate_pk,
            deck_size,
            layers,
        });
        // 被收编的 pending 空壳移除（get(0) 不再返回空条目）。
        self.entries.retain(|e| !(e.hand_id == 0 && e.layers.is_empty()));
        while self.entries.len() > PROOF_LEDGER_CAPACITY {
            self.entries.pop_front();
        }
    }

    fn ensure_pending(&mut self, table_id: u32, aggregate_pk: &str, deck_size: usize) -> &mut HandProofLedgerEntry {
        if let Some(idx) = self.entries.iter().position(|e| e.hand_id == 0) {
            let entry = &mut self.entries[idx];
            if !aggregate_pk.is_empty() {
                entry.aggregate_pk = aggregate_pk.to_owned();
            }
            return entry;
        }
        self.entries.push_back(HandProofLedgerEntry {
            hand_id: 0,
            table_id,
            aggregate_pk: aggregate_pk.to_owned(),
            deck_size,
            layers: Vec::new(),
        });
        self.entries.back_mut().expect("just pushed")
    }

    /// 按 hand_id 取条目（最新在前遍历）。
    pub fn get(&self, hand_id: u32) -> Option<&HandProofLedgerEntry> {
        self.entries.iter().rev().find(|e| e.hand_id == hand_id)
    }

    /// 下一层的轮次号（现有层数 + 1；新手首层计入待收编的 pending 层）。
    pub fn next_round(&self, hand_id: u32) -> u32 {
        let existing = self
            .entries
            .iter()
            .rev()
            .find(|e| e.hand_id == hand_id)
            .map(|e| e.layers.len())
            .unwrap_or(0);
        let pending = if existing == 0 {
            self.entries
                .iter()
                .find(|e| e.hand_id == 0)
                .map(|e| e.layers.len())
                .unwrap_or(0)
        } else {
            0
        };
        (existing + pending + 1) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(pk: &str, round: u32) -> ShuffleLayerRecord {
        ShuffleLayerRecord {
            round,
            seat: round,
            player_pk: pk.to_owned(),
            player_name: format!("p{round}"),
            proof_version: 2,
            proof: serde_json::from_value(serde_json::json!({
                "version": 2,
                "proof": {
                    "c_permutation_hex": "0x01",
                    "c_permuted_powers_hex": "0x02",
                    "multi_exponentiation": {
                        "c_alpha_hex": "0x01", "c_beta_hex": "0x01",
                        "ciphertext_0": {"c1_hex": "0x01", "c2_hex": "0x01"},
                        "ciphertext_1": {"c1_hex": "0x01", "c2_hex": "0x01"},
                        "alpha_response_hex": ["0x01"], "commitment_response_hex": "0x01",
                        "beta_hex": "0x01", "beta_blinding_response_hex": "0x01",
                        "rerandomization_response_hex": "0x01"
                    },
                    "product": {
                        "c_d_hex": "0x01", "c_delta_hex": "0x01", "c_capital_delta_hex": "0x01",
                        "a_response_hex": ["0x01"], "b_response_hex": ["0x01"],
                        "r_response_hex": "0x01", "s_response_hex": "0x01"
                    }
                }
            }))
            .expect("test v2 proof parses"),
            display: ShuffleProofDisplay {
                sum_c1_commit: None, sum_c2_commit: None,
                combined_schnorr_proof: None, sum_c1_schnorr_proof: None,
                sum_c2_schnorr_proof: None, nonce: None, derived: true,
            },
            global_challenge: Some("0xab".to_owned()),
            verified: true,
            tx_digest: None,
            ts: 1,
        }
    }

    #[test]
    fn pending_join_layers_adopted_by_next_hand() {
        let mut ledger = ProofLedger::default();
        // 开局前 join 洗牌（Waiting 阶段，current_hand_id 尚未分配）。
        ledger.push_layer(1, 0, "0xagg", 52, layer("0xpk-join", 1));
        // 下一手开局后的首层：pending 被收编为该手第一批层。
        ledger.push_layer(1, 7, "0xagg", 52, layer("0xpk-a", 2));
        let entry = ledger.get(7).expect("hand entry exists");
        assert_eq!(entry.layers.len(), 2);
        assert_eq!(entry.layers[0].player_pk, "0xpk-join", "join 层归入新手");
        assert_eq!(entry.layers[1].player_pk, "0xpk-a");
        assert!(ledger.get(0).is_none(), "pending 桶已清空");
        assert_eq!(entry.aggregate_pk, "0xagg");
    }

    #[test]
    fn fifo_capacity_evicts_oldest() {
        let mut ledger = ProofLedger::default();
        for hand in 1..=(PROOF_LEDGER_CAPACITY as u32 + 3) {
            ledger.push_layer(1, hand, "0xagg", 52, layer("0xpk", 1));
        }
        assert!(ledger.get(1).is_none(), "最旧手被淘汰");
        assert!(ledger.get(PROOF_LEDGER_CAPACITY as u32 + 3).is_some());
    }

    #[test]
    fn rounds_accumulate_within_hand() {
        let mut ledger = ProofLedger::default();
        for round in 1..=3 {
            ledger.push_layer(1, 9, "0xagg", 52, layer("0xpk", round));
        }
        let entry = ledger.get(9).expect("hand entry");
        assert_eq!(entry.layers.len(), 3);
        assert_eq!(entry.layers.last().unwrap().round, 3);
    }
}
