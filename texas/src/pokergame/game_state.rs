use std::collections::HashMap;

use poker_protocol::z_poker::convert::{ecpoint_to_hex, hex_to_ecpoint, hex_to_scalar};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};

use poker_protocol::crypto::DefaultCurve;
use poker_protocol::crypto::{CurveScalar, EcPoint, ElGamalCiphertext, Plaintext, Scalar};
use poker_protocol::z_poker::key_manager::PKOwnershipProof;
use poker_protocol::z_poker::protocol::LeaveGameRound;
use poker_protocol::z_poker::protocol::MaskAndShuffleRound;
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::bayer_groth::{
    BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument,
};
use poker_protocol::zk_shuffle::leave_proof::LeaveProof;
use poker_protocol::zk_shuffle::reconstruction::{
    CrossKeyNegationProof, ReconstructProof, ReconstructionStatement, SlotContributionOrProof,
};
use poker_protocol::zk_shuffle::remask_proof::RemaskProof;
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::versioned::VersionedShuffleProof;

use crate::pokergame::player::GamePkHex;

/// Macro to generate a JSON proof adapter struct and its conversion method.
/// Reduces boilerplate for structs where all fields are hex strings mapping to EcPoint or Scalar.
///
/// - `point` fields: hex string → EcPoint via `hex_to_ecpoint`
/// - `scalar` fields: hex string → Scalar via `hex_to_scalar`
/// - `scalar_vec` fields: Vec<String> → Vec<Scalar> via mapping `hex_to_scalar`
macro_rules! hex_proof_adapter {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident => [$($target:tt)+] {
            $($pfield:ident : $ptarget:ident),* $(,)?
        }
        scalar { $($sfield:ident : $starget:ident),* $(,)? }
        $(scalar_vec { $($svfield:ident : $svtarget:ident),* $(,)? })?
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $($pfield: String,)*
            $($sfield: String,)*
            $($($svfield: Vec<String>,)*)?
        }

        impl $name {
            pub fn to_proof(&self) -> Result<$($target)+, String> {
                Ok($($target)+ {
                    $($ptarget: hex_to_ecpoint(&self.$pfield)?,)*
                    $($starget: hex_to_scalar(&self.$sfield)?,)*
                    $($($svtarget: self.$svfield.iter()
                        .map(|h| hex_to_scalar(h))
                        .collect::<Result<Vec<_>, _>>()?,)*)?
                })
            }
        }
    };
}

/// 对齐 Move table_constants::shuffle_phase_*：
/// None=0, Waiting=1, Reconstruct=2, BeforePreflop=3
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub enum ShufflePhase {
    #[default]
    None,
    Waiting,
    Reconstruct,
    BeforePreflop,
}

impl ShufflePhase {
    /// 等价于 Move 的 shuffle_state.phase != shuffle_phase_none()
    pub fn is_active(self) -> bool {
        self != ShufflePhase::None
    }
}

impl std::fmt::Display for ShufflePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShufflePhase::None => write!(f, "none"),
            ShufflePhase::Waiting => write!(f, "waiting"),
            ShufflePhase::Reconstruct => write!(f, "reconstruct"),
            ShufflePhase::BeforePreflop => write!(f, "before_preflop"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShuffleState {
    /// 对齐 Move ShuffleState.phase：None 表示不活跃，BeforePreflop/Reconstruct 表示活跃
    pub phase: ShufflePhase,
    pub current_player_pk: Option<GamePkHex>,
    #[serde(skip)]
    pub timeout_start: Option<std::time::Instant>,
    pub timeout_seconds: u64,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    /// 本手 id（动作签名域 v2；开局分配，随状态广播到客户端）。
    #[serde(default)]
    pub hand_id: u32,
}

impl ShuffleState {
    pub fn new() -> Self {
        Self {
            phase: ShufflePhase::None,
            current_player_pk: None,
            timeout_start: None,
            timeout_seconds: 45,
            completed_players: Vec::new(),
            pending_players: Vec::new(),
            hand_id: 0,
        }
    }

    /// 等价于 Move 的 shuffle_state.phase != shuffle_phase_none()
    pub fn is_active(&self) -> bool {
        self.phase.is_active()
    }

    pub fn reset(&mut self) {
        self.phase = ShufflePhase::None;
        self.current_player_pk = None;
        self.timeout_start = None;
        self.timeout_seconds = 0;
        self.completed_players.clear();
        self.pending_players.clear();
    }
}

/// 对齐 Move table_constants::reveal_phase_*：
/// None=0 (inactive), HandReveal=1 (preflop), RedealReveal=2,
/// CommunityReveal=3 (flop/turn/river), ShowdownReveal=6
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub enum RevealPhase {
    #[default]
    None,
    HandReveal,
    RedealReveal,
    CommunityReveal,
    ShowdownReveal,
}

impl RevealPhase {
    /// 等价于 Move 的 reveal_phase != reveal_phase_none()
    pub fn is_active(self) -> bool {
        self != RevealPhase::None
    }
}

impl std::fmt::Display for RevealPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevealPhase::None => write!(f, "none"),
            RevealPhase::HandReveal => write!(f, "hand_reveal"),
            RevealPhase::CommunityReveal => write!(f, "community_reveal"),
            RevealPhase::ShowdownReveal => write!(f, "show_down_reveal"),
            RevealPhase::RedealReveal => write!(f, "redeal_reveal"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevealTokenState {
    /// 对齐 Move RevealTokenState.reveal_phase：None 表示不活跃
    pub phase: RevealPhase,
    pub current_card_index: usize,
    pub total_cards_per_player: usize,
    pub total_community_cards: usize,
    #[serde(skip)]
    pub timeout_start: Option<std::time::Instant>,
    /// 上次 REVEAL_NOTICE 广播时间：phase 存续期间周期性重播，
    /// 让刷新/重连后错过首播的客户端在超时前补交 reveal token。
    #[serde(skip)]
    pub last_notice_at: Option<std::time::Instant>,
    pub timeout_seconds: u64,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    pub player_assignments: HashMap<GamePkHex, PlayerRevealAssignment>,
}

impl RevealTokenState {
    pub fn new(cards_per_player: usize, community_cards: usize) -> Self {
        Self {
            phase: RevealPhase::None,
            current_card_index: 0,
            total_cards_per_player: cards_per_player,
            total_community_cards: community_cards,
            timeout_start: None,
            last_notice_at: None,
            timeout_seconds: 45,
            completed_players: Vec::new(),
            pending_players: Vec::new(),
            player_assignments: HashMap::new(),
        }
    }

    /// 等价于 Move 的 reveal_phase != reveal_phase_none()
    pub fn is_active(&self) -> bool {
        self.phase.is_active()
    }

    pub fn reset(&mut self) {
        self.phase = RevealPhase::None;
        self.current_card_index = 0;
        self.timeout_start = None;
        self.completed_players.clear();
        self.pending_players.clear();
        self.player_assignments.clear();
    }
}

#[derive(Debug, Clone, Default)]
pub struct PlayerRevealAssignment {
    pub hand_card: Vec<ElGamalCiphertext>,
    pub community_card: Vec<ElGamalCiphertext>,
}

#[derive(Debug, Clone, Default)]
pub struct PlayerResidualCarriers {
    pub residual_carriers: Vec<ElGamalCiphertext>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlayerResidualCarriersJson {
    pub residual_carriers: Vec<ElGamalCiphertextJson>,
}

impl Serialize for PlayerRevealAssignment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        let hand_card_jsons: Vec<ElGamalCiphertextJson> = self
            .hand_card
            .iter()
            .map(|c_uint| ElGamalCiphertextJson::from_ciphertext(c_uint))
            .collect();
        map.serialize_entry("hand_card", &hand_card_jsons)?;
        let community_card_jsons: Vec<ElGamalCiphertextJson> = self
            .community_card
            .iter()
            .map(|c_uint| ElGamalCiphertextJson::from_ciphertext(c_uint))
            .collect();
        map.serialize_entry("community_card", &community_card_jsons)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for PlayerRevealAssignment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            hand_card: Vec<ElGamalCiphertextJson>,
            community_card: Vec<ElGamalCiphertextJson>,
        }

        let helper = Helper::deserialize(deserializer)?;
        let hand_card = helper
            .hand_card
            .into_iter()
            .map(|json| json.to_ciphertext().map_err(serde::de::Error::custom))
            .collect::<Result<Vec<_>, _>>()?;
        let community_card = helper
            .community_card
            .into_iter()
            .map(|json| json.to_ciphertext().map_err(serde::de::Error::custom))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            hand_card,
            community_card,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReconstructState {
    pub is_active: bool,
    // pub phase: ReconstructPhase,
    pub timeout_start: Option<std::time::Instant>,
    pub timeout_seconds: u64,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>, // 发起时的玩家列表
    /// 本轮 reconstruct 的单调 epoch：进证明 statement 防跨轮重放。
    /// reset() 不清零（跨手单调），仅 start_reconstruct 递增。
    pub reconstruction_epoch: u64,
    /// 应用域摘要：绑定 table id / hand id / 曲线域（镜像 poker_l1 utils）。
    pub context_digest: [u8; 32],
    /// 每个玩家的上一轮 residual-carrier 状态摘要（服务端重算，拒绝客户端自报）。
    pub prior_state_digests: HashMap<GamePkHex, [u8; 32]>,
    pub cards: Vec<Plaintext>,
    /// 玩家 → 上一轮 owner residual carriers（原 player_readable_cards）。
    pub player_residual_carriers: HashMap<GamePkHex, PlayerResidualCarriers>,
    /// 玩家 → 已验证的 contributions（on_complete_reconstruct 同态叠加进新 deck）。
    pub player_deck: HashMap<GamePkHex, Vec<ElGamalCiphertext>>,
    /// L1 contributor mask 派生的聚合公钥（hex）——方案A 下由镜像权威提供，
    /// 是 reconstruct notice 与 statement 校验的单一真相（key_manager 聚合
    /// 仅作无镜像时的回退显示）。
    pub vm_aggregate_pk: String,
}

impl ReconstructState {
    pub fn new() -> Self {
        Self {
            is_active: false,
            timeout_start: None,
            timeout_seconds: 60,
            completed_players: Vec::new(),
            pending_players: Vec::new(),
            reconstruction_epoch: 0,
            context_digest: [0u8; 32],
            prior_state_digests: HashMap::new(),
            cards: Vec::new(),
            player_residual_carriers: HashMap::new(),
            player_deck: HashMap::new(),
            vm_aggregate_pk: String::new(),
        }
    }

    pub fn reset(&mut self) {
        self.is_active = false;
        self.timeout_start = None;
        self.completed_players.clear();
        self.pending_players.clear();
        self.cards.clear();
        // reconstruction_epoch 跨手单调，刻意不清零：epoch 回卷会让旧证明重放合法化。
        self.prior_state_digests.clear();
        self.player_residual_carriers.clear();
        self.player_deck.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealTokenPublicState {
    pub phase: String,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    pub player_assignments: HashMap<GamePkHex, PlayerRevealAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructPublicState {
    pub is_active: bool,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    pub cards: Vec<String>,
    /// 桌 epoch 聚合公钥（statement 绑定用）。
    pub aggregate_pk: String,
    /// 应用域摘要（statement.context_digest 回填用）。
    pub context_digest: String,
    /// 本轮 reconstruct epoch（statement.reconstruction_epoch 回填用）。
    pub reconstruction_epoch: u64,
    /// 玩家 → 上一轮 residual-carrier 状态摘要（statement.prior_state_digest 回填用）。
    pub prior_state_digests: HashMap<GamePkHex, String>,
    pub player_residual_carriers: HashMap<GamePkHex, PlayerResidualCarriersJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalCiphertextJson {
    pub c1_hex: String,
    pub c2_hex: String,
}

impl ElGamalCiphertextJson {
    pub fn from_ciphertext(ct: &poker_protocol::crypto::ElGamalCiphertext) -> Self {
        Self {
            c1_hex: ecpoint_to_hex(&ct.c1),
            c2_hex: ecpoint_to_hex(&ct.c2),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShufflePublicState {
    pub phase: ShufflePhase,
    pub current_player_pk: Option<GamePkHex>,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    pub deck_encrypted: Vec<ElGamalCiphertextJson>,
    pub aggregate_pk: String,
    /// 当前洗牌者是否需要补自己的密钥层（waiting 入座、从未 remask 过）。
    /// true 时客户端必须用 join_game_and_shuffle（remask+shuffle）出轮，
    /// 纯 re_encrypt 会让牌组份额与公钥和失衡 → 全桌解密失败。
    #[serde(default)]
    pub needs_join_layer: bool,
    /// 聚合公钥减去当前洗牌者公钥（join_game_and_shuffle 需要的 curr_share_pk）。
    #[serde(default)]
    pub share_pk: Option<String>,
    /// 本手 id（动作签名域 v2）。洗牌结束后 shuffleState 整体置 null，
    /// 下注阶段的签名改取 ClientTable.hand_id——此字段仅供洗牌期一致视图。
    #[serde(default)]
    pub hand_id: u32,
}

impl ElGamalCiphertextJson {
    pub fn to_ciphertext(&self) -> Result<ElGamalCiphertext, String> {
        Ok(ElGamalCiphertext {
            c1: hex_to_ecpoint(&self.c1_hex)?,
            c2: hex_to_ecpoint(&self.c2_hex)?,
        })
    }
}

hex_proof_adapter!(
    #[derive(Debug, Clone, Deserialize)]
    pub struct PkProofJson => [PKOwnershipProof] {
        commitment_hex : commitment,
    }
    scalar { response_hex : response }
);

#[derive(Debug, Clone, Deserialize)]
pub struct RemaskProofJson {
    pub per_card_commitments_hex: Vec<String>,
    pub commitment_pk_hex: String,
    pub response_hex: String,
    pub nonce_hex: String,
}

impl RemaskProofJson {
    pub fn to_remask_proof(&self) -> Result<RemaskProof<DefaultCurve>, String> {
        Ok(RemaskProof::from_parts(
            self.per_card_commitments_hex
                .iter()
                .map(|h| hex_to_ecpoint(h))
                .collect::<Result<Vec<_>, _>>()?,
            hex_to_ecpoint(&self.commitment_pk_hex)?,
            hex_to_scalar(&self.response_hex)?,
            hex_to_scalar(&self.nonce_hex)?,
        ))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeaveProofJson {
    pub per_card_commitments_hex: Vec<String>,
    pub commitment_pk_hex: String,
    pub response_hex: String,
    pub nonce_hex: String,
}

impl LeaveProofJson {
    pub fn to_leave_proof(&self) -> Result<LeaveProof<DefaultCurve>, String> {
        Ok(LeaveProof::from_parts(
            self.per_card_commitments_hex
                .iter()
                .map(|h| hex_to_ecpoint(h))
                .collect::<Result<Vec<_>, _>>()?,
            hex_to_ecpoint(&self.commitment_pk_hex)?,
            hex_to_scalar(&self.response_hex)?,
            hex_to_scalar(&self.nonce_hex)?,
        ))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeaveGameRoundJson {
    pub input_cards: Vec<ElGamalCiphertextJson>,
    pub output_cards: Vec<ElGamalCiphertextJson>,
    pub leave_proof: LeaveProofJson,
}

impl LeaveGameRoundJson {
    pub fn to_leave_game_round(&self) -> Result<LeaveGameRound, String> {
        let input_cards = self
            .input_cards
            .iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let output_cards = self
            .output_cards
            .iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LeaveGameRound {
            input_cards,
            output_cards,
            leave_proof: self.leave_proof.to_leave_proof()?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralizedSchnorrProofJson {
    pub commitment_hex: String,
    pub responses_hex: Vec<String>,
}

impl GeneralizedSchnorrProofJson {
    pub fn to_proof(
        &self,
    ) -> Result<
        poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof<
            DefaultCurve,
        >,
        String,
    > {
        let responses = self
            .responses_hex
            .iter()
            .map(|h| hex_to_scalar(h))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(
            poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof {
                commitment: hex_to_ecpoint(&self.commitment_hex)?,
                responses,
            },
        )
    }
}

/// 跨密钥取负证明（residual carrier → aggregate-key 负明文贡献）。
#[derive(Debug, Clone, Deserialize)]
pub struct CrossKeyNegationProofJson {
    pub commitment_owner_key_hex: String,
    pub commitment_contribution_c1_hex: String,
    pub commitment_joint_c2_hex: String,
    pub response_owner_sk_hex: String,
    pub response_contribution_randomness_hex: String,
}

impl CrossKeyNegationProofJson {
    fn to_proof(&self) -> Result<CrossKeyNegationProof<DefaultCurve>, String> {
        Ok(CrossKeyNegationProof {
            commitment_owner_key: hex_to_ecpoint(&self.commitment_owner_key_hex)?,
            commitment_contribution_c1: hex_to_ecpoint(&self.commitment_contribution_c1_hex)?,
            commitment_joint_c2: hex_to_ecpoint(&self.commitment_joint_c2_hex)?,
            response_owner_sk: hex_to_scalar(&self.response_owner_sk_hex)?,
            response_contribution_randomness: hex_to_scalar(
                &self.response_contribution_randomness_hex,
            )?,
        })
    }
}

/// 单槽贡献 {0, -card_i} 成员证明。
#[derive(Debug, Clone, Deserialize)]
pub struct SlotContributionOrProofJson {
    pub commitment_g: [String; 2],
    pub commitment_pk: [String; 2],
    pub challenges: [String; 2],
    pub responses: [String; 2],
}

impl SlotContributionOrProofJson {
    fn to_proof(&self) -> Result<SlotContributionOrProof<DefaultCurve>, String> {
        let points = |pair: &[String; 2]| -> Result<[EcPoint; 2], String> {
            Ok([hex_to_ecpoint(&pair[0])?, hex_to_ecpoint(&pair[1])?])
        };
        let scalars = |pair: &[String; 2]| -> Result<[Scalar; 2], String> {
            Ok([hex_to_scalar(&pair[0])?, hex_to_scalar(&pair[1])?])
        };
        Ok(SlotContributionOrProof {
            commitment_g: points(&self.commitment_g)?,
            commitment_pk: points(&self.commitment_pk)?,
            challenges: scalars(&self.challenges)?,
            responses: scalars(&self.responses)?,
        })
    }
}

/// reconstruction statement（新协议：context/epoch/prior-state 摘要 + 聚合钥 +
/// residual carriers + 每 canonical slot 的 contribution）。
#[derive(Debug, Clone, Deserialize)]
pub struct ReconstructionStatementJson {
    pub version: u8,
    pub context_digest: String,
    pub reconstruction_epoch: u64,
    pub prior_state_digest: String,
    pub aggregate_pk: String,
    pub owner_pk: String,
    pub cards: Vec<String>,
    pub residual_carriers: Vec<ElGamalCiphertextJson>,
    pub contributions: Vec<ElGamalCiphertextJson>,
}

fn hex_to_digest32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad digest hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "digest must be 32 bytes".to_string())
}

impl ReconstructionStatementJson {
    pub fn to_statement(&self) -> Result<ReconstructionStatement<DefaultCurve>, String> {
        Ok(ReconstructionStatement {
            version: self.version,
            context_digest: hex_to_digest32(&self.context_digest)?,
            reconstruction_epoch: self.reconstruction_epoch,
            prior_state_digest: hex_to_digest32(&self.prior_state_digest)?,
            aggregate_pk: hex_to_ecpoint(&self.aggregate_pk)?,
            owner_pk: hex_to_ecpoint(&self.owner_pk)?,
            cards: self
                .cards
                .iter()
                .map(|h| hex_to_ecpoint(h))
                .collect::<Result<Vec<_>, _>>()?,
            residual_carriers: self
                .residual_carriers
                .iter()
                .map(ElGamalCiphertextJson::to_ciphertext)
                .collect::<Result<Vec<_>, _>>()?,
            contributions: self
                .contributions
                .iter()
                .map(ElGamalCiphertextJson::to_ciphertext)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReconstructProofJson {
    pub version: u8,
    pub negative_contributions: Vec<ElGamalCiphertextJson>,
    pub cross_key_proofs: Vec<CrossKeyNegationProofJson>,
    pub contribution_shuffle_proof: BayerGrothShuffleProofJson,
    pub slot_membership_proofs: Vec<SlotContributionOrProofJson>,
}

impl ReconstructProofJson {
    pub fn to_proof(&self) -> Result<ReconstructProof<DefaultCurve>, String> {
        if self.version != poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_PROOF_VERSION
        {
            return Err(format!(
                "unsupported reconstruction proof version {}",
                self.version
            ));
        }
        Ok(ReconstructProof {
            negative_contributions: self
                .negative_contributions
                .iter()
                .map(ElGamalCiphertextJson::to_ciphertext)
                .collect::<Result<Vec<_>, _>>()?,
            cross_key_proofs: self
                .cross_key_proofs
                .iter()
                .map(|p| p.to_proof())
                .collect::<Result<Vec<_>, _>>()?,
            contribution_shuffle_proof: self.contribution_shuffle_proof.to_proof()?,
            slot_membership_proofs: self
                .slot_membership_proofs
                .iter()
                .map(|p| p.to_proof())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyShuffleProofJson {
    pub sum_c1_commit_hex: String,
    pub sum_c2_commit_hex: String,
    pub combined_schnorr_proof: GeneralizedSchnorrProofJson,
    pub sum_c1_schnorr_proof: GeneralizedSchnorrProofJson,
    pub sum_c2_schnorr_proof: GeneralizedSchnorrProofJson,
    pub nonce_hex: String,
}

impl LegacyShuffleProofJson {
    fn to_legacy_proof(
        &self,
    ) -> Result<poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof<DefaultCurve>, String>
    {
        Ok(poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof {
            sum_c1_commit: hex_to_ecpoint(&self.sum_c1_commit_hex)?,
            sum_c2_commit: hex_to_ecpoint(&self.sum_c2_commit_hex)?,
            combined_schnorr_proof: self.combined_schnorr_proof.to_proof()?,
            sum_c1_schnorr_proof: self.sum_c1_schnorr_proof.to_proof()?,
            sum_c2_schnorr_proof: self.sum_c2_schnorr_proof.to_proof()?,
            nonce: hex_to_scalar(&self.nonce_hex)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiExponentiationArgumentJson {
    pub c_alpha_hex: String,
    pub c_beta_hex: String,
    pub ciphertext_0: ElGamalCiphertextJson,
    pub ciphertext_1: ElGamalCiphertextJson,
    pub alpha_response_hex: Vec<String>,
    pub commitment_response_hex: String,
    pub beta_hex: String,
    pub beta_blinding_response_hex: String,
    pub rerandomization_response_hex: String,
}

impl MultiExponentiationArgumentJson {
    fn to_proof(&self) -> Result<MultiExponentiationArgument<DefaultCurve>, String> {
        Ok(MultiExponentiationArgument {
            c_alpha: hex_to_ecpoint(&self.c_alpha_hex)?,
            c_beta: hex_to_ecpoint(&self.c_beta_hex)?,
            ciphertext_0: self.ciphertext_0.to_ciphertext()?,
            ciphertext_1: self.ciphertext_1.to_ciphertext()?,
            alpha_response: self
                .alpha_response_hex
                .iter()
                .map(|value| hex_to_scalar(value))
                .collect::<Result<Vec<_>, _>>()?,
            commitment_response: hex_to_scalar(&self.commitment_response_hex)?,
            beta: hex_to_scalar(&self.beta_hex)?,
            beta_blinding_response: hex_to_scalar(&self.beta_blinding_response_hex)?,
            rerandomization_response: hex_to_scalar(&self.rerandomization_response_hex)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductArgumentJson {
    pub c_d_hex: String,
    pub c_delta_hex: String,
    pub c_capital_delta_hex: String,
    pub a_response_hex: Vec<String>,
    pub b_response_hex: Vec<String>,
    pub r_response_hex: String,
    pub s_response_hex: String,
}

impl ProductArgumentJson {
    fn to_proof(&self) -> Result<ProductArgument<DefaultCurve>, String> {
        Ok(ProductArgument {
            c_d: hex_to_ecpoint(&self.c_d_hex)?,
            c_delta: hex_to_ecpoint(&self.c_delta_hex)?,
            c_capital_delta: hex_to_ecpoint(&self.c_capital_delta_hex)?,
            a_response: self
                .a_response_hex
                .iter()
                .map(|value| hex_to_scalar(value))
                .collect::<Result<Vec<_>, _>>()?,
            b_response: self
                .b_response_hex
                .iter()
                .map(|value| hex_to_scalar(value))
                .collect::<Result<Vec<_>, _>>()?,
            r_response: hex_to_scalar(&self.r_response_hex)?,
            s_response: hex_to_scalar(&self.s_response_hex)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayerGrothShuffleProofJson {
    pub c_permutation_hex: String,
    pub c_permuted_powers_hex: String,
    pub multi_exponentiation: MultiExponentiationArgumentJson,
    pub product: ProductArgumentJson,
}

impl BayerGrothShuffleProofJson {
    fn to_proof(&self) -> Result<BayerGrothShuffleProof<DefaultCurve>, String> {
        Ok(BayerGrothShuffleProof {
            c_permutation: hex_to_ecpoint(&self.c_permutation_hex)?,
            c_permuted_powers: hex_to_ecpoint(&self.c_permuted_powers_hex)?,
            multi_exponentiation: self.multi_exponentiation.to_proof()?,
            product: self.product.to_proof()?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayerGrothShuffleProofEnvelopeJson {
    pub version: u8,
    pub proof: BayerGrothShuffleProofJson,
}

/// Accepts the explicit V2 envelope and can still decode the historical V1
/// object shape. The latter is wrapped as `LegacyV1` and is rejected by the
/// production verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ShuffleProofJson {
    BayerGrothV2(BayerGrothShuffleProofEnvelopeJson),
    LegacyV1(LegacyShuffleProofJson),
}

impl ShuffleProofJson {
    pub fn to_proof(&self) -> Result<ShuffleProof, String> {
        match self {
            Self::BayerGrothV2(envelope) => {
                if envelope.version != 2 {
                    return Err(format!(
                        "unsupported shuffle proof version {}",
                        envelope.version
                    ));
                }
                Ok(VersionedShuffleProof::BayerGrothV2(
                    envelope.proof.to_proof()?,
                ))
            }
            Self::LegacyV1(proof) => Ok(VersionedShuffleProof::LegacyV1(proof.to_legacy_proof()?)),
        }
    }

    /// 证明 wire 版本（1 = LegacyV1，2 = Bayer-Groth V2）。证明通道下发用。
    pub fn proof_version(&self) -> u8 {
        match self {
            Self::BayerGrothV2(envelope) => envelope.version,
            Self::LegacyV1(_) => 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MaskAndShuffleRoundJson {
    pub mask_cards: Vec<ElGamalCiphertextJson>,
    pub output_cards: Vec<ElGamalCiphertextJson>,
    pub remask_proof: RemaskProofJson,
    pub shuffle_proof: ShuffleProofJson,
}

impl MaskAndShuffleRoundJson {
    pub fn to_mask_and_shuffle_round(&self) -> Result<MaskAndShuffleRound, String> {
        let mask_cards = self
            .mask_cards
            .iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let output_cards = self
            .output_cards
            .iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(MaskAndShuffleRound {
            mask_cards,
            output_cards,
            proof: self.shuffle_proof.to_proof()?,
            remask_proof: self.remask_proof.to_remask_proof()?,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevealTokenProofJson {
    pub user_public_key_hex: String,
    pub commitment_t1_hex: String,
    pub commitment_t2_hex: String,
    pub response_s_hex: String,
    /// M4: anti-replay nonce（对齐 Move reveal_token_proof.move）
    pub nonce_hex: String,
}

impl RevealTokenProofJson {
    pub fn to_proof(&self) -> Result<RevealTokenProof<DefaultCurve>, String> {
        Ok(RevealTokenProof {
            user_public_key: hex_to_ecpoint(&self.user_public_key_hex)?,
            commitment_t1: hex_to_ecpoint(&self.commitment_t1_hex)?,
            commitment_t2: hex_to_ecpoint(&self.commitment_t2_hex)?,
            response_s: hex_to_scalar(&self.response_s_hex)?,
            nonce: hex_to_scalar(&self.nonce_hex)?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubmitRevealTokenJson {
    pub encrypted_card: ElGamalCiphertextJson,
    pub reveal_token_proof: RevealTokenProofJson,
    pub reveal_token_hex: String,
}
