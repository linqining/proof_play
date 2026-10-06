use serde::{Deserialize, Serialize};
use std::ops::Deref;

use crate::pokergame::game_state::ElGamalCiphertextJson;

/// Truncate a name to `max_len` characters, appending "…" if truncated.
/// Keeps the frontend PlayerName component logic in sync.
pub fn truncate_name(name: &str, max_len: usize) -> String {
    if name.chars().count() > max_len {
        let truncated: String = name.chars().take(max_len).collect();
        format!("{}…", truncated)
    } else {
        name.to_string()
    }
}

/// 用户钱包登录地址
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletAddress(pub String);

impl WalletAddress {
    pub fn new(addr: impl Into<String>) -> Self {
        Self(addr.into().to_lowercase())
    }
}

impl Deref for WalletAddress {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// 游戏加密公钥 hex（Mental Poker 协议中的玩家标识）
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GamePkHex(pub String);

impl GamePkHex {
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }
}

impl Deref for GamePkHex {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for GamePkHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for GamePkHex {
    fn default() -> Self {
        Self(String::new())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Player {
    pub socket_id: String,
    pub id: String,
    pub name: String,
    pub bankroll: i64,
    pub wallet_address: WalletAddress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GamePlayer {
    pub name: String,
    pub bankroll: i64,
    pub pk_hex: GamePkHex,
    pub readable_hands: Vec<ElGamalCiphertextJson>,
    pub wallet_address: WalletAddress,
}

#[derive(Debug, Clone)]
pub struct PlayerWithProof {
    pub pk: poker_protocol::crypto::EcPoint,
    pub pk_proof: poker_protocol::z_poker::PKOwnershipProof,
}
