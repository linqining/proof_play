use serde::{Deserialize, Serialize};
use poker_protocol::z_poker::{PlayingCard};

use crate::pokergame::game_state::ElGamalCiphertextJson;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Card {
    pub suit: String,
    pub rank: String,
}

impl Card {
    pub fn from_playing_card(card: &PlayingCard) -> Self {
        Self { suit: card.suit.short_name_lower().to_string(),  rank: card.rank.to_string() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedDeck {
    pub cards: Vec<ElGamalCiphertextJson>,
}
