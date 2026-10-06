use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidePot {
    pub amount: u64,
    pub players: Vec<u32>,
}
