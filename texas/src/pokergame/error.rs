use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum JoinError {
    PlayerAlreadyInGame,
    InvalidSeatId,
    SeatAlreadyOccupied,
    InvalidPkProof,
    InvalidRemaskProof,
    InvalidShuffleProof,
    Crypto(String),
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoinError::PlayerAlreadyInGame => write!(f, "Player already in game"),
            JoinError::InvalidSeatId => write!(f, "Invalid seat_id"),
            JoinError::SeatAlreadyOccupied => write!(f, "Seat already occupied"),
            JoinError::InvalidPkProof => write!(f, "Invalid PK proof"),
            JoinError::InvalidRemaskProof => write!(f, "Invalid remask proof"),
            JoinError::InvalidShuffleProof => write!(f, "Invalid shuffle proof"),
            JoinError::Crypto(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for JoinError {}

impl From<String> for JoinError {
    fn from(s: String) -> Self {
        JoinError::Crypto(s)
    }
}
