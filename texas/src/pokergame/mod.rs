
/// 模拟用户（dev_bot / e2e）的洗牌置换：本地 CSPRNG Fisher-Yates。
///
/// 用户洗牌的置换必须由用户侧传入（z_poker permute 收口）；服务端内嵌
/// 的 bot/测试模拟"用户"，在用户侧位置本地生成置换。
pub fn random_user_permute() -> [usize; poker_protocol::crypto::N_CARDS] {
    use rand::seq::SliceRandom;
    let mut arr: Vec<usize> = (0..poker_protocol::crypto::N_CARDS).collect();
    arr.shuffle(&mut rand::rngs::OsRng);
    let mut fixed = [0usize; poker_protocol::crypto::N_CARDS];
    fixed.copy_from_slice(&arr);
    fixed
}

pub mod actions;
pub mod receipts;
pub mod betting;
pub mod deck;
pub mod error;
pub mod errors;
pub mod evaluator;
pub mod game_state;
pub mod hand_rank;
pub mod history_store;
pub mod player;
pub mod proof_ledger;
pub mod rake;
pub mod seat;
pub mod side_pot;
pub mod table_summary;
pub mod table;
