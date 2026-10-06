use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub address: String,
    pub created: String,
    /// 已锁定筹码（入座时扣除，离开时返还）。实际余额由链上（PokerVault）余额决定。
    pub locked_chips: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub address: String,
    /// 可用筹码 = PokerVault 链上筹码余额 - locked_chips
    pub chips_amount: i64,
    /// PokerVault 链上筹码余额（1 chip = WEI_PER_CHIP wei，Starknet STRK20）
    pub vault_chips: i64,
    pub created: String,
}

#[derive(Clone)]
pub struct Database {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl Database {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn find_user_by_id(&self, id: &str) -> Option<User> {
        self.users.read().await.get(id).cloned()
    }

    pub async fn save_user(&self, user: &User) -> Result<(), String> {
        let mut users = self.users.write().await;
        users.insert(user.id.clone(), user.clone());
        Ok(())
    }

    pub async fn update_address(&self, id: &str, address: &str) -> bool {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(id) {
            user.address = address.to_string();
            true
        } else {
            false
        }
    }

    /// 锁定筹码（入座时调用）
    pub async fn lock_chips(&self, id: &str, amount: i64) -> Option<User> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(id) {
            user.locked_chips += amount;
            return Some(user.clone());
        }
        None
    }

    /// 解锁筹码（离开时调用）
    pub async fn unlock_chips(&self, id: &str, amount: i64) -> Option<User> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(id) {
            user.locked_chips = (user.locked_chips - amount).max(0);
            return Some(user.clone());
        }
        None
    }

}

impl Default for Database {
    fn default() -> Self {
        Self::new()
    }
}
