/// JWT 默认过期时间（毫秒）= 24 小时。
const JWT_DEFAULT_EXPIRES_IN_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub jwt_secret: String,
    pub jwt_token_expires_in: u64,
    pub betting_timeout_secs: u64,
    pub showdown_display_secs: u64,
    pub hand_complete_wait_secs: u64,
    pub ready_countdown_secs: u64,
    /// 当手牌结束进入 Waiting 状态后，若仍有 sitting_out 玩家（正在完成链上 leave 交易），
    /// 在 hand_complete_wait_secs 基础上额外等待的秒数。所有 sitting_out 玩家被移除后立即推进。
    pub leave_grace_secs: u64,
    pub max_players_per_table: u32,
    /// 初始 Table 1 使用的链上 table ID（环境相关，按部署环境配置）。
    pub default_chain_table_id: String,
    /// 关桌管理端点的 bearer token（`OPERATOR_ADMIN_TOKEN`）。
    /// 未配置时仅 debug 构建（本地联调）允许关桌，release 构建拒绝。
    pub operator_admin_token: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
            eprintln!("FATAL: JWT_SECRET environment variable is required");
            std::process::exit(1);
        });

        Self {
            port: std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(9001),
            jwt_secret,
            jwt_token_expires_in: JWT_DEFAULT_EXPIRES_IN_MS,
            betting_timeout_secs: std::env::var("BETTING_TIMEOUT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(30),
            showdown_display_secs: std::env::var("SHOWDOWN_DISPLAY_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3),
            hand_complete_wait_secs: std::env::var("HAND_COMPLETE_WAIT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(5),
            ready_countdown_secs: std::env::var("READY_COUNTDOWN_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(5),
            leave_grace_secs: std::env::var("LEAVE_GRACE_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(10),
            max_players_per_table: std::env::var("MAX_PLAYERS_PER_TABLE").ok().and_then(|s| s.parse().ok()).unwrap_or(5),
            default_chain_table_id: std::env::var("DEFAULT_CHAIN_TABLE_ID").unwrap_or_else(|_| "0xe5736dc65ee19df22daa13c8218ad42c28c31cb5b1f174e73740858371664b33".to_string()),
            operator_admin_token: std::env::var("OPERATOR_ADMIN_TOKEN").ok().filter(|s| !s.trim().is_empty()),
        }
    }
}
