pub use handlers::register_handlers;

pub mod broadcast;
pub mod game_loop;
pub mod handlers;
pub mod table_events;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::RwLock;

use serde::{Deserialize, Serialize};
use socketioxide::{SocketIo, extract::SocketRef};

use crate::config::Config;
use crate::models::Database;
use crate::pokergame::actions;
use crate::pokergame::deck::Card;
use crate::pokergame::game_state::{ElGamalCiphertextJson, MaskAndShuffleRoundJson, ShuffleProofJson, PlayerResidualCarriersJson,
    PkProofJson, ReconstructionStatementJson, ReconstructProofJson, RevealPhase, ShufflePublicState, LeaveGameRoundJson, SubmitRevealTokenJson};
use crate::pokergame::player::{Player, WalletAddress, GamePkHex};
use crate::pokergame::table::{ActionRequest, ClientTable, JoinError, JoinResult, RoundState, Table};
use poker_protocol::crypto::EcPoint;
use poker_protocol::z_poker::convert::{ecpoint_to_hex, hex_to_ecpoint, scalar_to_hex};

pub(crate) const MIN_START_NUM: u32 = 2;

pub(crate) fn table_room_name(table_id: u32) -> String {
    format!("table_{}", table_id)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LobbyInfo {
    pub tables: Vec<TableSummary>,
    pub players: Vec<PlayerInfo>,
    pub socket_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JoinTablePayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LeaveTablePayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableSummary {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub current_number_players: usize,
    pub small_blind: u64,
    pub big_blind: u64,
    /// 桌台已关闭（终态）：大厅据此置灰入口，客户端不再引导入座。
    pub closed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlayerInfo {
    pub socket_id: String,
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableLeftPayload {
    pub tables: Vec<TableSummary>,
    pub table_id: u32,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LeaveDeferredPayload {
    pub table_id: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableUpdatePayload {
    pub table: ClientTable,
    pub message: Option<String>,
    pub from: Option<String>,
    /// 重连单次快照扩展：该玩家自己的可读底牌 + 牌组明文（仅重连定向
    /// 推送携带，普通 TABLE_UPDATED 不序列化）。数据形状与
    /// HandRevealResultPayload 同源，客户端走同一条处理路径。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readable_cards: Option<Vec<ElGamalCiphertextJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deck_plaintext: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RaisePayload {
    pub table_id: u32,
    pub amount: u64,
    /// #16 动作签名（迁移期可选：None = 未签名）
    #[serde(default)]
    pub seq: Option<u64>,
    #[serde(default)]
    pub sig: Option<ActionSigPayload>,
}

/// #16 动作签名的传输形状（r/s 为 StarkCurve 压缩/标量 hex）。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ActionSigPayload {
    pub r_hex: String,
    pub s_hex: String,
}

/// FOLD/CHECK/CALL 的载荷（迁移期 sig/seq 可选）。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SimpleActionPayload {
    pub table_id: u32,
    #[serde(default)]
    pub seq: Option<u64>,
    #[serde(default)]
    pub sig: Option<ActionSigPayload>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableMessagePayload {
    pub message: String,
    pub from: String,
    pub table_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
/// 已废弃的 v1 入座消息：只用于识别并提示改用 SIT_DOWN_V2。
pub(crate) struct SitDownPayload {
    pub table_id: u32,
    pub seat_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SitDownV2Payload {
    pub token: String,
    pub table_id: u32,
    pub seat_id: u32,
    pub amount: u64,
    pub pk_hex: GamePkHex,
    pub pk_proof: PkProofJson,
    /// 入座模式（服务端权威决定，客户端值仅作参考提示）：
    /// Some = join_and_shuffle（牌桌 waiting/shuffle 阶段）；None = plain join
    /// （牌局进行中买入，waiting 身份入座，下一手参与洗牌）。
    #[serde(default)]
    pub mask_and_shuffle_round: Option<MaskAndShuffleRoundJson>,
    /// Starknet 买入：PokerVault.deposit 交易哈希（前端钱包执行 approve+deposit 后回传）。
    #[serde(default)]
    pub deposit_tx_hash: Option<String>,
    /// 玩家 Starknet 钱包地址（买入校验与结算参与者地址来源）。缺省回退 token 中的用户地址。
    #[serde(default)]
    pub wallet_address: Option<String>,
    /// P1-2 会话委托：客户端声明的会话交易公钥（Stark Schnorr 32B 压缩点
    /// hex，64 字符）。服务端经 vault `active_session_tx_pk` view 对拍核验
    /// 后随 join 缓冲登记——它是该座位 VM 层交易签名的验证锚。买入时与
    /// deposit 同一笔 multicall 完成链上登记（私密路径由 anonymizer 在
    /// 同笔私交易 `set_session_tx_pk_for` 完成）。
    #[serde(default)]
    pub session_tx_pk: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StandUpPayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
    /// 链上模式下，若客户端已直接提交
    /// leave_with_proof_verified 交易，则 leave_round 为 None。
    /// 此时后端跳过本地 proof 验证和 PTB 构建，仅清理 socket 状态，
    /// 实际玩家移除由 relayer 从 PlayerLeft 事件同步。
    pub leave_round: Option<LeaveGameRoundJson>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RebuyPayload {
    pub table_id: u32,
    pub seat_id: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SittingPayload {
    pub table_id: u32,
    pub seat_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ShuffleSubmitPayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
    #[serde(default)]
    pub output_cards: Vec<ElGamalCiphertextJson>,
    /// 纯 re_encrypt 路径必填；join 语义路径（携带 mask_and_shuffle_round）可省。
    #[serde(default)]
    pub shuffle_proof: Option<ShuffleProofJson>,
    /// join 语义洗牌（waiting 入座玩家补层）：remask 自身层 + shuffle。
    /// 与 needs_join_layer=true 的 SHUFFLE_NOTICE/快照配套；缺省走纯 re_encrypt 路径。
    #[serde(default)]
    pub mask_and_shuffle_round: Option<MaskAndShuffleRoundJson>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevealSubmitPayload {
    pub table_id: u32,
    /// Task 5: 可选 pk_hex（向后兼容旧客户端不传该字段）
    pub pk_hex: Option<GamePkHex>,
    /// Task 5: 可选 reveal_tokens（向后兼容旧客户端不传该字段）
    /// 若提供则在 on-chain 模式下构建 PTB，本地模式下走 submit_reveal_tokens_for_pk
    pub reveal_tokens: Option<Vec<SubmitRevealTokenJson>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RedealRequestPayload {
    pub table_id: u32,
    pub player_pk: GamePkHex,
    pub failed_card_indices: Vec<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReconstructSubmitPayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
    /// 新协议 reconstruction statement（服务端逐字段校验绑定）。
    pub statement: ReconstructionStatementJson,
    pub proof: ReconstructProofJson,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HandRevealResultPayload {
    pub table_id: u32,
    pub player_pk: GamePkHex,
    pub readable_cards: Vec<ElGamalCiphertextJson>,
    pub deck_plaintext: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommunityRevealResultPayload {
    pub table_id: u32,
    pub community_cards: Vec<Card>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconstructInitiatePayload {
    pub table_id: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShuffleNoticePayload {
    pub table_id: u32,
    pub shuffle_state: Option<ShufflePublicState>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RevealNoticePayload {
    pub table_id: u32,
    pub phase: RevealPhase,
    pub pending_players: Vec<GamePkHex>,
    pub completed_players: Vec<GamePkHex>,
    pub player_assignments: HashMap<GamePkHex, crate::pokergame::game_state::PlayerRevealAssignment>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReconstructNoticePayload {
    pub table_id: u32,
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconstructResultPayload {
    pub table_id: u32,
    pub completed_players: Vec<GamePkHex>,
    pub reconstructed: bool,
}

pub(crate) struct GameLoopEntry {
    pub _handle: tokio::task::JoinHandle<()>,
    pub action_sender: tokio::sync::mpsc::Sender<ActionRequest>,
    pub stop_sender: tokio::sync::watch::Sender<bool>,
    /// 每次 start_game_loop 递增；watchdog 清理残留 entry 时凭它避免误删
    /// stop+restart 产生的新一代条目。
    pub generation: u64,
}

pub(crate) struct GameLoopRegistry {
    pub entries: HashMap<u32, GameLoopEntry>,
    next_gen: u64,
}

impl GameLoopRegistry {
    pub fn new() -> Self {
        Self { entries: HashMap::new(), next_gen: 0 }
    }

    fn next_generation(&mut self) -> u64 {
        self.next_gen = self.next_gen.wrapping_add(1);
        self.next_gen
    }

    pub fn contains(&self, table_id: u32) -> bool {
        self.entries.contains_key(&table_id)
    }

    pub fn get_sender(&self, table_id: u32) -> Option<tokio::sync::mpsc::Sender<ActionRequest>> {
        self.entries.get(&table_id).map(|e| e.action_sender.clone())
    }

    pub fn insert(&mut self, table_id: u32, entry: GameLoopEntry) {
        self.entries.insert(table_id, entry);
    }

    pub fn remove(&mut self, table_id: u32) {
        if let Some(entry) = self.entries.remove(&table_id) {
            let _ = entry.stop_sender.send(true);
        }
    }
}

static SOCKET_IO: OnceLock<SocketIo> = OnceLock::new();

/// 按桌记录最近一次 SHUFFLE_NOTICE 推送签名（双通道去重，见
/// send_shuffle_notice 内注释）。
fn shuffle_notice_dedup()
-> &'static std::sync::Mutex<HashMap<u32, (String, std::time::Instant)>> {
    static S: OnceLock<std::sync::Mutex<HashMap<u32, (String, std::time::Instant)>>> =
        OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn last_shuffle_notice(table_id: u32) -> Option<(String, std::time::Instant)> {
    shuffle_notice_dedup().lock().ok()?.get(&table_id).cloned()
}

fn record_shuffle_notice(table_id: u32, sig: String) {
    if let Ok(mut g) = shuffle_notice_dedup().lock() {
        g.insert(table_id, (sig, std::time::Instant::now()));
    }
}

pub fn set_socket_io(io: SocketIo) {
    let _ = SOCKET_IO.set(io);
}

pub(crate) fn get_socket_io() -> Option<SocketIo> {
    SOCKET_IO.get().cloned()
}

pub(crate) struct GameState {
    pub tables: HashMap<u32, Table>,
    pub players: HashMap<String, Player>,
    pub disconnect_cancellers: HashMap<String, tokio::sync::watch::Sender<bool>>,
}

pub struct SocketState {
    pub db: Database,
    pub state: RwLock<GameState>,
    pub config: Config,
    pub game_loop_registry: RwLock<GameLoopRegistry>,
    /// C2 防重放：已接受的玩家动作 `(table_id, pk, seq)` 去重缓存。
    /// 覆盖 seq 强制校验关闭的迁移窗口——该窗口内同 seq 的签名重放
    /// 本会被二次接受；接受点标记 + 入口查重封堵此缺口。
    pub processed_actions: std::sync::Arc<std::sync::RwLock<HashMap<String, ()>>>,
}

impl SocketState {
    pub fn new(db: Database, tables: HashMap<u32, Table>, config: Config) -> Self {
        Self {
            db,
            state: RwLock::new(GameState {
                tables,
                players: HashMap::new(),
                disconnect_cancellers: HashMap::new(),
            }),
            config,
            game_loop_registry: RwLock::new(GameLoopRegistry::new()),
            processed_actions: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// C2：该 `(table_id, pk, seq)` 的动作是否已被接受过（入口查重）。
    pub fn is_action_processed(&self, table_id: u32, pk: &str, seq: u64) -> bool {
        let key = format!("{table_id}_{pk}_{seq}");
        self.processed_actions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&key)
    }

    /// C2：在动作接受点标记 `(table_id, pk, seq)`。超过 [`MAX_PROCESSED_ACTIONS`]
    /// 时整体清空（防无界增长；清空后的残余重放仍被 seq 单调校验兜底）。
    pub fn mark_action_processed(&self, table_id: u32, pk: &str, seq: u64) {
        const MAX_PROCESSED_ACTIONS: usize = 10000;
        let key = format!("{table_id}_{pk}_{seq}");
        let mut processed = self
            .processed_actions
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if processed.len() >= MAX_PROCESSED_ACTIONS {
            tracing::warn!("dedup cache overflow, clearing all entries");
            processed.clear();
        }
        processed.insert(key, ());
    }

    /// 为所有已注册的 table 创建事件 channel 并 spawn consumer 任务。
    ///
    /// 在 `main.rs` 中 `SocketIo` 实例创建后调用。对每个 table：
    /// 1. 创建 `mpsc::channel::<TableEvent>(256)`
    /// 2. 调用 `table.set_event_sender(tx)` 注入 sender
    /// 3. spawn `table_event_consumer` 任务消费事件并执行 socket 广播
    pub async fn init_table_event_channels(self: &Arc<Self>, io: SocketIo) {
        // 写锁块内只做 channel 创建与 sender 注入，consumer 的 spawn 必须在
        // 锁释放后进行：多线程 runtime 上 spawn 的任务可能在其他 worker
        // 立即运行，若 consumer 将来在开头读取 state 锁，持锁 spawn 即自锁
        // （与 39a390e 修复的持锁广播同类，tokio RwLock 不可重入）。
        let consumers: Vec<(u32, tokio::sync::mpsc::Receiver<crate::pokergame::table::events::TableEvent>)> = {
            let mut gs = self.state.write().await;
            let mut consumers = Vec::new();
            for table_id in gs.tables.keys().copied().collect::<Vec<_>>() {
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    let (tx, rx) = tokio::sync::mpsc::channel::<crate::pokergame::table::events::TableEvent>(256);
                    table.set_event_sender(tx);
                    tracing::info!("[TABLE-EVENTS] Initialized event channel for table {}", table_id);
                    consumers.push((table_id, rx));
                }
            }
            consumers
        };
        for (table_id, rx) in consumers {
            tokio::spawn(crate::socket::table_events::table_event_consumer(
                io.clone(),
                self.clone(),
                table_id,
                rx,
            ));
        }
    }

    pub(crate) async fn get_current_tables(&self) -> Vec<TableSummary> {
        let gs = self.state.read().await;
        gs.tables
            .values()
            .map(|t| TableSummary {
                id: t.summary.id,
                name: t.name().to_string(),
                limit: t.summary.limit,
                max_players: t.max_players(),
                current_number_players: t.players().len(),
                small_blind: t.summary.min_bet,
                big_blind: t.summary.min_bet * 2,
                closed: t.is_closed(),
            })
            .collect()
    }

    pub(crate) async fn get_current_players(&self) -> Vec<PlayerInfo> {
        let gs = self.state.read().await;
        gs.players
            .values()
            .map(|p| PlayerInfo {
                socket_id: p.socket_id.clone(),
                id: p.id.clone(),
                name: p.name.clone(),
            })
            .collect()
    }

    /// 关桌（终态，"关桌后不开新手"的服务端权威执行点）：
    /// 写锁内置 closed 标志（幂等）→ 广播终态视图 → 异步释放所有在座
    /// 玩家的 vault 会话锁 + 链上注册表关桌写链。
    /// 返回 `Ok(false)` = 桌台此前已关闭（幂等重复调用）。
    pub async fn close_table(self: &Arc<Self>, table_id: u32, reason: &str) -> Result<bool, String> {
        let (seated_wallets, registry_id) = {
            let mut gs = self.state.write().await;
            let Some(table) = gs.tables.get_mut(&table_id) else {
                return Err(format!("table {table_id} not found"));
            };
            if !table.close_table() {
                return Ok(false);
            }
            let wallets: Vec<String> =
                table.players().values().map(|w| w.0.clone()).collect();
            (wallets, table.registry_table_id)
        };
        tracing::info!(
            "[TABLE-CLOSE] table {table_id} closed (reason={reason}); releasing {} seated player lock(s)",
            seated_wallets.len()
        );

        // 终态视图广播（客户端据此禁用入座并提示）
        if let Some(io) = get_socket_io() {
            broadcast::broadcast_to_table(
                &io,
                self,
                table_id,
                Some("Table closed — no new hands will start"),
            )
            .await;
        }

        // 副作用异步化：锁释放/链上写不阻塞管理端点；本地 closed 标志已生效
        tokio::spawn(async move {
            for wallet in seated_wallets {
                crate::starknet::lock::release_player_lock(&wallet).await;
            }
            if let Some(registry_id) = registry_id {
                crate::starknet::table_registry::close_table(registry_id).await;
            }
        });
        Ok(true)
    }

    pub async fn get_action_sender(&self, table_id: u32) -> Option<tokio::sync::mpsc::Sender<ActionRequest>> {
        let registry = self.game_loop_registry.read().await;
        registry.get_sender(table_id)
    }

    pub async fn start_game_loop(&self, io: SocketIo, state: Arc<SocketState>, table_id: u32) {
        let mut registry = self.game_loop_registry.write().await;
        if registry.contains(table_id) {
            return;
        }
        let (tx, rx) = tokio::sync::mpsc::channel::<ActionRequest>(100);
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let generation = registry.next_generation();
        let handle = tokio::spawn(game_loop::game_loop_task(io, state.clone(), table_id, rx, stop_rx));
        // watchdog：game_loop_task panic 时，其结尾的 registry 清理不会执行，
        // 残留 entry 会让本函数的 contains() 永远拒绝重启（该桌永久冻结，
        // 动作通道也变成无人消费的死通道）。兜底：panic 可见 + 立即清理残留
        // 条目；generation 校验防止误删 stop+restart 产生的新一代条目。
        // 正常退出时 game_loop_task 已自行 remove，此处 handle.await 为 Ok。
        let watchdog = tokio::spawn({
            let supervisor = state.clone();
            async move {
                if let Err(join_err) = handle.await {
                    tracing::error!(
                        "[GAME-LOOP] task for table {table_id} failed: {join_err} — cleaning stale registry entry"
                    );
                    let mut registry = supervisor.game_loop_registry.write().await;
                    if registry.entries.get(&table_id).map(|e| e.generation) == Some(generation) {
                        registry.remove(table_id);
                    }
                }
            }
        });
        registry.insert(table_id, GameLoopEntry {
            _handle: watchdog,
            action_sender: tx,
            stop_sender: stop_tx,
            generation,
        });
    }

    pub async fn stop_game_loop(&self, table_id: u32) {
        // tracing::info!("stop_game_loop: {}", table_id);
        let mut registry = self.game_loop_registry.write().await;
        registry.remove(table_id);
    }

    /// Resolve socket_id from a pk_hex for a given table
    pub async fn send_shuffle_notice(&self, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };

        let shuffle_notice_data = {
            let gs = self.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                // 诊断日志：记录 deck 来源信息
                let mp_deck_len = table.mental_poker_game.deck_encrypted.len();
                let summary_deck_len = table.summary.crypto.deck_encrypted.len();
                let shuffle_active = table.shuffle_state.is_active();
                let shuffle_phase = format!("{:?}", table.shuffle_state.phase);
                tracing::info!(
                    "[send_shuffle_notice] table={} mental_poker_deck_len={} summary_crypto_deck_len={} shuffle_active={} shuffle_phase={}",
                    table_id, mp_deck_len, summary_deck_len, shuffle_active, shuffle_phase
                );

                let shuffle_state = table.get_shuffle_public_state();
                let current_pk = table.shuffle_state.current_player_pk.clone();
                let socket_id = if let Some(pk) = &current_pk {
                    if let Some(wallet_address) = table.players().get(pk) {
                        // 同一钱包可能残留多条 players 条目（页面重载后旧
                        // socket 未清理）。必须投递"活 socket"：命中死条目时
                        // notice 静默进死管道，玩家永远等不到洗牌轮转（实测
                        // 长跑死循环根因之一）。
                        let candidates: Vec<String> = gs.players.values()
                            .filter(|p| &p.wallet_address == wallet_address)
                            .map(|p| p.socket_id.clone())
                            .collect();
                        let live = candidates.iter().find_map(|sid| {
                            sid.parse::<socketioxide::socket::Sid>()
                                .ok()
                                .and_then(|s| io.get_socket(s))
                                .map(|_| sid.clone())
                        });
                        if live.is_none() {
                            tracing::warn!(
                                "send_shuffle_notice: table {} pk {} wallet {} has {} player entr(y/ies) but no live socket (wallet_addr mismatch or stale entries)",
                                table_id,
                                pk,
                                wallet_address.0,
                                candidates.len()
                            );
                        }
                        live
                    } else {
                        None
                    }
                } else {
                    None
                };
                shuffle_state.zip(socket_id)
            } else {
                None
            }
        };

        if let Some((shuffle_state, socket_id)) = shuffle_notice_data {
            let deck_len = shuffle_state.deck_encrypted.len();
            let first_c1 = shuffle_state.deck_encrypted.first().map(|c| c.c1_hex.as_str()).unwrap_or("none");
            let first_c2 = shuffle_state.deck_encrypted.first().map(|c| c.c2_hex.as_str()).unwrap_or("none");
            // 双通道去重（2026-09-07）：同一次洗牌状态会经 TableEvent 消费者
            // 与各处直接调用两条路径推送（game_loop 重构完成/超时、handlers
            // SHUFFLE_SUBMIT/RECONSTRUCT_SUBMIT），曾出现同毫秒双发 → 客户端
            // 双重洗牌提交（第二次被状态机拒绝，zk 面板误报"证明失败"）。
            // 签名 = 当前洗牌者 + 首张密牌承诺：状态真变（轮转/换牌）必然
            // 改签名；同签名 250ms 内视为重复推送，跳过 emit。
            let sig = format!(
                "{:?}|{}|{}",
                shuffle_state.current_player_pk, deck_len, first_c1
            );
            if let Some((last_sig, at)) = last_shuffle_notice(table_id) {
                if last_sig == sig && at.elapsed() < std::time::Duration::from_millis(250) {
                    tracing::debug!(
                        "[send_shuffle_notice] table={} duplicate push suppressed (same state within 250ms)",
                        table_id
                    );
                    return;
                }
            }
            record_shuffle_notice(table_id, sig);
            tracing::info!(
                "[send_shuffle_notice] table={} deck_len={} first_c1={}... first_c2={}... current_pk={:?}",
                table_id,
                deck_len,
                &first_c1[..std::cmp::min(16, first_c1.len())],
                &first_c2[..std::cmp::min(16, first_c2.len())],
                shuffle_state.current_player_pk
            );
            if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
                if let Some(socket) = io.get_socket(sid) {
                    let notice = ShuffleNoticePayload { table_id, shuffle_state: Some(shuffle_state) };
                    let _ = socket.emit(actions::SHUFFLE_NOTICE, &notice);
                }
            } else {
                tracing::warn!(
                    "[send_shuffle_notice] table={} failed to parse socket_id={:?} or socket not found",
                    table_id, socket_id
                );
            }
        } else {
            tracing::warn!(
                "[send_shuffle_notice] table={} no shuffle_notice_data (shuffle_state inactive or no socket)",
                table_id
            );
        }
    }

    pub async fn mark_player_sitting_out(&self, table_id: u32, wallet_address: &WalletAddress) {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            for seat in table.local_seats.values_mut() {
                if seat.player.as_ref().map_or(false, |p| &p.wallet_address == wallet_address) {
                    seat.sitting_out = true;
                }
            }
        }
    }

    pub async fn is_player_in_seat(&self, pk_hex: &GamePkHex) -> bool {
        let gs = self.state.read().await;
        gs.tables.values().any(|table| {
            table.seats().values().any(|seat| {
                seat.player.as_ref().map_or(false, |p| &p.pk_hex == pk_hex)
            })
        })
    }

    pub async fn find_player_by_pk(&self, table_id: u32, pk_hex: &GamePkHex) -> Option<Player> {
        let gs = self.state.read().await;
        let wallet_address = gs.tables.get(&table_id).and_then(|table| table.players().get(pk_hex).cloned());
        if let Some(wallet_addr) = wallet_address {
            gs.players.iter().find(|(_, p)| &p.wallet_address == &wallet_addr).map(|(_, p)| p.clone())
        } else {
            None
        }
    }

    pub async fn get_client_table(&self, table_id: u32) -> Option<ClientTable> {
        let gs = self.state.read().await;
        gs.tables.get(&table_id).map(|t| t.to_client())
    }

    pub async fn add_player_to_table(&self, table_id: u32, player: Player, pk_hex: &GamePkHex) -> Result<usize, String> {
        let mut gs = self.state.write().await;
        gs.players.insert(player.socket_id.clone(), player.clone());
        if let Some(table) = gs.tables.get_mut(&table_id) {
            let _ = table.add_player(pk_hex.clone(), player.wallet_address.clone());
            Ok(table.active_players().len())
        } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn join_player_and_shuffle(
        &self,
        table_id: u32,
        player: Player,
        player_pk: EcPoint,
        pk_proof_json: PkProofJson,
        round_json: Option<MaskAndShuffleRoundJson>,
        seat_id: u32,
        amount: u64,
    ) -> Result<(bool, JoinResult), JoinError> {
        let pk_proof_bytes = pk_proof_json.to_proof()
            .map(|p| crate::relayer::proof_bytes::serialize_pk_ownership_proof(&p))
            .unwrap_or_default();
        // 权威覆写用的证明字节副本（下方预写会 move 原值；入座成功后
        // 在写锁内覆写 join 缓冲为实际在座 pk，见 JoinedAndShuffled/
        // JoinedWaiting 分支）。
        let pk_proof_bytes_auth = pk_proof_bytes.clone();
        let socket_id = player.socket_id.clone();
        let pk_hex = GamePkHex::new(ecpoint_to_hex(&player_pk));
        let player_wallet_address = player.wallet_address.clone();

        let player_name = player.name.clone();
        let player_id = player.id.clone();
        let player_bankroll = player.bankroll;

                // #20 Phase 2：缓冲 join 证明（下一手 HandStart 消费）。
                // 会话交易公钥经 SIT_DOWN_V2 接受点核验后随 join 缓冲
                // 传递（见 socket/handlers.rs）；本路径（重连/机器人等
                // 次级 join）不携带——None = 未登记。
                crate::starknet::prove_log::record_join(
                    table_id,
                    &player_wallet_address,
                    pk_hex.clone().0.as_str(),
                    pk_proof_bytes,
                    None,
                );


        let result = {
            let mut gs = self.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.join_player_and_shuffle(player, player_pk, pk_proof_json, round_json, seat_id, amount)
            } else {
                Err(JoinError::Crypto("Table not found".to_string()))
            }
        };

        match &result {
            Ok(JoinResult::JoinedAndShuffled) => {
                let mut gs = self.state.write().await;
                // 权威覆写（2026-09-20 竞态终局修复）：入座已在同一写锁内
                // 落定，此刻把 join 缓冲覆写为「实际在座 pk + 证明」。上方
                // 预写发生在入座之前，重注入并发任务（后续 SeatAlready-
                // Occupied / PlayerAlreadyInGame 失败退出）会留下与座位不
                // 一致的预写 → 计划↔座位/揭示分叉（VM "reveal from
                // unknown pk" 风暴 + 失配踢座活锁）。座位与缓冲同锁落定
                // 后，record_hand_start 读到的恒为对齐值。
                crate::starknet::prove_log::record_join(
                    table_id,
                    &player_wallet_address,
                    pk_hex.0.as_str(),
                    pk_proof_bytes_auth.clone(),
                    None,
                );
                let already_exists = gs.players.values().any(|p| p.wallet_address == player_wallet_address);
                if !already_exists {
                    gs.players.insert(socket_id.clone(), Player {
                        socket_id: socket_id.clone(),
                        id: player_id,
                        name: player_name,
                        bankroll: player_bankroll,
                        wallet_address: player_wallet_address.clone(),
                    });
                }

                if let Some(table) = gs.tables.get_mut(&table_id) {
                    if table.is_pending_shuffle_player_empty() && table.complete_shuffle_player_count() >= MIN_START_NUM as usize  {
                        table.shuffle_state.phase = crate::pokergame::game_state::ShufflePhase::None;
                        tracing::info!("[SHUFFLE] Player {} joined and shuffled, all players shuffled {:?}", pk_hex,table.shuffle_state.completed_players);
                        return Ok((true, JoinResult::JoinedAndShuffled));
                    } else {
                        tracing::info!("[SHUFFLE] Player {} joined and shuffled, but not enough players to start,shuffle cnt {}", pk_hex, table.complete_shuffle_player_count());
                        table.advance_turn_pointer_only();
                    }
                }
                Ok((false, JoinResult::JoinedAndShuffled))
            }
            Ok(JoinResult::JoinedWaiting) => {
                let mut gs = self.state.write().await;
                // 权威覆写（2026-09-20 竞态终局修复）：入座已在同一写锁内
                // 落定，此刻把 join 缓冲覆写为「实际在座 pk + 证明」。上方
                // 预写发生在入座之前，重注入并发任务（后续 SeatAlready-
                // Occupied / PlayerAlreadyInGame 失败退出）会留下与座位不
                // 一致的预写 → 计划↔座位/揭示分叉（VM "reveal from
                // unknown pk" 风暴 + 失配踢座活锁）。座位与缓冲同锁落定
                // 后，record_hand_start 读到的恒为对齐值。
                crate::starknet::prove_log::record_join(
                    table_id,
                    &player_wallet_address,
                    pk_hex.0.as_str(),
                    pk_proof_bytes_auth.clone(),
                    None,
                );
                let already_exists = gs.players.values().any(|p| p.wallet_address.0 == player_wallet_address.0);
                if !already_exists {
                    gs.players.insert(socket_id.clone(), Player {
                        socket_id: socket_id.clone(),
                        id: player_id,
                        name: player_name,
                        bankroll: player_bankroll,
                        wallet_address: player_wallet_address,
                    });
                }
                Ok((false, JoinResult::JoinedWaiting))
            }
            Err(e) => Err(e.clone()),
        }
    }

    /// 返回 Ok(true) 表示洗牌完成且 reveal phase 已启动（需外部 broadcast reveal）。
    pub async fn submit_verified_shuffle_for_pk(
        &self,
        table_id: u32,
        pk_hex: &GamePkHex,
        _player: Player,
        output_cards: Vec<ElGamalCiphertextJson>,
        shuffle_proof: Option<ShuffleProofJson>,
        join_round: Option<MaskAndShuffleRoundJson>,
    ) -> Result<bool, String> {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
                    let verified = match &join_round {
                        // join 语义：waiting 入座玩家补自身层（remask+shuffle）
                        Some(round) => table.submit_join_shuffle(pk_hex, round.clone()),
                        None => match shuffle_proof {
                            Some(proof) => {
                                table.submit_verified_shuffle(pk_hex, output_cards.clone(), proof)
                            }
                            None => Err("missing shuffle_proof (plain path)".to_string()),
                        },
                    };
                    match verified {
                        Ok(()) => {
                            // 方案A：洗牌不再转发 mirror（deck 由游戏层验证后
                            // 在 advance_shuffle 终局点整体注入）。
                            if table.is_all_players_shuffled()
                                && table.complete_shuffle_player_count() >= MIN_START_NUM as usize
                            {
                                // 所有玩家完成洗牌 → advance_shuffle 推进流程
                                // (on_shuffle_complete + on_before_preflop_shuffle_complete + transition_to(PreFlop) + start_preflop_reveal_phase)
                                table.advance_shuffle();
                                // advance_shuffle 内部可能启动 reveal phase，
                                // 外部调用方需据此 broadcast reveal notice
                                Ok(table.reveal_token_state.is_active())
                            } else {
                                table.advance_turn_pointer_only();
                                Ok(false)
                            }
                        }
                        Err(e) => Err(e),
                    }
                } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn mark_reveal_complete_for_pk(&self, table_id: u32, pk_hex: &GamePkHex) -> Result<bool, String> {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            Ok(table.mark_player_reveal_complete(pk_hex))
        } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn submit_reveal_tokens_for_pk(
        &self,
        table_id: u32,
        pk_hex: &GamePkHex,
        tokens: Vec<poker_protocol::z_poker::protocol::RevealToken>,
    ) -> Result<(), String> {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            // reveal 喂食在 Table::submit_player_reveal_tokens 内统一完成。
            table.submit_player_reveal_tokens(pk_hex, tokens.clone())
        } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn get_reveal_phase_for_table(&self, table_id: u32) -> Option<crate::pokergame::game_state::RevealPhase> {
        let gs = self.state.read().await;
        gs.tables.get(&table_id).map(|t| t.reveal_token_state.phase)
    }
}

pub(crate) fn hide_opponent_cards(base: &ClientTable, wallet_address: &WalletAddress) -> ClientTable {
    let mut copy = base.clone();
    let hidden_card = Card { suit: "hidden".to_string(), rank: "hidden".to_string() };
    let hidden_hand = vec![hidden_card.clone(), hidden_card];

    let cards_dealt = !matches!(
        copy.round_state,
        RoundState::Waiting
    );

    for seat in copy.seats.values_mut() {
        let is_opponent = seat.player.as_ref().map_or(true, |p| &p.wallet_address != wallet_address);
        // 摊牌时所有未弃牌玩家都应亮牌；非摊牌时仅赢家亮牌
        let should_show = if copy.went_to_showdown {
            !seat.folded
        } else {
            seat.last_action.as_deref() == Some(actions::WINNER)
        };

        if is_opponent && !should_show {
            if seat.hand.len() > 0 {
                seat.hand = hidden_hand.clone();
            } else if cards_dealt && !seat.folded && !seat.sitting_out && seat.player.is_some() {
                seat.hand = hidden_hand.clone();
            }
        }
    }
    copy
}

/// 动作通道发送带超时。通道容量 100（见 `start_game_loop`），game loop
/// 卡死时 `send().await` 会永久悬挂，socket handler / HTTP 请求全部冻结
/// ——这是"无超时等待一个可能永不消费的通道"的死锁形态。超时或通道
/// 关闭视为 game loop 无响应，调用方向客户端返回可读错误。
pub(crate) async fn send_action_with_timeout(
    sender: &tokio::sync::mpsc::Sender<ActionRequest>,
    req: ActionRequest,
) -> Result<(), &'static str> {
    const ACTION_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    match tokio::time::timeout(ACTION_SEND_TIMEOUT, sender.send(req)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err("game loop not running"),
        Err(_) => Err("game loop not responding (send timeout)"),
    }
}

/// #16：带（可选）动作签名的简单动作发送。
pub(crate) async fn send_simple_action_signed(
    socket: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    action: &str,
    seq: Option<u64>,
    sig: Option<ActionSigPayload>,
) {
    let socket_id = socket.id.to_string();
    let pk_hex = {
        let gs = state.state.read().await;
        gs.players.get(&socket_id)
            .and_then(|p| gs.tables.get(&table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&p.wallet_address.0)))
    };
    if let (Some(pk_hex), Some(sender)) = (pk_hex, state.get_action_sender(table_id).await) {
        let req = ActionRequest {
            pk_hex,
            action: action.to_string(),
            amount: None,
            seq,
            sig: sig.map(|s| crate::pokergame::actions::ActionSig { r_hex: s.r_hex, s_hex: s.s_hex }),
        };
        if let Err(reason) = send_action_with_timeout(&sender, req).await {
            tracing::warn!("[ACTION] {action} dropped: game loop {reason} (table {table_id})");
            let _ = socket.emit("error", &serde_json::json!({
                "code": "GAME_LOOP_UNRESPONSIVE",
                "msg": "桌面无响应，请稍后重试",
                "detail": reason,
                "action": action,
                "table_id": table_id
            }));
        }
    }
}
