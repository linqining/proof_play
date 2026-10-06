mod config;
mod models;
mod auth;
mod handlers;
mod pokergame;
mod ratelimit;
mod socket;
mod relayer;
mod starknet;
mod dev_bot;

use std::collections::HashMap;
use axum::response::IntoResponse;
use std::sync::Arc;

use axum::{routing, Router};
use socket::SocketState;
use socketioxide::SocketIo;
use tower::ServiceBuilder;

use config::Config;
use handlers::AppState;
use models::Database;
use pokergame::table::Table;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,texas=debug".into())
        )
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(true)
        .init();

    let config = Config::from_env();
    let port = config.port;

    // Starknet 链客户端（dev 模式下 RPC 为空也可启动，买入/结算校验自动放行）。
    let sn_config = starknet::StarknetConfig::from_env();
    let settlement_exit_name = sn_config.settlement_exit_name().to_string();
    if sn_config.rpc_enabled() {
        tracing::info!(
            "Starknet enabled: rpc={} settlement={} vault={}",
            sn_config.rpc_url,
            if sn_config.settlement_enabled() { "on" } else { "off" },
            if sn_config.vault_address.is_empty() { "not-configured" } else { "configured" }
        );
    } else {
        tracing::info!("Starknet dev mode: no STARKNET_RPC_URL, on-chain checks skipped");
    }
    starknet::init(sn_config);
    tracing::info!(
        "Prover mode: {:?} (TEXAS_PROVER_MODE; dev = in-process local prover, remote = STARKNET_PROVER_URL service)",
        starknet::vm_session::prover_mode()
    );
    tracing::info!(
        "Settlement exit: {settlement_exit_name} (STARKNET_SETTLEMENT_EXIT; appchain = embedded sequencer, starknet = legacy calldata)"
    );
    // Plan C：paymaster 中继（未配置时自动禁用，客户端回退直签）。
    starknet::paymaster::init_from_env();

    // B6/B7：嵌入式 appchain 运行时（sequencer WAL + 证明管道 + 出入金桥 +
    // 自动对账；TEXAS_APPCHAIN=0 显式关闭）。失败降级为遗留路径并告警
    // （服务器绝不因 appchain 装配失败拒绝服务）。
    let appchain_config = starknet::appchain::AppchainConfig::from_env();
    if appchain_config.enabled {
        match starknet::appchain::runtime::init(appchain_config) {
            Ok(rt) => {
                tracing::info!(
                    "Appchain runtime ready (attestor 0x{})",
                    starknet::chain::hex_encode(&rt.attestor_public)
                );
            }
            Err(e) => tracing::error!("Appchain runtime init failed: {e} — settlements fall back to legacy starknet path"),
        }
    }

    let db = Database::new();

    let mut initial_tables = HashMap::new();
    initial_tables.insert(
        1,
        Table::new(1, "Table 1".to_string(), 10000, config.max_players_per_table, config.default_chain_table_id.clone())
            // 回合计时/下一手等待下发客户端（T2 线性倒计时、T4 下一手倒计时）；
            // 与 check_betting_timeout 用的 config 同源，避免两处漂移。
            .with_timeouts(
                config.betting_timeout_secs.saturating_mul(1000),
                config.hand_complete_wait_secs.saturating_mul(1000),
            ),
    );
    // initial_tables.insert(2, Table::new(2, "Table 2".to_string(), 20000, config.max_players_per_table, "".to_string()));
    // initial_tables.insert(3, Table::new(3, "Table 3".to_string(), 50000, config.max_players_per_table, "".to_string()));
    for table in initial_tables.values_mut() {
        let _ = table.start_shuffle();
    }

    let config_for_socket = config.clone();

    let socket_state = Arc::new(SocketState::new(db, initial_tables, config_for_socket));

    let (layer, io) = SocketIo::builder()
        .with_state(socket_state.clone())
        .build_layer();

    socket::set_socket_io(io.clone());
    socket_state.init_table_event_channels(io.clone()).await;
    socket::register_handlers(&io);

    // 桌台注册表锚定（可选）：配置了 STARKNET_TABLE_REGISTRY_ADDRESS 时，
    // 启动引导把初始桌台写上链，拿合约分配的 registry_table_id（协议：
    // "关桌后不开新手"的链上信号源；建桌失败仅告警，不阻塞启动）。
    // 先取参数快照再出锁：注册表调用是跨 await 的网络 I/O，state 写锁
    // 绝不跨越 await（tokio RwLock 不可重入 + 全局单锁冻结 tick）。
    if starknet::chain().is_some_and(|c| c.config.table_registry_enabled()) {
        let registry_snapshot: Vec<(u32, u32, u64, u64)> = {
            let gs = socket_state.state.write().await;
            gs.tables
                .values()
                .map(|t| {
                    (
                        t.summary.id,
                        t.max_players(),
                        t.summary.meta.small_blind as u64,
                        t.summary.meta.big_blind as u64,
                    )
                })
                .collect()
        };
        for (table_id, max_players, small_blind, big_blind) in registry_snapshot {
            match starknet::table_registry::register_table(max_players, small_blind, big_blind)
                .await
            {
                Some(registry_id) => {
                    let mut gs = socket_state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        table.registry_table_id = Some(registry_id);
                    }
                    tracing::info!(
                        "[table-registry] table {table_id} anchored on-chain as registry id {registry_id}"
                    );
                }
                None => {
                    tracing::warn!(
                        "[table-registry] table {table_id} NOT anchored (running without on-chain anchor)"
                    );
                }
            }
        }
    }

    let app_state = Arc::new(AppState {
        db: socket_state.db.clone(),
        config: config.clone(),
        socket_state: socket_state.clone(),
    });

    let mut api_routes = Router::new()
        .route("/auth",routing::get(handlers::get_current_user))
        .route("/auth/wallet", routing::post(handlers::wallet_login))
        .route("/auth/wallet/logout", routing::post(handlers::wallet_logout))
        .route("/tables/:table_id", routing::get(handlers::get_table))
        // 关桌（终态）：operator 鉴权（OPERATOR_ADMIN_TOKEN），关桌后不再开局
        .route("/tables/:table_id/close", routing::post(handlers::close_table))
        // P0-2 牌局记录看板：最近手牌列表 + 单手详情
        .route("/tables/:table_id/history", routing::get(handlers::get_table_history))
        .route("/tables/:table_id/history/:hand_seq", routing::get(handlers::get_table_hand))
        // D1 洗牌证明通道：按手查每层证明本体 + verified/tx + 结算/链上元数据
        .route("/tables/:table_id/hands/:hand_seq/proof", routing::get(handlers::get_table_hand_proof))
        .route("/games/:game_id/join", routing::post(handlers::join_game))
        .route("/games/:game_id/action", routing::post(handlers::player_action))
        .route("/games/:game_id/reveal-token", routing::post(handlers::submit_reveal_token));
    // audit #9：dev bot 是联调工具，release 构建默认不暴露匿名路由；
    // debug 构建（本地 cargo run）或显式 TEXAS_DEV_BOT_ENABLED=1 才注册。
    if cfg!(debug_assertions) || std::env::var("TEXAS_DEV_BOT_ENABLED").as_deref() == Ok("1") {
        api_routes = api_routes.route("/dev/bot", routing::post(dev_bot_start));
        // M3-2（发现 5/11 统一通道）：dev faucet——嵌入式嵌入模式给钱包
        // 直铸 PLAY 余额（zchain 栈无链上 RPC/账户部署也能上筹码）；REAL
        // 桌面与非嵌入模式在 faucet_submit 内 fail-closed 拒绝。
        api_routes = api_routes.route("/dev/faucet", routing::post(dev_faucet_credit));
    }
    let api_routes = api_routes
        // Plan C：paymaster 中继通道（提交者与用户解耦；API key 只在服务端）。
        .route("/starknet/paymaster", routing::post(starknet::paymaster::relay))
        .route(
            "/starknet/paymaster/status",
            routing::get(starknet::paymaster::status),
        )
        // G17：/api 限流（10s 窗口 200 次/IP，超限 429）
        .layer(axum::middleware::from_fn(ratelimit::limit));

    let app = Router::new()
        .nest("/api", api_routes)
        .route("/", routing::get(|| async { "Welcome to ProofPlay Poker (Rust)!" }))
        .layer(
            ServiceBuilder::new()
                .map_request(move |mut req: axum::http::Request<axum::body::Body>| {
                    let state = app_state.clone();
                    req.extensions_mut().insert(state);
                    req
                })
                .into_inner(),
        )
        .layer(layer)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::OPTIONS])
                .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::HeaderName::from_static("x-auth-token")])
        )
        .layer(tower_http::trace::TraceLayer::new_for_http());


    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("ProofPlay Poker Server (Rust) starting on port {}", port);
    tracing::info!("Using in-memory user storage (MongoDB removed). 筹码余额由 Starknet STRK20 链上结算决定。");

    axum::serve(
        listener,
        // with_connect_info：给限流中间件提供对端 IP（ratelimit::limit）
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
}

/// dev: 启动进程内机器人玩家（本地联调用）
async fn dev_bot_start(
    state: axum::extract::Extension<Arc<AppState>>,
    body: axum::body::Body,
) -> axum::response::Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct BotReq { wallet: String, #[serde(default)] deposit_tx_hash: String, #[serde(default)] seat_id: u32 }
    let bytes = match axum::body::to_bytes(body, 4096).await { Ok(b) => b, Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "bad body").into_response() };
    let Ok(req) = serde_json::from_slice::<BotReq>(&bytes) else {
        return (axum::http::StatusCode::BAD_REQUEST, "bad json").into_response()
    };
    let seat = if req.seat_id == 0 { 2 } else { req.seat_id };
    tokio::spawn(async move {
        if let Err(e) = dev_bot::start_bot(state.socket_state.clone(), req.wallet, req.deposit_tx_hash, seat).await {
            eprintln!("[bot] FAILED: {e}");
        }
    });
    axum::Json(serde_json::json!({"started": true})).into_response()
}

/// dev: 服务端 faucet（POST /api/dev/faucet，body camelCase）：
/// `{"wallet": "0x…", "amountWei": n?, "nonce": n?}`——嵌入式嵌入模式
/// 直铸 PLAY 余额 note；amountWei 缺省 100 chips（×WEI_PER_CHIP），
/// nonce 缺省时间派生（同钱包同额度重复领取不撞 deposit_id）。
/// 资产类钉死 PLAY：REAL 桌面/非嵌入模式在 [`starknet::appchain::
/// runtime::dev_faucet_credit`] 内 fail-closed 拒绝（503 透出原因）。
async fn dev_faucet_credit(
    body: axum::body::Body,
) -> axum::response::Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FaucetReq { wallet: String, #[serde(default)] amount_wei: Option<u64>, #[serde(default)] nonce: u64 }
    let bytes = match axum::body::to_bytes(body, 4096).await { Ok(b) => b, Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "bad body").into_response() };
    let Ok(req) = serde_json::from_slice::<FaucetReq>(&bytes) else {
        return (axum::http::StatusCode::BAD_REQUEST, "bad json").into_response()
    };
    use starknet_types_core::felt::Felt;
    let Some(wallet_felt) = Felt::from_hex(req.wallet.trim().trim_start_matches("0x")).ok()
        .map(|f| f.to_bytes_be())
    else {
        return (axum::http::StatusCode::BAD_REQUEST, "wallet hex 非法").into_response();
    };
    let amount = match req.amount_wei {
        Some(a) => a,
        None => {
            const WEI_PER_CHIP: u128 = crate::starknet::config::WEI_PER_CHIP;
            match u64::try_from(WEI_PER_CHIP.saturating_mul(100)) {
                Ok(v) => v,
                Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "缺省额度溢出").into_response(),
            }
        }
    };
    match starknet::appchain::runtime::dev_faucet_credit(wallet_felt, amount, req.nonce) {
        Ok(frame) => axum::Json(serde_json::json!({
            "credited": amount,
            "asset": "play",
            "frame": frame,
        }))
        .into_response(),
        Err(e) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
    }
}
