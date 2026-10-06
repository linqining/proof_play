//! batch-poster 常驻 daemon 入口（bin 名沿 prove-hand/wrap-proof 短横线
//! 惯例）。
//!
//! 用法：
//!
//! ```text
//! batch-poster run [--bind 127.0.0.1:7331]   # 常驻主循环（+ status HTTP 端点）
//! batch-poster status                          # 打印一次 status JSON（只读）
//! batch-poster drain                           # 逃生：置 drain 位，跑至在途清空退出
//! ```
//!
//! 发送面复用 texas 同款账户装配（`texas/src/starknet/chain.rs:57-71`：
//! SingleOwnerAccount + PreConfirmed 块位；env 同源：
//! STARKNET_RPC_URL / STARKNET_OPERATOR_ADDRESS / STARKNET_OPERATOR_PRIVATE_KEY）
//! ——缺任一 env 即拒绝启动（fail-closed，不做无签名面的半套上链）。

use std::sync::Arc;

use starknet::accounts::{ExecutionEncoding, SingleOwnerAccount};
use starknet::core::types::{BlockId, BlockTag, Felt};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider as _};
use starknet::signers::{LocalWallet, SigningKey};
use starknet_txmgr::provider::ProviderSend;

fn usage() -> ! {
    eprintln!(
        "用法: batch-poster <run|status|drain> [--bind 127.0.0.1:7331]\n\
         \x20 run    常驻主循环（recover → tick 循环 + status HTTP 端点）\n\
         \x20 status 打印一次 status JSON（只读，不需要 env）\n\
         \x20 drain  逃生：置 drain 位后跑至在途清空退出"
    );
    std::process::exit(2);
}

/// hex felt 解析（texas chain.rs parse_felt 同语义）。
fn parse_felt(s: &str) -> Option<Felt> {
    Felt::from_hex(s.trim().trim_start_matches("0x")).ok()
}

/// 生产发送面装配（fail-closed）。装配失败原因分类明示——env 缺失 /
/// env 格式错 / RPC 不可达三种退出路径分开报，不把 RPC 不可达误报成
/// 「env 缺失」把运维引去查 env（bug 1 残留修复）。
async fn production_send()
-> Result<
    Arc<ProviderSend<SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>>>,
    String,
> {
    let rpc = std::env::var("STARKNET_RPC_URL");
    let address = std::env::var("STARKNET_OPERATOR_ADDRESS");
    let secret = std::env::var("STARKNET_OPERATOR_PRIVATE_KEY");
    let missing: Vec<&str> = [
        rpc.is_err().then_some("STARKNET_RPC_URL"),
        address.is_err().then_some("STARKNET_OPERATOR_ADDRESS"),
        secret.is_err().then_some("STARKNET_OPERATOR_PRIVATE_KEY"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !missing.is_empty() {
        return Err(format!("发送面 env 缺失（{}）", missing.join(" / ")));
    }
    let rpc = rpc.unwrap().trim().to_string();
    let address = parse_felt(&address.unwrap()).ok_or_else(|| {
        "env 格式错误：STARKNET_OPERATOR_ADDRESS 无法解析为 felt".to_string()
    })?;
    let secret = parse_felt(&secret.unwrap()).ok_or_else(|| {
        "env 格式错误：STARKNET_OPERATOR_PRIVATE_KEY 无法解析为 felt".to_string()
    })?;
    let url = url::Url::parse(&rpc)
        .map_err(|e| format!("env 格式错误：STARKNET_RPC_URL={rpc} 解析失败（{e}）"))?;
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(url)));
    let chain_id = provider.chain_id().await.map_err(|e| {
        format!(
            "RPC 不可达（STARKNET_RPC_URL={rpc}，chain_id 查询失败：{e}）\
             ——检查网络与端点可用性，非 env 缺失"
        )
    })?;
    let mut account = SingleOwnerAccount::new(
        provider,
        LocalWallet::from_signing_key(SigningKey::from_secret_scalar(secret)),
        address,
        chain_id,
        ExecutionEncoding::New,
    );
    // PreConfirmed 块位（nonce 读取含已提交未 accepted 交易；chain.rs:66-69
    // 同注释口径）。
    account.set_block_id(BlockId::Tag(BlockTag::PreConfirmed));
    Ok(Arc::new(ProviderSend::new(Arc::new(account))))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or_else(|| usage());
    let bind = args
        .iter()
        .position(|a| a == "--bind")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7331".to_string());

    match mode {
        "status" => {
            // 只读快照：无发送面也可观测（sidecar/WAL 事实）。
            let st = read_only_status().await;
            println!("{}", st.to_json());
        }
        "run" | "drain" => {
            let send = match production_send().await {
                Ok(send) => send,
                Err(reason) => {
                    eprintln!(
                        "[batch-poster] {reason}——fail-closed 拒绝启动。\
                         只读观测可用 `batch-poster status`。"
                    );
                    std::process::exit(3);
                }
            };
            let cfg = batch_poster::config::PosterConfig::from_env();
            let proofs = Arc::new(batch_poster::proof::ScriptProofSource {
                script: cfg.fold.script.clone(),
                base_input: cfg.fold.base_input.clone(),
                work_dir: cfg.fold.work_dir.clone(),
                expected_program_hash: cfg.fold.expected_program_hash.clone(),
            });
            let mut driver = match batch_poster::PosterDriver::new(cfg, send, proofs) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[batch-poster] init failed: {e}");
                    std::process::exit(4);
                }
            };
            if mode == "drain" {
                driver.drain();
            }
            // status HTTP 端点（后台单连接循环；survey §9.7 监控最小集）。
            let bind_echo = bind.clone();
            let status_state = StatusHandle::default();
            let server_state = status_state.clone_handle();
            tokio::spawn(async move {
                if let Ok(listener) = tokio::net::TcpListener::bind(&bind).await {
                    loop {
                        let st = server_state.current();
                        if batch_poster::status::serve_status_once(&listener, &st)
                            .await
                            .is_err()
                        {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                }
            });
            eprintln!("[batch-poster] {mode} 启动（status 端点 http://{bind_echo}/）");
            if let Err(e) = driver.run().await {
                eprintln!("[batch-poster] run failed: {e}");
                std::process::exit(5);
            }
            status_state.update(driver.status());
            eprintln!("[batch-poster] 退出（drain 完成）");
        }
        _ => usage(),
    }
}

/// 只读 status：不装配发送面——以 sidecar/WAL 事实汇总（发送面观测量为
/// 空值）；余额树（若配置）只读快照。
async fn read_only_status() -> batch_poster::PosterStatus {
    let cfg = batch_poster::config::PosterConfig::from_env();
    let sidecar =
        settle_queue::sidecar::PosterSidecar::open(&cfg.sidecar_dir).expect("sidecar 目录");
    let state = settle_queue::wal::replay(&cfg.queue_wal).expect("queue WAL");
    let receipts = sidecar.list_receipts().expect("receipts");
    let dead = sidecar.list_dead().expect("dead");
    let batches = sidecar.list_batches().expect("batches");
    let open_batches: Vec<_> = batches
        .iter()
        .filter(|b| {
            !matches!(
                b.state,
                settle_queue::sidecar::BatchState::Receipted
                    | settle_queue::sidecar::BatchState::Dead
            )
        })
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // 余额树只读快照（state 文件在案才开——只读探测不创建文件）。
    let (balance_root_head, balance_applied_hands) =
        if cfg.balance.enabled && cfg.balance.state_path.exists() {
            let leaf = match cfg.privacy.as_ref().map(|p| p.leaf_format) {
                Some(privacy_profile::BalanceLeafFormat::Commitment) => {
                    balance_rollup::LeafFormat::Commitment
                }
                _ => balance_rollup::LeafFormat::Plain,
            };
            match balance_rollup::BalanceRollup::open(
                &cfg.balance.state_path,
                &cfg.balance.checkpoint_path,
                leaf,
            ) {
                Ok(r) => (Some(r.root_hex()), Some(r.applied_hands())),
                Err(e) => {
                    eprintln!("[batch-poster] balance rollup 只读快照失败: {e}");
                    (None, None)
                }
            }
        } else {
            (None, None)
        };
    batch_poster::PosterStatus {
        pending_tasks: state
            .open_records()
            .filter(|r| receipts.iter().all(|x| x.key != r.task.key))
            .filter(|r| dead.iter().all(|x| x.key != r.task.key))
            .count(),
        pending_batches: open_batches.len(),
        // 最老未决批年龄：created_at 取 min（最早创建）——见 lib.rs status 的同口径。
        oldest_batch_age_secs: open_batches
            .iter()
            .map(|b| b.created_at)
            .min()
            .map(|c| now.saturating_sub(c)),
        in_flight_txs: 0,
        txmgr_halted: false,
        draining: sidecar
            .read_state()
            .ok()
            .flatten()
            .is_some_and(|s| s.draining),
        operator_balance: None,
        balance_root_head,
        balance_applied_hands,
    }
}

/// 后台 status 快照（端点线程与主循环之间共享——Arc 句柄）。
#[derive(Default, Clone)]
struct StatusHandle {
    inner: Arc<std::sync::Mutex<Option<batch_poster::PosterStatus>>>,
}

impl StatusHandle {
    fn clone_handle(&self) -> Self {
        self.clone()
    }

    fn update(&self, st: batch_poster::PosterStatus) {
        if let Ok(mut g) = self.inner.lock() {
            *g = Some(st);
        }
    }

    fn current(&self) -> batch_poster::PosterStatus {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or(batch_poster::PosterStatus {
                pending_tasks: 0,
                pending_batches: 0,
                oldest_batch_age_secs: None,
                in_flight_txs: 0,
                txmgr_halted: false,
                draining: false,
                operator_balance: None,
                balance_root_head: None,
                balance_applied_hands: None,
            })
    }
}

// ProviderSend 广播接缝的可达性说明（编译期类型对齐；真实广播由驱动器在
// run 循环内经 txmgr 发起）。
