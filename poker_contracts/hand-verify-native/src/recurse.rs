//! Cairo 路线递归信封驱动（form-③ / 递归证明）——`cairo/src/recursion.cairo`
//! 的 host 侧。
//!
//! 递归模型（见 `docs/cairo-recursion-research.md` §1.3）：一层信封 = 一份
//! STARK 证明，电路内逐任务真验证（EC_OP in trace）并重算承诺链
//! `new_acc = poseidon([prev_acc] ++ claims)`；第 k+1 层把第 k 层证明的公开
//! 输出作为 `prev_acc` —— proof-carrying data 链，最终一份证明锚定整条链。
//!
//! 纪律：
//! - **公式 parity 门**：每层出证后，cairo 公开输出必须等于 host 侧同公式
//!   重算值（`fold_accumulator`），否则报错——承诺链公式漂移即失败；
//! - **fail-closed**：任何任务验证失败 → Cairo panic → 无证明；
//! - 出证走 `prove-hand` CLI（`--program cairo/src/recursion.cairo`），
//!   proving-tool 本体零改动。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use starknet_crypto::{poseidon_hash_many, Felt};

use crate::air::KindCounts;
use crate::handbatch::{payload_digest, verify_hand, VerifyReport};
use crate::mint;

/// Genesis 累计承诺（与 Cairo `GENESIS_ACC` 同值）。
pub const GENESIS_ACC: Felt = Felt::ZERO;

pub fn hand_binding(seed: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(0xB16Du64)])
}

/// 递归信封的一个任务：一手待验证的 hand_batch。
#[derive(Debug, Clone)]
pub struct RecurseTask {
    pub hand_binding: Felt,
    pub payload: Vec<Felt>,
}

impl RecurseTask {
    /// Host 侧 claim 词 —— 与 Cairo 端 claim 公式逐 felt 同构：
    /// `poseidon([hand_binding, payload_digest, n_own, n_reveal, n_leave,
    ///             n_recon, n_action])`（v3：尾部追加 action 桶计数）。
    pub fn claim(&self, report: &VerifyReport) -> Felt {
        let digest = payload_digest(&self.payload);
        poseidon_hash_many(&[
            self.hand_binding,
            digest,
            Felt::from(report.n_own),
            Felt::from(report.n_reveal),
            Felt::from(report.n_leave),
            Felt::from(report.n_recon),
            Felt::from(report.n_action),
        ])
    }
}

/// Host 侧累计承诺重算（parity 门的期望值）：
/// `poseidon([prev_acc] ++ claim_1 … claim_N)`。
pub fn fold_accumulator(prev_acc: Felt, claims: &[Felt]) -> Felt {
    let mut words = Vec::with_capacity(claims.len() + 1);
    words.push(prev_acc);
    words.extend_from_slice(claims);
    poseidon_hash_many(&words)
}

/// 铸造 `n_tasks` 手诚实任务（seed 连号，hand_binding 派生自 seed）。
pub fn mint_tasks(
    counts: KindCounts,
    n_action: u32,
    n_tasks: usize,
    seed_base: u64,
) -> Vec<RecurseTask> {
    (0..n_tasks as u64)
        .map(|i| {
            let seed = seed_base + i;
            let hand_binding = hand_binding(seed);
            let payload = mint::mint_hand(
                hand_binding,
                counts.n_own,
                n_action,
                counts.n_reveal,
                counts.n_leave,
                counts.n_recon,
                seed,
            );
            RecurseTask { hand_binding, payload }
        })
        .collect()
}

/// Host 侧完整链：逐任务直验 + claim 折叠（`run_recursion` 的期望值来源）。
pub fn host_fold_tasks(tasks: &[RecurseTask], prev_acc: Felt) -> Result<Felt, String> {
    let mut claims = Vec::with_capacity(tasks.len());
    for task in tasks {
        let report =
            verify_hand(task.hand_binding, &task.payload).map_err(|e| format!("host verify: {e:?}"))?;
        if !report.accepted() {
            return Err("task must verify host-side before proving".into());
        }
        claims.push(task.claim(&report));
    }
    Ok(fold_accumulator(prev_acc, &claims))
}

// ---------------------------------------------------------------------------
// prove-hand 驱动
// ---------------------------------------------------------------------------

fn felt_hex(f: Felt) -> String {
    format!("0x{}", f.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn default_prove_hand() -> PathBuf {
    std::env::var("HAND_VERIFY_PROVE_HAND")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(|p| p.parent())
                .expect("crate lives inside the repo")
                .join("proving-tool/target/release/prove-hand")
        })
}

fn cairo_recursion_src() -> PathBuf {
    // 部署环境（服务器）没有编译期仓库路径——HAND_VERIFY_RECURSION_SRC
    // 指向部署的 cairo 源码（递归证明 2026-09-08 上线时引入）。
    std::env::var("HAND_VERIFY_RECURSION_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cairo/src/recursion.cairo")
        })
}

/// `tasks` Span 的 wire 摊平：`[n_tasks, (hand_binding, payload_len, words)*]`。
fn tasks_wire(tasks: &[RecurseTask]) -> Vec<String> {
    let mut wire = vec![format!("0x{:x}", tasks.len())];
    for task in tasks {
        wire.push(felt_hex(task.hand_binding));
        wire.push(format!("0x{:x}", task.payload.len()));
        wire.extend(task.payload.iter().map(|w| felt_hex(*w)));
    }
    wire
}

/// prove-hand `--inputs` JSON：`[prev_acc, span_len, span elements…]`
/// （Span 参数 = [len, elements…] 摊平，与 form-② 的编码同风格）。
fn inputs_json(prev_acc: Felt, tasks: &[RecurseTask]) -> String {
    let mut arr = vec![felt_hex(prev_acc)];
    let span_len: usize = 1 + tasks.iter().map(|t| 2 + t.payload.len()).sum::<usize>();
    arr.push(format!("0x{span_len:x}"));
    arr.extend(tasks_wire(tasks));
    serde_json::to_string(&arr).expect("inputs json")
}

/// canonical_small + fast FRI（pow16/q40）——cairo 路线二轮定型的生产参数
/// （`docs/cairo-route-optimization.md` §建议生产配置；fast 档上生产前需
/// 安全评审）。写成 prove-hand `--params` JSON。
pub fn write_prod_params(dir: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join("params-prod.json");
    std::fs::write(
        &path,
        r#"{
  "channel_hash": "blake2s",
  "channel_salt": 0,
  "fri_config": {
    "pow_bits": 16,
    "log_last_layer_degree_bound": 0,
    "log_blowup_factor": 1,
    "n_queries": 40,
    "fold_step": 1
  },
  "preprocessed_trace": "canonical_small",
  "store_polynomials_coefficients": false,
  "include_all_preprocessed_columns": false,
  "opt_n_id_to_big_components": null,
  "lifting_size_policy": "auto"
}"#,
    )
    .map_err(|e| e.to_string())?;
    Ok(path)
}

/// 一层递归信封的出证结果。
#[derive(Debug, Clone)]
pub struct LayerOutcome {
    pub n_tasks: usize,
    pub prev_acc: Felt,
    /// Host 侧同公式重算的期望值（parity 门的期望侧）。
    pub expected_acc: Felt,
    /// Cairo 程序公开输出（parity 门的事实侧）。
    pub cairo_acc: Felt,
    /// prove-hand 整个出证 wall（compile + run + prove + 内置 verify）。
    pub total_ms: u128,
    /// summary.json 的纯 prove 相位耗时。
    pub cairo_prove_ms: u64,
    pub cairo_run_ms: u64,
    pub cairo_compile_ms: u64,
    pub steps: u64,
    pub ec_ops: u64,
    pub program_hash: Felt,
    pub proof_bytes: usize,
    /// `--check-only` 独立复验 wall（含反序列化）。
    pub check_verify_ms: u128,
    pub out_dir: PathBuf,
}

/// 出证一层信封并过 parity 门：
/// 1. 写 inputs.json（prev_acc + tasks wire）；
/// 2. spawn prove-hand（compile → run/witness → prove → 内置 verify）；
/// 3. 断言 `cairo_acc == expected_acc`（承诺链公式 parity）；
/// 4. `--check-only` 独立复验证明文件。
///
/// 任何任务验证失败都会在 Cairo 运行期 panic → prove-hand 非零退出 →
/// `Err`（该批次无证明，fail-closed）。
pub fn prove_layer(
    prev_acc: Felt,
    tasks: &[RecurseTask],
    expected_acc: Felt,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<LayerOutcome, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let prove_hand = default_prove_hand();
    if !prove_hand.exists() {
        return Err(format!(
            "prove-hand binary not found at {} (build it: cd proving-tool && cargo build --release)",
            prove_hand.display()
        ));
    }

    let inputs_path = out_dir.join("inputs.json");
    std::fs::write(&inputs_path, inputs_json(prev_acc, tasks)).map_err(|e| e.to_string())?;

    let mut cmd = Command::new(&prove_hand);
    cmd.arg("--program")
        .arg(cairo_recursion_src())
        .arg("--inputs")
        .arg(&inputs_path)
        .arg("--out-dir")
        .arg(out_dir);
    // corelib 与 prove-hand 同仓的编译期路径在服务器上不存在——部署时用
    // HAND_VERIFY_CORELIB 显式指定（与 HAND_VERIFY_PROVE_HAND 同组）。
    if let Ok(corelib) = std::env::var("HAND_VERIFY_CORELIB") {
        cmd.arg("--corelib").arg(corelib);
    }
    if let Some(params) = params_path {
        cmd.arg("--params").arg(params);
    }
    let t = Instant::now();
    let output = cmd.output().map_err(|e| format!("spawn prove-hand: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "prove-hand failed (batch rejected): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let total_ms = t.elapsed().as_millis();

    let summary: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(out_dir.join("summary.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("parse summary.json: {e}"))?;
    if !summary["verified"].as_bool().unwrap_or(false) {
        return Err("cairo proof did not verify".into());
    }
    let cairo_acc = summary["public"]["output"]
        .as_array()
        .and_then(|o| o.first())
        .and_then(|v| v.as_str())
        .ok_or("public output missing from summary.json")?;
    let cairo_acc =
        Felt::from_hex(cairo_acc).map_err(|e| format!("parse cairo acc: {e:?}"))?;
    if cairo_acc != expected_acc {
        return Err(format!(
            "accumulator parity failure: cairo {} != host {}",
            felt_hex(cairo_acc),
            felt_hex(expected_acc)
        ));
    }

    let proof_path = out_dir.join("proof.json");
    let t = Instant::now();
    let ck = Command::new(&prove_hand)
        .arg("--check-only")
        .arg("--proof")
        .arg(&proof_path)
        .output()
        .map_err(|e| format!("spawn prove-hand check-only: {e}"))?;
    if !ck.status.success() {
        return Err(format!(
            "standalone re-verify failed: {}",
            String::from_utf8_lossy(&ck.stderr).trim()
        ));
    }
    let check_verify_ms = t.elapsed().as_millis();

    let timings = &summary["timings_ms"];
    Ok(LayerOutcome {
        n_tasks: tasks.len(),
        prev_acc,
        expected_acc,
        cairo_acc,
        total_ms,
        cairo_prove_ms: timings["prove"].as_u64().unwrap_or(0),
        cairo_run_ms: timings["run_witness"].as_u64().unwrap_or(0),
        cairo_compile_ms: timings["compile"].as_u64().unwrap_or(0),
        steps: summary["execution"]["steps"].as_u64().unwrap_or(0),
        ec_ops: summary["execution"]["builtin_instance_counter"]["ec_op_builtin"]
            .as_u64()
            .unwrap_or(0),
        program_hash: summary["public"]["program_hash"]
            .as_str()
            .and_then(|h| Felt::from_hex(h).ok())
            .ok_or("program hash missing")?,
        proof_bytes: std::fs::metadata(&proof_path).map(|m| m.len() as usize).unwrap_or(0),
        check_verify_ms,
        out_dir: out_dir.to_path_buf(),
    })
}

// ---------------------------------------------------------------------------
// 递归链 / 负例 / 性能
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RecursionReport {
    pub layers: Vec<LayerOutcome>,
    /// Host 侧整链累计承诺（每层都与之对拍）。
    pub host_chain_acc: Felt,
    pub total_ms: u128,
}

/// 跑 `n_layers` 层递归链：第 0 层从 `GENESIS_ACC` 起，第 k+1 层把第 k 层
/// 的公开输出作为 `prev_acc`。每层过 parity 门 + 独立复验。
pub fn run_recursion(
    counts: KindCounts,
    n_action: u32,
    tasks_per_layer: usize,
    n_layers: usize,
    seed_base: u64,
    out_root: &Path,
    params_path: Option<&Path>,
) -> Result<RecursionReport, String> {
    let mut layers = Vec::with_capacity(n_layers);
    let mut prev_acc = GENESIS_ACC;
    let mut seed = seed_base;
    let total = Instant::now();
    for layer in 0..n_layers {
        let tasks = mint_tasks(counts, n_action, tasks_per_layer, seed);
        seed += tasks_per_layer as u64;
        let expected_acc = host_fold_tasks(&tasks, prev_acc)?;
        let outcome =
            prove_layer(prev_acc, &tasks, expected_acc, &out_root.join(format!("layer-{layer}")), params_path)?;
        prev_acc = outcome.cairo_acc;
        layers.push(outcome);
    }
    Ok(RecursionReport { layers, host_chain_acc: prev_acc, total_ms: total.elapsed().as_millis() })
}

/// 负例：篡改任务（ownership s 词 +1）→ Cairo 内 `verify_hand` 返回 false →
/// panic → 该批次无证明。返回 Err 即表示负例未被正确拒绝。
/// 一条待证明的动作签名语句（texas 结算路径的输入形态——wire 用 hex）。
#[derive(Debug, Clone)]
pub struct ActionSigStatement {
    pub pk_x_hex: String,
    pub pk_y_hex: String,
    pub r_x_hex: String,
    pub r_y_hex: String,
    pub s_hex: String,
    pub table_id: u32,
    pub hand_id: u32,
    pub seq: u64,
    pub action: String,
    pub amount: u64,
}

fn felt_from_hex(hex_str: &str) -> Result<Felt, String> {
    let t = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
    if t.is_empty() || t.len() % 2 != 0 || t.len() > 64 {
        return Err(format!("bad felt hex length {}", t.len()));
    }
    let mut buf = [0u8; 32];
    for (i, pair) in t.as_bytes().rchunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16).ok_or("bad hex digit")? as u8;
        let lo = (pair[1] as char).to_digit(16).ok_or("bad hex digit")? as u8;
        buf[31 - i] = hi * 16 + lo;
    }
    // types-core 的 from_bytes_be 无失败路径（≥ P 静默归约），沿用原
    // 旧 0.6 ff Result 语义：非 canonical 输入 fail-loud。
    let felt = Felt::from_bytes_be(&buf);
    if felt.to_bytes_be() != buf {
        return Err("felt out of range".to_string());
    }
    Ok(felt)
}

/// 组装 action-sig 批次 payload（v3 header 6 词 + 每语句 10 词）。
/// host 直验（fail-closed）：任一语句 off-curve / 签名不闭合 → Err。
/// `_hand_binding`：v3 header 预留位（当前 payload 不绑定 hand_binding）。
pub fn build_action_batch_payload(
    _hand_binding: Felt,
    table_id: u32,
    hand_id: u32,
    statements: &[ActionSigStatement],
) -> Result<Vec<Felt>, String> {
    use crate::handbatch::ascii_felt_pub;

    let mut payload: Vec<Felt> = vec![
        Felt::ZERO, // n_own（endorsement 退役，ownership 桶恒空）
        Felt::ZERO, // n_shuffle
        Felt::ZERO, // n_reveal
        Felt::ZERO, // n_leave
        Felt::ZERO, // n_recon
        Felt::from(statements.len() as u64),
    ];
    for st in statements {
        let pkx = felt_from_hex(&st.pk_x_hex)?;
        let pky = felt_from_hex(&st.pk_y_hex)?;
        let rx = felt_from_hex(&st.r_x_hex)?;
        let ry = felt_from_hex(&st.r_y_hex)?;
        let sv = felt_from_hex(&st.s_hex)?;
        let action_felt = ascii_felt_pub(&st.action);
        payload.extend_from_slice(&[
            pkx, pky, rx, ry, sv,
            Felt::from(st.table_id),
            Felt::from(st.hand_id),
            Felt::from(st.seq),
            action_felt,
            Felt::from(st.amount),
        ]);
    }
    let _ = (table_id, hand_id); // hand_id 已随每语句词条进挑战域
    Ok(payload)
}

/// 对一个已组装的 action-sig 批次出证一层信封：
/// host 直验（fail-closed）→ 期望承诺链 → prove-hand 出证 → parity 门。
/// 返回最终 acc（公开输出，hex）与出证摘要。
pub fn prove_payload_layer(
    hand_binding: Felt,
    payload: Vec<Felt>,
    prev_acc: Felt,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(Felt, LayerOutcome), String> {
    let task = RecurseTask { hand_binding, payload };
    // host 直验（fail-closed）
    let report = verify_hand(task.hand_binding, &task.payload)
        .map_err(|e| format!("host verify: {e:?}"))?;
    if !report.accepted() {
        return Err("batch must verify host-side before proving".into());
    }
    let claim = task.claim(&report);
    let expected_acc = fold_accumulator(prev_acc, &[claim]);
    let outcome = prove_layer(prev_acc, &[task], expected_acc, out_dir, params_path)?;
    Ok((outcome.cairo_acc, outcome))
}

pub fn run_negative_tampered_task(
    counts: KindCounts,
    seed: u64,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(), String> {
    let mut tasks = mint_tasks(counts, 2, 2, seed);
    let last = tasks.last_mut().expect("two tasks");
    // 篡改首个 ownership 响应词（v3 header 6 词 + word 4 = s 标量——
    // 标量篡改不破坏点编码，host verify 残差非零、Cairo 端同样拒绝）。
    last.payload[6 + 4] = last.payload[6 + 4] + Felt::from(1u32);
    let report = verify_hand(last.hand_binding, &last.payload).map_err(|e| format!("{e:?}"))?;
    if report.accepted() {
        return Err("tamper must fail host verification (test bug)".into());
    }
    match prove_layer(GENESIS_ACC, &tasks, GENESIS_ACC, out_dir, params_path) {
        Err(_) => Ok(()),
        Ok(_) => Err("tampered batch must not produce a proof".into()),
    }
}

/// 负例：跨层拼接——用伪造的 `prev_acc` 出证，程序照常出证成功，但其公开
/// 输出必然偏离诚实链的 host 重算值，被 parity 门拒绝。
pub fn run_negative_wrong_prev(
    counts: KindCounts,
    seed: u64,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(), String> {
    let tasks = mint_tasks(counts, 2, 2, seed);
    let expected_from_genesis = host_fold_tasks(&tasks, GENESIS_ACC)?;
    let forged = GENESIS_ACC + Felt::from(1u32);
    match prove_layer(forged, &tasks, expected_from_genesis, out_dir, params_path) {
        Err(msg) if msg.contains("accumulator parity failure") => Ok(()),
        Err(other) => Err(format!("unexpected failure mode: {other}")),
        Ok(_) => Err("forged prev_acc must be caught by the parity gate".into()),
    }
}

/// 性能矩阵的一行。
#[derive(Debug, Clone)]
pub struct PerfRow {
    pub n_tasks: usize,
    pub total_ms: u128,
    pub cairo_compile_ms: u64,
    pub cairo_run_ms: u64,
    pub cairo_prove_ms: u64,
    pub steps: u64,
    pub ec_ops: u64,
    pub proof_bytes: usize,
    pub check_verify_ms: u128,
}

/// 单层 N 任务性能扫描（每档独立出证，含独立复验）。
pub fn perf_sweep(
    counts: KindCounts,
    sizes: &[usize],
    seed_base: u64,
    out_root: &Path,
    params_path: Option<&Path>,
) -> Result<Vec<PerfRow>, String> {
    let mut rows = Vec::with_capacity(sizes.len());
    let mut seed = seed_base;
    for &n in sizes {
        let tasks = mint_tasks(counts, 2, n, seed);
        seed += n as u64;
        let expected_acc = host_fold_tasks(&tasks, GENESIS_ACC)?;
        let outcome = prove_layer(
            GENESIS_ACC,
            &tasks,
            expected_acc,
            &out_root.join(format!("n-{n}")),
            params_path,
        )?;
        rows.push(PerfRow {
            n_tasks: outcome.n_tasks,
            total_ms: outcome.total_ms,
            cairo_compile_ms: outcome.cairo_compile_ms,
            cairo_run_ms: outcome.cairo_run_ms,
            cairo_prove_ms: outcome.cairo_prove_ms,
            steps: outcome.steps,
            ec_ops: outcome.ec_ops,
            proof_bytes: outcome.proof_bytes,
            check_verify_ms: outcome.check_verify_ms,
        });
    }
    Ok(rows)
}
