//! 合并信封驱动（host 侧）——P 层任务 + 结算隐私语句，一次 prove-hand 出
//! 一份 Stwo 证明，公开输出 17 词 `[new_acc] ++ settlement 公开段(16)`。
//!
//! 与 `recurse.rs`（纯 P 层信封）的分工：combined 面向 snip36 生产形状
//! （每手一批 action-sig + 该手的结算语句），绑定断言在 Cairo 侧强制
//! （任务 hand_binding == settle hand_binding）。host 侧双 parity 门：
//! 1. acc parity：cairo 公开输出首词 == host `host_fold_tasks` 重算值；
//! 2. segment parity：输出后续 16 词 == host 独立重算的期望公开段
//!    （digest 按实际参与者折叠、cms/total 与合约公式逐字段一致）。
//!
//! 结算 wire 布局（102 词，9 人桌）与 `cairo/src/settlement_stmt.cairo`
//! 同源：`[hand_id, registered_digest, n_expected, hand_binding, p×9, s×9,
//!  m×9, c×9, action_log_digest, action_count, w×60]`。

use std::path::{Path, PathBuf};
use std::time::Instant;

use starknet_crypto::{poseidon_hash_many, Felt};

use crate::handbatch::{action_sig_challenge_raw, ascii_felt_pub, verify_hand};
use crate::recurse::{fold_accumulator, host_fold_tasks, RecurseTask, GENESIS_ACC};

/// settle 段词数（与 settlement_stmt.cairo SETTLE_WORDS 一致）。
pub const SETTLE_WORDS: usize = 102;

/// 公开段成功标记（'SP2M_OK'）。
pub fn segment_magic() -> Felt {
    let mut b = [0u8; 32];
    // 'SP2M_OK' = 0x5350324d5f4f4b（大端尾对齐）
    b[25..32].copy_from_slice(b"SP2M_OK");
    Felt::from_bytes_be(&b)
}

/// 动作日志吸收链域标签（starknet_keccak(b"zgame.action_log.v1")）。
pub fn action_log_domain() -> Felt {
    Felt::from_hex("0x11b4269299cbd19c8d701730e13001ca46cbdd2d7a74ba25d7b30be4258fa6e")
        .expect("frozen domain literal")
}

/// 结算隐私语句（host 侧镜像 + wire 构造）。
///
/// `players/signs/magnitudes/commitments` 固定 9 槽（尾部补零）；digest
/// 只按 `players` 前缀（非零槽）折叠——与合约 `compute_settlement_digest`
/// （calldata 实际人数）与 `settlement_stmt.cairo` 的前缀吸收一致。
#[derive(Debug, Clone)]
pub struct SettleStatement {
    pub hand_id: u64,
    pub registered_digest: Felt,
    pub n_expected: u64,
    pub hand_binding: Felt,
    /// 非零槽为实际参与者（felt 地址），尾部零槽 = 补位。
    pub players: [Felt; 9],
    pub signs: [u64; 9],
    pub magnitudes: [u64; 9],
    pub commitments: [Felt; 9],
    pub action_log_digest: Felt,
    /// 每条 2 词（[日志打包词, 合法性词]），≤ 30 条。
    pub action_entries: Vec<[Felt; 2]>,
}

impl SettleStatement {
    /// 实际参与者数（非零玩家前缀长度）。
    fn n_actual(&self) -> usize {
        self.players.iter().take_while(|p| **p != Felt::ZERO).count()
    }

    /// 期望 digest（与合约/texas submit.rs 同公式，按实际人数折叠）。
    pub fn expected_digest(&self) -> Felt {
        let mut fields = Vec::with_capacity(2 + 3 * self.n_actual());
        fields.push(Felt::from(self.hand_id));
        for i in 0..self.n_actual() {
            fields.push(self.players[i]);
            fields.push(Felt::from(self.signs[i]));
            fields.push(Felt::from(self.magnitudes[i]));
        }
        fields.push(self.action_log_digest);
        poseidon_hash_many(&fields)
    }

    /// 期望公开段（16 词）：`[MAGIC, hand_id, digest, n, binding, cm×9,
    /// total, ald]`——与 v2 合约消费口径逐字段一致。
    pub fn expected_segment(&self) -> Result<Vec<Felt>, String> {
        // 与 Cairo 语句同一批良构断言（fail-closed：不合法语句不出证）。
        let digest = self.expected_digest();
        if digest != self.registered_digest {
            return Err("host: digest mismatch (registered_digest stale?)".into());
        }
        if self.action_entries.len() > 30 {
            return Err("host: action entries exceed 30".into());
        }
        let mut sum: i128 = 0;
        let mut count = 0u64;
        let mut total: u64 = 0;
        let mut cms = [Felt::ZERO; 9];
        for i in 0..9 {
            if self.signs[i] > 1 {
                return Err(format!("host: sign at seat {i} not bool"));
            }
            sum = sum
                .checked_add(if self.signs[i] == 1 {
                    self.magnitudes[i] as i128
                } else {
                    -(self.magnitudes[i] as i128)
                })
                .ok_or("host: delta sum overflow")?;
            if self.magnitudes[i] != 0 {
                count += 1;
            }
            if self.signs[i] == 1 && self.magnitudes[i] != 0 {
                total = total
                    .checked_add(self.magnitudes[i])
                    .ok_or("host: total overflow")?;
                cms[i] = poseidon_hash_many(&[
                    self.commitments[i],
                    self.hand_binding,
                    Felt::from(self.magnitudes[i]),
                    Felt::ZERO,
                ]);
            }
        }
        if sum != 0 {
            return Err("host: settlement not zero-sum".into());
        }
        if count != self.n_expected {
            return Err(format!("host: n_expected {n} != non-zero count {count}", n = self.n_expected));
        }
        // 动作日志链根（空日志 = poseidon([DOMAIN])，与 Cairo 侧同）。
        let mut chain = vec![action_log_domain()];
        chain.extend(self.action_entries.iter().flat_map(|p| p.iter().copied()));
        if poseidon_hash_many(&chain) != self.action_log_digest {
            return Err("host: action log chain mismatch".into());
        }
        let mut segment = vec![
            segment_magic(),
            Felt::from(self.hand_id),
            self.registered_digest,
            Felt::from(self.n_expected),
            self.hand_binding,
        ];
        segment.extend(cms);
        segment.push(Felt::from(total));
        segment.push(self.action_log_digest);
        Ok(segment)
    }

    /// wire 摊平（102 词），与 settlement_stmt.cairo 布局一致。
    pub fn wire_words(&self) -> Vec<Felt> {
        let mut w = Vec::with_capacity(SETTLE_WORDS);
        w.push(Felt::from(self.hand_id));
        w.push(self.registered_digest);
        w.push(Felt::from(self.n_expected));
        w.push(self.hand_binding);
        w.extend(self.players);
        w.extend(self.signs.map(Felt::from));
        w.extend(self.magnitudes.map(Felt::from));
        w.extend(self.commitments);
        w.push(self.action_log_digest);
        w.push(Felt::from(self.action_entries.len() as u64));
        for slot in 0..30 {
            let pair = self.action_entries.get(slot).copied().unwrap_or([Felt::ZERO; 2]);
            w.extend(pair);
        }
        debug_assert_eq!(w.len(), SETTLE_WORDS);
        w
    }
}

/// 铸一条诚实 action-sig 语句（生产形状 wire，与 texas
/// `recursion_prover::ActionSigMaterial` 同构）：pk = sk·G，R = w·G，
/// c = challenge(...)，s = (w + c·sk) mod n。
pub fn mint_action_sig_statement(
    g: &crate::curve::Point,
    sk: Felt,
    w: Felt,
    table_id: u64,
    hand_id: u64,
    seq: u64,
    action: &str,
    amount: u64,
) -> crate::recurse::ActionSigStatement {
    use poker_protocol_core::curve::CurveScalar;
    use poker_protocol_core::stark_curve::StarkScalar;

    let pk = g.mul(sk);
    let r = g.mul(w);
    let c = action_sig_challenge_raw(table_id, hand_id, seq, ascii_felt_pub(action), amount, r);
    let to_scalar = |f: Felt| <StarkScalar as CurveScalar>::from_bytes_mod_order(&f.to_bytes_be());
    let s = to_scalar(w) + to_scalar(c) * to_scalar(sk);
    let s_felt = Felt::from_bytes_be(&s.to_bytes_be());
    let (pkx, pky) = pk.to_affine().expect("pk affine");
    let (rx, ry) = r.to_affine().expect("R affine");
    let hex_fe = |f: Felt| format!("0x{}", f.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>());
    crate::recurse::ActionSigStatement {
        pk_x_hex: hex_fe(pkx),
        pk_y_hex: hex_fe(pky),
        r_x_hex: hex_fe(rx),
        r_y_hex: hex_fe(ry),
        s_hex: hex_fe(s_felt),
        table_id: table_id as u32,
        hand_id: hand_id as u32,
        seq,
        action: action.into(),
        amount,
    }
}

/// combined 程序源码路径（部署环境用 HAND_VERIFY_COMBINED_SRC 覆盖）。
fn cairo_combined_src() -> PathBuf {
    std::env::var("HAND_VERIFY_COMBINED_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cairo/src/combined.cairo")
        })
}

fn prove_hand_bin() -> PathBuf {
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

/// 合并出证一层的结果。
#[derive(Debug, Clone)]
pub struct CombinedOutcome {
    pub cairo_acc: Felt,
    /// 17 词公开输出（[acc] ++ segment 16）。
    pub public_output: Vec<Felt>,
    pub total_ms: u128,
    pub cairo_prove_ms: u64,
    pub cairo_run_ms: u64,
    pub cairo_compile_ms: u64,
    pub steps: u64,
    pub ec_ops: u64,
    pub program_hash: Felt,
    pub proof_bytes: usize,
    pub check_verify_ms: u128,
    pub out_dir: PathBuf,
}

/// 合并出证 + 双 parity 门 + 独立复验：
/// 1. host 先验 P 任务（fail-closed）与 settle 语句（良构断言）；
/// 2. spawn prove-hand（combined.cairo）一次；
/// 3. 输出首词 == host acc 重算、后续 16 词 == host 期望公开段；
/// 4. `--check-only` 独立复验。
pub fn prove_combined_layer(
    tasks: &[RecurseTask],
    settle: &SettleStatement,
    prev_acc: Felt,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<CombinedOutcome, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let prove_hand = prove_hand_bin();
    if !prove_hand.exists() {
        return Err(format!(
            "prove-hand binary not found at {} (build: cd proving-tool && cargo build --release)",
            prove_hand.display()
        ));
    }
    // 绑定断言的 host 预检（Cairo 侧会再强制）：任务 binding == settle binding。
    for (i, task) in tasks.iter().enumerate() {
        if task.hand_binding != settle.hand_binding {
            return Err(format!(
                "task {i} hand_binding != settle hand_binding (combined envelope binds one hand)"
            ));
        }
    }
    // P 半边期望 acc（含每任务 host 直验）。
    let expected_acc = host_fold_tasks(tasks, prev_acc)?;
    // 结算半边期望公开段（含良构断言 + digest 链根重算）。
    let expected_segment = settle.expected_segment()?;

    // inputs：[prev_acc, tasks_len, tasks…, settle_len, settle…]
    let mut task_felts: Vec<Felt> = vec![Felt::from(tasks.len() as u64)];
    for task in tasks {
        task_felts.push(task.hand_binding);
        task_felts.push(Felt::from(task.payload.len() as u64));
        task_felts.extend(task.payload.iter().copied());
    }
    let settle_words = settle.wire_words();
    let mut inputs: Vec<Felt> = Vec::with_capacity(2 + task_felts.len() + settle_words.len());
    inputs.push(prev_acc);
    inputs.push(Felt::from(task_felts.len() as u64));
    inputs.extend(task_felts);
    inputs.push(Felt::from(settle_words.len() as u64));
    inputs.extend(settle_words);
    let inputs_json: Vec<String> = inputs.iter().map(|f| format!("0x{f:x}")).collect();
    let inputs_path = out_dir.join("inputs.json");
    std::fs::write(&inputs_path, serde_json::to_string(&inputs_json).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;

    let mut cmd = std::process::Command::new(&prove_hand);
    cmd.arg("--program")
        .arg(cairo_combined_src())
        .arg("--inputs")
        .arg(&inputs_path)
        .arg("--out-dir")
        .arg(out_dir);
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
    .map_err(|e| e.to_string())?;
    if !summary["verified"].as_bool().unwrap_or(false) {
        return Err("cairo proof did not verify".into());
    }
    let public: Vec<Felt> = summary["public"]["output"]
        .as_array()
        .ok_or("public output missing")?
        .iter()
        .map(|v| {
            let s = v.as_str().ok_or("public word not hex string")?;
            Felt::from_hex(s.trim_start_matches("0x")).map_err(|e| format!("parse felt: {e:?}"))
        })
        .collect::<Result<_, _>>()?;
    // 定位：output 前部可能有 runner 回显词；从 MAGIC 锚定公开段。
    let magic = segment_magic();
    let magic_pos = public
        .iter()
        .position(|w| *w == magic)
        .ok_or("SEGMENT_MAGIC not found in public output")?;
    if magic_pos == 0 {
        return Err("public output has no room for acc before MAGIC".into());
    }
    let cairo_acc = public[magic_pos - 1];
    let cairo_segment = &public[magic_pos..magic_pos + 16];
    if cairo_acc != expected_acc {
        return Err(format!(
            "acc parity failure: cairo {} != host {}",
            format!("{cairo_acc:x}"),
            format!("{expected_acc:x}")
        ));
    }
    if cairo_segment != expected_segment.as_slice() {
        return Err("segment parity failure: cairo output != host expected segment".into());
    }

    let proof_path = out_dir.join("proof.json");
    let t = Instant::now();
    let ck = std::process::Command::new(&prove_hand)
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
    Ok(CombinedOutcome {
        cairo_acc,
        public_output: public.clone(),
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

/// 组装 settle 语句的便捷入口（生产接缝：texas 把 HandSettlement 字段映射
/// 到这里）。返回 Err 即语句不合法（fail-closed，不出证）。
#[allow(clippy::too_many_arguments)]
pub fn build_settle_statement(
    hand_id: u64,
    hand_binding: Felt,
    players: &[Felt],
    deltas_wei: &[i128],
    commitments: &[Felt],
    action_log_digest: Felt,
    action_entries: &[[Felt; 2]],
) -> Result<SettleStatement, String> {
    if players.len() > 9 || deltas_wei.len() > 9 || commitments.len() > 9 {
        return Err("participants exceed 9".into());
    }
    if action_entries.len() > 30 {
        return Err("action entries exceed 30".into());
    }
    let mut st = SettleStatement {
        hand_id,
        registered_digest: Felt::ZERO,
        n_expected: 0,
        hand_binding,
        players: [Felt::ZERO; 9],
        signs: [0; 9],
        magnitudes: [0; 9],
        commitments: [Felt::ZERO; 9],
        action_log_digest,
        action_entries: action_entries.to_vec(),
    };
    let mut sum: i128 = 0;
    for (i, delta) in deltas_wei.iter().copied().enumerate() {
        if delta.unsigned_abs() > u64::MAX as u128 {
            return Err(format!("|delta| at seat {i} exceeds u64"));
        }
        st.players[i] = players.get(i).copied().unwrap_or(Felt::ZERO);
        st.signs[i] = u64::from(delta >= 0);
        st.magnitudes[i] = delta.unsigned_abs() as u64;
        if delta != 0 {
            st.n_expected += 1;
        }
        sum = sum.checked_add(delta).ok_or("delta sum overflow")?;
    }
    if sum != 0 {
        return Err("settlement is not zero-sum".into());
    }
    for (i, c) in commitments.iter().enumerate() {
        st.commitments[i] = *c;
    }
    for (i, delta) in deltas_wei.iter().copied().enumerate() {
        if delta > 0 && st.commitments[i] == Felt::ZERO {
            return Err(format!("winner at seat {i} has no payout commitment"));
        }
    }
    st.registered_digest = st.expected_digest();
    // 尾部补位槽必须全零玩家（与 Cairo 前缀折叠的规范一致）。
    for i in players.len()..9 {
        st.players[i] = Felt::ZERO;
    }
    Ok(st)
}

/// 期望 acc 的独立重算导出（combined parity 的期望侧，测试用）。
pub fn expected_acc(tasks: &[RecurseTask], prev_acc: Felt) -> Result<Felt, String> {
    host_fold_tasks(tasks, prev_acc)
}

/// 折叠公式导出（与 recurse::fold_accumulator 同源）。
pub fn acc_fold(prev_acc: Felt, claims: &[Felt]) -> Felt {
    fold_accumulator(prev_acc, claims)
}

/// GENESIS 重导出（驱动侧统一入口）。
pub const GENESIS: Felt = GENESIS_ACC;

/// build_action_batch_payload 重导出（生产接缝便捷）。
pub fn action_batch_payload(
    hand_binding: Felt,
    table_id: u32,
    hand_id: u32,
    statements: &[crate::recurse::ActionSigStatement],
) -> Result<Vec<Felt>, String> {
    crate::recurse::build_action_batch_payload(hand_binding, table_id, hand_id, statements)
}

/// verify_hand 重导出（host 先验）。
pub fn host_verify(hand_binding: Felt, payload: &[Felt]) -> Result<crate::handbatch::VerifyReport, String> {
    verify_hand(hand_binding, payload).map_err(|e| format!("host verify: {e:?}"))
}
