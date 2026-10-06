//! 控制逻辑入 AIR（Stage 2）端到端验收：真实手牌的 dispatch 控制轨迹 →
//! [`canonical_dispatch_trace::witnesses_from_dispatch_records`] 行链 →
//! Rust 侧全量关系验证 → 真实 stwo 出证 + 独立验证。
//!
//! 覆盖面（#22②扩展完成后）：preflop Reveal 完成、postflop Board 窗口
//! 完成（RevealStreet——同街下注开局）与摊牌窗口完成（Showdown →
//! ShowdownDisplay 终态）全部组合进 AIR，整手控制轨迹不再截断
//! （`truncate_at_supported_boundary` 已随 AIR 扩写移除）。

use crate::pokergame::game_state::RevealPhase;
use crate::pokergame::table::full_hand_tests::RealHandDriver;
use poker_texas_air::canonical_dispatch_trace::witnesses_from_dispatch_records;
use poker_texas_air::texas_canonical::{
    validate_batch, CanonicalPhase, CanonicalProtocolCompletionKind, CanonicalTransitionKind,
};
use poker_texas_air::texas_canonical_air::{
    prove_canonical_reveal_completion_batch, verify_canonical_tagged_batch,
};

fn records_of(
    mirror: &crate::starknet::vm_session::VmSession,
) -> Vec<poker_texas_air::canonical_dispatch_trace::DispatchRecord<'_>> {
    mirror
        .vm_traces()
        .iter()
        .map(|trace| trace.as_record())
        .collect()
}

#[test]
fn blind_allin_control_trace_proves_as_canonical_row_chain() {
    let table_id = 424_270u32;
    let table = RealHandDriver::new(table_id, 100).drive_to_showdown_window();
    let mirror = table
        .vm_session
        .as_ref()
        .expect("live VM session retained before finish");
    let traces = mirror.vm_traces();
    assert!(
        traces.len() >= 4,
        "reveal submissions + runout cascades recorded: {}",
        traces.len()
    );

    let records = records_of(mirror);
    assert!(
        records.len() >= 3,
        "control segment must contain submissions + completion + advance: {}",
        records.len()
    );

    let witnesses = witnesses_from_dispatch_records(&records, u64::from(table_id))
        .expect("row chain construction");
    assert!(witnesses.len() >= 3, "row chain: {}", witnesses.len());

    // 链式咬合 + call_seq 连续（生产者契约）。
    for pair in witnesses.windows(2) {
        assert_eq!(
            pair[0].post, pair[1].pre,
            "row chain broken at {:?}",
            pair[0].kind
        );
        assert_eq!(
            pair[1].pre.call_seq, pair[0].post.call_seq,
            "call_seq continues across rows"
        );
    }
    assert!(
        witnesses
            .iter()
            .any(|w| w.kind == CanonicalTransitionKind::AdvanceRound),
        "runout collection must appear as an explicit AdvanceRound row"
    );

    // Rust 侧全量关系验证（per-kind relation + openings）。
    validate_batch(&witnesses).expect("row chain satisfies the host relation");

    // 真实 stwo 出证 + 独立验证（reveal completion 批：blind opening +
    // rules-hash STARK 绑定）。
    let rules = records[0].pre.rules.clone();
    let archive = prove_canonical_reveal_completion_batch(&witnesses, &rules)
        .expect("canonical proof over the control row chain");
    verify_canonical_tagged_batch(&witnesses, &archive)
        .expect("independent verification of the canonical proof");
    let _ = RevealPhase::None;
}

/// 常规手（check/call 线）的控制轨迹同样可证（非 all-in 控制行）。
#[test]
fn normal_hand_preflop_control_trace_proves() {
    let table_id = 424_271u32;
    let table = RealHandDriver::new(table_id, 10_000).drive_to_showdown_window();
    let mirror = table.vm_session.as_ref().expect("live VM session");
    let records = records_of(mirror);
    let witnesses = witnesses_from_dispatch_records(&records, u64::from(table_id))
        .expect("row chain construction");
    validate_batch(&witnesses).expect("preflop control rows satisfy the host relation");
    for pair in witnesses.windows(2) {
        assert_eq!(pair[0].post, pair[1].pre);
    }
}

/// 整手控制轨迹（无截断）：翻前盲注完成 → flop/turn/river 窗口完成
/// （RevealStreet）→ 摊牌窗口完成（Showdown → ShowdownDisplay 终态）。
#[test]
fn full_hand_control_trace_proves_through_showdown_display() {
    let table_id = 424_272u32;
    let table = RealHandDriver::new(table_id, 10_000).drive_to_showdown_display();
    let mirror = table.vm_session.as_ref().expect("live VM session");
    let records = records_of(mirror);

    let witnesses = witnesses_from_dispatch_records(&records, u64::from(table_id))
        .expect("full-hand row chain construction");
    for pair in witnesses.windows(2) {
        assert_eq!(
            pair[0].post, pair[1].pre,
            "row chain broken at {:?}",
            pair[0].kind
        );
    }
    // 终态 = ShowdownDisplay。
    assert_eq!(
        witnesses.last().expect("rows").post.phase,
        CanonicalPhase::ShowdownDisplay,
        "chain terminates in the showdown display state"
    );
    // 完成行家族齐备：翻前 Reveal + 街道 RevealStreet + 摊牌 Showdown。
    assert!(
        witnesses
            .iter()
            .any(|w| w.protocol_completion.kind == CanonicalProtocolCompletionKind::Reveal),
        "preflop reveal completion present"
    );
    assert!(
        witnesses
            .iter()
            .any(|w| w.protocol_completion.kind == CanonicalProtocolCompletionKind::RevealStreet),
        "street reveal completion present"
    );
    assert!(
        witnesses
            .iter()
            .any(|w| w.protocol_completion.kind == CanonicalProtocolCompletionKind::Showdown),
        "showdown completion present"
    );

    validate_batch(&witnesses).expect("full-hand rows satisfy the host relation");
    let rules = records[0].pre.rules.clone();
    let archive = prove_canonical_reveal_completion_batch(&witnesses, &rules)
        .expect("canonical proof over the full-hand control row chain");
    verify_canonical_tagged_batch(&witnesses, &archive)
        .expect("independent verification of the canonical proof");
}

/// 一手牌 canonical 证明性能基准（真实整手控制行链，release 跑测）：
///
/// ```text
/// cargo test --release -p texas --bin texas bench_full_hand_prove -- --include-ignored --nocapture
/// ```
///
/// 对照两条 PCS 档位（stwo 猜想安全模型 `pow + blowup × queries`）：
/// - 生产 40-bit：pow10 + 1×30（`prover_context::protocol_pcs_config`）；
/// - **128-bit**：pow8 + 4×30（`prover_context::security_128_pcs_config`）。
/// 计时覆盖生产语义全程：行链构建 + host 校验（trace_for 内
/// validate_batch）+ STARK prove + flock rules-hash + STARK verify。
#[ignore = "performance benchmark; run explicitly with --include-ignored (release)"]
#[test]
fn bench_full_hand_prove_latency_security() {
    use std::time::Instant;

    use poker_texas_air::texas_canonical_air::{
        protocol_pcs_config, prove_canonical_reveal_completion_batch_with_pcs,
        security_128_pcs_config, verify_canonical_tagged_batch_with_pcs, PcsConfig,
    };

    let table_id = 424_280u32;
    let table = RealHandDriver::new(table_id, 10_000).drive_to_showdown_display();
    let mirror = table.vm_session.as_ref().expect("live VM session");
    let records: Vec<poker_texas_air::canonical_dispatch_trace::DispatchRecord<'_>> = mirror
        .vm_traces()
        .iter()
        .map(|trace| trace.as_record())
        .collect();

    // 1. 行链构建 + Rust 侧全量关系验证（fail-closed 门，计时单列）。
    let t0 = Instant::now();
    let witnesses = witnesses_from_dispatch_records(&records, u64::from(table_id))
        .expect("full-hand row chain");
    let rows = witnesses.len();
    validate_batch(&witnesses).expect("rows satisfy the host relation");
    let host_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let rules = records[0].pre.rules.clone();
    let profiles: [(&str, PcsConfig); 2] = [
        ("40bit(pow10+1x30)", protocol_pcs_config()),
        ("128bit(pow8+4x30)", security_128_pcs_config()),
    ];
    eprintln!(
        "hand proven: rows={rows} host_validate_ms={host_ms:.1}"
    );
    for (label, config) in profiles {
        assert_eq!(
            config.security_bits(),
            if label.starts_with("40") { 40 } else { 128 }
        );
        // 2. prove（含 STARK + flock rules-hash）。
        let t1 = Instant::now();
        let archive = prove_canonical_reveal_completion_batch_with_pcs(&witnesses, &rules, config)
            .expect("prove");
        let prove_ms = t1.elapsed().as_secs_f64() * 1000.0;
        let proof_bytes = archive.stark_proof_bytes.len();
        // 3. verify（独立全验证，含公共 scope 重建 + STARK verify）。
        let t2 = Instant::now();
        verify_canonical_tagged_batch_with_pcs(&witnesses, &archive, config)
            .expect("verify");
        let verify_ms = t2.elapsed().as_secs_f64() * 1000.0;
        eprintln!(
            "{label}: log_size={} rows={rows} prove={prove_ms:.1}ms verify={verify_ms:.1}ms stark_bytes={proof_bytes}",
            archive.log_size,
        );
    }
}
