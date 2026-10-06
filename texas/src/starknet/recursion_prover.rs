//! SNIP-36 模式的递归证明驱动（`STARKNET_SETTLEMENT_MODE=snip36`）。
//!
//! 牌局结束后把本手「每参与者第一条已签名动作」组装成 action-sig 批次
//! （v3 felt 域挑战，endorsement 退役后的唯一参与背书材料），交给
//! hand-verify-native 的 Cairo 递归信封出证（EC 残差经 EC_OP 进 trace、
//! 承诺链电路内重算、host parity 门），证明与最终累计承诺（acc）落盘
//! prover_work_dir，供 v3 双门入口提交（随 cairo >= 2.12 合约上链后
//! 激活）与第三方复验。
//!
//! 失败语义 fail-closed：任一语句签名不闭合则无证明；证明失败/超时则
//! 告警并回退 legacy 结算，绝不阻塞或虚构。

use serde::Serialize;

use super::chain::hex_encode;

/// 一条待证明的动作签名语句（每参与者首条已签名动作）。
#[derive(Debug, Clone)]
pub struct ActionSigMaterial {
    pub seat: u32,
    /// 座位牌局公钥仿射坐标 hex（从压缩 pk_hex 解压）。
    pub pk_x_hex: String,
    pub pk_y_hex: String,
    /// 签名 nonce 点 R 仿射坐标 hex（从压缩 r_hex 解压）。
    pub r_x_hex: String,
    pub r_y_hex: String,
    pub s_hex: String,
    pub seq: u64,
    pub action: String,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProveOutput {
    pub hand_id: u32,
    pub table_id: u32,
    /// 递归信封公开输出（累计承诺链根）。
    pub acc: String,
    /// 证明工件目录（inputs.json / proof.json / summary.json）。
    pub out_dir: String,
    pub steps: u64,
    pub ec_ops: u64,
    pub elapsed_ms: u64,
}

/// 从本手动作日志提取每参与者首条已签名动作，映射座位公钥。
/// 缺签名/缺映射的参与者跳过（调用侧按人数对账完整性）。
pub fn action_sig_materials(
    action_log: &[crate::pokergame::actions::ActionLogEntry],
    participants: &[crate::starknet::prove_log::HandParticipant],
) -> Vec<ActionSigMaterial> {
    use poker_protocol::crypto::curve::{Curve, CurveScalar, CurvePoint};
    type P = <poker_protocol::crypto::curve::StarkCurve as Curve>::Point;
    type S = <poker_protocol::crypto::curve::StarkCurve as Curve>::Scalar;

    let decode_point = |hex_str: &str| -> Option<(String, String)> {
        let bytes = crate::starknet::recursion_prover::decode_hex(hex_str)?;
        let point = P::from_compressed(&bytes)?;
        let (x, y) = point.to_affine_parts()?;
        Some((hex_encode(&x.to_bytes_be()), hex_encode(&y.to_bytes_be())))
    };

    let mut out: Vec<ActionSigMaterial> = Vec::new();
    for entry in action_log {
        let already = out.iter().any(|m| m.seat == entry.seat);
        if already || !entry.sig_ok {
            continue;
        }
        let Some(sig) = entry.sig.as_ref() else { continue };
        let Some(part) = participants.iter().find(|p| p.seat == entry.seat) else {
            continue;
        };
        let Some((pk_x_hex, pk_y_hex)) = decode_point(&part.pk_hex) else { continue };
        let Some((r_x_hex, r_y_hex)) = decode_point(&sig.r_hex) else { continue };
        let Some(s_bytes) = decode_hex(&sig.s_hex) else { continue };
        let Some(s_scalar) = S::from_canonical_bytes(&s_bytes) else { continue };
        out.push(ActionSigMaterial {
            seat: entry.seat,
            pk_x_hex,
            pk_y_hex,
            r_x_hex,
            r_y_hex,
            s_hex: hex_encode(&s_scalar.as_bytes()),
            seq: entry.seq,
            action: entry.action.clone(),
            amount: entry.amount,
        });
    }
    out
}

/// hex（可带 0x 前缀）→ 字节。长度奇数/超界返回 None（fail-closed）。
pub fn decode_hex(hex_str: &str) -> Option<Vec<u8>> {
    let t = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
    if t.is_empty() || t.len() % 2 != 0 || t.len() > 64 {
        return None;
    }
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).ok())
        .collect()
}

/// 出证一层递归信封（阻塞调用，调用方须放 spawn_blocking）。
pub fn prove_batch_blocking(
    table_id: u32,
    hand_id: u32,
    hand_binding: [u8; 32],
    materials: &[ActionSigMaterial],
    out_dir: &std::path::Path,
) -> Result<ProveOutput, String> {
    use hand_verify_native::recurse::{
        build_action_batch_payload, prove_payload_layer, write_prod_params, GENESIS_ACC,
    };

    // hand_binding 是 Poseidon 输出（< P），types-core from_bytes_be 恒 canonical。
    let hb = starknet_crypto::Felt::from_bytes_be(&hand_binding);
    let statements: Vec<hand_verify_native::recurse::ActionSigStatement> = materials
        .iter()
        .map(|m| hand_verify_native::recurse::ActionSigStatement {
            pk_x_hex: m.pk_x_hex.clone(),
            pk_y_hex: m.pk_y_hex.clone(),
            r_x_hex: m.r_x_hex.clone(),
            r_y_hex: m.r_y_hex.clone(),
            s_hex: m.s_hex.clone(),
            table_id,
            hand_id,
            seq: m.seq,
            action: m.action.clone(),
            amount: m.amount,
        })
        .collect();
    let payload = build_action_batch_payload(hb, table_id, hand_id, &statements)?;
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let params = write_prod_params(out_dir).map_err(|e| e.to_string())?;
    let (acc, outcome) = prove_payload_layer(hb, payload, GENESIS_ACC, out_dir, Some(&params))?;
    Ok(ProveOutput {
        hand_id,
        table_id,
        acc: hex_encode(&acc.to_bytes_be()),
        out_dir: out_dir.display().to_string(),
        steps: outcome.steps,
        ec_ops: outcome.ec_ops,
        elapsed_ms: outcome.total_ms as u64,
    })
}

#[cfg(test)]
mod sig_materials_tests {
    use super::*;

    /// 2026-09-08 线上：sig_ok=true 的动作入库后结算仍报
    /// "no signed actions"（hand 1788809743）——用真实签名全链路
    /// 验证 action_sig_materials 的每一步过滤。
    #[test]
    fn action_sig_materials_from_real_signatures() {
        use poker_protocol::z_poker::protocol::{sign_game_action, ClientPlayer};
        let player = ClientPlayer::new();
        let pk_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&player.pk);
        let sk_hex = poker_protocol::z_poker::convert::scalar_to_hex(&player.sk);
        let sk_bytes = hex::decode(&sk_hex).unwrap();
        let sk = <<poker_protocol::crypto::DefaultCurve as poker_protocol::crypto::curve::Curve>::Scalar as poker_protocol::crypto::curve::CurveScalar>::from_canonical_bytes(&sk_bytes).unwrap();
        let (r_hex, s_hex) = sign_game_action(&sk, 1, 42, 7, "check", 0, &mut rand_core::OsRng);

        let participants = vec![crate::starknet::prove_log::HandParticipant {
            seat: 3,
            tx_pk: None,
            wallet: "0xabc".into(),
            pk_hex: pk_hex.clone(),
            pk: crate::starknet::vm_session::conv::ec_point(&poker_protocol::crypto::types::ECPoint(player.pk)).unwrap(),
            pk_ownership_proof: vec![],
            stack: 1000,
        }];
        let action_log = vec![crate::pokergame::actions::ActionLogEntry {
            seat: 3, seq: 7, action: "check".into(), amount: 0, auto: false,
            sig_ok: true, owed: 0, my_bet: 0, big_blind: 100,
            sig: Some(crate::pokergame::actions::ActionSig { r_hex, s_hex }),
        }];
        let mats = action_sig_materials(&action_log, &participants);
        assert!(!mats.is_empty(), "materials must be non-empty for a valid signed entry (pk_hex_len={})", pk_hex.len());
    }
}
