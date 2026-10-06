//! MonadProofEnvelope：跨仓工件（zchain 侧消费的终证信封）。
//!
//! serde JSON，字段与 StarkVerifier.submitFinalProof 参数一一对应
//! （stark-recursion/src/onchain.rs:76 encode_submit_final_calldata 的
//! 五参数：keccak_root / acc_prev / batch_fact / output_commit / proof，
//! 外加信封元数据 version / program_hash / created_at）。落盘目录由
//! `TEXAS_MONAD_SPOOL_DIR` 指定——zchain 侧消费方是 monad_settlementd
//! `--mode settle`（经 `--settle-inbox` 目录拾取：settle_dispatch.rs 的
//! scan_inbox → MonadSettleDispatcher::ingest_inbox）；**不是** FactQueue
//! （FactQueue 是 zchain 自家 L1 proof 分块 fact 通道，用独立的
//! `--spool-dir ./spool` 与 `fact-queue.json` 状态文件，不消费本信封）。
//!
//! **主键** = `keccak_root`（同时是 zchain 侧幂等键与 poster sidecar 的
//! 批记录键——键域闭合，见 settle-queue crate 文档）。

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

use crate::proof::ProofArtifact;

/// 信封格式版本。
pub const MONAD_ENVELOPE_VERSION: u32 = 1;

/// Monad 终证信封。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonadProofEnvelope {
    pub version: u32,
    /// 批键 = keccak 批根（hex 32B；信封主键与 zchain 幂等键）。
    pub keccak_root: String,
    /// 累加链接入（hex felt；批 n-1 的 fact，首批 0x0）。
    pub acc_prev: String,
    /// 批 fact（hex felt）。
    pub batch_fact: String,
    /// 输出承诺（hex 32B）。
    pub output_commit: String,
    /// 终证字节（bz2）的 base64（压缩形态由出证腿产出，本层透传编码）。
    pub proof_bz2_b64: String,
    /// 出证程序哈希（hex felt；与 prove-batch.sh EXPECTED_PH 行钉扎值同源）。
    pub program_hash: String,
    /// 创建时刻（unix 秒）。
    pub created_at: u64,
}

impl MonadProofEnvelope {
    /// 从出证产物构造（acc_prev 来自 FoldBatchInput）。
    pub fn from_artifact(artifact: &ProofArtifact, acc_prev: &str, created_at: u64) -> Self {
        Self {
            version: MONAD_ENVELOPE_VERSION,
            keccak_root: format!("0x{}", hex::encode(artifact.keccak_root)),
            acc_prev: acc_prev.trim().to_string(),
            batch_fact: artifact.batch_fact.trim().to_string(),
            output_commit: artifact.output_commit.trim().to_string(),
            proof_bz2_b64: B64.encode(&artifact.proof),
            program_hash: artifact.program_hash.trim().to_string(),
            created_at,
        }
    }

    /// 主链 `submitFinalProof` calldata——复用
    /// stark-recursion/src/onchain.rs:76 encode_submit_final_calldata
    /// （selector ‖ 4×bytes32 头 ‖ 偏移/长度 ‖ 金字节）。
    pub fn submit_final_calldata(&self) -> Result<Vec<u8>, String> {
        let keccak_root = parse_hex32(&self.keccak_root)?;
        let output_commit = parse_hex32(&self.output_commit)?;
        let acc_prev = parse_felt(&self.acc_prev)?;
        let batch_fact = parse_felt(&self.batch_fact)?;
        let proof = B64
            .decode(&self.proof_bz2_b64)
            .map_err(|e| format!("proof_bz2_b64 解码失败: {e}"))?;
        stark_recursion::onchain::encode_submit_final_calldata(
            &keccak_root,
            &acc_prev,
            &batch_fact,
            &output_commit,
            &proof,
        )
        .map_err(|e| e.to_string())
    }

    /// 落盘 spool 目录（`<dir>/<keccak_root_hex>.json`，原子写）。
    pub fn spool_to(&self, dir: &Path) -> std::io::Result<std::path::PathBuf> {
        std::fs::create_dir_all(dir)?;
        let name = self.keccak_root.trim_start_matches("0x").to_string();
        let path = dir.join(format!("{name}.json"));
        settle_queue::sidecar::atomic_write_json(&path, self)?;
        Ok(path)
    }
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "hex32 长度非 32B".to_string())
}

fn parse_felt(s: &str) -> Result<groth16_wrap::Felt252, String> {
    groth16_wrap::felt::felt_from_hex(s.trim()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> ProofArtifact {
        ProofArtifact {
            program_hash: "0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d"
                .into(),
            batch_fact: "0x1234".into(),
            output_commit: format!("0x{}", hex::encode([7u8; 32])),
            keccak_root: [9u8; 32],
            proof: vec![1, 2, 3, 4],
            outputs: vec![],
        }
    }

    /// serde 往返（跨仓 JSON 工件契约）。
    #[test]
    fn envelope_serde_roundtrip() {
        let e = MonadProofEnvelope::from_artifact(&artifact(), "0x0", 42);
        let s = serde_json::to_string(&e).unwrap();
        let back: MonadProofEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
        assert!(s.contains("\"keccak_root\""));
        assert!(s.contains("\"proof_bz2_b64\""));
    }

    /// submitFinalProof calldata：selector 前缀 + 长度公式（selector 4 +
    /// 5 头字 ×32 = 164、长度字 32、proof 字节——onchain.rs:76 布局）。
    #[test]
    fn submit_final_calldata_layout() {
        let e = MonadProofEnvelope::from_artifact(&artifact(), "0x0", 42);
        let cd = e.submit_final_calldata().unwrap();
        let proof = B64.decode(&e.proof_bz2_b64).unwrap();
        assert_eq!(cd.len(), 164 + 32 + proof.len());
        // selector 来自 stark-recursion（submit_final_proof_selector）。
        let selector = stark_recursion::onchain::submit_final_proof_selector();
        assert_eq!(&cd[..selector.len()], selector.as_slice());
    }

    /// spool 落盘：文件名 = keccak_root；内容可回读。
    #[test]
    fn spool_writes_envelope_keyed_by_keccak_root() {
        let dir = std::env::temp_dir().join(format!("bp-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let e = MonadProofEnvelope::from_artifact(&artifact(), "0x0", 42);
        let path = e.spool_to(&dir).unwrap();
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&hex::encode([9u8; 32]))
        );
        let back: MonadProofEnvelope =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back, e);
        std::fs::remove_dir_all(&dir).ok();
    }
}
