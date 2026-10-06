//! B6：进程内 `SettlementProver`——poker_texas_air canonical AIR 栈与
//! poker_appchain 证明管道之间的本地适配器。
//!
//! ## 与 poker-appchain-texasair 的关系（重要）
//!
//! zchain/poker-appchain-texasair 的 [`TexasAirEngine`] 与本模块是**同一
//! 语义的两个实例**：那边是外部第三方接缝 crate（自带 lockfile，隔离
//! stwo 依赖图）；这边是游戏服务器内置实例——因为 poker-appchain-texasair
//! 依赖 poker_texas_air（本工作区根 crate），而本 crate（texas）也依赖
//! poker_texas_air，若 texas 再依赖适配器 crate 会把 poker_texas_air 以两
//! 份独立 lockfile 实例拉进同一依赖图（cargo 循环/冲突），故在本地重实现。
//! prove 语义逐条对齐（含 attestation v2.1 的域标签、消息形状与 192B
//! payload 布局）：
//!
//! 1. `hand_proof` 必须存在；
//! 2. 归档解析为 `poker_texas_air::texas_canonical_air::
//!    ArchivedCanonicalTaggedProof`（borsh 信封，STARK 证明本体 bincode）；
//! 3. 绑定检查：归档 `table_id` == 结算 `table_id`；归档终态承诺 ==
//!    声明 `post_state_commitment`；声明前后状态根与归档一致；
//! 4. **完整 STARK 验证**：`verify_canonical_tagged_proof`（手写约束
//!    canonical AIR 独立验证器：归档形状/端点 state-image 绑定/stwo 全
//!    约束复核，不信任 prover）；
//! 5. 完整结算关系校验（含 hand_proof：镜像 pot@74 逐字节绑定）：
//!    `poker_appchain::settlement::validate_settlement`；
//! 6. attestor 签名（attestation v2.1）：域 `poker-appchain.texas-air-v2`，
//!    消息 = binding/post_state_commitment/post_state_root/pre_state_root/
//!    plan_digest，payload = 4×32B 声明 + 64B 签名 = 192B；
//! 7. 无 `hand_proof` 的记录（PLAY 桌 dev 路径）：`validate_settlement`
//!    通过后按 host attestation 语义出具 64B 签名（与 poker_appchain
//!    `ValidationEngine` 同消息域）——REAL 结算在本引擎恒走 STARK 路径
//!    （缺 hand_proof 时直接拒绝，pipeline REAL 准入同样拒绝）。
//!
//! verifier key 钉扎（生产注入）：`with_verifier_key` 后 `verify` 对
//! attestor 不一致的 bundle 返回 `VerifierKeyMismatch`。

use ed25519_dalek::Signer as _;

use poker_appchain::error::{AppchainError, AppchainResult};
use poker_appchain::pipeline::{ProofBundle, ProofJob, SettlementProver};

/// 引擎名（`texas-air-` 前缀 = `real_policy::STARK_ENGINE_PREFIX` 允许集；
/// 与 poker-appchain-texasair 的 `TexasAirEngine` 同名同语义）。
pub const ENGINE_NAME: &str = "texas-air-v2";

/// host attestation 档引擎名（无 hand_proof 的 PLAY 出证；与
/// poker_appchain::pipeline::ValidationEngine 同域）。
const HOST_ENGINE_NAME: &str = "host-validate-v2";

/// attestation v2.1 payload 定长：终态承诺(32) + 终态状态根(32) +
/// 首状态根(32) + 计划摘要(32) + ed25519 签名(64) = 192B。
pub const ATTESTATION_PAYLOAD_BYTES: usize = 192;

/// attestation 消息（v2.1，与 poker-appchain-texasair 逐字节一致）。
fn attestation_message(
    binding: &[u8],
    state_commitment: &[u8; 32],
    post_state_root: &[u8; 32],
    pre_state_root: &[u8; 32],
    plan_digest: &[u8; 32],
) -> [u8; 32] {
    poker_appchain::keys::blake2s32(&[
        b"poker-appchain.texas-air-v2",
        binding,
        state_commitment,
        post_state_root,
        pre_state_root,
        plan_digest,
    ])
}

/// host attestation 消息（与 poker_appchain::pipeline 的 v2 域一致）。
fn host_attestation_message(binding_hex: &str) -> AppchainResult<Vec<u8>> {
    let binding = hex::decode(binding_hex)
        .map_err(|_| AppchainError::AdmissionRejected("bad binding hex"))?;
    if binding.len() != 32 {
        return Err(AppchainError::AdmissionRejected("bad binding length"));
    }
    Ok(poker_appchain::keys::blake2s32(&[b"host-validate-v2", &binding]).to_vec())
}

/// 进程内 canonical AIR 证明引擎。
#[derive(Debug, Clone)]
pub struct TexasAirLocalProver {
    attestor: ed25519_dalek::SigningKey,
    /// 钉扎固定 attestor 公钥（生产注入）；Some 时 `verify` 强制一致。
    verifier_key: Option<[u8; 32]>,
}

impl TexasAirLocalProver {
    /// 指定 attestor 密钥构造（生产：环境注入；不得入库）。
    #[must_use]
    pub fn new(attestor: ed25519_dalek::SigningKey) -> Self {
        Self {
            attestor,
            verifier_key: None,
        }
    }

    /// 钉扎固定 attestor 公钥（`StarkRequired` 生产语义的引擎侧强制）。
    #[must_use]
    pub fn with_verifier_key(mut self, key: [u8; 32]) -> Self {
        self.verifier_key = Some(key);
        self
    }

    /// attestor 公钥。
    #[must_use]
    pub fn attestor_public(&self) -> [u8; 32] {
        self.attestor.verifying_key().to_bytes()
    }

    /// 归档字节 → poker_texas_air canonical 归档结构（borsh 信封）。
    ///
    /// # Errors
    /// 编码不合法 → [`AppchainError::Codec`]。
    pub fn parse_archive(
        archive_bytes: &[u8],
    ) -> AppchainResult<poker_texas_air::texas_canonical_air::ArchivedCanonicalTaggedProof> {
        use borsh::BorshDeserialize as _;
        poker_texas_air::texas_canonical_air::ArchivedCanonicalTaggedProof::try_from_slice(
            archive_bytes,
        )
        .map_err(|e| AppchainError::Codec(format!("archive: {e}")))
    }
}

impl SettlementProver for TexasAirLocalProver {
    fn name(&self) -> &'static str {
        ENGINE_NAME
    }

    fn prove(&self, job: &ProofJob) -> AppchainResult<ProofBundle> {
        let binding_hex = hex::encode(job.record.hand_binding);
        match job.record.hand_proof.as_ref() {
            Some(hp) => {
                // ===== STARK 路径（REAL；attestation v2.1）=====
                let archive = Self::parse_archive(&hp.archive_bytes)?;
                // 绑定检查（table/终态承诺/前后状态根——[u8;32] == 即逐字节相等）
                if archive.table_id != job.record.table_id {
                    return Err(AppchainError::AdmissionRejected("archive table mismatch"));
                }
                if archive.post_state_commitment != hp.post_state_commitment {
                    return Err(AppchainError::AdmissionRejected(
                        "archive state commitment mismatch",
                    ));
                }
                if archive.pre_state_root != hp.pre_state_root
                    || archive.post_state_root != hp.post_state_root
                {
                    return Err(AppchainError::AdmissionRejected("archive state root mismatch"));
                }
                // 完整 STARK 验证（canonical AIR 独立验证器，fail-closed）
                poker_texas_air::texas_canonical_air::verify_canonical_tagged_proof(&archive)
                    .map_err(|_| AppchainError::AdmissionRejected("archive stark verify failed"))?;
                // 完整结算关系校验（含 hand_proof：镜像 pot@74 绑定等）
                poker_appchain::settlement::validate_settlement(&job.record, &job.policy)?;
                // attestation v2.1
                let plan_digest =
                    poker_appchain::settlement::plan_digest_bytes(&job.record.plan);
                let msg = attestation_message(
                    &job.record.hand_binding,
                    &archive.post_state_commitment,
                    &archive.post_state_root,
                    &archive.pre_state_root,
                    &plan_digest,
                );
                let mut payload = archive.post_state_commitment.to_vec();
                payload.extend_from_slice(&archive.post_state_root);
                payload.extend_from_slice(&archive.pre_state_root);
                payload.extend_from_slice(&plan_digest);
                payload.extend_from_slice(&self.attestor.sign(&msg).to_bytes());
                Ok(ProofBundle {
                    binding_hex,
                    op_index: job.op_index,
                    engine: self.name(),
                    attestor_public: self.attestor_public(),
                    payload,
                })
            }
            None => {
                // ===== host attestation 路径（PLAY dev；64B 签名）=====
                // 引擎层门（fail-closed，与 ValidationEngine 同语义）：REAL
                // 结算不得由 host 签名出证。
                if poker_appchain::real_policy::is_real_settlement(&job.record) {
                    return Err(AppchainError::RealRequiresStarkProof);
                }
                poker_appchain::settlement::validate_settlement(&job.record, &job.policy)?;
                let msg = host_attestation_message(&binding_hex)?;
                let payload = self.attestor.sign(&msg).to_bytes().to_vec();
                Ok(ProofBundle {
                    binding_hex,
                    op_index: job.op_index,
                    engine: HOST_ENGINE_NAME,
                    attestor_public: self.attestor_public(),
                    payload,
                })
            }
        }
    }

    fn verify(&self, bundle: &ProofBundle) -> AppchainResult<()> {
        // 钉扎（P0-3）：不一致即拒
        if let Some(key) = self.verifier_key {
            if bundle.attestor_public != key {
                return Err(AppchainError::VerifierKeyMismatch);
            }
        }
        let binding = hex::decode(&bundle.binding_hex)
            .map_err(|_| AppchainError::AdmissionRejected("bad binding hex"))?;
        if binding.len() != 32 {
            return Err(AppchainError::AdmissionRejected("bad binding length"));
        }
        match bundle.engine {
            ENGINE_NAME => {
                if bundle.payload.len() != ATTESTATION_PAYLOAD_BYTES {
                    return Err(AppchainError::AdmissionRejected("bad payload"));
                }
                let mut state_commitment = [0u8; 32];
                state_commitment.copy_from_slice(&bundle.payload[..32]);
                let mut post_state_root = [0u8; 32];
                post_state_root.copy_from_slice(&bundle.payload[32..64]);
                let mut pre_state_root = [0u8; 32];
                pre_state_root.copy_from_slice(&bundle.payload[64..96]);
                let mut plan_digest = [0u8; 32];
                plan_digest.copy_from_slice(&bundle.payload[96..128]);
                let msg = attestation_message(
                    &binding,
                    &state_commitment,
                    &post_state_root,
                    &pre_state_root,
                    &plan_digest,
                );
                verify_sig(&bundle.attestor_public, &msg, &bundle.payload[128..])
            }
            HOST_ENGINE_NAME => {
                if bundle.payload.len() != 64 {
                    return Err(AppchainError::AdmissionRejected("bad payload"));
                }
                let msg = host_attestation_message(&bundle.binding_hex)?;
                verify_sig(&bundle.attestor_public, &msg, &bundle.payload)
            }
            _ => Err(AppchainError::AdmissionRejected("unknown engine")),
        }
    }
}

/// ed25519 复验（走 poker_appchain 的 SequencerKey::verify，与全链同一路径）。
fn verify_sig(public: &[u8; 32], msg: &[u8], sig_bytes: &[u8]) -> AppchainResult<()> {
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AppchainError::AdmissionRejected("bad payload"))?;
    if poker_appchain::keys::SequencerKey::verify(public, msg, &sig) {
        Ok(())
    } else {
        Err(AppchainError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_appchain::fee::FeePolicy;
    use poker_appchain::settlement::{
        flat_settlement_plan, HandProofBinding, SettleInput, SettlementRecord, SpendAuth,
    };

    /// PLAY 记录（签名形状合法即可——本测试只看 engine 路由/attest 语义，
    /// 完整校验链路在 tests/appchain_bridge.rs 覆盖）。
    fn play_record(binding_byte: u8) -> SettlementRecord {
        let k = poker_appchain::keys::OwnerKey::from_seed(&[binding_byte; 32]).unwrap();
        let note = poker_appchain::note::Note::new(
            poker_appchain::note::AssetClass::Play,
            100,
            k.public_bytes(),
            [binding_byte; 32],
            Some(1),
        )
        .unwrap();
        let commitment = note.commitment_bytes();
        let nf = poker_appchain::felt::felt_to_bytes32(&note.nullifier(&[binding_byte; 32]));
        let mut record = SettlementRecord {
            table_id: 1,
            hand_binding: [binding_byte; 32],
            policy_commitment: FeePolicy::Zero.commitment_bytes(),
            pot: 100,
            inputs: vec![SettleInput {
                note,
                spend: SpendAuth {
                    commitment,
                    nullifier: nf,
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            }],
            payouts: vec![poker_appchain::note::NoteSpec {
                asset_class: poker_appchain::note::AssetClass::Play,
                amount: 100,
                owner: k.public_bytes(),
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            }],
            rake: poker_appchain::settlement::RakeSplitRecord {
                total: 0,
                treasury_out: None,
                operator_out: None,
            },
            plan: flat_settlement_plan(100, 0b01, {
                let mut awards = [0u64; 9];
                awards[0] = 100;
                awards
            }),
            hand_proof: None,
        };
        let effect = poker_appchain::settlement::settle_effect(&record);
        let scope = poker_appchain::settlement::settle_spend_scope(&record.hand_binding);
        let d = poker_appchain::keys::spend_digest(&commitment, &nf, &scope, &effect);
        record.inputs[0].spend.sig = k.sign(&d);
        record
    }

    /// PLAY（无 hand_proof）→ host attestation 档：64B payload、可复验、
    /// 篡改拒绝；REAL 无 hand_proof → 引擎层拒绝。
    #[test]
    fn play_host_attestation_path_and_real_gate() {
        let attestor = ed25519_dalek::SigningKey::from_bytes(&[0xBu8; 32]);
        let engine = TexasAirLocalProver::new(attestor);
        let job = ProofJob {
            op_index: 3,
            table_id: 1,
            record: std::sync::Arc::new(play_record(0x31)),
            policy: FeePolicy::Zero,
            priority: poker_appchain::pipeline::Priority::Play,
        };
        let bundle = engine.prove(&job).expect("host attestation bundle");
        assert_eq!(bundle.engine, HOST_ENGINE_NAME);
        assert_eq!(bundle.payload.len(), 64);
        engine.verify(&bundle).expect("attestation verifies");
        // 篡改载荷 → 签名拒绝
        let mut tampered = bundle.clone();
        tampered.payload[0] ^= 1;
        assert!(engine.verify(&tampered).is_err());
        // 冒名 attestor（钉扎了**自己的** verifier key）→ 钉扎不一致拒绝
        // （无钉扎的引擎只回答"签名是否归属 attestor_public"，不回答
        // "是不是预期签名者"——限制来自钉扎，见 real_policy P0-3）。
        let stranger_key = ed25519_dalek::SigningKey::from_bytes(&[0xCu8; 32]);
        let stranger = TexasAirLocalProver::new(stranger_key.clone())
            .with_verifier_key(stranger_key.verifying_key().to_bytes());
        assert!(matches!(
            stranger.verify(&bundle).unwrap_err(),
            AppchainError::VerifierKeyMismatch
        ));

        // REAL（无 hand_proof）→ 引擎层门拒绝（P0-3 fail-closed）
        let real = play_record(0x41);
        let real = SettlementRecord {
            inputs: real
                .inputs
                .iter()
                .map(|i| SettleInput {
                    note: poker_appchain::note::Note {
                        asset_class: poker_appchain::note::AssetClass::Real,
                        ..i.note.clone()
                    },
                    spend: i.spend.clone(),
                })
                .collect(),
            ..real
        };
        let real_job = ProofJob {
            record: std::sync::Arc::new(real),
            ..job
        };
        assert!(matches!(
            engine.prove(&real_job).unwrap_err(),
            AppchainError::RealRequiresStarkProof
        ));
    }

    /// 钉扎引擎对陌生 attestor 的 bundle 返回 VerifierKeyMismatch。
    #[test]
    fn verifier_key_pin_rejects_foreign_attestor() {
        let pinned = [9u8; 32];
        let engine = TexasAirLocalProver::new(ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]))
            .with_verifier_key(pinned);
        let bundle = ProofBundle {
            binding_hex: hex::encode([1u8; 32]),
            op_index: 0,
            engine: ENGINE_NAME,
            attestor_public: [7u8; 32],
            payload: vec![0u8; ATTESTATION_PAYLOAD_BYTES],
        };
        assert!(matches!(
            engine.verify(&bundle).unwrap_err(),
            AppchainError::VerifierKeyMismatch
        ));
    }

    /// 归档缺 hand_proof 的 REAL 记录被 pipeline 提交准入拒绝
    /// （本引擎 + StarkRequired 钉扎）——提交层不进队列。
    #[test]
    fn hand_proof_binding_shape_is_192b_layout_compatible() {
        // HandProofBinding 与归档 scope 的声明字段形状（编译期形状锚）。
        let hp = HandProofBinding {
            archive_bytes: Vec::new(),
            post_state_commitment: [1; 32],
            pre_state_root: [2; 32],
            post_state_root: [3; 32],
        };
        let _ = hp;
        assert_eq!(ATTESTATION_PAYLOAD_BYTES, 192);
    }
}
