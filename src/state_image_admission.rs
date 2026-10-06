//! 状态镜像认证接纳门（2026-09-10）。
//!
//! 把「prover-supplied canonical 状态镜像 = host-attested 输入」升级为
//! chain-anchored 的最后一厘米：将三条相互独立的语句组合为一个接纳判定。
//!
//! ```text
//! 1. ObjectDb SMT inclusion（Blake2b STARK）:
//!      smt.root  = 公共 L1 state root（共识事实，finalized 高度）
//!      smt.key   = blake2b_256(ObjectID)（L1 SMT 键派生，object_model/smt.rs）
//!      smt.value = 该键处的定宽叶子值（这里 = 状态镜像承诺）
//!    由 `verify_blake2b_lookup_smt_fixed_value_path` 零宿主哈希地证明。
//! 2. 镜像字节 → 镜像承诺（Blake2b STARK，`canonical_state_hash`）:
//!      commitment = Blake2b-256(CANONICAL_STATE_IMAGE_DOMAIN || Borsh(image))
//! 3. 绑定等式（本模块，宿主等式检查）:
//!      expected_root / object_key / image_commitment 三对等式。等式两侧
//!      都已被上述 STARK 语句钉住，等式本身不引入新信任。
//! ```
//!
//! `expected_root` 必须来自共识（finalized 块的状态根），**不得**来自
//! `ProveTask` 或 prover——那是本模块要消灭的信任缺口
//! （`TEXAS_TAGGED_AIR.md:147-153`）。finalized 高度数据的取数通道
//! （RPC/合约视图）是纯运维接线，不在本模块范围。
//!
//! 与 [`crate::canonical_state_hash`] 的分工：那边证明「镜像字节 → 承诺」，
//! 本模块证明「承诺 → 链上根下的叶子」。两者合起来即为 #43 的
//! "authenticated state image"；「canonical transition AIR 内部重算
//! Blake2b」的单一 statement 合成仍是后续项（见 TODO #48）。

use crate::blake2b_lookup_compression::{
    verify_blake2b_lookup_smt_fixed_value_path, ArchivedBlake2bLookupSmtFixedValuePathProof,
};
use crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness;
use crate::canonical_state_hash::{
    verify_canonical_state_image_hashes, ArchivedCanonicalStateImageHashProof,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::texas_canonical::CanonicalTransitionWitness;
use crate::texas_canonical_air::{
    verify_canonical_tagged_batch, ArchivedCanonicalTaggedProof,
};

/// finalized 高度公共 state root 的取数通道。
///
/// 实现方从共识事实（finalized 块状态下的 ObjectDb 根承诺，合约视图 /
/// RPC）解析出 `state_object_key` 对应的根；实现必须是 fail-closed 的——
/// 取数失败即拒绝接纳，绝不回退到 prover 供给的根。texas 服务端提供
/// `StarknetChain::finalized_state_root`（合约视图读取）作为生产实现。
pub trait FinalizedRootSource {
    /// 解析 `state_object_key`（blake2b_256(ObjectID)）在 finalized 高度
    /// 的公共 state root。取数失败返回 `Err`（接纳方据此 fail-closed）。
    fn finalized_state_root(&self, state_object_key: &[u8; 32]) -> Result<[u8; 32], String>;
}

/// 经取数通道解析共识根后接纳（[`admit_state_image`] 的运维接线形态）。
///
/// # Errors
/// - 取数失败（fail-closed：通道错误即拒绝）；
/// - 绑定等式不成立或 SMT inclusion STARK 验证失败。
pub fn admit_state_image_from_source(
    source: &impl FinalizedRootSource,
    smt_proof: &ArchivedBlake2bLookupSmtFixedValuePathProof,
    object_key: &[u8; 32],
    image_commitment: &[u8; 32],
) -> TexasAirResult<()> {
    let expected_root = source
        .finalized_state_root(object_key)
        .map_err(|error| {
            TexasAirError::SpecViolation(format!(
                "finalized root source failed (fail-closed): {error}"
            ))
        })?;
    admit_state_image(smt_proof, &expected_root, object_key, image_commitment)
}

/// 单一入口的组合验证：canonical transition 批次 + 两端点
/// 镜像哈希语句 + 两端点 SMT inclusion 接纳，一次调用按序完成。
///
/// 验证顺序（任一步失败即整体失败）：
/// 1. `verify_canonical_tagged_batch` — 转换关系 STARK + 公共范围对拍；
/// 2. `verify_canonical_state_image_hashes` — pre/post 镜像字节 → 承诺
///    （Blake2b STARK，承诺值取自批次公共范围，防止语句替换）；
/// 3. `admit_state_image` ×2 — 承诺锚定到 finalized 根下的 SMT 叶子
///    （pre/post 各一条，共享查找表承诺）。
///
/// 该入口成立后，调用方不再自行拼装有序语句表；「转换 AIR 内部重算
/// Blake2b」的内嵌形态仍由 #48-② 后续评估（见 TODO #48）。
pub fn verify_canonical_batch_authenticated(
    witnesses: &[CanonicalTransitionWitness],
    archive: &ArchivedCanonicalTaggedProof,
    image_hash_proof: &ArchivedCanonicalStateImageHashProof,
    smt_pre: &ArchivedBlake2bLookupSmtFixedValuePathProof,
    smt_post: &ArchivedBlake2bLookupSmtFixedValuePathProof,
    finalized_root: &[u8; 32],
) -> TexasAirResult<()> {
    // 1. 转换关系本体。
    verify_canonical_tagged_batch(witnesses, archive)?;
    // 2. 镜像字节 → 承诺（承诺值与批次公共范围绑定，防语句替换）。
    verify_canonical_state_image_hashes(
        image_hash_proof,
        archive.pre_state_commitment,
        archive.post_state_commitment,
    )?;
    // 3. 承诺 → finalized 根下的 SMT 叶子（pre/post 各一）。
    admit_state_image(
        smt_pre,
        finalized_root,
        &archive.state_object_key,
        &archive.pre_state_commitment,
    )?;
    admit_state_image(
        smt_post,
        finalized_root,
        &archive.state_object_key,
        &archive.post_state_commitment,
    )
}

/// 接纳绑定的纯校验（不跑 STARK 验证，快）：三对等式逐一检查。
///
/// 单独暴露以便测试与调用方先做廉价失败；完整接纳走 [`admit_state_image`]。
pub fn validate_admission_bindings(
    smt: &Blake2bSmtFixedValuePathWitness,
    expected_root: &[u8; 32],
    object_key: &[u8; 32],
    image_commitment: &[u8; 32],
) -> TexasAirResult<()> {
    if smt.root != *expected_root {
        return Err(TexasAirError::SpecViolation(
            "SMT inclusion statement roots at a digest that is not the consensus fact".into(),
        ));
    }
    if smt.key != *object_key {
        return Err(TexasAirError::SpecViolation(
            "SMT inclusion statement is keyed to a different table object".into(),
        ));
    }
    if smt.value != *image_commitment {
        return Err(TexasAirError::SpecViolation(
            "SMT leaf value does not carry the canonical state-image commitment".into(),
        ));
    }
    Ok(())
}

/// 完整接纳：绑定等式 + SMT inclusion STARK 验证（零宿主哈希）。
///
/// 调用方此前应已用 [`crate::canonical_state_hash`] 的语句证明
/// 「镜像字节 → `image_commitment`」；本函数再把 `image_commitment`
/// 锚到 `expected_root` 下的 SMT 叶子。二者合一即为完整的镜像认证。
pub fn admit_state_image(
    smt_proof: &ArchivedBlake2bLookupSmtFixedValuePathProof,
    expected_root: &[u8; 32],
    object_key: &[u8; 32],
    image_commitment: &[u8; 32],
) -> TexasAirResult<()> {
    validate_admission_bindings(
        &smt_proof.witness,
        expected_root,
        object_key,
        image_commitment,
    )?;
    verify_blake2b_lookup_smt_fixed_value_path(smt_proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 绑定等式的廉价失败路径（不触发 STARK 验证）。
    #[test]
    fn admission_bindings_reject_root_key_or_value_mismatch() {
        let mut smt = Blake2bSmtFixedValuePathWitness {
            key: [0xa5; 32],
            value: [0x5a; 32],
            siblings: std::array::from_fn(|height| [height as u8; 32]),
            nodes: [[0; 32]; 257],
            root: [0x77; 32],
        };
        smt.nodes[0] = smt.value;
        smt.nodes[1] = {
            let mut h = [0u8; 32];
            h[0] = 1;
            h
        };
        smt.root = [0x77; 32];

        // root/key/value 全对（绑定通过；STARK 验证交给 ignored 全栈测试）。
        validate_admission_bindings(&smt, &smt.root.clone(), &smt.key.clone(), &smt.value.clone())
            .expect("matching bindings must pass");

        // 共识根与语句根不一致 → 拒绝。
        assert!(validate_admission_bindings(
            &smt,
            &[0u8; 32],
            &smt.key.clone(),
            &smt.value.clone()
        )
        .is_err());
        // 键不是该表的 SMT 键 → 拒绝。
        assert!(validate_admission_bindings(
            &smt,
            &smt.root.clone(),
            &[0u8; 32],
            &smt.value.clone()
        )
        .is_err());
        // 叶子值不是该镜像的承诺 → 拒绝。
        assert!(validate_admission_bindings(
            &smt,
            &smt.root.clone(),
            &smt.key.clone(),
            &[0u8; 32]
        )
        .is_err());
    }
}
