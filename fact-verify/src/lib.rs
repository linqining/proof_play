//! fact-verify — 验证 prove-hand 产出的 Cairo/Stwo 证明并派生 settlement fact。
//!
//! 与 poker_texas_air `DualSettlement` 合约侧公式逐位对齐：
//! - 程序哈希钉扎：`program_hash`（prove-hand public_outputs.json 的同一值，
//!   主网 settlement 电路 = `0x744d16d3…`）；
//! - fact 公式：`poseidon([program_hash, segment…])`
//!   （合约 `fact_for_segment` 同式，字段顺序即契约）。
//!
//! 验证语义：`verify_cairo::<Blake2sMerkleChannel>`（cairo-air 2.4.0，与
//! 生产端同一份源码树），stark proof 的公开内存抽出 `program_hash` + output。
use anyhow::{Context, Result};
use cairo_air::utils::{ProofFormat, deserialize_proof_from_file, get_verification_output};
use cairo_air::verifier::verify_cairo;
use starknet_crypto::poseidon_hash_many;
use std::path::Path;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};

/// SNIP-36 消息哈希（poker_texas_air DualSettlement `snip36_message_hash`
/// 同式）：`poseidon_hash_many([consumer_addr, 0, seg_len, segment…])`。
///
/// Starknet v3 双门断言 `facts[8] == snip36_message_hash(合约地址, segment)`
/// ——zchain 侧钉扎 consumer_addr 后产出的 `fact_s36` 与之同式同值。
#[must_use]
pub fn snip36_message_hash(consumer_addr: starknet_crypto::Felt, segment: &[starknet_crypto::Felt]) -> starknet_crypto::Felt {
    let mut h_state = Vec::with_capacity(segment.len() + 3);
    h_state.push(consumer_addr);
    h_state.push(starknet_crypto::Felt::ZERO);
    h_state.push(starknet_crypto::Felt::from(segment.len() as u64));
    h_state.extend_from_slice(segment);
    starknet_crypto::poseidon_hash_many(&h_state)
}

/// 降级门 fact（poker_texas_air DualSettlement `fact_for_segment` 同式）：
/// `poseidon_hash_many([program_hash, segment…])`。
#[must_use]
pub fn fact_for_segment(program_hash: starknet_crypto::Felt, segment: &[starknet_crypto::Felt]) -> starknet_crypto::Felt {
    let mut felts = Vec::with_capacity(segment.len() + 1);
    felts.push(program_hash);
    felts.extend_from_slice(segment);
    starknet_crypto::poseidon_hash_many(&felts)
}

/// SNIP-36 消息哈希（[u8;32] 字节接口）：`poseidon([consumer_addr, 0, seg_len, segment…])`。
#[must_use]
pub fn snip36_message_hash_bytes(consumer_addr: [u8; 32], segment: &[[u8; 32]]) -> [u8; 32] {
    let c = starknet_crypto::Felt::from_bytes_be(&consumer_addr);
    let seg: Vec<starknet_crypto::Felt> =
        segment.iter().map(|f| starknet_crypto::Felt::from_bytes_be(f)).collect();
    snip36_message_hash(c, &seg).to_bytes_be()
}

/// 降级门 fact（[u8;32] 字节接口）：`poseidon([program_hash, segment…])`。
#[must_use]
pub fn fact_for_segment_bytes(program_hash: [u8; 32], segment: &[[u8; 32]]) -> [u8; 32] {
    let ph = starknet_crypto::Felt::from_bytes_be(&program_hash);
    let seg: Vec<starknet_crypto::Felt> =
        segment.iter().map(|f| starknet_crypto::Felt::from_bytes_be(f)).collect();
    fact_for_segment(ph, &seg).to_bytes_be()
}

/// 验证结果：程序哈希 + 公开输出 + 派生的 settlement fact。
#[derive(Debug, Clone, PartialEq)]
pub struct FactOutput {
    /// 被证明 Cairo 程序的哈希（= 链上 `set_circuit_program_hash` 钉扎值）。
    pub program_hash: starknet_crypto::Felt,
    /// 程序公开输出 felts。
    pub output: Vec<starknet_crypto::Felt>,
    /// `poseidon([program_hash, output…])` —— DualSettlement `fact_for_segment`
    /// 同式，可直接对照链上 `settlement_fact(fact)` 读回。
    pub fact: starknet_crypto::Felt,
}

/// fact 公式（与合约 `fact_for_segment` 同式）：`poseidon([program_hash, segment…])`。
///
/// 公开输出即合约侧 segment（`verify_and_settle_dapv_stark_private_v2` 的
/// calldata 公开段）。
#[must_use]
pub fn fact_for_output(program_hash: starknet_crypto::Felt, output: &[starknet_crypto::Felt]) -> starknet_crypto::Felt {
    let mut felts = Vec::with_capacity(output.len() + 1);
    felts.push(program_hash);
    felts.extend_from_slice(output);
    poseidon_hash_many(&felts)
}

/// 从 prove-hand 产物（JSON / bincode）验证证明并派生 fact。
///
/// # Errors
/// 反序列化失败 / Stwo 验证失败 → [`anyhow::Error`]（fail-closed）。
pub fn verify_cairo_proof_file(proof_path: &Path) -> Result<FactOutput> {
    let proof = deserialize_proof_from_file::<Blake2sMerkleHasher>(proof_path, ProofFormat::Json)
        .context("deserialize proof")?;
    let public_memory = proof.claim.public_data.public_memory.clone();
    verify_cairo::<Blake2sMerkleChannel>(proof).context("stwo verify FAILED")?;
    let verification = get_verification_output(&public_memory);
    // cairo-air 2.4.0 的 VerificationOutput 用 starknet-ff FieldElement：
    // 经 32B 大端字节桥接到 starknet-crypto Felt
    let program_hash =
        starknet_crypto::Felt::from_bytes_be(&verification.program_hash.to_bytes_be());
    let output: Vec<starknet_crypto::Felt> = verification
        .output
        .iter()
        .map(|f| starknet_crypto::Felt::from_bytes_be(&f.to_bytes_be()))
        .collect();
    let fact = fact_for_output(program_hash, &output);
    Ok(FactOutput { program_hash, output, fact })
}

/// 同 [`verify_cairo_proof_file`]，但绑定预期程序哈希（fail-closed：
/// 程序哈希不符即拒绝——对标合约 `set_circuit_program_hash` 钉扎语义）。
///
/// # Errors
/// 验证失败或程序哈希不匹配 → [`anyhow::Error`]。
pub fn verify_cairo_proof_file_pinned(
    proof_path: &Path,
    expected_program_hash: starknet_crypto::Felt,
) -> Result<FactOutput> {
    let out = verify_cairo_proof_file(proof_path)?;
    if out.program_hash != expected_program_hash {
        anyhow::bail!(
            "program hash mismatch: proof {:#x} != pinned {:#x}",
            out.program_hash,
            expected_program_hash
        );
    }
    Ok(out)
}

// ============================================================
// L1 批量终证腿（settlement_batch_private）钉扎与累加链尾对拍
//
// 与 poker_texas_air stark-recursion/src/stark_final.rs 同一公式，
// 但用 starknet-crypto 0.8 的 poseidon_hash_many —— 第二套独立实现
// 交叉验证电路内 batch_fact 公式（groth16-wrap 复刻 ↔ starknet-crypto）。
// ============================================================

/// 批程序（settlement_batch_private，含 acc_prev/批根入参与电路内 poseidon
/// 链接尾版）钉扎哈希。实测出处：prove-hand E2E K=1 真出证（2026-09-30
/// 九人桌迁移后电路；历史 8 人桌钉值 0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803）。
pub const PINNED_BATCH_PROGRAM_HASH: &str =
    "0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d";

/// 每手公开段长度 / 链尾长度（与 stark-recursion stark_final 同值；九人桌
/// 迁移后批段 = 字面 16 前缀 + 16 词语句段）。
pub const BATCH_SEGMENT_LEN: usize = 17;
pub const BATCH_TAIL_LEN: usize = 4;

/// 批证明公开输出的累加链尾（输出末 4 felt）。
#[derive(Debug, Clone, PartialEq)]
pub struct BatchChainTail {
    /// 手数（= (elements − 4) / 16）。
    pub k: usize,
    /// 批 n-1 的 batch_fact（首批 = 0）。
    pub acc_prev: starknet_crypto::Felt,
    /// keccak 批根 32B 的 hi 16B（大端入域）。
    pub root_hi: starknet_crypto::Felt,
    /// keccak 批根 32B 的 lo 16B。
    pub root_lo: starknet_crypto::Felt,
    /// 电路内 poseidon 链接值（= 累加链新链头）。
    pub batch_fact: starknet_crypto::Felt,
}

/// 电路内 batch_fact 公式的宿主镜像（starknet-crypto 实现）：
/// `poseidon_hash_many([acc_prev, root_hi, root_lo, k] ++ segments)`。
///
/// corelib HashState（配对吸收/耗尽补 1/末置换取 s0）与 poseidon_hash_many
/// 构造等价——stark-recursion 真双批 E2E（批 2 绑定批 1 的 batch_fact）实证。
#[must_use]
pub fn batch_fact_mirror(
    acc_prev: starknet_crypto::Felt,
    root_hi: starknet_crypto::Felt,
    root_lo: starknet_crypto::Felt,
    k: usize,
    segments: &[starknet_crypto::Felt],
) -> starknet_crypto::Felt {
    let mut msg = Vec::with_capacity(BATCH_TAIL_LEN + segments.len());
    msg.push(acc_prev);
    msg.push(root_hi);
    msg.push(root_lo);
    msg.push(starknet_crypto::Felt::from(k as u64));
    msg.extend_from_slice(segments);
    poseidon_hash_many(&msg)
}

/// 从批证明公开输出解析累加链尾（fail-closed：len 前缀 / 17k+4 形状）。
///
/// 输出形状（K=1 E2E 实测）：`[len] ++ 16k 手段 ++ [acc_prev, root_hi, root_lo,
/// batch_fact]`，len = 17k+4。
///
/// # Errors
/// 输出过短 / len 前缀与元素数不符 / 非 17k+4 形状。
pub fn parse_batch_chain_tail(output: &[starknet_crypto::Felt]) -> anyhow::Result<BatchChainTail> {
    anyhow::ensure!(
        output.len() >= 1 + BATCH_SEGMENT_LEN + BATCH_TAIL_LEN,
        "batch output too short: {}",
        output.len()
    );
    anyhow::ensure!(
        output[0] == starknet_crypto::Felt::from((output.len() - 1) as u64),
        "batch output len prefix mismatch（形状漂移，fail-closed）"
    );
    let elements = output.len() - 1;
    anyhow::ensure!(
        (elements - BATCH_TAIL_LEN) % BATCH_SEGMENT_LEN == 0,
        "batch output not 17k+4 shape"
    );
    let k = (elements - BATCH_TAIL_LEN) / BATCH_SEGMENT_LEN;
    let t = elements - BATCH_TAIL_LEN;
    Ok(BatchChainTail {
        k,
        acc_prev: output[1 + t],
        root_hi: output[2 + t],
        root_lo: output[3 + t],
        batch_fact: output[4 + t],
    })
}

/// L1 批量终证腿全链验证：验证证明 + 钉扎批程序哈希 + 解析链尾 +
/// 电路内 batch_fact 宿主镜像对拍 + acc/根回显断言（17k+4 形状）。
///
/// # Errors
/// 验证失败 / 哈希不符 / 形状不符 / 链尾对拍失败 / acc·根回显不符。
pub fn verify_batch_proof_file_pinned(
    proof_path: &Path,
    expected_acc_prev: starknet_crypto::Felt,
    expected_root: [u8; 32],
) -> anyhow::Result<BatchChainTail> {
    let out = verify_cairo_proof_file(proof_path)?;
    let pinned = starknet_crypto::Felt::from_hex(PINNED_BATCH_PROGRAM_HASH)?;
    anyhow::ensure!(
        out.program_hash == pinned,
        "batch program hash mismatch: {:#x} != pinned {:#x}",
        out.program_hash,
        pinned
    );
    let tail = parse_batch_chain_tail(&out.output)?;
    // 16B 大端左对齐入 32B felt（groth16-wrap batch.rs:46-55 同式）
    let mut hb = [0u8; 32];
    hb[16..].copy_from_slice(&expected_root[..16]);
    let mut lb = [0u8; 32];
    lb[16..].copy_from_slice(&expected_root[16..]);
    let exp_hi = starknet_crypto::Felt::from_bytes_be(&hb);
    let exp_lo = starknet_crypto::Felt::from_bytes_be(&lb);
    anyhow::ensure!(
        tail.acc_prev == expected_acc_prev,
        "acc chain mismatch: {:#x} != expected {:#x}",
        tail.acc_prev,
        expected_acc_prev
    );
    anyhow::ensure!(tail.root_hi == exp_hi && tail.root_lo == exp_lo, "root hi/lo mismatch");
    let k = tail.k;
    let segments = &out.output[1..1 + k * BATCH_SEGMENT_LEN];
    let recomputed = batch_fact_mirror(expected_acc_prev, exp_hi, exp_lo, k, segments);
    anyhow::ensure!(
        tail.batch_fact == recomputed,
        "in-circuit batch_fact != host mirror（starknet-crypto 第二实现）"
    );
    Ok(tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实 settlement 证明（prove-hand 2.4.0 栈产出；program_hash 与主网
    /// DualSettlement `set_circuit_program_hash` 钉扎值一致）。
    const REAL_PROOF: &str = "../proving-tool/output/settlement/proof.json";
    /// 主网钉扎的 settlement 电路程序哈希（DEPLOYMENTS.md #18 Phase C 切片 2）。
    const PINNED_PROGRAM_HASH: &str =
        "0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4";

    #[test]
    fn real_settlement_proof_verifies_and_fact_is_deterministic() {
        let out = verify_cairo_proof_file(Path::new(REAL_PROOF)).expect("real proof verifies");
        let pinned = starknet_crypto::Felt::from_hex(PINNED_PROGRAM_HASH).unwrap();
        assert_eq!(out.program_hash, pinned, "program hash 必须等于主网钉扎值");
        // fact 确定性：同输出重算一致
        let again = fact_for_output(out.program_hash, &out.output);
        assert_eq!(out.fact, again);
        // 钉扎验证入口
        verify_cairo_proof_file_pinned(Path::new(REAL_PROOF), pinned).expect("pinned verify");
    }

    #[test]
    fn tampered_proof_is_rejected() {
        // 篡改公开输出中的一个 felt → fact 变化（消费端对拍即可发现）
        let out = verify_cairo_proof_file(Path::new(REAL_PROOF)).expect("verify");
        let mut felts = vec![out.program_hash];
        felts.extend_from_slice(&out.output);
        felts[1] += starknet_crypto::Felt::from(1_u64);
        let tampered_fact = poseidon_hash_many(&felts);
        assert_ne!(out.fact, tampered_fact, "fact 必须绑定全部公开输出");
    }

    use starknet_crypto::Felt as _FeltAlias;
    use starknet_crypto::Felt;
    // ── L1 批量终证腿：真实批证明（settlement_batch_private，K=1）──────

    /// 真实批证明工件（9 人桌重采：batch_inputs 两阶段 + prove-hand 阶段 B
    /// 产物，2026-09-30；旧 8 人桌工件已被替换，provenance 见同目录 README）。
    const BATCH_PROOF: &str = "../proving-tool/output/settlement-batch/proof.json";
    /// 批根（manifest.json 的 keccak_batch_root；K=1 语句集 keccak 折叠；
    /// 9 人桌重采 run 的阶段 B 实测）。
    const BATCH_ROOT_HEX: &str =
        "0xb078968da79556fc1ccefbc7ef466fe172e87b172724398fd0f4de70e4326d58";
    /// 批 1 累加链头（genesis acc=0 出证；尾字 batch_fact，实测）。
    const BATCH_FACT_HEX: &str =
        "0x055a0418c9ec47c23386f02c2c322f68b756f6c42e796e236b986ca99ec8bbdc";

    /// 真实批证明：验证 + 钉扎 + 链尾对拍（starknet-crypto 第二实现对拍
    /// stark_final 宿主镜像与电路内 HashState）。
    /// hex -> 32B（keccak 根是全 256bit 值，可 >= felt prime——正是 hi/lo 拆分
    /// 的原因；不能过 Felt::from_hex）。
    fn root_bytes(hex_str: &str) -> [u8; 32] {
        let h = hex_str.trim_start_matches("0x");
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// 真实批证明：验证 + 钉扎 + 链尾对拍（starknet-crypto 第二实现对拍
    /// stark_final 宿主镜像与电路内 HashState）。
    #[test]
    fn real_batch_proof_verifies_with_pinned_hash_and_tail() {
        let root = root_bytes(BATCH_ROOT_HEX);
        let tail = verify_batch_proof_file_pinned(Path::new(BATCH_PROOF), Felt::ZERO, root)
            .expect("batch proof full-chain verify");
        assert_eq!(tail.k, 1);
        assert_eq!(tail.acc_prev, Felt::ZERO, "批 1 genesis");
        assert_eq!(
            tail.batch_fact,
            Felt::from_hex(BATCH_FACT_HEX).unwrap(),
            "电路内 batch_fact = E2E 实测值"
        );
        // 钉扎常量与公开输出 program_hash 一致
        let out = verify_cairo_proof_file(Path::new(BATCH_PROOF)).unwrap();
        assert_eq!(out.program_hash, Felt::from_hex(PINNED_BATCH_PROGRAM_HASH).unwrap());
    }

    /// parse_batch_chain_tail 形状负例：len 前缀漂移拒绝。
    #[test]
    fn batch_tail_parser_rejects_shape_drift() {
        let mut bad = vec![Felt::from(99u64)];
        bad.extend(std::iter::repeat_n(Felt::from(0u64), 21));
        assert!(parse_batch_chain_tail(&bad).is_err());
        assert!(parse_batch_chain_tail(&bad[..3]).is_err());
    }
}

// ============================================================
// 内存态二进制 wire 格式（Binary = bzip2(bincode(CairoProofForRustVerifier))）
//
// 供 zchain 侧分块上传：12MB JSON 压缩为 ~1/10 的二进制，按 64KB 切块
// 作为链上对象，节点内重组后走 [`verify_cairo_proof_bytes`]。
// ============================================================

use std::io::Read as _;

/// 从 prove-hand 的 JSON 产物读出证明并转为二进制 wire 格式。
///
/// # Errors
/// 读取 / JSON 反序列化 / bincode 序列化 / bzip2 压缩失败。
pub fn proof_binary_bytes_from_json(json_path: &Path) -> Result<Vec<u8>> {
    let proof = deserialize_proof_from_file::<Blake2sMerkleHasher>(json_path, ProofFormat::Json)
        .context("deserialize json proof")?;
    let bytes = bincode::serialize(&proof).context("bincode serialize")?;
    let mut compressor = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    std::io::Write::write_all(&mut compressor, &bytes).context("bzip2 write")?;
    compressor.finish().context("bzip2 finish")
}

/// 从二进制 wire 格式验证证明并派生 fact（节点内重组后入口）。
///
/// # Errors
/// bzip2 解压 / bincode 反序列化 / Stwo 验证失败。
pub fn verify_cairo_proof_bytes(bytes: &[u8]) -> Result<FactOutput> {
    let mut decompressor = bzip2::read::BzDecoder::new(bytes);
    let mut raw = Vec::new();
    decompressor.read_to_end(&mut raw).context("bzip2 read")?;
    let proof: cairo_air::CairoProofForRustVerifier<Blake2sMerkleHasher> =
        bincode::deserialize(&raw).context("bincode deserialize")?;
    let public_memory = proof.claim.public_data.public_memory.clone();
    verify_cairo::<Blake2sMerkleChannel>(proof).context("stwo verify FAILED")?;
    let verification = get_verification_output(&public_memory);
    let program_hash =
        starknet_crypto::Felt::from_bytes_be(&verification.program_hash.to_bytes_be());
    let output: Vec<starknet_crypto::Felt> = verification
        .output
        .iter()
        .map(|f| starknet_crypto::Felt::from_bytes_be(&f.to_bytes_be()))
        .collect();
    let fact = fact_for_output(program_hash, &output);
    Ok(FactOutput { program_hash, output, fact })
}

#[cfg(test)]
mod binary_tests {
    use super::*;

    /// 二进制 wire 格式体积实测 + 字节路径验证（与文件路径结果一致）。
    #[test]
    fn binary_roundtrip_matches_file_path() {
        let json = Path::new("../proving-tool/output/settlement/proof.json");
        let bytes = proof_binary_bytes_from_json(json).expect("binary bytes");
        println!(
            "binary wire size = {} bytes (json 12.2MB, 压缩比 ≈ {:.0}x)",
            bytes.len(),
            12_211_591_f64 / bytes.len() as f64
        );
        let out = verify_cairo_proof_bytes(&bytes).expect("bytes verify");
        let expected = verify_cairo_proof_file(json).expect("file verify");
        assert_eq!(out, expected);
        assert_eq!(out.program_hash, starknet_crypto::Felt::from_hex("0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4").unwrap());
    }
}
