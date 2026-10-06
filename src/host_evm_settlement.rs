//! Host (EVM family) settlement binding — Monad first, generic EVM-equivalent
//! hosts next. This is the EVM counterpart of [`crate::starknet_settlement`]:
//! a deliberately thin adapter that turns **already-verified artifacts**
//! (batch roots / aggregate roots / checkpoints / withdrawal claims produced
//! by the AIR pipeline) into strict EVM ABI calldata for the host settlement
//! contracts (zchain `contracts/monad`: L1Inbox / L1Outbox / L1Bridge).
//!
//! ## Layering contract (multi-settlement architecture)
//!
//! AIRs and the prover are chain-agnostic singletons. Per-host adaptation is
//! confined to this module (and future siblings, e.g. Solana). Adding a host:
//! 1. deploy the host settlement stack (see zchain `contracts/monad` shape),
//! 2. implement the host-side `SettlementAdapter` consuming THIS module's
//!    calldata/event encodings,
//! 3. register the chain in the wallet network registry (login + buy-in come
//!    for free).
//!
//! ## Byte-level discipline
//!
//! The encodings here are byte-for-byte identical to the zchain-side
//! `monad-settlement::abi` implementations. Cross-repo golden vectors (see
//! `tests` in this module, constants produced by zchain
//! `monad-settlement/examples/golden_vector.rs`) lock both sides together so
//! a drift on either side fails CI.

use sha3::{Digest, Keccak256 as Keccak256State};

use crate::error::{TexasAirError, TexasAirResult};

// ---------------------------------------------------------------------------
// 链身份常量（官方 docs.monad.xyz）
// ---------------------------------------------------------------------------

/// Monad 主网 chainId。
pub const MONAD_MAINNET_CHAIN_ID: u64 = 143;
/// Monad 测试网 chainId。
pub const MONAD_TESTNET_CHAIN_ID: u64 = 10143;

// ---------------------------------------------------------------------------
// 最小编码原语（与 zchain monad-settlement::rlp/abi 同形状）
// ---------------------------------------------------------------------------

/// keccak-256（以太坊域；与 zchain `monad-settlement::keccak` 同实现族）。
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256State::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// 函数 selector：keccak256("<abi 签名>")[0..4]。
#[must_use]
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// 32B 字（大端补齐 u64）。
#[must_use]
pub fn word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// 32B 字（uint8）。
#[must_use]
pub fn word_u8(value: u8) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = value;
    word
}

/// 32B 字（bool）。
#[must_use]
pub fn word_bool(value: bool) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = u8::from(value);
    word
}

/// 32B 字（20B EVM 地址零填充）。
#[must_use]
pub fn word_address(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&address);
    word
}

/// selector + 静态参数拼接。
fn encode_static(sig: &str, params: &[&[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + params.len() * 32);
    out.extend_from_slice(&selector(sig));
    for p in params {
        out.extend_from_slice(*p);
    }
    out
}

// ---------------------------------------------------------------------------
// L1Inbox（批次根 / 聚合根 / checkpoint 上锚）
// ---------------------------------------------------------------------------

/// `L1Inbox.submitBatch(uint64,bytes32,uint64)`。
#[must_use]
pub fn encode_submit_batch(index: u64, root: [u8; 32], through_op: u64) -> Vec<u8> {
    encode_static(
        "submitBatch(uint64,bytes32,uint64)",
        &[&word_u64(index), &root, &word_u64(through_op)],
    )
}

/// `L1Inbox.submitAggregate(uint64,bytes32,uint64,uint64)`。
#[must_use]
pub fn encode_submit_aggregate(
    index: u64,
    root: [u8; 32],
    through_op: u64,
    batch_count: u64,
) -> Vec<u8> {
    encode_static(
        "submitAggregate(uint64,bytes32,uint64,uint64)",
        &[
            &word_u64(index),
            &root,
            &word_u64(through_op),
            &word_u64(batch_count),
        ],
    )
}

/// `L1Inbox.submitCheckpoint(uint64,bytes32,bytes32,uint64)`。
#[must_use]
pub fn encode_submit_checkpoint(
    l2_height: u64,
    state_root: [u8; 32],
    withdrawal_root: [u8; 32],
    leaf_count: u64,
) -> Vec<u8> {
    encode_static(
        "submitCheckpoint(uint64,bytes32,bytes32,uint64)",
        &[
            &word_u64(l2_height),
            &state_root,
            &withdrawal_root,
            &word_u64(leaf_count),
        ],
    )
}

// ---------------------------------------------------------------------------
// L1Outbox（提现根注册 + 领取）
// ---------------------------------------------------------------------------

/// `L1Outbox.commitRoot(uint64,uint64,bytes32,bool)`。
#[must_use]
pub fn encode_commit_root(
    l2_height: u64,
    leaf_count: u64,
    root: [u8; 32],
    finalized: bool,
) -> Vec<u8> {
    encode_static(
        "commitRoot(uint64,uint64,bytes32,bool)",
        &[
            &word_u64(l2_height),
            &word_u64(leaf_count),
            &root,
            &word_bool(finalized),
        ],
    )
}

/// `L1Outbox.markFinalized(bytes32)`。
#[must_use]
pub fn encode_mark_finalized(digest: [u8; 32]) -> Vec<u8> {
    encode_static("markFinalized(bytes32)", &[&digest])
}

/// 提现叶子承诺（与 poker-appchain `WithdrawalLeaf` /
/// zchain `monad-settlement::abi::ClaimLeaf` 一一对应；borsh 紧凑小端 113B）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClaimLeaf {
    /// 提现请求幂等键。
    pub request_id: [u8; 32],
    /// 外部收款地址（低 20B = EVM 地址）。
    pub external_recipient: [u8; 32],
    /// 资产标签（1=原生 MON / 3=USDT / 4=USDC；2=PLAY 不可跨链兑付）。
    pub asset_tag: u8,
    /// 打款净额。
    pub amount: u64,
    /// 被销毁 note 承诺。
    pub burned_note_commitment: [u8; 32],
    /// 承载 checkpoint 高度。
    pub checkpoint_height: u64,
}

/// `L1Outbox.claim((bytes32,bytes32,uint8,uint64,bytes32,uint64),bytes32,uint64,uint64,bytes32[])`。
///
/// head 段 = selector + tuple(6 静态字) + root + leafCount + index + 数组偏移；
/// tail 段 = 数组长度 + 兄弟哈希。
#[must_use]
pub fn encode_claim(
    leaf: &ClaimLeaf,
    root: [u8; 32],
    leaf_count: u64,
    index: u64,
    proof: &[[u8; 32]],
) -> Vec<u8> {
    let offset_words = 6 + 3 + 1; // tuple 静态展开 + root + leafCount + index + 数组偏移
    let mut out = encode_static(
        "claim((bytes32,bytes32,uint8,uint64,bytes32,uint64),bytes32,uint64,uint64,bytes32[])",
        &[
            &leaf.request_id,
            &leaf.external_recipient,
            &word_u8(leaf.asset_tag),
            &word_u64(leaf.amount),
            &leaf.burned_note_commitment,
            &word_u64(leaf.checkpoint_height),
            &root,
            &word_u64(leaf_count),
            &word_u64(index),
            &word_u64(offset_words as u64 * 32),
        ],
    );
    out.extend_from_slice(&word_u64(proof.len() as u64));
    for node in proof {
        out.extend_from_slice(node);
    }
    out
}

// ---------------------------------------------------------------------------
// L1Bridge（钱包买入面）
// ---------------------------------------------------------------------------

/// `L1Bridge.depositNative(address)`（msg.value = 锁仓金额）。
#[must_use]
pub fn encode_deposit_native(to: [u8; 20]) -> Vec<u8> {
    encode_static("depositNative(address)", &[&word_address(to)])
}

// ---------------------------------------------------------------------------
// 事件解码（入金 / 强制包含）
// ---------------------------------------------------------------------------

/// `DepositInitiated(uint256,address,address,uint256)` 的 topic0。
#[must_use]
pub fn deposit_initiated_topic0() -> [u8; 32] {
    keccak256(b"DepositInitiated(uint256,address,address,uint256)")
}

/// 解析后的入金事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositEvent {
    /// 入金 nonce（L2 侧 deposit_id 幂等键的原料）。
    pub nonce: u64,
    /// L1 代币地址（`[0u8;20]` = 原生 MON）。
    pub token: [u8; 20],
    /// L2 收款人（EVM 地址投影）。
    pub to: [u8; 20],
    /// 锁仓金额（wei / 最小单位）。
    pub amount: u128,
}

fn word_to_u128(word: &[u8; 32]) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&word[16..32]);
    u128::from_be_bytes(b)
}

/// 从 log（topics + data）解析 [`DepositEvent`]。
///
/// # Errors
/// topics/data 形状不符 → [`TexasAirError::EvmEventDecode`]。
pub fn parse_deposit_log(topics: &[[u8; 32]], data: &[u8]) -> TexasAirResult<DepositEvent> {
    if topics.len() != 4 || topics[0] != deposit_initiated_topic0() {
        return Err(TexasAirError::EvmEventDecode("deposit topics mismatch".into()));
    }
    if data.len() < 32 {
        return Err(TexasAirError::EvmEventDecode("deposit data too short".into()));
    }
    let mut amount_word = [0u8; 32];
    amount_word.copy_from_slice(&data[0..32]);
    Ok(DepositEvent {
        nonce: word_to_u128(&topics[1]) as u64,
        token: topics[2][12..].try_into().expect("20 of 32"),
        to: topics[3][12..].try_into().expect("20 of 32"),
        amount: word_to_u128(&amount_word),
    })
}

/// `ForcedOp(uint256,address,bytes)` 的 topic0（escape channel）。
#[must_use]
pub fn forced_op_topic0() -> [u8; 32] {
    keccak256(b"ForcedOp(uint256,address,bytes)")
}

/// 解析后的强制包含记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcedOpEvent {
    /// 宿主侧单调序号。
    pub seq: u64,
    /// 提交者地址。
    pub submitter: [u8; 20],
    /// L2 操作字节。
    pub payload: Vec<u8>,
}

/// 从 log（topics + data）解析 [`ForcedOpEvent`]。
///
/// ABI 动态参数纪律：`data = [offset_word][len_word][content(padded)]`，
/// offset 指向 **len 字所在位置**，content 在 `offset + 32`。
///
/// # Errors
/// topics/data 形状不符 → [`TexasAirError::EvmEventDecode`]。
pub fn parse_forced_op_log(topics: &[[u8; 32]], data: &[u8]) -> TexasAirResult<ForcedOpEvent> {
    if topics.len() != 3 || topics[0] != forced_op_topic0() {
        return Err(TexasAirError::EvmEventDecode("forced-op topics mismatch".into()));
    }
    if data.len() < 64 {
        return Err(TexasAirError::EvmEventDecode("forced-op data too short".into()));
    }
    let offset = word_to_u128(&data[0..32].try_into().expect("32 of data")) as usize;
    if offset + 32 > data.len() {
        return Err(TexasAirError::EvmEventDecode("len word out of bounds".into()));
    }
    let len = word_to_u128(&data[offset..offset + 32].try_into().expect("32 of data")) as usize;
    let content_at = offset + 32;
    if data.len() < content_at + len {
        return Err(TexasAirError::EvmEventDecode("payload out of bounds".into()));
    }
    Ok(ForcedOpEvent {
        seq: word_to_u128(&topics[1]) as u64,
        submitter: topics[2][12..].try_into().expect("20 of 32"),
        payload: data[content_at..content_at + len].to_vec(),
    })
}

/// `L1Bridge.forceOp(bytes)`。
#[must_use]
pub fn encode_force_op(payload: &[u8]) -> Vec<u8> {
    let mut out = encode_static("forceOp(bytes)", &[&word_u64(0x20)]);
    out.extend_from_slice(&word_u64(payload.len() as u64));
    out.extend_from_slice(payload);
    while out.len() % 32 != 0 {
        out.push(0);
    }
    out
}

// ---------------------------------------------------------------------------
// 钱包提现打包（wallet claim bundle）
// ---------------------------------------------------------------------------

/// 钱包提现领取包：L2 侧导出（withdrawal_root builder 产 proof）→ 宿主
/// 提交（claim calldata）。serde JSON 序列化即钱包↔daemon 的传输形状。
///
/// 门位：`asset_tag == 2`（PLAY）不可跨链兑付（与 L1Outbox 合约 fail-closed
/// 一致）；`proof` 深度 ≥ 64 或 index 越界在宿主校验层拒绝。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WithdrawalClaimBundle {
    /// 提现叶子承诺。
    pub leaf: ClaimLeaf,
    /// 提现根（Merkle 根）。
    pub root: [u8; 32],
    /// 窗口真实叶子数。
    pub leaf_count: u64,
    /// 叶子在规范化树中的位置。
    pub leaf_index: u64,
    /// Merkle 兄弟路径（自叶向根）。
    pub proof: Vec<[u8; 32]>,
}

impl WithdrawalClaimBundle {
    /// 生成宿主 claim calldata（L1Outbox.claim）。
    ///
    /// # Errors
    /// PLAY（tag 2）或未知资产标签 → [`TexasAirError::SpecViolation`]。
    pub fn to_claim_calldata(&self) -> TexasAirResult<Vec<u8>> {
        if !(1..=4).contains(&self.leaf.asset_tag) || self.leaf.asset_tag == 2 {
            return Err(TexasAirError::SpecViolation(format!(
                "asset tag {} 不可跨链兑付（仅 1=MON / 3=USDT / 4=USDC）",
                self.leaf.asset_tag
            )));
        }
        Ok(encode_claim(
            &self.leaf,
            self.root,
            self.leaf_count,
            self.leaf_index,
            &self.proof,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // 金标准向量（跨仓守卫）：期望值由 zchain `monad-settlement::abi`
    // 独立实现计算（examples/golden_vector.rs 家族产出），硬编码于此。
    // 任一侧编码漂移 → 本测试红。
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // 金标准向量（跨仓守卫）：期望值由 zchain `monad-settlement::abi`
    // 独立实现计算（examples/golden_vector.rs 产出）后硬编码于此。
    // 任一侧编码漂移 → 本测试红（两仓不能共享 cargo 图，金向量是唯一
    // 可靠的字节级握手）。
    // -----------------------------------------------------------------

    const GOLDEN_LEAF_ROOT: &str =
        "b21e3d6b534f2130cb246bd934c71df6acd3fb6fda43401ff5d32f95a4cc8f8e";

    #[test]
    fn golden_selectors_and_topics() {
        let cases: &[(&str, &str)] = &[
            ("submitBatch(uint64,bytes32,uint64)", "0x62c53975"),
            ("submitAggregate(uint64,bytes32,uint64,uint64)", "0x5716a5e8"),
            ("submitCheckpoint(uint64,bytes32,bytes32,uint64)", "0x7980bf6b"),
            ("commitRoot(uint64,uint64,bytes32,bool)", "0xfe76f844"),
            ("markFinalized(bytes32)", "0x78901269"),
            ("claim((bytes32,bytes32,uint8,uint64,bytes32,uint64),bytes32,uint64,uint64,bytes32[])", "0x2ec5ff1d"),
            ("depositNative(address)", "0x33bb7f91"),
            ("forceOp(bytes)", "0x2b85b47c"),
        ];
        for (sig, want) in cases {
            assert_eq!(hex(&selector(sig)), *want, "selector drift: {sig}");
        }
        assert_eq!(
            hex(&deposit_initiated_topic0()),
            "0x7142c1446622b71fb14ba6808d8d08a5973a86e4433f33546e133c1d6cfa86bc"
        );
        assert_eq!(
            hex(&forced_op_topic0()),
            "0x779c5bf7511ed25c77cfbc71bf3cfc8d59e1e269a08999cf21a4b361aea2e028"
        );
    }

    #[test]
    fn golden_call_encodings() {
        let root = golden_root();
        assert_eq!(
            hex(&encode_submit_batch(1, root, 64)),
            "0x62c539750000000000000000000000000000000000000000000000000000000000000001b21e3d6b534f2130cb246bd934c71df6acd3fb6fda43401ff5d32f95a4cc8f8e0000000000000000000000000000000000000000000000000000000000000040"
        );
        assert_eq!(
            hex(&encode_submit_aggregate(2, root, 128, 5)),
            "0x5716a5e80000000000000000000000000000000000000000000000000000000000000002b21e3d6b534f2130cb246bd934c71df6acd3fb6fda43401ff5d32f95a4cc8f8e00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000005"
        );
        assert_eq!(
            hex(&encode_submit_checkpoint(7, root, root, 1)),
            "0x7980bf6b0000000000000000000000000000000000000000000000000000000000000007b21e3d6b534f2130cb246bd934c71df6acd3fb6fda43401ff5d32f95a4cc8f8eb21e3d6b534f2130cb246bd934c71df6acd3fb6fda43401ff5d32f95a4cc8f8e0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            hex(&encode_commit_root(7, 1, root, true)),
            "0xfe76f84400000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000001b21e3d6b534f2130cb246bd934c71df6acd3fb6fda43401ff5d32f95a4cc8f8e0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            hex(&encode_mark_finalized(root)),
            "0x78901269b21e3d6b534f2130cb246bd934c71df6acd3fb6fda43401ff5d32f95a4cc8f8e"
        );
        assert_eq!(
            hex(&encode_deposit_native([0x33; 20])),
            "0x33bb7f910000000000000000000000003333333333333333333333333333333333333333"
        );
        assert_eq!(
            hex(&encode_force_op(&[0x01, 0x02])),
            "0x2b85b47c0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000201020000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn golden_claim_encoding_and_wallet_bundle() {
        let root = golden_root();
        let bundle = WithdrawalClaimBundle {
            leaf: golden_leaf(),
            root,
            leaf_count: 1,
            leaf_index: 0,
            proof: vec![[9u8; 32]; 2],
        };
        assert_eq!(
            hex(&bundle.to_claim_calldata().expect("native claim")),
            "0x2ec5ff1d0fd31fdcba98c270b34de557bfe6edec68b0fa3331314a824575b66efbc81c3300000000000000000000000022222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000007b0e77ebb77ec443ab668cb20b84b778d9fb55e2cda24adeb5dbd44abaf240ebd70000000000000000000000000000000000000000000000000000000000000007b21e3d6b534f2130cb246bd934c71df6acd3fb6fda43401ff5d32f95a4cc8f8e000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000209090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909"
        );
        // PLAY（tag 2）fail-closed；serde JSON 往返（钱包↔daemon 传输形状）。
        let play = WithdrawalClaimBundle {
            leaf: ClaimLeaf { asset_tag: 2, ..bundle.leaf },
            ..bundle.clone()
        };
        assert!(play.to_claim_calldata().is_err());
        let json = serde_json::to_string(&bundle).expect("serializes");
        let back: WithdrawalClaimBundle = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, bundle);
    }

    #[test]
    fn event_decoders_roundtrip_and_reject() {
        // 入金事件往返。
        let topics = [
            deposit_initiated_topic0(),
            word_u64(42),
            word_address([0x11; 20]),
            word_address([0x22; 20]),
        ];
        let mut data = [0u8; 32];
        data[16..].copy_from_slice(&1_000_000u128.to_be_bytes());
        let ev = parse_deposit_log(&topics, &data).expect("parses");
        assert_eq!(ev.nonce, 42);
        assert_eq!(ev.amount, 1_000_000);

        // 强制包含事件往返（offset=0x20 指向 len 字）。
        let payload = vec![0x01u8, 0x02];
        let mut fdata = vec![0u8; 32];
        fdata[31] = 0x20;
        fdata.extend_from_slice(&word_u64(payload.len() as u64));
        fdata.extend_from_slice(&payload);
        while fdata.len() % 32 != 0 {
            fdata.push(0);
        }
        let ftopics = [forced_op_topic0(), word_u64(0), word_address([0x33; 20])];
        let fev = parse_forced_op_log(&ftopics, &fdata).expect("parses");
        assert_eq!(fev.seq, 0);
        assert_eq!(fev.payload, payload);

        // 拒绝：topic0 不符 / payload 越界。
        let bad_topics = [word_u64(1), word_u64(0), word_address([0x33; 20])];
        assert!(parse_forced_op_log(&bad_topics, &fdata).is_err());
        assert!(parse_forced_op_log(&ftopics, &fdata[..40]).is_err());
    }

    fn golden_root() -> [u8; 32] {
        let mut root = [0u8; 32];
        hex::decode_to_slice(GOLDEN_LEAF_ROOT, &mut root).expect("golden root hex");
        root
    }

    fn hex(v: &[u8]) -> String {
        format!("0x{}", hex::encode(v))
    }

    fn golden_leaf() -> ClaimLeaf {
        ClaimLeaf {
            request_id: keccak256(b"golden-request"),
            external_recipient: word_address([0x22; 20]),
            asset_tag: 1,
            amount: 123,
            burned_note_commitment: keccak256(b"golden-burn"),
            checkpoint_height: 7,
        }
    }
}
