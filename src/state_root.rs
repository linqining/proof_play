//! State root 计算 — BLAKE3 over ObjectDb hot-v30 projection。
//!
//! ## 设计
//!
//! proof transcript 仍携带完整 resolved `TexasPokerTable` preimage，供 verifier 重放业务
//! 逻辑；公开 state root 则承诺与 ObjectDb 完全相同的 hot-v30 bytes。metadata、rules、
//! governance 通过三个固定宽度 opening digest 进入 hot state，而不是在每个 hand-local
//! transition 中重复展开低频字段。
//!
//! ## 根绑定（host 重算已移除）
//!
//! root 定义为 `BLAKE3("zchain.texas_poker.state_root.v1" || hot-v30 bytes)`，与
//! flock 证明链所验证的压缩函数完全一致。`root = H(preimage)` 的绑定不再由可信
//! host 在验证器里重算 Poseidon252 建立，而是由
//! [`crate::state_root_binding`] 里的 flock 预证明语句覆盖：验证器把确定性导出的
//! hot bytes 与公开 root 组装成 statement，交给已验证的哈希证明，host 不再做任何
//! 哈希重算判定。
//!
//! ## 递归证明中的角色
//!
//! 每个 method AIR 的公开输入包含 `pre_state_root` 和 `post_state_root`；
//! Aggregator AIR 的核心约束为 `left.post_state_root == right.pre_state_root`。

use borsh::BorshDeserialize;
use starknet_crypto::Felt;
use stwo::core::fields::m31::M31;

use crate::error::{TexasAirError, TexasAirResult};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

/// Canonical felt decode: accepts only 32-byte encodings below the Stark
/// prime. types-core 的 `Felt::from_bytes_be` 无失败路径（≥ P 输入会被
/// 静默归约），这里用字节往返判定 canonical——语义与旧 0.6 ff 库
/// `from_bytes_be` 的 `Result` 完全一致。
pub(crate) fn felt_from_canonical_bytes(bytes: &[u8; 32]) -> Option<Felt> {
    let felt = Felt::from_bytes_be(bytes);
    (felt.to_bytes_be() == *bytes).then_some(felt)
}

// Historical sub-structure encoding regression fixtures.
#[cfg(test)]
use poker_l1::contracts::texas_poker::betting::BettingRound;
#[cfg(test)]
use poker_l1::contracts::texas_poker::types::{
    DeckState, ReconstructState, RevealTokenState, ShuffleState, TimeoutConfig,
};

/// 表台状态根（32 字节 BLAKE3 摘要）。
///
/// 实际上是 [`compute_state_root`] 的结果，作为 method AIR 的公开输入；其与
/// preimage 的绑定由 flock 哈希证明承载（见 [`crate::state_root_binding`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateRoot(pub [u8; 32]);

impl StateRoot {
    /// 零状态根（用于初始化场景）。
    #[must_use]
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// 从 32 字节摘要构造。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compatibility constructor from a field-element representation of a
    /// root (wire/legacy fixtures).  The 32-byte big-endian encoding is the
    /// canonical in-memory form.
    #[must_use]
    pub fn from_field(f: Felt) -> Self {
        Self(f.to_bytes_be())
    }

    /// 返回内部摘要字节。
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Domain-separation tag prefixed to the hot-v30 bytes before the BLAKE3
/// root digest; the tag is part of the proven statement preimage.
pub const STATE_ROOT_DOMAIN: &[u8] = b"zchain.texas_poker.state_root.v1";

/// Root digest over domain-separated canonical bytes, using the exact
/// BLAKE3 chain function the flock backend proves.
#[must_use]
pub fn state_root_digest(preimage: &[u8]) -> [u8; 32] {
    let mut message = STATE_ROOT_DOMAIN.to_vec();
    message.extend_from_slice(preimage);
    crate::blake3_flock::blake3_chain_digest(&message)
}

/// 把 32 字节 root 分解为 8 个大端 u32 字，供 Fiat–Shamir channel 的
/// `mix_u32s` 无损吸收。
#[must_use]
pub fn state_root_to_u32_words(root: StateRoot) -> [u32; 8] {
    let bytes = root.bytes();
    let mut words = [0u32; 8];
    for (i, word) in words.iter_mut().enumerate() {
        let offset = 4 * i;
        *word = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
    }
    words
}

/// Project the full Poseidon252 root into the four M31 limbs used by the current
/// method AIR schema. Full-width roots remain verifier public inputs and are
/// used for chain aggregation; this domain-separated projection binds them into
/// the M31 trace instead of the former all-zero placeholder.
#[must_use]
pub fn state_root_to_air_limbs(root: StateRoot) -> [M31; 4] {
    let mut material = b"zchain.texas_poker.air_state_root.v1".to_vec();
    material.extend_from_slice(&root.bytes());
    let digest = blake2b_256(&material);
    let mut limbs = [M31::from(0u32); 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let offset = i * 4;
        let word = u32::from_be_bytes([
            digest[offset],
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        *limb = M31::from(word & 0x7fff_ffff);
    }
    limbs
}

/// 把 u64 编码为 Starknet `Felt`。
#[must_use]
pub fn u64_to_field(v: u64) -> Felt {
    Felt::from(v)
}

/// Canonical, complete resolved `TexasPokerTable` transcript image.
///
/// The old hand-maintained 24-field list omitted consensus fields whenever the
/// VM table grew (addon/ante/rake/RIT and sequence metadata were all missed).
/// This encoding carries the exact Borsh serialization of the *entire* table,
/// with an explicit schema/domain tag, injective 31-byte field chunks, and byte
/// lengths.  Adding or changing any serialized VM field therefore changes the
/// verifier replay input without requiring a second manual field list to be kept in sync.
pub fn table_state_preimage(
    table: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
) -> TexasAirResult<Vec<Felt>> {
    canonical_borsh_preimage("zchain.texas_poker.table.v13", table)
}

/// 从 canonical table preimage 反解完整 `TexasPokerTable`。
///
/// 生产 verifier 用它把已经混入 Fiat–Shamir transcript、且 root 校验通过的
/// `pre_image` / `post_image` 还原为业务状态，从而把 action witness 与真实状态绑定。
/// 这不是从 proof-carried witness 取值；输入必须满足 [`table_state_preimage`] 的
/// version/tag/length/chunk 编码契约，任何非 canonical 编码都会被拒绝。
pub fn table_from_state_preimage(
    image: &[Felt],
) -> TexasAirResult<poker_l1::contracts::texas_poker::types::TexasPokerTable> {
    const TAG: &str = "zchain.texas_poker.table.v13";
    let payload = decode_canonical_borsh_preimage(image, TAG)?;
    let table =
        poker_l1::contracts::texas_poker::types::TexasPokerTable::try_from_slice(&payload)
            .map_err(|e| {
                TexasAirError::SerializationError(format!(
                    "TexasPokerTable canonical Borsh decode failed: {e}"
                ))
            })?;
    table.validate_state_schema().map_err(|e| {
        TexasAirError::SerializationError(format!("TexasPokerTable schema validation: {e}"))
    })?;
    Ok(table)
}

/// Compute the ObjectDb-compatible hot-v30 state root.
///
/// The root is the domain-separated BLAKE3 chain digest over the exact hot
/// bytes; its binding to the transcript preimage is carried by a flock
/// proof ([`crate::state_root_binding`]), never by host recomputation on
/// the verification path.
///
/// # Errors
///
/// 当字段编码失败（如 ObjectID 序列化异常）时返回错误。
/// Fixed sentinel preimage for the ObjectDb-absence placeholder table (the
/// hot-v30 codec rejects its empty governance creator, so it cannot be
/// encoded as ordinary hot bytes).  The absence root is still a uniform,
/// provable `BLAKE3(domain || sentinel)` statement.
pub const ABSENT_TABLE_PREIMAGE: &[u8] = b"zchain.texas_poker.absent.v1";

/// Whether `table` is the exact in-memory ObjectDb-absence placeholder that
/// `create_table` proves a transition from.
pub fn is_absent_table(
    table: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
) -> bool {
    use poker_l1::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};
    let absent = TexasPokerTable::new(table.id, EMPTY_PLAYER, 2, 1, 1);
    table == &absent
}

/// Compute the ObjectDb-compatible hot-v30 state root.
///
/// The root is the domain-separated BLAKE3 chain digest over the exact hot
/// bytes (or the fixed absence sentinel); its binding to the transcript
/// preimage is carried by a flock proof ([]),
/// never by host recomputation on the verification path.
///
/// # Errors
///
/// 当字段编码失败（如 ObjectID 序列化异常）时返回错误。
pub fn compute_state_root(
    table: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
) -> TexasAirResult<StateRoot> {
    if is_absent_table(table) {
        return Ok(StateRoot(state_root_digest(ABSENT_TABLE_PREIMAGE)));
    }
    let bytes = hot_table_state_bytes(table)?;
    Ok(StateRoot(state_root_digest(&bytes)))
}

/// Canonical hot-v30 bytes underlying the state-root statement.
///
/// Both the prover (statement construction) and the verifier (deterministic
/// derivation from the transcript-bound preimage) use this exact encoding,
/// so the flock statement's public preimage is never ambiguous.
pub fn hot_table_state_bytes(
    table: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
) -> TexasAirResult<Vec<u8>> {
    poker_l1::contracts::texas_poker::state_codec::encode_hot_table_state(table)
        .map_err(|e| TexasAirError::StateRootError(format!("encode Texas hot table: {e}")))
}

// ===== 内部辅助函数 =====

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// Encode at most 31 bytes injectively into a Starknet field element.
fn byte_chunk_to_field(chunk: &[u8]) -> TexasAirResult<Felt> {
    if chunk.len() > 31 {
        return Err(TexasAirError::StateRootError(format!(
            "canonical chunk length {} exceeds 31 bytes",
            chunk.len()
        )));
    }
    let mut buf = [0u8; 32];
    let start = 32 - chunk.len();
    buf[start..].copy_from_slice(chunk);
    // ≤31 字节恒 < 2^248 < P，from_bytes_be 无失败路径（canonical 恒成立）。
    Ok(Felt::from_bytes_be(&buf))
}

/// Build a domain-separated, injective field preimage for a Borsh value.
pub(crate) fn canonical_borsh_preimage<T: borsh::BorshSerialize>(
    tag: &str,
    value: &T,
) -> TexasAirResult<Vec<Felt>> {
    let bytes = borsh::to_vec(value)
        .map_err(|e| TexasAirError::StateRootError(format!("borsh serialization: {e}")))?;
    canonical_bytes_preimage(tag, &bytes)
}

/// Build a domain-separated, injective field preimage for already-canonical bytes.
fn canonical_bytes_preimage(tag: &str, bytes: &[u8]) -> TexasAirResult<Vec<Felt>> {
    let tag_bytes = tag.as_bytes();
    let mut fields =
        Vec::with_capacity(3 + tag_bytes.len().div_ceil(31) + bytes.len().div_ceil(31));
    fields.push(Felt::from(2u64)); // encoding version
    fields.push(Felt::from(u64::try_from(tag_bytes.len()).map_err(
        |_| TexasAirError::StateRootError("domain tag too long".into()),
    )?));
    for chunk in tag_bytes.chunks(31) {
        fields.push(byte_chunk_to_field(chunk)?);
    }
    fields.push(Felt::from(u64::try_from(bytes.len()).map_err(
        |_| TexasAirError::StateRootError("borsh payload too long".into()),
    )?));
    for chunk in bytes.chunks(31) {
        fields.push(byte_chunk_to_field(chunk)?);
    }
    Ok(fields)
}

/// Decode the injective canonical Borsh field encoding used above.
fn decode_canonical_borsh_preimage(
    fields: &[Felt],
    expected_tag: &str,
) -> TexasAirResult<Vec<u8>> {
    if fields.len() < 4 {
        return Err(TexasAirError::SerializationError(
            "canonical preimage too short".into(),
        ));
    }
    if fields[0] != Felt::from(2u64) {
        return Err(TexasAirError::SerializationError(
            "unsupported canonical preimage version".into(),
        ));
    }

    let tag_len = field_to_usize(fields[1], "domain tag length")?;
    let tag_chunks = tag_len.div_ceil(31);
    let payload_len_index = 2usize
        .checked_add(tag_chunks)
        .ok_or_else(|| TexasAirError::SerializationError("tag chunk count overflow".into()))?;
    if payload_len_index >= fields.len() {
        return Err(TexasAirError::SerializationError(
            "canonical preimage missing payload length".into(),
        ));
    }

    let tag = decode_field_chunks(&fields[2..payload_len_index], tag_len, "domain tag")?;
    if tag.as_slice() != expected_tag.as_bytes() {
        return Err(TexasAirError::SerializationError(
            "canonical preimage domain tag mismatch".into(),
        ));
    }

    let payload_len = field_to_usize(fields[payload_len_index], "payload length")?;
    let payload_chunks = payload_len.div_ceil(31);
    let payload_start = payload_len_index + 1;
    let expected_len = payload_start
        .checked_add(payload_chunks)
        .ok_or_else(|| TexasAirError::SerializationError("payload chunk count overflow".into()))?;
    if fields.len() != expected_len {
        return Err(TexasAirError::SerializationError(format!(
            "canonical preimage field count mismatch: expected {expected_len}, got {}",
            fields.len()
        )));
    }
    decode_field_chunks(&fields[payload_start..], payload_len, "payload")
}

fn field_to_usize(field: Felt, label: &str) -> TexasAirResult<usize> {
    let bytes = field.to_bytes_be();
    if bytes[..24].iter().any(|&b| b != 0) {
        return Err(TexasAirError::SerializationError(format!(
            "canonical {label} does not fit u64"
        )));
    }
    let value = u64::from_be_bytes(bytes[24..].try_into().expect("8-byte suffix"));
    usize::try_from(value).map_err(|_| {
        TexasAirError::SerializationError(format!("canonical {label} does not fit usize"))
    })
}

fn decode_field_chunks(
    fields: &[Felt],
    byte_len: usize,
    label: &str,
) -> TexasAirResult<Vec<u8>> {
    if fields.len() != byte_len.div_ceil(31) {
        return Err(TexasAirError::SerializationError(format!(
            "canonical {label} chunk count mismatch"
        )));
    }
    let mut out = Vec::with_capacity(byte_len);
    for (i, field) in fields.iter().enumerate() {
        let remaining = byte_len - out.len();
        let chunk_len = remaining.min(31);
        let bytes = field.to_bytes_be();
        // `byte_chunk_to_field` right-aligns each chunk. Canonicality also requires
        // every byte outside the declared chunk to remain zero.
        if bytes[..32 - chunk_len].iter().any(|&b| b != 0) {
            return Err(TexasAirError::SerializationError(format!(
                "canonical {label} chunk {i} has non-zero prefix"
            )));
        }
        out.extend_from_slice(&bytes[32 - chunk_len..]);
    }
    Ok(out)
}

/// Interpret a canonical 32-byte big-endian integer as a field element.
/// Out-of-field values are rejected; bytes are never masked or truncated.
#[cfg(test)]
fn bytes_to_field(bytes: &[u8; 32]) -> Option<Felt> {
    felt_from_canonical_bytes(bytes)
}

/// 把 Starknet `Felt` (~251 bit) 分解为 8 个 **大端** u32 字。
///
/// 这是 state_root 绑定的编码契约：把公开输入的 251-bit Fr 元素的 32 字节大端
/// 表示拆为 8 个完整 32-bit 字，供 Fiat-Shamir channel 的 `mix_u32s` mix。
///
/// 编码规则（prover 与 verifier 必须完全一致）：
/// - 取 `Felt` 的 32 字节 **大端** 表示（`to_bytes_be`）。
/// - 按字节顺序每 4 字节一个 u32（大端读取），共 8 个，保持大端顺序。
/// - **不做截断**：`mix_u32s` 将 u32 视为原始 transcript 字节（不解释为域元素），
///   因此完整 32-bit 无损。往返可精确还原原 Felt。
///
/// 返回固定长度 `[u32; 8]`，words[0] 对应最高 4 字节。
#[must_use]
pub fn field_element_to_u32_words(f: Felt) -> [u32; 8] {
    let bytes_be = f.to_bytes_be();
    let mut words = [0u32; 8];
    for (i, word) in words.iter_mut().enumerate() {
        let lo = 4 * i;
        *word = u32::from_be_bytes([
            bytes_be[lo],
            bytes_be[lo + 1],
            bytes_be[lo + 2],
            bytes_be[lo + 3],
        ]);
    }
    words
}

// 生产路径的唯一哈希宿主用户 `poseidon_string`（名字承诺）已随展示名出共识
// 移除；以下两个 helper 目前仅测试交叉核验引用（poseidon_betting_round 等）。
#[cfg(test)]
fn poseidon_hash_many(inputs: &[Felt]) -> Felt {
    starknet_crypto::poseidon_hash_many(inputs)
}

/// 通用「borsh 序列化 → Poseidon」编码契约（带域分隔标签）。
///
/// 把任意 `BorshSerialize` 类型序列化为字节，按 31 字节右对齐分块转 Felt，
/// 最后追加一个记录原始字节长度的 Felt，再做 Poseidon252。
///
/// 这是 state_root 各嵌套子结构（betting_round / deck_state / ... / side_pots）
/// 的统一编码契约。关键性质（soundness 契约）：
/// - **确定性**：borsh 序列化确定，同输入必同输出。
/// - **跨类型抗碰撞（域分隔）**：`tag` 作为哈希输入的**第一个** Felt，
///   确保不同类型即使 borsh 字节完全相同（如默认状态下的全零字节）也产生不同哈希。
///   这是必须的：例如 `ShuffleState::default()` 与 `ReconstructState::default()` 的
///   borsh 序列化恰好都是 10 个零字节，不加域分隔会导致跨字段碰撞。
/// - **同类型抗碰撞**：末尾长度 Felt 防止不同长度字节流产生相同分块序列
///   （例如 `[0x01,0x02]` 与 `[0x01,0x02,0x00]` 在分块后会相同，但长度后缀不同）。
/// - **空输入非零**：空字节也走完整哈希（返回一个固定非零 Felt），
///   以便区分「该子结构为空」与「该字段未编码」（未编码字段仍用 `Felt::ZERO`）。
///
/// `tag` 必须是稳定的、与类型一一对应的 ASCII 字符串（编码契约的一部分，
/// prover 与 L1 两侧必须使用完全相同的 tag）。
#[cfg(test)]
pub(crate) fn poseidon_borsh<T: borsh::BorshSerialize>(tag: &str, value: &T) -> Felt {
    let fields = canonical_borsh_preimage(tag, value)
        .expect("Borsh serialization into an in-memory Vec must succeed");
    poseidon_hash_many(&fields)
}

#[cfg(test)]
fn poseidon_betting_round(br: &BettingRound) -> Felt {
    // current_bet (u64) || min_raise (u64)，borsh 编码后哈希。
    // 注：BettingRound 仅含两个 u64，borsh 序列化为 16 字节定长。
    poseidon_borsh("betting_round", br)
}

#[cfg(test)]
fn poseidon_deck_state(ds: &DeckState) -> Felt {
    // 含加密牌组（ElGamalCiphertext 向量）、EC 点等，统一走 borsh 编码契约。
    poseidon_borsh("deck_state", ds)
}

#[cfg(test)]
fn poseidon_shuffle_state(ss: &ShuffleState) -> Felt {
    poseidon_borsh("shuffle_state", ss)
}

#[cfg(test)]
fn poseidon_reveal_token_state(rs: &RevealTokenState) -> Felt {
    poseidon_borsh("reveal_token_state", rs)
}

#[cfg(test)]
fn poseidon_reconstruct_state(rs: &ReconstructState) -> Felt {
    poseidon_borsh("reconstruct_state", rs)
}

#[cfg(test)]
fn poseidon_timeout_config(tc: &TimeoutConfig) -> Felt {
    poseidon_borsh("timeout_config", tc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support as seat_fixture;

    #[test]
    fn test_field_encoding_basic() {
        assert_eq!(u64_to_field(0), Felt::ZERO);
        assert_eq!(u64_to_field(u64::MAX), Felt::from(u64::MAX));
    }

    #[test]
    fn test_state_root_zero() {
        assert_eq!(StateRoot::zero().bytes(), [0u8; 32]);
    }

    #[test]
    fn test_table_state_preimage_roundtrip() {
        let mut table = poker_l1::contracts::texas_poker::types::TexasPokerTable::new(
            poker_l1::object_model::ObjectID::new([0xAB; 20], 7),
            [0xCD; 20],
            6,
            50,
            100,
        );
        table.hand_id = 9;
        table.call_seq = 17;
        table.call_seq = 23;
        table.pot = 65_537;
        seat_fixture::set_player(&mut table.seats[2], [0x22; 20]);
        seat_fixture::set_stack(&mut table.seats[2], 1_000_000);
        seat_fixture::set_bet(&mut table.seats[2], 65_536);
        table.seats[2].set_status(poker_l1::contracts::texas_poker::types::SeatStatus::Active);

        let image = table_state_preimage(&table).expect("canonical table should encode");
        let decoded = table_from_state_preimage(&image).expect("canonical table should decode");
        assert_eq!(decoded, table);
    }

    #[test]
    fn test_table_state_preimage_rejects_noncanonical_chunk_prefix() {
        const TAG: &str = "zchain.texas_poker.table.v13";
        let table = poker_l1::contracts::texas_poker::types::TexasPokerTable::new(
            poker_l1::object_model::ObjectID::new([0x11; 20], 3),
            [0x33; 20],
            2,
            1,
            2,
        );
        let mut image = table_state_preimage(&table).expect("canonical table should encode");

        // The one-chunk tag is right-aligned. Setting a byte immediately before
        // the declared tag bytes creates a numerically valid field element but
        // a noncanonical chunk encoding, which the decoder must reject.
        assert!(TAG.len() < 31);
        let mut bytes = image[2].to_bytes_be();
        bytes[32 - TAG.len() - 1] = 1;
        image[2] = Felt::from_bytes_be(&bytes);

        assert!(
            table_from_state_preimage(&image).is_err(),
            "non-zero bytes outside the declared chunk must be rejected"
        );
    }

    // ===== 阶段 1：preimage 编码契约测试（soundness 关键）=====
    //
    // 这些测试固化「同输入 → 同输出」与「不同输入 → 不同输出」两条契约，
    // 防止 prover 与 L1 两侧的序列化漂移。任何编码规则变更都必须同步更新此处。

    #[test]
    fn test_poseidon_borsh_deterministic_and_distinct() {
        let br1 = BettingRound {
            current_bet: 100,
            min_raise: 50,
        };
        let br2 = BettingRound {
            current_bet: 100,
            min_raise: 50,
        };
        let br3 = BettingRound {
            current_bet: 101,
            min_raise: 50,
        };
        // 确定性
        assert_eq!(poseidon_betting_round(&br1), poseidon_betting_round(&br2));
        // 区分性：current_bet 不同 → 哈希不同
        assert_ne!(poseidon_betting_round(&br1), poseidon_betting_round(&br3));
        // 非零（区分「已编码」与「未编码 ZERO」）
        assert_ne!(poseidon_betting_round(&br1), Felt::ZERO);
    }

    #[test]
    fn test_poseidon_borsh_tag_domain_separation() {
        // 域分隔契约：不同 tag 即使内容字节完全相同也必须哈希不同。
        // 这防住跨类型碰撞：例如 ShuffleState::default 与 ReconstructState::default
        // 的 borsh 序列化恰好都是 10 个零字节，必须靠 tag 区分。
        let z: [u8; 0] = [];
        let h_a = poseidon_borsh("shuffle_state", &z);
        let h_b = poseidon_borsh("reconstruct_state", &z);
        assert_ne!(h_a, h_b, "不同 tag 必须产生不同哈希（域分隔）");
        assert_ne!(h_a, Felt::ZERO);
        // 同 tag 同内容 → 确定性
        assert_eq!(h_a, poseidon_borsh("shuffle_state", &z));
    }

    #[test]
    fn test_poseidon_borsh_length_suffix_prevents_collision() {
        // 长度后缀契约：[0x01,0x02] 与 [0x01,0x02,0x00] 分块后内容相同（第二块填充零），
        // 但长度后缀不同，故哈希必须不同。
        let h_short = poseidon_borsh("x", &[0x01u8, 0x02]);
        let h_long = poseidon_borsh("x", &[0x01u8, 0x02, 0x00u8]);
        assert_ne!(h_short, h_long, "长度后缀必须防止填充碰撞");
        assert_eq!(h_short, poseidon_borsh("x", &[0x01u8, 0x02]));
    }

    #[test]
    fn test_sub_structure_hashes_distinct() {
        // 各子结构默认（空）状态哈希应互不相同且非零：
        // 它们将被写入 state_root preimage，若彼此相同会导致不同字段不可区分。
        let deck = poseidon_deck_state(&DeckState::default());
        let shuffle = poseidon_shuffle_state(&ShuffleState::default());
        let reveal = poseidon_reveal_token_state(&RevealTokenState {
            purpose: poker_l1::contracts::texas_poker::types::RevealPurpose::DealHole,
            assignments: vec![],
        });
        let reconstruct = poseidon_reconstruct_state(&ReconstructState::default());
        let timeout = poseidon_timeout_config(&TimeoutConfig::default());
        for h in [deck, shuffle, reveal, reconstruct, timeout] {
            assert_ne!(h, Felt::ZERO, "默认子结构哈希应非零");
        }
        // 默认值两两不同（它们 borsh 序列化不同）
        let all = [deck, shuffle, reveal, reconstruct, timeout];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "默认子结构哈希应两两不同 ({i},{j})");
            }
        }
    }

    #[test]
    fn test_field_element_to_u32_words_roundtrip() {
        // 编码契约：8-word 分解必须无损往返还原原 Felt。
        // mix_u32s 把 u32 当原始 transcript 字节，不做域解释，故完整 32-bit 无损。
        let cases = [
            Felt::ZERO,
            Felt::ONE,
            Felt::from(u64::MAX),
            {
                let mut buf = [0u8; 32];
                buf[0] = 0x07;
                buf[1] = 0xFF;
                for b in &mut buf[2..] {
                    *b = 0xAB;
                }
                // 0x07FF… < 0x0800…0001 = P，canonical。
                Felt::from_bytes_be(&buf)
            },
        ];
        for f in cases {
            let words = field_element_to_u32_words(f);
            // 重建：大端 word → 大端字节
            let mut bytes_be = [0u8; 32];
            for (i, word) in words.iter().enumerate() {
                let lo = 4 * i;
                let chunk = word.to_be_bytes();
                bytes_be[lo..lo + 4].copy_from_slice(&chunk);
            }
            let restored = Felt::from_bytes_be(&bytes_be);
            assert_eq!(f, restored, "field_element_to_u32_words 往返失败");
        }
        // 区分性：不同 Felt → 不同 word 序列
        assert_ne!(
            field_element_to_u32_words(Felt::ONE),
            field_element_to_u32_words(Felt::from(2u64)),
        );
    }

    #[test]
    fn test_side_pots_root_encoding() {
        use poker_l1::contracts::texas_poker::side_pot::SidePot;
        // 两个 side_pot 列表，内容不同 → 哈希不同
        let sp1 = vec![SidePot::new(100, 0b0011)];
        let sp2 = vec![SidePot::new(100, 0b0101)];
        let f = |pots: &[SidePot]| -> Felt {
            let mut fields: Vec<Felt> = Vec::new();
            let tag_bytes = b"side_pots";
            let mut tag_buf = [0u8; 32];
            tag_buf[..tag_bytes.len()].copy_from_slice(tag_bytes);
            fields.push(bytes_to_field(&tag_buf).unwrap_or(Felt::ZERO));
            fields.push(u64_to_field(pots.len() as u64));
            fields.extend(pots.iter().flat_map(|sp| {
                [
                    u64_to_field(sp.amount),
                    u64_to_field(u64::from(sp.eligible_seats)),
                ]
            }));
            poseidon_hash_many(&fields)
        };
        assert_ne!(
            f(&sp1),
            f(&sp2),
            "不同 eligible_seats 应产生不同 side_pots_root"
        );
        assert_ne!(f(&sp1), Felt::ZERO);
        // 确定性
        assert_eq!(f(&sp1), f(&sp1));
    }
}
