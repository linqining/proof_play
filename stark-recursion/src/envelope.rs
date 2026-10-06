//! 工件 wire 类型：leaf 输入/折叠树 packed 输出（与 vendored stwo-cairo 2.4.0 的
//! serde 布局逐字段对齐）+ 终证信封（本 crate 协议格式）。
//!
//! # 对齐出处（vendored 侧零修改，只读对齐）
//!
//! - [`SerializedLeafProof`] ↔ third_party/proving crates/leaf_proof_format/src/
//!   lib.rs:50-59：`circuit_preprocessed_root`/`circuit_hash` 为 [`DigestHex`]
//!   （8 个 `{word:#010x}` 小端词，:29-45），`proof` 为 Base64 字符串
//!   （serde_with Base64 → JSON 字符串；本 crate 手写 base64 免新依赖）。
//! - [`LeafProofEnvelope`] ↔ crates/stwo_run_and_prove_recursive_tree/src/
//!   leaf_io.rs:27-36：`#[serde(flatten)]` 把 proof 字段平铺 + `output_preimage`
//!   （十进制 felt 字符串）为顶层键。
//! - [`PackedNode`] ↔ leaf_proof_format/src/lib.rs:73-85：外部 tagged 枚举，
//!   `Composite{circuit_hash:[u32;8], subtasks}` / `Plain{output_preimage}`；
//!   定长数组使错误长度的 circuit_hash 在解析期被拒。
//!
//! # 如实声明
//!
//! 本机无 stwo 2.4 运行时（leaf-prover 需 registry 工件 + 19.4GB 内存），对齐
//! 依据是上述 serde derive 布局的**文档级逐字段复刻** + 本模块手写 fixture 的
//! 解析/序列化测试；未与真实二进制做字节往返。上服务器跑真实链前，应先以一条
//! 真实 leaf 产物做一次互操作冒烟（bench-recursion --backend cli 的第 0 步）。

use anyhow::{Context, Result};
use ark_ff::PrimeField as _;
use serde::{Deserialize, Serialize};

use crate::chain::ROOT_OUTPUT_WORDS;

/// Blake2s 摘要：8 个小端 u32 词，JSON 为 `["0x%010x", …]`
/// （leaf_proof_format/src/lib.rs:16-45 的复刻：`{word:#010x}` 序列化，
/// 解析容忍无 0x 前缀）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestHex(pub [u32; 8]);

impl From<[u8; 32]> for DigestHex {
    fn from(bytes: [u8; 32]) -> Self {
        let mut words = [0u32; 8];
        for (word, src) in words.iter_mut().zip(bytes.chunks_exact(4)) {
            *word = u32::from_le_bytes(src.try_into().expect("4 bytes"));
        }
        DigestHex(words)
    }
}

impl Serialize for DigestHex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // leaf_proof_format/src/lib.rs:29-33 同式
        self.0.map(|word| format!("{word:#010x}")).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DigestHex {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // leaf_proof_format/src/lib.rs:35-45 同式
        let words: [String; 8] = Deserialize::deserialize(deserializer)?;
        let mut digest = [0u32; 8];
        for (out, word) in digest.iter_mut().zip(words) {
            let hex = word.strip_prefix("0x").unwrap_or(&word);
            *out = u32::from_str_radix(hex, 16).map_err(serde::de::Error::custom)?;
        }
        Ok(DigestHex(digest))
    }
}

/// leaf-prover 输出文件（leaf_proof_format/src/lib.rs:50-59 同布局；proof 为
/// Base64 字符串，键名 `proof` 与 vendored `Vec<u8>` + serde_with Base64 的
/// JSON 形态一致）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedLeafProof {
    pub circuit_preprocessed_root: DigestHex,
    pub circuit_hash: DigestHex,
    /// Base64(序列化的电路证明)。
    pub proof: String,
}

/// 递归树的叶输入文件（leaf_io.rs:27-36 同布局：proof 字段 flatten 平铺 +
/// output_preimage 十进制 felt 串）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafProofEnvelope {
    #[serde(flatten)]
    pub proof: SerializedLeafProof,
    /// 叶输出预映像：`[program_hash] ++ concat(K×16 段)`，每个 felt 一个十进制串
    /// （leaf_io.rs:30-35 原文："the task's program hash followed by the task's
    /// raw output, each element a felt encoded as a decimal number"）。
    pub output_preimage: Vec<String>,
}

impl LeafProofEnvelope {
    /// 从 [`crate::chain::BatchPlan`] 构造（mock/测试与打包器共用）。
    #[must_use]
    pub fn from_preimage(
        circuit_hash: [u32; 8],
        circuit_preprocessed_root: [u32; 8],
        proof_base64: impl Into<String>,
        preimage: &[groth16_wrap::felt::Felt252],
    ) -> Self {
        Self {
            proof: SerializedLeafProof {
                circuit_hash: DigestHex(circuit_hash),
                circuit_preprocessed_root: DigestHex(circuit_preprocessed_root),
                proof: proof_base64.into(),
            },
            output_preimage: preimage
                .iter()
                .map(|f| felt_dec(f))
                .collect(),
        }
    }

    /// 叶输出 H1（leaf_io.rs:44-63 精确镜像；解析失败 fail-closed）。
    ///
    /// # Errors
    /// output_preimage 含非法十进制 felt（leaf_io.rs:49-53 同语义：只收十进制，
    /// 非法即 `BadLeafOutputs`）。
    pub fn output_words(&self) -> Result<[u32; ROOT_OUTPUT_WORDS]> {
        let mut preimage = Vec::with_capacity(self.output_preimage.len());
        for s in &self.output_preimage {
            let f = parse_decimal_felt(s)
                .with_context(|| format!("invalid decimal felt {s:?} in output_preimage"))?;
            preimage.push(f);
        }
        crate::chain::leaf_output_words(&preimage)
    }
}

/// felt 素数 p = 2^251 + 17·2^192 + 1 的 32B 大端（canonical 上界检查用）。
const FELT_PRIME_BE: [u8; 32] = [
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

fn parse_decimal_felt(s: &str) -> Result<groth16_wrap::felt::Felt252> {
    let be = num_parse(s)?;
    // 与 vendored Felt::from_dec_str 同 fail-closed：值 ≥ p 非法（拒绝静默 mod 归约）
    anyhow::ensure!(be < FELT_PRIME_BE, "decimal value >= felt prime is non-canonical");
    Ok(groth16_wrap::felt::Felt252::from_be_bytes_mod_order(&be))
}

fn num_parse(s: &str) -> Result<[u8; 32]> {
    // 大整数十进制 → 32B 大端（手写，免大数依赖；felt ≤ 2^251 必然可容纳，
    // 超界高位非零即拒绝）
    anyhow::ensure!(!s.is_empty(), "empty decimal string");
    let digits: Vec<u8> = s.bytes().map(|b| b.wrapping_sub(b'0')).collect();
    anyhow::ensure!(digits.iter().all(|&d| d <= 9), "not a decimal string");
    let mut out = [0u8; 32];
    for &d in &digits {
        // out = out*10 + d（大端 256bit 算术）
        let mut carry = u32::from(d);
        for byte in out.iter_mut().rev() {
            let v = u32::from(*byte) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        anyhow::ensure!(carry == 0, "felt decimal overflow (>= 2^256)");
    }
    Ok(out)
}

fn felt_dec(f: &groth16_wrap::felt::Felt252) -> String {
    // felt252 → 十进制串（经固定 64 位 hex 中转，hex_to_decimal 做基数变换）
    hex_to_decimal(groth16_wrap::felt::felt_to_hex(f).trim_start_matches("0x"))
}

/// 64 位 hex → 十进制（felt_to_hex 的固定 64 位大端 hex 输入）。
fn hex_to_decimal(hex64: &str) -> String {
    let mut digits: Vec<u8> = vec![0]; // 十进制低位在前
    for h in hex64.bytes() {
        let v = (h as char).to_digit(16).expect("hex digit") as u16;
        // digits = digits*16 + v
        let mut carry = u16::from(v);
        for d in digits.iter_mut() {
            let x = u16::from(*d) * 16 + carry;
            *d = (x % 10) as u8;
            carry = x / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    while digits.len() > 1 && *digits.last().unwrap() == 0 {
        digits.pop();
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

/// 折叠树 packed 输出（leaf_proof_format/src/lib.rs:73-85 同布局）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackedNode {
    /// 叶的哈希输出预映像（十进制 felt 串）。
    Plain { output_preimage: Vec<String> },
    /// 验证器节点：双子折叠 / 单子自折叠 / 叶电路单子；携带本节点证明的
    /// circuit_hash（解包器的信任锚）。
    Composite { circuit_hash: [u32; 8], subtasks: Vec<PackedNode> },
}

impl PackedNode {
    /// 叶条目（leaf_proof_format/src/lib.rs:88-95 同形）。
    #[must_use]
    pub fn leaf(circuit_hash: [u32; 8], output_preimage: Vec<String>) -> Self {
        PackedNode::Composite { circuit_hash, subtasks: vec![PackedNode::Plain { output_preimage }] }
    }

    /// 结构校验：叶节点 = 单 Plain 子；折叠节点 = 1（自折叠）或 2（两两）子；
    /// 树深有限（防环由 serde 树结构天然保证）。
    ///
    /// # Errors
    /// 空 subtasks / Plain 出现在非叶位 / 折叠子数 > 2。
    pub fn validate_shape(&self) -> Result<()> {
        match self {
            PackedNode::Plain { .. } => Ok(()),
            PackedNode::Composite { subtasks, .. } => {
                anyhow::ensure!(!subtasks.is_empty(), "composite node needs subtasks");
                anyhow::ensure!(subtasks.len() <= 2, "composite node supports at most 2 subtasks");
                if let [only] = subtasks.as_slice() {
                    anyhow::ensure!(
                        matches!(only, PackedNode::Plain { .. }),
                        "single-subtask composite must wrap a Plain leaf (leaf circuit node)"
                    );
                }
                for t in subtasks {
                    t.validate_shape()?;
                }
                Ok(())
            }
        }
    }

    /// 统计节点数（bench/日志用）。
    #[must_use]
    pub fn count(&self) -> usize {
        match self {
            PackedNode::Plain { .. } => 1,
            PackedNode::Composite { subtasks, .. } => {
                1 + subtasks.iter().map(PackedNode::count).sum::<usize>()
            }
        }
    }
}

/// 终证信封（本 crate 协议格式，`root_envelope.v1`）—— **Groth16 对照基线**
/// （2026-09-29 裁定：Groth16 出终证路径；主链提交信封 =
/// [`crate::stark_final::FinalEnvelope`]）。终证 → 上链形态的完整
/// 载荷——语句、公开输入、包裹证明、packed 树与逐手对账记录。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RootEnvelope {
    /// 格式版本（当前恒 1）。
    pub protocol_version: u32,
    /// 终证腿 cairo 电路验证器程序哈希（0x 64hex）。
    pub aggregator_program_hash: String,
    /// 折叠树根公开输出（8×u32 LE 词）。
    pub root_output_words: [u32; ROOT_OUTPUT_WORDS],
    /// keccak 批根（0x 64hex；L1Inbox 锚与 SettleBatch 重算的同一根）。
    pub keccak_batch_root: String,
    /// 累加链接入 acc_prev（0x 64hex；首批 = 0x0…0）。
    pub acc_prev: String,
    /// 本批 fact（0x 64hex；= 累加链接出 acc）。
    pub batch_fact: String,
    /// Groth16 公开输入（5×0x 64hex，顺序 = root_circuit publics）。
    pub statement_publics: [String; 5],
    /// 折叠树 packed 输出（fact-verify `--aggregated` 逐节点重算的输入）。
    pub packed_tree: PackedNode,
    /// 逐手对账记录（binding → fact；与链上 settledFact/batchFactOf 对照）。
    pub hands: Vec<HandRecord>,
    /// Groth16 包裹证明（calldata 字序 b_evm；未出证 = None）。
    pub wrap: Option<WrapSection>,
}

/// 逐手对账记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandRecord {
    /// hand_binding（0x 64hex，= 段槽位 5）。
    pub hand_binding: String,
    /// fact（0x 64hex）。
    pub fact: String,
}

/// 包裹证明节（公开输入单独在 [`RootEnvelope::statement_publics`]）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapSection {
    pub proof: crate::ProofJson,
}

/// PartialEq 经规范 JSON 比较（groth16-wrap 的 ProofJson 未实现 PartialEq，
/// 本 crate 不改它——最小侵入）。
impl PartialEq for WrapSection {
    fn eq(&self, other: &Self) -> bool {
        serde_json::to_string(&self.proof).ok() == serde_json::to_string(&other.proof).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 vendored serde 布局对齐的手写 fixture（leaf_io.rs:27-36 平铺键 +
    /// Base64 + DigestHex `{word:#010x}` 数组）。
    const LEAF_JSON: &str = r#"{
        "circuit_preprocessed_root": ["0x00000000","0x00000001","0x00000002","0x00000003","0x00000004","0x00000005","0x00000006","0x00000007"],
        "circuit_hash": ["0x0000000a","0x0000000b","0x0000000c","0x0000000d","0x0000000e","0x0000000f","0x00000010","0x00000011"],
        "proof": "QUJD",
        "output_preimage": ["3618502788666131213697322783095070105623107215331596699973092056135872020480", "11"]
    }"#;

    /// 手写 fixture 解析 + 序列化回写布局不变（键平铺、词格式、Base64 原样）。
    #[test]
    fn leaf_input_json_layout_matches_vendored() {
        let env: LeafProofEnvelope = serde_json::from_str(LEAF_JSON).expect("fixture must parse");
        assert_eq!(env.proof.proof, "QUJD");
        assert_eq!(env.proof.circuit_hash.0[0], 0x0a);
        assert_eq!(env.proof.circuit_preprocessed_root.0[7], 7);
        assert_eq!(env.output_preimage.len(), 2);
        // 序列化回写：仍是平铺键（flatten 生效）+ 同一词格式
        let back = serde_json::to_string(&env).unwrap();
        assert!(back.contains(r#""circuit_preprocessed_root":["0x00000000""#), "layout: {back}");
        assert!(back.contains(r#""proof":"QUJD""#));
        assert!(back.contains(r#""output_preimage":"#));
        assert!(!back.contains(r#""proof":{"#), "proof 字段必须平铺而非嵌套");
        // 解析出的 preimage 第一位 = felt 素数（fixture 手工校验十进制解析）
        let words = env.output_words().unwrap();
        assert_eq!(words.len(), 8);
    }

    /// from_preimage → output_words 的确定性 + 与 chain 层直算一致；
    /// 十进制序列化抽查已知小值（255 → "255"）。
    #[test]
    fn leaf_envelope_output_matches_chain_mirror() {
        use groth16_wrap::felt::{felt_from_hex, Felt252};
        let ph = felt_from_hex(
            "0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4",
        )
        .unwrap();
        let seg = vec![Felt252::from(15u64), Felt252::from(0x5350324d5f4f4bu64), Felt252::from(255u64)];
        let mut preimage = vec![ph];
        preimage.extend_from_slice(&seg);
        let direct = crate::chain::leaf_output_words(&preimage).unwrap();
        let env = LeafProofEnvelope::from_preimage([9; 8], [8; 8], "AA==", &preimage);
        assert_eq!(env.output_words().unwrap(), direct);
        // 十进制串确为预映像的十进制（已知小值抽查 + 全串可解析回原值）
        assert_eq!(env.output_preimage[3], "255", "preimage[3] = seg[2] = 255");
        for (s, f) in env.output_preimage.iter().zip(preimage.iter()) {
            let back = groth16_wrap::felt::Felt252::from_be_bytes_mod_order(&num_parse(s).unwrap());
            assert_eq!(back, *f, "十进制串必须可逆解析回原 felt");
        }
    }

    /// 非法十进制 / 超 2^256 → fail-closed。
    #[test]
    fn leaf_envelope_rejects_bad_preimage() {
        let env = LeafProofEnvelope {
            proof: SerializedLeafProof {
                circuit_hash: DigestHex([0; 8]),
                circuit_preprocessed_root: DigestHex([0; 8]),
                proof: String::new(),
            },
            output_preimage: vec!["12ab".into()],
        };
        assert!(env.output_words().is_err());
        let env2 = LeafProofEnvelope {
            proof: env.proof.clone(),
            output_preimage: vec!["1".repeat(90)],
        };
        assert!(env2.output_words().is_err(), "超界十进制必须拒绝");
    }

    /// PackedNode 往返 + 错误长度 circuit_hash 解析期拒绝（vendored 测试同款，
    /// leaf_proof_format/src/lib.rs:113-141）。
    #[test]
    fn packed_node_round_trips_and_rejects_bad_hash() {
        let leaf = PackedNode::leaf([1, 2, 3, 4, 5, 6, 7, 8], vec!["11".to_string()]);
        let tree = PackedNode::Composite {
            circuit_hash: [9; 8],
            subtasks: vec![leaf.clone(), leaf],
        };
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&tree).unwrap()).unwrap();
        assert_eq!(json["Composite"]["circuit_hash"][0], 9);
        assert_eq!(
            json["Composite"]["subtasks"][0]["Composite"]["subtasks"][0]["Plain"]["output_preimage"][0],
            "11"
        );
        assert_eq!(serde_json::from_value::<PackedNode>(json).unwrap(), tree);
        assert_eq!(tree.count(), 5);

        let bad = r#"{"Composite":{"circuit_hash":[1,2,3],"subtasks":[]}}"#;
        assert!(serde_json::from_str::<PackedNode>(bad).is_err(), "错误长度 hash 必须解析期拒绝");
        assert!(tree.validate_shape().is_ok());
        let empty = r#"{"Composite":{"circuit_hash":[1,2,3,4,5,6,7,8],"subtasks":[]}}"#;
        assert!(serde_json::from_str::<PackedNode>(empty).unwrap().validate_shape().is_err());
        // 三子折叠拒绝
        let three = PackedNode::Composite {
            circuit_hash: [1; 8],
            subtasks: vec![
                PackedNode::Plain { output_preimage: vec![] },
                PackedNode::Plain { output_preimage: vec![] },
                PackedNode::Plain { output_preimage: vec![] },
            ],
        };
        assert!(three.validate_shape().is_err());
    }

    /// RootEnvelope serde 往返无损。
    #[test]
    fn root_envelope_roundtrip() {
        let env = RootEnvelope {
            protocol_version: 1,
            aggregator_program_hash: format!("0x{:064x}", 0xabcd),
            root_output_words: [1, 2, 3, 4, 5, 6, 7, 8],
            keccak_batch_root: format!("0x{:064x}", 0x1234),
            acc_prev: format!("0x{:064x}", 0),
            batch_fact: format!("0x{:064x}", 0x5678),
            statement_publics: [
                format!("0x{:064x}", 1),
                format!("0x{:064x}", 2),
                format!("0x{:064x}", 3),
                format!("0x{:064x}", 4),
                format!("0x{:064x}", 5),
            ],
            packed_tree: PackedNode::leaf([7; 8], vec!["42".to_string()]),
            hands: vec![HandRecord {
                hand_binding: format!("0x{:064x}", 0xa6aa),
                fact: format!("0x{:064x}", 0x0306),
            }],
            wrap: None,
        };
        let s = serde_json::to_string(&env).unwrap();
        assert_eq!(serde_json::from_str::<RootEnvelope>(&s).unwrap(), env);
    }
}
