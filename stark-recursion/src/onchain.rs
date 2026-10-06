//! 终证 → Monad 上链形态：公开输入导出 + calldata/ABI 编码。
//!
//! # 主链通道（2026-09-29 裁定：终证路径无 Groth16）
//!
//! `submitFinalProof(bytes32 keccakRoot, bytes32 accPrev, bytes32 batchFact,
//! bytes32 outputCommit, bytes proof)` —— 直接提交 Monad **STARK 验证合约**
//! （zchain contracts/monad/src/StarkVerifier.sol，固定参数 cairo-air 验证器；
//! FRI 核心为二期交付，合约骨架 fail-closed）。语句字段与
//! [`crate::stark_final`] 的公开输出逐位对应：
//! - `keccakRoot`：L1Inbox 锚定的批根（SettleBatch 同式重算）；
//! - `accPrev`：累加链接入（= 合约 latestFact；首批 0）；
//! - `batchFact`：电路内 poseidon 链接值（公开输出尾字）；
//! - `outputCommit`：全部公开输出的 keccak 承诺（[`output_commit`]）；
//! - `proof`：STARK 证明序列化字节（bincode+bz2 wire，fact-verify 同格式）。
//!
//! 本模块钉死 **ABI 提案 + 金字节**，部署时以 zchain 合约实际签名/字节
//! 级对照（forge 金向量测试同口径）。
//!
//! # 对照基线通道（Groth16；feature `groth16-baseline` 的电路产出）
//!
//! - `settleRoot(bytes32,(uint256[2],uint256[2][2],uint256[2]),uint256[5])`
//!   —— 终证语句 5 公开输入的演进版提案（对照基线，不在主链路线）。
//! - `SettleBatch.settleBatch(bytes32,(uint256[2],uint256[2][2],uint256[2])[],
//!   uint256[][])`（zchain contracts/monad/src/SettleBatch.sol:80-84 在盘核验）
//!   —— 已上链的逐手批量通道（0xc6f134ef… SettleWrap 同代基线）。
//!
//! # 字序（实测钉死的 EVM 口径）
//!
//! B 点 calldata 用 **b_evm**（Fp2 虚部在前；groth16-wrap/src/lib.rs:125-129
//! 注释 + anvil/Monad eth_call 实测裁决，report §7.4）；本模块直接消费
//! [`groth16_wrap::ProofJson::b_evm`]，不重排。
//!
//! # 内存/复杂度
//!
//! 纯宿主字节拼装，O(calldata) 内存（最大 ~KB 级），无密码学重活。

use anyhow::{Context, Result, anyhow};
use groth16_wrap::felt::{felt_to_be_bytes, fr_to_hex, Felt252, Fr};
use groth16_wrap::ProofJson;
use sha3::{Digest, Keccak256};

/// `submitFinalProof(bytes32,bytes32,bytes32,bytes32,bytes)` 的 selector
/// （主链 STARK 验证合约提案 ABI；部署前以 zchain StarkVerifier.sol 实际签名复核）。
#[must_use]
pub fn submit_final_proof_selector() -> [u8; 4] {
    selector_of("submitFinalProof(bytes32,bytes32,bytes32,bytes32,bytes)")
}

/// ABI 签名 → 4B selector（keccak 前 4 字节；测试金向量锚点）。
fn selector_of(sig: &str) -> [u8; 4] {
    let h: [u8; 32] = Keccak256::digest(sig.as_bytes()).into();
    [h[0], h[1], h[2], h[3]]
}

/// 全部公开输出的 keccak 承诺：逐 felt 32B 大端顺次拼接后 keccak256。
///
/// 链上 `outputCommit` ↔ 链下证明公开内存的一一对应（验证器从证明公开段
/// 还原 output 后重算同式对拍）。
#[must_use]
pub fn output_commit(output: &[Felt252]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for f in output {
        h.update(felt_to_be_bytes(f));
    }
    h.finalize().into()
}

/// 主链通道 `submitFinalProof` calldata：
/// `selector ‖ 4×bytes32（head 内联）‖ offset(proof) ‖ len(proof) ‖ proof 字节`。
///
/// head = selector + 4 个 32B 字参数 + 1 个偏移字 = 5×32 + 4 = 164B 起；
/// proof 为动态 `bytes`（偏移相对参数区起点 = selector 之后，Solidity ABI 同口径）。
///
/// # Errors
/// proof 为空（空证明不可提交——fail-closed）。
pub fn encode_submit_final_calldata(
    keccak_root: &[u8; 32],
    acc_prev: &Felt252,
    batch_fact: &Felt252,
    o_commit: &[u8; 32],
    proof: &[u8],
) -> Result<Vec<u8>> {
    anyhow::ensure!(!proof.is_empty(), "empty STARK proof（fail-closed）");
    let mut out = Vec::with_capacity(164 + 32 + proof.len());
    out.extend_from_slice(&submit_final_proof_selector());
    out.extend_from_slice(keccak_root);
    out.extend_from_slice(&felt_to_be_bytes(acc_prev));
    out.extend_from_slice(&felt_to_be_bytes(batch_fact));
    out.extend_from_slice(o_commit);
    // offset(proof)：相对参数区起点（selector 之后）= 5 头字 ×32
    let offset = 5u64 * 32;
    out.extend_from_slice(&word(&(offset).to_be_bytes_32()));
    out.extend_from_slice(&word(&(proof.len() as u64).to_be_bytes_32()));
    out.extend_from_slice(proof);
    Ok(out)
}

/// `settleRoot(bytes32,(uint256[2],uint256[2][2],uint256[2]),uint256[5])` 的
/// selector（Groth16 对照基线的演进版提案 ABI；部署前以 zchain 合约实际签名复核）。
///
/// # Errors
/// 不失败（静态签名）。
pub fn settle_root_selector() -> [u8; 4] {
    selector_of("settleRoot(bytes32,(uint256[2],uint256[2][2],uint256[2]),uint256[5])")
}

/// `settleBatch(bytes32,(uint256[2],uint256[2][2],uint256[2])[],uint256[][])` 的
/// selector（已上链 SettleBatch.sol:80 的真实签名）。
#[must_use]
pub fn settle_batch_selector() -> [u8; 4] {
    selector_of("settleBatch(bytes32,(uint256[2],uint256[2][2],uint256[2])[],uint256[][])")
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let t = s.strip_prefix("0x").unwrap_or(s);
    anyhow::ensure!(t.len() <= 64, "{what} hex too long");
    let bytes = hex::decode(format!("{t:0>64}")).with_context(|| format!("bad {what} hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn word(b: &[u8; 32]) -> Vec<u8> {
    b.to_vec()
}

/// 校验 5 个公开输入的 hex 形态（0x 可选、≤64 位、齐零填充到 32B）。
fn pub_word(s: &str) -> Result<Vec<u8>> {
    Ok(word(&parse_hex32(s, "public input")?))
}

/// 演进版 `settleRoot` calldata：
/// `selector ‖ bytes32 root ‖ proof{a(2),b(4),c(2)} ‖ publics(5)` —— 全静态类型，
/// head 内联，总长 = 4 + 32 + 8×32 + 5×32 = **452 B**。
///
/// # Errors
/// proof 坐标 / publics hex 非法。
pub fn encode_settle_root_calldata(
    keccak_root: &[u8; 32],
    proof: &ProofJson,
    publics: &[String; 5],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(452);
    out.extend_from_slice(&settle_root_selector());
    out.extend_from_slice(keccak_root);
    for coord in &proof.a {
        out.extend_from_slice(&pub_word(coord)?);
    }
    for pair in &proof.b_evm {
        for coord in pair {
            out.extend_from_slice(&pub_word(coord)?);
        }
    }
    for coord in &proof.c {
        out.extend_from_slice(&pub_word(coord)?);
    }
    anyhow::ensure!(publics.len() == 5, "root statement needs exactly 5 publics");
    for p in publics {
        out.extend_from_slice(&pub_word(p)?);
    }
    anyhow::ensure!(out.len() == 452, "settleRoot calldata must be 452 bytes, got {}", out.len());
    Ok(out)
}

/// 回退通道 `SettleBatch.settleBatch` calldata（SettleBatch.sol:80-133 落位）：
/// `selector ‖ bytes32 root ‖ offset(proofs) ‖ offset(pubLists) ‖ [proofs 尾]
/// ‖ [pubLists 尾]`。proofs = 静态 struct 数组（每元素 8 词内联）；pubLists =
/// uint256[][]（内层数组带偏移）。
///
/// # Errors
/// proof 坐标 / publics hex 非法；pubs[j].length != 2n+1 或跨证明 program_hash
/// 不一致（SettleBatch.sol:92-93 同政策，编码前先拒）。
pub fn encode_settle_batch_calldata(
    keccak_root: &[u8; 32],
    proofs: &[ProofJson],
    pub_lists: &[Vec<String>],
) -> Result<Vec<u8>> {
    anyhow::ensure!(!proofs.is_empty(), "no proofs");
    anyhow::ensure!(pub_lists.len() == proofs.len(), "pubLists/proofs length mismatch");
    // 跨证明 program_hash 一致 + 每证明 2n+1 条（SettleBatch.sol:92-93 同政策）
    let ph = parse_hex32(pub_lists.first().ok_or_else(|| anyhow!("empty pubLists"))?.first().ok_or_else(|| anyhow!("empty pub head"))?, "program_hash")?;
    for (j, list) in pub_lists.iter().enumerate() {
        anyhow::ensure!(!list.is_empty() && (list.len() - 1) % 2 == 0, "pubLists[{j}] must be 1+2n");
        let n = (list.len() - 1) / 2;
        anyhow::ensure!(n > 0 && n.is_power_of_two(), "pubLists[{j}] batchN must be 2^k (got {n})");
        anyhow::ensure!(
            parse_hex32(&list[0], "program_hash")? == ph,
            "pubLists[{j}] program_hash mismatch"
        );
    }

    // head：selector + root + 2 偏移（偏移相对参数区起点 = selector 之后）
    let mut out = Vec::new();
    out.extend_from_slice(&settle_batch_selector());
    out.extend_from_slice(keccak_root);
    let head_words = 3u64; // root + 2 offsets
    let proofs_area_words = 1u64 + (proofs.len() as u64) * 8; // count + 每证明 8 词内联
    let offset_proofs = head_words * 32;
    let offset_publists = (head_words + proofs_area_words) * 32;
    out.extend_from_slice(&word(&(offset_proofs as u64).to_be_bytes_32()));
    out.extend_from_slice(&word(&(offset_publists as u64).to_be_bytes_32()));

    // proofs 尾：count + 每证明 {a0,a1, b00,b01,b10,b11, c0,c1}（b 用 b_evm 字序）
    out.extend_from_slice(&word(&(proofs.len() as u64).to_be_bytes_32()));
    for proof in proofs {
        for coord in &proof.a {
            out.extend_from_slice(&pub_word(coord)?);
        }
        for pair in &proof.b_evm {
            for coord in pair {
                out.extend_from_slice(&pub_word(coord)?);
            }
        }
        for coord in &proof.c {
            out.extend_from_slice(&pub_word(coord)?);
        }
    }

    // pubLists 尾：count + 每内层偏移 + 各内层 {len, words…}
    let mut tail = Vec::new();
    tail.extend_from_slice(&word(&(pub_lists.len() as u64).to_be_bytes_32()));
    // 内层偏移：相对 pubLists 区起点；第 j 个内层数组头 = 32*(1 + 前面内层个数)
    let mut cursor = 1u64 + pub_lists.len() as u64;
    let mut inner_areas = Vec::with_capacity(pub_lists.len());
    for list in pub_lists {
        tail.extend_from_slice(&word(&(cursor * 32).to_be_bytes_32()));
        let mut area = Vec::new();
        area.extend_from_slice(&word(&(list.len() as u64).to_be_bytes_32()));
        for p in list {
            area.extend_from_slice(&pub_word(p)?);
        }
        cursor += (area.len() / 32) as u64;
        inner_areas.push(area);
    }
    for area in inner_areas {
        tail.extend_from_slice(&area);
    }
    out.extend_from_slice(&tail);
    Ok(out)
}

/// Fr 公开输入 → 0x 64hex（打包 publics 用）。
#[must_use]
pub fn fr_publics_to_hex(publics: &[Fr]) -> Vec<String> {
    publics.iter().map(fr_to_hex).collect()
}

trait ToBeBytes32 {
    fn to_be_bytes_32(self) -> [u8; 32];
}

impl ToBeBytes32 for u64 {
    fn to_be_bytes_32(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&self.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use groth16_wrap::felt::{felt_from_hex, felt_to_hex, fr_from_hex};

    /// submitFinalProof（主链 STARK 通道）：selector 金向量、head 落位、
    /// 动态 bytes 偏移/长度、承诺逐字回读。
    #[test]
    fn submit_final_calldata_layout() {
        let sel = submit_final_proof_selector();
        let expect_sel: [u8; 32] =
            Keccak256::digest(b"submitFinalProof(bytes32,bytes32,bytes32,bytes32,bytes)").into();
        assert_eq!(sel, expect_sel[0..4], "selector 与签名 keccak 一致");

        let root = std::array::from_fn(|i| (i * 5 + 1) as u8);
        let acc = felt_from_hex("0xacc1").unwrap();
        let fact = felt_from_hex("0x4c1f").unwrap();
        let commit: [u8; 32] = std::array::from_fn(|i| (i * 3) as u8);
        let proof = vec![0xABu8; 100];
        let cd = encode_submit_final_calldata(&root, &acc, &fact, &commit, &proof).unwrap();
        // head：selector(4) + 4×32 参数 + 32 偏移 = 164；尾：32 长度 + 100 数据
        assert_eq!(cd.len(), 4 + 4 * 32 + 32 + 32 + 100);
        assert_eq!(&cd[0..4], &sel);
        assert_eq!(&cd[4..36], &root);
        assert_eq!(&cd[36..68], &felt_to_be_bytes(&acc));
        assert_eq!(&cd[68..100], &felt_to_be_bytes(&fact));
        assert_eq!(&cd[100..132], &commit);
        // 偏移 = 5×32 = 160，相对参数区起点（selector 后）；字域 [132..164]
        assert_eq!(u64::from_be_bytes(cd[156..164].try_into().unwrap()), 160);
        // 长度字 [164..196] = 100；proof 数据 [196..296]
        assert_eq!(u64::from_be_bytes(cd[188..196].try_into().unwrap()), 100);
        assert_eq!(&cd[196..296], &vec![0xABu8; 100][..]);

        // 空 proof 拒绝（fail-closed）
        assert!(encode_submit_final_calldata(&root, &acc, &fact, &commit, &[]).is_err());

        // 金字节 fixture（--nocapture 打印；zchain StarkVerifier.t.sol 钉同一向量，
        // Rust↔Solidity ABI 交叉钉扎）
        let proof_fixture = vec![0x5Au8; 64];
        let cd2 = encode_submit_final_calldata(&root, &acc, &fact, &commit, &proof_fixture).unwrap();
        println!("GOLDEN_FINAL_CALLDATA={}", hex::encode(&cd2));
    }

    /// output_commit：确定性 + 逐 felt 敏感（32B 大端拼接口径）。
    #[test]
    fn output_commit_is_deterministic_and_sensitive() {
        let o1 = vec![felt_from_hex("0x1").unwrap(), felt_from_hex("0x2").unwrap()];
        let o2 = vec![felt_from_hex("0x1").unwrap(), felt_from_hex("0x3").unwrap()];
        let c1 = output_commit(&o1);
        assert_eq!(c1, output_commit(&o1), "确定性");
        assert_ne!(c1, output_commit(&o2), "逐 felt 敏感");
        // 独立重算（同口径内联）
        let mut h = Keccak256::new();
        h.update(felt_to_be_bytes(&o1[0]));
        h.update(felt_to_be_bytes(&o1[1]));
        let direct: [u8; 32] = h.finalize().into();
        assert_eq!(c1, direct);
        let _ = felt_to_hex(&o1[0]);
    }

    fn dummy_proof() -> ProofJson {
        let w = |i: u64| format!("0x{:064x}", i);
        ProofJson {
            a: [w(1), w(2)],
            b: [
                [w(3), w(4)],
                [w(5), w(6)],
            ],
            b_evm: [
                [w(4), w(3)],
                [w(6), w(5)],
            ],
            c: [w(7), w(8)],
        }
    }

    /// settleRoot：selector 与签名 keccak 一致、总长 452、字段落位
    /// （root/proof/publics 逐字回读）。
    #[test]
    fn settle_root_calldata_layout() {
        let sel = settle_root_selector();
        let expect_sel: [u8; 32] = Keccak256::digest(
            b"settleRoot(bytes32,(uint256[2],uint256[2][2],uint256[2]),uint256[5])",
        )
        .into();
        assert_eq!(sel, expect_sel[0..4]);

        let root = std::array::from_fn(|i| (i * 3 + 1) as u8);
        let publics = [
            format!("0x{:064x}", 0x11),
            format!("0x{:064x}", 0),
            format!("0x{:064x}", 0x22),
            format!("0x{:064x}", 0x33),
            format!("0x{:064x}", 0x44),
        ];
        let cd = encode_settle_root_calldata(&root, &dummy_proof(), &publics).unwrap();
        assert_eq!(cd.len(), 452);
        assert_eq!(&cd[0..4], &sel);
        assert_eq!(&cd[4..36], &root);
        // proof a
        assert_eq!(&cd[36..68], &parse_hex32("0x01", "a0").unwrap());
        assert_eq!(&cd[68..100], &parse_hex32("0x02", "a1").unwrap());
        // b_evm 字序（虚部在前）：第一个词是 4 不是 3
        assert_eq!(&cd[100..132], &parse_hex32("0x04", "b00").unwrap());
        assert_eq!(&cd[132..164], &parse_hex32("0x03", "b01").unwrap());
        // publics 尾 5 词
        assert_eq!(&cd[292..324], &parse_hex32("0x11", "p0").unwrap());
        assert_eq!(&cd[324..356], &parse_hex32("0x00", "p1").unwrap());
        assert_eq!(&cd[420..452], &parse_hex32("0x44", "p4").unwrap());
        // 非法 hex publics 拒绝
        let bad_pubs = [String::new(), "zz".into(), String::new(), String::new(), String::new()];
        assert!(encode_settle_root_calldata(&root, &dummy_proof(), &bad_pubs).is_err());
    }

    /// settleBatch（回退通道）：偏移落位可解序回读、内层偏移相对区起点、
    /// program_hash 不一致编码期拒绝。
    #[test]
    fn settle_batch_calldata_layout() {
        let root = [0xaau8; 32];
        let proofs = vec![dummy_proof(), dummy_proof()];
        let mk_pubs = |ph: u64, k: usize| -> Vec<String> {
            let mut v = vec![format!("0x{:064x}", ph)];
            for i in 0..2 * k {
                v.push(format!("0x{:064x}", i + 1));
            }
            v
        };
        let pub_lists = vec![mk_pubs(0x77, 2), mk_pubs(0x77, 2)];
        let cd = encode_settle_batch_calldata(&root, &proofs, &pub_lists).unwrap();

        // 解序：selector + root + offset_proofs + offset_publists（word 取 32B 尾 8B）
        fn word_u64(cd: &[u8], at: usize) -> u64 {
            u64::from_be_bytes(cd[at + 24..at + 32].try_into().unwrap())
        }
        assert_eq!(&cd[0..4], &settle_batch_selector());
        assert_eq!(&cd[4..36], &root);
        // 偏移值相对参数区起点（selector 之后，即字节 4）——Solidity ABI 解码同口径
        let off_proofs = 4 + word_u64(&cd, 36) as usize;
        let off_publists = 4 + word_u64(&cd, 68) as usize;
        assert_eq!(off_proofs, 4 + 96);
        // proofs 区 = count(1) + 2×8 词
        assert_eq!(off_publists, 4 + 96 + (1 + 16) * 32);
        assert_eq!(word_u64(&cd, off_proofs), 2, "proof count");
        // pubLists 区：count + 内层偏移（相对区起点）+ 内层内容
        assert_eq!(word_u64(&cd, off_publists), 2, "pubLists count");
        let inner0 = word_u64(&cd, off_publists + 32) as usize;
        assert_eq!(inner0, 3 * 32, "第一个内层偏移 = count 词 + 2 偏移词");
        let inner0_abs = off_publists + inner0;
        assert_eq!(word_u64(&cd, inner0_abs), 5, "内层长度 = 1 + 2n = 5");
        // 总长一致性：尾区之后无字节
        assert_eq!(cd.len(), off_publists + 32 * (1 + 2) + 2 * (32 * 6));
        // program_hash 不一致拒绝
        let bad = vec![mk_pubs(0x77, 2), mk_pubs(0x88, 2)];
        assert!(encode_settle_batch_calldata(&root, &proofs, &bad).is_err());
        // batchN 非 2 的幂拒绝
        let bad2 = vec![mk_pubs(0x77, 3)];
        assert!(encode_settle_batch_calldata(&root, &proofs[..1], &bad2).is_err());
    }

    /// fr_publics_to_hex 形态（0x + 64 hex）。
    #[test]
    fn fr_publics_hex() {
        let f = fr_from_hex("0xa6aa").unwrap();
        let hexes = fr_publics_to_hex(&[f]);
        assert_eq!(hexes[0], format!("0x{:0>64}", "a6aa"));
        let _ = felt_from_hex("0x1").unwrap();
    }
}
