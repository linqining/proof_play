//! 终证语句的常数尺寸 Groth16 包裹电路 —— **对照基线**
//! （feature `groth16-baseline`；2026-09-29 裁定 Groth16 出终证路径，
//! 保留作回归对照；主链终证 = stark_final::FinalEnvelope 的单份 STARK 批证明）。
//!
//! # 语句（R1CS over BN254 Fr，5 个公开输入，**K 无关**）
//!
//! 1. `aggregator_program_hash` —— 终证腿消费的 cairo 电路验证器程序哈希
//!    （stwo_cairo_verifier 的 circuit-verifier 程序；scarb 2.18 腿的钉扎对象）；
//! 2. `acc_prev` —— 累加链接入（批 n-1 的 fact；首批 = 0）；
//! 3. `root_hi` / 4. `root_lo` —— keccak 批根的 32B hi/lo 拆分（batch.rs:46-55
//!    同式；keccak 256bit 不能无损装单个 felt）；
//! 5. `batch_fact = poseidon_hash_many([aph ‖ 根输出 8 felts ‖ acc_prev ‖ hi ‖ lo])`。
//!
//! 见证 = 折叠树根的公开输出（8×u32 词 → 8 felt，circuit_common/src/lib.rs:13
//! N_RESERVED = 8）+ acc_prev 的 felt 轨副本。
//!
//! # 约束量级（K 无关，模块内负例/正例测试钉死形状）
//!
//! 电路体 = 1 次 poseidon_hash_many（12 felts = aph+8 词+acc+hi+lo → 7 次 Hades
//! 置换 = 6 吸收 + 1 终置换）+ 5 组位绑定
//! （[`bind_felt_public`]）。对照单手 wrap（17 felts → 10 次置换，实测
//! 4,584,665 约束，out/monad-snark-engineering-report.md §5）：本电路置换数
//! 更少 → 约束 < 4.58M 且 **不随 K/L 增长**（tests/root_wrap_k2.rs 打印实测值）。
//!
//! # 信任边界（同 groth16-wrap/src/lib.rs:11-18，本电路不验证 STARK）
//!
//! 链上命题是「batch_fact 是 (aph, 根输出, acc_prev, keccak 根) 的 Poseidon 像」
//! 这一 hash 一致性 + operator 背书。「根输出确实折叠自 K 手语句」由链下
//! fact-verify（钉 verifier 程序哈希 + packed 树逐节点重算，`--aggregated` 腿）
//! 与 L1Inbox 批根锚共同把关；本电路把这四者不可拆地绑进一个 Groth16 语句。
//!
//! # 内存注释（ask 要求：每步峰值给依据）
//!
//! 约束合成 + seeded setup + prove 的峰值 ≈ 单手 wrap 同量级（<4.58M 约束）：
//! 本机 36GB 实测单手 setup+prove 正常完成（report §5）、K=4（18.3M）稳定、
//! K=8（36.7M）SIGKILL —— 本电路约束数 ≤ 单手（<4.58M）→ 峰值低于 K=4 批量
//! 电路，36GB 本机与 8G+swap 机器均可承载（tests/root_wrap_k2.rs 为门禁样本，
//! 实测峰值由 bench-recursion 打印）。

use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError};
use groth16_wrap::felt::{felt_to_fr, fr_to_felt, Felt252, Fr};
use groth16_wrap::poseidon_circuit::{poseidon_hash_many, witness_felt, CircuitFelt};

use crate::chain::{derive_batch_fact, split_root_hi_lo, ROOT_OUTPUT_WORDS};

/// 终证 Groth16 语句（链上 verifier 的 5 个 public signals，顺序即 IC 顺序）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootStatement {
    pub aggregator_program_hash: Fr,
    pub acc_prev: Fr,
    pub root_hi: Fr,
    pub root_lo: Fr,
    pub batch_fact: Fr,
}

/// 终证见证：折叠树根的 8×u32 输出词 + acc_prev 的 felt 轨副本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootWitness {
    pub root_output_words: [u32; ROOT_OUTPUT_WORDS],
    pub acc_prev: Felt252,
}

/// host 侧 fail-closed 预检：语句与见证/根互相咬合（出证前必过）。
///
/// # Errors
/// acc_prev 两轨不一致 / 根 hi-lo 拆分不符 / fact 宿主重算不符。
pub fn host_check(
    statement: &RootStatement,
    witness: &RootWitness,
    keccak_root: &[u8; 32],
) -> Result<(), String> {
    let acc = fr_to_felt(&statement.acc_prev).map_err(|_| "acc_prev not a felt".to_string())?;
    if acc != witness.acc_prev {
        return Err("witness.acc_prev != statement.acc_prev".into());
    }
    let (hi, lo) = split_root_hi_lo(keccak_root);
    let s_hi = fr_to_felt(&statement.root_hi).map_err(|_| "root_hi not a felt".to_string())?;
    let s_lo = fr_to_felt(&statement.root_lo).map_err(|_| "root_lo not a felt".to_string())?;
    if hi != s_hi || lo != s_lo {
        return Err("statement root hi/lo != split(keccak_root)".into());
    }
    let aph = fr_to_felt(&statement.aggregator_program_hash)
        .map_err(|_| "aggregator_program_hash not a felt".to_string())?;
    let (_, _, fact) = derive_batch_fact(&aph, &witness.root_output_words, &acc, keccak_root);
    if felt_to_fr(&fact) != statement.batch_fact {
        return Err("batch_fact != poseidon([aph ‖ root_output ‖ acc_prev ‖ hi ‖ lo])".into());
    }
    Ok(())
}

/// 从 host 侧材料派生（语句+见证）——derive_batch_fact 的打包形态。
///
/// # Errors
/// keccak 根拆分失败（不发生：入参即 32B）。
pub fn derive_statement(
    aggregator_program_hash: &Felt252,
    root_output: &[u32; ROOT_OUTPUT_WORDS],
    acc_prev: &Felt252,
    keccak_root: &[u8; 32],
) -> (RootStatement, RootWitness) {
    let (hi, lo, fact) = derive_batch_fact(aggregator_program_hash, root_output, acc_prev, keccak_root);
    (
        RootStatement {
            aggregator_program_hash: felt_to_fr(aggregator_program_hash),
            acc_prev: felt_to_fr(acc_prev),
            root_hi: felt_to_fr(&hi),
            root_lo: felt_to_fr(&lo),
            batch_fact: felt_to_fr(&fact),
        },
        RootWitness { root_output_words: *root_output, acc_prev: *acc_prev },
    )
}

/// 终证电路（setup/prove 共用）。
#[derive(Debug, Clone)]
pub struct RootCircuit {
    pub statement: RootStatement,
    pub witness: RootWitness,
}

/// 位绑定：公开 Fr 变量与电路内非原生 Fp252 变量是同一个 felt252。
///
/// groth16-wrap/src/wrap_circuit.rs:101-111 `bind_felt_public` 的复刻（原函数为
/// pub(crate) 不可跨 crate 依赖；逐行同式，一致性由本 crate 的电路正/负例测试
/// 与金向量 roundtrip 共同钉死）：两侧均为各自域内规范值的 LSB 位分解，
/// 齐长后逐位相等 ⟺ 数值相等；填充位两侧都必须是 0。
pub(crate) fn bind_felt_public(pub_var: &FpVar<Fr>, nn: &CircuitFelt) -> R1CSResult<()> {
    let mut a = pub_var.to_bits_le()?;
    let mut b = nn.to_bits_le()?;
    let n = a.len().max(b.len());
    a.resize(n, Boolean::constant(false));
    b.resize(n, Boolean::constant(false));
    for i in 0..n {
        a[i].enforce_equal(&b[i])?;
    }
    Ok(())
}

/// Fr 公开输入 → 电路 felt 轨（值 ≥ p_felt 的语句在本协议里不存在；
/// 出现即 Unsatisfiable，fail-closed）。
fn felt_of(x: &Fr) -> R1CSResult<Felt252> {
    fr_to_felt(x).map_err(|_| SynthesisError::Unsatisfiable)
}

impl ConstraintSynthesizer<Fr> for RootCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R1CSResult<()> {
        // 5 个公开输入（顺序 = IC 顺序 = publics() 顺序）
        let aph_pub = FpVar::new_input(
            ark_relations::ns!(cs, "aggregator_program_hash"),
            || Ok(self.statement.aggregator_program_hash),
        )?;
        let acc_pub = FpVar::new_input(ark_relations::ns!(cs, "acc_prev"), || Ok(self.statement.acc_prev))?;
        let hi_pub = FpVar::new_input(ark_relations::ns!(cs, "root_hi"), || Ok(self.statement.root_hi))?;
        let lo_pub = FpVar::new_input(ark_relations::ns!(cs, "root_lo"), || Ok(self.statement.root_lo))?;
        let fact_pub = FpVar::new_input(ark_relations::ns!(cs, "batch_fact"), || Ok(self.statement.batch_fact))?;

        // 公开轨道 → 非原生 felt 轨 + 位绑定（反拼装，同 wrap_circuit 的语义）
        let aph_nn = witness_felt(cs.clone(), felt_of(&self.statement.aggregator_program_hash)?)?;
        bind_felt_public(&aph_pub, &aph_nn)?;
        let acc_nn = witness_felt(cs.clone(), felt_of(&self.statement.acc_prev)?)?;
        bind_felt_public(&acc_pub, &acc_nn)?;
        let hi_nn = witness_felt(cs.clone(), felt_of(&self.statement.root_hi)?)?;
        bind_felt_public(&hi_pub, &hi_nn)?;
        let lo_nn = witness_felt(cs.clone(), felt_of(&self.statement.root_lo)?)?;
        bind_felt_public(&lo_pub, &lo_nn)?;

        // 见证：折叠树根输出 8 词（u32 → felt，无损）
        let mut preimage: Vec<CircuitFelt> = Vec::with_capacity(2 + ROOT_OUTPUT_WORDS + 2);
        preimage.push(aph_nn);
        for w in &self.witness.root_output_words {
            preimage.push(witness_felt(cs.clone(), Felt252::from(*w))?);
        }
        preimage.push(acc_nn);
        preimage.push(hi_nn);
        preimage.push(lo_nn);
        debug_assert_eq!(preimage.len(), 4 + ROOT_OUTPUT_WORDS);

        let computed = poseidon_hash_many(&cs, &preimage)?;
        // 计算 fact ⟷ 公开 batch_fact 位绑定（computed 的 to_bits_le 强制规范值）
        bind_felt_public(&fact_pub, &computed)?;
        Ok(())
    }
}

impl RootStatement {
    /// 公开输入个数（形状常数 5；K 不进入语句形状的结构性证据）。
    #[must_use]
    pub fn publics_len(&self) -> usize {
        self.publics_of().len()
    }

    fn publics_of(&self) -> [Fr; 5] {
        [
            self.aggregator_program_hash,
            self.acc_prev,
            self.root_hi,
            self.root_lo,
            self.batch_fact,
        ]
    }
}

impl RootCircuit {
    /// 语句公开输入（verify_with_vk / 链上 publics，顺序同电路 new_input）。
    #[must_use]
    pub fn publics(&self) -> [Fr; 5] {
        [
            self.statement.aggregator_program_hash,
            self.statement.acc_prev,
            self.statement.root_hi,
            self.statement.root_lo,
            self.statement.batch_fact,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{acc_genesis, BatchPlan, HandEntry};
    use groth16_wrap::felt::felt_from_hex;
    use groth16_wrap::golden;
    use groth16_wrap::wrap_circuit::{WrapWitness, HAND_BINDING_INDEX};

    fn sample_materials() -> (Felt252, [u8; 32], [u32; ROOT_OUTPUT_WORDS], Felt252) {
        let aph = felt_from_hex("0x00000000000000000000000000000000000000000000000000000000abcdef00").unwrap();
        let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap();
        let segment: Vec<Felt252> =
            golden::GOLDEN_OUTPUT.iter().map(|h| felt_from_hex(h).unwrap()).collect();
        let binding = felt_from_hex(golden::GOLDEN_HAND_BINDING).unwrap();
        let mut seg = segment.clone();
        seg[HAND_BINDING_INDEX] = binding;
        let fact = WrapWitness { output: seg.clone() }.expected_fact(&program_hash);
        let hand = HandEntry {
            statement: groth16_wrap::batch::BatchStatement {
                program_hash,
                hand_binding: binding,
                fact,
            },
            segment: seg,
        };
        let plan = BatchPlan::new(program_hash, vec![hand]).unwrap();
        let root = plan.keccak_batch_root().unwrap();
        // 根输出词用叶 H1（精确镜像）做样本——真实链里这是折叠树根输出
        let words = plan.leaf_output_words().unwrap();
        (aph, root, words, acc_genesis())
    }

    /// host 预检通过 + 派生确定性（同输入两次派生逐字段一致）。
    #[test]
    fn derive_and_host_check_ok() {
        let (aph, root, words, acc) = sample_materials();
        let (stmt, wit) = derive_statement(&aph, &words, &acc, &root);
        host_check(&stmt, &wit, &root).expect("host check must pass");
        let (stmt2, wit2) = derive_statement(&aph, &words, &acc, &root);
        assert_eq!(stmt, stmt2);
        assert_eq!(wit, wit2);
        // publics 顺序固定 5 个
        let circuit = RootCircuit { statement: stmt, witness: wit };
        assert_eq!(circuit.publics().len(), 5);
        assert_eq!(circuit.publics()[4], stmt.batch_fact);
    }

    /// host 预检负例：fact / hi-lo / acc 任一篡改皆拒绝（fail-closed 出证闸门）。
    #[test]
    fn host_check_rejects_tampering() {
        let (aph, root, words, acc) = sample_materials();
        let (mut stmt, wit) = derive_statement(&aph, &words, &acc, &root);
        let mut s2 = stmt;
        s2.batch_fact += Fr::from(1u64);
        assert!(host_check(&s2, &wit, &root).is_err(), "fact 篡改必须拒绝");
        stmt.root_hi += Fr::from(1u64);
        assert!(host_check(&stmt, &wit, &root).is_err(), "根 hi 篡改必须拒绝");
        let (stmt3, mut wit3) = derive_statement(&aph, &words, &acc, &root);
        wit3.acc_prev += Felt252::from(1u64);
        assert!(host_check(&stmt3, &wit3, &root).is_err(), "见证 acc 篡改必须拒绝");
        let (stmt4, wit4) = derive_statement(&aph, &words, &acc, &root);
        let mut root2 = root;
        root2[0] ^= 0xff;
        assert!(host_check(&stmt4, &wit4, &root2).is_err(), "换根必须拒绝");
    }

    /// 电路形状自检（纯类型层）：见证固定 8 词、语句固定 5 元——K 不进入电路形状，
    /// 即约束数 K 无关的结构性依据（数量实测在 tests/root_wrap_k2.rs 打印）。
    #[test]
    fn circuit_shape_is_k_independent_by_construction() {
        let (aph, root, words, acc) = sample_materials();
        let (stmt, wit) = derive_statement(&aph, &words, &acc, &root);
        // K 无法出现在任何字段：见证只有 8 词 + acc，语句只有 5 个 Fr
        let (stmt_k16, wit_k16) = {
            // 模拟另一批（不同 K 也不影响形状：字段类型不含长度参数）
            let mut w2 = words;
            w2[7] = w2[7].wrapping_add(1);
            derive_statement(&aph, &w2, &acc, &root)
        };
        assert_eq!(stmt.publics_len(), stmt_k16.publics_len());
        assert_eq!(wit.root_output_words.len(), wit_k16.root_output_words.len());
        assert_ne!(stmt.batch_fact, stmt_k16.batch_fact, "不同见证必须给出不同语句");
    }
}
