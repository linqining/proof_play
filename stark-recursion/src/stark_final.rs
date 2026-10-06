//! L1 终证腿：**单个 STARK 终证**的语句层（稳定上线主链，架构 §终证上链）。
//!
//! # 终证形态（按用户裁定 2026-09-29：Groth16 全出局）
//!
//! K ≤ 64 手 → `settlement_batch_private`（proving-tool/src/，本 crate 的
//! [`BATCH_PROGRAM_HASH_HEX`] 钉扎其编译产物哈希）单跑单证——一个 cairo-air
//! STARK 批证明，K 手共享一次出证/一次上链验证。这**就是**稳定上线的单个
//! STARK 终证：无 Groth16、无电路递归层（叶 19.4G/折叠 7.4G 的电路递归腿是
//! 二期压缩层，见 [`crate::budget`]，不进主链）。
//!
//! # 公开输出形状（9 人桌迁移后：语句段 16 词，批段含字面前缀 17 词）
//!
//! ```text
//! output = [len] ++ segments(17·K) ++ [acc_prev, root_hi, root_lo, batch_fact]
//!   len = 17·K + 4（corelib ArraySerde 前缀，实测 21 = 1+16+4 @K=1 的
//!   8 人桌旧形状；9 人桌 K=1 即 22 = 1+17+4）
//! ```
//!
//! # 累加链（陈述层；电路内 poseidon 链接的宿主镜像）
//!
//! - 电路内：`batch_fact = poseidon_hash_state([acc_prev, root_hi, root_lo, k]
//!   ++ segments)`（settlement_batch_private.cairo main 尾部）。
//!   宿主镜像 = [`expected_batch_fact`]，sponge 与 corelib `HashState`
//!   （new/update/finalize）逐构造一致（配对吸收、耗尽补 1、末置换取 s0；
//!   与 starknet-crypto 的跨实现对拍在 groth16-wrap/src/poseidon.rs 测试钉死）。
//! - 累加链接出的 acc_n = **电路内 batch_fact**（不是 fact-registry 的
//!   final_fact——后者是 poseidon([ph‖output]) 的全输出哈希，EVM 无
//!   poseidon 预编译、链上重算不经济）。归纳：batch_fact_n = poseidon(
//!   [acc_{n-1}, root hi/lo, k, segments])，其中 acc_{n-1} = batch_fact_{n-1}
//!   → 知道链头即可递归回溯全历史批（真 K 双批 E2E 实证：批 2 绑定批 1 的
//!   batch_fact，proving-tool 2026-09-29）。final_fact 保留为 fact-verify
//!   注册面公式（informational）。
//! - 批根：`root = keccak_batch_root(statements)`（SettleBatch.sol 逐式），
//!   hi/lo = [`crate::chain::split_root_hi_lo`]；语句由公开段派生
//!   （fact = poseidon([ph ‖ seg])，binding = seg[5]），由 [`verify_final_output`]
//!   fail-closed 重算对拍。
//!
//! # 内存（ask 要求：估算依据注释）
//!
//! 本模块纯宿主算术（poseidon/keccak），O(K) felts，KB 级。
//! 证明腿（prove-hand canonical_small 参数）实测：K=1 峰值 1.87 GiB、
//! prove 1.9s（/usr/bin/time -l，2026-09-29）；canonical 预处理迹参数同程序
//! 实测 9.6-12.9 GiB——**L1 腿钉扎 canonical_small 是 ≤6G 硬约束的成立前提**
//! （budget.rs 锚点表引用本实测）。

use anyhow::{anyhow, Context, Result};
use groth16_wrap::batch::{keccak_batch_root, BatchStatement};
use groth16_wrap::felt::{felt_from_hex, felt_to_hex, Felt252};
use groth16_wrap::poseidon::poseidon_hash_many;

/// 批程序（settlement_batch_private，含链尾版）的钉扎程序哈希。
///
/// 实测出处：prove-hand E2E K=1 真出证（本机 2026-09-30，九人桌迁移后
/// 电路；/tmp/fold9/run1，verify OK，steps 8,492，输出 22 词 = 1+17+4）。
/// 重编程序（改 cairo 源）必然换哈希 → 同步更新此处、proving-tool main.rs
/// 与 fact-verify 钉扎。9 人桌迁移前的 8 人桌历史钉值：
/// 0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803。
pub const BATCH_PROGRAM_HASH_HEX: &str =
    "0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d";

/// fold 链批程序（生产版 18 词段，规格 out/fold-spec.md §1/D1）的钉扎程序哈希。
///
/// **发布时自动钉扎**：跑 `bash scripts/pin_fold_program_hash.sh` ——K=1 真出证
/// 提取实测 program_hash → 幂等更新本常量 → `cargo test -p stark-recursion
/// --lib` 验证（钉扎测试两态兼容：空串 = [`fold_batch_program_hash`]
/// fail-closed；非空 = 访问器精确还原钉值）。哈希只钉程序不钉参数；重编程序
/// （改 fold_batch.cairo）必然换哈希，发布脚本会自动改钉，**不要手填**。
/// **不动** [`BATCH_PROGRAM_HASH_HEX`]——它钉的是
/// settlement_batch_private 17 词段在证程序（规格 D3b/K-1）。
pub const FOLD_BATCH_PROGRAM_HASH_HEX: &str = "0x00668efec4dbe90831565fa723a9b47cd32cd35b5c71125e6fc591919aa2b0cf";

/// 批程序 L1 腿钉扎的 prover 参数（≤6G 硬约束的成立前提，见模块注释）。
///
/// canonical_small 预处理迹 = 10,161,776 cells（common/src/prover_params.rs
/// n_trace_cells），上限 2^20 steps——与 K ≤ 64 政策（chain.rs trace 预算）
/// 同一地板。参数 JSON 模板随 prove-hand `--params` 传入（proving-tool/
/// params/canonical_small.json）。
pub const BATCH_PROVER_PARAMS_NOTE: &str =
    "channel_hash=blake2s pow_bits=26 n_queries=70 log_blowup=1 preprocessed_trace=canonical_small";

/// 每手公开段长度（settlement_batch_private 9 人桌输出段 = 字面 16 前缀 +
/// 16 词语句段；旧 wrap_circuit.rs OUTPUT_LEN=16 为 Groth16 baseline 值，
/// 该路径已出局、段形状随 baseline 停在 16 词）。
pub const SEGMENT_LEN: usize = 17;
/// fold 链每手公开段长度：combined 17 词信封原样 + roster_digest 尾插
/// index 17（规格 out/fold-spec.md §1/D1、D3b——**与 [`SEGMENT_LEN`] 并存
/// 不共享**，combined fallback 在证材料全部绑定在批程序段形上）。
///
/// 解析互斥闸的长度碰撞面：两解析器分别要求 elements−4 ≡ 0 (mod 17) 与
/// ≡ 0 (mod 18)，17 与 18 互素 ⇒ lcm(17,18)=306——首个同时满足两形状的
/// elements = 310（306+4）以下互斥无碰撞；批政策 ΣK ≤ 64 下
/// elements ≤ max(17,18)·64+4 = 1156，虽越过 310，但两程序哈希分槽 +
/// fact 绑 ph（D3c 第 2 层）承担真正的禁混批闭合，解析闸只是第一层。
pub const FOLD_SEGMENT_LEN: usize = 18;
/// 手 binding 在手段内的槽位（wrap_circuit.rs:50 HAND_BINDING_INDEX 同值）。
pub const HAND_BINDING_INDEX: usize = 5;
/// 链尾长度：acc_prev / root_hi / root_lo / batch_fact。
pub const TAIL_LEN: usize = 4;
/// 每手入参长度（settlement_batch_private HAND_INPUT_LEN 同值）。
pub const HAND_INPUT_LEN: usize = 102;

/// 电路内链尾公式的宿主镜像：
/// `batch_fact = poseidon_hash_many([acc_prev, root_hi, root_lo, k] ++ segments)`。
///
/// 对 `segments` 切片长度不敏感（逐词吸收）——**fold 链（18 词段）原样复用
/// 同式**（规格 D3b：电路内 batch_fact 公式逐字沿用，fold 平行版只换段长
/// 与程序钉扎，不改链接公式）。
///
/// corelib HashState（new/update/finalize）与 poseidon_hash_many 的构造等价性：
/// 配对吸收（s0/s1 交替 +1）、奇数残位补 1、末尾一次置换取 s0——三态逐例
/// 推演一致（空/单/偶/奇），且 groth16-wrap/src/poseidon.rs 与
/// starknet-crypto 0.8 的随机对拍测试同源钉死。
#[must_use]
pub fn expected_batch_fact(
    acc_prev: &Felt252,
    root_hi: &Felt252,
    root_lo: &Felt252,
    k: usize,
    segments: &[Felt252],
) -> Felt252 {
    let mut msg = Vec::with_capacity(TAIL_LEN + segments.len());
    msg.push(*acc_prev);
    msg.push(*root_hi);
    msg.push(*root_lo);
    msg.push(Felt252::from(k as u64));
    msg.extend_from_slice(segments);
    poseidon_hash_many(&msg)
}

/// 终局 fact（= 累加链接出的 acc_n）：`poseidon([program_hash ‖ output…])`。
///
/// fact-verify `fact_for_output` 同式（该函数用 starknet-crypto 0.8；此处用
/// groth16-wrap 复刻，两者等价由 groth16-wrap/src/poseidon.rs 随机对拍测试
/// 钉死）。output 含 ArraySerde len 前缀（E2E 实测形状）。
#[must_use]
pub fn final_fact(program_hash: &Felt252, output: &[Felt252]) -> Felt252 {
    let mut msg = Vec::with_capacity(output.len() + 1);
    msg.push(*program_hash);
    msg.extend_from_slice(output);
    poseidon_hash_many(&msg)
}

/// 从证明公开输出解析的链尾（累加链接入/出 + 批根拆分）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTail {
    /// 批 n-1 的终局 fact（首批 = 0）。
    pub acc_prev: Felt252,
    /// keccak 批根 32B 的高 16B（大端入域）。
    pub root_hi: Felt252,
    /// keccak 批根 32B 的低 16B。
    pub root_lo: Felt252,
    /// 电路内 poseidon 链接值（[`expected_batch_fact`] 镜像）。
    pub batch_fact: Felt252,
}

/// 解析后的批终证公开输出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalOutput {
    /// 手数（= (elements − TAIL_LEN) / SEGMENT_LEN）。
    pub k: usize,
    /// 17·K 手段（每手段 [16, MAGIC, hand_id, digest, n, binding, cm×9,
    /// total, action_digest]，16 为字面前缀——批程序 Serde 形态逐位同形）。
    pub segments: Vec<Felt252>,
    /// 链尾（公开输出的最后 4 felt）。
    pub tail: ChainTail,
}

impl FinalOutput {
    /// 逐手语句派生：fact = poseidon([program_hash ‖ seg])、binding = seg[5]。
    ///
    /// # Errors
    /// 手段数非 16 的倍数（构造已保证；防御性保留）。
    pub fn statements(&self, program_hash: &Felt252) -> Result<Vec<BatchStatement>> {
        anyhow::ensure!(
            self.segments.len() % SEGMENT_LEN == 0,
            "segments not a multiple of {SEGMENT_LEN}"
        );
        Ok((0..self.k)
            .map(|i| {
                let seg = &self.segments[i * SEGMENT_LEN..(i + 1) * SEGMENT_LEN];
                let mut msg = Vec::with_capacity(SEGMENT_LEN + 1);
                msg.push(*program_hash);
                msg.extend_from_slice(seg);
                BatchStatement { program_hash: *program_hash, hand_binding: seg[HAND_BINDING_INDEX], fact: poseidon_hash_many(&msg) }
            })
            .collect())
    }
}

/// 从证明公开输出解析（fail-closed 形状检查；形状出处见模块注释）。
///
/// # Errors
/// 输出过短 / len 前缀与元素数不符 / 手段数与 17k+4 形状不符。
pub fn parse_final_output(output: &[Felt252]) -> Result<FinalOutput> {
    anyhow::ensure!(
        output.len() >= 1 + SEGMENT_LEN + TAIL_LEN,
        "output too short: {} felts",
        output.len()
    );
    let declared = output[0];
    let elements = output.len() - 1;
    anyhow::ensure!(
        declared == Felt252::from(elements as u64),
        "output len prefix != element count（形状漂移，fail-closed）"
    );
    anyhow::ensure!(
        elements >= SEGMENT_LEN + TAIL_LEN && (elements - TAIL_LEN) % SEGMENT_LEN == 0,
        "output elements {elements} does not match 17k+{TAIL_LEN} shape"
    );
    let k = (elements - TAIL_LEN) / SEGMENT_LEN;
    let segments = output[1..1 + k * SEGMENT_LEN].to_vec();
    let tail = ChainTail {
        acc_prev: output[1 + k * SEGMENT_LEN],
        root_hi: output[2 + k * SEGMENT_LEN],
        root_lo: output[3 + k * SEGMENT_LEN],
        batch_fact: output[4 + k * SEGMENT_LEN],
    };
    Ok(FinalOutput { k, segments, tail })
}

/// fold 批程序钉扎哈希的 [`Felt252`]（fold 终证语句层用）。
///
/// # Errors
/// 钉扎为空（生产 fold 程序未编译落库，规格 D3b/开放点 Q-2 同批落库）或
/// 常量非法 hex。
pub fn fold_batch_program_hash() -> Result<Felt252> {
    anyhow::ensure!(
        !FOLD_BATCH_PROGRAM_HASH_HEX.is_empty(),
        "FOLD_BATCH_PROGRAM_HASH_HEX not pinned yet: the production fold batch program \
         (17-word segment, fold-spec D1/D3b) must be compiled and proven before pinning"
    );
    felt_from_hex(FOLD_BATCH_PROGRAM_HASH_HEX).context("FOLD_BATCH_PROGRAM_HASH_HEX")
}

/// 从 fold 批证明公开输出解析的批终证（17 词段版，规格 D3b）。
///
/// 顶层形状与 [`FinalOutput`] 同构：`[len] ++ K×17 词段 ++ 链尾(4)`——链尾
/// （acc 链接/批根拆分/电路内 batch_fact）与 combined 完全同构，段长换
/// [`FOLD_SEGMENT_LEN`]；电路内链接公式原样复用 [`expected_batch_fact`]
/// （对段长不敏感）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldFinalOutput {
    /// 手数（= (elements − TAIL_LEN) / FOLD_SEGMENT_LEN）。
    pub k: usize,
    /// 18·K 手段（每手段 word 0–16 = combined 信封同位（批终 acc@0、MAGIC@1、
    /// hand_id@2、digest@3、n@4、binding@5、cm×9@6..14、total@15、ald@16），
    /// word 17 = roster_digest **桌内常量**——规格 D1a 多桌修订（out/
    /// fold-multitable-spec.md §4/M4：roster 每桌进电路一次，桌内段各自
    /// 重复携带；跨桌可异、不同桌允许同值，T=1 特例下退化为原批常量））。
    pub segments: Vec<Felt252>,
    /// 链尾（公开输出的最后 4 felt；与 combined 同构）。
    pub tail: ChainTail,
}

impl FoldFinalOutput {
    /// 逐手语句派生：fact = poseidon([program_hash ‖ seg_17])、binding =
    /// seg[5]（[`crate::chain::FOLD_BINDING_INDEX`] 同值）。
    ///
    /// # Errors
    /// 手段数非 17 的倍数（构造已保证；防御性保留）。
    pub fn statements(&self, program_hash: &Felt252) -> Result<Vec<BatchStatement>> {
        anyhow::ensure!(
            self.segments.len() % FOLD_SEGMENT_LEN == 0,
            "fold segments not a multiple of {FOLD_SEGMENT_LEN}"
        );
        Ok((0..self.k)
            .map(|i| {
                let seg =
                    &self.segments[i * FOLD_SEGMENT_LEN..(i + 1) * FOLD_SEGMENT_LEN];
                let mut msg = Vec::with_capacity(FOLD_SEGMENT_LEN + 1);
                msg.push(*program_hash);
                msg.extend_from_slice(seg);
                BatchStatement {
                    program_hash: *program_hash,
                    hand_binding: seg[crate::chain::FOLD_BINDING_INDEX],
                    fact: poseidon_hash_many(&msg),
                }
            })
            .collect())
    }
}

/// 从 fold 批证明公开输出解析（fail-closed 形状检查；形状 = `[len] ++
/// K×18 ++ 尾 4`，规格 D3b——[`parse_final_output`] 的 fold 平行版，两解析器
/// 互拒对方段形即 D3c 禁混批的解析层闸；长度碰撞面见 [`FOLD_SEGMENT_LEN`]
/// 的 lcm(17,18)=306 注释）。
///
/// # Errors
/// 输出过短 / len 前缀与元素数不符 / 手段数与 18k+4 形状不符。
pub fn parse_fold_final_output(output: &[Felt252]) -> Result<FoldFinalOutput> {
    anyhow::ensure!(
        output.len() >= 1 + FOLD_SEGMENT_LEN + TAIL_LEN,
        "fold output too short: {} felts",
        output.len()
    );
    let declared = output[0];
    let elements = output.len() - 1;
    anyhow::ensure!(
        declared == Felt252::from(elements as u64),
        "fold output len prefix != element count（形状漂移，fail-closed）"
    );
    anyhow::ensure!(
        elements >= FOLD_SEGMENT_LEN + TAIL_LEN
            && (elements - TAIL_LEN) % FOLD_SEGMENT_LEN == 0,
        "fold output elements {elements} does not match 18k+{TAIL_LEN} shape"
    );
    let k = (elements - TAIL_LEN) / FOLD_SEGMENT_LEN;
    let segments = output[1..1 + k * FOLD_SEGMENT_LEN].to_vec();
    let tail = ChainTail {
        acc_prev: output[1 + k * FOLD_SEGMENT_LEN],
        root_hi: output[2 + k * FOLD_SEGMENT_LEN],
        root_lo: output[3 + k * FOLD_SEGMENT_LEN],
        batch_fact: output[4 + k * FOLD_SEGMENT_LEN],
    };
    Ok(FoldFinalOutput { k, segments, tail })
}

/// 终证语句层全链验证（提交上链前的 fail-closed 闸门；上链后合约对
/// acc/根的同款断言见 StarkVerifier.sol）：
///
/// 1. 形状（[`parse_final_output`]）；
/// 2. 程序哈希钉扎（= [`BATCH_PROGRAM_HASH_HEX`]）；
/// 3. acc 链：尾 acc_prev == expected_acc_prev（合约同款：acc_prev 必须
///    等于链上 latestFact，防换链/跳批）；
/// 4. 根绑定：尾 hi/lo == split(expected_root)；
/// 5. 电路内链接：尾 batch_fact == [`expected_batch_fact`] 重算；
/// 6. 批根覆盖：由手段重派生语句 → keccak_batch_root == expected_root
///    （批根确实覆盖本批全部已证语句，SettleBatch 同式重算）。
///
/// 返回 (解析结果, 累加链新链头)。**新链头 = 电路内 batch_fact**
/// （in-circuit poseidon 值，见模块注释「累加链接出的 acc_n」）。
///
/// # Errors
/// 任一检查失败（含具体失配字段）。
pub fn verify_final_output(
    output: &[Felt252],
    expected_acc_prev: &Felt252,
    expected_root: &[u8; 32],
) -> Result<(FinalOutput, Felt252)> {
    let parsed = parse_final_output(output).context("final output shape")?;
    let ph = felt_from_hex(BATCH_PROGRAM_HASH_HEX)?;

    anyhow::ensure!(
        parsed.tail.acc_prev == *expected_acc_prev,
        "acc chain mismatch: tail acc_prev {} != expected {}",
        felt_to_hex(&parsed.tail.acc_prev),
        felt_to_hex(expected_acc_prev)
    );
    let (hi, lo) = crate::chain::split_root_hi_lo(expected_root);
    anyhow::ensure!(
        parsed.tail.root_hi == hi && parsed.tail.root_lo == lo,
        "keccak root hi/lo mismatch: tail != split(root)"
    );
    let expect_fact = expected_batch_fact(expected_acc_prev, &hi, &lo, parsed.k, &parsed.segments);
    anyhow::ensure!(
        parsed.tail.batch_fact == expect_fact,
        "in-circuit batch_fact mismatch: {} != recomputed {}",
        felt_to_hex(&parsed.tail.batch_fact),
        felt_to_hex(&expect_fact)
    );
    // 批根覆盖检查：由公开段重派生语句（ph 钉扎 → fact/binding 确定），
    // keccak 折叠必须还原 expected_root。
    let statements = parsed.statements(&ph)?;
    let recomputed_root =
        keccak_batch_root(&statements).map_err(|e| anyhow!("keccak root recompute: {e}"))?;
    anyhow::ensure!(
        recomputed_root == *expected_root,
        "keccak root does not cover the proven segments（换根/换段攻击，fail-closed）"
    );
    // 累加链新链头 = 电路内 batch_fact（尾字，已与 expected_batch_fact 对拍）。
    // 真双批 E2E：批 2 程序以批 1 的 batch_fact 为 acc_prev 出证成功并
    // 逐字对拍（proving-tool 2026-09-29）。
    let acc_head = parsed.tail.batch_fact;
    let _ = final_fact(&ph, output); // fact-registry fact 公式在位（informational）
    Ok((parsed, acc_head))
}

/// 钉扎程序哈希的 [`Felt252`]（测试与编码器共用）。
///
/// # Errors
/// 常量非法（不发生：常量在测试钉死）。
pub fn batch_program_hash() -> Result<Felt252> {
    felt_from_hex(BATCH_PROGRAM_HASH_HEX).context("BATCH_PROGRAM_HASH_HEX")
}

/// L1 终证提交信封（`final_envelope.v1`）：单份 STARK 批证明 → Monad
/// StarkVerifier 提交的完整载荷（证明文件 + 语句面 + 累加链状态）。
///
/// 与对照基线 [`crate::envelope::RootEnvelope`]（Groth16 包裹信封）平行；
/// 本信封**不含任何 Groth16 字段**——wrap 通道被裁定出终证路径。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FinalEnvelope {
    /// 格式版本（当前恒 1）。
    pub protocol_version: u32,
    /// 批程序钉扎哈希（0x 64hex，= [`BATCH_PROGRAM_HASH_HEX`]）。
    pub program_hash: String,
    /// 证明公开输出（含 len 前缀 + 链尾，0x 64hex 逐 felt）。
    pub output: Vec<String>,
    /// L1Inbox 锚定的 keccak 批根（0x 64hex）。
    pub keccak_batch_root: String,
    /// 累加链接入 acc_prev = 前批的电路内 batch_fact（0x 64hex；首批 = 0x0…0）。
    pub acc_prev: String,
    /// 电路内 poseidon 链接值 = 本批累加链新链头（0x 64hex）。
    pub batch_fact: String,
    /// fact-registry 面 fact = poseidon([ph ‖ 全部公开输出])（0x 64hex；
    /// fact-verify fact_for_output 同式，informational——不进链上累加链）。
    pub final_fact: String,
    /// 证明文件路径（bincode+bz2 或 json；上链 wire 由打包器转 bytes）。
    pub proof_path: String,
}

impl FinalEnvelope {
    /// 从已过 [`verify_final_output`] 闸门的材料打包（fail-closed）。
    /// batch_fact/acc 链头与 fact-registry final_fact 由 output 自派生
    /// （不信任调用方传值）。
    ///
    /// # Errors
    /// 形状/链校验失败（[`verify_final_output`] 全链闸门）/ 证明文件路径为空。
    pub fn from_verified(
        output: &[Felt252],
        keccak_root: &[u8; 32],
        acc_prev: &Felt252,
        proof_path: impl Into<String>,
    ) -> Result<Self> {
        let path: String = proof_path.into();
        anyhow::ensure!(!path.is_empty(), "proof_path is empty");
        let (_parsed, _acc_head) = verify_final_output(output, acc_prev, keccak_root)?;
        let ph = batch_program_hash()?;
        let tail = parse_final_output(output)?.tail;
        Ok(Self {
            protocol_version: 1,
            program_hash: felt_to_hex(&ph),
            output: output.iter().map(felt_to_hex).collect(),
            keccak_batch_root: format!("0x{}", hex::encode(keccak_root)),
            acc_prev: felt_to_hex(acc_prev),
            batch_fact: felt_to_hex(&tail.batch_fact),
            final_fact: felt_to_hex(&final_fact(&ph, output)),
            proof_path: path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::split_root_hi_lo;
    use groth16_wrap::golden;
    use groth16_wrap::wrap_circuit::HAND_BINDING_INDEX as GHW_BINDING_IDX;

    /// 金向量段形态的 K 手段（手段 = 17 felt 含字面 16：groth16 金向量段
    /// 16 felt（前缀 15 + 15 词）+ 9 人桌补位 1 词——形状测试语料）。
    fn golden_segments(k: usize, program_hash: &Felt252) -> Vec<Felt252> {
        let mut base: Vec<Felt252> =
            golden::GOLDEN_OUTPUT.iter().map(|h| felt_from_hex(h).unwrap()).collect();
        assert_eq!(base.len(), 16, "groth16 金向量 wrap 段 16 词");
        base.push(Felt252::from(0x5E47u64)); // 9 人桌 cm×9 补位
        let mut segs = Vec::with_capacity(k * SEGMENT_LEN);
        for i in 0..k {
            let mut seg = base.clone();
            seg[GHW_BINDING_IDX] = seg[GHW_BINDING_IDX] + Felt252::from(i as u64);
            // 段内 binding 槽位与 wrap_circuit 一致（= 5）
            assert_eq!(GHW_BINDING_IDX, HAND_BINDING_INDEX);
            let _ = program_hash;
            segs.extend_from_slice(&seg);
        }
        segs
    }

    /// 宿主镜像 vs corelib HashState 构造等价：逐例推演已在模块注释；
    /// 这里钉死「K=2 段数 17·2 + 4 尾」的 expected_batch_fact 确定性 + 敏感性。
    #[test]
    fn expected_batch_fact_is_deterministic_and_binding() {
        let ph = batch_program_hash().unwrap();
        let segs = golden_segments(2, &ph);
        let acc = Felt252::from(0u64);
        let mut root = [0u8; 32];
        for (i, b) in root.iter_mut().enumerate() {
            *b = (i * 11 + 5) as u8;
        }
        let (hi, lo) = split_root_hi_lo(&root);
        let f1 = expected_batch_fact(&acc, &hi, &lo, 2, &segs);
        let f2 = expected_batch_fact(&acc, &hi, &lo, 2, &segs);
        assert_eq!(f1, f2, "确定性");
        // 任一输入变 → fact 变
        assert_ne!(f1, expected_batch_fact(&(acc + Felt252::from(1u64)), &hi, &lo, 2, &segs), "acc 敏感");
        assert_ne!(f1, expected_batch_fact(&acc, &hi, &lo, 2, &segs[..31].to_vec()), "段敏感");
        assert_ne!(f1, expected_batch_fact(&acc, &hi, &lo, 4, &segs), "k 敏感");
        let mut root2 = root;
        root2[0] ^= 1;
        let (hi2, lo2) = split_root_hi_lo(&root2);
        assert_ne!(f1, expected_batch_fact(&acc, &hi2, &lo2, 2, &segs), "根敏感");
    }

    /// parse_final_output：K=2 合成输出往返 + 形状负例（len 前缀漂移/短尾）。
    #[test]
    fn parse_final_output_shape_and_rejects() {
        let ph = batch_program_hash().unwrap();
        let segs = golden_segments(2, &ph);
        let acc = Felt252::from(7u64);
        let root = [9u8; 32];
        let (hi, lo) = split_root_hi_lo(&root);
        let fact = expected_batch_fact(&acc, &hi, &lo, 2, &segs);
        let mut output = vec![Felt252::from((segs.len() + TAIL_LEN) as u64)];
        output.extend_from_slice(&segs);
        output.extend_from_slice(&[acc, hi, lo, fact]);
        let parsed = parse_final_output(&output).unwrap();
        assert_eq!(parsed.k, 2);
        assert_eq!(parsed.segments, segs);
        assert_eq!(parsed.tail.acc_prev, acc);
        assert_eq!(parsed.tail.batch_fact, fact);

        // len 前缀漂移拒绝
        let mut bad = output.clone();
        bad[0] = Felt252::from(999u64);
        assert!(parse_final_output(&bad).is_err());
        // 短输出拒绝
        assert!(parse_final_output(&output[..5]).is_err());
        // 非 17k+4 形状拒绝（19 elements：18−4=14 非 17 倍数）
        let mut bad2 = vec![Felt252::from(18u64)];
        bad2.extend(std::iter::repeat_n(Felt252::from(0u64), 18));
        assert!(parse_final_output(&bad2).is_err());
    }

    /// fold 金向量段形态的 K 手段（18 词：[批终 acc] ++ golden v2 段 16 ++
    /// [roster_digest]，批终 acc/roster 全手同值——Q-1/D1a 批常量）。
    fn fold_segments(k: usize, program_hash: &Felt252) -> Vec<Felt252> {
        let mut base_v2: Vec<Felt252> = golden::GOLDEN_OUTPUT
            .iter()
            .skip(1)
            .map(|h| felt_from_hex(h).unwrap())
            .collect();
        assert_eq!(base_v2.len(), 15);
        base_v2.push(Felt252::from(0x5E47u64)); // 9 人桌 cm×9 补位
        assert_eq!(base_v2.len(), 16);
        let roster_d = poseidon_hash_many(&[Felt252::from(0x1057u64), Felt252::from(k as u64)]);
        let batch_acc =
            poseidon_hash_many(&[Felt252::from(0xB47Cu64), Felt252::from(k as u64)]);
        let _ = program_hash;
        let mut segs = Vec::with_capacity(k * FOLD_SEGMENT_LEN);
        for i in 0..k {
            let mut seg = vec![batch_acc];
            seg.extend_from_slice(&base_v2);
            seg[GHW_BINDING_IDX] = seg[GHW_BINDING_IDX] + Felt252::from(i as u64);
            seg.push(roster_d);
            assert_eq!(seg.len(), FOLD_SEGMENT_LEN);
            segs.extend_from_slice(&seg);
        }
        segs
    }

    /// 合成 fold 批程序公开输出（形状 = [len] ++ K×18 ++ [acc,hi,lo,fact]，
    /// 与 combined 形状同构、段长 17；E2E 对拍待生产 fold 程序落库）。
    fn synth_fold_final_output(
        segments: &[Felt252],
        acc: &Felt252,
        root: &[u8; 32],
        k: usize,
    ) -> Vec<Felt252> {
        let (hi, lo) = split_root_hi_lo(root);
        let fact = expected_batch_fact(acc, &hi, &lo, k, segments);
        let mut output = vec![Felt252::from((segments.len() + TAIL_LEN) as u64)];
        output.extend_from_slice(segments);
        output.extend_from_slice(&[*acc, hi, lo, fact]);
        output
    }

    /// parse_fold_final_output：K=2 合成输出往返（含 expected_batch_fact
    /// 原样复用对拍——对 18 词段长度不敏感，D3b）+ 形状负例（len 前缀漂移/
    /// 短输出/17 词段混入）。
    #[test]
    fn parse_fold_final_output_shape_and_rejects() {
        let ph = batch_program_hash().unwrap();
        let segs = fold_segments(2, &ph);
        assert_eq!(segs.len(), 2 * FOLD_SEGMENT_LEN);
        let acc = Felt252::from(7u64);
        let root = [9u8; 32];
        let (hi, lo) = split_root_hi_lo(&root);
        let fact = expected_batch_fact(&acc, &hi, &lo, 2, &segs);
        // 输出构造走 synth_fold_final_output（与 combined 侧同构的合成路径，
        // 避免测试内联重复一份 [len]++segs++tail 拼装）
        let output = synth_fold_final_output(&segs, &acc, &root, 2);
        let parsed = parse_fold_final_output(&output).unwrap();
        assert_eq!(parsed.k, 2);
        assert_eq!(parsed.segments, segs);
        assert_eq!(parsed.tail.acc_prev, acc);
        assert_eq!(parsed.tail.batch_fact, fact);
        // 链尾公式原样复用：尾字 == expected_batch_fact(…, 17 词段)。
        assert_eq!(
            parsed.tail.batch_fact,
            expected_batch_fact(&acc, &parsed.tail.root_hi, &parsed.tail.root_lo, 2, &segs),
            "fold 链尾复用同式（段长无关，D3b）"
        );

        // len 前缀漂移拒绝
        let mut bad = output.clone();
        bad[0] = Felt252::from(999u64);
        assert!(parse_fold_final_output(&bad).is_err());
        // 短输出拒绝
        assert!(parse_fold_final_output(&output[..5]).is_err());
        // 17 词段混入 fold 解析（combined 形状 → elements=38，38-4=34 非 18 倍数）
        let combined_style = {
            let mut o = vec![Felt252::from((2 * SEGMENT_LEN + TAIL_LEN) as u64)];
            o.extend(std::iter::repeat_n(Felt252::from(1u64), 2 * SEGMENT_LEN + TAIL_LEN));
            o
        };
        assert!(
            parse_fold_final_output(&combined_style).is_err(),
            "17 词段形状必须被 fold 解析拒绝（D3c 解析层闸）"
        );
        // 反向：18 词段混入 combined 解析同样拒绝
        assert!(
            parse_final_output(&output).is_err(),
            "18 词段形状必须被 combined 解析拒绝（D3c 解析层闸）"
        );
    }

    /// fold 语句派生：fact = poseidon([ph ‖ seg_17])（与 chain::fold_expected_fact
    /// 跨模块同式）、binding = seg[5]；换 ph 必改 fact（D3c 第 2 层）；钉扎
    /// 未落库时 fold_batch_program_hash fail-closed（如实，不伪造可用哈希）。
    #[test]
    fn fold_final_output_statements_and_pinning() {
        let ph = batch_program_hash().unwrap();
        let segs = fold_segments(2, &ph);
        let parsed = FoldFinalOutput {
            k: 2,
            segments: segs.clone(),
            tail: ChainTail {
                acc_prev: Felt252::from(0u64),
                root_hi: Felt252::from(0u64),
                root_lo: Felt252::from(0u64),
                batch_fact: Felt252::from(0u64),
            },
        };
        let statements = parsed.statements(&ph).unwrap();
        assert_eq!(statements.len(), 2);
        for (i, st) in statements.iter().enumerate() {
            let seg = &segs[i * FOLD_SEGMENT_LEN..(i + 1) * FOLD_SEGMENT_LEN];
            assert_eq!(st.program_hash, ph);
            assert_eq!(st.hand_binding, seg[crate::chain::FOLD_BINDING_INDEX], "binding = seg[5]");
            assert_eq!(
                felt_to_hex(&st.fact),
                felt_to_hex(&crate::chain::fold_expected_fact(&ph, seg)),
                "与 chain::fold_expected_fact 跨模块同式"
            );
        }
        // 两手 binding 互异（金向量逐手递增）
        assert_ne!(statements[0].hand_binding, statements[1].hand_binding);
        // 换 ph：同段内容不同程序哈希 → fact 必不同（两链禁混批锚）
        let other = parsed.statements(&(ph + Felt252::from(1u64))).unwrap();
        assert_ne!(statements[0].fact, other[0].fact);
        // 非 17 倍数段防御性拒绝
        let bad = FoldFinalOutput {
            k: 2,
            segments: segs[..2 * FOLD_SEGMENT_LEN - 1].to_vec(),
            tail: parsed.tail.clone(),
        };
        assert!(bad.statements(&ph).is_err());
        // 钉扎纪律（两态皆不破）：生产 fold 程序未落库前 fail-closed，且失败
        // 必须是「钉扎缺失」而非其它；落库后访问器必须精确还原钉扎哈希。
        match fold_batch_program_hash() {
            Ok(h) => assert_eq!(felt_to_hex(&h), FOLD_BATCH_PROGRAM_HASH_HEX),
            Err(e) => assert!(
                format!("{e}").contains("not pinned"),
                "未钉扎时的失败必须是钉扎缺失: {e}"
            ),
        }
        // 常量分立（D3/K-1）：批程序段 17 词（字面 16 前缀 + 语句 16）与
        // fold 段 18 词是两个独立常量，禁共享改基。
        assert_eq!(SEGMENT_LEN, 17);
        assert!(!BATCH_PROGRAM_HASH_HEX.is_empty(), "批程序钉扎在役");
        assert_eq!(FOLD_SEGMENT_LEN, 18);
    }

    /// verify_final_output 正例：语句重派生 → keccak 根还原 → 全链一致；
    /// 且终局 fact = final_fact(钉扎 ph, output)。
    #[test]
    fn verify_final_output_full_chain() {
        let ph = batch_program_hash().unwrap();
        let segs = golden_segments(2, &ph);
        let acc = Felt252::from(0u64);
        // 根由「语句派生」得到（模拟真实流程：根 = keccak(语句)）
        let statements = FinalOutput {
            k: 2,
            segments: segs.clone(),
            tail: ChainTail { acc_prev: acc, root_hi: Felt252::from(0u64), root_lo: Felt252::from(0u64), batch_fact: Felt252::from(0u64) },
        }
        .statements(&ph)
        .unwrap();
        let root = keccak_batch_root(&statements).unwrap();
        let (hi, lo) = split_root_hi_lo(&root);
        let fact = expected_batch_fact(&acc, &hi, &lo, 2, &segs);
        let mut output = vec![Felt252::from((segs.len() + TAIL_LEN) as u64)];
        output.extend_from_slice(&segs);
        output.extend_from_slice(&[acc, hi, lo, fact]);

        let (parsed, acc_next_val) = verify_final_output(&output, &acc, &root).expect("全链验证");
        assert_eq!(parsed.k, 2);
        assert_eq!(felt_to_hex(&acc_next_val), felt_to_hex(&parsed.tail.batch_fact), "acc 新链头 = 电路内 batch_fact");
        assert_ne!(acc_next_val, acc, "genesis → 非 0");
        assert_ne!(acc_next_val, final_fact(&ph, &output), "acc ≠ fact-registry fact（两公式分离）");
    }

    /// verify_final_output 负例 ×4：acc 换链 / 根换锚 / 链接值篡改 /
    /// 根不覆盖本批段（换根攻击）——逐一 fail-closed。
    #[test]
    fn verify_final_output_rejects_tampering() {
        let ph = batch_program_hash().unwrap();
        let segs = golden_segments(2, &ph);
        let acc = Felt252::from(3u64);
        let statements = FinalOutput {
            k: 2,
            segments: segs.clone(),
            tail: ChainTail { acc_prev: acc, root_hi: Felt252::from(0u64), root_lo: Felt252::from(0u64), batch_fact: Felt252::from(0u64) },
        }
        .statements(&ph)
        .unwrap();
        let root = keccak_batch_root(&statements).unwrap();
        let (hi, lo) = split_root_hi_lo(&root);
        let fact = expected_batch_fact(&acc, &hi, &lo, 2, &segs);
        let mk = |a: Felt252, h: Felt252, l: Felt252, f: Felt252| {
            let mut o = vec![Felt252::from((segs.len() + TAIL_LEN) as u64)];
            o.extend_from_slice(&segs);
            o.extend_from_slice(&[a, h, l, f]);
            o
        };

        // ① acc 换链（提交到别的累加链头）
        let good = mk(acc, hi, lo, fact);
        assert!(verify_final_output(&good, &(acc + Felt252::from(1u64)), &root).is_err());
        // ② 根换锚
        let mut root2 = root;
        root2[31] ^= 1;
        assert!(verify_final_output(&good, &acc, &root2).is_err());
        // ③ 链接值篡改
        let bad_fact = mk(acc, hi, lo, fact + Felt252::from(1u64));
        assert!(verify_final_output(&bad_fact, &acc, &root).is_err());
        // ④ 根不覆盖本批段：用另一语句集的根
        let other_root = {
            let mut s2 = statements.clone();
            s2[1].hand_binding = s2[1].hand_binding + Felt252::from(100u64);
            keccak_batch_root(&s2).unwrap()
        };
        assert!(verify_final_output(&good, &acc, &other_root).is_err(), "根不覆盖段必须拒绝");
    }

    /// FinalEnvelope serde 往返无损 + 钉扎哈希一致性；空 proof_path 拒绝。
    #[test]
    fn final_envelope_roundtrip_and_pinning() {
        let ph = batch_program_hash().unwrap();
        let segs = golden_segments(2, &ph);
        let acc = Felt252::from(0u64);
        let statements = FinalOutput {
            k: 2,
            segments: segs.clone(),
            tail: ChainTail { acc_prev: acc, root_hi: Felt252::from(0u64), root_lo: Felt252::from(0u64), batch_fact: Felt252::from(0u64) },
        }
        .statements(&ph)
        .unwrap();
        let root = keccak_batch_root(&statements).unwrap();
        let (hi, lo) = split_root_hi_lo(&root);
        let fact = expected_batch_fact(&acc, &hi, &lo, 2, &segs);
        let mut output = vec![Felt252::from((segs.len() + TAIL_LEN) as u64)];
        output.extend_from_slice(&segs);
        output.extend_from_slice(&[acc, hi, lo, fact]);
        let (_, acc_next_val) = verify_final_output(&output, &acc, &root).unwrap();
        assert_eq!(felt_to_hex(&acc_next_val), felt_to_hex(&fact), "acc 新链头 = 电路内 batch_fact");

        let env = FinalEnvelope::from_verified(&output, &root, &acc, "/tmp/settlement-batch/run/proof.bin")
            .unwrap();
        assert_eq!(env.program_hash, BATCH_PROGRAM_HASH_HEX, "信封钉扎哈希 = 常量");
        assert_eq!(env.protocol_version, 1);
        assert_eq!(env.output.len(), 1 + segs.len() + TAIL_LEN, "输出 = len 前缀 + 段 + 尾");
        assert_eq!(env.batch_fact, felt_to_hex(&acc_next_val), "信封 batch_fact = acc 新链头");
        assert_eq!(env.final_fact, felt_to_hex(&final_fact(&ph, &output)), "信封 final_fact = fact-registry 公式");
        assert_ne!(env.final_fact, env.batch_fact, "两个公式值域不同（防混用）");
        let s = serde_json::to_string(&env).unwrap();
        assert_eq!(serde_json::from_str::<FinalEnvelope>(&s).unwrap(), env, "serde 往返无损");
        assert!(FinalEnvelope::from_verified(&output, &root, &acc, "").is_err());
    }
}
