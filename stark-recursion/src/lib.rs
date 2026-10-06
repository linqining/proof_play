//! stark-recursion —— 递归聚合链（架构 §RecursionPlan / §终证上链 的链 API 与上链形态）。
//!
//! # 终证路线（2026-09-29 用户裁定：**Groth16 全出局，终证 = 单个 STARK 证明**）
//!
//! ```text
//! [K ≤ 64 手牌局]（= SHARP task/pie 的语句面）
//!   │ BatchPlan：K 手语句 + 16-felt 公开段见证（fact 宿主重算 fail-closed）
//!   ▼ ① BatchPlan::keccak_batch_root —— 链上锚定根（SettleBatch 同式，精确复刻）
//!   ▼ ② L1 终证腿（稳定上线主链）：settlement_batch_private 单跑单证
//!   │     —— 一个 cairo-air STARK 批证明，K 手共享一次出证/一次上链验证；
//!   │     电路内 poseidon 链接 acc_{n-1} 与 keccak 批根 → 公开输出尾
//!   │     [acc_prev, root_hi, root_lo, batch_fact]（stark_final 模块）
//!   ▼ ③ 累加链接：acc_n = final_fact = poseidon([ph ‖ 全部公开输出])
//!   │     —— 批 n 的输出内嵌 acc_{n-1}，归纳法把全历史批 fact 链进本批
//!   ▼ ④ 上链：Monad StarkVerifier 合约（submitFinalProof(bytes32×4,bytes)；
//!   │     固定参数 cairo-air 验证器；FRI 核心二期，骨架 fail-closed）
//!   ▼ ⑤ 压缩层（二期，本 crate 承载语句面）：N 个批证明 → leaf-prover →
//!         递归树（FoldPlan）→ stwo_circuit_verifier 终证 → 同一合约验一次
//! ```
//!
//! SHARP 对应：批程序 = task pie → 单证明；递归树 = proof aggregation；
//! Cairo 电路验证器 = recursive verifier；上链 = 「验证一次、承诺复用」。
//!
//! # 信任边界（如实声明，本 crate 不扩大）
//!
//! - 本 crate 是**语句/编排层**：STARK 真伪由链下 fact-verify（stwo
//!   verify_cairo + 程序哈希钉扎 [`stark_final::BATCH_PROGRAM_HASH_HEX`]）
//!   与链上 StarkVerifier（二期 FRI 核心）把关。链上体现的是「语句层一致性
//!   + acc 链 + 根锚」；`submitFinalProof` 的验证器语义以 StarkVerifier.sol
//!   实际实现为准（骨架期 fail-closed 拒绝一切，不伪造通过）。
//! - 不再使用 trusted setup（无 Groth16；对照基线除外）。
//!
//! # 各腿实现状态（如实，本轮门禁 = `cargo test -p stark-recursion` 全绿）
//!
//! | 腿 | 状态 | 依据 |
//! |---|---|---|
//! | host 公式（fact/keccak 根/H1/split） | **精确镜像，测试钉死** | fact-verify/src/lib.rs:78-83；groth16-wrap/src/batch.rs:94-124 ↔ zchain SettleBatch.sol:99-119；leaf_io.rs:44-63 |
//! | L1 终证腿（批程序 acc/批根入参 + 电路内 poseidon 链接） | **E2E 实测**：K=1/8/64 出证 + verify OK，电路内 batch_fact 与宿主镜像逐字一致；K=64 = 555,223 steps / prove 4.5s / 峰值 3.69 GiB | proving-tool/src/settlement_batch_private.cairo；stark_final::expected_batch_fact |
//! | 累加链接 / 终证语句 | **本 crate 协议定义**（测试含负例：acc/根/链接值/换根皆拒绝） | stark_final / chain 模块测试 |
//! | 上链编码（submitFinalProof 提案 ABI） | **金字节测试钉死**（selector/落位/动态偏移） | onchain::encode_submit_final_calldata |
//! | Monad StarkVerifier 合约 | **骨架交付**：累加链存储 + ABI 钉扎 + fail-closed 验证入口（FRI 核心二期） | zchain contracts/monad/src/StarkVerifier.sol |
//! | leaf/fold 工件 wire 类型 | 与 vendored serde 布局逐字段对齐（文档级复刻 + fixture 测试；未对真实二进制往返） | envelope 模块注释 |
//! | 递归树真证明腿（leaf-prover / fold） | **不在主链**（叶 19.4G/折叠 7.4G 实测，超 ≤6G → 二期；fail-closed 闸门见 budget） | budget.rs 锚点 |
//! | Groth16 对照基线 | **feature 隔离**（`groth16-baseline`；K=2 真出证 roundtrip 保留在 feature 内，不进默认门禁/终证路径） | root_circuit.rs / tests/root_wrap_k2_baseline.rs |
//!
//! # 内存纪律（每步峰值受控，估算依据见 [`budget`]）
//!
//! - L1 批证明腿（canonical_small 参数）：K=1 实测 1.87-1.94 GiB、K=64 实测
//!   3.69 GiB（/usr/bin/time -l，2026-09-29）——≤6G 达标；**钉扎 canonical_small
//!   是前提**（canonical 预处理迹同程序实测 9.6-12.9 GiB，超界）。
//! - 电路递归层（二期）：叶 19.4G / 折叠 7.4G（实测锚点）——必须分进程且
//!   不进 stark 服务器裸跑（[`budget::check_step`] fail-closed）。
//! - 本 crate 全部测试为纯宿主算术（poseidon/keccak/blake），KB-MB 级。
//!
//! # 门禁
//!
//! `cargo test -p stark-recursion`（默认全绿；纯 host，无重活）；
//! `cargo test -p stark-recursion --features groth16-baseline`（对照基线，含
//! K=2 Groth16 真出证，<10 分钟）；
//! `cargo run -p stark-recursion --bin bench-recursion -- --help`（服务器真 K 入口）；
//! `cargo run -p stark-recursion --bin batch-inputs -- --help`（L1 批输入/清单生成）。

#[cfg(feature = "groth16-baseline")]
pub mod root_circuit;
pub mod backend;
pub mod budget;
pub mod chain;
pub mod envelope;
pub mod onchain;
pub mod stark_final;

pub use groth16_wrap::batch::BatchStatement;
// ProofJson = 纯 serde 数据类型（对照基线信封/编码器承载用；非证明路径）
pub use groth16_wrap::ProofJson;
