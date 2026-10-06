// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {AuthorityOwnable} from "./AuthorityOwnable.sol";

/// @title StarkVerifier — Monad 固定参数 cairo-air STARK 验证合约（主链终证通道）
/// @notice 递归聚合链（poker_texas_air stark-recursion）产出的**单个 STARK 终证**
///         直接上链验证的入口。按 2026-09-29 裁定：终证路径不含任何 Groth16
///         （SettleWrap/Groth16Verifier 栈仅作对照基线保留）。
///
/// # 验证链（与 stark-recursion/src/stark_final.rs 语句层逐位对应）
/// 1. `accPrev == latestFact` —— 累加链接（批 n-1 的电路内 batch_fact；
///    首批 accPrev = 0x0…0 = genesis）。防换链/跳批/重放历史批。
/// 2. `_verifyStarkProof(proof, …)` —— 固定参数 cairo-air FRI 验证核心：
///    - 程序哈希钉扎：`BATCH_PROGRAM_HASH`
///      = 0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803
///      （settlement_batch_private 编译产物，prove-hand E2E 实测 2026-09-29，
///      与 proving-tool/params/canonical_small.json 参数集对应；
///      参数 = blake2s channel / pow_bits 26 / n_queries 70 / log_blowup 1 /
///      canonical_small 预处理迹）；
///    - FRI 低度测试 + OOD + PoW（n_queries=70 × pow_bits=26 ≈ 96bit 安全）；
///    - keccak256 channel/Merkle 路线走 EVM keccak256 预编译（本地补丁
///      ChannelHash::Keccak256 已在 vendored 栈暴露，E2E 实测出证/验证通过）。
/// 3. 公开内存还原 output → 与 calldata `outputCommit` 对拍（keccak256）→
///    尾四字 (accPrev, rootHi, rootLo, batchFact) 与 calldata 对拍。
/// 4. 状态：`latestFact = uint256(batchFact)`（新累加链头）；
///    `settledFact(keccakRoot) = uint256(batchFact)`（根一次性）。
///
/// # 信任边界（务必知悉）
/// 1. **FRI 核心为二期交付**：`submitFinalProof` 骨架期 fail-closed——
///    一律 revert（`FRIVerifierNotDelivered`），绝不伪造「验证通过」。
///    链下过渡期由 fact-verify（stwo verify_cairo + 程序哈希钉扎）把关，
///    operator 背书口径与 SettleBatch.sol 相同。
/// 2. **批根 ↔ L1Inbox 锚定关系**：keccakRoot 由 L1Inbox 锚定（BatchAnchored）；
///    消费方应同时核对 settledFact(keccakRoot) 与 inbox 锚的一致性。
/// 3. **permissioned**：仅 authority 可提交（与 L1Inbox/SettleBatch 同口径）。
contract StarkVerifier is AuthorityOwnable {
    // ------------------------------------------------------------------
    // 常量（参数钉扎；交付 FRI 核心时逐字冻结）
    // ------------------------------------------------------------------

    /// 批程序钉扎哈希（settlement_batch_private，位于 proving-tool，
    /// K=1/8/32/64 E2E 实测一致；改程序源码必换哈希并重新部署）。
    uint256 public constant BATCH_PROGRAM_HASH =
        0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803;

    // ------------------------------------------------------------------
    // 状态
    // ------------------------------------------------------------------

    /// L1Inbox（批根锚；构造期钉扎，用于事件关联与消费方对账）。
    address public immutable l1Inbox;
    /// 累加链头（= 最近一结批的电路内 batch_fact；genesis = 0）。
    uint256 public latestFact;
    /// keccakRoot → 已结 batchFact（根一次性）。
    mapping(bytes32 => uint256) public settledFact;

    // ------------------------------------------------------------------
    // 事件 / 错误
    // ------------------------------------------------------------------

    event FinalSettled(
        address indexed operator,
        bytes32 indexed keccakRoot,
        uint256 accPrev,
        uint256 batchFact,
        bytes32 outputCommit,
        uint256 proofBytes
    );

    error AccChainMismatch();
    error RootAlreadySettled();
    error EmptyProof();
    error FRIVerifierNotDelivered();

    // ------------------------------------------------------------------
    // 构造
    // ------------------------------------------------------------------

    constructor(address initialAuthority_, address l1Inbox_) AuthorityOwnable(initialAuthority_) {
        if (l1Inbox_ == address(0)) revert ZeroAddress();
        l1Inbox = l1Inbox_;
    }

    // ------------------------------------------------------------------
    // 主链终证入口（ABI 与 stark-recursion onchain::encode_submit_final_calldata
    // 提案钉扎一致；selector = submitFinalProof(bytes32,bytes32,bytes32,bytes32,bytes)）
    // ------------------------------------------------------------------

    /// @notice 提交单个 STARK 终证并结算一批（K ≤ 64 手共享一次验证）。
    /// @param keccakRoot L1Inbox 锚定的批根（SettleBatch 同式 keccak 折叠）。
    /// @param accPrev 累加链接入（= 前批 batchFact；首批 0）。
    /// @param batchFact 电路内 poseidon 链接值（公开输出尾字 = 新链头）。
    /// @param outputCommit 全部公开输出的 keccak256 承诺（逐 felt 32B 大端）。
    /// @param proof STARK 证明序列化字节（bincode+bz2 wire / fact-verify 同格式）。
    function submitFinalProof(
        bytes32 keccakRoot,
        bytes32 accPrev,
        bytes32 batchFact,
        bytes32 outputCommit,
        bytes calldata proof
    ) external onlyAuthority whenNotPaused {
        if (uint256(accPrev) != latestFact) revert AccChainMismatch();
        if (settledFact[keccakRoot] != 0) revert RootAlreadySettled();
        if (proof.length == 0) revert EmptyProof();

        // —— FRI 验证核心（二期交付；骨架期 fail-closed）——
        // 交付后此处的语义（与 Rust 侧 verify_final_output 对齐）：
        //   1. _verifyStarkProof(proof, BATCH_PROGRAM_HASH, params) — FRI/OOD/PoW；
        //   2. 从证明公开内存还原 output；keccak(output) == outputCommit；
        //   3. output 尾四字 == (accPrev, rootHi, rootLo, batchFact)。
        // 骨架期：一律 revert，不进入任何状态变更（防伪造通过）。
        revert FRIVerifierNotDelivered();

        // unreachable（FRI 核心交付后启用）：
        // settledFact[keccakRoot] = uint256(batchFact);
        // latestFact = uint256(batchFact);
        // emit FinalSettled(msg.sender, keccakRoot, uint256(accPrev), uint256(batchFact), outputCommit, proof.length);
    }

    /// @notice FRI 核心交付位（二期）：固定参数 cairo-air 验证器。
    ///         keccak256 路线全部走预编译；M31/CM31 域算术内联（复刻
    ///         stwo core QM31；参考 Permissionless Technologies 原生 Circle
    ///         STARK verifier 形状，其开源状态未核实——交付前自行实现）。
    function _verifyStarkProof(bytes calldata, uint256, bytes32) internal pure returns (bool) {
        return false;
    }
}
