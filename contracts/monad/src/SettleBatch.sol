// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Groth16VerifierBatch} from "./Groth16VerifierBatch.sol";

/// @notice SettleBatch —— 批量 STARK→Groth16 包裹的 Monad 结算入口（实现 C）。
///
/// 批容量口径（2026-09-29 扩容）：`maxStatements` = 单 tx 语句上限（构造
/// 参数，2 的幂使用），首实例（0x37901e99…）= 8（缩样 2 × K4），扩容实例
/// = 64（对齐 stark-recursion K=64 桶）。`batchN` = **每证明语句数**（非
/// 证明数——语义由 Groth16VerifierBatch 的公开输入长度 2N+1 钉死），由
/// 证明产源形状决定：当前产源（36GB 机器）只能产 K4（K8 setup 峰值被
/// SIGKILL），故 batchN=4；64 语句 = 16 证明 × 4 语句，单 tx 多证明入口
/// 一次吃下。gas 路径线性：叶子 keccak O(N)、两两折叠 O(N)、settledFact
/// 写入 O(N)，无 O(N²) 项。校验链：
/// 1. `Groth16VerifierBatch.verifyProof`（语句集 = 电路公开输入，3N+… 已由
///    电路钉死：fact == poseidon(program_hash‖output)、output 形状、
///    output[5] == hand_binding）；
/// 2. 语句集 keccak 批根重算一致（leaf_i = keccak256(uint32(i) ‖
///    program_hash ‖ hand_binding ‖ fact)，两两折叠，条数 = batchN，
///    2 的幂）—— 链上锚定「已验证语句集合」本身；
/// 3. 批根一次性 + hand_binding 不重复。
///
/// # 信任边界（务必知悉，勿当去信任事实引用）
/// 1. **Trusted setup**：VK 来自 groth16-wrap 固定种子单方仪式 —— 测试网
///    口径；主网必须换 MPC powers-of-tau ceremony 并重新部署 verifier。
/// 2. **不验证 STARK**：链上命题只是 hash 一致性 + 电路一致，NOT「存在合法
///    STARK 证明」。STARK 真伪由链下 fact-verify（stwo verify_cairo + 程序
///    哈希钉扎 0x744d16d3…）与运营方把关。
/// 3. **appchain 批根对应关系在链下**：poker-appchain 的批次根是 binding 的
///    Poseidon 域折叠（pipeline.rs::batch_root，域
///    "poker-appchain.batch_root.v1"），Monad 无 Poseidon 预编译、链上验算
///    不经济。operator 在提交前用 groth16-wrap
///    `batch::appchain_batch_root`（与 poker-appchain 冻结金向量
///    0x00f6fae9… 对拍）离线核对 keccak 根所覆盖的 binding 集合与 appchain
///    批根一致——即本合约体现「operator 背书 + 电路一致」，非去信任事实。

/// calldata 形态的单个批量证明（文件级 struct，便于测试/脚本复用）。
struct BatchProof {
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
}

contract SettleBatch {
    Groth16VerifierBatch public immutable verifier;
    uint256 public immutable batchN;
    uint256 public immutable maxStatements;

    /// keccak 批根 → 已结算。
    mapping(bytes32 => bool) public settledRoots;
    /// hand_binding → fact（跨批次一次性：同一手不可重复入账）。
    mapping(uint256 => uint256) public settledFact;

    event BatchSettled(
        address indexed operator,
        bytes32 indexed keccakRoot,
        uint256 indexed programHash,
        uint256 proofCount,
        uint256 statementCount
    );

    error BadProof();
    error BadPublicInputsLength();
    error BadBatchShape();
    error RootMismatch();
    error AlreadySettledRoot();
    error DuplicateBinding();

    constructor(address verifier_, uint256 batchN_, uint256 maxStatements_) {
        verifier = Groth16VerifierBatch(verifier_);
        require(batchN_ > 0 && (batchN_ & (batchN_ - 1)) == 0, "batchN must be 2^k");
        require(maxStatements_ >= batchN_ && maxStatements_ <= 4096, "maxStatements");
        batchN = batchN_;
        maxStatements = maxStatements_;
    }

    /// @notice 连验多个批量证明并把整批语句入账（一次 tx 覆盖 ≤maxStatements
    ///         条语句；缩样金向量 2 × N4 = 8 条，扩容实例 16 × N4 = 64 条；
    ///         count 只要求「≤maxStatements 且为 2 的幂」——子批粒度可任选）。
    /// @param keccakRoot 整批语句集的 keccak 根（调用方预填；合约重算强制一致）
    /// @param proofs 每个覆盖 batchN 条语句的 Groth16 证明
    /// @param pubLists proofs[j] 的公开输入（各 2N+1 =
    ///        [program_hash, hand_binding_1, fact_1, …, hand_binding_N, fact_N]；
    ///        program_hash 跨证明一致）
    function settleBatch(
        bytes32 keccakRoot,
        BatchProof[] calldata proofs,
        uint256[][] calldata pubLists
    ) external {
        uint256 n = batchN;
        if (proofs.length == 0 || pubLists.length != proofs.length) revert BadBatchShape();
        uint256 count = proofs.length * n;
        if (count > maxStatements || (count & (count - 1)) != 0) revert BadBatchShape();

        // 1) 逐证明配平 + program_hash 跨证明一致
        for (uint256 j = 0; j < proofs.length; ++j) {
            if (pubLists[j].length != 2 * n + 1) revert BadPublicInputsLength();
            if (pubLists[j][0] != pubLists[0][0]) revert BadBatchShape();
            if (!verifier.verifyProof(proofs[j].a, proofs[j].b, proofs[j].c, pubLists[j])) {
                revert BadProof();
            }
        }

        // 2) 全批语句 keccak 根重算（leaf_i = keccak256(uint32(i) ‖ ph ‖ hb ‖ fact)）
        uint256 programHash = pubLists[0][0];
        bytes32[] memory level = new bytes32[](count);
        for (uint256 j = 0; j < proofs.length; ++j) {
            for (uint256 i = 0; i < n; ++i) {
                uint256 idx = j * n + i;
                level[idx] = keccak256(
                    abi.encodePacked(uint32(idx), programHash, pubLists[j][1 + 2 * i], pubLists[j][2 + 2 * i])
                );
            }
        }
        while (level.length > 1) {
            uint256 nextLen = level.length / 2;
            for (uint256 i = 0; i < nextLen; ++i) {
                level[i] = keccak256(abi.encodePacked(level[2 * i], level[2 * i + 1]));
            }
            assembly {
                mstore(level, nextLen)
            }
        }
        if (level[0] != keccakRoot) revert RootMismatch();
        if (settledRoots[keccakRoot]) revert AlreadySettledRoot();
        settledRoots[keccakRoot] = true;

        // 3) 逐手入账（同一 hand_binding 全局一次性）
        for (uint256 j = 0; j < proofs.length; ++j) {
            for (uint256 i = 0; i < n; ++i) {
                uint256 hb = pubLists[j][1 + 2 * i];
                if (settledFact[hb] != 0) revert DuplicateBinding();
                settledFact[hb] = pubLists[j][2 + 2 * i];
            }
        }

        emit BatchSettled(msg.sender, keccakRoot, programHash, proofs.length, count);
    }

    /// @notice 批内单手 fact 读回（未结算 = 0）。
    function batchFactOf(uint256 handBinding) external view returns (uint256) {
        return settledFact[handBinding];
    }
}
