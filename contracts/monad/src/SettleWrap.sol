// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @notice SettleWrap —— 单手 STARK→Groth16 包裹的 Monad 结算入口。
///
/// 电路语句（3 个公开输入 [programHash, handBinding, fact]）由 groth16-wrap
/// 电路（upstream arkworks 0.5，BN254）生成：fact ==
/// poseidon_hash_many([program_hash ‖ output])、output 形状合法（长度前缀
/// 15 + 'SP2M_OK'）、output[5] == hand_binding（反拼装绑定）。
///
/// # 信任边界（务必知悉，勿当去信任事实引用）
/// 1. **Trusted setup**：Groth16Verifier 的 VK 来自 groth16-wrap 固定种子的
///    单方仪式 —— 测试网口径可接受；主网必须换 MPC powers-of-tau ceremony
///    并重新部署 verifier。
/// 2. **不验证 STARK**：链上命题只是上述 hash 一致性，NOT「存在合法 STARK
///    证明」。STARK 真伪由链下 fact-verify（stwo verify_cairo + 程序哈希
///    钉扎 0x744d16d3…）与运营方把关；被攻破的 operator 可以包装任意格式
///    良好的伪造 output 上链。本合约体现的是「operator 背书 + 电路一致」。
contract SettleWrap {
    Groth16Verifier public immutable verifier;

    /// hand_binding → fact（0 = 未结算；单手生命周期内一次性）。
    mapping(uint256 => uint256) public settledFact;

    event WrapSettled(uint256 indexed programHash, uint256 indexed handBinding, uint256 fact);

    error BadProof();
    error AlreadySettled();

    constructor(address verifier_) {
        verifier = Groth16Verifier(verifier_);
    }

    /// @notice verifyProof 通过 → 登记 (hand_binding → fact) 并 emit
    ///         WrapSettled(programHash, handBinding, fact)。
    /// @param a 证明 A（G1 [x, y]）
    /// @param b 证明 B（G2，ark 顺序 [[x.c0, x.c1], [y.c0, y.c1]]，与
    ///          groth16-wrap wrap-proof 产物 JSON 的 proof.b 一致）
    /// @param c 证明 C（G1 [x, y]）
    /// @param pubSignals [programHash, handBinding, fact]
    function settle(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[3] calldata pubSignals
    ) external {
        if (!verifier.verifyProof(a, b, c, pubSignals)) revert BadProof();
        uint256 programHash = pubSignals[0];
        uint256 handBinding = pubSignals[1];
        uint256 fact = pubSignals[2];
        if (settledFact[handBinding] != 0) revert AlreadySettled();
        settledFact[handBinding] = fact;
        emit WrapSettled(programHash, handBinding, fact);
    }
}
