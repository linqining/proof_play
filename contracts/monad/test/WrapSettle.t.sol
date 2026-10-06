// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {SettleWrap} from "../src/SettleWrap.sol";
import {Golden} from "./WrapGoldenVector.sol";

/// @notice groth16-wrap 金向量链上验证测试。
///
/// 金向量（test/WrapGoldenVector.sol，gen-sol 生成）来自 poker_texas_air/
/// groth16-wrap 固定种子 trusted setup + 真实形状 settlement 公开段。
/// 本测试把 Rust 侧 roundtrip（cargo test -p groth16-wrap）与 EVM 侧
/// verifyProof 对拍：同一 (VK, proof, publics) 必须双侧同为 true。
contract WrapSettleTest is Test {
    // BN254 标量域 r（篡改测试的取模用）
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    Groth16Verifier verifier;
    SettleWrap settle;

    function setUp() public {
        verifier = new Groth16Verifier();
        settle = new SettleWrap(address(verifier));
    }

    function _a() internal pure returns (uint256[2] memory a) {
        a = [Golden.A0, Golden.A1];
    }

    function _b() internal pure returns (uint256[2][2] memory b) {
        // EVM/calldata 字序（EIP-197 Fp2 虚部在前），Golden 常量即此顺序
        b[0] = [Golden.B0, Golden.B1];
        b[1] = [Golden.B2, Golden.B3];
    }

    function _c() internal pure returns (uint256[2] memory c) {
        c = [Golden.C0, Golden.C1];
    }

    function _pubs() internal pure returns (uint256[3] memory pubs) {
        pubs = [Golden.PUB0, Golden.PUB1, Golden.PUB2];
    }

    /// 金向量证明链上 verifyProof == true（真实 3 公开输入 Groth16 配平）。
    function test_GoldenProofVerifiesOnEvm() public view {
        assertTrue(verifier.verifyProof(_a(), _b(), _c(), _pubs()));
    }

    /// 篡改公开输入（fact+1 mod r）→ 配平失败，verifyProof == false。
    function test_TamperedFactRejected() public view {
        uint256[3] memory pubs = _pubs();
        pubs[2] = (pubs[2] + 1) % R;
        assertFalse(verifier.verifyProof(_a(), _b(), _c(), pubs));
    }

    /// settle：verifyProof 通过 → WrapSettled 事件 + (handBinding → fact) 登记。
    function test_SettleEmitsAndRegisters() public {
        vm.expectEmit(true, true, false, true, address(settle));
        emit SettleWrap.WrapSettled(Golden.PUB0, Golden.PUB1, Golden.PUB2);
        settle.settle(_a(), _b(), _c(), _pubs());
        assertEq(settle.settledFact(Golden.PUB1), Golden.PUB2);
    }

    /// 同一 hand_binding 二次结算必须 revert（一次性语义）。
    function test_DoubleSettleReverts() public {
        settle.settle(_a(), _b(), _c(), _pubs());
        vm.expectRevert(SettleWrap.AlreadySettled.selector);
        settle.settle(_a(), _b(), _c(), _pubs());
    }

    /// 假证明（handBinding+1）settle 必须 revert（BadProof）。
    function test_BadProofReverts() public {
        uint256[3] memory bad = _pubs();
        bad[1] = (bad[1] + 1) % R;
        vm.expectRevert(SettleWrap.BadProof.selector);
        settle.settle(_a(), _b(), _c(), bad);
    }
}
