// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @notice groth16-wrap 批量包裹电路（BN254，N=4 条语句/证明）的
///         Groth16 verifier。
/// @dev 由 poker_texas_air/groth16-wrap 的 `gen-sol-batch --sub-n 4`
///      生成，VK 来自固定种子单方仪式 —— **测试网口径**；主网部署必须换
///      MPC powers-of-tau ceremony。公开输入 2N+1 =
///      [program_hash, hand_binding_1, fact_1, …, hand_binding_N, fact_N]，
///      语义与单手电路逐字段相同（N 份并列、共享 program_hash 绑定）。
///      同形状电路共享本 VK：生产 64 手 = 4 × N16 证明连验，即同一 VK。
///      本合约 **不验证 STARK**。
contract Groth16VerifierBatch {
    // BN254 基域（EIP-197 alt_bn128 Fp）
    uint256 internal constant P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    uint256 internal constant SUB_N = 4;
    uint256 internal constant NUM_PUBS = 9;

    // ---- Verifying Key（gen-sol-batch 注入；G2 字序 = EIP-197 (虚部 c1, 实部 c0)；
    //      solc 0.8 不支持数组型 constant，全部展开为标量） ----
    uint256 internal constant VK_ALPHA1_X = 0x229a9bba3e2ec298421ee522cbe43bf85c7a6520cff8040932df6fd00ec91299;
    uint256 internal constant VK_ALPHA1_Y = 0x089b02f449d88577eb97bb1de2cd706d6bce159d305eeedc2f120fd59d627e87;
    uint256 internal constant VK_BETA2_0 = 0x2db156a56688e73d697c5c955e0f4feae0244debd46583b3f4cc89239208cc04;
    uint256 internal constant VK_BETA2_1 = 0x054a5c7f2ef53a63c982f9e0a8789c4195006760dade42c87b22038cb22454a9;
    uint256 internal constant VK_BETA2_2 = 0x11dd77b7501816361b5dc528314f0864c9fcc5903f10ee11186bacba8076f5f4;
    uint256 internal constant VK_BETA2_3 = 0x26fe1e63176ef4a7cf8562cd980f05d1e992b9cbf28eb5d20d3dfe9ea202e329;
    uint256 internal constant VK_GAMMA2_0 = 0x13bfc874545c7adc450a1e087d17c9942f775be5dc2b7d5089f88d91def4e896;
    uint256 internal constant VK_GAMMA2_1 = 0x2a2df1e80152bbfd96b18e8f534016216a0b16234fdb85b9136f4137be794473;
    uint256 internal constant VK_GAMMA2_2 = 0x0801fa0f37bc3786fdd4c903d1c5ae2627dd39b558ee9c6951659562e372a2a4;
    uint256 internal constant VK_GAMMA2_3 = 0x2b55caf98584b2394b1d0aa560ebd002e6a17539c02aca49a5077995f9983ec5;
    uint256 internal constant VK_DELTA2_0 = 0x19d65d0aac55a4e7ae9d7351fb909bb9de7a691756df9688f83e86e18f80f63b;
    uint256 internal constant VK_DELTA2_1 = 0x215f18a3fcb939e8da53b1f187c4b38efa235317188d10c9a125838ecb2b1d82;
    uint256 internal constant VK_DELTA2_2 = 0x17cc0c58b35060ee50d78791138f0a395fb438af9d4b586c86db2e95b64bcc43;
    uint256 internal constant VK_DELTA2_3 = 0x2b323d1aed273d1989498e5bf97154fe33368339f86992b3fd4408f393210df1;
    uint256 internal constant VK_IC0_X = 0x15b5c296a3d83a21985f11bcd87b5d7842f9f2abc5f275c84ed2c73237b6e2bf;
    uint256 internal constant VK_IC0_Y = 0x1aa7445f09105304282e2705d4b37aaee4a309bd1f96b562da508affa3971c32;
    uint256 internal constant VK_IC1_X = 0x23d379d7c2effd3f3c719aaed7e0e3c8508d6d571c581de2be6f47bfc2354380;
    uint256 internal constant VK_IC1_Y = 0x2b2842343e2dd10859464f7ffc7080ef823c7d2c426e8aea589eb1e7cdbe8b9b;
    uint256 internal constant VK_IC2_X = 0x2fa2130c7f6d742f9eea8916c15a8f5c78852c299491a9ff3f2ec29c4877eb86;
    uint256 internal constant VK_IC2_Y = 0x18d8b46569504ac40b6f03b4994197947ed4306bae94a6d2ad2a7ea4a6a509e5;
    uint256 internal constant VK_IC3_X = 0x295c4654ec095a37863f816df2009c1b750cc3f24019eb4fb9e39db7531586f7;
    uint256 internal constant VK_IC3_Y = 0x24f83108d2d5e4886f457a1ce536b72f4449495827a2e8eabf3c320b197ba73a;
    uint256 internal constant VK_IC4_X = 0x1dee61f1f6e1a9c87f9c4d7362ef9eb683e383118b617d86746d996f20a121c4;
    uint256 internal constant VK_IC4_Y = 0x1c512aaf5a7396d749fd16c6d6baa534b9e3e0b5b9442cc8b55cb2e14fdc0fa0;
    uint256 internal constant VK_IC5_X = 0x22c3eb6c3a2bcc3705b59f8e5439bdbb60e32bfbba5d4ef8f77dc11d72f18902;
    uint256 internal constant VK_IC5_Y = 0x17809da9dbc8826b66edda899b00d828ac6e8b9e480e3ab87b674e66a483f90a;
    uint256 internal constant VK_IC6_X = 0x2cc8795b28cfc817c8c0023500a01ffcfcd8363bb9a1b23fb2389cb0071e7b9d;
    uint256 internal constant VK_IC6_Y = 0x2df888884526a152e4a8321db43257ac09b64291c07d6dc6ce4572c600e12674;
    uint256 internal constant VK_IC7_X = 0x227e3e061573c680221ce23bb8db150b57e07b7e4a4385b667ac1e34d5831e57;
    uint256 internal constant VK_IC7_Y = 0x03754655f0b910011b05bca35f865b97b6bb92e3a2d8993c2ef0e9f3ec24b07f;
    uint256 internal constant VK_IC8_X = 0x08aa5964900a1225210effad6892db93cc30101685d56262c17aaa68c79b945f;
    uint256 internal constant VK_IC8_Y = 0x16f9aa6ac25467b62322ff8ab019085212834100709c348254c6ccdb933960d7;
    uint256 internal constant VK_IC9_X = 0x1e341c250b10c3668a9575945cb7a3d20fb3206e569cee714c27e1c27774e44e;
    uint256 internal constant VK_IC9_Y = 0x0bb4f9f71864d4ae4358e322365be734404fa99529656b4d91629155d0e5d21b;

    error PairingPrecompileFailed();
    error EcOpPrecompileFailed();
    error BadPublicInputsLength();

    /// @notice 验证一个批量证明（覆盖 4 条语句）。
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata _pubSignals
    ) external view returns (bool) {
        if (_pubSignals.length != NUM_PUBS) revert BadPublicInputsLength();
        // vk_x = IC0 + Σ pubSignals[i] · IC(i+1)（0x07 拒绝 ≥p 非规范标量
        // → 公开输入隐式域检查）
        uint256[2] memory vkx = [VK_IC0_X, VK_IC0_Y];
        uint256[2][10] memory ic;
        ic[0] = [VK_IC0_X, VK_IC0_Y];
        ic[1] = [VK_IC1_X, VK_IC1_Y];
        ic[2] = [VK_IC2_X, VK_IC2_Y];
        ic[3] = [VK_IC3_X, VK_IC3_Y];
        ic[4] = [VK_IC4_X, VK_IC4_Y];
        ic[5] = [VK_IC5_X, VK_IC5_Y];
        ic[6] = [VK_IC6_X, VK_IC6_Y];
        ic[7] = [VK_IC7_X, VK_IC7_Y];
        ic[8] = [VK_IC8_X, VK_IC8_Y];
        ic[9] = [VK_IC9_X, VK_IC9_Y];

        uint256[2] memory q;
        for (uint256 i = 0; i < _pubSignals.length; ++i) {
            q = ic[i + 1];
            vkx = _mulAdd(vkx, _pubSignals[i], q);
        }
        return _pairingCheck(_pA, _pB, _pC, vkx);
    }

    /// vk_x = p + s·q：先 0x07 求 q·s，再 0x06 加到 p。
    function _mulAdd(
        uint256[2] memory p,
        uint256 s,
        uint256[2] memory q
    ) internal view returns (uint256[2] memory) {
        (bool okM, bytes memory outM) = address(0x07).staticcall(
            abi.encodePacked(q[0], q[1], s)
        );
        if (!okM || outM.length != 64) revert EcOpPrecompileFailed();
        (uint256 mx, uint256 my) = abi.decode(outM, (uint256, uint256));
        (bool okA, bytes memory outA) = address(0x06).staticcall(
            abi.encodePacked(p[0], p[1], mx, my)
        );
        if (!okA || outA.length != 64) revert EcOpPrecompileFailed();
        uint256[2] memory out;
        (out[0], out[1]) = abi.decode(outA, (uint256, uint256));
        return out;
    }

    /// Groth16 配平：e(-A, B) · e(vk_x, γ) · e(C, δ) == e(α, β)。
    /// 分段拼接 bytes 以规避 stack too deep（不开 via-IR）。
    function _pairingCheck(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[2] memory vkx
    ) internal view returns (bool) {
        // EIP-197 每对 192B：G1(x, y) + G2(X_i, X_r, Y_i, Y_r)
        bytes memory segA = abi.encodePacked(_pA[0], _neg(_pA[1]), _pB[0][0], _pB[0][1], _pB[1][0], _pB[1][1]);
        bytes memory segG = abi.encodePacked(vkx[0], vkx[1], VK_GAMMA2_0, VK_GAMMA2_1, VK_GAMMA2_2, VK_GAMMA2_3);
        bytes memory segC = abi.encodePacked(_pC[0], _pC[1], VK_DELTA2_0, VK_DELTA2_1, VK_DELTA2_2, VK_DELTA2_3);
        bytes memory segV = abi.encodePacked(VK_ALPHA1_X, VK_ALPHA1_Y, VK_BETA2_0, VK_BETA2_1, VK_BETA2_2, VK_BETA2_3);
        bytes memory input = bytes.concat(segA, segG, segC, segV);
        (bool ok, bytes memory out) = address(0x08).staticcall(input);
        if (!ok || out.length != 32) revert PairingPrecompileFailed();
        return abi.decode(out, (bool));
    }

    function _neg(uint256 v) internal pure returns (uint256) {
        unchecked {
            return v == 0 ? 0 : P - v;
        }
    }
}
