// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @notice groth16-wrap 单手包裹电路（BN254）的 Groth16 verifier。
/// @dev 由 poker_texas_air/groth16-wrap 的 `gen-sol` 生成，VK 常量来自固定
///      种子的单方仪式 —— **测试网口径**；主网部署必须换 MPC powers-of-tau
///      ceremony 并重新生成 VK。
///      语句（3 个公开输入）：[program_hash, hand_binding, fact]，语义为
///      fact == poseidon_hash_many([program_hash ‖ output]) 且 output 形状
///      合法且 output[5] == hand_binding。本合约 **不验证 STARK**。
contract Groth16Verifier {
    // BN254 基域（EIP-197 alt_bn128 Fp）
    uint256 internal constant P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // ---- Verifying Key（gen-sol 注入；G2 字序 = EIP-197 (虚部 c1, 实部 c0)；
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
    uint256 internal constant VK_IC0_X = 0x13ecf783140e207fdd5fb5a1455ca86b1de9463b4c8a737c5c5b99af440cd56d;
    uint256 internal constant VK_IC0_Y = 0x06105c964dc195610658c475971bcb967417ecedf5f2fc2c6d965732bdf8dc0f;
    uint256 internal constant VK_IC1_X = 0x0b447623a87298eb1d1f48ce7643b925cf6a2e4c0400e96491d2a6402d43733b;
    uint256 internal constant VK_IC1_Y = 0x207f00ace3caf27b4d528f67ad41537219e754fd442a0642894e2bb8f2c201a1;
    uint256 internal constant VK_IC2_X = 0x1d7a8ec437fee8e9f9148484e39a957e4dcaa3c6e330a1bc018d59a5d694e143;
    uint256 internal constant VK_IC2_Y = 0x03f40e99a742b63a70d7c1d3e6c17ecc28a59eb50c11d0943dea6831d90e5bf2;
    uint256 internal constant VK_IC3_X = 0x24cd4581a7cfacd5b3ef39ddff559dc7f4ca7cb05cbfbfaeeece1b3fd7b9cf76;
    uint256 internal constant VK_IC3_Y = 0x00eb58ddf5ffea01caace38d7ffe7a916f526467903b94041fc6803302c189fe;

    error PairingPrecompileFailed();
    error EcOpPrecompileFailed();

    /// @notice 验证单手包裹证明。
    /// @param _pA 证明 A（G1 [x, y]）
    /// @param _pB 证明 B（G2，EVM 字序 [[X_i, X_r], [Y_i, Y_r]]（Fp2 虚部在
    ///        前，EIP-197 a·i+b 编码；与 wrap-proof 产物 JSON 的 proof.b_evm
    ///        一致）——配平输入直接铺入
    /// @param _pC 证明 C（G1 [x, y]）
    /// @param _pubSignals [programHash, handBinding, fact]
    /// @dev 拆小函数避免 stack too deep（不开 via-IR，与 build_solc.sh 口径一致）。
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[3] calldata _pubSignals
    ) external view returns (bool) {
        // vk_x = IC0 + Σ pubSignals[i] · IC(i+1)
        // （0x07 拒绝 ≥p 的非规范标量 → 公开输入隐式域检查）
        uint256[2] memory vkx = [VK_IC0_X, VK_IC0_Y];
        vkx = _mulAdd(vkx, _pubSignals[0], VK_IC1_X, VK_IC1_Y);
        vkx = _mulAdd(vkx, _pubSignals[1], VK_IC2_X, VK_IC2_Y);
        vkx = _mulAdd(vkx, _pubSignals[2], VK_IC3_X, VK_IC3_Y);
        uint256[2] memory a = [_pA[0], _pA[1]];
        uint256[2][2] memory b = [_pB[0], _pB[1]];
        uint256[2] memory c = [_pC[0], _pC[1]];
        return _pairingCheck(a, b, c, vkx);
    }

    /// vk_x = p + s·q：先 0x07 求 q·s（标量乘 **IC 点**），再 0x06 加到 p。
    /// （初版误把累加元做了标量乘——金向量 forge 测试钉出的 bug。）
    function _mulAdd(
        uint256[2] memory p,
        uint256 s,
        uint256 qx,
        uint256 qy
    ) internal view returns (uint256[2] memory) {
        (bool okM, bytes memory outM) = address(0x07).staticcall(
            abi.encodePacked(qx, qy, s)
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
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory vkx
    ) internal view returns (bool) {
        // EIP-197 每对 192B：G1(x, y) + G2(X_i, X_r, Y_i, Y_r)；calldata 的
        // _pB 已是 EVM 字序，直接铺入
        bytes memory segA = abi.encodePacked(a[0], _neg(a[1]), b[0][0], b[0][1], b[1][0], b[1][1]);
        bytes memory segG = abi.encodePacked(vkx[0], vkx[1], VK_GAMMA2_0, VK_GAMMA2_1, VK_GAMMA2_2, VK_GAMMA2_3);
        bytes memory segC = abi.encodePacked(c[0], c[1], VK_DELTA2_0, VK_DELTA2_1, VK_DELTA2_2, VK_DELTA2_3);
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
