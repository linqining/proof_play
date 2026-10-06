// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @notice groth16-wrap 金向量（gen-sol 生成；与 Groth16Verifier.sol 的 VK
///         同一次固定种子 setup 产出）。
/// @dev calldata 字序：G2 为 EVM 字序 [i系数, 实系数]（= wrap-proof 产物
///         JSON 的 proof.b_evm）。solc 0.8 不支持数组型 constant ——
///         全部展开为标量；组装见 WrapSettle.t.sol。
library Golden {
    /// 证明 A（G1 x, y）。
    uint256 constant A0 = 0x0dedead646aab1f3544f12de9b27439dd711b480edef104cde6899c6c1358d3f;
    uint256 constant A1 = 0x16ed535890efc097a02baa78b7b1e13553f3a3a8b8fa426c993c8c7bae1215a9;
    /// 证明 B（G2，EVM/calldata 字序 [Xi, Xr, Yi, Yr]）。
    uint256 constant B0 = 0x284e2bd320301377e3d82e6f428ef6dc1fd686dc5d7037ae7e56d4c73edcdf22;
    uint256 constant B1 = 0x284dbbeb78c75406e04d0690d02f02037cfeccdfc7f826d992af9dd5385ef080;
    uint256 constant B2 = 0x1090e4e70edccdb8c46d720c5eac76b7394e2eeaefc0a2b69b5fc2272066c6ee;
    uint256 constant B3 = 0x06fbb473489311b42ad78310b116b843a337c6a64e63230fd9d4a02c2d9c1b44;
    /// 证明 C（G1 x, y）。
    uint256 constant C0 = 0x1d40de7330c6358bee9381150fbec62fa72d485932d1aab657549423a351198e;
    uint256 constant C1 = 0x14b3c69d4883a0fa0989a8fb296737af073ce27285422cd834b73cd2ff1eeb2a;
    /// 公开语句 [programHash, handBinding, fact]。
    uint256 constant PUB0 = 0x0744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4;
    uint256 constant PUB1 = 0x000000000000000000000000000000000000000000000000000000000000a6aa;
    uint256 constant PUB2 = 0x030675cf10171e01d672af7b19fcbd51c0e5f88bc8f5932186cc581e297c0ea5;
}
