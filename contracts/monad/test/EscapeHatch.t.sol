// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuthorityOwnable} from "../src/AuthorityOwnable.sol";
import {L1Inbox} from "../src/L1Inbox.sol";
import {L1Outbox} from "../src/L1Outbox.sol";
import {L1Bridge} from "../src/L1Bridge.sol";
import {EscapeHatch} from "../src/EscapeHatch.sol";

/// @notice EscapeHatch forge 测试（仿 L1Settlement.t.sol：setUp 本地部署 +
///         authority 接线、真实 depositNative 入资、鉴权 prank/expectRevert）。
///         余额根金向量由 Solidity 侧自算（域 zchain.vault.balance_root.v1，
///         叶 = sha256(DOMAIN‖0x00‖bytes20(player)‖u64LE(amount))）——
///         【待 Rust 对拍】：Rust 侧同式余额根实现落地后交叉验证（对标
///         monad-settlement crate 现有 withdrawal_root 交叉验证）。
contract EscapeHatchTest is Test {
    // EscapeHatch 存储槽：frozen(1B)+frozenAt(8B)+frozenTicketId(8B) 按声明
    // 序同槽打包（AuthorityOwnable 中 pendingAuthority 20B + paused 1B 同槽，
    // 故派生合约从槽 2 起）。R3-3 纵深防御分支注入需要回拨 frozenAt——槽位
    // 由模式匹配**自定位**（bit0=frozen==1 且高位两段与公开 getter 读数
    // 一致），不硬编码；定位失败立刻 revert 而不是假绿。

    address authority = makeAddr("authority");
    address player = makeAddr("player");
    address sentinel = makeAddr("sentinel");
    address submitter = makeAddr("submitter");
    address third = makeAddr("third");
    address recipient = makeAddr("recipient");

    L1Inbox inbox;
    L1Outbox outbox;
    L1Bridge bridge;
    EscapeHatch hatch;

    function setUp() public {
        bridge = new L1Bridge(authority);
        outbox = new L1Outbox(authority);
        inbox = new L1Inbox(authority);
        hatch = new EscapeHatch(authority, address(bridge), address(inbox));
        // 互联边均为 onlyAuthority（与生产一致：由 authority 发起）。
        vm.startPrank(authority);
        outbox.setInbox(address(inbox));
        outbox.setBridge(address(bridge));
        inbox.setOutbox(address(outbox));
        bridge.setOutbox(address(outbox));
        // 冻结卫兵接线（三合约各自一次性 setEscapeHatch）。
        inbox.setEscapeHatch(address(hatch));
        outbox.setEscapeHatch(address(hatch));
        bridge.setEscapeHatch(address(hatch));
        // genesis 余额根（同 Deploy.s.sol：index 0 豁免 Inbox 对账，空账本
        // 规范根 = 空叶哈希，leafCount = 0）。
        hatch.registerBalanceRoot(0, hatch.emptyLeafHash(), 0);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------
    // 通用 helper
    // ------------------------------------------------------------------

    function _fundBridge(uint256 amount) private {
        // 走真实入金路径（冻结前；冻结期 depositNative 被卫兵挡住）。
        vm.deal(third, amount);
        vm.prank(third);
        bridge.depositNative{value: amount}(third);
    }

    function _registerGenesis() internal view returns (bytes32) {
        return hatch.emptyLeafHash();
    }

    function _anchorInboxUpTo(uint64 idx) internal {
        vm.startPrank(authority);
        for (uint64 i = inbox.batchCount(); i <= idx; ++i) {
            inbox.submitBatch(i, bytes32(uint256(0x1000 + i)), uint64(100 + i));
        }
        vm.stopPrank();
    }

    function _fileTicket(address p, address by) internal returns (uint64) {
        // 注意：TICKET_BOND() 是外部调用，必须先于 vm.prank 取值——否则会
        // 消耗 prank 使 forcedWithdraw 以测试合约身份执行。
        uint256 bond = hatch.TICKET_BOND();
        vm.deal(by, bond);
        vm.prank(by);
        hatch.forcedWithdraw{value: bond}(p);
        return hatch.openTicketOf(p);
    }

    /// 冻结并把时钟推到 unfreeze 可用时点（frozenAt + MIN_FREEZE_DURATION）。
    function _freezeAndMature(uint64 ticketId) internal {
        vm.warp(block.timestamp + hatch.TICKET_TIMEOUT() + 1);
        hatch.freeze(ticketId); // permissionless：test 合约即任意第三方
        vm.warp(block.timestamp + hatch.MIN_FREEZE_DURATION());
    }

    function _rewindFrozenAt(uint64 newFrozenAt) internal {
        for (uint256 s; s < 20; ++s) {
            bytes32 slot = bytes32(s);
            uint256 v = uint256(vm.load(address(hatch), slot));
            // 模式匹配：bit0 = frozen(1)、bits 8-71 = frozenAt、bits 72-135 =
            // frozenTicketId，后两段须与公开 getter 读数一致。
            if (
                v & 1 == 1 && uint64(v >> 8) == hatch.frozenAt()
                    && uint64(v >> 72) == hatch.frozenTicketId()
            ) {
                v &= ~(uint256(type(uint64).max) << 8);
                v |= uint256(newFrozenAt) << 8;
                vm.store(address(hatch), slot, bytes32(v));
                assertEq(hatch.frozenAt(), newFrozenAt, "frozenAt rewind failed");
                return;
            }
        }
        revert("frozen packed slot not found");
    }

    // ------------------------- 余额根树（测试侧自算，待 Rust 对拍）---------

    function _domain() private pure returns (bytes memory) {
        return bytes("zchain.vault.balance_root.v1");
    }

    function _le64(uint64 v) internal pure returns (bytes memory) {
        bytes memory o = new bytes(8);
        for (uint256 i; i < 8; ++i) o[i] = bytes1(uint8(v >> (8 * i)));
        return o;
    }

    function _leaf(address p, uint64 amount) internal view returns (bytes32) {
        return sha256(abi.encodePacked(_domain(), hex"00", bytes20(p), _le64(amount)));
    }

    function _node(bytes32 l, bytes32 r) internal view returns (bytes32) {
        return sha256(abi.encodePacked(_domain(), hex"01", l, r));
    }

    function _emptyLeaf() internal view returns (bytes32) {
        return sha256(abi.encodePacked(_domain(), hex"00"));
    }

    /// canonical 叶序 = player 地址升序（就地排序副本并返回），补空叶到 2 的幂。
    function _leafLevel(address[] memory players, uint64[] memory amounts)
        internal
        view
        returns (bytes32[] memory level, address[] memory sorted, uint64[] memory sortedAmounts)
    {
        sorted = players;
        sortedAmounts = amounts;
        for (uint256 i; i < sorted.length; ++i) {
            for (uint256 j = i + 1; j < sorted.length; ++j) {
                if (uint160(sorted[j]) < uint160(sorted[i])) {
                    (sorted[i], sorted[j]) = (sorted[j], sorted[i]);
                    (sortedAmounts[i], sortedAmounts[j]) = (sortedAmounts[j], sortedAmounts[i]);
                }
            }
        }
        uint256 size = 1;
        while (size < sorted.length) size *= 2;
        level = new bytes32[](size);
        for (uint256 i; i < sorted.length; ++i) level[i] = _leaf(sorted[i], sortedAmounts[i]);
        for (uint256 i = sorted.length; i < size; ++i) level[i] = _emptyLeaf();
    }

    function _balanceRoot(address[] memory players, uint64[] memory amounts) internal view returns (bytes32) {
        (bytes32[] memory level, , ) = _leafLevel(players, amounts);
        while (level.length > 1) {
            bytes32[] memory next = new bytes32[](level.length / 2);
            for (uint256 i; i < next.length; ++i) next[i] = _node(level[2 * i], level[2 * i + 1]);
            level = next;
        }
        return level[0];
    }

    function _proof(address[] memory players, uint64[] memory amounts, uint256 leafIdx)
        internal
        view
        returns (bytes32[] memory proof, address[] memory sorted, uint64[] memory sortedAmounts)
    {
        bytes32[] memory level;
        (level, sorted, sortedAmounts) = _leafLevel(players, amounts);
        uint256 depth;
        while ((level.length >> depth) > 1) ++depth;
        proof = new bytes32[](depth);
        uint256 li = leafIdx;
        for (uint256 d; d < depth; ++d) {
            proof[d] = (li & 1 == 0) ? level[li + 1] : level[li - 1];
            bytes32[] memory next = new bytes32[](level.length / 2);
            for (uint256 i; i < next.length; ++i) next[i] = _node(level[2 * i], level[2 * i + 1]);
            level = next;
            li >>= 1;
        }
    }

    function _sortedIdx(address[] memory sorted, address who) internal pure returns (uint256) {
        for (uint256 i; i < sorted.length; ++i) {
            if (sorted[i] == who) return i;
        }
        revert("who not in tree");
    }

    /// 单叶树准备：登记 (victim, amount) 为最新根 + 冻结 + 时钟就绪。
    function _prepareSingleLeafEscape(address victim, uint64 amount) internal returns (uint64 ticketId) {
        address[] memory ps = new address[](1);
        ps[0] = victim;
        uint64[] memory amts = new uint64[](1);
        amts[0] = amount;
        _anchorInboxUpTo(1);
        vm.startPrank(authority);
        hatch.registerBalanceRoot(1, _balanceRoot(ps, amts), 1);
        vm.stopPrank();
        ticketId = _fileTicket(player, player);
        _freezeAndMature(ticketId);
    }

    // ------------------------- Outbox 提现叶（wiring 测试用）--------------

    function _outboxLeafHash(L1Outbox.WithdrawalLeaf memory lf) internal view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                bytes("zchain.vault.withdrawal_root.v1"),
                hex"00",
                lf.requestId,
                lf.externalRecipient,
                bytes1(lf.assetTag),
                _le64(lf.amount),
                lf.burnedNoteCommitment,
                _le64(lf.checkpointHeight)
            )
        );
    }

    // ------------------------------------------------------------------
    // ① registerBalanceRoot：连续性 / genesis 豁免 / 锚定对账 / 冻结拒绝
    // ------------------------------------------------------------------

    function test_RegisterGenesis_ExemptFromInboxAnchor() public view {
        (bytes32 root, uint64 leafCount, uint64 l1Block) = hatch.balanceRoots(0);
        assertEq(root, _registerGenesis());
        assertEq(uint256(leafCount), 0);
        assertTrue(l1Block != 0);
        assertEq(uint256(hatch.balanceRootCount()), 1);
        assertEq(uint256(hatch.latestBalanceBatch()), 0);
        // genesis 之后 register(1)：inbox 无 index 1 锚 → NotAnchored（读面对账生效）。
    }

    function test_Register_Index1_RequiresAnchoredBatch() public {
        bytes32 root = bytes32(uint256(0xa001));
        vm.prank(authority);
        vm.expectRevert(EscapeHatch.NotAnchored.selector);
        hatch.registerBalanceRoot(1, root, 3);
        _anchorInboxUpTo(1);
        vm.prank(authority);
        hatch.registerBalanceRoot(1, root, 3);
        (bytes32 stored, uint64 leafCount, ) = hatch.balanceRoots(1);
        assertEq(stored, root);
        assertEq(uint256(leafCount), 3);
        assertEq(uint256(hatch.latestBalanceBatch()), 1);
    }

    function test_Register_SkipIndexReverts() public {
        vm.prank(authority);
        vm.expectRevert(EscapeHatch.OutOfOrder.selector);
        hatch.registerBalanceRoot(2, bytes32(uint256(0x2)), 0); // 跳号
    }

    function test_Register_ZeroRootReverts() public {
        vm.prank(authority);
        vm.expectRevert(EscapeHatch.BadRoot.selector);
        hatch.registerBalanceRoot(1, bytes32(0), 0);
    }

    function test_Register_OnlyAuthority() public {
        vm.prank(third);
        vm.expectRevert(AuthorityOwnable.NotAuthority.selector);
        hatch.registerBalanceRoot(1, bytes32(uint256(0x1)), 0);
    }

    function test_Register_EmitsEvent() public {
        _anchorInboxUpTo(1);
        vm.expectEmit(true, true, true, true, address(hatch));
        emit EscapeHatch.BalanceRootRegistered(1, bytes32(uint256(0xb001)), 3, uint64(block.number));
        vm.prank(authority);
        hatch.registerBalanceRoot(1, bytes32(uint256(0xb001)), 3);
    }

    function test_Register_FrozenReverts() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        vm.prank(authority);
        vm.expectRevert(EscapeHatch.IsFrozen.selector);
        hatch.registerBalanceRoot(1, bytes32(uint256(0x1)), 0);
    }

    // ------------------------------------------------------------------
    // ② forcedWithdraw：押金 / 身份三分 / 一人一单
    // ------------------------------------------------------------------

    function test_ForcedWithdraw_ByPlayer_BondEscrowed() public {
        vm.deal(player, 1 ether);
        vm.prank(player);
        hatch.forcedWithdraw{value: 0.1 ether}(player);
        uint64 id = hatch.openTicketOf(player);
        assertEq(uint256(id), 1); // id 从 1 起
        (
            address tPlayer,
            address tSubmitter,
            uint64 createdAt,
            uint64 filedAt,
            EscapeHatch.TicketState st,
            uint256 bond
        ) = hatch.tickets(id);
        assertEq(tPlayer, player);
        assertEq(tSubmitter, player);
        assertEq(uint256(createdAt), uint256(uint64(block.timestamp)));
        assertEq(uint256(filedAt), uint256(hatch.balanceRootCount()));
        assertEq(uint256(st), uint256(EscapeHatch.TicketState.Open));
        assertEq(bond, 0.1 ether);
        assertEq(address(hatch).balance, 0.1 ether); // 押金入账
        assertEq(uint256(hatch.ticketCount()), 1);
    }

    function test_ForcedWithdraw_FiledAtRootCountIsAuditField() public {
        // filedAtRootCount = 提单时 balanceRootCount（纯审计，无链上强制）。
        _anchorInboxUpTo(1);
        vm.prank(authority);
        hatch.registerBalanceRoot(1, bytes32(uint256(0xa001)), 0);
        uint64 id = _fileTicket(player, player);
        (, , , uint64 filedAt, , ) = hatch.tickets(id);
        assertEq(uint256(filedAt), 2);
    }

    function test_ForcedWithdraw_BySentinel() public {
        vm.prank(authority);
        hatch.addSentinel(sentinel);
        uint64 id = _fileTicket(player, sentinel); // 哨兵代提
        assertEq(uint256(id), 1);
        (address tPlayer, address tSubmitter, , , , ) = hatch.tickets(id);
        assertEq(tPlayer, player);
        assertEq(tSubmitter, sentinel);
    }

    function test_ForcedWithdraw_NonSentinelReverts() public {
        vm.deal(third, 1 ether);
        vm.prank(third);
        vm.expectRevert(EscapeHatch.NotPlayerOrSentinel.selector);
        hatch.forcedWithdraw{value: 0.1 ether}(player); // 非本人且非哨兵
    }

    function test_ForcedWithdraw_OneTicketPerPlayer() public {
        _fileTicket(player, player);
        vm.deal(player, 1 ether);
        vm.prank(player);
        vm.expectRevert(EscapeHatch.TicketAlreadyOpen.selector);
        hatch.forcedWithdraw{value: 0.1 ether}(player);
    }

    function test_ForcedWithdraw_WrongBondReverts() public {
        vm.deal(player, 1 ether);
        vm.prank(player);
        vm.expectRevert(EscapeHatch.BadBond.selector);
        hatch.forcedWithdraw{value: 0.05 ether}(player);
    }

    function test_ForcedWithdraw_ZeroPlayerReverts() public {
        vm.deal(player, 1 ether);
        vm.prank(player);
        vm.expectRevert(AuthorityOwnable.ZeroAddress.selector);
        hatch.forcedWithdraw{value: 0.1 ether}(address(0));
    }

    function test_ForcedWithdraw_FrozenReverts() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        vm.deal(third, 1 ether);
        vm.prank(third);
        vm.expectRevert(EscapeHatch.IsFrozen.selector);
        hatch.forcedWithdraw{value: 0.1 ether}(third);
    }

    // ------------------------------------------------------------------
    // ③ freeze / unfreeze：窗口边界、原子恢复（R3-1）、时钟保护（R3-3）
    // ------------------------------------------------------------------

    function test_Freeze_BeforeWindowReverts_AtExactly7d() public {
        uint64 id = _fileTicket(player, player);
        vm.warp(block.timestamp + hatch.TICKET_TIMEOUT()); // == deadline：严格 > 不满足
        vm.expectRevert(EscapeHatch.TicketNotExpired.selector);
        hatch.freeze(id);
    }

    function test_Freeze_AnyoneAfterExpiry() public {
        uint64 id = _fileTicket(player, player);
        vm.warp(block.timestamp + hatch.TICKET_TIMEOUT() + 1); // +1 过期
        vm.expectEmit(true, true, true, true, address(hatch));
        emit EscapeHatch.Frozen(id, uint64(block.timestamp));
        vm.prank(third); // 任何人
        hatch.freeze(id);
        assertTrue(hatch.isFrozen());
        assertEq(uint256(hatch.frozenTicketId()), uint256(id));
        assertEq(uint256(hatch.frozenAt()), uint256(uint64(block.timestamp)));
        // 重复冻结
        vm.expectRevert(EscapeHatch.AlreadyFrozen.selector);
        hatch.freeze(id);
    }

    function test_Freeze_BadTicketId() public {
        vm.expectRevert(EscapeHatch.BadTicketId.selector);
        hatch.freeze(0);
        vm.expectRevert(EscapeHatch.BadTicketId.selector);
        hatch.freeze(99);
    }

    function test_Freeze_NonOpenTicketReverts() public {
        uint64 id = _fileTicket(player, player);
        vm.prank(authority);
        hatch.serveTicket(id);
        vm.expectRevert(EscapeHatch.TicketNotOpen.selector);
        hatch.freeze(id);
    }

    /// R3-1 死锁回归：正常 cadence（balanceRootCount == batchCount == N）下
    /// 冻结 → 单 tx unfreeze 不依赖 inbox（批次 N 未锚定也必须成功）→
    /// 解冻后 submitBatch + registerBalanceRoot 正常恢复。
    function test_Unfreeze_R3_1_DeadlockRegression() public {
        _anchorInboxUpTo(1);
        vm.prank(authority);
        hatch.registerBalanceRoot(1, bytes32(uint256(0xa001)), 0);
        assertEq(uint256(hatch.balanceRootCount()), 2);
        assertEq(uint256(inbox.batchCount()), 2);

        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        assertTrue(hatch.isFrozen());
        // 冻结期 submitBatch(2) 被卫兵挡住 → 批次 2 恒未锚定（旧设计在此死锁：
        // unfreeze 内嵌 registerBalanceRoot(2) 会因 NotAnchored revert）。
        vm.startPrank(authority);
        vm.expectRevert(L1Inbox.Frozen.selector);
        inbox.submitBatch(2, bytes32(uint256(0xa002)), 3);

        // 单 tx unfreeze：批次 2 未锚定的前提下必须成功。
        uint64[] memory ids = new uint64[](1);
        ids[0] = id;
        hatch.unfreeze(ids);
        vm.stopPrank();
        assertFalse(hatch.isFrozen());
        (, , , , EscapeHatch.TicketState st, ) = hatch.tickets(id);
        assertEq(uint256(st), uint256(EscapeHatch.TicketState.Served));
        assertEq(hatch.bondCredit(player), 0.05 ether); // 过期 50%
        assertEq(hatch.openTicketOf(player), 0);

        // 解冻后正常 cadence 自愈（新根走 submitBatch + register）。
        vm.startPrank(authority);
        inbox.submitBatch(2, bytes32(uint256(0xa002)), 3);
        hatch.registerBalanceRoot(2, bytes32(uint256(0xa002)), 0);
        vm.stopPrank();
        assertEq(uint256(hatch.latestBalanceBatch()), 2);
    }

    function test_Unfreeze_AtExactlyMinDuration_Succeeds() public {
        uint64 id = _fileTicket(player, player);
        vm.warp(block.timestamp + hatch.TICKET_TIMEOUT() + 1);
        hatch.freeze(id);
        uint64 frozenAt = hatch.frozenAt();
        vm.warp(uint256(frozenAt) + hatch.MIN_FREEZE_DURATION()); // == 下界：>= 满足
        uint64[] memory ids = new uint64[](1);
        ids[0] = id;
        vm.prank(authority);
        hatch.unfreeze(ids);
        assertFalse(hatch.isFrozen());
    }

    function test_Unfreeze_BeforeMinDuration_Reverts() public {
        uint64 id = _fileTicket(player, player);
        vm.warp(block.timestamp + hatch.TICKET_TIMEOUT() + 1);
        hatch.freeze(id);
        vm.warp(uint256(hatch.frozenAt()) + hatch.MIN_FREEZE_DURATION() - 1);
        uint64[] memory ids = new uint64[](1);
        ids[0] = id;
        vm.prank(authority);
        vm.expectRevert(EscapeHatch.FreezeTooEarly.selector);
        hatch.unfreeze(ids);
    }

    function test_Unfreeze_OnlyAuthority() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        uint64[] memory ids = new uint64[](1);
        ids[0] = id;
        vm.prank(third);
        vm.expectRevert(AuthorityOwnable.NotAuthority.selector);
        hatch.unfreeze(ids);
    }

    function test_Unfreeze_RequiresFrozen() public {
        uint64[] memory ids = new uint64[](0);
        vm.prank(authority);
        vm.expectRevert(EscapeHatch.NotFrozen.selector);
        hatch.unfreeze(ids);
    }

    function test_Unfreeze_EmptyList_UnlocksOnly() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        vm.prank(authority);
        hatch.unfreeze(new uint64[](0)); // 只解锁（触发器工单仍 Open——再冻结
        // 风险由运营纪律承担，见 unfreeze natspec）
        assertFalse(hatch.isFrozen());
        (, , , , EscapeHatch.TicketState st, ) = hatch.tickets(id);
        assertEq(uint256(st), uint256(EscapeHatch.TicketState.Open));
    }

    function test_Unfreeze_UnknownTicketInList_Reverts() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        uint64[] memory ids = new uint64[](1);
        ids[0] = 42;
        vm.prank(authority);
        vm.expectRevert(EscapeHatch.BadTicketId.selector);
        hatch.unfreeze(ids);
    }

    /// R3-3 时钟保护：unfreeze 只清冻结触发器，未过期工单关不掉（玩家等待
    /// 时钟不被重置）。该分支在当前常量组合（TICKET_TIMEOUT ==
    /// MIN_FREEZE_DURATION == 7d）下经公开入口不可达（冻结前提 = 工单已过期
    /// ⇒ unfreeze 时点必晚于全部 Open 工单 deadline），属纵深防御——用
    /// vm.store 把 frozenAt 回拨注入（槽位假设由 _rewindFrozenAt 读回断言
    /// 兜底）。
    function test_Unfreeze_UnexpiredTicket_R3_3_ClockGuard() public {
        vm.warp(1_000_000);
        uint64 id = _fileTicket(player, player);
        (, , uint64 createdAt, , , ) = hatch.tickets(id);
        vm.warp(uint256(createdAt) + hatch.TICKET_TIMEOUT() + 1);
        hatch.freeze(id);
        vm.warp(uint256(createdAt) + hatch.TICKET_TIMEOUT()); // == deadline：工单未过期
        _rewindFrozenAt(createdAt); // unfreeze 恰好可解锁（>= frozenAt + 7d）
        uint64[] memory ids = new uint64[](1);
        ids[0] = id;
        vm.prank(authority);
        vm.expectRevert(EscapeHatch.TicketNotExpired.selector);
        hatch.unfreeze(ids);
        // 状态未被触碰：仍冻结、工单仍 Open。
        assertTrue(hatch.isFrozen());
        (, , , , EscapeHatch.TicketState st, ) = hatch.tickets(id);
        assertEq(uint256(st), uint256(EscapeHatch.TicketState.Open));
    }

    /// R3-3 错误类修正：过期单全部关毕后第三方再 freeze(同 id) →
    /// TicketNotOpen（非 Frozen——frozen 位已清）。
    function test_Unfreeze_ThenRefreezeAttempt_TicketNotOpen() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        uint64[] memory ids = new uint64[](1);
        ids[0] = id;
        vm.prank(authority);
        hatch.unfreeze(ids);
        vm.expectRevert(EscapeHatch.TicketNotOpen.selector);
        hatch.freeze(id);
    }

    // ------------------------------------------------------------------
    // ④ 押金经济：及时 100% / 过期 50% / 弃单 100% 没收；claimBond pull
    // ------------------------------------------------------------------

    function test_ServeTicket_Timely_FullBond100() public {
        uint64 id = _fileTicket(player, player); // submitter == player
        vm.prank(authority);
        hatch.serveTicket(id); // deadline 内及时 serve
        assertEq(hatch.bondCredit(player), 0.1 ether); // 100%
        assertEq(hatch.openTicketOf(player), 0);
        vm.prank(player);
        hatch.claimBond();
        assertEq(player.balance, 0.1 ether);
        assertEq(hatch.bondCredit(player), 0); // pull：先清零再转账
        // 双领
        vm.prank(player);
        vm.expectRevert(EscapeHatch.NothingToClaim.selector);
        hatch.claimBond();
    }

    function test_ServeTicket_OnlyAuthority() public {
        uint64 id = _fileTicket(player, player);
        vm.prank(third);
        vm.expectRevert(AuthorityOwnable.NotAuthority.selector);
        hatch.serveTicket(id);
    }

    function test_ServeTicket_FrozenReverts() public {
        uint64 id = _fileTicket(player, player);
        vm.warp(block.timestamp + hatch.TICKET_TIMEOUT() + 1);
        hatch.freeze(id);
        vm.prank(authority);
        vm.expectRevert(EscapeHatch.IsFrozen.selector);
        hatch.serveTicket(id); // 及时路径在冻结期不可用（过期单走 unfreeze 关单）
    }

    function test_ServeTicket_NonOpenReverts() public {
        uint64 id = _fileTicket(player, player);
        vm.prank(authority);
        hatch.serveTicket(id);
        vm.prank(authority);
        vm.expectRevert(EscapeHatch.TicketNotOpen.selector);
        hatch.serveTicket(id);
    }

    function test_Bond_ExpiredPath_FiftyPercent() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        uint64[] memory ids = new uint64[](1);
        ids[0] = id;
        vm.prank(authority);
        hatch.unfreeze(ids);
        assertEq(hatch.bondCredit(player), 0.05 ether); // 50%；另 50% 滞留
        vm.prank(player);
        hatch.claimBond();
        assertEq(player.balance, 0.05 ether);
        assertEq(address(hatch).balance, 0.05 ether); // 罚没部分滞留合约
    }

    function test_CancelTicket_ForfeitsAll() public {
        uint64 id = _fileTicket(player, player); // submitter == player
        vm.prank(third);
        vm.expectRevert(EscapeHatch.NotSubmitter.selector);
        hatch.cancelTicket(id); // 仅 submitter
        vm.prank(player);
        hatch.cancelTicket(id);
        (, , , , EscapeHatch.TicketState st, ) = hatch.tickets(id);
        assertEq(uint256(st), uint256(EscapeHatch.TicketState.Cancelled));
        assertEq(hatch.openTicketOf(player), 0);
        assertEq(hatch.bondCredit(player), 0); // 全额没收
        assertEq(address(hatch).balance, 0.1 ether); // 滞留合约
        vm.prank(player);
        vm.expectRevert(EscapeHatch.NothingToClaim.selector);
        hatch.claimBond();
    }

    function test_CancelTicket_AllowedDuringFreeze() public {
        uint64 id = _fileTicket(player, player);
        vm.warp(block.timestamp + hatch.TICKET_TIMEOUT() + 1);
        hatch.freeze(id);
        vm.prank(player);
        hatch.cancelTicket(id); // 任意时刻（含冻结期）；不解除 frozen 位
        assertTrue(hatch.isFrozen());
        (, , , , EscapeHatch.TicketState st, ) = hatch.tickets(id);
        assertEq(uint256(st), uint256(EscapeHatch.TicketState.Cancelled));
    }

    /// spam 全循环净成本 = bond/2（prank 不计 gas；链上另有 gas 成本）。
    function test_SpamCycle_NetCost_HalfBond() public {
        // spam 者须具备提单身份：哨兵白名单（或玩家本人）。
        vm.prank(authority);
        hatch.addSentinel(submitter);
        uint64 id = _fileTicket(player, submitter);
        vm.warp(block.timestamp + hatch.TICKET_TIMEOUT() + 1);
        hatch.freeze(id);
        vm.warp(block.timestamp + hatch.MIN_FREEZE_DURATION());
        uint64[] memory ids = new uint64[](1);
        ids[0] = id;
        vm.prank(authority);
        hatch.unfreeze(ids);
        vm.prank(submitter);
        hatch.claimBond();
        assertEq(submitter.balance, 0.05 ether); // dealt 0.1，净成本 0.05
    }

    // ------------------------------------------------------------------
    // 哨兵白名单管理
    // ------------------------------------------------------------------

    function test_Sentinel_AddRemove() public {
        vm.prank(authority);
        hatch.addSentinel(sentinel);
        assertTrue(hatch.sentinels(sentinel));
        uint64 id = _fileTicket(player, sentinel);
        assertEq(uint256(id), 1);
        vm.prank(authority);
        hatch.removeSentinel(sentinel);
        assertFalse(hatch.sentinels(sentinel));
        vm.deal(sentinel, 1 ether);
        vm.prank(sentinel);
        vm.expectRevert(EscapeHatch.NotPlayerOrSentinel.selector);
        hatch.forcedWithdraw{value: 0.1 ether}(player); // 摘除后不可再代提
    }

    // ------------------------------------------------------------------
    // ⑤ escape：金向量全链路 / 负例 / 一次性台账
    // ------------------------------------------------------------------

    function test_Escape_HappyPath_FourLeafTree() public {
        // 4 叶树（canonical 叶序 = 地址升序；2 的幂无需补空叶）。
        address[] memory ps = new address[](4);
        uint64[] memory amts = new uint64[](4);
        ps[0] = makeAddr("esc-a");
        ps[1] = makeAddr("esc-b");
        ps[2] = makeAddr("esc-c");
        ps[3] = makeAddr("esc-d");
        amts[0] = 1 ether;
        amts[1] = 2 ether;
        amts[2] = 3 ether;
        amts[3] = 4.5 ether;

        _anchorInboxUpTo(1);
        vm.startPrank(authority);
        hatch.registerBalanceRoot(1, _balanceRoot(ps, amts), 4);
        vm.stopPrank();

        _fundBridge(11 ether); // Bridge 浮存（真实 depositNative 路径）
        assertEq(address(bridge).balance, 11 ether);

        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        assertTrue(hatch.isFrozen());

        (bytes32[] memory proof, address[] memory sorted, uint64[] memory sortedAmts) = _proof(ps, amts, 0);
        address victim = sorted[0];
        uint64 amount = sortedAmts[0];

        // 第三方执行，款项打 player。
        vm.prank(third);
        hatch.escape(victim, amount, 0, proof);
        assertEq(victim.balance, uint256(amount));
        assertTrue(hatch.escaped(victim));
        assertEq(address(bridge).balance, 11 ether - uint256(amount));
        assertEq(address(hatch).balance, 0.1 ether); // 押金不受影响

        // 同树其余叶子仍可 escape（台账按 player 记）。
        (bytes32[] memory proof2, address[] memory sorted2, uint64[] memory sortedAmts2) = _proof(ps, amts, 3);
        vm.prank(third);
        hatch.escape(sorted2[3], sortedAmts2[3], 3, proof2);
        assertEq(sorted2[3].balance, uint256(sortedAmts2[3]));
    }

    function test_Escape_NotFrozenReverts() public {
        vm.prank(third);
        vm.expectRevert(EscapeHatch.NotFrozen.selector);
        hatch.escape(player, 1 ether, 0, new bytes32[](0));
    }

    function test_Escape_BadProof_Rejected_LedgerUnchanged() public {
        _fundBridge(2 ether); // 先入浮存（冻结期 depositNative 被卫兵挡住）
        _prepareSingleLeafEscape(player, 1 ether);
        uint256 bridgeBefore = address(bridge).balance;
        // 单叶树证明为空——伪造一个兄弟哈希即败。
        bytes32[] memory bad = new bytes32[](1);
        bad[0] = bytes32(uint256(0xdead));
        vm.prank(third);
        vm.expectRevert(EscapeHatch.BalanceProofInvalid.selector);
        hatch.escape(player, 1 ether, 0, bad);
        // 台账不变（可重试）。
        assertFalse(hatch.escaped(player));
        assertEq(address(bridge).balance, bridgeBefore);
        assertEq(player.balance, 0);
        // 正确证明重试成功。
        vm.prank(third);
        hatch.escape(player, 1 ether, 0, new bytes32[](0));
        assertEq(player.balance, 1 ether);
    }

    function test_Escape_IndexBeyondLeafCount() public {
        _prepareSingleLeafEscape(player, 1 ether);
        vm.prank(third);
        vm.expectRevert(EscapeHatch.IndexBeyondLeafCount.selector);
        hatch.escape(player, 1 ether, 1, new bytes32[](0)); // leafCount == 1
    }

    function test_Escape_AmountOverflow() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        vm.prank(third);
        vm.expectRevert(EscapeHatch.LeafAmountOverflow.selector);
        hatch.escape(player, uint256(type(uint64).max) + 1, 0, new bytes32[](0));
    }

    function test_Escape_DoubleEscape_AlreadyEscaped() public {
        _fundBridge(2 ether);
        _prepareSingleLeafEscape(player, 1 ether);
        vm.prank(third);
        hatch.escape(player, 1 ether, 0, new bytes32[](0));
        vm.prank(third);
        vm.expectRevert(EscapeHatch.AlreadyEscaped.selector);
        hatch.escape(player, 1 ether, 0, new bytes32[](0));
        assertEq(player.balance, 1 ether); // 未双付
    }

    function test_Escape_GenesisEmptyLedger_IndexBeyond() public {
        // 仅 genesis（leafCount = 0）：escape 无叶子可证 → IndexBeyond（正确语义）。
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        vm.prank(third);
        vm.expectRevert(EscapeHatch.IndexBeyondLeafCount.selector);
        hatch.escape(player, 1 ether, 0, new bytes32[](0));
    }

    function test_Escape_OnlyLatestRoot_StaleProofRejected() public {
        // 根 A（含 victim）之后登记根 B（不含 victim）：escape 只锚定
        // latestBalanceBatch 唯一根——旧根证明必须被拒（跨根套利防线）。
        address[] memory psA = new address[](2);
        uint64[] memory amtsA = new uint64[](2);
        psA[0] = player;
        psA[1] = makeAddr("peer-a");
        amtsA[0] = 1 ether;
        amtsA[1] = 1 ether;
        (bytes32[] memory proofA, , ) = _proof(psA, amtsA, 0);

        address[] memory psB = new address[](2);
        uint64[] memory amtsB = new uint64[](2);
        psB[0] = makeAddr("peer-b");
        psB[1] = makeAddr("peer-c");
        amtsB[0] = 1 ether;
        amtsB[1] = 1 ether;

        _anchorInboxUpTo(2);
        vm.startPrank(authority);
        hatch.registerBalanceRoot(1, _balanceRoot(psA, amtsA), 2);
        hatch.registerBalanceRoot(2, _balanceRoot(psB, amtsB), 2);
        vm.stopPrank();

        _fundBridge(4 ether);
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        vm.prank(third);
        // index 1 < leafCount 2（不触 IndexBeyond）——败在根不一致。
        vm.expectRevert(EscapeHatch.BalanceProofInvalid.selector);
        hatch.escape(player, 1 ether, 0, proofA);
        assertFalse(hatch.escaped(player));
    }

    // ------------------------------------------------------------------
    // ⑥ 冻结接线：三兄弟合约卫兵 / 未接线零回归 / claim 保留
    // ------------------------------------------------------------------

    function test_FreezeWire_InboxThreeEntries_Revert() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        vm.startPrank(authority);
        vm.expectRevert(L1Inbox.Frozen.selector);
        inbox.submitBatch(1, bytes32(uint256(0x1)), 1);
        vm.expectRevert(L1Inbox.Frozen.selector);
        inbox.submitAggregate(0, bytes32(uint256(0x1)), 1, 1);
        vm.expectRevert(L1Inbox.Frozen.selector);
        inbox.submitCheckpoint(7, bytes32(uint256(0x11)), bytes32(0), 0);
        vm.stopPrank();
    }

    function test_FreezeWire_BridgeDeposits_Revert() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        vm.deal(third, 1 ether);
        vm.startPrank(third);
        vm.expectRevert(L1Bridge.Frozen.selector);
        bridge.depositNative{value: 1 ether}(third);
        vm.expectRevert(L1Bridge.Frozen.selector);
        bridge.depositToken(address(0x1234), third, 1); // 卫兵先于 transferFrom
        vm.stopPrank();
    }

    function test_FreezeWire_OutboxCommitAndFinalize_Revert() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        bytes32 root = bytes32(uint256(0x9));
        // authority 直通口（commitAuth 的 authority 分支）一并堵死。
        vm.startPrank(authority);
        vm.expectRevert(L1Outbox.Frozen.selector);
        outbox.commitRoot(9, 0, root, false);
        bytes32 digest = outbox.digestOf(9, 0, root);
        vm.expectRevert(L1Outbox.Frozen.selector);
        outbox.markFinalized(digest);
        vm.stopPrank();
    }

    function test_FreezeWire_UnwiredStack_NoRegression() public {
        // 未接线（escapeHatch == 0）短路为零行为变化：冻结期新合约照常工作。
        L1Inbox freshInbox = new L1Inbox(authority);
        L1Bridge freshBridge = new L1Bridge(authority);
        vm.startPrank(authority);
        freshInbox.submitBatch(0, bytes32(uint256(0x1)), 1);
        vm.stopPrank();
        vm.deal(third, 1 ether);
        vm.prank(third);
        freshBridge.depositNative{value: 1 ether}(third);
    }

    function test_ForceOp_NotGuarded() public {
        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        vm.prank(third);
        bridge.forceOp(hex"0102"); // 有意不设卫兵（独立审查通道）
        assertEq(uint256(bridge.forcedOpSeq()), 1);
    }

    function test_FreezeWire_OutboxClaim_StillWorks_DuringFreeze() public {
        // 预冻结：authority 直提一个单叶提现根（finalized；延迟阈值未配置 = 0）。
        L1Outbox.WithdrawalLeaf memory lf = L1Outbox.WithdrawalLeaf({
            requestId: keccak256("req-esc"),
            externalRecipient: bytes32(uint256(uint160(recipient))),
            assetTag: 1,
            amount: 0.3 ether,
            burnedNoteCommitment: keccak256("burn-esc"),
            checkpointHeight: 7
        });
        bytes32 wroot = _outboxLeafHash(lf);
        vm.prank(authority);
        outbox.commitRoot(7, 1, wroot, true);
        _fundBridge(1 ether);

        uint64 id = _fileTicket(player, player);
        _freezeAndMature(id);
        // claim 有意不挂卫兵：预冻结窗保留可领，与 escape 竞争浮存先到先得。
        outbox.claim(lf, wroot, 1, 0, new bytes32[](0));
        assertEq(recipient.balance, 0.3 ether);
    }

    function test_SetEscapeHatch_Once_OnlyAuthority() public {
        address[] memory targets = new address[](3);
        // 借 bytes 转换拼三个已接线合约的 setEscapeHatch 调用面。
        vm.startPrank(third);
        vm.expectRevert(AuthorityOwnable.NotAuthority.selector);
        inbox.setEscapeHatch(third);
        vm.expectRevert(AuthorityOwnable.NotAuthority.selector);
        outbox.setEscapeHatch(third);
        vm.expectRevert(AuthorityOwnable.NotAuthority.selector);
        bridge.setEscapeHatch(third);
        vm.stopPrank();
        vm.startPrank(authority);
        vm.expectRevert(AuthorityOwnable.ZeroAddress.selector);
        inbox.setEscapeHatch(address(0));
        vm.expectRevert(L1Inbox.EscapeHatchAlreadySet.selector);
        inbox.setEscapeHatch(third);
        vm.expectRevert(L1Outbox.EscapeHatchAlreadySet.selector);
        outbox.setEscapeHatch(third);
        vm.expectRevert(L1Bridge.EscapeHatchAlreadySet.selector);
        bridge.setEscapeHatch(third);
        vm.stopPrank();
    }

    function test_Pause_DoesNotBlockEscapeOrUnfreeze() public {
        // R3-2：escape / unfreeze 有意不带 whenNotPaused——pause 不卡逃生与恢复。
        _fundBridge(1 ether);
        _prepareSingleLeafEscape(player, 1 ether);
        vm.prank(authority);
        hatch.pause();
        // 暂停语义照常约束常规入口。
        vm.prank(authority);
        vm.expectRevert(AuthorityOwnable.IsPaused.selector);
        hatch.registerBalanceRoot(1, bytes32(uint256(0x1)), 0);
        // 但逃生不被 pause 卡死。
        vm.prank(third);
        hatch.escape(player, 1 ether, 0, new bytes32[](0));
        assertEq(player.balance, 1 ether);
        // unfreeze（含关单）同样不被 pause 卡死。
        vm.warp(block.timestamp + hatch.MIN_FREEZE_DURATION());
        uint64[] memory ids = new uint64[](1);
        ids[0] = hatch.frozenTicketId();
        vm.prank(authority);
        hatch.unfreeze(ids);
        assertFalse(hatch.isFrozen());
    }

    // ------------------------------------------------------------------
    // ⑦ 重入：escape 回呼撞一次性台账；claimBond 回呼撞权限位
    // ------------------------------------------------------------------

    function test_Escape_ReentrantPlayer_HitsAlreadyEscaped() public {
        ReentrantPlayer attacker = new ReentrantPlayer(hatch);
        _fundBridge(1 ether);
        _prepareSingleLeafEscape(address(attacker), 0.7 ether);
        attacker.arm(0.7 ether, 0, new bytes32[](0));
        vm.prank(third);
        hatch.escape(address(attacker), 0.7 ether, 0, new bytes32[](0));
        // CEI：escaped 先置位 → 重入 escape 撞 AlreadyEscaped（真断言）。
        assertTrue(attacker.sawAlreadyEscaped());
        assertTrue(hatch.escaped(address(attacker)));
        assertEq(address(attacker).balance, 0.7 ether);
    }

    function test_ClaimBond_ReentrantServe_HitsNotAuthority() public {
        SubmitterTrap trap = new SubmitterTrap(hatch);
        uint256 bond = hatch.TICKET_BOND(); // 先取值（外部调用会消耗 prank）
        vm.deal(address(trap), bond);
        vm.prank(address(trap));
        uint64 id = trap.file{value: bond}();
        vm.prank(authority);
        hatch.serveTicket(id); // 及时 100% 贷记
        assertEq(hatch.bondCredit(address(trap)), 0.1 ether);
        // claimBond 打款回呼 serveTicket：撞 NotAuthority 权限位（工单此时已
        // Served——即便 authority 也会被 TicketNotOpen 挡；此处如实验证的是
        // 权限门位本身）。
        trap.claim();
        assertTrue(trap.sawNotAuthority());
        assertEq(address(trap).balance, 0.1 ether);
        assertEq(hatch.bondCredit(address(trap)), 0);
    }

    // ------------------------------------------------------------------
    // ⑧ fuzz（256 runs）：deadline 边界 + escaped/bondCredit 不变量
    // ------------------------------------------------------------------

    function testFuzz_Freezable_OnlyAfterTimeout(uint64 delta) public {
        delta = uint64(bound(uint256(delta), 0, 30 days));
        vm.warp(1_000_000);
        uint64 id = _fileTicket(player, player);
        vm.warp(1_000_000 + delta);
        if (delta <= hatch.TICKET_TIMEOUT()) {
            vm.expectRevert(EscapeHatch.TicketNotExpired.selector);
            hatch.freeze(id);
        } else {
            hatch.freeze(id);
            assertTrue(hatch.isFrozen());
        }
    }

    function testFuzz_Escape_OncePerPlayer_LedgerInvariants(uint160 seed, uint64 amount) public {
        amount = uint64(bound(uint256(amount), 1, uint256(type(uint64).max)));
        address victim = vm.addr(uint256(bound(uint256(seed), 1, uint256(type(uint160).max))));

        uint64 id = _prepareSingleLeafEscape(victim, amount);
        vm.deal(address(bridge), uint256(amount)); // 金向量测试同例：直注浮存
        vm.prank(third);
        hatch.escape(victim, amount, 0, new bytes32[](0));

        // escaped 一次性：余额精确等于叶子金额，二次 escape 拒绝，Bridge 出账精确。
        assertTrue(hatch.escaped(victim));
        assertEq(victim.balance, uint256(amount));
        assertEq(address(bridge).balance, 0);
        vm.expectRevert(EscapeHatch.AlreadyEscaped.selector);
        hatch.escape(victim, amount, 0, new bytes32[](0));

        // bondCredit 不变量：过期关单 50% → claimBond 清零到账。
        vm.prank(authority);
        hatch.unfreeze(_singleton(id));
        assertEq(hatch.bondCredit(player), hatch.TICKET_BOND() / 2);
        vm.prank(player);
        hatch.claimBond();
        assertEq(hatch.bondCredit(player), 0);
        assertEq(player.balance, hatch.TICKET_BOND() / 2);
    }

    function _singleton(uint64 id) private pure returns (uint64[] memory arr) {
        arr = new uint64[](1);
        arr[0] = id;
    }
}

/// 重入玩家：收到 escape 打款时以同一 (player, balance, leafIndex, proof)
/// 再入 escape——应撞 AlreadyEscaped（CEI 状态位先置）。必须吞掉自己的重入
/// revert 才能拿到钱（收款人主动 revert 会毒化 escapePayoutNative 的
/// call{value}，整笔 escape 回滚）。
contract ReentrantPlayer {
    EscapeHatch private immutable _hatch;
    uint256 private _balance;
    uint64 private _leafIndex;
    bytes32[] private _proof;
    bool public sawAlreadyEscaped;

    constructor(EscapeHatch hatch_) {
        _hatch = hatch_;
    }

    function arm(uint256 balance_, uint64 leafIndex_, bytes32[] calldata proof_) external {
        _balance = balance_;
        _leafIndex = leafIndex_;
        delete _proof;
        for (uint256 i; i < proof_.length; ++i) _proof.push(proof_[i]);
    }

    receive() external payable {
        // 打款方是 L1Bridge（escapePayoutNative 的 call{value}），不是 hatch
        // 本身——无条件尝试再入 escape 即可。
        try _hatch.escape(address(this), _balance, _leafIndex, _proof) {
            revert("reentrant escape unexpectedly succeeded");
        } catch (bytes memory reason) {
            if (bytes4(reason) == EscapeHatch.AlreadyEscaped.selector) {
                sawAlreadyEscaped = true;
            }
        }
    }
}

/// 押金领取回呼：claimBond 打款时回呼 serveTicket——撞 NotAuthority 权限位
/// （如实标注：serveTicket 是 authority 专属入口，与重入资金面无关）。
contract SubmitterTrap {
    EscapeHatch private immutable _hatch;
    uint64 private _ticketId;
    bool public sawNotAuthority;

    constructor(EscapeHatch hatch_) {
        _hatch = hatch_;
    }

    function file() external payable returns (uint64) {
        _hatch.forcedWithdraw{value: msg.value}(address(this));
        _ticketId = _hatch.openTicketOf(address(this));
        return _ticketId;
    }

    function claim() external {
        _hatch.claimBond();
    }

    receive() external payable {
        try _hatch.serveTicket(_ticketId) {
            revert("serveTicket unexpectedly succeeded");
        } catch (bytes memory reason) {
            if (bytes4(reason) == AuthorityOwnable.NotAuthority.selector) {
                sawNotAuthority = true;
            }
        }
    }
}
