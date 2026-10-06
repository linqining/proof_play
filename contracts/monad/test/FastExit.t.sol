// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuthorityOwnable} from "../src/AuthorityOwnable.sol";
import {L1Inbox} from "../src/L1Inbox.sol";
import {L1Outbox} from "../src/L1Outbox.sol";
import {L1Bridge} from "../src/L1Bridge.sol";
import {EscapeHatch} from "../src/EscapeHatch.sol";
import {FastExit} from "../src/FastExit.sol";

/// @notice FastExit forge 测试（计划 = 草案 fastexit-advance-design.md §七 A–J，
///         外加任务书不变量 1–8 的正反例）。基建照搬 L1Settlement/EscapeHatch
///         测试模式：setUp 本地全栈部署 + authority 接线、提现叶哈希/单叶树
///         helper 复用 EscapeHatch.t.sol 的 _outboxLeafHash/_le64 同构实现、
///         expectRevert(selector)/expectEmit(四 true) 断言、重入陷阱合约置
///         文件尾。
///
/// # 与草案 §七的一处已上报偏离（F3）
///         草案 F3 要求 fuzz 断言 `floatLedger ≥ totalOutstanding`；实现
///         （FastExit.withdrawable natspec）明确该态可达可违（每笔垫付使
///         float−outstanding 下降 2X：出账 X + 在途锁 X，仅逐笔检查
///         float ≥ amount）。本文件改断言真实不变量：合约余额 ≥ totalCredits
///         （credit 恒有足额背书）+ 余额 ≥ floatLedger（claim 落账隔离），
///         并以专门用例钉扎 withdrawable 下限钳 0 语义（见 F2c）。
contract FastExitTest is Test {
    // ------------------------------------------------------------------
    // 金标准向量（python hashlib 独立计算，非 Solidity 预编译自算）：
    // sha256("zchain.fastexit.request.v1" ‖ bytes20(R) ‖ bytes12(nonce) ‖ uint8(3))
    // R = 0x1234…7890, nonce = 0x0102030405060708090a0b0c
    // ------------------------------------------------------------------
    address constant GOLDEN_R = address(0x1234567890123456789012345678901234567890);
    bytes12 constant GOLDEN_NONCE = 0x0102030405060708090a0b0c;
    bytes32 constant GOLDEN_BINDING = 0x4ad26460283e4f9ba437ad41607a2ea387fa9752688b4315070a2eeb8b567f92;

    address authority = makeAddr("authority");
    address operator = makeAddr("operator"); // 首任垫付热键（余额恒 0 起步，便于到账断言）
    address operator2 = makeAddr("operator2"); // 轮换后热键
    address treasury = makeAddr("treasury"); // 浮存出资方（fund() 任何人可注）
    address user = makeAddr("user"); // 用户 L1 收款地址 R
    address user2 = makeAddr("user2");
    address third = makeAddr("third"); // 任意第三方（代办 / 抢跑者）
    address attacker = makeAddr("attacker");

    L1Inbox inbox;
    L1Outbox outbox;
    L1Bridge bridge;
    EscapeHatch hatch;
    FastExit fastExit;
    USDTLikeToken mockUsdt; // tag3（USDT 式无返回值代币，覆盖低层 transfer 兼容路径）

    /// 测试内快速通道叶子专用 nonce（每测试独立取值避免跨根 requestId 复用）。
    bytes12 constant NONCE = 0x010000000000000000000001;
    bytes12 constant NONCE2 = 0x010000000000000000000002;

    /// 单叶树根高度计数器（每片叶子唯一高度 → digest 唯一）。
    uint64 private _nextHeight = 100;

    function setUp() public {
        bridge = new L1Bridge(authority);
        outbox = new L1Outbox(authority);
        inbox = new L1Inbox(authority);
        hatch = new EscapeHatch(authority, address(bridge), address(inbox));
        fastExit = new FastExit(authority, address(outbox), address(hatch));
        mockUsdt = new USDTLikeToken();

        // 互联边均为 onlyAuthority（镜像 EscapeHatch.t.sol setUp 全栈接线）。
        vm.startPrank(authority);
        outbox.setInbox(address(inbox));
        outbox.setBridge(address(bridge));
        inbox.setOutbox(address(outbox));
        bridge.setOutbox(address(outbox));
        inbox.setEscapeHatch(address(hatch));
        outbox.setEscapeHatch(address(hatch));
        bridge.setEscapeHatch(address(hatch));
        hatch.registerBalanceRoot(0, hatch.emptyLeafHash(), 0); // genesis
        outbox.setTokenForTag(3, address(mockUsdt));
        fastExit.setOperator(operator);
        vm.stopPrank();

        // Bridge 浮存（金向量测试同例：直注，L1Settlement.t.sol:235 模式）。
        vm.deal(address(bridge), 1_000 ether);
        mockUsdt.mint(address(bridge), 1_000_000 ether);

        // 浮存注入（唯一合法注资口 = fund()；由 treasury 注入，operator 余额
        // 恒 0 起步，回收/提取断言不掺底噪）。
        vm.deal(treasury, 100 ether);
        vm.prank(treasury);
        fastExit.fund{value: 10 ether}();
    }

    // ------------------------------------------------------------------
    // 通用 helper（提现叶哈希 = EscapeHatch.t.sol:217-230 同构复用）
    // ------------------------------------------------------------------

    function _le64(uint64 v) internal pure returns (bytes memory o) {
        o = new bytes(8);
        for (uint256 i; i < 8; ++i) o[i] = bytes1(uint8(v >> (8 * i)));
    }

    function _outboxLeafHash(L1Outbox.WithdrawalLeaf memory lf) internal pure returns (bytes32) {
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

    /// 快速通道叶子包：externalRecipient = FastExit、requestId = 绑定哈希、
    /// 单叶树（证明为空数组、leafCount = 1、index = 0）。
    struct FastLeaf {
        L1Outbox.WithdrawalLeaf leaf;
        address recipient; // 绑定哈希原像 R
        bytes12 nonce;
        bytes32 root;
    }

    function _fastLeaf(address recipient, bytes12 nonce, uint8 assetTag, uint64 amount)
        internal
        returns (FastLeaf memory f)
    {
        f.leaf = L1Outbox.WithdrawalLeaf({
            requestId: fastExit.requestBinding(recipient, nonce, assetTag),
            externalRecipient: bytes32(uint256(uint160(address(fastExit)))),
            assetTag: assetTag,
            amount: amount,
            burnedNoteCommitment: keccak256(abi.encodePacked("burn", recipient, nonce)),
            checkpointHeight: _nextHeight++
        });
        f.recipient = recipient;
        f.nonce = nonce;
        f.root = _outboxLeafHash(f.leaf);
    }

    /// 自定收款人叶子（外部收款人 = 指定地址；requestId 可自选），单叶树。
    function _customLeaf(bytes32 requestId, address leafRecipient, uint8 assetTag, uint64 amount)
        internal
        returns (FastLeaf memory f)
    {
        f.leaf = L1Outbox.WithdrawalLeaf({
            requestId: requestId,
            externalRecipient: bytes32(uint256(uint160(leafRecipient))),
            assetTag: assetTag,
            amount: amount,
            burnedNoteCommitment: keccak256(abi.encodePacked("burn-x", leafRecipient)),
            checkpointHeight: _nextHeight++
        });
        f.recipient = leafRecipient;
        f.nonce = 0;
        f.root = _outboxLeafHash(f.leaf);
    }

    /// 上锚（authority 直通口，finalized = true；大额延迟未配置 = 0）。
    function _commit(FastLeaf memory f) internal {
        vm.prank(authority);
        outbox.commitRoot(f.leaf.checkpointHeight, 1, f.root, true);
    }

    /// 空 proof（单叶树）。
    function _noProof() internal pure returns (bytes32[] memory p) {
        p = new bytes32[](0);
    }

    /// 冻结全栈（EscapeHatch 脚手架：玩家自提单 → 超时 → 任何人 freeze）。
    function _freezeStack() internal {
        uint256 bond = hatch.TICKET_BOND();
        vm.deal(user, bond);
        vm.prank(user);
        hatch.forcedWithdraw{value: bond}(user);
        uint64 id = hatch.openTicketOf(user);
        vm.warp(block.timestamp + hatch.TICKET_TIMEOUT() + 1);
        hatch.freeze(id); // permissionless
        assertTrue(hatch.isFrozen(), "freeze scaffold failed");
    }

    /// operator 注入 ERC20 浮存（mint + approve + fundToken）。
    function _fundTokenFloat(uint256 amount) internal {
        mockUsdt.mint(operator, amount);
        vm.startPrank(operator);
        mockUsdt.approve(address(fastExit), amount);
        fastExit.fundToken(address(mockUsdt), amount);
        vm.stopPrank();
    }

    /// fuzz 叶子专用 nonce（uint96 ↔ bytes12 恰为 96 位，低位不丢）。
    function _nonceOf(uint256 v) internal pure returns (bytes12) {
        return bytes12(uint96(v + 1));
    }

    // ==================================================================
    // A. advance 正例
    // ==================================================================

    /// A1 / 任务书不变量 3：tag1 全额垫付——同笔 tx 真实出账 + 三台账 + 事件，
    /// funder 快照固定为当时 operator。
    function test_Advance_Native_PaysRecipientAndBooksLedger() public {
        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.AdvancePaid(K, user, 1, 0.6 ether);
        vm.prank(operator);
        fastExit.advance(K, user, 1, 0.6 ether, NONCE);

        assertEq(user.balance, 0.6 ether, "recipient not paid in same tx");
        (address funder, address tkn, uint8 tg, uint128 amt, bool rt) = fastExit.advances(K);
        assertEq(funder, operator, "funder snapshot");
        assertEq(tkn, address(0), "tag1 -> native token key");
        assertEq(uint256(tg), 1);
        assertEq(uint256(amt), 0.6 ether, "accumulated advance X");
        assertFalse(rt, "not routed");
        assertEq(fastExit.totalOutstanding(address(0)), 0.6 ether, "outstanding increased");
        assertEq(fastExit.floatLedger(address(0)), 10 ether - 0.6 ether, "float paid out");
    }

    /// A2：同 requestId 多次垫付累加（绑定参数不变），recipient 到账累加。
    function test_Advance_RepeatedOnSameRequestId_Accumulates() public {
        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        vm.startPrank(operator);
        fastExit.advance(K, user, 1, 0.2 ether, NONCE);
        fastExit.advance(K, user, 1, 0.3 ether, NONCE);
        vm.stopPrank();
        (address funder,, uint8 tg, uint128 amt,) = fastExit.advances(K);
        assertEq(uint256(amt), 0.5 ether, "amounts accumulate");
        assertEq(funder, operator, "funder not rewritten");
        assertEq(uint256(tg), 1, "tag snapshot unchanged");
        assertEq(user.balance, 0.5 ether, "two pushes both received");
        assertEq(fastExit.totalOutstanding(address(0)), 0.5 ether);
        assertEq(fastExit.floatLedger(address(0)), 10 ether - 0.5 ether);
    }

    /// A3：tag3 ERC20 垫付（USDT 式无返回值代币）——fundToken → advance → push。
    function test_Advance_ERC20_USDTLike_PaysRecipientAndBooksLedger() public {
        _fundTokenFloat(500);
        bytes32 K = fastExit.requestBinding(user, NONCE, 3);
        vm.prank(operator);
        fastExit.advance(K, user, 3, 40, NONCE);
        assertEq(mockUsdt.balanceOf(user), 40, "ERC20 push received");
        assertEq(fastExit.floatLedger(address(mockUsdt)), 460, "token float paid out");
        assertEq(fastExit.totalOutstanding(address(mockUsdt)), 40);
        (, address tkn,,,) = fastExit.advances(K);
        assertEq(tkn, address(mockUsdt), "token snapshot = tokenForTag(3)");
    }

    /// A4：非 operator 拒；全新部署未设 operator 一切 advance 拒；authority
    /// 轮换后旧键失效、台账无损、新键可用。
    function test_Advance_OnlyOperator_RotationKeepsLedger() public {
        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        vm.prank(third);
        vm.expectRevert(FastExit.NotOperator.selector);
        fastExit.advance(K, user, 1, 0.1 ether, NONCE);

        // 未设 operator 的新部署：authority 本身也非 operator。
        FastExit fresh = new FastExit(authority, address(outbox), address(hatch));
        vm.prank(authority);
        vm.expectRevert(FastExit.NotOperator.selector);
        fresh.advance(K, user, 1, 0.1 ether, NONCE);

        // 轮换：事件 + 旧键失效 + 在途台账无损 + 新键垫付可用。
        vm.prank(operator);
        fastExit.advance(K, user, 1, 0.2 ether, NONCE);
        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.OperatorSet(operator2);
        vm.prank(authority);
        fastExit.setOperator(operator2);
        bytes32 K2 = fastExit.requestBinding(user2, NONCE2, 1);
        vm.prank(operator);
        vm.expectRevert(FastExit.NotOperator.selector);
        fastExit.advance(K2, user2, 1, 0.1 ether, NONCE2);
        vm.prank(operator2);
        fastExit.advance(K2, user2, 1, 0.1 ether, NONCE2);
        (,,,, bool rt) = fastExit.advances(K);
        assertFalse(rt);
        assertEq(fastExit.totalOutstanding(address(0)), 0.3 ether, "old ledger intact");
    }

    // ==================================================================
    // B. advance 反例
    // ==================================================================

    /// B1 / 任务书"虚报伪造 requestId 的垫付无法截留他人叶子资金"：
    /// operator 对用户叶子 K 伪造收款人（自己/错误 nonce/错误 tag）→ 绑定哈希
    /// 必拒、零台账；其后该叶子照常全额路由给真用户。
    function test_Advance_ForgedRecipient_CannotHijackLeaf_RevertsAndUserStillWhole() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        bytes32 K = f.leaf.requestId;

        // 攻击样本 1：把收款人伪造成 operator 自己。
        vm.startPrank(operator);
        vm.expectRevert(FastExit.RequestBindingMismatch.selector);
        fastExit.advance(K, operator, 1, 1 ether, NONCE);
        // 攻击样本 2：错误 nonce。
        vm.expectRevert(FastExit.RequestBindingMismatch.selector);
        fastExit.advance(K, user, 1, 1 ether, NONCE2);
        // 攻击样本 3：错误 tag（K 按 tag1 绑定）。
        vm.expectRevert(FastExit.RequestBindingMismatch.selector);
        fastExit.advance(K, user, 3, 1 ether, NONCE);
        vm.stopPrank();

        // 零台账（伪造垫付根本立不了账）。
        (address funder,,,,) = fastExit.advances(K);
        assertEq(funder, address(0), "forged advance must not book");
        assertEq(fastExit.totalOutstanding(address(0)), 0);

        // 用户叶子照常全额路由（X=0 → 全额 Y 归用户 credit）。
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), user), 1 ether, "user gets full amount");
        assertEq(fastExit.credits(address(0), operator), 0, "operator intercepts nothing");
    }

    /// B2a：tag2（PLAY 内部筹码）不可垫付 → UnsupportedAssetTag（绑定哈希按
    /// tag2 构造使校验先行通过，专测 tag 纪律）。
    function test_Advance_Tag2Play_RevertsUnsupportedAssetTag() public {
        bytes32 K = fastExit.requestBinding(user, NONCE, 2);
        vm.prank(operator);
        vm.expectRevert(FastExit.UnsupportedAssetTag.selector);
        fastExit.advance(K, user, 2, 0.1 ether, NONCE);
    }

    /// B2b：tag0 越界 → UnsupportedAssetTag。
    function test_Advance_Tag0_RevertsUnsupportedAssetTag() public {
        bytes32 K = fastExit.requestBinding(user, NONCE, 0);
        vm.prank(operator);
        vm.expectRevert(FastExit.UnsupportedAssetTag.selector);
        fastExit.advance(K, user, 0, 0.1 ether, NONCE);
    }

    /// B2c：tag≥3 而 tokenForTag 未配置（tag4 未接线）→ TokenNotSet。
    function test_Advance_Tag4TokenNotSet_RevertsTokenNotSet() public {
        bytes32 K = fastExit.requestBinding(user, NONCE, 4);
        vm.prank(operator);
        vm.expectRevert(FastExit.TokenNotSet.selector);
        fastExit.advance(K, user, 4, 0.1 ether, NONCE);
    }

    /// B3a：amount=0 → BadAmount。
    function test_Advance_ZeroAmount_RevertsBadAmount() public {
        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        vm.prank(operator);
        vm.expectRevert(FastExit.BadAmount.selector);
        fastExit.advance(K, user, 1, 0, NONCE);
    }

    /// B3b / 不变量 4：已 routed 的 requestId 禁止再垫（杜绝用户总额 > Y）。
    function test_Advance_AfterRouted_RevertsAlreadyRouted() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        vm.prank(operator);
        vm.expectRevert(FastExit.AlreadyRouted.selector);
        fastExit.advance(f.leaf.requestId, user, 1, 0.1 ether, NONCE);
    }

    /// B4：浮存不足 → InsufficientFloat，零台账污染（含"先 withdraw 掏空再
    /// advance"时序）。
    function test_Advance_InsufficientFloat_RevertsNoLedgerPollution() public {
        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        // 直接超额。
        vm.prank(operator);
        vm.expectRevert(FastExit.InsufficientFloat.selector);
        fastExit.advance(K, user, 1, 10 ether + 1, NONCE);
        assertEq(fastExit.totalOutstanding(address(0)), 0, "failed advance leaves no outstanding");

        // 掏空时序：垫 0.4（float 9.6 / outstanding 0.4 → 可提 9.2）→ 提走全部
        // 可提 9.2（float 余 0.4）→ 再垫 0.5 > 0.4 必败。
        vm.prank(operator);
        fastExit.advance(K, user, 1, 0.4 ether, NONCE);
        vm.prank(operator);
        fastExit.operatorWithdraw(address(0), 9.2 ether);
        bytes32 K2 = fastExit.requestBinding(user2, NONCE2, 1);
        vm.prank(operator);
        vm.expectRevert(FastExit.InsufficientFloat.selector);
        fastExit.advance(K2, user2, 1, 0.5 ether, NONCE2);
        assertEq(fastExit.totalOutstanding(address(0)), 0.4 ether, "only first advance outstanding");
        assertEq(fastExit.floatLedger(address(0)), 0.4 ether, "float left = in-flight occupancy");
    }

    /// B5 / 不变量 3（记账与资金流同笔 tx 绑定）：recipient 为无 receive()
    /// 合约 → 整笔回滚、台账零污染。
    function test_Advance_RecipientWithoutReceive_RevertsWholeTxZeroLedger() public {
        NoReceiveRecipient noRecv = new NoReceiveRecipient();
        bytes32 K = fastExit.requestBinding(address(noRecv), NONCE, 1);
        vm.prank(operator);
        vm.expectRevert(FastExit.TokenTransferFailed.selector);
        fastExit.advance(K, address(noRecv), 1, 0.1 ether, NONCE);
        (address funder,,,,) = fastExit.advances(K);
        assertEq(funder, address(0), "no advances record");
        assertEq(fastExit.totalOutstanding(address(0)), 0, "totalOutstanding unchanged");
        assertEq(fastExit.floatLedger(address(0)), 10 ether, "floatLedger unchanged");
        assertEq(address(fastExit).balance, 10 ether, "funds untouched");
    }

    /// B6a / 不变量 5：冻结期（EscapeHatch frozen）advance 拒 → Frozen。
    function test_Advance_DuringFreeze_RevertsFrozen() public {
        _freezeStack();
        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        vm.prank(operator);
        vm.expectRevert(FastExit.Frozen.selector);
        fastExit.advance(K, user, 1, 0.1 ether, NONCE);
    }

    /// B6b / 不变量 5：FastExit 自身 pause 期 advance 拒 → IsPaused。
    function test_Advance_DuringPause_RevertsIsPaused() public {
        vm.prank(authority);
        fastExit.pause();
        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        vm.prank(operator);
        vm.expectRevert(AuthorityOwnable.IsPaused.selector);
        fastExit.advance(K, user, 1, 0.1 ether, NONCE);
    }

    /// B7：tokenForTag 重映射后对既有 requestId 追加垫付 → TokenRemapped
    /// （fail-closed，防跨资产错配）。
    function test_Advance_AfterTokenRemap_RevertsTokenRemapped() public {
        _fundTokenFloat(500);
        bytes32 K = fastExit.requestBinding(user, NONCE, 3);
        vm.prank(operator);
        fastExit.advance(K, user, 3, 10, NONCE);

        USDTLikeToken token2 = new USDTLikeToken();
        vm.prank(authority);
        outbox.setTokenForTag(3, address(token2));

        vm.prank(operator);
        vm.expectRevert(FastExit.TokenRemapped.selector);
        fastExit.advance(K, user, 3, 10, NONCE);
        // 首笔台账不受 remap 影响（amount 保持 10）。
        (,,, uint128 amt,) = fastExit.advances(K);
        assertEq(uint256(amt), 10);
    }

    // ==================================================================
    // C. claimAndRoute 正例
    // ==================================================================

    /// C1 / 不变量 1+2+5+7 核心正例：完整快路径（原生 X=0.6Y）——分流精确、
    /// 事件全字段、pull 后用户最终所得 ≡ Y、每叶总流出 = Y（Bridge 口径）。
    /// 注：本路径的 Bridge payout 回调 = FastExit.receive() 在 nonReentrant
    /// 持锁期间被调用（草案 H3：receive 有意不加守卫，此处即证明不自锁死）。
    function test_ClaimAndRoute_Native_SplitsAdvanceAndRemainder_UserFinalTotalEqualsLeaf() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        bytes32 K = f.leaf.requestId;
        vm.prank(operator);
        fastExit.advance(K, user, 1, 0.6 ether, NONCE);

        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.WithdrawalRouted(K, user, 1, 1 ether, 0.6 ether, 0.6 ether, 0.4 ether, true, operator);
        vm.prank(third); // 任何人可调（C4 一并在场验证）
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);

        assertEq(address(fastExit).balance, 10 ether - 0.6 ether + 1 ether, "claim lands Y");
        assertEq(fastExit.credits(address(0), user), 0.4 ether, "user remainder credit");
        assertEq(fastExit.credits(address(0), operator), 0.6 ether, "operator recovery credit");
        assertEq(fastExit.totalCredits(address(0)), 1 ether, "credit delta = Y");
        assertEq(fastExit.totalOutstanding(address(0)), 0, "outstanding reduced by full advance");
        assertEq(address(bridge).balance, 1_000 ether - 1 ether, "per-leaf outflow = Y (bridge float view unchanged)");
        (,,,, bool rt) = fastExit.advances(K);
        assertTrue(rt, "routed set exactly once");

        // pull 领取（代办）：用户最终所得 = 垫付 0.6 + 差额 0.4 ≡ Y。
        vm.prank(attacker);
        fastExit.claimCredit(address(0), user);
        vm.prank(attacker);
        fastExit.claimCredit(address(0), operator);
        assertEq(user.balance, 1 ether, "inv1: user final total == Y");
        assertEq(operator.balance, 0.6 ether, "operator recovers min(X,Y) = X");
        assertEq(address(fastExit).balance, 10 ether - 0.6 ether, "pool back after pulls");
    }

    /// C2 / 任务书"无垫付的快速通道叶子全额透传"：X=0 → claimAndRoute 即慢
    /// 路径，全额 Y 归用户 credit。
    function test_ClaimAndRoute_NoAdvance_FullLeafToUserCredit() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.WithdrawalRouted(f.leaf.requestId, user, 1, 1 ether, 0, 0, 1 ether, false, address(0));
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), user), 1 ether, "full Y to user");
        assertEq(fastExit.credits(address(0), operator), 0);
        vm.prank(user);
        fastExit.claimCredit(address(0), user);
        assertEq(user.balance, 1 ether);
    }

    /// 任务书/草案 §5.3 多垫自亏（X > Y）：operator 回收封顶 Y，多垫部分
    /// 不补偿；用户合计 X > Y（占优）。
    function test_ClaimAndRoute_OverAdvance_OperatorCappedAtLeafAmount_NoRefund() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(operator);
        fastExit.advance(f.leaf.requestId, user, 1, 1.5 ether, NONCE);
        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.WithdrawalRouted(f.leaf.requestId, user, 1, 1 ether, 1.5 ether, 1 ether, 0, true, operator);
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), operator), 1 ether, "recovery capped at Y");
        assertEq(fastExit.credits(address(0), user), 0, "user remainder 0 (already overpaid)");
        assertEq(fastExit.totalOutstanding(address(0)), 0, "outstanding reduced by full 1.5");
        assertEq(user.balance, 1.5 ether, "user total X > Y");
        vm.prank(operator);
        fastExit.claimCredit(address(0), operator);
        assertEq(operator.balance, 1 ether, "operator net loss 0.5, no refund");
        assertEq(address(fastExit).balance, 10 ether - 1.5 ether + 1 ether - 1 ether);
    }

    /// C3：ERC20 叶（tag3）同构快路径。
    function test_ClaimAndRoute_ERC20_SplitsCorrectly() public {
        _fundTokenFloat(500);
        FastLeaf memory f = _fastLeaf(user, NONCE, 3, 100);
        _commit(f);
        vm.prank(operator);
        fastExit.advance(f.leaf.requestId, user, 3, 40, NONCE);
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);

        assertEq(mockUsdt.balanceOf(address(fastExit)), 500 - 40 + 100, "token lands");
        assertEq(fastExit.credits(address(mockUsdt), user), 60);
        assertEq(fastExit.credits(address(mockUsdt), operator), 40);
        assertEq(fastExit.totalOutstanding(address(mockUsdt)), 0);
        vm.prank(third);
        fastExit.claimCredit(address(mockUsdt), user);
        assertEq(mockUsdt.balanceOf(user), 40 + 60, "token side user final total == Y");
    }

    /// C5：调用方 ≠ R（代办者无法冒领——款项只进 credit[R]，调用方零所得）。
    function test_ClaimAndRoute_CallerNotRecipient_FundsOnlyRecipientCredit() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(attacker); // 攻击者代办，提供正确 (R, nonce)
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), user), 1 ether, "funds only to credit[R]");
        assertEq(fastExit.credits(address(0), attacker), 0, "caller gets nothing");
    }

    // ==================================================================
    // D. claimAndRoute 反例
    // ==================================================================

    /// D1 / 防抽干回归：叶收款人 ≠ FastExit（普通叶子）→ LeafRecipientNotFastExit，
    /// 池余额分文未动（必须断言）。
    function test_ClaimAndRoute_LeafRecipientNotFastExit_Reverts_PoolUntouched() public {
        FastLeaf memory f = _customLeaf(keccak256("normal-leaf"), user, 1, 1 ether);
        _commit(f);
        vm.prank(third);
        vm.expectRevert(FastExit.LeafRecipientNotFastExit.selector);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(address(fastExit).balance, 10 ether, "pool balance untouched");
        assertEq(fastExit.totalCredits(address(0)), 0, "no credit minted");
        assertEq(address(bridge).balance, 1_000 ether, "bridge not paid (claim not reached)");
    }

    /// D2：绑定哈希不符（错 R / 错 nonce）→ RequestBindingMismatch。
    function test_ClaimAndRoute_WrongRecipientOrNonce_RevertsRequestBindingMismatch() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.startPrank(third);
        // 错 R：用 attacker 作为 R 提交。
        vm.expectRevert(FastExit.RequestBindingMismatch.selector);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), attacker, NONCE);
        // 错 nonce。
        vm.expectRevert(FastExit.RequestBindingMismatch.selector);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE2);
        vm.stopPrank();
    }

    /// D3a：根未上锚 → 透传 RootNotCommitted；台账原子还原，上锚后可重试。
    function test_ClaimAndRoute_RootNotCommitted_RevertsThenRetrySucceeds() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        // 未 commit。
        vm.prank(third);
        vm.expectRevert(L1Outbox.RootNotCommitted.selector);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        // claim 失败 → FastExit 侧台账原子还原（routed/credit 均未落）。
        assertEq(fastExit.credits(address(0), user), 0, "failed route mints no credit");
        assertEq(fastExit.totalCredits(address(0)), 0);
        assertEq(address(fastExit).balance, 10 ether);
        // 上锚后同一调用重试成功。
        _commit(f);
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), user), 1 ether);
    }

    /// D3b：根未 finalized → RootNotFinalized（透传）。
    function test_ClaimAndRoute_RootNotFinalized_Reverts() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        vm.prank(authority);
        outbox.commitRoot(f.leaf.checkpointHeight, 1, f.root, false);
        vm.prank(third);
        vm.expectRevert(L1Outbox.RootNotFinalized.selector);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
    }

    /// D3c：index 超 leafCount → IndexBeyondLeafCount（透传）。
    function test_ClaimAndRoute_IndexBeyondLeafCount_Reverts() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(third);
        vm.expectRevert(L1Outbox.IndexBeyondLeafCount.selector);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 5, _noProof(), user, NONCE);
    }

    /// D3d：证明篡改 → WithdrawalProofInvalid（透传；单叶树真证明为空，
    /// 伪造一个兄弟哈希即败）。
    function test_ClaimAndRoute_TamperedProof_Reverts() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        bytes32[] memory bad = new bytes32[](1);
        bad[0] = bytes32(uint256(0xdead));
        vm.prank(third);
        vm.expectRevert(L1Outbox.WithdrawalProofInvalid.selector);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, bad, user, NONCE);
    }

    /// D3e / 不变量 4：claimAndRoute 重放拒绝（FastExit 侧 routed 台账先于
    /// outbox AlreadyClaimed 触发）。
    function test_ClaimAndRoute_Replay_RevertsAlreadyRouted() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.startPrank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        vm.expectRevert(FastExit.AlreadyRouted.selector);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        vm.stopPrank();
        assertEq(fastExit.totalCredits(address(0)), 1 ether, "replay mints no extra credit");
    }

    /// D4：大额延迟窗口内 → ClaimTooEarly（透传，垫付部分 X 已即时到手不受
    /// 限制）；warp 过窗后成功。
    function test_ClaimAndRoute_LargePayout_ClaimTooEarlyThenSucceedsAfterDelay() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        vm.startPrank(authority);
        outbox.setLargePayoutThreshold(1, 0.5 ether); // 1 ether ≥ 阈值 → 30 块延迟
        outbox.commitRoot(f.leaf.checkpointHeight, 1, f.root, true);
        vm.stopPrank();
        vm.prank(operator);
        fastExit.advance(f.leaf.requestId, user, 1, 0.5 ether, NONCE);
        assertEq(user.balance, 0.5 ether, "advance part not delay-gated");

        vm.prank(third);
        vm.expectRevert(L1Outbox.ClaimTooEarly.selector);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        // 窗口内台账原子还原。
        assertEq(fastExit.credits(address(0), user), 0, "delay failure mints no credit");

        vm.roll(block.number + outbox.claimDelayBlocks());
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), user), 0.5 ether, "remainder arrives after window");
    }

    /// D5 / 任务书"垫付与叶子不匹配则全额归用户"（可达形态）：operator 把垫
    /// 付记在 tag3 绑定的 requestId 上（对 tag1 快速通道叶子而言是错误键）→
    /// 叶子路由时查无台账，全额 Y 归用户；错键垫付悬置为 operator 自亏。
    function test_ClaimAndRoute_AdvanceOnMismatchedTagRequestId_FullLeafToUser() public {
        _fundTokenFloat(500);
        // operator 垫到 tag3 绑定键（binding(user, nonce, 3) ≠ 叶子键）。
        bytes32 wrongKey = fastExit.requestBinding(user, NONCE, 3);
        vm.prank(operator);
        fastExit.advance(wrongKey, user, 3, 40, NONCE);
        assertEq(fastExit.totalOutstanding(address(mockUsdt)), 40);

        // 用户的 tag1 快速通道叶子照常路由：无台账 → 全额归用户。
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.WithdrawalRouted(f.leaf.requestId, user, 1, 1 ether, 0, 0, 1 ether, false, address(0));
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), user), 1 ether, "full amount to user");
        assertEq(fastExit.credits(address(0), operator), 0, "operator recovers 0");
        // 错键垫付悬置（在途不释放——operator 自担，信任边界 4）。
        assertEq(fastExit.totalOutstanding(address(mockUsdt)), 40, "wrong-key advance stuck");
    }

    /// D6：tokenForTag 重映射后路由 → 垫付判无效（token 快照 ≠ 当前映射）→
    /// operator 回收 0、全额（当前映射代币）归用户。
    function test_ClaimAndRoute_AfterTokenRemap_AdvanceInvalid_FullLeafToUser() public {
        _fundTokenFloat(500);
        FastLeaf memory f = _fastLeaf(user, NONCE, 3, 100);
        _commit(f);
        vm.prank(operator);
        fastExit.advance(f.leaf.requestId, user, 3, 40, NONCE);

        USDTLikeToken token2 = new USDTLikeToken();
        token2.mint(address(bridge), 1_000);
        vm.prank(authority);
        outbox.setTokenForTag(3, address(token2));

        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.WithdrawalRouted(f.leaf.requestId, user, 3, 100, 40, 0, 100, false, operator);
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        // claim 按当前映射支付 token2 → 全额 token2 归用户。
        assertEq(token2.balanceOf(address(fastExit)), 100, "token2 lands");
        assertEq(fastExit.credits(address(token2), user), 100, "full to user (token2)");
        assertEq(fastExit.credits(address(token2), operator), 0, "operator recovers 0");
        // 垫付在途按原 token 键全额了结（悬置解除、锁的是 operator 浮存）。
        assertEq(fastExit.totalOutstanding(address(mockUsdt)), 0);
    }

    /// 任务书不变量 6（路由侧 tag 纪律）：tag2 快速通道叶子不可路由——
    /// outbox.claim 的 tag 判定透传 UnsupportedAssetTag，且失败路由不铸
    /// 任何 credit（_split effects 随整笔回滚）。
    function test_ClaimAndRoute_Tag2Leaf_RevertsUnsupportedAssetTagFromOutbox() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 2, 1 ether);
        _commit(f);
        vm.prank(third);
        vm.expectRevert(L1Outbox.UnsupportedAssetTag.selector);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), user), 0, "tag2 mints no credit");
        assertEq(fastExit.totalCredits(address(0)), 0);
    }

    // ==================================================================
    // E. route（外部已 claim 叶子的补救分流）
    // ==================================================================

    /// E1：抢跑场景全流程——第三方直接 outbox.claim（FastExit 收款、未分流、
    /// 叶哈希台账已写）→ 任意人 route → 分流结果与 C1 逐字段一致。
    function test_Route_AfterFrontRunClaim_SplitsIdenticalToClaimAndRoute() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(operator);
        fastExit.advance(f.leaf.requestId, user, 1, 0.7 ether, NONCE);

        // 抢跑：attacker 直接 claim（permissionless），Y 落账 FastExit。
        vm.prank(attacker);
        outbox.claim(f.leaf, f.root, 1, 0, _noProof());
        assertEq(address(fastExit).balance, 10 ether - 0.7 ether + 1 ether, "landed but not split");
        assertEq(outbox.claimedLeafHashes(f.leaf.requestId), _outboxLeafHash(f.leaf), "leaf-hash ledger written");
        assertTrue(outbox.claimedLeafMatches(f.leaf));
        (,,,, bool rt) = fastExit.advances(f.leaf.requestId);
        assertFalse(rt, "not yet routed");
        assertEq(fastExit.credits(address(0), attacker), 0, "frontrunner gains nothing");

        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.WithdrawalRouted(f.leaf.requestId, user, 1, 1 ether, 0.7 ether, 0.7 ether, 0.3 ether, true, operator);
        vm.prank(third); // 任意人补救
        fastExit.route(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), operator), 0.7 ether, "identical to claimAndRoute: operator share");
        assertEq(fastExit.credits(address(0), user), 0.3 ether, "identical to claimAndRoute: user remainder");
        assertEq(fastExit.totalOutstanding(address(0)), 0);
    }

    /// E2：claim 之后、route 之前补垫付 → 合法且分流正确（时序自由度）。
    function test_Route_LateAdvanceBetweenClaimAndRoute_SplitsCorrectly() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(attacker);
        outbox.claim(f.leaf, f.root, 1, 0, _noProof()); // 先 claim（此时 X=0）
        vm.prank(operator); // 后补垫付（claim 后仍可垫，routed 未置位）
        fastExit.advance(f.leaf.requestId, user, 1, 0.5 ether, NONCE);
        assertEq(user.balance, 0.5 ether, "late advance paid instantly");
        vm.prank(third);
        fastExit.route(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), operator), 0.5 ether);
        assertEq(fastExit.credits(address(0), user), 0.5 ether);
        assertEq(fastExit.totalOutstanding(address(0)), 0);
    }

    /// E3a：从未被领取的叶 → NotYetClaimed。
    function test_Route_UnclaimedLeaf_RevertsNotYetClaimed() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(third);
        vm.expectRevert(FastExit.NotYetClaimed.selector);
        fastExit.route(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
    }

    /// E3b / 不变量 4：route 重放拒绝。
    function test_Route_Replay_RevertsAlreadyRouted() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        outbox.claim(f.leaf, f.root, 1, 0, _noProof());
        vm.startPrank(third);
        fastExit.route(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        vm.expectRevert(FastExit.AlreadyRouted.selector);
        fastExit.route(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        vm.stopPrank();
        assertEq(fastExit.totalCredits(address(0)), 1 ether, "replay mints no extra credit");
    }

    /// E3c：普通叶（收款人 ≠ FastExit）→ route 亦拒。
    function test_Route_LeafRecipientNotFastExit_Reverts() public {
        FastLeaf memory f = _customLeaf(keccak256("normal-leaf-route"), user, 1, 1 ether);
        _commit(f);
        outbox.claim(f.leaf, f.root, 1, 0, _noProof()); // 已被他人领走
        vm.prank(third);
        vm.expectRevert(FastExit.LeafRecipientNotFastExit.selector);
        fastExit.route(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
    }

    /// E3d：route 自持根判定——同 requestId 双叶中叶 B 的根从未上锚 →
    /// RootNotCommitted。
    function test_Route_RootNotCommitted_Reverts() public {
        // 叶 A（K）上锚并被领取。
        FastLeaf memory fa = _customLeaf(fastExit.requestBinding(user, NONCE, 1), attacker, 1, 1);
        _commit(fa);
        outbox.claim(fa.leaf, fa.root, 1, 0, _noProof());
        // 叶 B（同 K、收款人 = FastExit）的根从未上锚。
        FastLeaf memory fb = _fastLeaf(user, NONCE, 1, 5 ether);
        // fb.requestId 与 fa 相同（同一绑定原像）；fb 根未 commit。
        vm.prank(third);
        vm.expectRevert(FastExit.RootNotCommitted.selector);
        fastExit.route(fb.leaf, fb.root, 1, 0, _noProof(), user, NONCE);
    }

    /// E3e：证明篡改 → WithdrawalProofInvalid（route 自持校验）。
    function test_Route_TamperedProof_Reverts() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        outbox.claim(f.leaf, f.root, 1, 0, _noProof());
        bytes32[] memory bad = new bytes32[](1);
        bad[0] = bytes32(uint256(0xbeef));
        vm.prank(third);
        vm.expectRevert(FastExit.WithdrawalProofInvalid.selector);
        fastExit.route(f.leaf, f.root, 1, 0, bad, user, NONCE);
    }

    /// E4a / L1Outbox diff 回归：verifyInclusion 公开后对每个叶字段篡改敏感。
    function test_OutboxVerifyInclusion_Public_TamperSensitivePerField() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        assertTrue(outbox.verifyInclusion(f.leaf, _noProof(), 0, f.root), "genuine leaf passes");

        L1Outbox.WithdrawalLeaf memory t = f.leaf;
        t.requestId = bytes32(uint256(1));
        assertFalse(outbox.verifyInclusion(t, _noProof(), 0, f.root), "tampered requestId");
        t = f.leaf;
        t.externalRecipient = bytes32(uint256(uint160(attacker)));
        assertFalse(outbox.verifyInclusion(t, _noProof(), 0, f.root), "tampered externalRecipient");
        t = f.leaf;
        t.assetTag = 3;
        assertFalse(outbox.verifyInclusion(t, _noProof(), 0, f.root), "tampered assetTag");
        t = f.leaf;
        t.amount = 2 ether;
        assertFalse(outbox.verifyInclusion(t, _noProof(), 0, f.root), "tampered amount");
        t = f.leaf;
        t.burnedNoteCommitment = bytes32(uint256(2));
        assertFalse(outbox.verifyInclusion(t, _noProof(), 0, f.root), "tampered burnedNoteCommitment");
        t = f.leaf;
        t.checkpointHeight = f.leaf.checkpointHeight + 1;
        assertFalse(outbox.verifyInclusion(t, _noProof(), 0, f.root), "tampered checkpointHeight");
    }

    // ==================================================================
    // F. 领取与回收（solvency）
    // ==================================================================

    /// F1a：claimCredit 代办调用款项恒付 owner（原生与 ERC20）。
    function test_ClaimCredit_ByProxy_PaysOwner_NativeAndERC20() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.CreditClaimed(address(0), user, 1 ether);
        vm.prank(attacker); // 代办
        fastExit.claimCredit(address(0), user);
        assertEq(user.balance, 1 ether, "pays owner, not caller");
        assertEq(attacker.balance, 0);
        assertEq(fastExit.totalCredits(address(0)), 0);

        _fundTokenFloat(500);
        FastLeaf memory f2 = _fastLeaf(user2, NONCE2, 3, 100);
        _commit(f2);
        vm.prank(third);
        fastExit.claimAndRoute(f2.leaf, f2.root, 1, 0, _noProof(), user2, NONCE2);
        vm.prank(attacker);
        fastExit.claimCredit(address(mockUsdt), user2);
        assertEq(mockUsdt.balanceOf(user2), 100, "ERC20 credit also pays owner");
    }

    /// F1b：拒收合约领取 → 回滚可重试、credit 保留（pull 语义消灭拒收卡死）。
    function test_ClaimCredit_RevertingOwner_RevertsCreditPreserved() public {
        RevertingReceiver rr = new RevertingReceiver();
        FastLeaf memory f = _fastLeaf(address(rr), NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), address(rr), NONCE);
        assertEq(fastExit.credits(address(0), address(rr)), 1 ether, "pull model: split has no external call");

        vm.prank(third);
        vm.expectRevert(FastExit.TokenTransferFailed.selector);
        fastExit.claimCredit(address(0), address(rr));
        assertEq(fastExit.credits(address(0), address(rr)), 1 ether, "failed claim keeps credit");
        assertEq(fastExit.totalCredits(address(0)), 1 ether);
    }

    /// F2a / 不变量 7：operatorWithdraw 超额拒（floatLedger − totalOutstanding
    /// 为上界），恰额成功。
    function test_OperatorWithdraw_BeyondWithdrawable_Reverts_ExactSucceeds() public {
        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        vm.prank(operator);
        fastExit.advance(K, user, 1, 0.6 ether, NONCE);
        // float 9.4、outstanding 0.6 → withdrawable 8.8。
        assertEq(fastExit.withdrawable(address(0)), 8.8 ether);
        vm.prank(operator);
        vm.expectRevert(FastExit.ExceedsWithdrawable.selector);
        fastExit.operatorWithdraw(address(0), 8.8 ether + 1);
        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.OperatorWithdrew(address(0), 8.8 ether);
        vm.prank(operator);
        fastExit.operatorWithdraw(address(0), 8.8 ether);
        assertEq(operator.balance, 8.8 ether, "exact amount withdrawn");
        assertEq(fastExit.floatLedger(address(0)), 0.6 ether, "float left only covers outstanding");
    }

    /// F2b / 不变量 7 强化项（关键时序攻击回归）：外部抢跑 claim 落账 Y 后、
    /// route 前，operator 试图提走 Y → 必须被 floatLedger 隔离挡下；其后
    /// route + 用户领取仍足额（credit 恒有背书）。
    function test_OperatorWithdraw_CannotStealFrontRunClaimReceipt_BeforeRoute() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 2 ether);
        _commit(f);
        vm.prank(attacker);
        outbox.claim(f.leaf, f.root, 1, 0, _noProof()); // 抢先落账 2 ether
        assertEq(address(fastExit).balance, 12 ether);
        assertEq(fastExit.withdrawable(address(0)), 10 ether, "landed funds not withdrawable");

        vm.prank(operator);
        vm.expectRevert(FastExit.ExceedsWithdrawable.selector);
        fastExit.operatorWithdraw(address(0), 10 ether + 1); // 探入落账资金 1 wei 即拒
        vm.prank(operator);
        fastExit.operatorWithdraw(address(0), 10 ether); // 全部浮存可提（合法）
        assertEq(address(fastExit).balance, 2 ether, "landed Y stays in pool");

        vm.prank(third);
        fastExit.route(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        vm.prank(user);
        fastExit.claimCredit(address(0), user);
        assertEq(user.balance, 2 ether, "user paid in full (credit backed)");
        assertEq(address(fastExit).balance, 0);
    }

    /// F2c / 草案 F3 偏离的钉扎用例（见文件头说明）：单笔垫付 > 浮存一半即触
    /// 发 floatLedger < totalOutstanding 的**可达态**——withdrawable 钳 0
    /// （非算术下溢 Panic），route 后在途释放、可提恢复。
    function test_OperatorWithdraw_FloatBelowOutstanding_ClampsToZero_ThenRecovers() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(operator);
        fastExit.advance(f.leaf.requestId, user, 1, 6 ether, NONCE); // float 4 < outstanding 6
        assertEq(fastExit.floatLedger(address(0)), 4 ether);
        assertEq(fastExit.totalOutstanding(address(0)), 6 ether);
        assertEq(fastExit.withdrawable(address(0)), 0, "clamps to 0, no underflow panic");
        vm.prank(operator);
        vm.expectRevert(FastExit.ExceedsWithdrawable.selector);
        fastExit.operatorWithdraw(address(0), 1);

        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.totalOutstanding(address(0)), 0, "outstanding released");
        assertEq(fastExit.withdrawable(address(0)), 4 ether, "withdrawable restored");
        vm.prank(operator);
        fastExit.operatorWithdraw(address(0), 4 ether);
    }

    /// F3（修订版，见文件头）：原生 solvency fuzz——合法随机操作序列下，
    /// 池余额恒 ≥ totalCredits（credit 足额背书）且 ≥ floatLedger（claim
    /// 落账隔离）。
    function testFuzz_Solvency_Native_BalanceAlwaysBacksCredits(uint256 seed) public {
        _solvencyFuzz(seed, true);
    }

    /// F3（修订版）：ERC20（tag3）侧同构。
    function testFuzz_Solvency_ERC20_BalanceAlwaysBacksCredits(uint256 seed) public {
        _solvencyFuzz(seed, false);
    }

    /// fuzz 上下文（结构体化以控制栈深）。
    struct FuzzCtx {
        address token;
        uint8 tag;
        uint64 leafY;
        uint256 maxAdv;
        address[3] users;
        FastLeaf[3] leaves;
        uint256 settled; // bitmap：该叶已分流（claimAndRoute 或 route）
        uint256 extClaimed; // bitmap：该叶已被外部直领（route 待做）
    }

    function _solvencyFuzz(uint256 seed, bool isNative) internal {
        FuzzCtx memory ctx;
        ctx.token = isNative ? address(0) : address(mockUsdt);
        ctx.tag = isNative ? 1 : 3;
        ctx.leafY = isNative ? 1 ether : 100;
        ctx.maxAdv = isNative ? 0.4 ether : 40;
        if (!isNative) _fundTokenFloat(1_000);
        ctx.users = [makeAddr("fz-a"), makeAddr("fz-b"), makeAddr("fz-c")];
        for (uint256 i; i < 3; ++i) {
            ctx.leaves[i] = _fastLeaf(ctx.users[i], _nonceOf(i), ctx.tag, ctx.leafY);
            _commit(ctx.leaves[i]);
        }

        uint256 rng = seed;
        for (uint256 step; step < 10; ++step) {
            rng = uint256(keccak256(abi.encode(rng, step)));
            _solvencyStep(ctx, rng);
            _assertSolvency(ctx.token);
        }
    }

    function _solvencyStep(FuzzCtx memory ctx, uint256 rng) internal {
        uint256 op = rng % 6;
        uint256 which = (rng >> 32) % 3;
        uint256 amt = ((rng >> 64) % ctx.maxAdv) + 1;
        FastLeaf memory f = ctx.leaves[which];

        if (op == 0) {
            // 注资（原生 fund / ERC20 fundToken）。
            if (ctx.token == address(0)) {
                vm.deal(third, amt);
                vm.prank(third);
                fastExit.fund{value: amt}();
            } else {
                mockUsdt.mint(third, amt);
                vm.startPrank(third);
                mockUsdt.approve(address(fastExit), amt);
                fastExit.fundToken(ctx.token, amt);
                vm.stopPrank();
            }
        } else if (op == 1) {
            // 垫付（已分流叶禁垫 = AlreadyRouted；外部已领未分流叶仍可垫；
            // 浮存不足时该 op 是合法失败（InsufficientFloat）——前置条件跳过）。
            if (ctx.settled & (1 << which) == 0 && fastExit.floatLedger(ctx.token) >= amt) {
                vm.prank(operator);
                fastExit.advance(f.leaf.requestId, ctx.users[which], ctx.tag, uint64(amt), f.nonce);
            }
        } else if (op == 2) {
            // 快路径领取并分流。
            if (ctx.settled & (1 << which) == 0 && ctx.extClaimed & (1 << which) == 0) {
                vm.prank(third);
                fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), ctx.users[which], f.nonce);
                ctx.settled |= 1 << which;
            }
        } else if (op == 3) {
            // 抢跑外部直领 + 补救 route。
            if (ctx.settled & (1 << which) == 0 && ctx.extClaimed & (1 << which) == 0) {
                vm.prank(attacker);
                outbox.claim(f.leaf, f.root, 1, 0, _noProof());
                ctx.extClaimed |= 1 << which;
                vm.prank(third);
                fastExit.route(f.leaf, f.root, 1, 0, _noProof(), ctx.users[which], f.nonce);
                ctx.settled |= 1 << which;
            }
        } else if (op == 4) {
            // credit 领取（随机 owner，余额 > 0 才调）。
            address owner = ((rng >> 96) & 3) == 0 ? operator : ctx.users[(rng >> 104) % 3];
            if (fastExit.credits(ctx.token, owner) > 0) {
                vm.prank(third);
                fastExit.claimCredit(ctx.token, owner);
            }
        } else {
            // operator 提取：可提为 0 时显式断言拒绝，否则随机恰内额度成功。
            uint256 w = fastExit.withdrawable(ctx.token);
            if (w > 0) {
                vm.prank(operator);
                fastExit.operatorWithdraw(ctx.token, ((rng >> 112) % w) + 1);
            } else {
                vm.prank(operator);
                vm.expectRevert(FastExit.ExceedsWithdrawable.selector);
                fastExit.operatorWithdraw(ctx.token, 1);
            }
        }
    }

    /// solvency 不变量（每步断言）：池余额恒 ≥ totalCredits（credit 足额背书）
    /// 且 ≥ floatLedger（claim 落账与浮存隔离）。
    function _assertSolvency(address token) internal view {
        uint256 poolBal = token == address(0) ? address(fastExit).balance : mockUsdt.balanceOf(address(fastExit));
        assertGe(poolBal, fastExit.totalCredits(token), "solvency: balance < totalCredits");
        assertGe(poolBal, fastExit.floatLedger(token), "isolation: balance < floatLedger");
    }

    // ==================================================================
    // G. 冻结 / 暂停矩阵
    // ==================================================================

    /// G1 / 不变量 5：冻结期——advance 拒（Frozen）、claimAndRoute 放行、
    /// 外部直领 + route 放行、claimCredit 放行。
    function test_Frozen_AdvanceReverted_ClaimRouteAndCreditAllowed() public {
        FastLeaf memory f1 = _fastLeaf(user, NONCE, 1, 1 ether);
        FastLeaf memory f2 = _fastLeaf(user2, NONCE2, 1, 1 ether);
        _commit(f1); // 冻结前上锚
        _commit(f2);
        _freezeStack();

        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        vm.prank(operator);
        vm.expectRevert(FastExit.Frozen.selector);
        fastExit.advance(K, user, 1, 0.1 ether, NONCE);

        // claimAndRoute 不受冻结阻断。
        vm.prank(third);
        fastExit.claimAndRoute(f1.leaf, f1.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), user), 1 ether);

        // 外部直领（claim 无冻结卫兵）+ 补救 route 同样放行。
        vm.prank(attacker);
        outbox.claim(f2.leaf, f2.root, 1, 0, _noProof());
        vm.prank(third);
        fastExit.route(f2.leaf, f2.root, 1, 0, _noProof(), user2, NONCE2);
        assertEq(fastExit.credits(address(0), user2), 1 ether);

        // claimCredit 放行。
        vm.prank(user);
        fastExit.claimCredit(address(0), user);
        vm.prank(user2);
        fastExit.claimCredit(address(0), user2);
        assertEq(user.balance, 1 ether);
        assertEq(user2.balance, 1 ether);
    }

    /// G2a / 不变量 5：FastExit 自身 pause——advance/operatorWithdraw 拒；
    /// claimAndRoute/route/claimCredit 不受自身 pause 阻断。
    function test_Pause_FastExitOwn_AdvanceAndWithdrawReverted_UserFacesAllowed() public {
        FastLeaf memory f1 = _fastLeaf(user, NONCE, 1, 1 ether);
        FastLeaf memory f2 = _fastLeaf(user2, NONCE2, 1, 1 ether);
        _commit(f1);
        _commit(f2);
        vm.prank(attacker);
        outbox.claim(f2.leaf, f2.root, 1, 0, _noProof()); // pause 前外部直领

        vm.prank(authority);
        fastExit.pause();

        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        vm.prank(operator);
        vm.expectRevert(AuthorityOwnable.IsPaused.selector);
        fastExit.advance(K, user, 1, 0.1 ether, NONCE);
        vm.prank(operator);
        vm.expectRevert(AuthorityOwnable.IsPaused.selector);
        fastExit.operatorWithdraw(address(0), 1);

        vm.prank(third);
        fastExit.claimAndRoute(f1.leaf, f1.root, 1, 0, _noProof(), user, NONCE);
        vm.prank(third);
        fastExit.route(f2.leaf, f2.root, 1, 0, _noProof(), user2, NONCE2);
        vm.prank(user);
        fastExit.claimCredit(address(0), user);
        assertEq(user.balance, 1 ether, "user recovery face not blocked");
    }

    /// G2b / 草案 §5.7 栈传导：outbox pause（栈级）→ claimAndRoute 经
    /// outbox.claim 传导回滚 IsPaused；route（纯 view 访问 outbox）与
    /// claimCredit 不受影响。
    function test_Pause_StackOutbox_ClaimAndRouteReverted_RouteUnaffected() public {
        FastLeaf memory f1 = _fastLeaf(user, NONCE, 1, 1 ether);
        FastLeaf memory f2 = _fastLeaf(user2, NONCE2, 1, 1 ether);
        _commit(f1);
        _commit(f2);
        vm.prank(attacker);
        outbox.claim(f1.leaf, f1.root, 1, 0, _noProof()); // pause 前外部直领

        vm.prank(authority);
        outbox.pause();

        vm.prank(third);
        vm.expectRevert(AuthorityOwnable.IsPaused.selector); // 透传自 outbox.claim
        fastExit.claimAndRoute(f2.leaf, f2.root, 1, 0, _noProof(), user2, NONCE2);
        // route 只读 outbox，不受栈级 pause 影响。
        vm.prank(third);
        fastExit.route(f1.leaf, f1.root, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit.credits(address(0), user), 1 ether);
        vm.prank(user);
        fastExit.claimCredit(address(0), user);
        assertEq(user.balance, 1 ether);
    }

    // ==================================================================
    // H. 重入与 receive
    // ==================================================================

    /// H1a / 不变量 8：advance push 回调内重入四个资金入口——advance/
    /// operatorWithdraw/claimAndRoute/route 全部撞自含 nonReentrant（基座
    /// AuthorityOwnable 不含守卫）；外层交易照常完成。
    function test_Reentrancy_OnAdvancePayout_AllEntriesBlockedByOwnGuard() public {
        AdvanceReentrancyTrap trap = new AdvanceReentrancyTrap(fastExit);
        vm.prank(authority);
        fastExit.setOperator(address(trap)); // 重入 advance 须先过 onlyOperator

        bytes12 n = 0x02000000000000000000000f;
        bytes32 K = fastExit.requestBinding(address(trap), n, 1);
        trap.arm(K, 0.1 ether, n);
        trap.doAdvance(); // trap 为 operator，向自己垫付并触发回调

        assertTrue(trap.sawReentrantOnAdvance(), "advance reentry blocked by guard");
        assertTrue(trap.sawReentrantOnOperatorWithdraw(), "operatorWithdraw reentry blocked by guard");
        assertTrue(trap.sawReentrantOnClaimAndRoute(), "claimAndRoute reentry blocked by guard");
        assertTrue(trap.sawReentrantOnRoute(), "route reentry blocked by guard");
        assertEq(address(trap).balance, 0.1 ether, "outer advance completes");
        (,,, uint128 amt,) = fastExit.advances(K);
        assertEq(uint256(amt), 0.1 ether, "ledger unpolluted by reentry");
        assertEq(fastExit.floatLedger(address(0)), 10 ether - 0.1 ether);
    }

    /// H1b / 不变量 8（claimCredit 无守卫、靠 CEI）：claimCredit push 回调内
    /// 重入 claimCredit → 撞已清零余额 NothingToClaim；外层照常完成。
    function test_Reentrancy_OnClaimCreditPayout_HitsNothingToClaim() public {
        CreditReentrancyTrap trap = new CreditReentrancyTrap(fastExit);
        FastLeaf memory f = _fastLeaf(address(trap), NONCE, 1, 1 ether);
        _commit(f);
        vm.prank(third);
        fastExit.claimAndRoute(f.leaf, f.root, 1, 0, _noProof(), address(trap), NONCE);

        trap.pull();
        assertTrue(trap.sawNothingToClaim(), "reentry hits zeroed credit");
        assertEq(address(trap).balance, 1 ether, "outer claim completes");
        assertEq(fastExit.credits(address(0), address(trap)), 0);
    }

    /// H2 / 误直转滞留（信任边界 3）：直接 transfer 进合约不 revert、
    /// NativeReceived 留痕、floatLedger 不动（不入可提面）。
    function test_Receive_DirectTransfer_EmitsNativeReceived_FloatUntouched() public {
        vm.deal(attacker, 1 ether);
        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.NativeReceived(attacker, 0.1 ether);
        vm.prank(attacker);
        (bool ok,) = address(fastExit).call{value: 0.1 ether}("");
        assertTrue(ok, "direct transfer must not revert");
        assertEq(fastExit.floatLedger(address(0)), 10 ether, "not in float");
        assertEq(fastExit.withdrawable(address(0)), 10 ether, "not withdrawable");
        assertEq(address(fastExit).balance, 10.1 ether, "stuck in contract, no exit");
    }

    // ==================================================================
    // I. 金标准对拍
    // ==================================================================

    /// I1：requestBinding 对拍独立预计算向量（python hashlib，非 Solidity 自算）。
    function test_RequestBinding_MatchesGoldenVector() public view {
        assertEq(
            fastExit.requestBinding(GOLDEN_R, GOLDEN_NONCE, 3),
            GOLDEN_BINDING,
            "requestBinding golden vector mismatch"
        );
    }

    /// I2：绑定哈希对三参数逐字段篡改敏感（收款人/资产/nonce 全入绑）。
    function test_RequestBinding_TamperSensitive_OnRecipientNonceTag() public view {
        bytes32 h = fastExit.requestBinding(user, NONCE, 1);
        assertFalse(h == fastExit.requestBinding(attacker, NONCE, 1), "recipient must be bound");
        assertFalse(h == fastExit.requestBinding(user, NONCE2, 1), "nonce must be bound");
        assertFalse(h == fastExit.requestBinding(user, NONCE, 3), "assetTag must be bound");
    }

    // ==================================================================
    // J. 同 requestId 双叶攻击回归（评审 High）
    // ==================================================================

    /// J1 全链路（claimAndRoute 腿）：叶 A（K、1 wei、收款人 = attacker）被
    /// 直领后，同 K 的叶 B（收款人 = FastExit、5 ether、证明可过）经
    /// claimAndRoute → 透传 AlreadyClaimed；FastExit 台账零变化（_split 的
    /// effects 随整笔回滚）。
    function test_DuplicateRequestId_SecondLeafViaClaimAndRoute_RevertsAlreadyClaimed_NoLedger() public {
        // 叶 A：requestId K、1 wei、收款人 = attacker（普通直领路径）。
        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        FastLeaf memory fa = _customLeaf(K, attacker, 1, 1);
        _commit(fa);
        vm.prank(attacker);
        outbox.claim(fa.leaf, fa.root, 1, 0, _noProof());
        assertEq(attacker.balance, 1, "attacker got only leaf A 1 wei");

        // 叶 B：同 K、收款人 = FastExit、5 ether，单独成根且证明可过。
        FastLeaf memory fb = _fastLeaf(user, NONCE, 1, 5 ether);
        assertEq(fb.leaf.requestId, K, "two leaves share one requestId");
        _commit(fb);
        assertTrue(outbox.verifyInclusion(fb.leaf, _noProof(), 0, fb.root), "leaf B proof passes");

        vm.prank(third);
        vm.expectRevert(L1Outbox.AlreadyClaimed.selector); // 透传自 outbox.claim
        fastExit.claimAndRoute(fb.leaf, fb.root, 1, 0, _noProof(), user, NONCE);

        // 池与台账零变化。
        assertEq(fastExit.totalCredits(address(0)), 0, "no unbacked credit minted");
        assertEq(fastExit.credits(address(0), user), 0);
        assertEq(fastExit.credits(address(0), operator), 0);
        assertEq(address(fastExit).balance, 10 ether);
    }

    /// J1 全链路（route 腿，评审 High 主修复面）：route(叶 B) 必须被
    /// ClaimedLeafMismatch 挡下（叶哈希台账存的是叶 A 的哈希）；即便 operator
    /// 在 K 名下有真实垫付，也只悬置不回收、池不被抽干。
    function test_DuplicateRequestId_SecondLeafViaRoute_RevertsClaimedLeafMismatch_PoolUntouched() public {
        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        // operator 在 K 名下真实垫付（绑定校验通过——绑定原像与叶 B 一致）。
        vm.prank(operator);
        fastExit.advance(K, user, 1, 0.5 ether, NONCE);

        FastLeaf memory fa = _customLeaf(K, attacker, 1, 1);
        _commit(fa);
        vm.prank(attacker);
        outbox.claim(fa.leaf, fa.root, 1, 0, _noProof());

        FastLeaf memory fb = _fastLeaf(user, NONCE, 1, 5 ether);
        _commit(fb);

        vm.prank(third);
        vm.expectRevert(FastExit.ClaimedLeafMismatch.selector);
        fastExit.route(fb.leaf, fb.root, 1, 0, _noProof(), user, NONCE);

        // 池与台账零变化：垫付悬置（routed 未置位、在途未释放、credit 零）。
        (,,,, bool rt) = fastExit.advances(K);
        assertFalse(rt, "routed not set");
        assertEq(fastExit.totalOutstanding(address(0)), 0.5 ether, "advance stuck (operator loss)");
        assertEq(fastExit.totalCredits(address(0)), 0, "no unbacked 5 ether credit");
        assertEq(address(fastExit).balance, 10 ether - 0.5 ether, "pool not drained");
    }

    /// J2：claimedLeafMatches 对六字段逐字段篡改敏感（叶哈希台账判别面）。
    function test_ClaimedLeafMatches_TamperSensitivePerField() public {
        FastLeaf memory f = _fastLeaf(user, NONCE, 1, 1 ether);
        _commit(f);
        outbox.claim(f.leaf, f.root, 1, 0, _noProof());
        assertTrue(outbox.claimedLeafMatches(f.leaf), "genuine leaf matches");

        L1Outbox.WithdrawalLeaf memory t = f.leaf;
        t.amount = 2 ether;
        assertFalse(outbox.claimedLeafMatches(t), "tampered amount");
        t = f.leaf;
        t.externalRecipient = bytes32(uint256(uint160(attacker)));
        assertFalse(outbox.claimedLeafMatches(t), "tampered externalRecipient");
        t = f.leaf;
        t.assetTag = 3;
        assertFalse(outbox.claimedLeafMatches(t), "tampered assetTag");
        t = f.leaf;
        t.burnedNoteCommitment = bytes32(uint256(3));
        assertFalse(outbox.claimedLeafMatches(t), "tampered burnedNoteCommitment");
        t = f.leaf;
        t.checkpointHeight = f.leaf.checkpointHeight + 1;
        assertFalse(outbox.claimedLeafMatches(t), "tampered checkpointHeight");
        t = f.leaf;
        t.requestId = bytes32(uint256(4)); // 换键 → 台账为零
        assertFalse(outbox.claimedLeafMatches(t), "tampered requestId (no ledger)");
    }

    /// J3 跨池变体：收款人 = v1 的叶被领取后，同 K、收款人 = v2 的叶在 v2
    /// 侧 route → ClaimedLeafMismatch（recipient 入叶哈希，天然覆盖）。
    function test_DuplicateRequestId_CrossPoolVariant_SecondPoolRouteReverts() public {
        FastExit fastExit2 = new FastExit(authority, address(outbox), address(hatch));
        vm.prank(authority);
        fastExit2.setOperator(operator);
        vm.prank(treasury);
        fastExit2.fund{value: 0.5 ether}();

        bytes32 K = fastExit.requestBinding(user, NONCE, 1);
        // 叶 v1：收款人 = fastExit1，被外部直领（1 wei 落账 v1）。
        FastLeaf memory f1 = _customLeaf(K, address(fastExit), 1, 1);
        _commit(f1);
        outbox.claim(f1.leaf, f1.root, 1, 0, _noProof());
        assertEq(address(fastExit).balance, 10 ether + 1);

        // 叶 v2：同 K、收款人 = fastExit2、5 ether，在 v2 侧补救路由。
        L1Outbox.WithdrawalLeaf memory l2 = f1.leaf;
        l2.externalRecipient = bytes32(uint256(uint160(address(fastExit2))));
        l2.amount = 5 ether;
        l2.checkpointHeight = _nextHeight++;
        bytes32 root2 = _outboxLeafHash(l2);
        vm.prank(authority);
        outbox.commitRoot(l2.checkpointHeight, 1, root2, true);
        assertTrue(outbox.verifyInclusion(l2, _noProof(), 0, root2), "v2 leaf proof passes");

        vm.prank(third);
        vm.expectRevert(FastExit.ClaimedLeafMismatch.selector);
        fastExit2.route(l2, root2, 1, 0, _noProof(), user, NONCE);
        assertEq(fastExit2.totalCredits(address(0)), 0, "v2 pool mints no credit");
        assertEq(fastExit2.credits(address(0), user), 0);
    }

    /// J4 / 草案 D11（评审 Low-2）：operator 轮换后在途回收按 funder 快照归
    /// 旧主体；新主体新垫付归新主体。
    function test_OperatorRotation_InFlightRecoveryCreditedToFunderSnapshot() public {
        FastLeaf memory f1 = _fastLeaf(user, NONCE, 1, 1 ether);
        FastLeaf memory f2 = _fastLeaf(user2, NONCE2, 1, 1 ether);
        _commit(f1);
        _commit(f2);
        vm.prank(operator); // 旧键垫付
        fastExit.advance(f1.leaf.requestId, user, 1, 0.3 ether, NONCE);
        vm.prank(authority);
        fastExit.setOperator(operator2);
        vm.prank(operator2); // 新键垫付
        fastExit.advance(f2.leaf.requestId, user2, 1, 0.5 ether, NONCE2);

        vm.expectEmit(true, true, true, true, address(fastExit));
        emit FastExit.WithdrawalRouted(f1.leaf.requestId, user, 1, 1 ether, 0.3 ether, 0.3 ether, 0.7 ether, true, operator);
        vm.prank(third);
        fastExit.claimAndRoute(f1.leaf, f1.root, 1, 0, _noProof(), user, NONCE);
        vm.prank(third);
        fastExit.claimAndRoute(f2.leaf, f2.root, 1, 0, _noProof(), user2, NONCE2);

        assertEq(fastExit.credits(address(0), operator), 0.3 ether, "in-flight recovery to first funder snapshot");
        assertEq(fastExit.credits(address(0), operator2), 0.5 ether, "new advance to new operator");
        assertEq(fastExit.credits(address(0), user), 0.7 ether);
        assertEq(fastExit.credits(address(0), user2), 0.5 ether);
    }
}

// ======================================================================
// 测试辅助合约（置文件尾，EscapeHatch.t.sol 同模式）
// ======================================================================

/// USDT 式最小 ERC20：transfer/transferFrom 无返回值（覆盖 FastExit/L1Bridge
/// 低层 call 的 USDT 兼容分支）。
contract USDTLikeToken {
    string public constant name = "Mock USDT (no bool returns)";
    string public constant symbol = "mUSDT";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external {
        _move(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external {
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        _move(from, to, amount);
    }

    function _move(address from, address to, uint256 amount) private {
        require(balanceOf[from] >= amount, "mUSDT: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}

/// 无 receive()/fallback 的合约：原生 push 必败（B5）。
contract NoReceiveRecipient {}

/// 拒收合约：receive 恒 revert（F1b）。
contract RevertingReceiver {
    receive() external payable {
        revert("rejecting transfer");
    }
}

/// H1a：advance push 回调中重入四个资金入口，全部应撞 FastExit 自含
/// nonReentrant（陷阱合约自身须为 operator 才能过 onlyOperator）。
contract AdvanceReentrancyTrap {
    FastExit private immutable _fx;
    bytes32 private _requestId;
    uint64 private _amount;
    bytes12 private _nonce;
    bool public sawReentrantOnAdvance;
    bool public sawReentrantOnOperatorWithdraw;
    bool public sawReentrantOnClaimAndRoute;
    bool public sawReentrantOnRoute;

    constructor(FastExit fx) {
        _fx = fx;
    }

    function arm(bytes32 requestId, uint64 amount, bytes12 nonce) external {
        _requestId = requestId;
        _amount = amount;
        _nonce = nonce;
    }

    function doAdvance() external {
        _fx.advance(_requestId, address(this), 1, _amount, _nonce);
    }

    receive() external payable {
        try _fx.advance(_requestId, address(this), 1, _amount, _nonce) {
            revert("reentrant advance unexpectedly succeeded");
        } catch (bytes memory r) {
            if (bytes4(r) == FastExit.Reentrant.selector) sawReentrantOnAdvance = true;
        }
        try _fx.operatorWithdraw(address(0), 0) {
            revert("reentrant operatorWithdraw unexpectedly succeeded");
        } catch (bytes memory r) {
            if (bytes4(r) == FastExit.Reentrant.selector) sawReentrantOnOperatorWithdraw = true;
        }
        try _fx.claimAndRoute(_dummy(), bytes32(0), 0, 0, new bytes32[](0), address(0), bytes12(0)) {
            revert("reentrant claimAndRoute unexpectedly succeeded");
        } catch (bytes memory r) {
            if (bytes4(r) == FastExit.Reentrant.selector) sawReentrantOnClaimAndRoute = true;
        }
        try _fx.route(_dummy(), bytes32(0), 0, 0, new bytes32[](0), address(0), bytes12(0)) {
            revert("reentrant route unexpectedly succeeded");
        } catch (bytes memory r) {
            if (bytes4(r) == FastExit.Reentrant.selector) sawReentrantOnRoute = true;
        }
    }

    function _dummy() private pure returns (L1Outbox.WithdrawalLeaf memory l) {
        l = L1Outbox.WithdrawalLeaf({
            requestId: bytes32(uint256(1)),
            externalRecipient: bytes32(uint256(1)),
            assetTag: 1,
            amount: 1,
            burnedNoteCommitment: bytes32(uint256(1)),
            checkpointHeight: 1
        });
    }
}

/// H1b：claimCredit push 回调中重入 claimCredit——应撞 CEI 清零后的
/// NothingToClaim（claimCredit 无 nonReentrant，防线 = 先清零后转账）。
contract CreditReentrancyTrap {
    FastExit private immutable _fx;
    bool public sawNothingToClaim;

    constructor(FastExit fx) {
        _fx = fx;
    }

    function pull() external {
        _fx.claimCredit(address(0), address(this));
    }

    receive() external payable {
        try _fx.claimCredit(address(0), address(this)) {
            revert("reentrant claimCredit unexpectedly succeeded");
        } catch (bytes memory r) {
            if (bytes4(r) == FastExit.NothingToClaim.selector) sawNothingToClaim = true;
        }
    }
}
