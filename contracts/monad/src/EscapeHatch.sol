// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {AuthorityOwnable} from "./AuthorityOwnable.sol";
import {IL1Bridge} from "./IL1Bridge.sol";

/// @notice L1Inbox 批次锚定的只读对账接口。public mapping-of-struct 的自动
///         getter 按 ABI 返回**扁平 tuple**（无成员访问语法），此处签名与
///         `L1Inbox.batches` 的 getter 完全一致（forge 测试以真实 L1Inbox
///         实例对拍闭合）。
interface IL1Inbox {
    function batches(uint64 index) external view returns (bytes32 root, uint64 throughOp, uint64 l1Block);
}

/// @title EscapeHatch — zchain Monad(L1) 侧审查/停摆逃生舱（资金型）
/// @notice 运营方停止服务/失能（但已登记根诚实）时的资金逃生路径，五步：
///          1. 正常 cadence：authority 随每批把 L2 全体玩家余额根
///             `registerBalanceRoot`（强制该批已在 L1Inbox 锚定；genesis
///             index 0 由 Deploy 豁免登记，消零根悬崖）；
///          2. 玩家或哨兵以 `TICKET_BOND` 押金 `forcedWithdraw` 提单
///             （一人一单；filedAtRootCount 供链下对账）；
///          3. 工单超时（`TICKET_TIMEOUT`）未被 serve → **任何人** `freeze`
///             —— 全栈冻结（L1Inbox 三锚定入口 / L1Bridge 两入金口 /
///             L1Outbox commitRoot+markFinalized 全部挂 Frozen 卫兵）；
///          4. 分叉：authority 在 `MIN_FREEZE_DURATION` 后 `unfreeze`
///             （逐单关单、押金 50% 罚没），之后新根按既有 cadence 自愈；
///             或冻结期**任何人** `escape`：按最新余额根的 Merkle 证明
///             permissionless 从 L1Bridge 库把余额一次性全额打给玩家。
///
///         押金三分规则（spam 净成本 0.05 ether/轮）：
///           - 及时 serve（deadline 内）→ 押金 100% 贷记 submitter；
///           - 过期后关单（unfreeze 逐单路径）→ 50% 贷记，另 50% 滞留合约；
///           - submitter 弃单 cancelTicket → 100% 没收滞留。
///
/// # 信任边界（务必知悉，勿当去信任事实引用）
/// 1. **余额根为 operator 背书层级**（与 SettleBatch.sol:24-36 同层）：恶意
///    authority 可登记压低的根；叶子级证明内嵌验证（终解双花与压低根）为
///    后续交付项。哨兵提单为链下义务——freeze 触发依赖过期工单存在。
/// 2. **覆盖面 = 仅原生 MON**：冻结期 ERC20 存量无出口（已接受限制）。
/// 3. **escape × L1Outbox.claim 交叉双花链上不设防**（claim 有意不挂卫兵，
///    预冻结窗保留可领；两者竞争 Bridge 浮存先到先得）。兜底 = 总流出
///    ≤ Bridge 浮存（两出口均 call{value} 自 Bridge 余额，不足即 revert，
///    双花只改分配不增总支出）。
/// 4. **pause/frozen 语义**：escape / unfreeze（及 Bridge.escapePayoutNative）
///    **有意不带 whenNotPaused**——逃生与恢复路径不被 pause 位卡死；其余
///    入口维持 whenNotPaused。勿当 bug 修回（见 AuthorityOwnable.sol 注释）。
/// 5. **freeze 对持钥方仅延时**：authority 可 unfreeze；治理硬化（多签/
///    timelock/不可逆冻结）为后续项。
/// 6. **强制语义 = 经济强制**：运营方不真正结算 → 根内余额未变 → 玩家可
///    再提单 → 再一轮 7 天停摆（ServeNeedsNewRoot 弱强制废弃后的替代
///    forcing chain）；serve 纳入结算为运营纪律，无链上强制。
///
/// # Merkle 树（逐字节镜像约定，与 L1Outbox 同骨架、全新域）
///   - 域标签 DOMAIN = "zchain.vault.balance_root.v1"；
///   - 叶：sha256(DOMAIN ‖ 0x00 ‖ bytes20(player) ‖ u64 小端(amount))（28B）；
///   - 内部节点：sha256(DOMAIN ‖ 0x01 ‖ l ‖ r)；
///   - 不平衡树以空叶 sha256(DOMAIN ‖ 0x00 ‖ "") 补齐到 2 的幂；
///   - canonical 叶序 = player 地址升序。
///   自含实现不引 OpenZeppelin（同 AuthorityOwnable.sol:7 口径：离线可编译、
///   代码面小可全量审计）；骨架复用 L1Outbox（前缀常量/MAX_PROOF_LEN/空叶
///   补齐），叶字段集 28B 为本合约全新编码——Rust 侧同式实现 + 交叉对拍为
///   后续项（当前金向量由测试 Solidity 侧自算，标注『待 Rust 对拍』）。
contract EscapeHatch is AuthorityOwnable {
    // ------------------------------------------------------------------
    // 常量
    // ------------------------------------------------------------------

    /// 提单押金（押金三分规则的原料；见 contract natspec）。
    uint256 public constant TICKET_BOND = 0.1 ether;
    /// 工单服务窗口：超时未 serve 即可被任何人 freeze。
    uint64 public constant TICKET_TIMEOUT = 7 days;
    /// 冻结最短持续：给 authority 自救窗口（对持钥恶意方仅延时，见边界 5）。
    uint64 public constant MIN_FREEZE_DURATION = 7 days;

    /// RFC 6962 式前缀（骨架与 L1Outbox.sol:41-43 同式，域不同）。
    uint256 private constant LEAF_PREFIX = 0x00;
    uint256 private constant INTERNAL_PREFIX = 0x01;
    /// 证明深度上限（与 L1Outbox.sol:52 的 Rust verify_inclusion ≥64 拒绝口径对齐）。
    uint256 private constant MAX_PROOF_LEN = 63;

    // ------------------------------------------------------------------
    // 不可变依赖
    // ------------------------------------------------------------------

    /// L1Bridge 资金库（escape 唯一支付出口；经 escapePayoutNative 单向授权）。
    IL1Bridge public immutable bridge;
    /// L1Inbox（仅 registerBalanceRoot 的锚定只读对账用）。依赖方向收窄：
    /// unfreeze 不触碰 inbox——冻结期 Inbox 被卫兵挡住、恢复走 unfreeze 后
    /// 的正常 cadence（submitBatch + registerBalanceRoot）自愈，本合约对
    /// inbox 无任何写依赖。
    address public immutable inbox;

    // ------------------------------------------------------------------
    // 数据结构
    // ------------------------------------------------------------------

    /// 余额根账本条目。
    struct BalanceRootRecord {
        bytes32 root;
        uint64 leafCount;
        uint64 l1Block; // 登记时的 Monad 高度（审计用）
    }

    enum TicketState {
        Open,
        Served,
        Cancelled
    }

    /// 工单。filedAtRootCount = 提单时 balanceRootCount，纯审计字段（供哨兵
    /// 链下对账『提单后是否有含扣减的新根』）——无链上强制，宁丑勿糊。
    struct Ticket {
        address player;
        address submitter;
        uint64 createdAt;
        uint64 filedAtRootCount;
        TicketState state;
        uint256 bond;
    }

    // ------------------------------------------------------------------
    // 存储（注意：本区声明序即存储槽序，测试 EscapeHatch.t.sol 依赖
    // frozen/frozenAt/frozenTicketId 同槽打包的槽位做纵深防御分支注入）
    // ------------------------------------------------------------------

    /// batchIndex → 余额根记录（canonical 叶序 = player 地址升序）。
    mapping(uint64 batchIndex => BalanceRootRecord) public balanceRoots;
    /// 下一个期望的余额根 batchIndex（与 L1Inbox.index 同连续纪律）。
    uint64 public balanceRootCount;
    /// escape 锚定的唯一最新批次（genesis 登记后恒有非零记录）。
    uint64 public latestBalanceBatch;

    /// ticketId → 工单（id 从 1 起；0 保留为「无单」哨兵值）。
    mapping(uint64 ticketId => Ticket) public tickets;
    uint64 public ticketCount;
    /// player → 其 Open 工单 id（一人一单；关单即清除）。
    mapping(address player => uint64) public openTicketOf;
    /// submitter → 可领押金（pull 模式；先清零再转账）。
    mapping(address submitter => uint256) public bondCredit;

    /// 全栈冻结位（三兄弟合约经 isFrozen() 卫兵只读查询）。
    bool public frozen;
    /// 冻结时刻（MIN_FREEZE_DURATION 计时基准）。
    uint64 public frozenAt;
    /// 触发冻结的工单（审计留痕，unfreeze 不清）。
    uint64 public frozenTicketId;

    /// 哨兵白名单（可代任意玩家提单的链下监控方）。
    mapping(address => bool) public sentinels;
    /// player → 已逃生（一次性全额；CEI 先置位再支付）。
    mapping(address player => bool) public escaped;

    // ------------------------------------------------------------------
    // 事件
    // ------------------------------------------------------------------

    event BalanceRootRegistered(
        uint64 indexed batchIndex, bytes32 root, uint64 leafCount, uint64 l1Block
    );
    event TicketFiled(
        uint64 indexed ticketId, address indexed player, address indexed submitter, uint64 filedAtRootCount, uint256 bond
    );
    /// bondCredited = bond（及时 100%）或 bond/2（过期 50%）。
    event TicketServed(uint64 indexed ticketId, address indexed player, uint256 bondCredited);
    event TicketCancelled(uint64 indexed ticketId, address indexed player, address indexed submitter);
    event Frozen(uint64 indexed ticketId, uint64 frozenAt);
    event Unfrozen(uint64 indexed triggerTicketId);
    event Escaped(address indexed player, uint256 balance, uint64 indexed leafIndex, uint64 batchIndex, address executor);
    event BondClaimed(address indexed submitter, uint256 amount);
    event SentinelUpdated(address indexed sentinel, bool enabled);

    // ------------------------------------------------------------------
    // 错误
    // ------------------------------------------------------------------

    error IsFrozen(); // 注册/提单/及时 serve 的冻结期拒绝
    error AlreadyFrozen(); // 重复 freeze
    error NotFrozen(); // escape / unfreeze 的未冻结拒绝
    error FreezeTooEarly(); // 未满 MIN_FREEZE_DURATION
    error NotPlayerOrSentinel();
    error NotSubmitter();
    error TicketAlreadyOpen();
    error TicketNotOpen();
    error TicketNotExpired();
    error BadTicketId();
    error BadBond();
    error BadRoot();
    error OutOfOrder();
    error NotAnchored();
    error LeafAmountOverflow();
    error IndexBeyondLeafCount();
    error BalanceProofInvalid();
    error AlreadyEscaped();
    error NothingToClaim();
    error BondTransferFailed();

    // ------------------------------------------------------------------
    // 构造
    // ------------------------------------------------------------------

    /// @param initialAuthority_ L2 sequencer/运营方地址（生产 = 多签）。
    /// @param bridge_ L1Bridge 资金库（Deploy 接线后由 bridge.setEscapeHatch
    ///                单向授权 escapePayoutNative）。
    /// @param inbox_ L1Inbox（锚定对账只读面）。
    constructor(address initialAuthority_, address bridge_, address inbox_) AuthorityOwnable(initialAuthority_) {
        if (bridge_ == address(0) || inbox_ == address(0)) revert ZeroAddress();
        bridge = IL1Bridge(bridge_);
        inbox = inbox_;
    }

    // ------------------------------------------------------------------
    // 哨兵管理（authority）
    // ------------------------------------------------------------------

    function addSentinel(address sentinel_) external onlyAuthority {
        if (sentinel_ == address(0)) revert ZeroAddress();
        sentinels[sentinel_] = true;
        emit SentinelUpdated(sentinel_, true);
    }

    function removeSentinel(address sentinel_) external onlyAuthority {
        sentinels[sentinel_] = false;
        emit SentinelUpdated(sentinel_, false);
    }

    // ------------------------------------------------------------------
    // 余额根登记（authority；daemon = monad_settlementd anchor 模式在
    // submitBatch 之后追加调用）
    // ------------------------------------------------------------------

    /// @notice 登记一批玩家余额根。index 严格连续（== balanceRootCount）；
    ///         batchIndex > 0 强制该批已在 L1Inbox 锚定（batches 第三返回值
    ///         l1Block != 0）；batchIndex == 0 为 genesis，豁免对账（Deploy
    ///         即登记空账本根，消「根从零开始」的悬崖）。
    ///         冻结期拒绝——冻结语义就是「旧根事实不再推进」（R3-1：恢复不
    ///         在此路径，unfreeze 后新根走正常 cadence 自愈）。
    function registerBalanceRoot(uint64 batchIndex, bytes32 root, uint64 leafCount)
        external
        onlyAuthority
        whenNotPaused
    {
        if (frozen) revert IsFrozen();
        if (batchIndex != balanceRootCount) revert OutOfOrder();
        if (root == bytes32(0)) revert BadRoot();
        if (batchIndex != 0) {
            // 扁平三标量 getter 对账：未锚定批次（l1Block == 0）不可登记。
            (, , uint64 l1Block) = IL1Inbox(inbox).batches(batchIndex);
            if (l1Block == 0) revert NotAnchored();
        }
        uint64 height = uint64(block.number);
        balanceRoots[batchIndex] = BalanceRootRecord({root: root, leafCount: leafCount, l1Block: height});
        balanceRootCount = batchIndex + 1;
        latestBalanceBatch = batchIndex;
        emit BalanceRootRegistered(batchIndex, root, leafCount, height);
    }

    // ------------------------------------------------------------------
    // 工单（提单 / 及时 serve / 弃单）
    // ------------------------------------------------------------------

    /// @notice 提单：玩家本人或哨兵以 TICKET_BOND 押金为 player 申请提现。
    ///         一人一单（openTicketOf 未清不可再提）。
    function forcedWithdraw(address player) external payable whenNotPaused {
        if (frozen) revert IsFrozen();
        if (msg.value != TICKET_BOND) revert BadBond();
        if (player == address(0)) revert ZeroAddress();
        if (msg.sender != player && !sentinels[msg.sender]) revert NotPlayerOrSentinel();
        if (openTicketOf[player] != 0) revert TicketAlreadyOpen();

        uint64 ticketId = ticketCount + 1;
        ticketCount = ticketId;
        tickets[ticketId] = Ticket({
            player: player,
            submitter: msg.sender,
            createdAt: uint64(block.timestamp),
            filedAtRootCount: balanceRootCount,
            state: TicketState.Open,
            bond: msg.value
        });
        openTicketOf[player] = ticketId;
        emit TicketFiled(ticketId, player, msg.sender, balanceRootCount, msg.value);
    }

    /// @notice 及时路径（deadline 内、未冻结）：authority 真正结算玩家提现
    ///         （L2 侧纳入 checkpoint 提现窗 → 登记含扣减新根——时序为纯
    ///         运营纪律，无链上强制，如实声明）后关单，押金 100% 贷记。
    function serveTicket(uint64 ticketId) external onlyAuthority whenNotPaused {
        if (frozen) revert IsFrozen();
        _requireTicket(ticketId);
        Ticket storage t = tickets[ticketId];
        if (t.state != TicketState.Open) revert TicketNotOpen();
        t.state = TicketState.Served;
        delete openTicketOf[t.player];
        bondCredit[t.submitter] += t.bond;
        emit TicketServed(ticketId, t.player, t.bond);
    }

    /// @notice 弃单：仅 submitter、任意时刻（含冻结期）。押金 100% 没收滞留
    ///         合约（无 sweep 出口——治理再分配为后续项）。冻结期关单不解除
    ///         frozen 位本身。
    function cancelTicket(uint64 ticketId) external {
        _requireTicket(ticketId);
        Ticket storage t = tickets[ticketId];
        if (msg.sender != t.submitter) revert NotSubmitter();
        if (t.state != TicketState.Open) revert TicketNotOpen();
        t.state = TicketState.Cancelled;
        delete openTicketOf[t.player];
        emit TicketCancelled(ticketId, t.player, msg.sender);
    }

    // ------------------------------------------------------------------
    // 冻结状态机（freeze permissionless / unfreeze 原子恢复）
    // ------------------------------------------------------------------

    /// @notice 任何人以**已过期**（block.timestamp > createdAt + TICKET_TIMEOUT，
    ///         严格不等号）的 Open 工单触发全栈冻结——免费辩护：触发器已被
    ///         工单押金回书（spam 一个过期单的成本 = 押金罚没规则承担）。
    function freeze(uint64 ticketId) external {
        if (frozen) revert AlreadyFrozen();
        _requireTicket(ticketId);
        Ticket storage t = tickets[ticketId];
        if (t.state != TicketState.Open) revert TicketNotOpen();
        if (block.timestamp <= t.createdAt + TICKET_TIMEOUT) revert TicketNotExpired();

        frozen = true;
        frozenAt = uint64(block.timestamp);
        frozenTicketId = ticketId;
        emit Frozen(ticketId, uint64(block.timestamp));
    }

    /// @notice 原子恢复（R3-1 修订：与 register 彻底解耦）——authority 在
    ///         MIN_FREEZE_DURATION 后一次性「解锁 + 逐单关单」。
    ///         **有意不带 whenNotPaused**：与 escape 同侧，恢复路径不被
    ///         pause 位卡死（去 register 化后本入口不触碰任何带 pause 语义
    ///         的子入口，语义自洽）。不内嵌 registerBalanceRoot：死锁根因
    ///         （balanceRootCount == batchCount == N 的 cadence 下，冻结卫兵
    ///         挡 submitBatch(N) 致唯一可登记 index 恒未锚定，单 tx 两序皆
    ///         revert）自此消除；解冻后新根走正常 cadence 自愈。
    ///         逐单校验 state==Open 且已过期（R3-3：只清冻结触发器；未过期
    ///         工单留待及时路径，玩家等待时钟不被重置——当前常量组合下该
    ///         分支经公开入口不可达，属纵深防御，见测试注入说明）。
    ///         空列表可用（只解锁）——但随后触发器可再被同一过期单冻结，
    ///         关单义务为运营纪律。
    function unfreeze(uint64[] calldata ticketIds) external onlyAuthority {
        if (!frozen) revert NotFrozen();
        if (block.timestamp < frozenAt + MIN_FREEZE_DURATION) revert FreezeTooEarly();
        frozen = false;

        for (uint256 i = 0; i < ticketIds.length; ++i) {
            uint64 ticketId = ticketIds[i];
            _requireTicket(ticketId);
            Ticket storage t = tickets[ticketId];
            if (t.state != TicketState.Open) revert TicketNotOpen();
            if (block.timestamp <= t.createdAt + TICKET_TIMEOUT) revert TicketNotExpired();
            t.state = TicketState.Served;
            delete openTicketOf[t.player];
            bondCredit[t.submitter] += t.bond / 2; // 过期罚没 50%，另 50% 滞留合约
            emit TicketServed(ticketId, t.player, t.bond / 2);
        }
        emit Unfrozen(frozenTicketId);
    }

    // ------------------------------------------------------------------
    // 逃生（冻结期 permissionless Merkle 提现）
    // ------------------------------------------------------------------

    /// @notice 冻结期按最新余额根（balanceRoots[latestBalanceBatch] 唯一根）
    ///         permissionless 逃生：任何人执行、款项打 player（执行者可代办）。
    ///         一次性全额（escaped 台账）。**有意不带 whenNotPaused**。
    ///         CEI：先置 escaped 再支付——payout 回呼重入撞 AlreadyEscaped；
    ///         payout revert（如 Bridge 浮存不足）整笔回滚、台账还原，可重试。
    function escape(address player, uint256 balance, uint64 leafIndex, bytes32[] calldata proof) external {
        if (!frozen) revert NotFrozen();
        if (escaped[player]) revert AlreadyEscaped();
        if (balance > type(uint64).max) revert LeafAmountOverflow();

        BalanceRootRecord storage rec = balanceRoots[latestBalanceBatch];
        if (leafIndex >= rec.leafCount) revert IndexBeyondLeafCount();
        if (!_verifyInclusion(player, balance, leafIndex, proof, rec.root)) revert BalanceProofInvalid();

        escaped[player] = true; // effects 先于 interactions（重入防线）
        bridge.escapePayoutNative(player, balance);
        emit Escaped(player, balance, leafIndex, latestBalanceBatch, msg.sender);
    }

    // ------------------------------------------------------------------
    // 押金领取（pull 模式）
    // ------------------------------------------------------------------

    /// @notice 领取押金贷记：先清零再转账（拒收卡死被 pull 化消灭；回呼
    ///         重入撞零余额）。
    function claimBond() external {
        uint256 amount = bondCredit[msg.sender];
        if (amount == 0) revert NothingToClaim();
        bondCredit[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert BondTransferFailed();
        emit BondClaimed(msg.sender, amount);
    }

    // ------------------------------------------------------------------
    // 卫兵查询面（L1Inbox / L1Bridge / L1Outbox 的 Frozen 卫兵调用）
    // ------------------------------------------------------------------

    function isFrozen() external view returns (bool) {
        return frozen;
    }

    // ------------------------------------------------------------------
    // 内部
    // ------------------------------------------------------------------

    function _requireTicket(uint64 ticketId) private view {
        if (ticketId == 0 || ticketId > ticketCount) revert BadTicketId();
    }

    /// 形状防线 + 自叶向根折叠（镜像 L1Outbox._verifyInclusion，域不同）。
    function _verifyInclusion(address player, uint256 balance, uint64 leafIndex, bytes32[] calldata proof, bytes32 root)
        private
        view
        returns (bool)
    {
        // 证明过深或 index 超出路径覆盖范围 → 不可能属于本树。
        if (proof.length > MAX_PROOF_LEN) return false;
        if (proof.length < 64 && (leafIndex >> proof.length) != 0) return false;

        bytes32 h = _leafHash(player, balance);
        for (uint256 depth = 0; depth < proof.length; depth++) {
            bytes32 sibling = proof[depth];
            if ((leafIndex >> depth) & 1 == 0) {
                h = _internalHash(h, sibling);
            } else {
                h = _internalHash(sibling, h);
            }
        }
        return h == root;
    }

    function _sha256(bytes memory input) private view returns (bytes32 result) {
        // Monad 为 EVM 等价：0x02 = sha256 预编译可用。输出必须落在已分配
        // 内存（mload(0x40) 前进 32B 后读回）——直接把栈变量当输出地址是
        // 未定义行为（L1Outbox.sol:302-316 同式，Monad 测试网实测教训）。
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0)
            let ok := staticcall(gas(), 0x02, add(input, 32), mload(input), ptr, 32)
            if iszero(ok) {
                revert(0, 0)
            }
            result := mload(ptr)
        }
    }

    function _domain() private pure returns (bytes memory) {
        return bytes("zchain.vault.balance_root.v1");
    }

    /// u64 小端 8 字节（borsh 编码；Solidity 默认大端，须手工展开；
    /// L1Outbox.sol:323-329 同式）。
    function _le64(uint64 v) private pure returns (bytes memory) {
        bytes memory out = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            out[i] = bytes1(uint8(v >> (8 * i)));
        }
        return out;
    }

    /// 叶哈希：sha256(DOMAIN ‖ 0x00 ‖ bytes20(player) ‖ u64 小端 amount)。
    function _leafHash(address player, uint256 balance) private view returns (bytes32) {
        return _sha256(abi.encodePacked(_domain(), bytes1(uint8(LEAF_PREFIX)), bytes20(player), _le64(uint64(balance))));
    }

    /// 内部节点：sha256(DOMAIN ‖ 0x01 ‖ l ‖ r)。
    function _internalHash(bytes32 l, bytes32 r) private view returns (bytes32) {
        return _sha256(abi.encodePacked(_domain(), bytes1(uint8(INTERNAL_PREFIX)), l, r));
    }

    /// 空叶哈希（不平衡树补齐位；= 空账本规范根，Deploy 用作 genesis 根；
    /// L1Outbox.sol:357-360 同式）。
    function emptyLeafHash() public view returns (bytes32) {
        return _sha256(abi.encodePacked(_domain(), bytes1(uint8(LEAF_PREFIX))));
    }
}
