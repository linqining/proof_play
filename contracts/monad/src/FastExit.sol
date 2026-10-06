// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {AuthorityOwnable} from "./AuthorityOwnable.sol";
import {L1Outbox} from "./L1Outbox.sol";

/// @notice FastExit 对 L1Outbox 的只读/领取面（claim、树校验、已领叶哈希
///         台账、根 getter）。WithdrawalLeaf/RootRecord 直接复用 L1Outbox
///         的单一字段定义（113B 叶是 Rust↔Solidity 金标准，不另抄结构）。
interface IL1OutboxForFastExit {
    function claim(
        L1Outbox.WithdrawalLeaf calldata leaf,
        bytes32 root,
        uint64 leafCount,
        uint64 index,
        bytes32[] calldata proof
    ) external;

    function verifyInclusion(
        L1Outbox.WithdrawalLeaf calldata leaf,
        bytes32[] calldata proof,
        uint64 index,
        bytes32 root
    ) external view returns (bool);

    function claimedLeafHashes(bytes32 requestId) external view returns (bytes32);

    function claimedLeafMatches(L1Outbox.WithdrawalLeaf calldata leaf) external view returns (bool);

    function roots(bytes32 digest) external view returns (L1Outbox.RootRecord memory);

    function tokenForTag(uint8 tag) external view returns (address);

    function digestOf(uint64 l2Height, uint64 leafCount, bytes32 root) external view returns (bytes32);
}

/// @notice 复用 L1Outbox.sol / L1Bridge.sol 的同形冻结查询接口（由
///         EscapeHatch 实现）。仅 advance 挂卫兵——冻结期新垫付停摆；
///         claimAndRoute/route/claimCredit 有意不挂（用户取回面不卡死）。
interface IEscapeHatch {
    function isFrozen() external view returns (bool);
}

/// @title FastExit — zchain L2→Monad(L1) 提现快速通道（operator 垫付 + 领取分流）
/// @notice 机制（站起即领的运营垫付通道）：
///          1. 用户在 L2 站起选择快速通道：快速通道叶子的 externalRecipient
///             = FastExit 地址、requestId = requestBinding(R, nonce, tag)
///             = sha256("zchain.fastexit.request.v1" ‖ bytes20(R) ‖
///             bytes12(nonce) ‖ uint8(tag))——收款人、资产、nonce 在垫付前
///             就烧进 requestId（L2 侧派生约定，接线清单范围外）；
///          2. operator 收到 L2 事件后 `advance`：同笔 tx 从自有浮存池真实
///             出账给用户 L1 地址 R 并同步记账（防链下打款后口头登记）；
///          3. 根上锚后任何人 `claimAndRoute`：FastExit 代发 L1Outbox.claim
///             （叶子收款人即 FastExit，原子落账 Y），随即纯记账分流——
///             operator 得 min(X_eff, Y)（按垫付时点 funder 快照入账）、
///             用户得 Y − min(X_eff, Y)，均入 pull 式 credit 随时可领；
///             无人垫付时 X=0，本函数即慢路径（全额 Y 归用户，
///             permissionless、无排他窗口）；
///          4. 第三方抢跑直接 claim 的叶子由 `route` 凭 L1Outbox 的
///             claimedLeafHashes/claimedLeafMatches 叶哈希台账补救分流。
///
/// # 安全要点（任务书不变量 1–8 的落实）
///   - 用户最终所得 ≡ Y（X ≤ Y 时 = 垫付 X + 差额；X > Y 为 operator
///     多垫自亏，不设上限不补偿）；
///   - operator 回收 ≤ min(X, Y)，且仅当垫付有效（tag/token 双匹配）；
///     无效垫付全额归用户——"收款人匹配"由绑定哈希结构性保证（advance
///     与叶子 requestId 出自同一哈希原像，伪造 R 立不了账）；
///   - requestId 一次性：领取侧对齐 L1Outbox.claimedRequests（跨根全局），
///     分流侧独立 routed 台账；route 的分流证据绑定叶哈希六字段（防同
///     requestId 双叶铸无背书 credit）；已 routed 的 requestId 禁止再垫付
///     （杜绝用户总额 > Y）；
///   - 冻结/暂停只停 advance 与 operatorWithdraw；claimAndRoute/route/
///     claimCredit 不受 FastExit 自身卫兵阻断（对齐 L1Outbox.claim /
///     EscapeHatch.escape 的取回面哲学——每叶总流出仍 = Y，L1Bridge
///     浮存口径不变）；
///   - 资产纪律：tag 2（PLAY 内部筹码）不可垫付；tag 1 原生 MON；tag ≥ 3
///     ERC20，代币地址复用 L1Outbox.tokenForTag（单一事实源，不另设映射）；
///   - solvency：operatorWithdraw ≤ floatLedger − totalOutstanding（原生与
///     每个 ERC20 分别记账）；claim 落账的 Y 与 credit 均不入浮存——credit
///     恒有足额余额背书，claimCredit 永不因池亏空失败；
///   - 重入：自含 nonReentrant（基座 AuthorityOwnable 不含守卫）+
///     effects-before-interactions + 分流零外呼；receive() 有意不加守卫
///     （claimAndRoute 持锁期间 Bridge payout 回调不可自锁死），其函数体
///     仅 emit 事件，零状态零调用，天然不可重入。
///
/// # 信任边界（务必知悉，勿当去信任事实引用）
/// 1. **L2 接线违约 → 永久锁定（fail-closed）**：叶子收款人 = FastExit 但
///    requestId 不满足绑定哈希时，claimAndRoute 与 route 均
///    RequestBindingMismatch，且该叶子无其他领取出口——绑定派生是 L2 侧
///    硬性交付项（Rust 侧镜像 + 交叉对拍）。
/// 2. **最终性/冻结风险归 operator**：根不上锚、L2 回滚、EscapeHatch.escape
///    抽干浮存，损失均为 operator 已垫付的 X（在途 totalOutstanding 悬置）；
///    用户已落袋（多垫自亏同此）。
/// 3. **误直转滞留**：直接 transfer 进合约的原生币不入 floatLedger、v1 无
///    sweep 出口（NativeReceived 事件留痕供链下对账）；注资只可走
///    fund()/fundToken()。
/// 4. **requestId 唯一性是 L2 纪律**：同 requestId 双叶的 L1 侧后果已被叶
///    哈希台账封死为"第二片叶不可领/不可路由"（contained），但被占用
///    requestId 名下的垫付将悬置（operator 自亏）。
contract FastExit is AuthorityOwnable {
    // ------------------------------------------------------------------
    // 常量
    // ------------------------------------------------------------------

    /// 绑定哈希域标签（L2 侧派生约定的 Solidity 镜像；Rust 侧对拍测试为
    /// L2 侧交付项——两侧任一改动必须同步另一侧）。
    bytes private constant BINDING_DOMAIN = "zchain.fastexit.request.v1";

    /// 资产标签判别面（与 L1Outbox 常量同值镜像：合法面 = {1=原生 MON} ∪
    /// [3,255]=ERC20；tag 2 = L2 内部筹码。Solidity 不支持跨合约直读常量，
    /// 改动须两侧同步）。
    uint8 private constant TAG_REAL_NATIVE = 1;
    uint8 private constant TAG_REAL_USDT = 3;

    // ------------------------------------------------------------------
    // 数据结构
    // ------------------------------------------------------------------

    /// 垫付台账（首笔初始化 funder/token/tag 快照；同 requestId 后续只
    /// 累加金额）。
    struct AdvanceRecord {
        address funder; // 首笔垫付时点的 operator 快照（回收归属；轮换不转移在途归属）
        address token; // 首笔快照：tag1=address(0) 原生；tag≥3=outbox.tokenForTag(tag)
        uint8 assetTag;
        uint128 amount; // 累计垫付 X
        bool routed; // 一次性分流标记（route 侧防重放）
    }

    // ------------------------------------------------------------------
    // 存储
    // ------------------------------------------------------------------

    /// requestId → 垫付台账（键 = 快速通道叶子 requestId）。
    mapping(bytes32 requestId => AdvanceRecord) public advances;
    /// operator 浮存（token = address(0) 表示原生 MON）。只经 fund/fundToken
    /// 增、经 advance 出账与 operatorWithdraw 减；claim 落账资金不入浮存。
    mapping(address token => uint256) public floatLedger;
    /// 在途垫付（垫付计增、route 按该笔垫付全额计减；同键约定）。
    mapping(address token => uint256) public totalOutstanding;
    /// 未领 credit 合计（solvency 证明用：合约余额 ≥ totalCredits 恒成立）。
    mapping(address token => uint256) public totalCredits;
    /// token → owner → 未领 credit（用户差额份额与 operator 回收份额共用）。
    mapping(address token => mapping(address owner => uint256)) public credits;
    /// 垫付执行方（authority 可轮换；不影响在途垫付的归属——按 funder 快照）。
    address public operator;

    // ------------------------------------------------------------------
    // 不可变依赖
    // ------------------------------------------------------------------

    /// L1Outbox（领取/树校验/叶哈希台账/根 getter；构造一次性接线）。
    IL1OutboxForFastExit public immutable outbox;
    /// EscapeHatch（仅读 isFrozen；构造一次性接线，非零强制）。
    address public immutable escapeHatch;

    // ------------------------------------------------------------------
    // 重入守卫（自含实现——基座 AuthorityOwnable 不含 nonReentrant）
    // ------------------------------------------------------------------

    /// 守卫槽（0 = 空闲，1 = 执行中）。receive() 有意不检查本槽：持锁期间
    /// Bridge payout 回调必须可入（仅 emit 事件，无重入面）。
    uint256 private _guard;

    modifier nonReentrant() {
        if (_guard == 1) revert Reentrant();
        _guard = 1;
        _;
        _guard = 0;
    }

    /// 垫付执行方卫兵（部署后 operator 初始为 0 → 一切 advance 拒绝，
    /// 直至 authority 调 setOperator）。
    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    /// 逃生舱冻结卫兵（镜像 L1Outbox.whenNotFrozen 的语义；escapeHatch 为
    /// 构造强制非零的不可变接线，无需零址短路分支）。只挂 advance——
    /// 冻结期新垫付停摆，分流/领取面不卡。
    modifier whenNotFrozen() {
        if (IEscapeHatch(escapeHatch).isFrozen()) revert Frozen();
        _;
    }

    // ------------------------------------------------------------------
    // 事件
    // ------------------------------------------------------------------

    event OperatorSet(address indexed operator);
    /// token = address(0) 表示原生 MON。
    event PoolFunded(address indexed token, address indexed funder, uint256 amount);
    event AdvancePaid(bytes32 indexed requestId, address indexed recipient, uint8 assetTag, uint256 amount);

    /// credit 分流：operator 与用户份额一次事件全披露；advanceValid 供审计
    /// 无效垫付归零；operatorCredited = 实际入账主体（funder 快照，轮换稽核面）。
    event WithdrawalRouted(
        bytes32 indexed requestId,
        address indexed recipient,
        uint8 assetTag,
        uint256 leafAmount, // Y
        uint256 advancedTotal, // X（台账原值，含无效垫付）
        uint256 operatorShare, // min(X_eff, Y)
        uint256 userShare, // Y − operatorShare
        bool advanceValid,
        address operatorCredited
    );

    event CreditClaimed(address indexed token, address indexed owner, uint256 amount);
    event OperatorWithdrew(address indexed token, uint256 amount);

    /// receive() 统一入账留痕（claim 落账与误直转均触发；链下以 tx 上下文区分）。
    event NativeReceived(address indexed from, uint256 amount);

    // ------------------------------------------------------------------
    // 错误（与既有合约同名错误为有意复用——语义逐字节相同的判定不另造名）
    // ------------------------------------------------------------------

    error NotOperator();
    error RequestBindingMismatch();
    error UnsupportedAssetTag();
    error TokenNotSet();
    error BadAmount();
    error AlreadyRouted();
    error TokenRemapped();
    error InsufficientFloat();
    error TokenTransferFailed();
    error LeafRecipientNotFastExit();
    error NotYetClaimed();
    error ClaimedLeafMismatch();
    error RootNotCommitted();
    error IndexBeyondLeafCount();
    error WithdrawalProofInvalid();
    error NothingToClaim();
    error ExceedsWithdrawable();
    error Frozen();
    error Reentrant();
    // ZeroAddress / NotAuthority / IsPaused 继承自 AuthorityOwnable。

    // ------------------------------------------------------------------
    // 构造 / 配置
    // ------------------------------------------------------------------

    /// @notice 构造：接线 outbox 与 escapeHatch（均不可变，一次性）。
    constructor(address initialAuthority_, address outbox_, address escapeHatch_)
        AuthorityOwnable(initialAuthority_)
    {
        if (outbox_ == address(0) || escapeHatch_ == address(0)) revert ZeroAddress();
        outbox = IL1OutboxForFastExit(outbox_);
        escapeHatch = escapeHatch_;
    }

    /// @notice 设置/轮换 operator（垫付热键，建议与 authority 多签分离）。
    ///         轮换语义：只影响**新垫付**的归属——在途垫付的回收仍按
    ///         AdvanceRecord.funder 快照入账；轮换窗口内对既有 requestId
    ///         的追加垫付，其回收仍归首笔 funder（首笔固定语义，运营侧
    ///         应在轮换窗口避免在途追加或链下对账）。
    function setOperator(address operator_) external onlyAuthority {
        if (operator_ == address(0)) revert ZeroAddress();
        operator = operator_;
        emit OperatorSet(operator_);
    }

    // ------------------------------------------------------------------
    // 浮存注入（唯一合法注资口）
    // ------------------------------------------------------------------

    /// @notice 注入原生 MON 浮存（任何人可注；实入 floatLedger）。
    ///         直接 transfer 进合约的钱不入浮存、无出口（误直转滞留）。
    function fund() external payable {
        floatLedger[address(0)] += msg.value;
        emit PoolFunded(address(0), msg.sender, msg.value);
    }

    /// @notice 注入 ERC20 浮存（先 approve；USDT 无返回值兼容，镜像
    ///         L1Bridge._pullToken）。原生注资只可走 fund()——token 传
    ///         address(0) 会虚增无背书的原生浮存（solvency 破坏面，拒绝）。
    function fundToken(address token, uint256 amount) external {
        if (token == address(0)) revert ZeroAddress();
        if (amount == 0) revert BadAmount();
        _pullToken(token, msg.sender, amount);
        floatLedger[token] += amount;
        emit PoolFunded(token, msg.sender, amount);
    }

    // ------------------------------------------------------------------
    // 垫付
    // ------------------------------------------------------------------

    /// @notice operator 预垫付：同笔 tx 从池内付给 recipient 并记账。
    ///         requestId 必须满足绑定哈希 requestBinding(recipient, nonce,
    ///         assetTag) == requestId（防 operator 伪造收款人——绑定即快速
    ///         通道叶子的 L2 侧派生约定）。
    /// @param requestId 快速通道叶子 requestId（= 绑定哈希）
    /// @param recipient 用户 L1 收款地址 R（哈希绑定校验对象）
    /// @param assetTag  1=MON、3/4=ERC20（2 拒绝）
    /// @param amount    本笔垫付额（多次垫付累加；X>Y 自亏不设上限）
    /// @param nonce     L2 侧 12B 随机数（绑定哈希原料）
    function advance(bytes32 requestId, address recipient, uint8 assetTag, uint64 amount, bytes12 nonce)
        external
        onlyOperator
        whenNotFrozen
        whenNotPaused
        nonReentrant
    {
        // ---- 绑定哈希：收款人/资产/nonce 在垫付前就烧进 requestId ----
        if (requestId != requestBinding(recipient, nonce, assetTag)) revert RequestBindingMismatch();

        // ---- tag 纪律（fail-closed）：合法面 = {1=原生} ∪ [3,255]=ERC20；
        //      tag 2（PLAY）为 L2 内部筹码，不可垫付不可路由 ----
        if (assetTag != TAG_REAL_NATIVE && assetTag < TAG_REAL_USDT) {
            revert UnsupportedAssetTag();
        }

        // ---- tag ≥ 3：token 复用 L1Outbox.tokenForTag（单一事实源）----
        address token = address(0);
        if (assetTag >= TAG_REAL_USDT) {
            token = outbox.tokenForTag(assetTag);
            if (token == address(0)) revert TokenNotSet();
        }

        if (amount == 0) revert BadAmount();
        if (recipient == address(0)) revert ZeroAddress();

        AdvanceRecord storage a = advances[requestId];
        // ---- 已结算的 requestId 禁止再垫（杜绝用户总额 > Y）----
        if (a.routed) revert AlreadyRouted();

        // ---- 首笔初始化（funder/token/tag 快照固定）；追加笔校验 token
        //      快照（fail-closed，防 authority 中途换币造成跨资产错配；
        //      funder 不改写）----
        if (a.funder == address(0)) {
            a.funder = msg.sender;
            a.token = token;
            a.assetTag = assetTag;
        } else if (token != a.token) {
            revert TokenRemapped();
        }

        // ---- effects（先于出账；出账失败整笔回滚，无幻影台账）----
        a.amount += amount;
        totalOutstanding[token] += amount;
        emit AdvancePaid(requestId, recipient, assetTag, amount);

        // ---- 浮存校验与出账（记账与资金流同笔 tx 绑定）----
        if (floatLedger[token] < amount) revert InsufficientFloat();
        floatLedger[token] -= amount;
        _payout(token, recipient, amount);
        // 注：push 失败（如 R 为无 receive() 合约）= 该用户无法快速垫付，
        // 整笔回滚零台账；其慢路径 claimAndRoute（X=0）+ pull credit 仍可用。
    }

    // ------------------------------------------------------------------
    // 领取并分流（快路径 = 慢路径）
    // ------------------------------------------------------------------

    /// @notice 任何人可调：FastExit 代发 L1Outbox.claim（收款人 = FastExit，
    ///         原子落账 Y）后纯记账分流（零外呼）：operator 得 min(X_eff, Y)
    ///         （垫付有效时，按 funder 快照入账），用户得 Y − min(X_eff, Y)，
    ///         均入 credit。X=0（无人垫付）时全额 Y 归用户——本函数即慢路径。
    ///         有意不挂 whenNotPaused/whenNotFrozen（对齐 L1Outbox.claim 自身
    ///         亦不挂冻结卫兵——用户取回面不卡死；栈级 pause 时 claim 传导
    ///         回滚，unpause 后可重试）。
    /// @param leaf/root/leafCount/index/proof 与 L1Outbox.claim 同形。
    /// @param recipient 用户 L1 收款地址 R（绑定哈希 preimage 之一，合约
    ///        不可从叶子反解，须调用方供给）。
    /// @param nonce     绑定哈希 preimage 之一。
    function claimAndRoute(
        L1Outbox.WithdrawalLeaf calldata leaf,
        bytes32 root,
        uint64 leafCount,
        uint64 index,
        bytes32[] calldata proof,
        address recipient,
        bytes12 nonce
    ) external nonReentrant {
        // ---- 防抽干前置：叶子收款人不是 FastExit 时，claim 付款给他人而
        //      分流会动用池内资金 ----
        if (address(uint160(uint256(leaf.externalRecipient))) != address(this)) {
            revert LeafRecipientNotFastExit();
        }
        // ---- 快速通道叶子判定 + 用户 R 的密码学恢复 ----
        if (leaf.requestId != requestBinding(recipient, nonce, leaf.assetTag)) revert RequestBindingMismatch();
        // ---- 与 outbox.claim 的 claimedRequests 双保险 ----
        if (advances[leaf.requestId].routed) revert AlreadyRouted();

        // ---- effects（routed、credit、outstanding 全部先于唯一外部调用）；
        //      claim 内任一检查失败 → 整笔回滚、台账原子还原，可重试 ----
        _split(leaf, recipient);

        // ---- interaction：Y 经 Bridge 付给 FastExit（原生走 receive() 仅
        //      emit 事件，ERC20 走低层 transfer 无回调）----
        outbox.claim(leaf, root, leafCount, index, proof);
    }

    // ------------------------------------------------------------------
    // 外部已 claim 叶子的补救分流
    // ------------------------------------------------------------------

    /// @notice 补救路径：叶子已被第三方直接 outbox.claim 抢先领到 FastExit
    ///         后，任何人凭同一证明材料补做分流。纯记账、零外呼（全部
    ///         outbox 访问均为 view）。
    ///         分流证据 = L1Outbox.claimedLeafMatches(leaf)（叶哈希台账）：
    ///         证明"被领取的正是这片叶子（六字段全同）"，而非仅 requestId
    ///         曾被置位——后者对同 requestId 的第二片叶子同样为真，会铸出
    ///         无背书 credit。有意不挂 pause/freeze、不检查 finalized
    ///         （分流是已发生历史支付的记账补救，支付当时已过 claim 的
    ///         finalized 判定；叶哈希匹配才是权威证据）。
    function route(
        L1Outbox.WithdrawalLeaf calldata leaf,
        bytes32 root,
        uint64 leafCount,
        uint64 index,
        bytes32[] calldata proof,
        address recipient,
        bytes12 nonce
    ) external nonReentrant {
        if (address(uint160(uint256(leaf.externalRecipient))) != address(this)) {
            revert LeafRecipientNotFastExit();
        }
        if (leaf.requestId != requestBinding(recipient, nonce, leaf.assetTag)) revert RequestBindingMismatch();
        if (advances[leaf.requestId].routed) revert AlreadyRouted();

        // ---- 台账与证明判定（判定序镜像 L1Outbox.claim，凡可镜像处复用
        //      同名错误；本函数不检查 finalized——见 natspec）----
        bytes32 digest = outbox.digestOf(leaf.checkpointHeight, leafCount, root);
        L1Outbox.RootRecord memory rr = outbox.roots(digest);
        if (rr.root != root) revert RootNotCommitted();
        if (index >= rr.leafCount) revert IndexBeyondLeafCount();

        // ---- 叶哈希证据：该 requestId 从未被领取 / 曾领取的是另一片叶子
        //      （同 requestId 双叶攻击面）----
        if (outbox.claimedLeafHashes(leaf.requestId) == bytes32(0)) revert NotYetClaimed();
        if (!outbox.claimedLeafMatches(leaf)) revert ClaimedLeafMismatch();

        if (!outbox.verifyInclusion(leaf, proof, index, root)) revert WithdrawalProofInvalid();

        // ---- 分流记账（与 claimAndRoute 完全一致的 _split 语义）----
        _split(leaf, recipient);
    }

    // ------------------------------------------------------------------
    // 领取 / 回收
    // ------------------------------------------------------------------

    /// @notice 领取 credit（用户差额份额与 operator 回收份额共用）：任何人
    ///         可代办，款项恒付 owner（pull 语义，拒收卡死被消灭）。先清零
    ///         后转账（重入撞零余额），转账失败整笔回滚可重试。无
    ///         pause/freeze 卫兵（用户取回面）。
    function claimCredit(address token, address owner) external {
        uint256 amount = credits[token][owner];
        if (amount == 0) revert NothingToClaim();
        credits[token][owner] = 0;
        totalCredits[token] -= amount;
        _payout(token, owner, amount);
        emit CreditClaimed(token, owner, amount);
    }

    /// @notice operator 提取浮存超额：amount ≤ floatLedger[token] −
    ///         totalOutstanding[token]，否则 ExceedsWithdrawable。claim 落账
    ///         资金与 credit 不在可提面（floatLedger 隔离——抢先 claim 落账
    ///         的 Y 在 route 前不可被 operator 提走，credit 恒有背书）。
    ///         注：直接 transfer 进合约的原生币不入 floatLedger、亦无其他
    ///         出口（误直转滞留）。
    function operatorWithdraw(address token, uint256 amount)
        external
        onlyOperator
        whenNotPaused
        nonReentrant
    {
        if (amount > withdrawable(token)) revert ExceedsWithdrawable();
        floatLedger[token] -= amount;
        _payout(token, msg.sender, amount);
        emit OperatorWithdrew(token, amount);
    }

    // ------------------------------------------------------------------
    // 视图
    // ------------------------------------------------------------------

    /// @notice 绑定哈希（L2 侧派生约定的 Solidity 镜像；供 daemon/测试对拍）：
    ///         sha256("zchain.fastexit.request.v1" ‖ bytes20(recipient) ‖
    ///         bytes12(nonce) ‖ uint8(assetTag))。注：声明为 public（草案
    ///         签名 external）——advance/claimAndRoute/route 内部复用同一
    ///         实现，外部 ABI 面不变。
    function requestBinding(address recipient, bytes12 nonce, uint8 assetTag) public view returns (bytes32) {
        return _sha256(abi.encodePacked(BINDING_DOMAIN, bytes20(recipient), nonce, bytes1(assetTag)));
    }

    /// @notice operator 当前可提超额（原生：token 传 address(0)）。当浮存被
    ///         在途垫付超额占用（floatLedger < totalOutstanding，可达态——
    ///         每笔垫付使差额下降 2X：出账 X + 在途锁 X）时按 0 处理（提额
    ///         锁死 fail-closed；字面减法会以算术下溢 Panic 替代干净回退）。
    function withdrawable(address token) public view returns (uint256) {
        return floatLedger[token] > totalOutstanding[token]
            ? floatLedger[token] - totalOutstanding[token]
            : 0;
    }

    // ------------------------------------------------------------------
    // 兼容收款（L1Bridge.payoutNative 以空 calldata 调用收款人——无
    // receive() 则整笔 claim revert）
    // ------------------------------------------------------------------

    /// @notice 函数体仅 emit NativeReceived（不可 revert——毒化打款语义同
    ///         L1Bridge.payoutNative 注释）：claim 落账与任何误直转入金统一
    ///         留痕，供链下对账区分"合法落账 vs 误直转"（后者不入浮存、
    ///         无出口）。事件外零状态、零调用 → 空体语义等同，天然不可
    ///         重入，不加守卫（若加 nonReentrant 会在 claimAndRoute 持锁
    ///         期间使 payout 回调自锁死——设计上禁止）。
    receive() external payable {
        emit NativeReceived(msg.sender, msg.value);
    }

    // ------------------------------------------------------------------
    // 内部：分流记账 / 转账原语 / 哈希原语
    // ------------------------------------------------------------------

    /// @notice 分流记账（claimAndRoute 与 route 共用）：operator 得
    ///         min(X_eff, Y)、用户得 Y − min(X_eff, Y)，均入 credit；在途
    ///         计减按垫付全额（无效垫付同样计减——该垫付已了结，锁定的
    ///         是 operator 自身浮存）。纯记账零外呼。
    function _split(L1Outbox.WithdrawalLeaf calldata leaf, address recipient) private {
        bytes32 requestId = leaf.requestId;
        uint256 y = leaf.amount;
        AdvanceRecord storage a = advances[requestId];

        // ---- effects ----
        a.routed = true;

        // 叶子资产（tag1 = 原生；tag ≥ 3 = 当前 tokenForTag——与垫付快照
        // 逐一比对即垫付有效性判定）。
        address token = leaf.assetTag == TAG_REAL_NATIVE
            ? address(0)
            : outbox.tokenForTag(leaf.assetTag);

        // 垫付有效性 = 记录存在 && tag 匹配 && token 快照匹配；任一不匹配
        // → operator 回收 0，全额归用户（funder=address(0) 即无垫付记录）。
        bool advanceValid = a.funder != address(0) && a.assetTag == leaf.assetTag && a.token == token;
        uint256 operatorShare = advanceValid ? (a.amount < y ? a.amount : y) : 0;
        uint256 userShare = y - operatorShare;

        // 在途计减按垫付全额、按垫付时点 token 键（tag/token 失配的无效
        // 垫付也在此了结）。
        totalOutstanding[a.token] -= a.amount;

        // credit 按 funder 快照入账（轮换不转移在途归属），用户份额按
        // 绑定哈希恢复的 R 入账。
        credits[token][a.funder] += operatorShare;
        credits[token][recipient] += userShare;
        totalCredits[token] += y;

        emit WithdrawalRouted(
            requestId, recipient, leaf.assetTag, y, a.amount, operatorShare, userShare, advanceValid, a.funder
        );
    }

    /// @notice 出账原语：tag1 原生走低层 call，ERC20 走 USDT 兼容 transfer。
    function _payout(address token, address to, uint256 amount) private {
        if (token == address(0)) {
            (bool ok,) = to.call{value: amount}("");
            if (!ok) revert TokenTransferFailed();
        } else {
            _pushToken(token, to, amount);
        }
    }

    /// USDT 兼容的 transferFrom（镜像 L1Bridge._pullToken）。
    function _pullToken(address token, address from, uint256 amount) private {
        (bool ok, bytes memory ret) =
            token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, address(this), amount));
        if (!ok || (ret.length != 0 && !(ret.length == 32 && abi.decode(ret, (bool))))) {
            revert TokenTransferFailed();
        }
    }

    /// USDT 兼容的 transfer（镜像 L1Bridge._pushToken）。
    function _pushToken(address token, address to, uint256 amount) private {
        (bool ok, bytes memory ret) =
            token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        if (!ok || (ret.length != 0 && !(ret.length == 32 && abi.decode(ret, (bool))))) {
            revert TokenTransferFailed();
        }
    }

    /// sha256 预编译（镜像 L1Outbox._sha256：输出必须落在已分配内存——
    /// 直接把栈变量当输出地址是未定义行为）。
    function _sha256(bytes memory input) private view returns (bytes32 result) {
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
}
