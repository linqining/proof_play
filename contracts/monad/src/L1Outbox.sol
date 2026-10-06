// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {AuthorityOwnable} from "./AuthorityOwnable.sol";
import {IERC20} from "./IERC20.sol";
import {IL1Bridge} from "./IL1Bridge.sol";

/// @notice 逃生舱冻结位查询接口（由 EscapeHatch 实现；commitRoot/markFinalized
///         挂 Frozen 卫兵——冻结期提现根不再注册/终结。claim **有意不挂**：
///         预冻结窗保留可领，与 EscapeHatch.escape 竞争 Bridge 浮存先到先得，
///         链上兜底 = 总流出 ≤ Bridge 浮存）。
interface IEscapeHatch {
    function isFrozen() external view returns (bool);
}

/// @title L1Outbox — zchain L2 → Monad(L1) 提现出箱
/// @notice L2 侧 REAL note burn → `WithdrawalLeaf` → 按 checkpoint 分窗聚合
///         为 `withdrawalRoot`（RFC 6962 风格域分隔 sha256 树，见
///         poker-appchain `withdrawal_root.rs`）→ checkpoint BFT finalized 后
///         经 L1Inbox.submitCheckpoint 注册到本合约 → 用户（或代办方）持
///         Merkle 证明 permissionless claim，资产由 L1Bridge 库支付。
///
///         本合约**逐字节镜像** Rust 侧树构造（golden 规则）：
///           - 域标签 DOMAIN = "zchain.vault.withdrawal_root.v1"；
///           - 叶：sha256(DOMAIN ‖ 0x00 ‖ borsh(leaf))，borsh(WithdrawalLeaf)
///             = request_id(32B) ‖ external_recipient(32B) ‖ asset_class(1B)
///             ‖ amount(8B 小端) ‖ burned_note_commitment(32B)
///             ‖ checkpoint_height(8B 小端)，共 113B；
///           - 内部节点：sha256(DOMAIN ‖ 0x01 ‖ l ‖ r)；
///           - 不平衡树以空叶 sha256(DOMAIN ‖ 0x00 ‖ "") 补齐到 2 的幂；
///           - 根摘要 digest = sha256(DOMAIN ‖ 0x02 ‖ height(8B 大端)
///             ‖ leaf_count(8B 大端) ‖ root)。
///         两侧一致性由 `monad-settlement` crate 的交叉验证测试锁死
///         （Rust builder 产根/证明 → 本合约等价 verifier 校验通过；篡改即败）。
///
///         最终性纪律（审计项 §6）：
///           - 根可领取的前提 = finalized（L2 BFT finalized 先于上锚，
///             由 daemon 纪律保证；未终结根须等 markFinalized）；
///           - 大额提现追加 Monad 侧出块延迟（claimDelayBlocks），覆盖
///             MonadBFT 异步执行的极端 reorg 窗口；
///           - request_id 一经领取永久记账（防重放）；重入由
///             effects-before-interactions + nonReentrant 双保险。
contract L1Outbox is AuthorityOwnable {
    // ------------------------------------------------------------------
    // 常量（与 poker-appchain::withdrawal_root 逐字节对齐）
    // ------------------------------------------------------------------

    /// RFC 6962 前缀。
    uint256 private constant LEAF_PREFIX = 0x00;
    uint256 private constant INTERNAL_PREFIX = 0x01;
    uint256 private constant DIGEST_PREFIX = 0x02;

    /// 资产标签（poker-appchain `leaf_asset_tag` 冻结判别表）。
    uint8 public constant TAG_REAL_NATIVE = 1; // MON
    uint8 public constant TAG_GAME_PLAY_LEGACY = 2; // L2 内部筹码，不可上 L1 领取
    uint8 public constant TAG_REAL_USDT = 3;
    uint8 public constant TAG_REAL_USDC = 4;

    /// 证明深度上限（与 Rust verify_inclusion 的 >=64 拒绝对齐）。
    uint256 private constant MAX_PROOF_LEN = 63;

    // ------------------------------------------------------------------
    // 数据结构
    // ------------------------------------------------------------------

    struct RootRecord {
        bytes32 root;
        uint64 leafCount;
        uint64 l2Height;
        uint64 committedAt; // Monad 高度（大额延迟基准）
        bool finalized;
    }

    /// leaf 承诺（与 poker-appchain `WithdrawalLeaf` 字段一一对应；
    /// Solidity 侧哈希前按 borsh 小端重打包，见 `_leafHash`）。
    struct WithdrawalLeaf {
        bytes32 requestId;
        bytes32 externalRecipient; // 低 20B = EVM 地址
        uint8 assetTag;
        uint64 amount; // 打款净额（fee 已扣）
        bytes32 burnedNoteCommitment;
        uint64 checkpointHeight;
    }

    // ------------------------------------------------------------------
    // 存储
    // ------------------------------------------------------------------

    /// digest → 根记录（digest 绑定 (height, leaf_count, root) 三元组）。
    mapping(bytes32 digest => RootRecord) public roots;
    /// request_id → 已领取（跨根全局防重放）。
    mapping(bytes32 requestId => bool) public claimedRequests;
    /// 资产标签 → L1 代币地址（0 = 未配置；tag 1 = 原生 MON 走 Bridge 库）。
    mapping(uint8 tag => address) public tokenForTag;

    /// L1Bridge 地址（资金库；一次性设置）。
    IL1Bridge public bridge;
    /// L1Inbox 地址（允许 Inbox 在 submitCheckpoint 中代为 commitRoot）。
    address public inbox;
    /// EscapeHatch 地址（一次性设置；0 = 未接线，冻结卫兵短路为零开销）。
    address public escapeHatch;

    /// 大额判定阈值（按标签；0 = 该标签不启用延迟）。
    mapping(uint8 tag => uint256) public largePayoutThreshold;
    /// 大额提现追加的 Monad 出块延迟（MonadBFT 终结 ≈ 亚秒，30 块 ≈ 30s
    /// 量级，覆盖异步执行极端情形；可由 authority 调整）。
    uint64 public claimDelayBlocks = 30;

    /// request_id → 已领取叶子的完整哈希（FastExit.route 补救分流的证据面：
    /// claim 与 :279 同点写入，供外部合约校验"被领取的正是这片叶子"——
    /// 仅 requestId 键控的 claimedRequests 不绑定叶内容，重复 request_id 的
    /// 第二片叶子无法凭它证明款项落账归属）。声明置于存储段末尾 = 追加式，
    /// 不动既有槽位。
    mapping(bytes32 requestId => bytes32) public claimedLeafHashes;

    // ------------------------------------------------------------------
    // 事件
    // ------------------------------------------------------------------

    event WithdrawalRootCommitted(
        bytes32 indexed digest,
        uint64 indexed l2Height,
        uint64 leafCount,
        bytes32 root,
        bool finalized
    );
    event RootFinalized(bytes32 indexed digest);
    event WithdrawalClaimed(
        bytes32 indexed digest,
        bytes32 indexed requestId,
        address indexed recipient,
        uint8 assetTag,
        uint256 amount
    );
    event TokenTagSet(uint8 indexed tag, address indexed token);
    event BridgeSet(address indexed bridge);
    event InboxSet(address indexed inbox);
    event EscapeHatchSet(address indexed escapeHatch);
    event ClaimDelayUpdated(uint64 blocks);
    event LargePayoutThresholdUpdated(uint8 indexed tag, uint256 threshold);

    // ------------------------------------------------------------------
    // 错误（与 poker-appchain AppchainError 语义对齐的命名）
    // ------------------------------------------------------------------

    error RootNotCommitted();
    error RootNotFinalized();
    error AlreadyCommitted();
    error AlreadyClaimed();
    error WithdrawalProofInvalid();
    error IndexBeyondLeafCount();
    error UnsupportedAssetTag();
    error ClaimTooEarly();
    error BridgeAlreadySet();
    error InboxAlreadySet();
    error BridgeNotSet();
    error TokenNotSet();
    error ProofShapeInvalid();
    error EscapeHatchAlreadySet();
    error Frozen();

    // ------------------------------------------------------------------
    // 构造 / 一次性配置
    // ------------------------------------------------------------------

    constructor(address initialAuthority_) AuthorityOwnable(initialAuthority_) {}

    function setBridge(address bridge_) external onlyAuthority {
        if (bridge_ == address(0)) revert ZeroAddress();
        if (address(bridge) != address(0)) revert BridgeAlreadySet();
        bridge = IL1Bridge(bridge_);
        emit BridgeSet(bridge_);
    }

    function setInbox(address inbox_) external onlyAuthority {
        if (inbox_ == address(0)) revert ZeroAddress();
        if (inbox != address(0)) revert InboxAlreadySet();
        inbox = inbox_;
        emit InboxSet(inbox_);
    }

    /// 一次性接线 EscapeHatch（0 永不回滚为未接线态）。
    function setEscapeHatch(address escapeHatch_) external onlyAuthority {
        if (escapeHatch_ == address(0)) revert ZeroAddress();
        if (escapeHatch != address(0)) revert EscapeHatchAlreadySet();
        escapeHatch = escapeHatch_;
        emit EscapeHatchSet(escapeHatch_);
    }

    /// 配置资产标签 → L1 代币（tag 1/2 不可配置：1 为原生、2 为 L2 内部筹码）。
    function setTokenForTag(uint8 tag, address token) external onlyAuthority {
        if (tag < TAG_REAL_USDT) revert UnsupportedAssetTag();
        if (token == address(0)) revert ZeroAddress();
        tokenForTag[tag] = token;
        emit TokenTagSet(tag, token);
    }

    function setClaimDelayBlocks(uint64 blocks_) external onlyAuthority {
        claimDelayBlocks = blocks_;
        emit ClaimDelayUpdated(blocks_);
    }

    function setLargePayoutThreshold(uint8 tag, uint256 threshold) external onlyAuthority {
        largePayoutThreshold[tag] = threshold;
        emit LargePayoutThresholdUpdated(tag, threshold);
    }

    // ------------------------------------------------------------------
    // 根注册（authority 直提交，或 Inbox 在 submitCheckpoint 中代为提交）
    // ------------------------------------------------------------------

    modifier commitAuth() {
        if (msg.sender != authority && msg.sender != inbox) revert NotAuthority();
        _;
    }

    /// 逃生舱冻结卫兵：冻结期 authority 直通口（commitAuth 的 authority 分支）
    /// 一并堵死——旧提现根不再注册/终结；未接线时短路为零开销、零行为变化。
    modifier whenNotFrozen() {
        if (escapeHatch != address(0) && IEscapeHatch(escapeHatch).isFrozen()) revert Frozen();
        _;
    }

    /// 注册提现根。`finalized=false` 时须等 authority 调 markFinalized 才可领。
    function commitRoot(uint64 l2Height, uint64 leafCount, bytes32 root, bool finalized)
        external
        commitAuth
        whenNotFrozen
        whenNotPaused
    {
        if (root == bytes32(0)) revert ZeroAddress();
        bytes32 digest = digestOf(l2Height, leafCount, root);
        if (roots[digest].root != bytes32(0)) revert AlreadyCommitted();

        roots[digest] = RootRecord({
            root: root,
            leafCount: leafCount,
            l2Height: l2Height,
            committedAt: uint64(block.number),
            finalized: finalized
        });
        emit WithdrawalRootCommitted(digest, l2Height, leafCount, root, finalized);
    }

    /// 未终结根的终结标记（daemon 纪律下通常不需要：上锚前已 finalized）。
    /// 冻结期拒绝（未终结根留待解冻后再终结）。
    function markFinalized(bytes32 digest) external commitAuth whenNotFrozen {
        if (roots[digest].root == bytes32(0)) revert RootNotCommitted();
        if (!roots[digest].finalized) {
            roots[digest].finalized = true;
            emit RootFinalized(digest);
        }
    }

    // ------------------------------------------------------------------
    // 领取
    // ------------------------------------------------------------------

    /// @notice 持 Merkle 证明领取提现。资产由 L1Bridge 库支付：
    ///         tag 1 = 原生 MON；tag 3/4 = L1 ERC20；tag 2（PLAY）为 L2
    ///         内部筹码，不提供 L1 兑付（fail-closed）。
    /// @param leaf 提现承诺全字段（任一字段被篡改 → 证明校验失败）。
    /// @param root 待领取的提现根（从 Inbox CheckpointAnchored 事件查得）。
    /// @param leafCount 根窗口真实叶子数（与 root 一起注册）。
    /// @param index 叶子在规范化树中的位置（0 起）。
    /// @param proof 兄弟哈希路径（自叶向根）。
    function claim(
        WithdrawalLeaf calldata leaf,
        bytes32 root,
        uint64 leafCount,
        uint64 index,
        bytes32[] calldata proof
    ) external whenNotPaused {
        // ---- 台账判定（fail-closed 顺序与 ClaimLedger 一致）----
        bytes32 digest = digestOf(leaf.checkpointHeight, leafCount, root);
        RootRecord storage rr = roots[digest];
        if (rr.root == bytes32(0)) revert RootNotCommitted();
        if (!rr.finalized) revert RootNotFinalized();
        if (index >= rr.leafCount) revert IndexBeyondLeafCount();
        if (claimedRequests[leaf.requestId]) revert AlreadyClaimed();

        // ---- 证明校验 ----
        if (!verifyInclusion(leaf, proof, index, root)) revert WithdrawalProofInvalid();

        // ---- effects 先于 interactions（重入防线 1/2）----
        claimedRequests[leaf.requestId] = true;
        claimedLeafHashes[leaf.requestId] = _leafHash(leaf);

        // ---- 大额延迟（Monad 侧 reorg/异步执行窗口）----
        uint64 delay = _delayFor(leaf.assetTag, leaf.amount);
        if (uint64(block.number) < rr.committedAt + delay) revert ClaimTooEarly();

        // ---- 支付（interactions 最后；重入防线 2/2 = Bridge 侧 onlyOutbox）----
        address recipient = address(uint160(uint256(leaf.externalRecipient)));
        if (recipient == address(0)) revert ZeroAddress();

        if (leaf.assetTag == TAG_REAL_NATIVE) {
            bridge.payoutNative(recipient, leaf.amount);
        } else if (leaf.assetTag >= TAG_REAL_USDT) {
            address token = tokenForTag[leaf.assetTag];
            if (token == address(0)) revert TokenNotSet();
            bridge.payoutToken(token, recipient, leaf.amount);
        } else {
            revert UnsupportedAssetTag();
        }

        emit WithdrawalClaimed(digest, leaf.requestId, recipient, leaf.assetTag, leaf.amount);
    }

    // ------------------------------------------------------------------
    // Merkle 校验（逐字节镜像 Rust `verify_inclusion`）
    // ------------------------------------------------------------------

    /// @notice 包含证明校验（public：FastExit.route 需对"已被 claim 的叶子"
    ///         自持校验——无法借道 claim（AlreadyClaimed））。
    function verifyInclusion(
        WithdrawalLeaf calldata leaf,
        bytes32[] calldata proof,
        uint64 index,
        bytes32 root
    ) public view returns (bool) {
        // 形状防线：证明过深或 index 超出路径覆盖范围 → 不可能属于本树。
        if (proof.length > MAX_PROOF_LEN) return false;
        if (proof.length < 64 && (index >> proof.length) != 0) return false;

        bytes32 h = _leafHash(leaf);
        for (uint256 depth = 0; depth < proof.length; depth++) {
            bytes32 sibling = proof[depth];
            if ((index >> depth) & 1 == 0) {
                h = _internalHash(h, sibling);
            } else {
                h = _internalHash(sibling, h);
            }
        }
        return h == root;
    }

    // ------------------------------------------------------------------
    // 哈希原语（逐字节镜像 Rust 侧）
    // ------------------------------------------------------------------

    function _sha256(bytes memory input) private view returns (bytes32 result) {
        // Monad 为 EVM 等价：0x02 = sha256 预编译可用。
        // 输出必须落在已分配内存（mload(0x40) 前进 32B 后读回）——直接把
        // 栈变量当输出地址是未定义行为（Monad 测试网实测抓出：哈希恒为
        // 栈上垃圾 → WithdrawalProofInvalid / AlreadyCommitted 连环假象）。
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
        return bytes("zchain.vault.withdrawal_root.v1");
    }

    /// u64 小端 8 字节（borsh 编码；Solidity 默认大端，须手工展开）。
    function _le64(uint64 v) private pure returns (bytes memory) {
        bytes memory out = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            out[i] = bytes1(uint8(v >> (8 * i)));
        }
        return out;
    }

    function _be64(uint64 v) private pure returns (bytes memory) {
        return abi.encodePacked(bytes8(v));
    }

    /// 叶哈希：sha256(DOMAIN ‖ 0x00 ‖ borsh(leaf))；borsh 字段序与紧凑
    /// 小端编码必须与本函数 packed 段完全一致（113B）。
    function _leafHash(WithdrawalLeaf calldata leaf) private view returns (bytes32) {
        return _sha256(
            abi.encodePacked(
                _domain(),
                bytes1(uint8(LEAF_PREFIX)),
                leaf.requestId,
                leaf.externalRecipient,
                bytes1(leaf.assetTag),
                _le64(leaf.amount),
                leaf.burnedNoteCommitment,
                _le64(leaf.checkpointHeight)
            )
        );
    }

    /// 内部节点：sha256(DOMAIN ‖ 0x01 ‖ l ‖ r)。
    function _internalHash(bytes32 l, bytes32 r) private view returns (bytes32) {
        return _sha256(abi.encodePacked(_domain(), bytes1(uint8(INTERNAL_PREFIX)), l, r));
    }

    /// 空叶哈希（不平衡树补齐位；claim 校验不感知补齐——证明路径自带）。
    function emptyLeafHash() public view returns (bytes32) {
        return _sha256(abi.encodePacked(_domain(), bytes1(uint8(LEAF_PREFIX))));
    }

    /// 根摘要：sha256(DOMAIN ‖ 0x02 ‖ height_be ‖ leaf_count_be ‖ root)。
    function digestOf(uint64 l2Height, uint64 leafCount, bytes32 root) public view returns (bytes32) {
        return _sha256(
            abi.encodePacked(_domain(), bytes1(uint8(DIGEST_PREFIX)), _be64(l2Height), _be64(leafCount), root)
        );
    }

    /// @notice requestId 名下已领取的叶子是否与给定叶子完全一致
    ///         （claimedLeafHashes 非零且等于本叶哈希；FastExit.route 的分流证据）。
    function claimedLeafMatches(WithdrawalLeaf calldata leaf) public view returns (bool) {
        bytes32 claimed = claimedLeafHashes[leaf.requestId];
        return claimed != bytes32(0) && claimed == _leafHash(leaf);
    }

    // ------------------------------------------------------------------
    // 延迟策略
    // ------------------------------------------------------------------

    function _delayFor(uint8 assetTag, uint64 amount) private view returns (uint64) {
        uint256 threshold = largePayoutThreshold[assetTag];
        if (threshold != 0 && uint256(amount) >= threshold) {
            return claimDelayBlocks;
        }
        return 0;
    }
}
