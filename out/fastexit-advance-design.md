# FastExit 接口草案 — 站起即领的运营垫付通道（zchain Monad 结算栈）

> 状态：设计草案 v2（接口签名 + 语义 + 安全论证；不含实现代码）。v2 系评审修订版：修复 route() 以 `claimedRequests` 为分流证据的重放抽干面（评审 High）、operator 轮换归属、receive() 误注资滞留、既有部署升级路径（三条 Low）。
> 依据：本会话实际读取 `zchain/contracts/monad/src/{L1Outbox,L1Bridge,EscapeHatch,AuthorityOwnable,IL1Bridge}.sol`、`script/Deploy.s.sol`、`test/EscapeHatch.t.sol`（helper 区），及任务书附带的《FastExit 先例调研纪要》《仓库勘察纪要》（勘察中"已实测"条目系上会话 /tmp 执行）。
> **本会话已执行验证**：在 `/tmp/fastexit-probe` 副本应用 §3.2 全量 L1Outbox 增量 diff 后 `forge build` 通过（exit 0，仅存量 lint 告警）；`forge test` 全套 **100 passed / 0 failed**（既有 98 + 本次新增 2 支评审修复探针，含"同 requestId 双叶攻击必须被 `claimedLeafMatches` 判别"用例）。探针源：`/tmp/fastexit-probe/test/ClaimedLeafProbe.t.sol`。

---

## 一、概述与先例对标

### 1.1 机制总览

用户在 L2 站起时选择快速通道：L2 生成**快速通道叶子**（`externalRecipient = FastExit 合约地址`，`requestId` 按新约定由用户 L1 收款地址推导，见 §6.1 接线要求）。operator 收到 L2 事件后调用 `advance` 从自有浮存池**先行垫付**（同笔 tx 出账 + 记账）。checkpoint 上锚后，任何人可调 `claimAndRoute`：FastExit 以自己名义代发 `L1Outbox.claim`（叶子收款人即 FastExit，原子落账 Y），随即纯记账分流——operator 得 `min(X, Y)`、用户得 `Y − min(X, Y)`，两者均记入 **pull 式 credit**，随时可领。第三方抢跑直接 claim 的叶子由 `route()` 凭 **L1Outbox 侧新增的"已领叶哈希台账"**（§3.2）补救分流。operator 不垫付时，`claimAndRoute` 本身就是用户的慢路径（X=0 → 全额 Y 归用户），permissionless、无排他窗口。

### 1.2 关键设计决策 → 先例对标

| # | 设计决策 | 对标方案 | 借鉴点 / 规避的陷阱 |
|---|---------|---------|---------------------|
| D1 | operator 垫付仅是流动性前置，`claimAndRoute` permissionless、无排他窗口，X=0 时全额归用户 | Across slowFill；StarkEx "任何人可调 withdraw" | 用户保底与垫付解耦（共性不变量 1）。规避 Across `NoSlowFillsInExclusivityWindow` 式排他锁死 |
| D2 | `requestId := sha256("zchain.fastexit.request.v1" ‖ bytes20(用户L1收款地址R) ‖ bytes12(nonce) ‖ uint8(assetTag))`——**收款人、资产、nonce 在垫付前就烧进 requestId** | Hop `transferId = hash(chainId, recipient, amount, nonce, bonderFee)` | 调研纪要陷阱节明言"zchain 的 external_recipient/asset_tag 应在垫付时即入哈希"。Hop 靠此使虚报 bond 永远冲不回。zchain 叶子结构 113B 是 Rust↔Solidity 金标准（L1Outbox.sol:23-34），不可加字段；**复用 requestId 这 32B 承载绑定**是零结构改动解。注意：**绑定哈希不含 amount**（D6 独立覆盖金额维），故 requestId 唯一性仅是 L2 纪律——D11 为其在 L1 侧的强制后盾 |
| D3 | operator 回收 = `min(X, Y)`，且仅当垫付有效（tag 匹配、token 未 remap）才可回收；无效垫付全额归用户 | Across 按真实成交量退款；Hop debit 只能被真实 transferId 冲销 | 回收上界 = 真实垫付额（共性不变量 2），垫付动作本身无法多拿 |
| D4 | `advance` 同笔 tx 内真实出账并记账（CEI：先记账后转账，转账失败整笔回滚） | Hop `bondWithdrawal`（bond 与 debit 同 tx） | 防链下打款后口头登记（任务书不变量 3）；防虚报截留 |
| D5 | requestId 一次性：claim 侧对齐 `L1Outbox.claimedRequests`（L1Outbox.sol:91-92, 273, 279），route 侧独立 `routed` 台账 | Across (deposit, relayer) 唯一记账；StarkEx pending 不可取消 | 防重放/防虚报（共性不变量 3）；route 已结算后禁止再 advance，杜绝用户总额 > Y |
| D6 | **分流证据绑定到叶内容本身**：L1Outbox claim 台账增记 `claimedLeafHashes[requestId] = _leafHash(leaf)`（叶哈希覆盖全部六字段含金额与收款人，L1Outbox.sol:367-380）；`route()` 以 `claimedLeafMatches(leaf)` 为唯一"款项确已落账本合约"的证据 | Hop `settleBondedWithdrawals`：debit 只能被 confirmed root 中**真实存在的那笔 transferId** 冲销 | 评审 High 修复：`claimedRequests` 仅按 requestId 键控（L1Outbox.sol:92），不绑定叶内容——同 requestId 的第二片叶子（金额/收款人可不同，因绑定哈希不含 amount、唯一性仅 L2 纪律）可借 route 铸无背书 credit 抽干池内待领资金。叶哈希台账把"被领取的是哪片叶子"变成 L1 强制事实，金额与收款人维度全部入绑（跨部署变体亦由此覆盖：两池叶子的 recipient 字段不同 → 叶哈希不同，§5.8） |
| D7 | 最终性/冻结风险归 operator：根不上锚、L2 回滚、EscapeHatch.escape 抽干浮存，损失均为 operator 已垫付的 X，用户已落袋 | Across 挑战期风险归 relayer；StarkEx 回滚风险归 operator | 共性不变量 4 |
| D8 | 无排他窗口、无强制费用（v1 免费垫付；用户最终所得 ≡ Y 由不变量硬性排除用户侧手续费） | Hop bonderFee / StarkEx max(gas, 0.1%) 收费模式 | 任务书不变量 1 与用户侧手续费互斥。对标收费动机转记运营侧商业考量，未来引入须修订不变量 1（§5.8） |
| D9 | 分流所得一律 pull 式 credit（用户与 operator 皆是），不 push | 本仓 `EscapeHatch.claimBond`（EscapeHatch.sol:390-399，"拒收卡死被 pull 化消灭"） | 规避：用户 R 为无 receive() 合约/恶意 revert 合约时，push 失败会把整条 claimAndRoute 永久卡死（叶子收款人固定为 FastExit，无其他出口） |
| D10 | FastExit 自带 nonReentrant + CEI + 分流零外呼 | 勘察/调研确认基座无 nonReentrant（勘察纪要 §3；本会话读 AuthorityOwnable.sol 全文证实） | 任务书不变量 8 明令自带；重入面收敛到空 receive()（§4.8） |
| D11 | operator 归属按**垫付时点快照**（`AdvanceRecord.funder`，首笔固定），route 回收计入快照主体；轮换不改变在途归属 | Across relayer 退款记给成交 relayer（非当下调用者） | 评审 Low-2 修复：否则 setOperator 轮换后在途回收隐性转入新主体名下且无事件可稽 |

---

## 二、完整接口清单

合约 `FastExit is AuthorityOwnable`（新文件 `src/FastExit.sol`；SPDX BUSL-1.1、`pragma ^0.8.24`、不引 OpenZeppelin，全中文 NatSpec——对齐 src/L1Outbox.sol:1-7, 16-42 风格）。文件内自带最小接口声明（对齐 L1Outbox.sol/L1Bridge.sol 各自声明 `IEscapeHatch` 的既有重复模式）：

```solidity
/// @notice FastExit 对 L1Outbox 的只读/领取面（claim、树校验、已领叶哈希台账、根 getter）。
interface IL1OutboxForFastExit {
    function claim(leaf, root, leafCount, index, proof) external;          // 签名用 L1Outbox.WithdrawalLeaf 全形
    function verifyInclusion(leaf, proof, index, root) external view returns (bool);   // §3.2 新暴露
    function claimedLeafHashes(bytes32 requestId) external view returns (bytes32);     // §3.2 新增台账
    function claimedLeafMatches(leaf) external view returns (bool);                    // §3.2 新增证据视图
    function roots(bytes32 digest) external view returns (L1Outbox.RootRecord memory);
    function tokenForTag(uint8 tag) external view returns (address);
    function digestOf(uint64 l2Height, uint64 leafCount, bytes32 root) external view returns (bytes32);
}

/// @notice 复用 L1Outbox.sol:12-14 / L1Bridge.sol:10-12 的同形冻结查询接口。
interface IEscapeHatch { function isFrozen() external view returns (bool); }
```

（`WithdrawalLeaf` 结构体直接 `import {L1Outbox}` 复用——测试侧已有此用法，EscapeHatch.t.sol:892-899，保持单一字段定义。）

### 2.1 存储结构

```solidity
/// 垫付台账（首笔初始化；同 requestId 后续只累加金额）。
struct AdvanceRecord {
    address funder;     // 首笔垫付时点的 operator 快照（回收归属；轮换不转移在途归属——评审 Low-2）
    address token;      // 首笔快照：tag1=address(0) 原生；tag≥3=outbox.tokenForTag(tag)
    uint8 assetTag;
    uint128 amount;     // 累计垫付 X
    bool routed;        // 一次性分流标记（route 侧防重放）
}

mapping(bytes32 requestId => AdvanceRecord) public advances;   // 键 = 叶子 requestId
mapping(address token => uint256) public floatLedger;          // operator 浮存（token=address(0)=原生 MON）
mapping(address token => uint256) public totalOutstanding;     // 在途垫付（同键约定）
mapping(address token => uint256) public totalCredits;         // 未领 credit 合计（solvency 证明用）
mapping(address token => mapping(address owner => uint256)) public credits;
address public operator;                                       // 垫付执行方（authority 可轮换；不影响在途归属）
IL1OutboxForFastExit public immutable outbox;                  // 构造接线
address public immutable escapeHatch;                          // 构造接线（仅读 isFrozen）
```

**记账模型**（solvency 证明基础，§4.7）：浮存 `floatLedger` 只经 `fund/fundToken` 增、经 `advance` 出账与 `operatorWithdraw` 减；claim 落账的 Y 与 credit 均**不进**浮存。operator 可提额恒 ≤ `floatLedger − totalOutstanding`；claim 落账资金对 operator 不可见，credit 永远有足额余额背书。

### 2.2 函数清单

#### 构造 / 配置

```solidity
/// @notice 构造：接线 outbox 与 escapeHatch（均不可变，一次性）。
constructor(address initialAuthority_, address outbox_, address escapeHatch_)
    AuthorityOwnable(initialAuthority_);   // 校验三者非零，否则 ZeroAddress

/// @notice 设置/轮换 operator（垫付热键，建议与 authority 多签分离）。
///         轮换语义：只影响**新垫付**的归属——在途垫付的回收仍按 AdvanceRecord.funder
///         快照入账（评审 Low-2）；轮换窗口内对既有 requestId 的追加垫付，其回收仍归
///         首笔 funder（首笔固定语义，运营侧应在轮换窗口避免在途追加或链下对账，§5.8）。
function setOperator(address operator_) external onlyAuthority;   // 事件 OperatorSet

/// @notice 注入原生 MON 浮存（任何人可注；实入 floatLedger）。
///         唯一合法的原生注资口：直接 transfer 进合约的钱不入浮存、无出口（§5.8）。
function fund() external payable;

/// @notice 注入 ERC20 浮存（先 approve；USDT 无返回值兼容，镜像 L1Bridge._pullToken——L1Bridge.sol:200-206）。
function fundToken(address token, uint256 amount) external;
```

#### 核心：垫付

```solidity
/// @notice operator 预垫付：同笔 tx 从池内付给 recipient 并记账。
///         requestId 必须满足绑定哈希 requestBinding(recipient, nonce, assetTag) == requestId
///         （防 operator 伪造收款人——绑定即快速通道叶子的 L2 侧派生约定，§6.1）。
/// @param requestId 快速通道叶子 requestId（= 绑定哈希）
/// @param recipient 用户 L1 收款地址 R（哈希绑定校验对象）
/// @param assetTag  1=MON、3/4=ERC20（2 拒绝）
/// @param amount    本笔垫付额（多次垫付累加；X>Y 自亏不设上限）
/// @param nonce     L2 侧 12B 随机数（绑定哈希原料）
function advance(bytes32 requestId, address recipient, uint8 assetTag, uint64 amount, bytes12 nonce)
    external
    onlyOperator            // 自定义 modifier：msg.sender == operator，否则 NotOperator
    whenNotFrozen           // 自定义 modifier：escapeHatch.isFrozen() → Frozen（镜像 L1Outbox.sol:212-215）
    whenNotPaused           // 基座 AuthorityOwnable.sol:51-54
    nonReentrant;           // 自含守卫（不变量 8）
```

语义序（fail-closed）：
1. `requestId != requestBinding(recipient, nonce, assetTag)` → `RequestBindingMismatch`；
2. `assetTag == 2`（PLAY）或 ∉{1}∪[3,255] → `UnsupportedAssetTag`（镜像 L1Outbox.sol:54-57, 296 判定面）；
3. `assetTag ≥ 3`：`outbox.tokenForTag(tag) == 0` → `TokenNotSet`（复用 L1Outbox.sol:150 命名）；
4. `amount == 0` → `BadAmount`（L1Bridge.sol:80 命名）；`recipient == address(0)` → `ZeroAddress`；
5. `advances[requestId].routed` → `AlreadyRouted`（叶子已结算，再垫会让用户总额 > Y）；
6. 首笔：初始化记录（**funder = msg.sender**、token 快照）；非首笔：当前 `tokenForTag(tag)` 与快照不符 → `TokenRemapped`（fail-closed，防 authority 中途换币造成跨资产错配；funder 不改写）；
7. **effects**：`advances[requestId].amount += amount`；`totalOutstanding[token] += amount`；`emit AdvancePaid`；
8. **浮存校验与出账**：`floatLedger[token] < amount` → `InsufficientFloat`；`floatLedger[token] -= amount`；原生 `recipient.call{value:amount}("")` 失败或 ERC20 `_pushToken` 失败 → `TokenTransferFailed` 整笔回滚（台账还原，无幻影台账——不变量 3）。
   注：push 失败（如 R 为无 receive() 合约）= 该用户无法快速垫付，**不产生任何台账**；其慢路径 `claimAndRoute`（X=0）+ pull credit 仍完整可用（§5.6）。

#### 核心：领取并分流

```solidity
/// @notice 任何人可调：FastExit 代发 L1Outbox.claim（收款人=FastExit，原子落账 Y）
///         后纯记账分流（零外呼）：operator 得 min(X,Y)（垫付有效时，按 funder 快照入账），
///         用户得 Y−min(X,Y)，均入 credit。X=0（无人垫付）时全额 Y 归用户——本函数即慢路径。
/// @param leaf/root/leafCount/index/proof 与 L1Outbox.claim 同形（L1Outbox.sol:260-266）
/// @param recipient 用户 L1 收款地址 R（绑定哈希 preimage 之一，合约不可从叶子反解，须调用方供给）
/// @param nonce     绑定哈希 preimage 之一
function claimAndRoute(
    L1Outbox.WithdrawalLeaf calldata leaf,
    bytes32 root,
    uint64 leafCount,
    uint64 index,
    bytes32[] calldata proof,
    address recipient,
    bytes12 nonce
) external nonReentrant;    // 有意不挂 whenNotPaused/whenNotFrozen（对齐 L1Outbox.claim 自身亦不挂冻结卫兵——L1Outbox.sol:8-11, 266；用户取回面不卡死，见 AuthorityOwnable.sol:18-22 同一哲学）
```

语义序：
1. `address(uint160(uint256(leaf.externalRecipient))) != address(this)` → `LeafRecipientNotFastExit`（**防抽干前置**：叶子收款人不是 FastExit 时，claim 付款给他人而分流会动用池内资金）；
2. `leaf.requestId != requestBinding(recipient, nonce, leaf.assetTag)` → `RequestBindingMismatch`（快速通道叶子判定 + 用户 R 的密码学恢复）；
3. `advances[requestId].routed` → `AlreadyRouted`（与 outbox.claim 的 `claimedRequests` 双保险）；
4. **effects（全部先于外部调用）**：`routed = true`；计算 `token`（tag1=address(0)，否则 `outbox.tokenForTag(tag)`）；垫付有效性 = 记录存在 && `a.assetTag == leaf.assetTag` && `a.token == token`（任一不匹配 → 无效，operator 回收 0，全额归用户——不变量 2）；`X_eff = 有效 ? a.amount : 0`；`operatorShare = min(X_eff, Y)`、`userShare = Y − operatorShare`；`totalOutstanding[a.token] -= a.amount`（**按垫付全额计减**，任务书不变量 7 原文语义；无效垫付同样计减——该垫付已了结，锁定 operator 自身浮存）；`credits[token][a.funder] += operatorShare`（**按 funder 快照**，非当下 operator——评审 Low-2）；`credits[token][recipient] += userShare`；`totalCredits[token] += Y`；`emit WithdrawalRouted`（含 `operatorCredited` 字段供归属稽核）；
5. **interaction**：`outbox.claim(leaf, root, leafCount, index, proof)`——Y 经 Bridge 付给 FastExit（原生走 `receive()`，ERC20 走低层 transfer，勘察纪要 §2 已实测：`payoutNative` 为 `to.call{value}("")` 空 calldata，合约收款人必须实现 `receive()`；ERC20 无回调无需 receive）。claim 内部任一检查失败（RootNotCommitted/RootNotFinalized/IndexBeyondLeafCount/AlreadyClaimed/WithdrawalProofInvalid/ClaimTooEarly/UnsupportedAssetTag/TokenNotSet）→ 整笔回滚，第 4 步台账原子还原，可重试。**本路径的落账证据由 claim 自身的原子性提供（同 tx 验证的就是这片叶子），不依赖 D6 台账**；
6. 分流到此为止——**本函数出账外呼为零**（credit 纯记账），用户/operator 各自 pull（§2.2 领取）。大额延迟（`largePayoutThreshold`/`claimDelayBlocks`，L1Outbox.sol:103-107, 282-283）由 claim 继承：大额快速通道的"差额到账"仍受 30 块延迟约束（垫付部分 X 不受限，用户已即时到手）。

#### 核心：外部已 claim 叶子的补救分流

```solidity
/// @notice 补救路径：叶子已被第三方直接 outbox.claim 抢先领到 FastExit 后，
///         任何人凭同一证明材料补做分流。纯记账、零外呼。
///         **分流证据 = L1Outbox.claimedLeafMatches(leaf)**（§3.2 新增叶哈希台账）：
///         证明"被领取的正是这片叶子（金额、收款人、note 承诺、高度全字段一致）"，
///         而非仅 requestId 曾被置位——后者对同 requestId 的第二片叶子同样为真，
///         会铸出无背书 credit（评审 High，§5.1 攻击样例）。
function route(
    L1Outbox.WithdrawalLeaf calldata leaf,
    bytes32 root,
    uint64 leafCount,
    uint64 index,
    bytes32[] calldata proof,
    address recipient,
    bytes12 nonce
) external nonReentrant;    // 有意不挂 pause/freeze（补救面，同上）
```

语义序（判定序镜像 L1Outbox.claim:267-276，凡可镜像处复用同名错误）：
1. 同 claimAndRoute 第 1、2 步（收款人前置 + 绑定哈希）；
2. `advances[requestId].routed` → `AlreadyRouted`；
3. `bytes32 digest = outbox.digestOf(leaf.checkpointHeight, leafCount, root)`；`outbox.roots(digest).root != root` → `RootNotCommitted`；`index >= rr.leafCount` → `IndexBeyondLeafCount`；
4. **叶哈希证据（评审 High 修复核心）**：`outbox.claimedLeafHashes(leaf.requestId) == bytes32(0)` → `NotYetClaimed`（该 requestId 从未被领取）；`!outbox.claimedLeafMatches(leaf)` → `ClaimedLeafMismatch`（曾被领取的是**另一片**叶子——典型即同 requestId 双叶攻击，或调用方提交了同 requestId 的错误叶子）。通过 ⟹ 与当前叶子六字段全同的那片叶子确曾成功 claim（claim 置位与写哈希同点，L1Outbox.sol:279 邻行），且其收款人 = FastExit（第 1 步已验本叶）⟹ **Y 确已落账本合约**；
5. `!outbox.verifyInclusion(leaf, proof, index, root)` → `WithdrawalProofInvalid`；
6. 分流记账与 claimAndRoute 第 4 步完全一致（共用内部 `_split` 语义；建议实现为 internal 函数，本草案不展开）。
   设计说明：本函数**不检查 `finalized`**——分流是"已发生的历史支付"的记账补救而非新领取，支付当时已通过 claim 的 finalized 判定；叶哈希匹配才是权威证据，根/index/包含证明仅作形状校验。

#### 领取 / 回收

```solidity
/// @notice 领取 credit（用户差额份额与 operator 回收份额共用）：任何人可代办，
///         款项恒付 owner（镜像 EscapeHatch.escape 的 executor 代办 + claimBond 的 pull 语义，
///         EscapeHatch.sol:372-384, 392-399）。先清零后转账，转账失败整笔回滚可重试。
function claimCredit(address token, address owner) external;   // 无 pause/freeze 卫兵（用户取回面）；错误 NothingToClaim / TokenTransferFailed

/// @notice operator 提取浮存超额：amount ≤ floatLedger[token] − totalOutstanding[token]，
///         否则 ExceedsWithdrawable。claim 落账资金与 credit 不在可提面（§4.7 证明）。
///         注：直接 transfer 进合约的原生币不入 floatLedger、亦无其他出口（§5.8 登记项）。
function operatorWithdraw(address token, uint256 amount)
    external onlyOperator whenNotPaused nonReentrant;   // 事件 OperatorWithdrew
```

#### 视图 / 兼容收款

```solidity
/// @notice 绑定哈希（L2 侧派生约定的 Solidity 镜像；供 daemon/测试对拍。
///         sha256("zchain.fastexit.request.v1" ‖ bytes20(recipient) ‖ bytes12(nonce) ‖ uint8(assetTag))，
///         实现镜像 L1Outbox._sha256 预编译用法——L1Outbox.sol:332-346）。
function requestBinding(address recipient, bytes12 nonce, uint8 assetTag) external view returns (bytes32);

/// @notice operator 当前可提超额（原生：token 传 address(0)）。
function withdrawable(address token) external view returns (uint256);

/// @notice 必须存在且 payable：L1Bridge.payoutNative 以空 calldata 调用收款人（L1Bridge.sol:158），
///         无 receive() 则整笔 claim revert（勘察纪要 §2 已实测）。函数体仅 emit NativeReceived
///         （不可 revert——毒化打款语义同 L1Bridge.sol:179-180 注释）：claim 落账与任何直转
///         入金统一留痕，供链下对账区分"合法落账 vs 误直转"（后者不入浮存、无出口，§5.8）。
///         事件外零状态、零调用 → 空体语义等同，天然不可重入，不加守卫
///         （若加 nonReentrant 会在 claimAndRoute 持锁期间使 payout 回调 revert——设计上禁止）。
receive() external payable;   // emit NativeReceived(msg.sender, msg.value);
```

### 2.3 事件（过去式，对齐 `WithdrawalClaimed`/`BondClaimed`/`BridgeSet` 风格；indexed 关键字段，对齐 L1Outbox.sol:113-133）

```solidity
event OperatorSet(address indexed operator);                                    // 对齐 BridgeSet 风格
event PoolFunded(address indexed token, address indexed funder, uint256 amount); // token=address(0)=原生（对齐 DepositInitiated 的 token 注释约定，L1Bridge.sol:51）
event AdvancePaid(bytes32 indexed requestId, address indexed recipient, uint8 assetTag, uint256 amount);
/// creditSplit：operator 与用户份额一次事件全披露；advanceValid 供审计无效垫付归零；
/// operatorCredited = 实际入账主体（funder 快照，评审 Low-2 稽核面）。
event WithdrawalRouted(
    bytes32 indexed requestId,
    address indexed recipient,
    uint8 assetTag,
    uint256 leafAmount,          // Y
    uint256 advancedTotal,       // X（台账原值，含无效垫付）
    uint256 operatorShare,       // min(X_eff, Y)
    uint256 userShare,           // Y − operatorShare
    bool advanceValid,
    address operatorCredited
);
event CreditClaimed(address indexed token, address indexed owner, uint256 amount);  // 对齐 BondClaimed
event OperatorWithdrew(address indexed token, uint256 amount);
/// receive() 统一入账留痕（claim 落账与误直转均触发；链下以 tx 上下文区分，§5.8）。
event NativeReceived(address indexed from, uint256 amount);
```

### 2.4 错误码（custom error 无前缀、集中声明，对齐 L1Outbox.sol:139-153；与既有合约同名错误为**有意复用**——语义逐字节相同的判定不另造名）

| 错误 | 触发点 | 复用/新增 |
|------|--------|----------|
| `NotOperator()` | advance/operatorWithdraw 非 operator 调用 | 新增（对齐 NotOutbox/NotEscapeHatch 构词，L1Bridge.sol:75,78） |
| `RequestBindingMismatch()` | advance / claimAndRoute / route 绑定哈希不符 | 新增 |
| `UnsupportedAssetTag()` | advance tag=2 或 tag∉{1,3..255} | 复用（L1Outbox.sol:145） |
| `TokenNotSet()` | advance tag≥3 而 tokenForTag=0 | 复用（L1Outbox.sol:150） |
| `BadAmount()` | advance amount=0 / fundToken amount=0 | 复用（L1Bridge.sol:80） |
| `ZeroAddress()` | 构造/setOperator 零地址；recipient 零地址 | 复用（AuthorityOwnable.sol:39） |
| `AlreadyRouted()` | advance 撞已结算 / claimAndRoute·route 重放 | 新增 |
| `TokenRemapped()` | 追加垫付时 tokenForTag 与首笔快照不符 | 新增 |
| `InsufficientFloat()` | advance 出账额超浮存 | 新增 |
| `TokenTransferFailed()` | advance push / claimCredit push 失败 | 复用（L1Bridge.sol:82） |
| `LeafRecipientNotFastExit()` | claimAndRoute/route 叶收款人 ≠ 本合约 | 新增（防抽干关键检查） |
| `NotYetClaimed()` | route 时该 requestId 从未被领取（叶哈希台账为零） | 复用命名（EscapeHatch.sol:194 同词，语义不同源；亦可改 ClaimLedgerEmpty，从仓库命名先例取 NothingToClaim 风格——实现期定稿） |
| `ClaimedLeafMismatch()` | route 时已领取叶子与本次提交叶子内容不一致（同 requestId 双叶攻击面，评审 High） | 新增 |
| `RootNotCommitted()` / `IndexBeyondLeafCount()` / `WithdrawalProofInvalid()` | route 台账与证明判定 | 复用（L1Outbox.sol:139,144,143） |
| `NothingToClaim()` | claimCredit 零余额 | 复用（EscapeHatch.sol:194） |
| `ExceedsWithdrawable()` | operatorWithdraw 超额 | 新增 |
| `Frozen()` | advance 冻结期 | 复用（L1Outbox.sol:153） |
| `NotAuthority()` / `IsPaused()` | 基座继承 | 复用（AuthorityOwnable.sol:37,40） |

---

## 三、与 L1Outbox / L1Bridge / EscapeHatch / AuthorityOwnable 的接线

### 3.1 零改动合约

| 合约 | 改动 | 理由 |
|------|------|------|
| **L1Bridge** | **零改动** | FastExit 从不直接调用 Bridge。资金路径 = `outbox.claim → bridge.payoutNative/payoutToken`（onlyOutbox 单向授权不变，L1Bridge.sol:189-197）；FastExit 只是"又一个 permissionless claim 调用者 + 一个实现了 receive() 的收款人"。不新增任何信任边 |
| **EscapeHatch** | **零改动** | FastExit 仅读 `isFrozen()`（EscapeHatch.sol:405-407）；不注册为哨兵、不触碰工单/余额根 |
| **AuthorityOwnable** | **零改动** | FastExit 直接继承（自带独立 paused 位，与三兄弟合约的 pause 互不影响） |

### 3.2 L1Outbox 增量 diff（**需要，追加式四处**；本会话已在 /tmp 副本实施并验证：`forge build` exit 0，`forge test` 100 passed / 0 failed，含双叶攻击判别探针）

`route()` 要对一枚**已被 claim** 的叶子自持校验（无法借道 claim——AlreadyClaimed），且其分流证据必须绑定叶内容（评审 High：`claimedRequests` 仅按 requestId 键控、不绑定金额与收款人，L1Outbox.sol:91-92；同 requestId 双叶场景下 route 会凭"叶 A 曾被领取"为叶 B 铸无背书 credit）。diff 全部为**追加式**（不动既有存储槽序、不改任何既有 getter 语义、不删不改既有行为）：

```diff
// ① 存储（追加于存储段末尾，既有槽位零挪动）
+    /// request_id → 已领取叶子完整哈希（FastExit.route 分流证据面）。
+    mapping(bytes32 requestId => bytes32) public claimedLeafHashes;

// ② claim 内 effects 区（L1Outbox.sol:279 邻行，仍在 interactions 之前）
     claimedRequests[leaf.requestId] = true;
+    claimedLeafHashes[leaf.requestId] = _leafHash(leaf);

// ③ 树校验公开（原 :306-311，唯一调用点 :276 同步改名）
-    function _verifyInclusion(...) private view returns (bool) {
+    function verifyInclusion(...) public view returns (bool) {

// ④ 证据视图（新增，叶哈希计算保持私有——单一实现）
+    function claimedLeafMatches(WithdrawalLeaf calldata leaf) public view returns (bool) {
+        bytes32 claimed = claimedLeafHashes[leaf.requestId];
+        return claimed != bytes32(0) && claimed == _leafHash(leaf);
+    }
```

`_leafHash` 覆盖全部六个叶字段（requestId、externalRecipient、assetTag、amount、burnedNoteCommitment、checkpointHeight，L1Outbox.sol:367-380）——**金额与收款人维度由此入绑**，这恰是绑定哈希 D2 不含 amount（多笔累加需要）留下的敞口的 L1 侧强制后盾。`WithdrawalClaimed` 事件与 `claimedRequests` getter 语义均不变（外部消费者零感知）。
本会话验证记录（/tmp/fastexit-probe）：`forge build` exit 0（仅存量 lint 告警）；`forge test` 全套 **98 存量 + 2 新增探针 = 100 passed / 0 failed**，探针含：叶 A（requestId K、1 wei、收款人=攻击者 EOA）被 claim 后，同 K 的叶 B（收款人=FastExit、5 ether、verifyInclusion 通过）`claimedLeafMatches` 必为 false、`claim` 路径照旧 AlreadyClaimed、篡改任一字段即 false。

不推荐的替代 = FastExit 自抄 113B 叶哈希与折叠逻辑——违背单一实现，Rust 侧金标准修订时存在复制漂移风险（勘察纪要 §8 同结论）；更弱的替代 = route 改查"未分流入金桶"——原生路径可用 receive() 记账拦截，但 **ERC20 外部 claim 无回调、无从记账**，覆盖不全，否决。

### 3.3 部署与一次性配置顺序（扩展 script/Deploy.s.sol，在其既有步骤 Deploy.s.sol:42-76 之后追加）

**v1 交付假定 fresh deploy**（含 §3.2 diff 的 L1Outbox 一体部署）；既有存续实例的升级路径见 §3.4。

1. 既有四合约照旧部署互联（**完全不变**：outbox.setInbox/setBridge/setEscapeHatch、bridge.setOutbox/setEscapeHatch、inbox.setOutbox/setEscapeHatch、genesis 余额根、claimDelay/largePayoutThreshold/tokenForTag——FastExit 不占用任何既有 setter，"一次性"语义不受影响）；
2. `new FastExit(authority, address(outbox), address(escapeHatch))`；
3. authority：`fastExit.setOperator(operatorBot)`（垫付热键，与 authority 多签分离；可轮换，在途归属按 funder 快照不受影响）；
4. operator：`fastExit.fund{value:…}()` / `fastExit.fundToken(usdt, …)` 注入浮存（**必须走 fund 口**；直转不入浮存且无出口，§5.8）；
5. L2/daemon 侧配置 FastExit 地址与绑定哈希派生（范围外，§6.1）。

**无需任何既有合约的新授权**：FastExit 不进 Bridge 的 onlyOutbox/onlyEscapeHatch 白名单，不进 Outbox 的 inbox/commitAuth 名单——它是纯外部调用方 + 独立资金池。

### 3.4 既有部署的升级路径（评审 Low-4 登记）

若测试网/主网已有存续实例（本仓栈已多轮演进），**§3.2 的 diff 无法原地获得**：`claimedLeafHashes`/`verifyInclusion` 需要新代码，而互联边全部一次性（已读证实的三处：`outbox.setBridge/setInbox/setEscapeHatch` 一次性，L1Outbox.sol:161-181；`bridge.setOutbox/setEscapeHatch` 一次性，L1Bridge.sol:91-104；`EscapeHatch.bridge/inbox` 为构造 immutable，EscapeHatch.sol:86-91。L1Inbox.sol 本会话未读，其接线面不在此断言）。推论：**替换 outbox ⟹ 必须重部署 bridge（setOutbox 不可改）⟹ 必须重部署 escapeHatch（持 immutable bridge）⟹ 实质全栈重部署 + Bridge 资金搬家**。升级纪律（登记为运维 runbook 项，非 v1 代码交付）：

1. 冻结窗口：停 advance → 停新根上锚（commitRoot）→ 存量叶清账（claim/claimAndRoute 收尾）或显式放弃并公告 → pause 全栈；
2. 重部署新栈（含 §3.2 diff）→ Bridge 资产全额迁移至新 Bridge；
3. **台账迁移是硬前提**：若在新 outbox 上重 commit 历史根而不迁移 `claimedRequests`/`claimedLeafHashes`，历史已领叶子可二次领取（双付）；不可迁则历史根一律不得在新栈重锚，未领余额走 L2 重新出叶；
4. 窗口内新旧栈并存期，FastExit v1 只接线**新** outbox（构造 immutable），杜绝"旧栈置位、新栈分流"的台账分裂面（评审 High 的跨栈变体，§5.8）。

---

## 四、不变量与安全论证（逐条对应任务书 1–8）

设叶子额 `Y = leaf.amount`，累计垫付 `X = advances[K].amount`（K=leaf.requestId），有效垫付 `X_eff ∈ {X, 0}`。

**不变量 1：用户最终所得 ≡ Y（X ≤ Y 时）；operator 任何行为下少给无利可图。**
用户所得 = advance push 的 X + route 时 `credits[R] += Y − min(X_eff, Y)`。收款地址 R 由绑定哈希烧进 requestId（D2），而 requestId 是 Merkle 叶字段、经 finalized 根验证（`verifyInclusion` 折叠逐层含 leaf.requestId：L1Outbox.sol:276, 316-325, 367-380）——**operator 无法把用户叶子的分流指向他人**：advance 时哈希校验（`RequestBindingMismatch`）使伪造 R 的垫付根本立不了账；claimAndRoute/route 时调用方提供的 (R, nonce) 必须重算出叶子里的 requestId。tag/token 失配的无效化规则只把 operator 份额归零、只会**增大**用户份额。X ≤ Y 时用户合计 = X + (Y−X) = Y 恒等；X > Y 时 = X > Y（多垫自亏，§5.3）。fee 不存在（D8）。∎

**不变量 2：operator 回收 ≤ min(X, Y)；垫付收款人必须匹配，不匹配则全额归用户。**
回收额 = `operatorShare = advanceValid ? min(X, Y) : 0`，且以 credit 记账、每 requestId 经 `routed` 恰好结算一次、计入 funder 快照名下（D11）。"收款人匹配"由 D2 哈希绑定结构性保证（比任务书原文的字面比对更强：advance 登记的收款人与叶子收款人出自同一哈希原像，不可能不一致）；`advanceValid` 补足 tag、token 两个维度（调研纪要"资产错配"陷阱的对位物：烧 tag 入 requestId + route 时 token 快照比对）。跨资产套利面归零：tag 失配或 remap 失配 → operator 回收 0，垫付资产自亏。∎

**不变量 3：记账与资金流同笔 tx 绑定。**
advance 的 effects（台账累加、totalOutstanding 计增、floatLedger 扣减）全部先于 push；push 失败 → `TokenTransferFailed` 整笔回滚（EVM 原子性），不存在"只记账不出账"或"只出账不记账"的中间态。链下打款后口头登记在合约面不存在登记入口（advance 是唯一立账途径且强制同 tx 出账）。∎

**不变量 4：requestId 全局一次性，route 侧防重放且证据绑定叶内容。**
claim 侧：`L1Outbox.claimedRequests[K]` 跨根全局一次性（L1Outbox.sol:91-92，claim 内 CEI 先置位 :279）——claimAndRoute 的 Y 只会落账一次。route 侧：`routed` 恰好置位一次；**分流证据 = `claimedLeafMatches`（叶哈希六字段全绑）**，杜绝"叶 A 置位、叶 B 分流"的跨叶重放（评审 High 攻击在证据面直接不可通过，本会话探针已执行验证）。**advance 撞 routed → AlreadyRouted**，堵死"结算后再垫付"使用户总额突破 Y 的路径。route 的 `NotYetClaimed`（零哈希）排除"未领叶子凭空分流"。∎

**不变量 5：冻结/暂停停新垫付；分流与领取不受冻结阻断；每叶总流出 = Y。**
advance 挂 `whenNotFrozen`（读 `IEscapeHatch(escapeHatch).isFrozen()`，与 L1Outbox.sol:212-215 同式）+ `whenNotPaused`。claimAndRoute/route/claimCredit 有意不挂冻结卫兵——与 `L1Outbox.claim` 本身不挂（L1Outbox.sol:8-11, 266）、`escape` 不挂（EscapeHatch 信任边界 4，EscapeHatch.sol:44-46）为同一哲学：预冻结窗资金照常可领。pause 面：FastExit 自有 paused 位只挡 advance/operatorWithdraw（operator 侧流程）；用户领取面不卡（claimAndRoute 若遇**栈级** pause，outbox.claim 自身 whenNotPaused 会回滚，属全栈应急语义，用户已得 X、差额待 unpause——如实声明，§5.7）。每叶总流出 = claim 恰付一次 Y（Bridge 视角）+ FastExit 分流合计 = Y（credit 增量 = operatorShare + userShare = Y）→ **L1Bridge 浮存口径不变**（对照 EscapeHatch 信任边界 3 的"总流出 ≤ 浮存"框架，FastExit 不放大总出口，只是 Y 的二次分配者）。∎

**不变量 6：资产纪律。**
advance：tag=2 → `UnsupportedAssetTag`（对齐"PLAY 为 L2 内部筹码，不提供 L1 兑付（fail-closed）"，L1Outbox.sol:254, 295-296）；tag≥3 → `TokenNotSet` 强制 tokenForTag 已配置并快照 token。claim 侧：claimAndRoute 的 tag 校验由 outbox.claim 继承（tag2/未配 token 的叶子不可能 claim 成功 → 不可能分流）；route 侧：叶子被 claim 过 ⟹ 曾通过 claim 的 tag 判定（claimedRequests 只在全部判定通过后置位，L1Outbox.sol:267-279），fail-closed 传递。代币地址复用 `L1Outbox.tokenForTag`，FastExit 不另设映射——单一事实源。∎

**不变量 7（细化）：池 solvency——`operatorWithdraw ≤ floatLedger − totalOutstanding`，且任意时点合约实际余额 B ≥ totalCredits C。**
记账模型：`floatLedger`（F）只经 fund/fundToken 入、advance 出账与 operatorWithdraw 出；**claim 落账的 Y 不入 F**（原生路径 receive() 仅 emit 事件零状态，ERC20 路径 transfer 无回调无从入账）。定义 Φ = B − C，对操作逐一 看 (Φ, F) 增量：fund (+v, +v)；advance (−X, −X)；operatorWithdraw (−w, −w)；claimCredit (0, 0)（B−w 与 C−w 同减）；外部 claim (+Y, 0)；route (−Y, 0)。于是 Φ − F 只被 claim/route 改变。**配对性由 D6 叶哈希台账强制成立**：route 的 −Y 仅在 `claimedLeafMatches(leaf)` 通过时发生，即"与当前叶子六字段全同的那片叶子曾被成功 claim 并支付"——**+Y 与 −Y 引用的是同一片叶子**（评审指出的原证明缺口：仅凭 claimedRequests 键控，配对假设在同 requestId 双叶下不成立；叶哈希绑定后恢复成立）。故 Φ − F = Σ(已 claim 未 route 的 Y) ≥ 0，即 **Φ ≥ F 恒成立**。advance 出账前检查 F ≥ X ⟹ Φ ≥ F ≥ X ⟹ 出账后 Φ − X ≥ 0 不被破坏；claimAndRoute 的 +Y/−Y 同 tx 配对，净 0。归纳得 B ≥ C 恒成立 → claimCredit 只会因 owner 拒收回滚、**永不因池亏空失败**。此为任务书不变量 7 的**强化形式**：原文以实际余额 B 为基，本设计以 F 为基——F ≤ B 恒成立（F 只随真实入账增、随等额真实出账减），故本设计上界**严格不宽于**原文上界；强化动因 = pull-credit 下若以 B 为基允许 operator 提走"已落账未分流"的外部 claim 资金，会出现 credit 无背书窗口（§5.1 衍生攻击面，设计上直接消灭）。执行级验证 = 测试 F2/F3/J。∎

**不变量 8：重入——CEI + 自含 nonReentrant + 零外呼分流结构。**
逐入口：(a) advance：effects 先、push 后，push 目标 recipient 为任意地址可回调——nonReentrant 兜底 + 台账已定型；(b) claimAndRoute：**effects（routed、credit、outstanding）全部先于唯一外部调用 outbox.claim**，claim 内部 Bridge→FastExit.receive() 仅 emit 事件（零状态、不可重入），分流阶段零外呼——即便无守卫也无可重入窗口，nonReentrant 为纵深；(c) route：纯记账零外呼；(d) claimCredit：先清零后转账（镜像 claimBond，EscapeHatch.sol:392-399），重入撞零余额；(e) ERC20 全路径经 Bridge `_pushToken` 低层 transfer 无回调（勘察纪要 §2 已核实 L1Bridge.sol:203, 208-214；本会话复读确认），非 ERC777 回调面；(f) receive() 有意不加守卫（§2.2 注释：持锁期间 payout 回调会自锁死）。基座无 nonReentrant 可继承（勘察纪要 §3 grep 证实，本会话读 AuthorityOwnable.sol 全文确认）——守卫为 FastExit 自含实现（uint256 私有槽 + 临时置 1）。∎

---

## 五、边界与残余风险

### 5.1 第三方抢跑 claim 到 FastExit → 差额滞留（griefing）与同 requestId 双叶攻击（评审 High）
**抢跑（无损失、可补救）**：抢跑者在根 finalized 后直接调 `outbox.claim`（permissionless，L1Outbox.sol:260-266），Y 落账 FastExit、分流未发生。**抢不走**：分流归属由绑定哈希 + Merkle 证明 + 叶哈希台账决定。**滞留**：在有人调 `route()` 前差额停在池内——route permissionless，operator 有直接经济动机（回收 min(X,Y)），用户/哨兵/daemon 均可代办（对标 StarkEx 任何人代领）。建议 watcher 对"claimedLeafHashes 非零且 advances.routed=false"积压告警（§6.2）。

**同 requestId 双叶攻击（评审 High，已修复，此处留档攻击样例）**：`claimedRequests` 仅按 requestId 键控（L1Outbox.sol:92）、绑定哈希不含 amount（D2）、requestId 唯一性仅 L2 纪律（§6.1）——修复前路径：叶 A（K、1 wei、收款人=任意 EOA）被正常 claim 置位 `claimedRequests[K]`，Bridge 仅付 1 wei；叶 B（同 K、收款人=FastExit、金额 Y_B 巨大）只需进入任一已 commit 的根（authority 可直接 commitRoot，L1Outbox.sol:205-222；或 L2 nonce 碰撞 bug）；`route(叶 B)` 凭借"K 曾被领取"为叶 B 铸 Y_B credit，而池内只收过 1 wei → 无背书 credit 抽干池内待领资金（claimCredit 因池亏空失败，受害者为用户）。既有栈中该场景后果仅是叶 B 永久不可领（AlreadyClaimed，L1Outbox.sol:273，contained）；route() 曾把它放大为对池内真实资金的抽取。**修复后**：route 的证据是 `claimedLeafMatches(叶 B)`——台账存的是叶 A 的哈希，六字段比对必 false → `ClaimedLeafMismatch`，攻击不可通过（本会话探针 `test_ClaimedLeafHash_DiscriminatesDuplicateRequestId` 已执行验证，PASS）。**衍生攻击面同步消灭**：若允许 operator 提走"已落账未分流"的外部 claim 资金（以 B 为基的提额），会出现 credit 无背书窗口——floatLedger 隔离使其不可行（§4.7）。抢跑者自身净损失 = gas，无收益纯捣乱。

### 5.2 EscapeHatch.escape 与垫付的交互（operator 自担的信用风险）
escape 冻结期按**余额根**直付玩家余额（EscapeHatch.sol:372-384），与提现叶 claim"链上不设防、竞争浮存先到先得"（EscapeHatch 信任边界 3，EscapeHatch.sol:40-43）。FastExit 引入后多一个浮存竞争者（claimAndRoute 冻结期可用，§4 不变量 5），但总出口仍以 Bridge 余额 fail-closed 封顶，不放大系统性风险。**对 operator 的三重信用敞口，如实登记**：
1. 垫付后、根上锚前发生冻结 → 根可能永不再锚（commitRoot/markFinalized 冻结期停摆，L1Outbox.sol:210-215, 238-246）→ 在途 X 永久悬置（`totalOutstanding` 不释放、浮存锁定）；
2. 余额根含 burn 后余额时（根新鲜是 operator 纪律，EscapeHatch 信任边界 1），玩家 escape 拿的是**扣减后余额**，与提现叶不双花——但若浮存被 escape 优先抽干，claimAndRoute 的 `outbox.claim → bridge.payout` 因余额不足回滚，可重试但可能长期不可付（既有 EscapeHatch 语义，非 FastExit 引入）；
3. operator 与 authority 同源（同一运营方）时，垫付回收实质依赖自家锚根纪律——这是把 StarkEx"快提完全由 operator 负责"（调研纪要 §一）的最终性风险显式内化。

### 5.3 多垫自亏（X > Y）
不设垫付上限、不补偿：operator 回收 min(X,Y)=Y，缺口 X−Y 从 floatLedger 永久消失（用户合计 X > Y，占优）。机制上"多给"无利可图也无危害，"少给"不可能（不变量 1）。追加垫付（多次 advance 累加）同理，仅首笔固定 token/tag/funder 快照。

### 5.4 operator 跑路 / 拒垫
用户不依赖 operator 的任何主动性：(a) 未垫付 → X=0，用户在根 finalized（+大额延迟）后自行或托任意第三方调 claimAndRoute，全额 Y 以 credit 落账、pull 领取——慢路径退化 = 原生 claim 的时效 + 一次 pull，无排他窗口（规避 Across 排他窗陷阱，D1）；(b) 已垫付后跑路 → X 已到手，差额同上路径；(c) operator 跑路致 daemon 停摆 → 根不再上锚是**既有结算栈风险**（EscapeHatch 工单/freeze 机制对冲），FastExit 不改变其边界；(d) FastExit 池内 credit 与浮存不受影响——claimCredit 无 operator 依赖。唯一退化为"等"：不亏本金（对标共性不变量 1）。

### 5.5 L2 接线违约 → 永久锁定（fail-closed 声明）
叶子收款人 = FastExit 但 requestId 不满足绑定哈希（L2 实现违约/恶意的 authority）：claimAndRoute 与 route 均 `RequestBindingMismatch`，而该叶子无法被其他路径领取（收款人只能是 FastExit）→ **资金永久锁死**。这是有意的 fail-closed（弱绑定 = 放开伪造 R 的抽干面）。缓解：§6.1 把派生约定列为 L2 侧硬性交付项 + Rust↔Solidity 交叉对拍测试（金标准惯例的延伸，L1Outbox.sol:33-34）。

### 5.6 用户侧边界
R 为无 receive() 合约：advance push 失败 → 无垫付无台账（干净失败）；claimAndRoute 仍可用（分流零外呼），差额入 credit，R 需能**主动调** claimCredit（pull 语义）领取——R 连函数都不能调属用户自陷，credit 永久保留不丢失。大额（≥largePayoutThreshold，Deploy 默认 tag1 100 MON，script/Deploy.s.sol:69-70）：差额到账受 claimDelayBlocks（30 块）约束，"即时"仅覆盖垫付部分。

### 5.7 全栈 pause 的传导
FastExit 自身 pause 只停 advance/operatorWithdraw；但 claimAndRoute 内含 outbox.claim（whenNotPaused）与 Bridge payout（whenNotPaused）——栈级 pause 时差额分流整体暂停，unpause 后可重试。与既有栈"pause = 治理应急全停"语义一致，不新增不一致面。

### 5.8 其他登记项
- **operator 轮换的归属边界（评审 Low-2）**：在途回收按 `AdvanceRecord.funder` 快照入账，轮换不转移；但**轮换窗口内对既有 requestId 的追加垫付**，其回收仍归首笔 funder（首笔固定语义）——两 operator 主体间的转移虽已可稽核（`WithdrawalRouted.operatorCredited` + `AdvancePaid` 事件链），制度上仍建议：轮换选在途垫付清零窗口执行，或有待清账目时链下对账后再轮换。
- **误直转滞留（评审 Low-3）**：`receive()` 吞入的一切直转（含 dust）不入 floatLedger、v1 无 sweep 出口——operator 注资**只可走 fund()/fundToken()**；`NativeReceived` 事件提供可观测性（claim 落账与误直转均触发，链下以 tx 上下文区分）。长期可选：authority 侧仅针对"余额 − 浮存 − credit"超额部分的 sweep（登记为后续项，v1 不做）。
- **跨部署重放（评审 High 的跨池变体）**：v1/v2 并存期，收款人=v1 与收款人=v2 的同 requestId 叶子是**不同叶子**（recipient 字段不同 → 叶哈希不同）→ v2 的 route 要求 `claimedLeafMatches`，而台账存的是（若曾领取）某一片的哈希，另一片必 `ClaimedLeafMismatch`——**双叶修复天然覆盖跨池变体**，无需两池同属一个 operator 的假设。残余面转为运营纪律：被"另一池叶子"占用了 requestId 的本池垫付将无法路由（operator 自亏），迁移期先停垫后切池（§3.4）。
- **tokenForTag 重映射**：追加垫付被 `TokenRemapped` 挡（fail-closed）；已垫未路由的叶子在 remap 后路由 → 垫付判无效（token 快照 ≠ 当前）→ operator 回收 0。authority 行为，由 operator（同一运营方）自担。
- **v1 无费用**：对标 Hop bonderFee/StarkEx 0.1% 的商业模式被不变量 1 排除；若未来引入，须修订不变量 1 并重新过安全论证（预留：operatorShare 公式为唯一改动点）。
- **勘察纪要中"NatSpec 与代码不一致"事项**（nonReentrant 只存在于注释，src/L1Outbox.sol:41-42、src/L1Bridge.sol:156）：与本草案无阻塞关系，但 FastExit 的中文 NatSpec 措辞将避免复述该失实声明，如实写"自含守卫"。

---

## 六、L2 侧与运营侧接线清单

### 6.1 L2 侧（**均属本次范围外**，草案仅登记要求）
1. **站起快速通道参数化**：用户站起 UI/流程收集 L1 收款地址 R（EVM）与 12B nonce；快速通道叶子构造为 `externalRecipient := bytes32(uint256(uint160(FastExit 地址)))`、`requestId := sha256("zchain.fastexit.request.v1" ‖ bytes20(R) ‖ bytes12(nonce) ‖ uint8(assetTag))`——**硬性约定**（违约后果 = §5.5 锁定）；tag=2（PLAY）禁止走快速通道。
2. **requestId 唯一性**：nonce 全局唯一纪律（L2 侧查重）。注意：唯一性违约的直接后果已被 D6 叶哈希台账封死为"第二片叶不可领/不可路由"（contained），但仍有垫付悬置的 operator 损失面，纪律不豁免。
3. **daemon 事件面**：站起事件向 operator bot 推送 (requestId, R, assetTag, Y, nonce)；operator 决策垫付额（建议首笔即全额 Y，商业模式内嵌于运营策略）。
4. **Rust 侧绑定哈希镜像 + 交叉对拍**：poker-appchain / monad-settlement crate 增派生函数与 Solidity `requestBinding` 金标准测试（对齐 withdrawal_root 的交叉验证惯例，L1Outbox.sol:33-34）。
5. **（可选，§5.8）派生域版本化**，为合约迁移预留。

### 6.2 运营侧（范围外）
1. operator bot 热键管理（与 authority 多签分离；轮换经 `setOperator`，在途归属按 funder 快照不受影响，追加垫付归属边界见 §5.8）；
2. 浮存水位策略：按 `totalOutstanding` 峰值 + 提现峰值留存，`withdrawable` 视图监控；**注资只走 fund()/fundToken()**（§5.8 误直转滞留）；
3. watcher 四件套告警：(a) `claimedLeafHashes 非零 ∧ ¬routed` 积压（§5.1，自动或人工补 route）；(b) `floatLedger − totalOutstanding` 低于水位；(c) 长期未领 credit（用户提醒）；(d) `NativeReceived` 中无 claim 上下文的入账（误直转侦测）；
4. 大额延迟（claimDelayBlocks/largePayoutThreshold）与快速通道 UX 文案对齐（§5.6）。

### 6.3 范围内（下一阶段实现交付物）
`src/FastExit.sol` + `src/L1Outbox.sol` 追加式 diff（§3.2，本会话已验证可编译、全套测试无回归）+ 测试（§七）+ Deploy 扩展（§3.3）。

---

## 七、测试计划（供测试工程师直接执行）

测试基建照搬：forge-std Test（test/L1Settlement.t.sol:4 模式）、fuzz 256 runs（foundry.toml）、提现树 helper = `EscapeHatch.t.sol:119-192` 的 `_leaf/_leafLevel/_balanceRoot/_proof` 同构改写（域换 `zchain.vault.withdrawal_root.v1`、叶为 113B `_outboxLeafHash`——EscapeHatch.t.sol:217-230 已有现成叶哈希，直接复用/泛化）、单叶树空证明技巧（L1Settlement.t.sol:221-242 + EscapeHatch.t.sol:890-910 的 commitRoot-then-claim 模式；本会话探针 `ClaimedLeafProbe.t.sol` 已按此法落了一份可参考实现）、断言风格 `expectRevert(X.selector)`/`expectEmit(四true)`、重入攻击合约置文件尾（EscapeHatch.t.sol:1047-1108 模式）。

**A. advance（正例）**
- A1 tag1 全额垫付：绑定哈希构造 requestId → advance → recipient 到账 X、`advances/totalOutstanding/floatLedger` 三台账与事件 `AdvancePaid` 全对（含 `funder` 快照断言）；
- A2 多次垫付累加同 requestId（不同 nonce 不变、同 (R,nonce,tag)）：amount 累加、recipient 到账累加；
- A3 tag3 垫付：mock ERC20（含 USDT 式无返回值代币）路径 fundToken→advance→_pushToken；
- A4 非 operator 调用 revert `NotOperator`；authority 轮换 operator 后旧键失效、台账无损。
**B. advance（反例）**
- B1 `RequestBindingMismatch`：requestId ≠ requestBinding(R,nonce,tag)（含"operator 伪造 R'=operator 自己"的攻击样本——哈希校验必拒）；
- B2 tag=2 → `UnsupportedAssetTag`；tag≥3 未配 token → `TokenNotSet`；
- B3 amount=0 → `BadAmount`；已 routed 的 requestId → `AlreadyRouted`；
- B4 浮存不足 → `InsufficientFloat`（含"先 withdraw 掏空再 advance"时序）；
- B5 recipient 为无 receive() 合约 → 整笔回滚、台账零污染（关键断言：`advances` 无记录、`totalOutstanding` 未增）；
- B6 冻结期（搭 EscapeHatch freeze 脚手架）→ `Frozen`；pause → `IsPaused`；
- B7 tokenForTag remap 后追加垫付 → `TokenRemapped`。

**C. claimAndRoute（正例）**
- C1 完整快路径：advance(X=0.6Y) → 根上锚（commitRoot finalized）→ claimAndRoute → FastExit 余额 +Y、`credits[native][R]=0.4Y`、`credits[native][operator]=0.6Y`、`totalOutstanding` 归减 X、事件 `WithdrawalRouted` 字段全对（含 `operatorCredited`）、`advances.routed=true`；
- C2 无人垫付（X=0）：全额 Y → credits[R]（慢路径等价性，核心正例）；
- C3 ERC20 叶（tag3）同构；
- C4 第三方（非 operator 非 R）代办调用成功（permissionless 声明验证）；
- C5 R 与调用方不同、nonce 正确 → 通过（调用方无法冒领：款项只进 credit[R]）。
**D. claimAndRoute（反例）**
- D1 叶收款人 ≠ FastExit（构造普通叶子）→ `LeafRecipientNotFastExit`，且**池余额分文未动**（防抽干回归测试，必须断言）；
- D2 绑定哈希不符（错 R / 错 nonce / 错 tag）→ `RequestBindingMismatch`；
- D3 根未上锚/未 finalized/证明篡改/超 leafCount/重复路由 → 透传 outbox 错误（`RootNotCommitted/RootNotFinalized/WithdrawalProofInvalid/IndexBeyondLeafCount`）+ `AlreadyRouted`；
- D4 大额延迟窗口内 → `ClaimTooEarly`，warp 过窗后成功（L1Outbox.sol:282-283 传导）；
- D5 tag 失配垫付（advance tag3、叶 tag1）→ operatorShare=0、userShare=Y、事件 `advanceValid=false`；
- D6 token remap 后路由 → 同 D5 判无效（operator 自亏路径断言）。

**E. route（补救路径）**
- E1 抢跑场景全流程：第三方直接 `outbox.claim`（FastExit 收款）→ 断言 FastExit 余额 +Y 且未分流、`claimedLeafHashes` 已写入 → 任意人 route → 分流结果与 C1 逐字段一致；
- E2 claim 后 operator 补垫付（advance 于外部 claim 之后、route 之前）→ 合法且分流正确（时序自由度验证）；
- E3 反例：未 claim 过的叶 → `NotYetClaimed`；重复 route → `AlreadyRouted`；普通叶（收款人≠FastExit）→ `LeafRecipientNotFastExit`；证明/根/index 判定镜像 D3；
- E4 **L1Outbox diff 回归**：改名后全仓 `forge test` 通过（本会话已在 /tmp 副本先行执行：100 passed / 0 failed——正式仓落地后原样复跑）；`verifyInclusion` 公开后篡改任一叶字段返回 false（勘察纪要 §8 探针场景 + 本次 `ClaimedLeafProbe` 探针并入正式用例）。
**F. 领取与回收**
- F1 claimCredit：代办调用款项付 owner；转账失败（拒收合约）→ 回滚可重试、credit 保留；
- F2 operatorWithdraw：超额 → `ExceedsWithdrawable`；**关键时序攻击回归**：外部抢跑 claim Y 后、route 前，operator 尝试提走 Y → 必须被 floatLedger 隔离挡下（不变量 7 强化项的执行级验证）；
- F3 solvency fuzz：随机序列（fund/advance/route/claimCredit/withdraw 合法随机参数）执行后断言 `合约余额 ≥ totalCredits[token]` 且 `floatLedger ≥ totalOutstanding[token]`（256 runs，每 tag 各一组）。
**G. 冻结/pause 矩阵**
- G1 冻结期：advance 拒、claimAndRoute 成（对齐 L1Outbox.claim 冻结放行——EscapeHatch.t.sol:890-910 同构场景）、route 成、claimCredit 成；
- G2 FastExit pause：advance/operatorWithdraw 拒；claimAndRoute 受栈传导（配 outbox.pause 组合用例）；route/claimCredit 不受 FastExit 自身 pause 影响。
**H. 重入与 receive**
- H1 重入攻击合约（文件尾）：于 advance push 回调、claimCredit push 回调尝试重入各入口 → 全部被 nonReentrant/CEI 挡下（EscapeHatch.t.sol:1047-1108 模式）；
- H2 receive() 探针：直接向 FastExit 转账（模拟外部 claim 落账与误直转）不 revert、`NativeReceived` 事件触发、floatLedger 不动（误直转不可提额断言）；
- H3 claimAndRoute 执行中（持锁）外部合约向其转账 → 仅事件不 revert（守卫不在 receive 上的设计验证）。
**I. 金标准对拍**
- I1 Solidity `requestBinding` vs 预计算向量（Rust/JS 侧产出固定测试向量入仓，对齐 L1Settlement.t.sol:14-18 金向量风格）；
- I2 绑定哈希含全部三参数的篡改敏感测试（逐字段改动 → 哈希变）。
**J. 同 requestId 双叶攻击回归（评审 High；本会话探针已执行，正式化并入）**
- J1 攻击全链路：叶 A（K、1 wei、收款人=attacker EOA）直接 claim → 叶 B（同 K、收款人=FastExit、5 ether）commit 入另一根且 `verifyInclusion` 通过 → `route(叶 B)` 必须 revert `ClaimedLeafMismatch`；`claimAndRoute(叶 B)` 必须 revert `AlreadyClaimed`（透传）；池内 credit/台账零变化；
- J2 `claimedLeafMatches` 篡改敏感：领取后逐字段篡改（amount/recipient/requestId/noteCommitment/height）均 false；
- J3 跨池变体：两个 FastExit 实例 mock，收款人=v1 的叶被 claim 后，同 K 收款人=v2 的叶在 v2 侧 route → `ClaimedLeafMismatch`；
- J4 operator 归属（评审 Low-2）：op1 advance → `setOperator(op2)` → route → `credits` 归 op1（funder 快照）、事件 `operatorCredited==op1`；轮换后 op2 的新垫付归 op2。

---

## 附：与任务书推荐主路径的四次修订（及理由）

1. **advance 增补 `nonce` 参数并强制绑定哈希校验**（推荐路径原签名 advance(requestId, recipient, assetTag, amount) 无从校验 recipient 真实性）：不修订则 operator 可垫付到自设地址、路由时侵吞全额 Y（用户所得 0），直接违反不变量 1——这是信息论级的洞（叶子不含用户地址，合约必须从哈希原像恢复 R），修订依据 = 调研纪要 Hop transferId 全参数烧入模式。
2. **分流所得改 pull 式 credit（用户与 operator 皆是）**（推荐路径原文"立即分流"隐含 push）：push 到任意 R 的失败面会把 claimAndRoute 整体卡死且叶子无第二出口；依据 = 本仓 claimBond 既有先例（EscapeHatch.sol:390-399）。
3. **operatorWithdraw 上界以 floatLedger 为基并隔离 claim 落账**（任务书不变量 7 原文"池余额 − totalOutstanding"以实际余额为基）：原文上界在 pull-credit + 抢跑时序下不足以背书 credit（§4 不变量 7 论证）；修订后上界严格更紧，且仍然满足原文不等式。
4. **route() 的分流证据从 `claimedRequests` 升级为叶哈希台账（评审 High 驱动，L1Outbox 增量 diff §3.2）**：`claimedRequests` 仅按 requestId 键控、不绑定叶内容，同 requestId 双叶（绑定哈希不含 amount、唯一性仅 L2 纪律）可凭 route 铸无背书 credit 抽干池内待领资金；修复 = claim 时增记 `claimedLeafHashes[K] = _leafHash(leaf)`（六字段全绑）+ `claimedLeafMatches` 证据视图，跨部署变体因 recipient 入叶哈希同时覆盖。已在本会话 /tmp 探针验证：`forge build` exit 0、全套 `forge test` 100 passed / 0 failed（含双叶攻击判别用例）。
