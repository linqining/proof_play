# FastExit 快速提现通道交付报告

> 交付日 2026-10-03。依据：设计草案 v2（本会话通读）、实现与测试源码（本会话通读）、
> ask 给定的实现摘要/门禁/评审/终审材料；测试门禁本次会话独立复跑（§三）。
> 终审 2 项发现均复核证实（low），未修复，登记为后续项（§四、§五）。

## 一、交付物清单

| 文件（绝对路径） | 说明 |
|---|---|
| `/Users/mac/projects/zchain/contracts/monad/src/FastExit.sol` | 新增（599 行）：按草案 v2 全量实现 `advance`/`claimAndRoute`/`route`/`claimCredit`/`operatorWithdraw` + `fund`/`fundToken`/`setOperator` + 自含重入守卫 + pull credit 分流（本会话通读核实接口齐全） |
| `/Users/mac/projects/zchain/contracts/monad/src/L1Outbox.sol` | 修改：草案 §3.2 四点追加式 diff——`claimedLeafHashes` 存储（:114）、claim 内写叶哈希（:287）、`verifyInclusion` 转 public（:316）、`claimedLeafMatches` 证据视图（:411-414）；本会话逐点核实存在；ask 给定：与 /tmp/fastexit-probe 验证副本逐字节一致 |
| `/Users/mac/projects/zchain/contracts/monad/test/FastExit.t.sol` | 新增（1547 行）：草案 §七 A–J 计划全量 + 任务书不变量 1–8 正反例，含同 requestId 双叶攻击回归（J1–J3）、原生/ERC20 solvency fuzz（F3 修订版）、绑定哈希金标准向量（I1） |
| `/Users/mac/projects/zchain/contracts/monad/build_solc.sh` | 修改：solc 直编清单纳入 `src/FastExit.sol`（:32），供无 foundry 环境编译验收 |
| `/Users/mac/projects/zchain/contracts/monad/README.md` | 修改：合约一览新增 FastExit 行（:14）+ FastExit 部署/初始化/运维要点节（:68-105） |
| `/Users/mac/projects/poker_texas_air/out/fastexit-advance-design.md` | 设计草案 v2（接口签名 + 语义 + 不变量论证 + L1Outbox diff + 测试计划；本仓 untracked） |

注：zchain 仓上述改动当前位于工作区未提交（`git status`：2 新增 + 3 修改，本次会话核对）。

## 二、设计要点与先例对标摘要

- **机制**：L2 站起生成快速通道叶子（`externalRecipient` = FastExit、`requestId` = 绑定哈希）；operator `advance` 同笔 tx 从浮存池垫付出账并记账；根上锚后任何人 `claimAndRoute` 代发 `L1Outbox.claim` 原子落账 Y 并纯记账分流——operator 得 `min(X_eff, Y)`（按垫付时点 funder 快照）、用户得差额，均入 pull credit；第三方抢跑直接 claim 的叶子由 `route` 凭叶哈希台账补救。X=0 时 `claimAndRoute` 即慢路径：permissionless、无排他窗口（对标 Across slowFill / StarkEx 任何人可领，规避排他窗锁死陷阱）。
- **收款人/资产/nonce 烧进 requestId**（对标 Hop transferId）：operator 伪造收款人立不了账（B1 用例实证零台账）；113B 叶结构零改动，复用 32B requestId 承载绑定。
- **operator 回收 ≤ min(X, Y)**，且仅当 tag/token 双匹配；无效垫付全额归用户（对标 Across 按真实成交退款 / Hop 真实 transferId 冲销）。
- **叶哈希台账（评审 High 修复，D6）**：route 分流证据绑定叶六字段（金额/收款人入绑），封死同 requestId 双叶铸无背书 credit 抽干池内资金；跨部署变体因 recipient 入叶哈希天然覆盖。
- **solvency**：`operatorWithdraw ≤ floatLedger − totalOutstanding`，claim 落账资金与 credit 均不入浮存——credit 恒有足额背书，上界严格紧于任务书原文（以 floatLedger 为基）。
- **风险归属**：最终性/冻结/多垫自亏归 operator；用户取回面（claimAndRoute/route/claimCredit）有意不挂 pause/freeze；重入 = 自含 nonReentrant + CEI + 分流零外呼，receive() 有意不挂守卫（持锁期 payout 回调不可自锁死）。
- **实现偏离草案仅 4 处工程必要项**（ask 给定材料）：① `requestBinding`/`withdrawable` 改 public 供内部复用；② `withdrawable` 在浮存<在途的可达态钳 0 防下溢 Panic；③ 新增 `Reentrant()` 错误名；④ `fundToken` 拒 `address(0)` 防虚增无背书原生浮存。
- **另提请注意**（ask 给定材料）：草案 F3 断言 `floatLedger ≥ totalOutstanding` 在草案记账下非恒成立（每笔垫付使差额降 2X：出账 X + 在途锁 X）——不影响安全（提额钳 0 fail-closed），测试文件头已登记该偏离并改断言真实不变量（余额 ≥ totalCredits、余额 ≥ floatLedger），另设 F2c 用例钉扎钳 0 语义（`FastExit.t.sol:19-25, 946`）。

## 三、测试门禁结果

- **本次会话执行**：`forge test --root /Users/mac/projects/zchain/contracts/monad`
  → 6 套件 **157 passed / 0 failed / 0 skipped**（FastExitTest 套件 59 passed；157 − 59 = 98，与 ask 给定既有基线 98 条吻合）。
- ask 给定门禁口径：forge 全量门禁累计 **1 轮**通过（基线 98 既有 + 新增套件），与本次复跑一致。
- 构建验收为 ask 给定材料，本次会话未单独复跑：`forge build` exit 0、`./build_solc.sh` exit 0。
- 设计评审：2 轮独立评审，未关闭意见为空（ask 给定材料）。

## 四、终审发现与复核状态

### 发现 1（severity low｜status verified｜未修复）：tokenForTag 重映射窗口后 route 的 credit 代币键与实际落账代币错配

- **发现**：`_split` 以调用时点的 `outbox.tokenForTag(leaf.assetTag)` 作 credit 键（`FastExit.sol:533-535`、`549-551`），而 bridge 在 claim 时点按当时映射付旧币 T1（`L1Outbox.sol:300-302`）——抢跑 claim（付 T1）后发生 remap，再走 `route`（按 T2 记 credit）时 T1 实物滞留合约无出口、T2 侧 credit 无背书，与 `FastExit.sol:78-80` natspec『credit 恒有足额背书』相悖（按币种 solvency 破约）。
- **证据**（终审复核产出，ask 给定材料；本次会话未复跑 PoC）：代码依据三处行号核对一致；`setTokenForTag` 仅 onlyAuthority 且不检查在途（`L1Outbox.sol:191-196`，本次会话核实）；叶哈希不含代币地址，remap 后 route 全部检查仍通过。可执行 PoC 实证：拷贝至 /tmp/fastexit-poc 新增 `RemapRoutePoC.t.sol`，`forge test --match-contract RemapRoutePoC -vvv` → 60 passed——抢跑 claim 后 100 T1 落 FastExit 且 floatLedger=0 → remap tag3→token2 → route 成功、`credits[token2][user]=100` 而 `credits[T1][user]=0`、token2 余额 0 < totalCredits 100 → `claimCredit` revert `TokenTransferFailed` → operator 补注 T2 后用户可领（消耗 operator 浮存）、T1 的 100 永久滞留。既有测试无 route+remap 组合用例（D6 走同 tx 天然一致；fuzz 无 remap 算子）。
- **定级依据**：remap 是 authority 特权行为，且 authority 本可借 commitRoot 任意根领取 Bridge 资金（`L1Outbox.sol:212-243`）——low 恰当。
- **是否已修复**：否，登记为后续项（§五.4）。

### 发现 2（severity low｜status verified｜未修复）：合约头注失实——operatorWithdraw 并未挂冻结卫兵

- **发现**：头注称『冻结/暂停只停 advance 与 operatorWithdraw』（`FastExit.sol:72-75`），但 `operatorWithdraw` 修饰符仅 onlyOperator/whenNotPaused/nonReentrant（`:465-470`），无 whenNotFrozen——冻结未暂停窗口内 operator 仍可提走浮存超额；与 `:178-181`『只挂 advance』自述矛盾。
- **证据**（终审复核产出，ask 给定材料）：whenNotFrozen 全文件唯一挂载点 = advance（`:302`）；代码符合设计（草案 :200-201 签名即无冻结卫兵、:353/:392 用暂停专属措辞）——属文档失实，资金面无恙（withdrawable 上界隔离 credit；终审定向复跑 G1/G2a/F2b 等 5 用例均 PASS，本次会话未复跑该子集）。复核另指出原发现引『L1Outbox.sol:72』行号有误（精确注释在 :8-11），不影响结论。
- **是否已修复**：否（建议改法：头注拆分冻结/暂停两半句，与草案措辞对齐）。

## 五、残余风险与后续工作（均不在本次范围）

1. **L2 侧叶子参数化**（硬性交付项）：requestId 绑定派生 + Rust 侧镜像 + 交叉对拍测试；违约后果 = 叶子永久锁定（fail-closed，草案 §5.5）。
2. **运营垫付 daemon + watcher 四件套**：站起事件推送/垫付决策、浮存水位、`claimedLeafHashes 非零 ∧ 未 routed` 积压告警、误直转侦测（草案 §6.2）。
3. **Monad 测试网演练**：fresh deploy 全流程 + 既有部署升级 runbook（互联边一次性 → 实质全栈重部署 + `claimedRequests/claimedLeafHashes` 台账迁移硬前提，草案 §3.4）。
4. **第三方审计**：将终审 2 项 low 发现一并处理——remap 窗口 credit 键错配的 remediation（如 `setTokenForTag` 在途检查、或 route 按 claim 时点代币键记账）与头注措辞修正。
5. **已登记边界**（草案 §5，v1 有意接受）：误直转滞留无 sweep 出口；冻结期在途垫付永久悬置（operator 自担）；大额差额受 30 块延迟约束；v1 无费用（引入须修订不变量 1）。
