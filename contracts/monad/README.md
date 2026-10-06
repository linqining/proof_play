# contracts/monad — zchain L2 的 Monad(L1) 结算合约栈

zchain 扑克 appchain（poker-appchain，soft-confirm sequencer）作为 **Monad 的 L2**，
本目录是把 Monad 当结算层（settlement layer）的最小合约栈。设计文档与全景见
[docs/monad-l2-settlement.md](../../docs/monad-l2-settlement.md)。

## 合约一览

| 合约 | 职责 | 关键入口 |
| --- | --- | --- |
| `L1Inbox` | L2 批次根/聚合根/checkpoint 锚定（index 连续纪律，checkpoint 按 L2 高度防重放） | `submitBatch` / `submitAggregate` / `submitCheckpoint` |
| `L1Outbox` | 提现根注册 + Merkle 证明领取（逐字节镜像 Rust `withdrawal_root` 树构造） | `commitRoot` / `markFinalized` / `claim` |
| `L1Bridge` | 资产资金库：入金锁仓事件（L2 侧铸 note）、提现支付通道（onlyOutbox） | `depositNative` / `depositToken` / `payoutNative` / `payoutToken` |
| `FastExit` | 站起即领的运营垫付通道：`advance` 同笔 tx 垫付出账 + `claimAndRoute`/`route` 按 `min(X, Y)` 分流入 pull credit | `advance` / `claimAndRoute` / `route` / `claimCredit` |
| `AuthorityOwnable` | 公共基座：单一 authority（两步转移）+ 全局暂停 | — |

与以太坊 OP-stack 的差异（为什么是自部署而非官方接口）：Monad 是独立 L1，
没有原生 rollup 接口（portal/blob 语义），这套合约栈即"自建 Inbox/Outbox/Bridge"，
对应接入清单的模式 B（Monad = settlement layer）。

## 数据承诺对齐（关键！）

L1Outbox 的树构造与 `poker-appchain/src/withdrawal_root.rs` **逐字节一致**：

- 域标签：`zchain.vault.withdrawal_root.v1`
- 叶哈希：`sha256(DOMAIN ‖ 0x00 ‖ borsh(leaf))`（borsh = 32B request_id ‖ 32B
  external_recipient ‖ 1B asset_tag ‖ 8B LE amount ‖ 32B burned_note_commitment
  ‖ 8B LE checkpoint_height，共 113B）
- 内部节点：`sha256(DOMAIN ‖ 0x01 ‖ l ‖ r)`；不平衡补空叶 `sha256(DOMAIN ‖ 0x00 ‖ "")`
- 根摘要：`sha256(DOMAIN ‖ 0x02 ‖ height_be ‖ leaf_count_be ‖ root)`

两侧一致性由 `monad-settlement` crate 的交叉验证测试锁死（Rust 真实 builder 产根
/证明 → Solidity 等价 verifier 对拍），合约内 `claim` 与 Rust `verify_inclusion`
的 fail-closed 边界（证明深度 ≥64 拒绝、index 越界拒绝）亦对齐。

## 编译与测试

```bash
cd contracts/monad
curl -L https://foundry.paradigm.xyz | bash && foundryup   # 首次装 foundry
forge install --no-git foundry-rs/forge-std                # 首次装依赖
forge test                           # 单元测试：13 项（治理/重放/授权/入金/互联面）
forge build                          # 产出 out/
```

> 无 foundry 的环境可用 `./build_solc.sh`（solc 直编）做编译验收；Merkle/签名
> 字节级正确性由 Rust 侧测试（`monad-settlement/tests/`）与 forge 测试双面保障。
> 合约改动两侧必须同步。

## 部署（Monad 主网 chainId=143 / 测试网 10143）

```bash
export AUTHORITY_ADDRESS=0x…          # L2 sequencer/运营方（生产建议多签）
export MONAD_RPC_URL=https://rpc.monad.xyz
export PRIVATE_KEY=0x…                # 部署私钥
forge script script/Deploy.s.sol \
  --rpc-url monad --broadcast --verify
```

互联调用全部为 `onlyAuthority`，部署脚本会**校验 PRIVATE_KEY 就是 authority**
（不一致直接 revert；生产多签场景把 AUTHORITY_ADDRESS 设为多签地址并以其身份
完成 wire 四步）。脚本自动完成互联（`outbox.setInbox` / `outbox.setBridge` /
`inbox.setOutbox` / `bridge.setOutbox` —— 注意 `bridge.setOutbox` 漏配会导致
所有提现支付 `NotOutbox` 失败，forge 测试已覆盖此缺陷）、大额延迟（默认原生
MON ≥100 时延迟 30 块）与可选代币标签（USDT/USDC）配置。把输出的三个地址写入
`monad_settlementd` / `monad_e2e` 启动参数（见 runbook）。

## FastExit 快速提现通道（部署与初始化）

`FastExit` 是站起即领的运营垫付通道（设计定稿：FastExit 接口草案 v2）：用户在
L2 站起选择快速通道时，叶子以 FastExit 为 `externalRecipient`、`requestId` 按
绑定哈希派生；operator `advance` 从自有浮存池先行垫付（同笔 tx 出账 + 记账）；
checkpoint 上锚后任何人 `claimAndRoute` 代发 `L1Outbox.claim`（收款人 =
FastExit，原子落账 Y）并纯记账分流——operator 得 `min(X, Y)`（按垫付时点
`funder` 快照）、用户得 `Y − min(X, Y)`，均入 pull 式 credit（`claimCredit`
领取）。无人垫付时 `claimAndRoute` 即慢路径（全额 Y 归用户，permissionless、
无排他窗口）；第三方抢跑直接 claim 的叶子由 `route()` 凭 L1Outbox 的
`claimedLeafHashes`/`claimedLeafMatches` 叶哈希台账补救分流。

部署与一次性初始化（在既有四合约互联**之后**追加；v1 交付假定 fresh deploy，
含 `claimedLeafHashes` 台账的 L1Outbox 一体部署）：

1. `new FastExit(authority, address(outbox), address(escapeHatch))`——outbox
   与 escapeHatch 均为不可变接线；FastExit 是纯外部 claim 调用方 + 独立资金
   池，**无需任何既有合约的新授权**（不进 Bridge 的 onlyOutbox 白名单、不占用
   任何既有一次性 setter）；
2. authority 调 `fastExit.setOperator(operatorBot)`——垫付热键，建议与
   authority 多签分离；轮换只影响新垫付归属，在途回收仍按 `AdvanceRecord.
   funder` 快照入账（`WithdrawalRouted.operatorCredited` 可稽核）；
3. operator 注入浮存：`fastExit.fund{value: …}()` /
   `fastExit.fundToken(token, amount)`（先 approve）。**注资只可走 fund 口**：
   直接 transfer 进合约的原生币不入 `floatLedger`、无提回出口（`receive()` 仅
   emit `NativeReceived` 留痕，链下以 tx 上下文区分 claim 落账 vs 误直转）；
4. L2/daemon 侧配置 FastExit 地址与 requestId 绑定派生（本次范围外的硬性
   接线约定）：
   `requestId = sha256("zchain.fastexit.request.v1" ‖ bytes20(R) ‖ bytes12(nonce) ‖ uint8(assetTag))`
   （R = 用户 L1 收款地址；合约侧 `requestBinding` 视图供 Rust/JS 对拍；
   tag=2 的 PLAY 内部筹码禁止走快速通道）。

运维要点：`withdrawable(token)` 监控可提超额（`operatorWithdraw ≤
floatLedger − totalOutstanding`，原生与每个 ERC20 分别记账；claim 落账资金
不入浮存、被隔离在 operator 可提面之外）；watcher 对 "claimedLeafHashes 非零
∧ 尚未 routed" 的积压补 `route`；EscapeHatch.escape 与垫付的交互是 operator
自担的信用风险（冻结期在途垫付可能永久悬置）；用户侧 credit 为 pull 式——
R 为不能主动调用的合约时 credit 永久保留不丢失。

## 审计关注点（对应接入清单 §6-7）

1. **最终性**：checkpoint 上锚前必须 L2 BFT finalized（daemon 纪律）；Monad 侧
   大额提现默认延迟 30 块（`claimDelayBlocks` + `largePayoutThreshold`）。
2. **重放**：checkpoint 同高度不可覆写；提现 `request_id` 全局记账；入金 nonce
   单调递增，L2 侧 `DepositV2.deposit_id` 幂等。
3. **资金路径**：Bridge 无 owner 提款——资金只能经 Outbox 证明路径流出；支付
   仅限 `onlyOutbox`；claim 先置 claimed 再支付（effects-before-interactions）。
4. **权限**：authority 两步转移；生产建议多签/ timelock；全局 pause 应急。
5. **字节对齐**：Outbox 树构造与 Rust 侧任何一侧改动都必须同步另一侧 + 测试。
