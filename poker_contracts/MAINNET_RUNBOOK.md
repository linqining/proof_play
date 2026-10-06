# 主网部署 Runbook（2026-09-19 整理）

> 一页式执行手册。历史账目与逐次部署记录见 [DEPLOYMENTS.md](DEPLOYMENTS.md)，
> 合约地址速查见 [strk20.json](../strk20.json)。本文回答"现在主网跑什么、
> 要部署什么、怎么执行、怎么验证、怎么回退"。

## 0. 现状盘点（2026-09-19 快照）

### 主网在网（全部可用，但三个合约类已过时）

| 合约 | 地址 | 类（在网） | 类（当前源码） | 结论 |
| --- | --- | --- | --- | --- |
| PokerVault | `0x3f4ef706…` | `0x7c74ca1a…`（9-04 世代） | `0x6de64f9a…` | **重部署**（缺 P1-2 `set_session_tx_pk` → 桌面买入必挂） |
| PokerVaultAnonymizer | `0x88c1f843…` | `0x525646bd…`（9-07） | `0x6dbb1f82…` | **重部署**（与 vault 配套） |
| PokerDualSettlement v5 | `0x1d39b80b…` | `0x047e91d5…` | `0x255cafe3…`（v6） | **重部署**（v6：SNIP-36 门修正；无 set_vault，须随 vault 重部署实例） |
| PokerSettlement（legacy 兜底） | `0x2bf6a09c…` | `0x6f2e01a6…` | `0x6f2e01a6…` | ✅ 不动 |
| SettlementPayoutAnonymizer | `0x40237293…` | `0x7c11073c…` | `0x7c11073c…` | ✅ 不动 |
| PokerTableRegistry | — | — | `0x7cc910b5…` | 新增（可选但建议） |

- 主网 vault 存量玩家筹码：**9.47 STRK**（2026-09-19 实测）→ 需迁移公告。
- canonical STRK、主网隐私池 `0x040337b1…`、电路 program hash `0x744d16d3…`、
  hand-verify `0x303029d8…` 与 Sepolia 同值，无网络差异。

### Sepolia 参照（2026-09-19 已验证的同款批次）

vault `0x1b1b7b37…` / anonymizer `0x335db85a…` / dual v6 `0x66daeeee…` /
registry `0x39b3531d…`——9 笔部署接线 TX 全 SUCCEEDED，买入/结算冒烟通过。
执行顺序与接线即 `scripts/deploy_mainnet_v6.sh` 的蓝本。

## 1. 前置条件

1. **资金**：deployer `0x412e4d43…` 现余 **64.81 STRK**；本批估算 ≈97.5 STRK
   （declare vault≈28 + anonymizer≈6.3 + dual v6≈60 + registry≈3 + 部署接线≈0.2）。
   **先充值至 ≥150 STRK**（含 gas 波动缓冲）。
2. **构建**：`cargo build -p texas --bin snops --release`；
   `PATH="$HOME/.local/opt/toolchains/scarb-2.19.4/bin:$PATH" scarb build`
   （在 `poker_contracts/`，产物 `target/dev/*.json`）。
3. **账户**：`.env.mainnet` 的 ADDRESS/PRIVATE_KEY（= 全部在网合约 owner）。
4. **回填目标**：`strk20.json`、本文档、`texas/.env`、`client/.env.production`。

## 2. 执行（一键）

```bash
CONFIRM_MAINNET=yes ./scripts/deploy_mainnet_v6.sh
```

脚本流程（含 compiled-hash mismatch 自动重试与 nonce 竞态重试）：

```
declare ×4（vault / anonymizer / dual v6 / registry）
→ deploy vault(owner, canonical STRK, settlement=0)
→ deploy anonymizer(owner, vault, 主网池)
→ deploy dual v6(owner, vault, prover)   # dual 无 set_vault，必须随 vault 重部署
→ deploy registry(owner, grace=604800)
→ 接线：vault.settlement/unshield/authorized；dual.claim_helper/
  circuit_program_hash/hand_verify_program_hash/virtual_snos(占位)
→ 链上回读（含 session_tx_pk 入口存在性检查）
```

PAYOUT（`0x40237293…`）、池、两个 program hash 已内建为默认值，可用环境变量覆盖。

## 3. 部署后切换（改 env 即生效，旧合约原地保留）

```
texas/.env:                STARKNET_CHAIN_ID=SN_MAIN（保持）
                           STARKNET_VAULT_ADDRESS=<新 vault>
                           STARKNET_DUAL_SETTLEMENT_ADDRESS=<新 dual v6>
                           STARKNET_TABLE_REGISTRY_ADDRESS=<registry>
                           （legacy settlement / claim helper 不变）
client/.env.production:    VITE_POKER_VAULT_ADDRESS=<新 vault>
                           VITE_POKER_VAULT_ANONYMIZER_ADDRESS=<新 anonymizer>
                           （其余不变）
```

## 4. 验证清单

- [ ] 脚本回读全绿：`vault.token`=canonical STRK、`vault.unshield_helper`=新
      anonymizer、`session_tx_pk` 入口存在（P1-2）、`dual.vault`=新 vault、
      `dual.claim_helper`=payout、两个 program hash、registry.table_count=0
- [ ] 服务器重启后 registry 引导 `create_table` 上链 + `is_open` 回读 ✓
- [ ] 浏览器真实买入 1 STRK（会触发 `set_session_tx_pk`——本批的核心验证点）
- [ ] 打完一手牌，结算走 DAPV v2 入口（TX SUCCEEDED）
- [ ] 公开提现 `vault.withdraw` 一笔

## 5. 迁移与回退

- **迁移**：公告主网玩家在旧 vault `0x3f4ef706…` 公开 `withdraw`（存量
  9.47 STRK），到新 vault 重新买入。旧 vault/anonymizer/dual v5 原地保留，
  服务历史提现与认领，永不销毁。
- **回退**：`texas/.env` 与 client env 指回旧地址 + 两笔 owner invoke 把
  交易路径还原（旧 dual v5 / 旧 vault）即回 9-07 行为。

## 6. 开放门槛（不阻塞本批部署）

| 门 | 内容 | 处置 |
| --- | --- | --- |
| G2（SNIP-36） | dual 的 `virtual_snos_program_hash` 当前为占位值 `0x602b02cf…`；真实 proved 交易前须以主网实测 proof_facts 修正（`snops dump-proof-facts` 对拍） | 本批照部署；`STARKNET_DAPV_SETTLE_ENTRY` 保持 `v2`（fact-registry 腿，行为与 v5 等价）；过 G2 后再切 `snip36`。**transaction-prover 需 Linux x86_64 主机**（`docker run -d -p 127.0.0.1:3000:3000 -e RPC_URL=<v0.10 节点> ghcr.io/starkware-libs/starknet-privacy/transaction-prover:PRIVACY-0.14.3-RC.2`；Apple Silicon Mac 上 arm64/amd64 二进制均 SIGILL，实测 2026-09-19）；**内存基线实测 ≈2.35GiB**——上限低于此值会 OOM 死循环（重启风暴拖垮磁盘 IO），生产配置：宿主加 4G swapfile + 容器 `--memory 4g --memory-swap 8g`（2026-09-19 stark 服务器实测稳定）；prover 不可达/失败时结算自动回退 v2 腿，不中断。**2026-09-19 实测**：prover 已在 stark 上线并接受请求形状（小写 resource_bounds），但证明期 ~40s 内存死亡（7.3GB 主机带不动 SNOS 证明峰值）→ 入口已暂回 **v2**。**重新启用清单**：① 实例升配 16G（或 prover 迁独立大内存主机）② 容器上限调 12G ③ `.env` 改回 `STARKNET_DAPV_SETTLE_ENTRY=snip36` 并重启 ④ 下一手验证 ⑤ `snops dump-proof-facts` 钉扎 G2。**边界澄清（2026-09-27）**：该容器只证明 SNOS（Starknet OS）交易执行、仅 entry=snip36 需要；P 层递归信封与 settlement_private 证明全部由自托管 proving-tool/prove-hand 出证（编译缓存后 ~2.2s/手），与容器无关——entry=v2 现役路径零容器依赖；不可用 prove-hand 替代容器（程序/格式/验证器三者都不同，换了证明必被拒）。 |
| P3（⚠️ 高隐蔽前置） | 一切**隐私结算入口**（snip36 v3 / proved / private）要求**所有正 delta 地址**注册 payout commitment——**包括 treasury（抽水接收方）**。漏注册 treasury 的症状：每手仅一条 `[settlement-private] request build failed (non-fatal): winner 0x<treasury> has no payout commitment` WARN，随后静默回退公开线性——玩家侧无感，私密腿永不触发 | 已执行（2026-09-19）：treasury/operator `0x412e4d43…` 注册了**测试占位 commitment `0x7e57c0de7e57c0de`**（无 preimage——其 escrow 抽水无法私密领取）。生产修复：钱包内用正式 secret 重新 register（latest-wins 覆盖） |
| 私密领取 156 | Ready X / Avnu paymaster 对私密交易（含钱包原生 Shield）代发失败，交易不上链；Sepolia fork 测试证明合约腿健康，9-08 同流程曾成功 | 钱包侧问题，非本批合约阻塞项；私密出金 UX 暂以 Public withdrawal 兜底，进展见 DEPLOYMENTS.md 2026-09-19 章节 |
