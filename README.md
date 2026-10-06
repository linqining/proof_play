# proof_play

**ProofPlay** — 可验证、高性能、低延迟的链上游戏平台。参赛 [Monad Metropolis Hackathon](https://monad.xyz/developers/hackathons/metropolis)。

从 `poker_texas_air`（Starknet 时代的全栈项目）迁入：保留游戏服务器、证明端与结算管线，L1 从 Starknet/zchain 切换为 **Monad**（EVM），品牌以 ProofPlay 推广、娱乐向定位，当前为账本风格 UI 的过渡版，UI/UX 将重做。

## 仓库结构

| 目录 | 内容 |
|---|---|
| `src/` | Texas Hold'em 方法 AIR（19 个）+ Stwo circle-STARK 证明栈；含 EVM/Monad ABI 适配 `host_evm_settlement.rs` |
| `texas/` | 游戏服务器：axum + socket.io 牌局循环、JWT、限流、dev bot、结算接线。**无 `STARKNET_RPC_URL` 时自动进本地 dev 模式，可跑完整牌局** |
| `client/` | 游戏前端（React 18 + Vite + socket.io），已含 Monad 钱包/结算读取层（`client/src/starknet/monadWallet.ts` 等） |
| `client-wasm/` | wasm-bindgen 桥：浏览器内洗牌/揭示 σ 证明校验 |
| `contracts/monad/` | **Monad 合约**（Foundry，solc 0.8.28）：L1Inbox / L1Outbox / L1Bridge / StarkVerifier(`submitFinalProof`) / SettleWrap / SettleBatch / Groth16Verifier(Batch) / EscapeHatch / FastExit |
| `stark-recursion/` | K 手牌 → 单个 STARK 终证 + Monad 链上 calldata 编码（`onchain.rs`） |
| `groth16-wrap/` | STARK→Groth16(BN254) 包装，面向 Monad EVM 验证 |
| `proving-tool/` | `prove-hand` CLI：Cairo 编译 → cairo-vm → Stwo 证明 → 验证（独立 workspace） |
| `fact-verify/` | 证明核验与结算事实派生 CLI（独立 workspace） |
| `batch-poster/` | 结算驻留进程：读 settle-queue WAL、出终证、写 Monad envelope spool（Starknet 提交腿待替换为 EVM txmgr） |
| `settle-queue/` `balance-rollup/` `privacy-profile/` `da-backup/` `vm-common/` | 链中立的结算队列 / 余额 rollup / 隐私档位 / DA 备份 / 共享类型 |
| `poker_l1/` | 德州合约/VM 语义（证明重放用，Rust，链中立） |
| `poker_contracts/` | Starknet Cairo 时代的合约与 **dual/ 证明程序**（证明程序仍被证明管线使用；Cairo L1 合约为休眠遗留） |
| `starknet-txmgr/` | Starknet 交易管理器（**待替换**为 EVM txmgr，batch-poster 目前依赖它编译） |
| `third_party/` | vendored 依赖：stwo（patched）、flock、proving、cairo corelib —— 编译必需 |
| `docs/` | 品牌资产（`docs/brand/`）、设计文档、运维文档；`docs/legacy/` 为迁移前 README |

## 本地跑起来（无链 dev 模式）

```bash
# 1. 游戏服务器（:9001）。JWT_SECRET 必填；不设 STARKNET_* 即本地 dev 模式
JWT_SECRET=$(openssl rand -hex 32) TEXAS_PROVER_MODE=dev cargo run -p texas

# 2. 前端（wasm 包已预构建在 client-wasm/pkg/；重跑: wasm-pack build client-wasm --target web）
cd client && pnpm install && pnpm dev   # vite，/api 与 /socket.io 代理到 127.0.0.1:9001
```

需要 Starknet devnet + 合约部署的完整联调链路见 `scripts/dev.sh`（迁移自原仓库，Monad 适配进行中）。

### Monad 买入（L1Bridge）与本地全链路

买入已从 Cairo `PokerVault` 切到 Monad `L1Bridge`（`contracts/monad/src/L1Bridge.sol`）：

- 浏览器（Monad 钱包，EIP-1193）→ `L1Bridge.depositNative(自己)` 锁 MON → 回执哈希随 `SIT_DOWN_V2` 上送
- 服务端 `texas/src/starknet/appchain/monad_bridge.rs`：回执 + `DepositInitiated` 事件核验（收款人==买家、可用余额+面额覆盖买入额）→ 存款桥幂等铸 appchain note（chips 即到账；每 2s 自动轮询补铸漏网事件）
- 余额视图：`/api/auth` 的 chips 与入座预检在嵌入式模式下以 appchain note 为权威（差额才上链，余额够则零交易入座）

本地离线跑通完整买入闭环（anvil 当 Monad devnet，chainId 10143）：

```bash
~/.foundry/bin/anvil --chain-id 10143                                   # 本地 "Monad"
cd contracts/monad && forge script script/DeployDevL1Bridge.s.sol \
  --rpc-url http://127.0.0.1:8545 --broadcast                           # 输出 L1Bridge 地址

# server env（示例见 .env.smoke）
TEXAS_APPCHAIN_PROVIDER=monad MONAD_RPC_URL=http://127.0.0.1:8545 \
MONAD_L1BRIDGE_ADDRESS=<部署输出> JWT_SECRET=… TEXAS_PROVER_MODE=dev cargo run -p texas

# client env（client/.env.development.local）
VITE_MONAD_L1BRIDGE_ADDRESS=<部署输出>
VITE_DEV_ANVIL_RPC=http://127.0.0.1:8545   # 无 MetaMask 时注入 dev EIP-1193 代理（anvil 账户）
```

浏览器：登录弹窗「Monad 钱包」→ 大厅 → JOIN TABLE → 买入弹窗（MON 余额/可购筹码）→ Sit Down 即发真实 EVM 存款交易。上 Monad 测试网只需换 `MONAD_RPC_URL=https://testnet-rpc.monad.xyz` 并用真钱包（MetaMask 加 Monad 测试网 10143）。

### Monad 合约

```bash
cd contracts/monad && forge build   # 需 Foundry；部署脚本 script/Deploy.s.sol
```

Monad 主网 chainId=143，测试网=10143（`https://testnet-rpc.monad.xyz`）。结算设计：`stark-recursion` 出终证 → `L1Inbox.submitBatch`/`StarkVerifier.submitFinalProof` 锚定，Groth16 包装路径走 `SettleWrap`/`SettleBatch`。

## 品牌

- [品牌文档索引](docs/brand/README.md) · [标志两路九套方向 + 出图管线](docs/brand/logos/README.md)
- 改标志几何只改 `docs/brand/logos/build.py`，重跑 `./docs/brand/logos/render.sh`（注意：本机 Intel Homebrew 的 rsvg-convert/python3 在 arm64 上不可用，PNG 步骤需 arm64 工具链）

## 迁移说明（2026-10-06 自 poker_texas_air）

- 未迁入：Lean 形式化（`stwo_lean/`、`src/airs_lean/`，7.8G 研究资产）、`fuzz/`、`payout-sidecar/`（STRK20 专属）、`poster-sidecar/` 运行数据、`.env.dev/.env.play/.env.mainnet`（**含真实私钥，已确认未带入**）
- 深度文档：[docs/legacy/README.poker_texas_air.md](docs/legacy/README.poker_texas_air.md)
- 已完成：买入合约 Cairo `PokerVault` → Monad `L1Bridge`（见上节）
- 待办：batch-poster 的 Starknet 提交腿 → EVM txmgr；groth16-wrap `gen_sol*` 输出路径指向 zchain 仓库 → 改指本仓库 `contracts/monad`；`pay_withdrawal`（Monad 出金打款，需 EVM 交易签名，与 txmgr 一并接）
