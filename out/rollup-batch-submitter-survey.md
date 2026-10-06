# Rollup 批量上链（batch submission）工具调研：StarkEx 及主流体系的组织与管理方式

> 调研日期：2026-09-30。服务于 todo 第 2 项「批量上链 rollup 程序」的立项决策。
> 覆盖体系：StarkEx（重点）、Starknet 主网 + SHARP、Optimism OP Stack、Arbitrum Nitro、zkSync Era、Polygon zkEVM、Linea、Scroll。
> 所有结论带一手出处；调研中未能核实的点均标注「未能确认」。

---

## 0. TL;DR

**问题：「rollup 批量上链的工具是单独一个库么？怎么管理？」**

**回答：没有任何一家把批量上链做成「独立库」对外发布。它是 operator 基础设施里的一个一等组件，业界只有三种形态：**

| 形态 | 代表 | 说明 |
|---|---|---|
| **闭源 SaaS 组件** | StarkEx 的 Dispatcher + Blockchain Writer | StarkWare 托管整个后端，客户端经 REST + mTLS 接入；开源的只有合约、Cairo 程序、DAC 参考实现、JS SDK |
| **monorepo 里的独立二进制** | OP Stack 的 `op-batcher`/`op-proposer`、Scroll 的 `rollup_relayer`、Linea 的 coordinator（独立 Java 服务） | 单独进程、单独容器，但交易管理（txmgr）抽成 monorepo 内共享库 |
| **单二进制内的组件/角色开关** | Arbitrum nitro-node（`--node.batch-poster.enable`）、zkSync `zksync_server`（components.rs 选 `eth_sender`）、Polygon zkevm-node（`run --components sequencesender,aggregator`） | 一个二进制，按 flag 拆角色部署，一容器一角色 |

**管理上的共性（这是比「放哪」更重要的答案）：**

1. **持久化队列 + 幂等**：待提交操作先落库（zkSync 落 Postgres、Arbitrum dataposter 落 DB/Redis、zkEVM 用 monitored-tx 表），重启断点续发，而非内存状态。
2. **专门的 L1 交易管理层**：zkSync `eth_tx_manager`、zkEVM `ethtxmanager`、OP `op-service/txmgr`、Arbitrum `dataposter`——nonce 推断、RBF 加价重发、卡死交易取消、reorg 处理，全部不手写裸 RPC 循环。
3. **密钥分级**：提交用的 operator 热钱包 与治理/升级用的冷钱包（Governor/multisig）严格分开；合约侧把 operator 地址白名单化（`isBatchPoster`、StarkEx `Operator` 组件、Starknet 两个 proposer EOA/multisig）。
4. **程序哈希/verifier 钉扎 + 时间锁升级**：StarkEx 合约校验 program hash，升级走注册新版本 → timelock → 切换；zkSync 证明走 validator timelock。
5. **safety over liveness**：zkSync L1 交易失败直接 panic 回滚（宁可停机不可错提）；op-proposer 不提交未 finalized 状态。
6. **监控闭环**：pending 积压、nonce 三档（finalized/soft/unconfirmed）、poster 余额、链上事件停涨告警。

---

## 1. StarkEx：批量上链是闭源托管后端里的两个组件

### 1.1 八组件流水线

StarkEx backend 官方文档定义为 8 个组件（[backend architecture](https://docs.starkware.co/starkex/architecture/starkware-exchange-back-end-architecture.html)）：

1. **Gateway** — 接收 app 交易，无状态校验后入队
2. **Batcher** — 交易聚合成 batch，有状态顺序校验；batch 链式构建，链上 revert 自动检测并从最后有效 batch 重建
3. **Feeder Gateway** — 对外提供已验证 batch 数据
4. **Availability Gateway** — batch 上链前的委员会 quorum 审批（DA + operator 一致性确认双重用途）
5. **Ambassador** — 内含 Cairo 程序执行每个 batch，把 trace 作为 job 发给 SHARP
6. **Dispatcher** — 生成流式 package，流顺序即上链顺序
7. **Blockchain Writer** — 把 state transition 发到 L1 合约，管 gas price / nonce / 签名，必要时提价重发
8. **Catcher** — 监控链上回执，把 revert 报回 Batcher

**「批量上链」的职责就落在 Dispatcher + Blockchain Writer + Catcher 三件套上**——它们不是独立库，也不是 app 侧工具，而是与 Batcher 同进程群的闭源服务组件。

### 1.2 开源 vs 闭源清单（starkware-libs org 实测盘点）

| 仓库 | 内容 | 状态 |
|---|---|---|
| [starkex-contracts](https://github.com/starkware-libs/starkex-contracts) | StarkExchange 合约：Proxy/Dispatcher/sub-contracts（因 EIP-170 用 perfect hash 路由）、`GpsFactRegistryAdapter`、`Operator.sol`/`StarkExOperator.sol`、Governance、Freezable | 开源 |
| [starkex-core](https://github.com/starkware-libs/starkex-core) | v4.5 起的 meta-repo，git submodule 聚合 5 个开源件 | 开源（仅入口） |
| [starkex-js](https://github.com/starkware-libs/starkex-js) | REST API SDK（gateway / feederGateway，`/v2/` 前缀），npm `@starkware-industries/starkex-js` | 开源 |
| [starkex-resources](https://github.com/starkware-libs/starkex-resources) | 委员会成员服务、crypto、storage、aerospike | 开源 |
| [starkex-data-availability-committee](https://github.com/starkware-libs/starkex-data-availability-committee) | DAC 节点参考实现（C++ + Docker） | 开源 |
| [starkex-for-spot-trading](https://github.com/starkware-libs/starkex-for-spot-trading) / [stark-perpetual](https://github.com/starkware-libs/stark-perpetual) | Cairo 程序源码 + `program_hash.json` + `extract_cairo_hash.py`（可对主网合约核对运行中的 program hash） | 开源 |
| [cairo-lang](https://github.com/starkware-libs/cairo-lang) | 含 SHARP 客户端 `src/starkware/cairo/sharp/sharp_client.py`（submit/status/is_verified CLI + fact 轮询） | 开源 |
| **Gateway/Batcher/Ambassador/Dispatcher/Blockchain Writer/Catcher** | 真正的批量上链执行体 | **闭源，StarkWare 托管** |

- **`starkex-deploy` 仓库不存在**（404，org 列表三页无此仓库，搜索引擎无索引——是否曾存在后删除未能确认）。部署面由 starkex-contracts 的 `abi/` 目录 + docs 的 [deployments-addresses](https://docs.starkware.co/starkex/deployments-addresses.html) 承担。
- 接入模式是 SaaS：官方文档要求「获得 dedicated StarkEx instance + 你自己的 L1 合约」，REST + 双向 TLS 证书，客户端是唯一 operator（[Integrating your own StarkEx instance](https://docs.starkware.co/starkex/con_integrating_your_own_starkex_instance.html)）。第三方自托管闭源 backend 无公开路径（未能确认可行）。
- 案例：dYdX v3 用独立 prover + 独立 GPS/FRI verifier（唯一不用 SHARP 的客户，已停机走 escape-hatch）；Immutable X、Sorare 是定制化部署（均已宣布迁移离开）。

### 1.3 DA 模式与 updateState 提交者

三种模式（[Data availability](https://docs.starkware.co/starkex/con_data_availability.html)）：

- **ZK-Rollup**：净余额变更（net balance changes，非逐笔）以 calldata 上链
- **Validium**：数据链下由 DAC 持有，updateState 须委员会 quorum 签名（`Committee` 合约校验）
- **Volition**：按 vault ID 范围分两棵树，用户可选

`updateState` 的提交者是合约里 operator 角色 =「StarkEx 服务的热钱包」，由 Governor（冷钱包）即任命/撤销（[Contract management](https://docs.starkware.co/starkex/perpetual/shared/contract-management.html)）。注意即便 rollup 模式，每个 batch 上链前也要先拿到 app 侧委员会服务对 Availability Gateway 的签名批准——「batch 审批」与 DA 是两回事。

### 1.4 合约与证明管理（对本项目最有参考价值）

- **Program hash 钉扎**：Cairo 程序仓库内 `program_hash.json` + CI 校验；`extract_cairo_hash.py --main_address <addr> --node_endpoint <node>` 可随时对主网合约核对正在使用的 hash。业务配置（如 dydx-config）只含资产/oracle/risk 参数，verifier 与 program hash 不混在业务配置里。
- **可升级性**：Proxy 持状态与资金，逻辑可换；升级流 = 注册新版本 → timelock（给用户退出窗口）→ 切换，旧版本可立即回滚。
- **Verifier 管理**：Governor 可加新 verifier（过渡期要求全部通过）；删除 verifier 需 `announceVerifierRemovalIntent` + `VERIFIER_REMOVAL_DELAY` 时间锁——防运营方破坏 soundness。
- **SHARP**：job 到达即证、两两递归聚合，触发条件满足时一个最终 proof 进共享的 `GpsStatementVerifier`（主网 `0x4731...db60`），多方分摊验证成本；app 合约经 `GpsFactRegistryAdapter` 把自己的 fact 格式对齐 SHARP 格式。事实（fact）= program hash 链 hash 出的 claim。
- **逃生机制**：用户 L1 强制操作 → operator 窗口期不服务 → 任何人 `freezeRequest` 冻结 → Merkle path `verifyEscape` → `escape` 提款。dYdX 停机后实战用过；L2Beat 开源了 [starkex-explorer](https://github.com/l2beat/starkex-explorer) 可解码 calldata 发起 forced exits。

### 1.5 StarkEx 运维管理

- **密钥分级**：Governor（冷钱包，治理/升级/任命 operator）vs Operator（服务热钱包，只发 updateState）。
- **DAC 节点**：Docker 部署，`config.yaml` + `private_key.txt` + mTLS 证书连 Availability Gateway；存储参考 Aerospike（约 40GB）；mandatory signer 建议强一致存储双副本。
- **监控**：backend 内置 Catcher 盯 revert 回灌 Batcher；operator 自身 HA 拓扑与内部监控未见公开（未能确认）。

---

## 2. Starknet 主网 + SHARP：proposer 只是合约 operator 角色，运营闭源

- 结算路径：sequencer 出 state diff → SHARP 证明 Starknet OS 执行并注册 fact → operator 调 L1 core contract（`Starknet.sol`）`updateState`，合约校验 SHARP fact + **pinned 的 OS program hash / config hash**（L2Beat：「cannot bypass the pinned program and config hashes」——与本项目 owner 钉扎 program hash 同一模式）。出处：[L2Beat – Starknet](https://l2beat.com/layer2s/projects/starknet)。
- **proposer 没有独立开源软件**： proposing 是 permissioned 白名单，目前恰好两个 operator（StarkWare EOA `0x4032...C2c2` + 抗审查少数派 3/12 multisig）。`updateState` 逻辑在开源的 `Starknet.sol` / `StarknetOperator.sol`（cairo-lang 仓库内），但签名的运营方闭源。
- Blob：v0.13.1 起 state diff 默认走 EIP-4844（blob 内放 diff 多项式 FFT 求值，配「commitment equivalence trick」把 KZG 承诺与 STARK-friendly 承诺绑在一起）。出处：[DA with EIP-4844](https://community.starknet.io/t/data-availability-with-eip4844/113065)。
- 生产 sequencer 闭源（现为 5 个 StarkWare 控制的 BFT sequencer）；新一代 Rust sequencer 在 [starkware-libs/sequencer](https://github.com/starkware-libs/sequencer) 开源开发中；SN Stack（2025-01 公开）面向 appchain 复用这些组件。
- **SHARP 流水线**：Gateway → Job Creator（去重）→ Validator → Scheduler（聚合分组）→ Cairo Runner → Prover（Stone → 已切 S-Two）→ Dispatcher（或链下递归再证）→ Blockchain Writer → Catcher。第三方可用 cairo-lang 的 `sharp_client.py` 提交 PIE + 轮询 fact，或走 Herodotus 的 **Atlantic**（SHARP 托管网关，L1 走 GpsStatementVerifier / L2 走 Integrity verifier）。
- **L2 上验证 STARK 的实践（与本项目同构）**：[HerodotusDev/integrity](https://github.com/HerodotusDev/integrity)——Cairo 写的 Stone verifier + 配套 **FactRegistry**（`verify_proof_full_and_register_fact`，其他合约 Scarb 依赖查 `is_fact_hash_valid_with_security`）；为绕 Starknet calldata/step 限制把 AIR 拆 side contracts、FRI witness 分多笔交易；bootloader 模式只校验 program hash 而非完整 bytecode。

---

## 3. OP Stack：op-batcher —— 独立二进制的教科书样本

### 3.1 形态

- **独立二进制**（`op-batcher/` 目录 → `./bin/op-batcher`），与 op-node（sequencer 共识层）、执行引擎（op-geth/op-reth，已拆独立仓库）分开构建运行。目录：`batcher/`（driver）、`cmd/`、`compressor/`、`config/`、`flags/`、`metrics/`、`rpc/`（admin API）。出处：[op-batcher](https://github.com/ethereum-optimism/optimism/tree/develop/op-batcher)。
- 部署：官方 docker-compose 里 sequencer（op-node + op-reth）+ **op-batcher 独立容器** + op-proposer / op-challenger 各自独立容器（[compose 示例](https://github.com/ethereum-optimism/optimism/blob/develop/docs/public-docs/create-l2-rollup-example/docker-compose.yml)）。无官方 Helm chart（未能确认存在；社区有 Tokamak 等）。

### 3.2 工作机制（值得抄的细节）

- **四个并发循环**：`blockLoadingLoop`（按 safe head 剪枝已上链数据）/ `publishingLoop`（开 channel、压缩、切 frame、发 tx）/ `receiptsLoop`（处理回执与 channel 超时）/ `throttlingLoop`（DA 积压时反向节流 sequencer 出块，支持 Step/Linear/Quadratic/PID 控制器）。
- **打包**：channel = 多个 batch RLP 后 zlib/Brotli 压缩（Fjord 起 versioned encoding）；frame 固定 23 字节头 + ≤1MB 数据，一笔 tx 可混装多 channel 的 frames；derivation 端按 `(channel_id, frame_number)` 去重。
- **txmgr**（`op-service/txmgr/`，monorepo 共享库）：`SendState` 跟踪同一逻辑 tx 的多个 gas 变体 hash；nonce-too-low 计数超阈值才放弃；gas bump 重发 + 价格护栏（min/max tip、basefee、fee limit multiplier）；`TxpoolState` 状态机处理卡死 nonce（发 cancellation tx 清位）。
- **防重复提交**：启动时 `--check-recent-txs-depth` 回看 L1 近 N 块找自己最近的 batch tx + `--wait-node-sync` 等验证节点消化。
- **HA**：无内置 leader election，按单实例 + crash-safe 重启设计；op-conductor 的 raft 选举只覆盖 op-node，不覆盖 batcher。
- **成本调节**：`--target-num-frames`（≈每笔 blob tx 的 blob 数，建议 6）、`--max-channel-duration`（攒批时长，建议 1500 块 ≈5h）、`--sub-safety-margin`（提前量）、DA 类型 `calldata/blobs/auto`、throttling 阈值。

### 3.3 op-proposer

独立二进制，定时向 L1 提交 L2 output root claim（fault proof 链走 DisputeGameFactory）。设计取向「safety over liveness」：提交未 finalized 状态会产生无效 claim 并被罚没，`--allow-non-finalized` 仅供测试网。

---

## 4. Arbitrum Nitro：单二进制内的 batch poster 角色 + dataposter 交易层

- **不是独立二进制**：`arbnode/batch_poster.go`（约 2200 行）+ `arbnode/dataposter/`，`--node.batch-poster.enable=true` 开启；官方 nitro-testnode 用同一镜像、独立容器 + `poster_config.json` 跑纯 poster 节点。出处：[batch_poster.go](https://github.com/OffchainLabs/nitro/blob/master/arbnode/batch_poster.go)、[deep-dive](https://docs.arbitrum.io/how-arbitrum-works/deep-dives/batchposter)。
- **数据源是本地 DB 不是 sequencer feed**：TransactionStreamer 持久化 sequenced messages → BatchPoster 主循环 `MaybePostSequencerBatch` 拉取 → typed segments → Brotli 压缩 → DA 层 → DataPoster 发 `SequencerInbox`。所以 poster 必须跑在有 streamer 数据的节点（sequencer 或其 DB/Redis 副本）上。
- **DataPoster**（[dataposter](https://github.com/OffchainLabs/nitro/tree/master/arbnode/dataposter)）：nonce 持久化到队列存储（DB 或 Redis），重启断点续发；RBF 梯度重发（默认 5m,10m,30m,1h,4h,8h,16h,22h）；`MaxQueuedTransactions/MaxMempoolTransactions/MaxMempoolWeight` 约束；指标 `arb/dataposter/nonce/{finalized,softconfirmed,unconfirmed}`。
- **授权**：L1 `SequencerInbox.isBatchPoster` 白名单（`setBatchPoster` 由 rollup owner / Batch Poster Manager 设置）；poster 地址余额无自动补充，需按 ~3 天成本阈值告警（`arb/batchposter/wallet/eth`）。
- **AnyTrust**：数据发 DAC 收集 N-1 个 BLS 签名聚合成 DACert 上链（信任假设 1-of-N 失效）；DAS 签名收集超时则**自动回退 rollup 模式**直接全量上链（`ethDAFallbackRemaining` 计数）——回退发生本身就是告警信号。
- **HA**：seq-coordinator + Redis 做 sequencer 3 副本跨 AZ；poster 也开 seq-coordinator 跟随协调状态但**绝不能进 priorities 选举表**（官方明确警告，否则链停摆）。

---

## 5. zkSync Era：eth_sender 组件 + eth_tx_manager 交易层

- monorepo 里**没有叫 operator 的 crate**；「operator」= 运行 `zksync_server` 的实体，L1 提交职责在 `core/node/eth_sender/`（`eth_tx_aggregator.rs` / `eth_tx_manager.rs` / `zksync_functions.rs` / `aggregated_operations.rs`）。单二进制，`core/bin/zksync_server/src/components.rs` 按字符串别名选组件启动。出处：[core/node](https://github.com/matter-labs/zksync-era/tree/main/core/node)、[架构文档](https://github.com/matter-labs/zksync-era/blob/main/docs/src/guides/architecture.md)。
- **三阶段生命周期**：`aggregated_operations.rs` 定义 `Commit` / `PublishProofOnchain(ProveBatches)` / `Execute`（另有 L2 级 Precommit），每阶段独立聚合上限与 deadline；三阶段全由 eth_sender 提交。prove 路径经 validator timelock 延迟验证。
- **eth_tx_manager**：nonce 不本地分配，从 L1 链上读 operator nonce（latest / fast_finality / finalized 三档）推断 in-flight 状态；每轮只重发第一笔保序；stuck 交易按费用 oracle 重新定价；每次 attempt 落库 Postgres 带 gas/latency 历史。**交易失败触发 circuit breaker 直接 panic 回滚 proven 状态**（"We can't operate after tx fail"）——宁可停机不可错提。
- **密钥**：`core/lib/operator_signer` 支持本地私钥与 **GCP KMS**（主网是否实际用 KMS 未能确认）；多 operator 与 Blob/NonBlob/Gateway 三通道并行（2024-06 PR #2341）。
- DA：blob（PubdataChunkPublisher 切 4096×31B chunk 最多 6 blob，L1 `Executor.commitBatches` 的 `pubdataCommitments` 带 Calldata=0/Blob=1 头）+ 正交的外部 DA 维度（GCS/Avail/Celestia/Eigen）。
- 配置管理已迁到 **ZK Stack CLI**：根 `ZkStack.yaml` + `configs/`，由 `zkstack_cli` 驱动部署。

---

## 6. Polygon zkEVM（v1，已归档）：sequencesender + aggregator + ethtxmanager

- 单 Go 二进制多组件：`zkevm-node run --components SYNCHRONIZER,SEQUENCER,SEQUENCE_SENDER,RPC,AGGREGATOR,ETHTXMANAGER,L2GASPRICER`，一容器一角色共享二进制（test compose：zkevm-sequencer / zkevm-sequence-sender / zkevm-aggregator / zkevm-eth-tx-manager 各一个服务）。出处：[zkevm-node](https://github.com/0xPolygon/zkevm-node)。
- **batch 上链**：`sequencesender/sequencesender.go` —— batch 关闭后独立组件把一批 batch 打成 sequence，`EstimateGasSequenceBatches` 超限截断，构造 calldata 交给 ethtxmanager 调 `PolygonZkEVM.sequenceBatches`。
- **proof 上链**：`aggregator/final.go:sendFinalProof` → `verifyBatchesTrustedAggregator`（注意：没有叫 submitProof 的函数，那是二手资料的说法）。
- **ethtxmanager**：monitored tx 状态机（Created→Sent→Confirmed/Failed/Reorged）、nonce 从 pending 推导、`GasPriceMarginFactor` 加价封顶 `MaxGasPriceLimit`；私钥用加密 keystore 文件（`[SequenceSender] PrivateKey = {Path, Password}`）。
- trusted sequencer 由 L1 合约强制唯一；permissionless 路径靠 `forceBatch`。v1 纯 rollup（calldata 上链），blob 证明路径是 stub 未启用。

---

## 7. Linea 与 Scroll（简要）

- **Linea**：coordinator 是**独立编排服务**（monorepo 顶层 `coordinator/`，Java + Gradle，镜像内打包 blob compressor 与 shnarf calculator 两个 JAR）。Pipeline：Conflation（按 trace 上限合流 L2 block 成 batch）→ Compression → Aggregation → Finalization（先提交 blob 到 L1 rollup 合约，再提交 aggregation proof finalize，主网约 2 小时一次）→ poll L1 finality 反馈。Stage 间共享数据库、各按自己节奏推进、**重启可续**。出处：[coordinator docs](https://docs.linea.build/protocol/architecture/coordinator)。
- **Scroll**：独立 `rollup_relayer` 服务（Go monorepo `rollup/` 目录）。三组件：Chunk Proposer（proving 单元）→ Batch Proposer（L1 提交单元）→ Relayer（commit 与 finalize **都由 l2_relayer 完成**：commit 阶段每个 batch 编码为 kzg4844 blob 调 `commitBatches`，finalize 阶段从 DB 取 verified proof 打包 `finalizeBundle`）。有基于 blob 费率滑窗的延迟提交费用策略 `skipSubmitByFee()`。出处：[scroll rollup](https://github.com/scroll-tech/scroll/tree/develop/rollup)。

---

## 8. 横向对比总表

| 维度 | StarkEx | OP Stack | Arbitrum | zkSync Era | Polygon zkEVM | Linea | Scroll |
|---|---|---|---|---|---|---|---|
| 上链工具形态 | 闭源 SaaS 组件（Dispatcher/Blockchain Writer） | **独立二进制** op-batcher/op-proposer | 单二进制角色 batch_poster | 单二进制组件 eth_sender | 单二进制组件 sequencesender + aggregator | **独立服务** coordinator（Java） | **独立服务** rollup_relayer |
| 交易管理层 | Blockchain Writer 内置 | op-service/txmgr（共享库） | arbnode/dataposter | core/node/eth_sender/eth_tx_manager | ethtxmanager | coordinator 内置 sender | controller/sender |
| 队列/状态存储 | 闭源（未能确认） | 内存 + 链上游标（crash-safe 重启） | DB / Redis 持久化队列 | **Postgres 落库** | Postgres monitored-tx 表 | 共享数据库 | DB |
| nonce 策略 | 闭源 | SendState 变体追踪 | 链上推断 + 队列持久化 | 链上三档推断，每轮只重发第一笔 | pending 推导 | 内置 | sender 内置 |
| 提交者授权 | 合约 Operator 角色（Governor 任命） | SystemConfig 里 batcher 地址 | SequencerInbox.isBatchPoster | operator 签名账户 | trusted sequencer 唯一地址 | operator | relayer |
| HA | SaaS 内部 | 单实例 + crash-safe（无 leader election） | seq-coordinator + Redis；poster 跟随不参选 | 组件化单 operator | 单 sequencer | coordinator 单实例 | relayer 单实例 |
| 失败哲学 | Catcher 回收 + 从最后有效 batch 重建 | 回退 frameCursor 重发（宁重付不错序） | backlog 告警 + 回退 | **失败即 panic**（停机优先） | monitored tx 重试 | 重启可续 | 费率高延迟提交 |
| DA | calldata 净差额 / DAC 签名 / volition | calldata / blob / auto / Alt-DA | calldata / blob / AnyTrust DACert（超时回退 L1） | blob(6个/批) / calldata + 外部 DA | calldata | blob | blob + validium 变体 |

---

## 9. 对 poker_texas_air 的映射与建议

现状（调研时确认）：
- 结算+calldata 组装+提交内嵌在 texas 服务里（`texas/src/starknet/submit.rs` 的 `settle_hand`，dev 模式只出 calldata 记日志）；
- fold 工作流：`proving-tool/prove-batch.sh` 手动出证，`scripts/pin_fold_program_hash.sh` 钉扎程序哈希，合约 `poker_dual_settlement.cairo` owner 调 `set_*_program_hash`；
- 证明生成（~51.6s/批、431k steps）与上链提交之间没有常驻组件。

结合业界做法的建议：

1. **形态：参照 op-batcher / eth_sender，做 monorepo 内独立 crate（如 `batcher/` 或复用 payout-sidecar 位置），而不是独立仓库、也不是库。** 理由：所有体系都把它做成 operator 栈内单独进程/组件（独立仓库的只有 Linea 这种多语言 monorepo 场景）；交易管理层（txmgr 等价物）抽成 crate 内模块供复用。职责：从结算队列拉 fold batch → 攒批/触发 cadence → 调 proving-tool 出证 → 组装 `poker_dual_settlement` calldata → 经交易管理器提交 → 监控回执。
2. **持久化队列 + 幂等**：待上链 batch（batch_id、program hash、proof、calldata、tx hash、状态机 pending→submitted→accepted/reverted）先落库再发交易（zkSync/Arbitrum/zkEVM 全这么做）。重启后按链上状态对账续发——注意 Starknet 上要处理交易被丢弃后重新 estimate fee 的问题。现有的 `prove_log.rs` 是雏形，建议升级成正式的状态表。
3. **交易管理层不要裸写**：至少实现 zkSync 式「nonce 从链上推断 + 每轮只推进第一笔保序」、RBF 式加价重发、失败熔断（zkSync 哲学：宁可停机人工介入，不跳过证明或乱序上链——对资金结算尤其正确）。
4. **密钥分级**：operator 热钱包（只发 `register/settle`）与 owner（钉扎 program hash、升级合约）分开；合约侧把 operator 地址白名单化并支持轮换（StarkEx `Operator` 组件 / `isBatchPoster` 模式）。
5. **程序哈希管理沿用 StarkEx 模式**：`program_hash.json` 式的清单文件 + CI 校验 + 一个「对链上合约核对当前 hash」的脚本（等价 `extract_cairo_hash.py`），与业务配置分离；升级 hash 走 timelock 或两步切换（先 set 新 hash 到 pending，再激活）。
6. **成本与节奏**：定 cadence（按批大小或时间窗触发，等价 `max_channel_duration`）；Starknet L1 是 fee 机制而非 blob，但「积压反向节流」（op-batcher throttling）和「费率滑窗延迟提交」（Scroll `skipSubmitByFee`）的思路可借。
7. **监控最小集**：pending 批数/最老批年龄、in-flight tx 数、nonce 档位、operator 账户余额（Arbitrum 按 ~3 天成本告警）、链上事件停涨告警、（若做 DAC/委员会审批）审批延迟。
8. **长期（若走向 appchain/settlement 服务化）**：StarkEx 的三层逃生设计（用户强制操作 → 冻结 → Merkle escape 提款）是资金类应用的安全底线模板；L2 验证可对照 Herodotus integrity 的 FactRegistry 模式（fact 注册后其他合约消费），比每笔结算都过 verifier 便宜。

---

## 附：主要出处

- StarkEx：[backend architecture](https://docs.starkware.co/starkex/architecture/starkware-exchange-back-end-architecture.html) · [contract architecture](https://docs.starkware.co/starkex/architecture/starkware-exchange-smart-contracts-architecture.html) · [DA](https://docs.starkware.co/starkex/con_data_availability.html) · [contract management](https://docs.starkware.co/starkex/perpetual/shared/contract-management.html) · [deployments-addresses](https://docs.starkware.co/starkex/deployments-addresses.html) · [starkex-contracts](https://github.com/starkware-libs/starkex-contracts) · [starkex-core](https://github.com/starkware-libs/starkex-core) · [L2Beat starkex-explorer](https://github.com/l2beat/starkex-explorer)
- Starknet/SHARP：[SHARP docs](https://docs.starknet.io/learn/protocol/sharp) · [DA docs](https://docs.starknet.io/learn/protocol/data-availability) · [EIP-4844 帖](https://community.starknet.io/t/data-availability-with-eip4844/113065) · [L2Beat Starknet](https://l2beat.com/layer2s/projects/starknet) · [cairo-lang sharp](https://github.com/starkware-libs/cairo-lang/tree/master/src/starkware/cairo/sharp) · [starkware-libs/sequencer](https://github.com/starkware-libs/sequencer) · [HerodotusDev/integrity](https://github.com/HerodotusDev/integrity) · [Meet the Cairo Verifier](https://www.starknet.io/blog/meet-the-cairo-verifier/) · [Atlantic](https://starkware.co/blog/atlantic-brings-sharp-to-devs/)
- OP Stack：[op-batcher](https://github.com/ethereum-optimism/optimism/tree/develop/op-batcher) · [batcher 配置指南](https://docs.optimism.io/chain-operators/guides/configuration/batcher) · [batcher spec](https://specs.optimism.io/protocol/batcher.html) · [derivation spec](https://specs.optimism.io/protocol/derivation.html) · [op-service/txmgr](https://github.com/ethereum-optimism/optimism/tree/develop/op-service/txmgr) · [throttling](https://github.com/ethereum-optimism/optimism/blob/develop/op-batcher/throttling.md)
- Arbitrum：[batchposter deep-dive](https://docs.arbitrum.io/how-arbitrum-works/deep-dives/batchposter) · [batch_poster.go](https://github.com/OffchainLabs/nitro/blob/master/arbnode/batch_poster.go) · [dataposter](https://github.com/OffchainLabs/nitro/tree/master/arbnode/dataposter) · [fee tuning](https://docs.arbitrum.io/launch-arbitrum-chain/chain-config/batch-poster/fee-tuning) · [HA sequencer](https://docs.arbitrum.io/launch-arbitrum-chain/run-a-node/high-availability-sequencer) · [SequencerInbox.sol](https://github.com/OffchainLabs/nitro-contracts/blob/main/src/bridge/SequencerInbox.sol)
- zkSync：[architecture](https://github.com/matter-labs/zksync-era/blob/main/docs/src/guides/architecture.md) · [core/node](https://github.com/matter-labs/zksync-era/tree/main/core/node) · [eth_sender](https://github.com/matter-labs/zksync-era/tree/main/core/node/eth_sender) · [pubdata post 4844](https://docs.zksync.io/zksync-protocol/era-vm/contracts/pubdata-post-4844)
- Polygon zkEVM：[zkevm-node](https://github.com/0xPolygon/zkevm-node) · [sequencesender](https://github.com/0xPolygon/zkevm-node/tree/develop/sequencesender) · [ethtxmanager](https://github.com/0xPolygon/zkevm-node/blob/develop/ethtxmanager/ethtxmanager.go)
- Linea：[coordinator](https://docs.linea.build/protocol/architecture/coordinator) · [conflation](https://docs.linea.build/protocol/architecture/coordinator/conflation)
- Scroll：[rollup](https://github.com/scroll-tech/scroll/tree/develop/rollup) · [l2_relayer.go](https://github.com/scroll-tech/scroll/blob/develop/rollup/internal/controller/relayer/l2_relayer.go) · [rollup node docs](https://docs.scroll.io/en/technology/sequencer/rollup-node/)
