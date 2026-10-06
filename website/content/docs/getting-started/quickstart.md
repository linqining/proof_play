---
title: 15 分钟 quickstart
lang: zh-CN
section: getting-started
description: 克隆、构建、起 3 节点 devnet、完成一手带真实证明的牌局并验证。
lead: 目标：在干净环境 15 分钟内启动 devnet，并用真实 stwo 证明完成与验证一手 PLAY 牌局。
---

## 0. 前置（约 3 分钟）

```console
# Rust（rustup 会按 rust-toolchain.toml 自动装 nightly-2026-04-15）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustc --version          # 应显示 nightly-2026-04-15
git --version
```

## 1. 克隆与构建（约 4 分钟）

```console
git clone <公开仓库地址，上线前固定> zchain && cd zchain
cargo build --release --bin zchain
```

构建产物：`target/release/zchain`。首次构建需编译 stwo，耗时取决于机器。

## 2. 启动 3 节点 devnet（约 3 分钟）

```console
# 起 3 个 validator，全互联 TCP P2P，验证出块与高度收敛
scripts/multi_node_e2e.sh 3
```

预期输出（节选）：

```text
=== multi-node e2e: N=3 validators, workdir /tmp/zchain_multi_e2e_XXXXXX ===
[node-1] commit_round=1 height=1
[node-2] commit_round=1 height=1
[node-3] commit_round=1 height=1
=== OK: 3/3 validators committed, heights converged (skew=0) ===
```

脚本验收标准：全部 N 个节点出块（日志含 `commit_round=`），RPC 高度收敛（允许 ±1 在途偏差）。4 节点容错可跑 `scripts/scenario_kill_one_of_four.sh`（quorum(4)=3）；重启追块可跑 `scripts/scenario_restart_catchup.sh`。

说明：`multi_node_e2e.sh` 默认使用 `./target/debug/zchain`，可用 `ZCHAIN_BIN=./target/release/zchain scripts/multi_node_e2e.sh 3` 指定 release 二进制。

## 3. 完成一手（带真实证明，约 4 分钟）

当前 devnet 的完整一手（盲注 → 下注 → 结算 → 出证）由 E2E 测试与单桌压测程序承载：

```console
# 单桌演示：批量跑桌与结算（64 桌 × 50 手的入口同款）
cargo run -p poker-appchain --release --bin loadtest

# 完整一手 E2E：3 人 REAL 桌，单 canonical batch 真实 stwo 出证
cargo test -p poker-appchain-texasair --release -- e2e_full_hand --nocapture
```

预期输出（节选）：

```text
[loadtest] 64 tables x 50 hands ... 3200 settlements / 16064 ops OK
[loadtest] buy-in soft confirm p50=2.1ms p99=3.5ms (budget 100ms)

[e2e_full_hand] 3 players, hand_start mirror injected
[e2e_full_hand] deal -> raise -> all-in -> fold -> call -> settle
[e2e_full_hand] conservation: sum(inputs) == sum(payouts) + rake == gross_pot  OK
[e2e_full_hand] stwo proof: verified (canonical tagged batch)  OK
```

<code>wallet-core</code> CLI（并行工作提供）上线后，本步骤替换为面向玩家的逐操作命令：创建 PLAY note → buy-in → 下注 → 读取 SettlementPlan → 本地验证。当前先以上述测试命令演示同等链路，CLI 命令以 <code> poker-wallet</code> crate 发布为准（证明验证命令见<a href="/proofs/">官网证明页</a>）。

## 4. 验证（约 1 分钟）

```console
# 证明验证路径（适配器 crate 自带负例回归）
cargo test -p poker-appchain-texasair --release
# 钱包侧 CLI（wallet-core 提供后可用）
cargo run -p poker-wallet --release -- verify proof.json
```

验证器信息：canonical tagged AIR，stwo 2.3，verifier 版本占位 `texas-air-v2`。

## 下一步

- 概念：<a href="/docs/concepts/">Note、nullifier、最终性</a>
- 协议：<a href="/docs/protocol/abi/">ABI 规范</a>
- 证明：<a href="/docs/proofs/">Texas AIR 与公开输入</a>

示例全程只使用 PLAY 或测试密钥，不得默认使用 REAL 或真实外部地址。
