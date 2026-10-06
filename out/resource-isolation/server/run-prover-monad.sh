#!/usr/bin/env bash
# run-prover-monad.sh —— texas-prover-monad.service 的 ExecStart 包装（stark）
# 职责：前置检查 + 产物目录就位 + exec proving-tool；绝不触碰 texas.service。
# 纪律：prover 未部署二进制前，本包装 fail-fast（exit 127），杜绝误启动裸跑占资源。
set -euo pipefail

WORK="${PROVER_WORK_DIR:-/opt/zchain-monad/chain-data/prover-work}"
BIN="${PROVER_BIN:-/opt/zchain-monad/bin/proving-tool}"

# 产物目录位于隔离回环镜像内（写满只伤镜像）
mkdir -p "$WORK"

if [ ! -x "$BIN" ]; then
  echo "FATAL: prover 二进制 $BIN 不存在。" >&2
  echo "部署方式：在本机构建 proving-tool，scp 到 $BIN 并 chmod +x，" >&2
  echo "随后按 MIGRATION.md 核对启动参数后：systemctl start texas-prover-monad.service" >&2
  exit 127
fi

# 具体启动参数在二进制部署时按 proving-tool CLI 核对后补充；
# 当前默认透传额外参数，工作目录经环境变量注入。
exec "$BIN" "$@"
