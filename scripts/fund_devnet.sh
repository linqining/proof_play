#!/usr/bin/env bash
# 本地开发网钱包充值：给任意地址充 STRK（真实钱包联调用）。
#
# 与 scripts/dev.sh fund 同一条充值通道（新版 devnet 的 devnet_mint
# JSON-RPC，旧版回落 HTTP POST /mint），但可独立运行：devnet 用
# --keep-devnet 留在后台、或手动 starknet-devnet 起的场合，不必拉起
# 整套 dev.sh。充值只需 curl + python3；充值后顺带查一次该地址的
# STRK 余额做确认（有 snops 构建产物才查，没有就跳过）。
#
# 用法：
#   scripts/fund_devnet.sh <地址> [STRK数量]   # 默认 100 STRK，支持小数（如 0.5）
#
# 典型场景：Ready/Argent 真实钱包首连报"余额不足"——钱包的智能账户
# 是反事实地址（部署费从地址自身余额扣），地址只能连上后在钱包 UI
# 里读到，拿到后再来这里充值。
#
# 环境变量：DEVNET_URL / DEVNET_PORT 覆盖 devnet 地址（默认
# http://127.0.0.1:5051，与 scripts/dev.sh 一致）；STARKNET_STRK_ADDRESS
# 覆盖余额查询用的 STRK 合约（默认规范 STRK 地址，与 devnet 预部署一致）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_PORT="${DEVNET_PORT:-5051}"
DEVNET_URL="${DEVNET_URL:-http://127.0.0.1:${DEVNET_PORT}}"

log() { echo "[fund] $*"; }

TARGET="${1:-}"
[[ -n "$TARGET" ]] || { echo "用法: scripts/fund_devnet.sh <地址> [STRK数量]（默认 100，支持小数）"; exit 1; }
AMT_STRK="${2:-100}"
[[ "$TARGET" =~ ^0x[0-9a-fA-F]+$ ]] || { echo "地址格式不对（须 0x 开头的十六进制）: $TARGET"; exit 1; }

# STRK 18 位小数 → FRI 整数。Decimal 全程精确，支持小数金额。
AMT_FRI=$(python3 - "$AMT_STRK" <<'PY'
import sys
from decimal import Decimal, InvalidOperation
try:
    amt = Decimal(sys.argv[1])
except InvalidOperation:
    sys.exit(f"金额不是数字: {sys.argv[1]}")
if amt <= 0:
    sys.exit(f"金额须为正数: {sys.argv[1]}")
print(int(amt * 10**18))
PY
) || exit 1

curl -sf "$DEVNET_URL/is_alive" >/dev/null 2>&1 || {
  echo "devnet 未运行（${DEVNET_URL}）。先跑 scripts/dev.sh（--keep-devnet 可保留 devnet），"
  echo "或单独起一个: starknet-devnet --seed 0 --port ${DEVNET_PORT}"
  exit 1
}

# 新版 devnet：devnet_mint JSON-RPC；旧版：HTTP POST /mint。
mint_strk() {
  curl -sf "$DEVNET_URL" -X POST -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"devnet_mint","params":{"address":"'"$1"'","amount":'"$2"',"unit":"FRI"}}' \
      >/dev/null 2>&1 \
    || curl -sf -X POST "$DEVNET_URL/mint" -H 'Content-Type: application/json' \
      -d '{"address":"'"$1"'","amount":'"$2"'}' >/dev/null 2>&1
}

SNOPS="$ROOT/target/release/snops"
[[ -x "$SNOPS" ]] || SNOPS="$ROOT/target/debug/snops"
STRK_ADDRESS="${STARKNET_STRK_ADDRESS:-0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d}"

if mint_strk "$TARGET" "$AMT_FRI"; then
  log "已向 $TARGET 充值 ${AMT_STRK} STRK"
else
  echo "充值失败（devnet_mint 与 /mint 均不可用）"; exit 1
fi

# 余额确认（best-effort）：snops call 走 starknet_call；u256 余额拆两个
# felt 返回，展示只取低位段足够。snops 未构建或查询失败都不算错。
if [[ -x "$SNOPS" ]]; then
  BAL=$("$SNOPS" --url "$DEVNET_URL" call --contract "$STRK_ADDRESS" \
        --fn balance_of --calldata "$TARGET" 2>/dev/null \
        | head -1 | grep -oE '0x[0-9a-f]+' || true)
  if [[ -n "$BAL" ]]; then
    python3 -c "print(f'[fund] 充值后 STRK 余额: {int(\"$BAL\", 16) / 10**18:,.4f}')"
  else
    log "（余额查询失败，跳过确认；充值请求本身已成功）"
  fi
else
  log "（未找到 snops 产物，跳过余额查询；跑一次 scripts/dev.sh 或 cargo build -p texas --bin snops 后可用）"
fi
