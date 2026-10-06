#!/usr/bin/env bash
# devnet 本地部署（现代接线，与主网/Sepolia 在用合约一致：筹码直接锚定
# 原生 STRK，pSTRK/PokerSwap 已退役）。产出 /tmp/starknet_e2e_env 供
# 服务器/客户端消费；scripts/dev.sh 一键流程也走本脚本。
#
# 用法：OWNER=<地址> OPKEY=<私钥> [URL=<rpc>] [STRK=<STRK 地址>] ./local_deploy.sh
#   STRK 缺省用规范 STRK 地址（devnet 的费用代币同址）。
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
URL="${URL:-http://127.0.0.1:5051}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# snops = 本仓库 cargo build -p texas --bin snops 的产物，可用 SNOPS= 覆盖
SNOPS="${SNOPS:-$ROOT/target/debug/snops}"
OWNER="${OWNER:?Set OWNER}"
OPKEY="${OPKEY:?Set OPKEY}"
# pSTRK 已下线，筹码锚定原生 STRK（主网/Sepolia/devnet 费用代币同址）
STRK="${STRK:-0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d}"
ART="$ROOT/poker_contracts/target/dev"
TX_OF() { echo "$1" | python3 "$ROOT/poker_contracts/scripts/parse_out.py" tx; }
ADDR_OF() { echo "$1" | python3 "$ROOT/poker_contracts/scripts/parse_out.py" addr; }
CLASS_OF() { echo "$1" | python3 "$ROOT/poker_contracts/scripts/parse_out.py" class; }

declare_one() {
  local name=$1
  local class="$ART/poker_contracts_${name}.contract_class.json"
  local compiled="$ART/poker_contracts_${name}.compiled_contract_class.json"
  local out
  out=$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" declare --class "$class" --compiled "$compiled" 2>&1) || {
    # 已声明过则从错误中提取 class hash
    echo "$out" | python3 "$ROOT/poker_contracts/scripts/parse_out.py" already
    return 0
  }
  CLASS_OF "$out"
}

# invoke（带重试）：瞬时 RPC/estimate 抖动直接 fail 会留下半接线环境，
# 且 `>/dev/null` 会把错误吞掉——失败重试 3 次，间隔 3s，仍败则打印错误。
invoke_retry() {
  local contract=$1 fn=$2 calldata=$3 attempt out
  for attempt in 1 2 3; do
    if out=$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" invoke \
        --contract "$contract" --fn "$fn" --calldata "$calldata" 2>&1); then
      return 0
    fi
    echo "invoke $fn (attempt $attempt/3) failed: $out" >&2
    sleep 3
  done
  echo "invoke $fn failed after 3 attempts — aborting" >&2
  return 1
}

V_CLASS=$(declare_one PokerVault)
D_OUT=$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" deploy --class-hash "$V_CLASS" --calldata "$OWNER,$STRK,0" 2>&1)
VAULT=$(ADDR_OF "$D_OUT")
echo "VAULT=$VAULT"

S_CLASS=$(declare_one PokerSettlement)
D_OUT=$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" deploy --class-hash "$S_CLASS" --calldata "$OWNER,$VAULT,$OWNER" 2>&1)
SETTLEMENT=$(ADDR_OF "$D_OUT")
echo "SETTLEMENT=$SETTLEMENT"

DS_CLASS=$(declare_one PokerDualSettlement)
D_OUT=$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" deploy --class-hash "$DS_CLASS" --calldata "$OWNER,$VAULT,$OWNER" 2>&1)
DUAL=$(ADDR_OF "$D_OUT")
echo "DUAL=$DUAL"

# 桌台注册表（"关桌后不开新手"的链上锚点）：owner 兜底 + 闲置关桌宽限
# 期（秒，REGISTRY_GRACE 可覆盖；devnet 默认 1 小时便于联调关桌路径）。
R_CLASS=$(declare_one PokerTableRegistry)
D_OUT=$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" deploy --class-hash "$R_CLASS" --calldata "$OWNER,${REGISTRY_GRACE:-3600}" 2>&1)
REGISTRY=$(ADDR_OF "$D_OUT")
echo "REGISTRY=$REGISTRY"

# DAPV 为默认结算路径：vault 的 settlement 绑定指向 PokerDualSettlement
#（legacy 回退时由 server 自动重绑）。
invoke_retry "$VAULT" set_settlement_contract "$DUAL"
# owner 流动性：devnet 预充值账户自带 STRK（费用代币），approve + 买入 100 chips。
invoke_retry "$STRK" approve "$VAULT,100000000000000000000000,0"
DEPOSIT=$(TX_OF "$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" invoke --contract "$VAULT" --fn deposit --calldata 100000000000000000000,0 2>&1)")
echo "DEPOSIT_TX=$DEPOSIT"

cat > /tmp/starknet_e2e_env << EOF
STARKNET_RPC_URL=$URL
STARKNET_STRK_ADDRESS=$STRK
STARKNET_VAULT_ADDRESS=$VAULT
STARKNET_SETTLEMENT_ADDRESS=$SETTLEMENT
STARKNET_DUAL_SETTLEMENT_ADDRESS=$DUAL
STARKNET_TABLE_REGISTRY_ADDRESS=$REGISTRY
STARKNET_SETTLEMENT_MODE=auto
STARKNET_OPERATOR_ADDRESS=$OWNER
STARKNET_OPERATOR_PRIVATE_KEY=$OPKEY
DEPOSIT_TX=$DEPOSIT
EOF
echo "--- env written ---"
cat /tmp/starknet_e2e_env
