#!/usr/bin/env bash
# =============================================================================
# deploy_wrap_monad.sh — 部署单手 STARK→Groth16 包裹合约栈到 Monad 测试网。
#
# 部署件：contracts/monad/src/Groth16Verifier.sol（金向量 VK，gen-sol 生成）
#         contracts/monad/src/SettleWrap.sol（settle → WrapSettled 事件）
#
# 前置：
#   1. 金向量已生成：cargo run -p groth16-wrap --release --bin gen-sol
#      （写入 contracts/monad/src/Groth16Verifier.sol 的 VK 常量）
#   2. 私钥：env MONAD_KEY_FILE（默认 /tmp/monad_e2e_key.txt）
#   3. 余额门槛：写链前查余额，低于 MON_MIN_BALANCE（默认 1 MON）直接退出
#      ——Monad 按 gas_limit×price 计费（非 used），紧 limit 口径见
#      zchain/monad-settlement/src/bin/monad_hand_gas.rs。
#
# gas 纪律：每笔交易先 eth_estimateGas，limit = est×1.1（向上取整），
#           gasPrice 取节点建议价（eth_gasPrice，测试网约 102 gwei）。
#
# 用法：
#   ./scripts/deploy_wrap_monad.sh
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$(pwd)"
ZCHAIN_CONTRACTS="${ZCHAIN_CONTRACTS:-$ROOT/../zchain/contracts/monad}"
RPC="${MONAD_TESTNET_RPC_URL:-https://testnet-rpc.monad.xyz}"
CHAIN_ID=10143
KEY_FILE="${MONAD_KEY_FILE:-/tmp/monad_e2e_key.txt}"
MIN_BALANCE_WEI="${MON_MIN_BALANCE:-1000000000000000000}"   # 1 MON
CAST=/Users/mac/.foundry/bin/cast
SOLC_DIR="$ZCHAIN_CONTRACTS/out/solc"

for tool in "$CAST" python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: missing $tool" >&2; exit 1; }
done
if [[ ! -f "$SOLC_DIR/Groth16Verifier.bin" || ! -f "$SOLC_DIR/SettleWrap.bin" ]]; then
  echo "==> build_solc.sh 产物缺失，先编译…"
  (cd "$ZCHAIN_CONTRACTS" && ./build_solc.sh >/dev/null)
fi
for f in Groth16Verifier SettleWrap; do
  [[ -f "$SOLC_DIR/$f.bin" ]] || { echo "error: $f.bin 缺失" >&2; exit 1; }
done

# ---------- 私钥与余额门槛 ----------
[[ -f "$KEY_FILE" ]] || { echo "error: key file $KEY_FILE 不存在" >&2; exit 1; }
KEY="$(tr -d '[:space:]' < "$KEY_FILE")"
OPERATOR="$("$CAST" wallet address --private-key "$KEY")"
BALANCE="$("$CAST" balance "$OPERATOR" --rpc-url "$RPC")"
echo "operator = $OPERATOR"
echo "balance  = $BALANCE wei"
if (( BALANCE < MIN_BALANCE_WEI )); then
  echo "error: 余额不足（<$MIN_BALANCE_WEI wei）——按环境约定 escalate，不写链" >&2
  exit 3
fi

# ---------- gas 纪律：est×1.1 + 节点建议价 ----------
gas_price() { "$CAST" gas-price --rpc-url "$RPC"; }

# estimate_create <deploy-bin-hex-no0x>  → est×1.1
estimate_create() {
  local est_hex
  est_hex="$("$CAST" rpc eth_estimateGas \
    "{\"from\":\"$OPERATOR\",\"data\":\"0x$1\"}" --rpc-url "$RPC" | tr -d '"')"
  python3 -c "print(int('$est_hex', 16) * 11 // 10 + 1)"
}

# estimate_call <to> <calldata-hex-no0x>  → est×1.1
estimate_call() {
  local est_hex
  est_hex="$("$CAST" rpc eth_estimateGas \
    "{\"from\":\"$OPERATOR\",\"to\":\"$1\",\"data\":\"0x$2\"}" --rpc-url "$RPC" | tr -d '"')"
  python3 -c "print(int('$est_hex', 16) * 11 // 10 + 1)"
}

# ---------- 部署 Groth16Verifier ----------
echo "==> deploy Groth16Verifier"
V_BIN="$(python3 -c "print(open('$SOLC_DIR/Groth16Verifier.bin').read().strip().removeprefix('0x'))")"
V_LIMIT="$(estimate_create "$V_BIN")"
V_PRICE="$(gas_price)"
echo "    gas limit = $V_LIMIT (est×1.1), gasPrice = $V_PRICE"
# cast 1.8.x：--create 后是 trailing var-arg，gas 等选项必须放在 --create 之前
V_HASH="$("$CAST" send --gas-limit "$V_LIMIT" --gas-price "$V_PRICE" --chain-id "$CHAIN_ID" \
  --private-key "$KEY" --rpc-url "$RPC" --create "$V_BIN" --json |
  python3 -c "import json,sys; print(json.load(sys.stdin)['transactionHash'])")"
VERIFIER="$("$CAST" receipt "$V_HASH" --rpc-url "$RPC" --json |
  python3 -c "import json,sys; print(json.load(sys.stdin)['contractAddress'])")"
echo "    Groth16Verifier = $VERIFIER  (tx $V_HASH)"

# ---------- 部署 SettleWrap(verifier) ----------
echo "==> deploy SettleWrap"
S_BIN="$(python3 -c "print(open('$SOLC_DIR/SettleWrap.bin').read().strip().removeprefix('0x'))")"
CTOR="$("$CAST" abi-encode "constructor(address)" "$VERIFIER" | sed 's/^0x//')"
S_LIMIT="$(estimate_create "$S_BIN$CTOR")"
S_PRICE="$(gas_price)"
echo "    gas limit = $S_LIMIT (est×1.1), gasPrice = $S_PRICE"
S_HASH="$("$CAST" send --gas-limit "$S_LIMIT" --gas-price "$S_PRICE" --chain-id "$CHAIN_ID" \
  --private-key "$KEY" --rpc-url "$RPC" --create "$S_BIN$CTOR" --json |
  python3 -c "import json,sys; print(json.load(sys.stdin)['transactionHash'])")"
SETTLE="$("$CAST" receipt "$S_HASH" --rpc-url "$RPC" --json |
  python3 -c "import json,sys; print(json.load(sys.stdin)['contractAddress'])")"
echo "    SettleWrap = $SETTLE  (tx $S_HASH)"

echo ""
echo "=== 部署完成（Monad 测试网 chainId=$CHAIN_ID） ==="
echo "Groth16Verifier = $VERIFIER"
echo "SettleWrap      = $SETTLE"
echo "提示：链上命题仅为 hash 一致性（operator 背书 + 电路一致），NOT STARK 去信任验证；"
echo "      VK 来自固定种子单方仪式，主网必须换 MPC powers-of-tau ceremony。"
