#!/usr/bin/env bash
# =============================================================================
# deploy_wrap_batch_monad.sh — 部署批量包裹合约栈到 Monad 测试网（E2E 批量腿）。
#
# 部署件：contracts/monad/src/Groth16VerifierBatch.sol（K4 批量 VK，gen-sol-batch
#         生成；同形状电路共享 VK——2×K4 两证明同钥连验）
#         contracts/monad/src/SettleBatch.sol（settleBatch → BatchSettled 事件
#         + settledFact 逐手登记 + keccak 批根一次性）
#
# 前置：
#   1. build_solc.sh 产物在盘（Groth16VerifierBatch.bin / SettleBatch.bin）；
#      注意 gen-sol-batch 会重写 Groth16VerifierBatch.sol——部署前必须重编。
#   2. 私钥：env MONAD_KEY_FILE（默认 /tmp/monad_e2e_key.txt）
#   3. 余额门槛：MON_MIN_BALANCE（默认 1 MON）。
#
# gas 纪律：每笔先 eth_estimateGas，limit = est×1.1（向上取整），
#           gasPrice 取节点建议价——Monad 按 gas_limit×price 计费。
#
# 用法：scripts/deploy_wrap_batch_monad.sh
# 输出：末尾两行 `Groth16VerifierBatch = 0x…` / `SettleBatch = 0x…`
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$(pwd)"
ZCHAIN_CONTRACTS="${ZCHAIN_CONTRACTS:-$ROOT/../zchain/contracts/monad}"
RPC="${MONAD_TESTNET_RPC_URL:-https://testnet-rpc.monad.xyz}"
CHAIN_ID=10143
KEY_FILE="${MONAD_KEY_FILE:-/tmp/monad_e2e_key.txt}"
MIN_BALANCE_WEI="${MON_MIN_BALANCE:-1000000000000000000}"
BATCH_N="${BATCH_N:-4}"
MAX_STATEMENTS="${MAX_STATEMENTS:-8}"
CAST=/Users/mac/.foundry/bin/cast
SOLC_DIR="$ZCHAIN_CONTRACTS/out/solc"

for tool in "$CAST" python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: missing $tool" >&2; exit 1; }
done
for f in Groth16VerifierBatch SettleBatch; do
  [[ -f "$SOLC_DIR/$f.bin" ]] || { echo "error: $f.bin 缺失（先 ./build_solc.sh）" >&2; exit 1; }
done

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

gas_price() { "$CAST" gas-price --rpc-url "$RPC"; }
estimate_create() {
  local est_hex
  est_hex="$("$CAST" rpc eth_estimateGas \
    "{\"from\":\"$OPERATOR\",\"data\":\"0x$1\"}" --rpc-url "$RPC" | tr -d '"')"
  python3 -c "print(int('$est_hex', 16) * 11 // 10 + 1)"
}

echo "==> deploy Groth16VerifierBatch"
V_BIN="$(python3 -c "print(open('$SOLC_DIR/Groth16VerifierBatch.bin').read().strip().removeprefix('0x'))")"
V_LIMIT="$(estimate_create "$V_BIN")"
V_PRICE="$(gas_price)"
echo "    gas limit = $V_LIMIT (est×1.1), gasPrice = $V_PRICE"
V_HASH="$("$CAST" send --gas-limit "$V_LIMIT" --gas-price "$V_PRICE" --chain-id "$CHAIN_ID" \
  --private-key "$KEY" --rpc-url "$RPC" --create "$V_BIN" --json |
  python3 -c "import json,sys; print(json.load(sys.stdin)['transactionHash'])")"
VERIFIER="$("$CAST" receipt "$V_HASH" --rpc-url "$RPC" --json |
  python3 -c "import json,sys; print(json.load(sys.stdin)['contractAddress'])")"
echo "    Groth16VerifierBatch = $VERIFIER  (tx $V_HASH)"

echo "==> deploy SettleBatch(verifier, batchN=$BATCH_N, maxStatements=$MAX_STATEMENTS)"
S_BIN="$(python3 -c "print(open('$SOLC_DIR/SettleBatch.bin').read().strip().removeprefix('0x'))")"
CTOR="$("$CAST" abi-encode "constructor(address,uint256,uint256)" "$VERIFIER" "$BATCH_N" "$MAX_STATEMENTS" | sed 's/^0x//')"
S_LIMIT="$(estimate_create "$S_BIN$CTOR")"
S_PRICE="$(gas_price)"
echo "    gas limit = $S_LIMIT (est×1.1), gasPrice = $S_PRICE"
S_HASH="$("$CAST" send --gas-limit "$S_LIMIT" --gas-price "$S_PRICE" --chain-id "$CHAIN_ID" \
  --private-key "$KEY" --rpc-url "$RPC" --create "$S_BIN$CTOR" --json |
  python3 -c "import json,sys; print(json.load(sys.stdin)['transactionHash'])")"
SETTLEBATCH="$("$CAST" receipt "$S_HASH" --rpc-url "$RPC" --json |
  python3 -c "import json,sys; print(json.load(sys.stdin)['contractAddress'])")"
echo "    SettleBatch = $SETTLEBATCH  (tx $S_HASH)"

echo ""
echo "=== batch deploy done (Monad testnet chainId=$CHAIN_ID) ==="
echo "Groth16VerifierBatch = $VERIFIER"
echo "SettleBatch          = $SETTLEBATCH"
echo "note: on-chain claim is hash-consistency (operator endorsement + circuit match), NOT trustless STARK verification;"
echo "      VK from fixed-seed one-party ceremony; mainnet must replace with MPC powers-of-tau ceremony."
