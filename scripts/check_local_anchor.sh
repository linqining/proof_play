#!/usr/bin/env bash
# =============================================================================
# check_local_anchor.sh — 复核 /tmp/monad-local-anchor.json 里的 Monad 测试网
# 上锚交易（本地 appchain 批次根 → L1Inbox.submitBatch）。
#
# 数据源：JSON 至少含 { "tx": "0x…" }；可选 { "block": N, "gasUsed": N,
# "costWei": "N" } ——存在时一并交叉核对回执字段。
#
# 复核通道（双通道，任一失败即非 0 退出）：
#   1. cast receipt（foundry）：status == "1"；
#   2. curl eth_getTransactionReceipt（原生 JSON-RPC）：status == "0x1"。
# 另核对：to == L1Inbox、blockNumber 与 JSON.block 一致（JSON 记录了 block 时）。
#
# 用法：
#   scripts/check_local_anchor.sh [json路径]   # 默认 /tmp/monad-local-anchor.json
# 环境变量：
#   MONAD_TESTNET_RPC_URL（默认 https://testnet-rpc.monad.xyz）
#   MONAD_L1_INBOX（默认 0x60ecddd1359356a43a69de84a1cf235a69a30e71）
# =============================================================================
set -euo pipefail

JSON_PATH="${1:-/tmp/monad-local-anchor.json}"
RPC="${MONAD_TESTNET_RPC_URL:-https://testnet-rpc.monad.xyz}"
INBOX="$(tr -d '[:space:]' <<<"${MONAD_L1_INBOX:-0x60ecddd1359356a43a69de84a1cf235a69a30e71}" | tr 'A-F' 'a-f')"
CAST=/Users/mac/.foundry/bin/cast

[[ -f "$JSON_PATH" ]] || { echo "FAIL: $JSON_PATH 不存在" >&2; exit 1; }
TX="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['tx'])" "$JSON_PATH")"
[[ "$TX" == 0x* ]] || { echo "FAIL: JSON.tx 非法: $TX" >&2; exit 1; }
JSON_BLOCK="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('block',''))" "$JSON_PATH")"

echo "tx    = $TX"
echo "rpc   = $RPC"
echo "inbox = $INBOX"

# ---------- 通道 1：cast receipt（字段为 hex 串 → 统一归一化为 int/小写）----------
RECEIPT="$("$CAST" receipt "$TX" --rpc-url "$RPC" --json)"
read -r CAST_STATUS CAST_TO CAST_BLOCK CAST_GAS CAST_EFF < <(python3 -c "
import json,sys
r=json.load(sys.stdin)
def n(v):
    v=str(v)
    return str(int(v,16)) if v.startswith('0x') else v
print(n(r.get('status','')), (r.get('to') or '').lower(), n(r.get('blockNumber','')), n(r.get('gasUsed','')), n(r.get('effectiveGasPrice','')))" <<<"$RECEIPT")
echo "cast  : status=$CAST_STATUS block=$CAST_BLOCK gasUsed=$CAST_GAS to=$CAST_TO eff=$CAST_EFF"
[[ "$CAST_STATUS" == "1" ]] || { echo "FAIL: cast status != 1（交易未成功）" >&2; exit 1; }
[[ "$CAST_TO" == "$INBOX" ]] || { echo "FAIL: 回执 to=$CAST_TO != L1Inbox $INBOX" >&2; exit 1; }

# ---------- 通道 2：curl 原生 JSON-RPC ----------
CURL_JSON="$(curl -sf -X POST "$RPC" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX\"]}")"
CURL_STATUS="$(python3 -c "
import json,sys
d=json.loads(sys.stdin.read())
r=d.get('result') or {}
print(r.get('status',''))" <<<"$CURL_JSON")"
echo "curl  : status=$CURL_STATUS"
[[ "$CURL_STATUS" == "0x1" ]] || { echo "FAIL: RPC status != 0x1" >&2; exit 1; }

# ---------- 交叉核对 JSON 记录 vs 链上回执（两侧 hex/十进制归一化）----------
if [[ -n "$JSON_BLOCK" ]]; then
  python3 -c "
import sys
def n(v):
    v=str(v).strip()
    return str(int(v,16)) if v.startswith('0x') else v
a,b=n('$JSON_BLOCK'),n('$CAST_BLOCK')
sys.exit(0 if a==b else 1)" \
    || { echo "FAIL: JSON.block=$JSON_BLOCK != 回执 blockNumber=$CAST_BLOCK" >&2; exit 1; }
fi

# costWei 一致性：gasUsed × effectiveGasPrice == costWei（记录了才核对；JSON 侧同样归一化）
python3 - "$JSON_PATH" "$CAST_GAS" "$CAST_EFF" <<'PYEOF'
import json, sys
def n(v):
    v=str(v).strip()
    return int(v,16) if v.startswith('0x') else int(v)
rec = json.load(open(sys.argv[1]))
gas_used = n(sys.argv[2])
eff = n(sys.argv[3]) if sys.argv[3] else None
if rec.get("costWei") is not None and eff:
    cost = n(rec["costWei"])
    expect = gas_used * eff
    if cost != expect:
        print(f"FAIL: costWei={cost} != gasUsed({gas_used})×effGasPrice({eff})={expect}")
        sys.exit(1)
    print(f"costWei 一致: {gas_used} × {eff} = {cost}")
PYEOF

echo "OK: 上锚交易复核通过（status=0x1，to=L1Inbox，字段一致）"
