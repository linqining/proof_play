#!/usr/bin/env bash
# 重新部署 PokerVaultAnonymizer（operation 分流版：0=买入 1=领取），
# 并把 vault 的 authorized_helper 指到新 helper。
# 用法：URL=https://starknet-sepolia-rpc.publicnode.com ./scripts/redeploy_anonymizer.sh <VAULT> <POOL>
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# snops = 本仓库 cargo build -p texas --bin snops 的产物，可用 SNOPS= 覆盖
SNOPS="${SNOPS:-$ROOT/target/debug/snops}"
URL="${URL:-https://starknet-sepolia-rpc.publicnode.com}"
ART="$ROOT/poker_contracts/target/dev"
ENV_ROOT="$ROOT"
VAULT="${1:?VAULT address required}"
POOL="${2:?POOL address required}"

# shellcheck disable=SC1091
. "$ENV_ROOT/.env.dev"
PK="${PRIVATE_KEY:?PRIVATE_KEY missing}"
OWNER="${ADDRESS:?ADDRESS missing}"

get_nonce() {
  curl -s -m 15 -X POST "$URL" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"starknet_getNonce\",\"params\":[\"latest\",\"$OWNER\"]}" \
    | grep -oE '"result":"0x[0-9a-f]+"' | grep -oE '0x[0-9a-f]+' || echo 0x0
}
wait_nonce_gt() {
  local used=$1 i cur
  for i in $(seq 1 90); do
    cur=$(get_nonce)
    if [ -n "$cur" ] && (( $cur > $used )); then return 0; fi
    sleep 2
  done
  echo "   (warn) nonce did not advance past $used" >&2
}
submit_wait() {
  local label=$1; shift
  local attempt out tx n
  for attempt in 1 2 3 4 5; do
    n=$(get_nonce)
    out=$("$@" 2>&1 || true)
    tx=$(printf '%s' "$out" | grep -oE 'TX=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    if [ -n "$tx" ]; then
      wait_nonce_gt "$n"
      echo "$tx"
      return 0
    fi
    echo "   $label attempt $attempt: $(head -c 200 <<< "$out" | tr '\n' ' ')" >&2
    # already-declared 场景直接把 CLASS_HASH 透传
    local cls
    cls=$(printf '%s' "$out" | grep -oE 'CLASS_HASH=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    if [ -n "$cls" ]; then echo "$cls"; return 0; fi
    sleep 5
  done
  echo "   $label FAILED after 5 attempts" >&2
  return 1
}

echo "== deployer: $OWNER"

echo "== declare PokerVaultAnonymizer"
CLS=$(submit_wait declare "$SNOPS" --url "$URL" --pk "$PK" --addr "$OWNER" declare \
  --class "$ART/poker_contracts_PokerVaultAnonymizer.contract_class.json" \
  --compiled "$ART/poker_contracts_PokerVaultAnonymizer.compiled_contract_class.json")
echo "ANON_CLASS=$CLS"

echo "== deploy anonymizer (vault=$VAULT pool=$POOL)"
ANON=$(for attempt in 1 2 3 4 5; do
  n=$(get_nonce)
  out=$($SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" deploy --class-hash "$CLS" --calldata "$VAULT,$POOL" 2>&1 || true)
  addr=$(printf '%s' "$out" | grep -oE 'CONTRACT_ADDRESS=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
  if [ -n "$addr" ]; then
    wait_nonce_gt "$n"; echo "$addr"; break
  fi
  existing=$(printf '%s' "$out" | grep -oE 'already deployed at address 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
  if [ -n "$existing" ]; then echo "$existing"; break; fi
  echo "   deploy attempt $attempt: $(head -c 200 <<< "$out" | tr '\n' ' ')" >&2
  sleep 5
done)
[ -n "$ANON" ] || { echo "deploy FAILED" >&2; exit 1; }
echo "ANON_ADDR=$ANON"

echo "== vault.set_authorized_helper($ANON)"
submit_wait vault.set_authorized_helper "$SNOPS" --url "$URL" --pk "$PK" --addr "$OWNER" invoke \
  --contract "$VAULT" --fn set_authorized_helper --calldata "$ANON" >/dev/null
echo "== done"
echo "ANON_CLASS=$CLS"
echo "ANON_ADDR=$ANON"
