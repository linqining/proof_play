#!/usr/bin/env bash
# P2-M4：部署 dual settlement v4（含 verify_and_settle_dapv_proved_private
# 双证明入口：hand_verify fact 绑 p_batch 承诺 + stark verify fact 绑公开段）
# 并完成运营配置：set_claim_helper + set_circuit_program_hash +
# set_hand_verify_program_hash。
#
# 前置（与 deploy_sepolia_v3.sh 同源）：
#   - /.env.dev（PRIVATE_KEY/ADDRESS = poker-deployer）
#   - texas/.env（STARKNET_VAULT_ADDRESS / STARKNET_CLAIM_HELPER_ADDRESS）
#   - 本仓 snops（cargo build -p texas --bin snops）
#   - PROGRAM_HASH（settlement_private 电路，#18 Phase C 切片 2）
#   - HAND_VERIFY_PROGRAM_HASH（hand-verify-native form-② composed）
set -euo pipefail
ROOT=/Users/mac/projects/poker_texas_air
SNOPS="$ROOT/target/debug/snops"
URL="${URL:-https://starknet-sepolia-rpc.publicnode.com}"
ART="$ROOT/poker_contracts/target/dev"
HELPER="${HELPER:-$(grep '^STARKNET_CLAIM_HELPER_ADDRESS=' "$ROOT/texas/.env" | cut -d= -f2)}"
VAULT="${VAULT:-$(grep '^STARKNET_VAULT_ADDRESS=' "$ROOT/texas/.env" | cut -d= -f2)}"
PROGRAM_HASH="${PROGRAM_HASH:-0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4}"
HAND_VERIFY_PROGRAM_HASH="${HAND_VERIFY_PROGRAM_HASH:-0x303029d8ce0ec1d0295e4037fc7f87a1ada0c27423cc99bcd080d25b1c6829f}"

# shellcheck disable=SC1091
. "$ROOT/.env.dev"
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
    if [ -n "$tx" ]; then wait_nonce_gt "$n"; echo "$tx"; return 0; fi
    echo "   $label attempt $attempt: $(head -c 200 <<< "$out" | tr '\n' ' ')" >&2
    sleep 5
  done
  echo "   $label FAILED after 5 attempts" >&2
  return 1
}

SN="$SNOPS --url $URL --pk $PK --addr $OWNER"

echo "== [1/5] declare PokerDualSettlement（自动处理 compiled-hash 方案差异）"
CLS=""
for attempt in 1 2 3; do
  n=$(get_nonce)
  out=$($SN declare \
    --class "$ART/poker_contracts_PokerDualSettlement.contract_class.json" \
    --compiled "$ART/poker_contracts_PokerDualSettlement.compiled_contract_class.json" 2>&1 || true)
  tx=$(printf '%s' "$out" | grep -oE 'TX=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
  if [ -n "$tx" ]; then wait_nonce_gt "$n"; CLS="$tx"; break; fi
  actual=$(printf '%s' "$out" | grep -oE 'Actual: 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
  if [ -n "$actual" ]; then
    echo "   compiled-hash scheme mismatch → retry with --compiled-hash $actual" >&2
    n=$(get_nonce)
    out=$($SN declare \
      --class "$ART/poker_contracts_PokerDualSettlement.contract_class.json" \
      --compiled "$ART/poker_contracts_PokerDualSettlement.compiled_contract_class.json" \
      --compiled-hash "$actual" 2>&1 || true)
    tx=$(printf '%s' "$out" | grep -oE 'TX=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    if [ -n "$tx" ]; then wait_nonce_gt "$n"; CLS="$tx"; break; fi
    echo "   retry output: $(head -c 300 <<< "$out" | tr '\n' ' ')" >&2
  else
    echo "   attempt $attempt: $(head -c 300 <<< "$out" | tr '\n' ' ')" >&2
  fi
  sleep 10
done
[ -n "$CLS" ] || { echo "declare FAILED" >&2; exit 1; }
echo "DUAL_CLASS=$CLS"

echo "== [2/5] deploy dual（owner=$OWNER vault=$VAULT prover=$OWNER）"
DUAL=""
for attempt in 1 2 3 4 5; do
  n=$(get_nonce)
  out=$($SN deploy --class-hash "$CLS" --calldata "$OWNER,$VAULT,$OWNER" 2>&1 || true)
  addr=$(printf '%s' "$out" | grep -oE 'CONTRACT_ADDRESS=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
  if [ -n "$addr" ]; then wait_nonce_gt "$n"; DUAL="$addr"; break; fi
  echo "   deploy attempt $attempt: $(head -c 200 <<< "$out" | tr '\n' ' ')" >&2
  sleep 5
done
[ -n "$DUAL" ] || { echo "deploy FAILED" >&2; exit 1; }
echo "DUAL_V4_ADDR=$DUAL"

echo "== [3/5] set_claim_helper($HELPER)"
submit_wait set_claim_helper $SN invoke --contract "$DUAL" --fn set_claim_helper --calldata "$HELPER" >/dev/null

echo "== [4/5] set_circuit_program_hash($PROGRAM_HASH)"
submit_wait set_program_hash $SN invoke --contract "$DUAL" --fn set_circuit_program_hash --calldata "$PROGRAM_HASH" >/dev/null

echo "== [5/5] set_hand_verify_program_hash($HAND_VERIFY_PROGRAM_HASH)"
submit_wait set_hand_verify_hash $SN invoke --contract "$DUAL" --fn set_hand_verify_program_hash --calldata "$HAND_VERIFY_PROGRAM_HASH" >/dev/null

printf "DUAL_V4_CLASS=%s\nDUAL_V4_ADDR=%s\n" "$CLS" "$DUAL"
