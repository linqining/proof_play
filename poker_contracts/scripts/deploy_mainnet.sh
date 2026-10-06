#!/usr/bin/env bash
# Starknet mainnet full deployment (5 contracts; see strk20.json /
# DEPLOYMENTS.md mainnet sections).
#
# Contracts in use (after the 2026-09-07 cleanup; excludes the retired
# PokerToken/PokerSwap/CashoutUnshieldHelper):
#   PokerVault / PokerSettlement(legacy fallback) / PokerDualSettlement(v5,snip36)
#   PokerVaultAnonymizer(v4) / SettlementPayoutAnonymizer
#
# Prerequisites:
#   - snops built: cargo build -p texas --bin snops (this repo's target/debug/snops)
#   - contract artifacts built with scarb 2.19.4 (poker_contracts/target/dev/*.json)
#   - deploy account: a mainnet OZ account, deployed, STRK balance >= 130
#     (measured estimate 115 + buffer)
#   - .env.mainnet (or .env.dev) provides ADDRESS/PRIVATE_KEY = mainnet deployer/owner
#
# Usage:
#   CONFIRM_MAINNET=yes ./scripts/deploy_mainnet.sh
# Overridable: URL=… OWNER_ENV=.env.mainnet POOL=… PROGRAM_HASH=… HAND_VERIFY_PROGRAM_HASH=…
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SNOPS="${SNOPS:-$ROOT/target/debug/snops}"
URL="${URL:-https://starknet-rpc.publicnode.com}"
ART="$ROOT/poker_contracts/target/dev"
ENV_FILE="${ENV_FILE:-$ROOT/.env.mainnet}"
[ -f "$ENV_FILE" ] || ENV_FILE="$ROOT/.env.dev"

# Mainnet constants (verified 2026-09-07)
STRK="0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"  # canonical STRK (mainnet=sepolia)
POOL="${POOL:-0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a}"  # STRK20 privacy pool mainnet
PROGRAM_HASH="${PROGRAM_HASH:-0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4}"  # #18 Phase C slice-2 circuit
HAND_VERIFY_PROGRAM_HASH="${HAND_VERIFY_PROGRAM_HASH:-0x303029d8ce0ec1d0295e4037fc7f87a1ada0c27423cc99bcd080d25b1c6829f}"

if [ "${CONFIRM_MAINNET:-}" != "yes" ]; then
  echo "ERROR: 主网部署需要显式确认：CONFIRM_MAINNET=yes $0" >&2
  exit 1
fi

# shellcheck disable=SC1091
. "$ENV_FILE"
PK="${PRIVATE_KEY:?PRIVATE_KEY missing in $ENV_FILE}"
OWNER="${ADDRESS:?ADDRESS missing in $ENV_FILE}"
SN="$SNOPS --url $URL --pk $PK --addr $OWNER"

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
# declare (handles the node's compiled-hash scheme mismatch automatically,
# same as deploy_sepolia_v4.sh)
do_declare() {
  local name=$1 cls attempt out tx n actual
  for attempt in 1 2 3; do
    n=$(get_nonce)
    out=$($SN declare \
      --class "$ART/poker_contracts_$name.contract_class.json" \
      --compiled "$ART/poker_contracts_$name.compiled_contract_class.json" 2>&1 || true)
    tx=$(printf '%s' "$out" | grep -oE 'TX=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    if [ -n "$tx" ]; then wait_nonce_gt "$n"; cls=$(printf '%s' "$out" | grep -oE 'CLASS_HASH=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1); echo "$cls"; return 0; fi
    actual=$(printf '%s' "$out" | grep -oE 'Expected: 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    if [ -n "$actual" ]; then
      echo "   $name: compiled-hash scheme mismatch → retry --compiled-hash $actual" >&2
      n=$(get_nonce)
      out=$($SN declare \
        --class "$ART/poker_contracts_$name.contract_class.json" \
        --compiled "$ART/poker_contracts_$name.compiled_contract_class.json" \
        --compiled-hash "$actual" 2>&1 || true)
      tx=$(printf '%s' "$out" | grep -oE 'TX=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
      if [ -n "$tx" ]; then wait_nonce_gt "$n"; cls=$(printf '%s' "$out" | grep -oE 'CLASS_HASH=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1); echo "$cls"; return 0; fi
      echo "   retry output: $(head -c 300 <<< "$out" | tr '\n' ' ')" >&2
    else
      echo "   $name attempt $attempt: $(head -c 300 <<< "$out" | tr '\n' ' ')" >&2
    fi
    sleep 10
  done
  return 1
}
do_deploy() {
  local label=$1 cls=$2 cd=$3 addr attempt out n
  for attempt in 1 2 3 4 5; do
    n=$(get_nonce)
    out=$($SN deploy --class-hash "$cls" --calldata "$cd" 2>&1 || true)
    addr=$(printf '%s' "$out" | grep -oE 'CONTRACT_ADDRESS=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    if [ -n "$addr" ]; then wait_nonce_gt "$n"; echo "$addr"; return 0; fi
    echo "   $label deploy attempt $attempt: $(head -c 200 <<< "$out" | tr '\n' ' ')" >&2
    sleep 5
  done
  return 1
}

echo "== mainnet deployer: $OWNER (rpc: $URL)"
BAL=$($SNOPS --url "$URL" call --contract "$STRK" --fn balance_of --calldata "$OWNER" 2>/dev/null | head -1 | grep -oE '0x[0-9a-f]+' || echo 0x0)
echo "   STRK balance(low word) = ${BAL} (need >=130 for est.115 + buffer)"

echo "== [1/7] declare 5 classes"
CLS_VAULT=$(do_declare PokerVault)         || exit 1; echo "vault class   = $CLS_VAULT"
CLS_SETTLE=$(do_declare PokerSettlement)   || exit 1; echo "settle class  = $CLS_SETTLE"
CLS_DUAL=$(do_declare PokerDualSettlement) || exit 1; echo "dual class    = $CLS_DUAL"
CLS_ANON=$(do_declare PokerVaultAnonymizer)         || exit 1; echo "anonymizer class = $CLS_ANON"
CLS_PAYOUT=$(do_declare SettlementPayoutAnonymizer) || exit 1; echo "payout class  = $CLS_PAYOUT"

echo "== [2/7] deploy PokerVault(owner, STRK, settlement=0 占位)"
VAULT=$(do_deploy vault "$CLS_VAULT" "$OWNER,$STRK,0x0") || exit 1; echo "VAULT=$VAULT"

echo "== [3/7] deploy PokerSettlement + PokerDualSettlement (prover=${OWNER})"
SETTLE=$(do_deploy settlement "$CLS_SETTLE" "$OWNER,$VAULT,$OWNER") || exit 1; echo "SETTLEMENT=$SETTLE"
DUAL=$(do_deploy dual "$CLS_DUAL" "$OWNER,$VAULT,$OWNER") || exit 1; echo "DUAL=$DUAL"

echo "== [4/7] deploy anonymizers (pool=${POOL})"
ANON=$(do_deploy anonymizer "$CLS_ANON" "$OWNER,$VAULT,$POOL") || exit 1; echo "ANONYMIZER=$ANON"
PAYOUT=$(do_deploy payout "$CLS_PAYOUT" "$VAULT,$POOL,$DUAL") || exit 1; echo "PAYOUT_ANONYMIZER=$PAYOUT"

echo "== [5/7] vault 接线：settlement=dual、unshield_helper=anonymizer"
submit_wait set_settlement_contract $SN invoke --contract "$VAULT" --fn set_settlement_contract --calldata "$DUAL" >/dev/null
submit_wait set_unshield_helper    $SN invoke --contract "$VAULT" --fn set_unshield_helper --calldata "$ANON" >/dev/null

echo "== [6/7] dual 接线：claim_helper + 两个 program hash"
submit_wait set_claim_helper $SN invoke --contract "$DUAL" --fn set_claim_helper --calldata "$PAYOUT" >/dev/null
submit_wait set_circuit_program_hash $SN invoke --contract "$DUAL" --fn set_circuit_program_hash --calldata "$PROGRAM_HASH" >/dev/null
submit_wait set_hand_verify_program_hash $SN invoke --contract "$DUAL" --fn set_hand_verify_program_hash --calldata "$HAND_VERIFY_PROGRAM_HASH" >/dev/null

echo "== [7/7] 链上回读验证"
echo "vault.token            = $($SNOPS --url "$URL" call --contract "$VAULT" --fn token 2>/dev/null | head -1)"
echo "vault.unshield_helper  = $($SNOPS --url "$URL" call --contract "$VAULT" --fn unshield_helper 2>/dev/null | head -1)"
echo "dual.claim_helper      = $($SNOPS --url "$URL" call --contract "$DUAL" --fn claim_helper 2>/dev/null | head -1)"
echo "dual.circuit_program_hash = $($SNOPS --url "$URL" call --contract "$DUAL" --fn circuit_program_hash 2>/dev/null | head -1)"

cat <<EOF

部署完成。回填（必做）：
  strk20.json / DEPLOYMENTS.md（地址 + class hash）
  texas/.env：STARKNET_RPC_URL=<主网RPC> STARKNET_CHAIN_ID=SN_MAIN
              STARKNET_STRK_ADDRESS=$STRK STARKNET_VAULT_ADDRESS=$VAULT
              STARKNET_SETTLEMENT_ADDRESS=$SETTLE STARKNET_DUAL_SETTLEMENT_ADDRESS=$DUAL
              STARKNET_CLAIM_HELPER_ADDRESS=$PAYOUT
  client/.env.production：VITE_STARKNET_CHAIN_ID=0x534e5f4d41494e
              VITE_STRK_TOKEN_ADDRESS=$STRK VITE_POKER_VAULT_ADDRESS=$VAULT
              VITE_POKER_SETTLEMENT_ADDRESS=$SETTLE
              VITE_POKER_VAULT_ANONYMIZER_ADDRESS=$ANON
              VITE_STRK20_POOL_ADDRESS=$POOL
EOF
printf 'MAINNET_VAULT=%s\nMAINNET_SETTLEMENT=%s\nMAINNET_DUAL=%s\nMAINNET_ANONYMIZER=%s\nMAINNET_PAYOUT=%s\n' \
  "$VAULT" "$SETTLE" "$DUAL" "$ANON" "$PAYOUT"
