#!/usr/bin/env bash
# 主网增量升级批次（2026-09-19 定稿；对应 Sepolia 已验证的同款流程）。
#
# 背景：主网在网 vault（9-07 类 0x7c74ca1a…）/anonymizer（9-07 类 0x525646bd…）
# 均早于 P1-2（2026-09-10，vault.set_session_tx_pk 会话委托）——客户端买入
# multicall 携带该入口，主网买入会像 Sepolia 一样撞 ENTRYPOINT_NOT_FOUND。
# dual v6（SNIP-36 门修正 + emit_settlement_proof_message）也待上主网。
#
# 本批部署/接线（不动的：legacy settlement 0x6f2e01a6 与 payout anonymizer
# 0x7c11073c —— 主网类与当前源码一致；旧 vault/anonymizer/dual v5 原地保留）：
#   declare：PokerVault(0x6de64f9a…) / PokerVaultAnonymizer(0x6dbb1f82…) /
#            PokerDualSettlement(0x255cafe3…，v6) / PokerTableRegistry(0x7cc910b5…)
#   deploy： vault(owner, canonical STRK, settlement=0 占位)
#            anonymizer(owner, vault, 主网池 0x040337b1…)
#            dual v6(owner, vault, prover)  ← 无 set_vault，必须随 vault 重部署
#            registry(owner, close_grace_secs=604800)
#   接线：   vault.set_settlement_contract / set_unshield_helper /
#            set_authorized_helper；dual.set_claim_helper /
#            set_circuit_program_hash / set_hand_verify_program_hash /
#            set_virtual_snos_program_hash（占位值——真实 proved 交易前须以
#            主网实测 proof_facts 修正，G2 门；此前 DAPV 入口保持 v2，
#            行为与 v5 等价）
#
# 前置：
#   - cargo build -p texas --bin snops --release（或 SNOPS= 指定）
#   - scarb 2.19.4 产物已构建（poker_contracts/target/dev/*.json）
#   - 主网 deployer 已部署、余额 ≥150 STRK（估算 ≈97.5 + 波动缓冲；
#     2026-09-19 实测余额 64.81 → 需先充值）
#
# 用法：
#   CONFIRM_MAINNET=yes ./scripts/deploy_mainnet_v6.sh
# 可覆盖：URL OWNER_ENV POOL PROGRAM_HASH HAND_VERIFY_PROGRAM_HASH
#         VIRTUAL_SNOS_PROGRAM_HASH REGISTRY_GRACE SNOPS
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SNOPS="${SNOPS:-$ROOT/target/release/snops}"
[ -x "$SNOPS" ] || SNOPS="$ROOT/target/debug/snops"
URL="${URL:-https://starknet-rpc.publicnode.com}"
ART="$ROOT/poker_contracts/target/dev"
ENV_FILE="${OWNER_ENV:-${ENV_FILE:-$ROOT/.env.mainnet}}"
[ -f "$ENV_FILE" ] || { echo "缺少 $ENV_FILE（需 ADDRESS/PRIVATE_KEY）" >&2; exit 1; }

STRK="0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"  # canonical STRK（主网=sepolia 同址）
POOL="${POOL:-0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a}"  # STRK20 privacy pool mainnet
PROGRAM_HASH="${PROGRAM_HASH:-0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4}"  # #18 Phase C slice-2 电路
HAND_VERIFY_PROGRAM_HASH="${HAND_VERIFY_PROGRAM_HASH:-0x303029d8ce0ec1d0295e4037fc7f87a1ada0c27423cc99bcd080d25b1c6829f}"
# 虚拟 SNOS program hash：0.14.3 回归样本占位（G2 门——首个真实 proved 交易前
# 须以主网实测 proof_facts 修正：snops dump-proof-facts 对拍）
VIRTUAL_SNOS_PROGRAM_HASH="${VIRTUAL_SNOS_PROGRAM_HASH:-0x602b02cff498684fae3d66016137978fdad45a5036878a57257689d4f3f6ccb}"
REGISTRY_GRACE="${REGISTRY_GRACE:-604800}"  # 7 天（生产口径）
# 主网在网 payout anonymizer（SettlementPayoutAnonymizer，类与当前源码一致，
# 本批不重部署；dual.set_claim_helper 继续绑它）
PAYOUT="${PAYOUT:-0x402372930ea52cccbafa459169b3dae3d67051ed741e9af7da669a0f1fbb308}"

if [ "${CONFIRM_MAINNET:-}" != "yes" ]; then
  echo "ERROR: 主网部署需要显式确认：CONFIRM_MAINNET=yes $0" >&2
  exit 1
fi
# shellcheck disable=SC1091
. "$ENV_FILE"
PK="${PRIVATE_KEY:?PRIVATE_KEY missing in $ENV_FILE}"
OWNER="${ADDRESS:?ADDRESS missing in $ENV_FILE}"
SN="$SNOPS --url $URL --pk $PK --addr $OWNER"

# ---- 交易辅助（nonce 竞态重试，随 deploy_mainnet.sh 验证过的实现）----
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
BAL_HEX=$($SNOPS --url "$URL" call --contract "$STRK" --fn balance_of --calldata "$OWNER" 2>/dev/null | head -1 | grep -oE '0x[0-9a-f]+' | head -1 || echo 0x0)
BAL=$($SNOPS --url "$URL" call --contract "$STRK" --fn balance_of --calldata "$OWNER" 2>/dev/null | head -1 | grep -oE '0x[0-9a-f]+' | head -1)
BAL_N=$(python3 -c "print(round(int('${BAL:-0}',16)/1e18,2))" 2>/dev/null || echo "?")
echo "   STRK balance ≈ ${BAL_N} (hex $BAL_HEX) —— 需 ≥150（估算 ≈97.5 + 缓冲）"
if command -v python3 >/dev/null 2>&1; then
  if python3 -c "import sys; sys.exit(0 if int('${BAL:-0}',16)/1e18 >= 150 else 1)"; then :; else
    echo "ERROR: 余额不足 150 STRK，请先充值后再运行。" >&2
    exit 1
  fi
fi

echo "== [1/6] declare 4 classes（vault / anonymizer / dual v6 / registry）"
CLS_VAULT=$(do_declare PokerVault)             || exit 1; echo "vault class     = $CLS_VAULT"
CLS_ANON=$(do_declare PokerVaultAnonymizer)    || exit 1; echo "anonymizer class= $CLS_ANON"
CLS_DUAL=$(do_declare PokerDualSettlement)     || exit 1; echo "dual v6 class   = $CLS_DUAL"
CLS_REG=$(do_declare PokerTableRegistry)       || exit 1; echo "registry class  = $CLS_REG"

echo "== [2/6] deploy PokerVault(owner, canonical STRK, settlement=0 占位)"
VAULT=$(do_deploy vault "$CLS_VAULT" "$OWNER,$STRK,0x0") || exit 1; echo "VAULT=$VAULT"

echo "== [3/6] deploy anonymizer + dual v6（绑新 vault）+ registry"
ANON=$(do_deploy anonymizer "$CLS_ANON" "$OWNER,$VAULT,$POOL") || exit 1; echo "ANONYMIZER=$ANON"
DUAL=$(do_deploy dual "$CLS_DUAL" "$OWNER,$VAULT,$OWNER") || exit 1; echo "DUAL=$DUAL"
REG=$(do_deploy registry "$CLS_REG" "$OWNER,$REGISTRY_GRACE") || exit 1; echo "REGISTRY=$REG"

echo "== [4/6] vault 接线：settlement=dual、unshield/authorized=anonymizer"
submit_wait vault.set_settlement_contract $SN invoke --contract "$VAULT" --fn set_settlement_contract --calldata "$DUAL" >/dev/null
submit_wait vault.set_unshield_helper     $SN invoke --contract "$VAULT" --fn set_unshield_helper     --calldata "$ANON" >/dev/null
submit_wait vault.set_authorized_helper   $SN invoke --contract "$VAULT" --fn set_authorized_helper   --calldata "$ANON" >/dev/null

echo "== [5/6] dual 接线：claim_helper + 两个 program hash + 虚拟 OS（占位，G2 门）"
submit_wait dual.set_claim_helper              $SN invoke --contract "$DUAL" --fn set_claim_helper              --calldata "$PAYOUT" >/dev/null
submit_wait dual.set_circuit_program_hash    $SN invoke --contract "$DUAL" --fn set_circuit_program_hash    --calldata "$PROGRAM_HASH" >/dev/null
submit_wait dual.set_hand_verify_program_hash $SN invoke --contract "$DUAL" --fn set_hand_verify_program_hash --calldata "$HAND_VERIFY_PROGRAM_HASH" >/dev/null
submit_wait dual.set_virtual_snos_program_hash $SN invoke --contract "$DUAL" --fn set_virtual_snos_program_hash --calldata "$VIRTUAL_SNOS_PROGRAM_HASH" >/dev/null

echo "== [6/6] 链上回读验证"
echo "vault.token                  = $($SNOPS --url "$URL" call --contract "$VAULT" --fn token 2>/dev/null | head -1)"
echo "vault.unshield_helper        = $($SNOPS --url "$URL" call --contract "$VAULT" --fn unshield_helper 2>/dev/null | head -1)"
echo "vault.session_tx_pk(owner)   = $($SNOPS --url "$URL" call --contract "$VAULT" --fn session_tx_pk --calldata "$OWNER" 2>/dev/null | head -1)  ← 入口必须存在（P1-2）"
echo "dual.vault                   = $($SNOPS --url "$URL" call --contract "$DUAL" --fn vault 2>/dev/null | head -1)"
echo "dual.claim_helper            = $($SNOPS --url "$URL" call --contract "$DUAL" --fn claim_helper 2>/dev/null | head -1)"
echo "dual.circuit_program_hash    = $($SNOPS --url "$URL" call --contract "$DUAL" --fn circuit_program_hash 2>/dev/null | head -1)"
echo "dual.virtual_snos            = $($SNOPS --url "$URL" call --contract "$DUAL" --fn virtual_snos_program_hash 2>/dev/null | head -1)"
echo "registry.table_count         = $($SNOPS --url "$URL" call --contract "$REG" --fn table_count 2>/dev/null | head -1)"

cat <<EOF

部署完成。回填（必做）：
  strk20.json / DEPLOYMENTS.md（地址 + class hash + TX）
  texas/.env：STARKNET_RPC_URL=$URL STARKNET_CHAIN_ID=SN_MAIN
              STARKNET_STRK_ADDRESS=$STRK STARKNET_VAULT_ADDRESS=$VAULT
              STARKNET_SETTLEMENT_ADDRESS=<legacy 0x2bf6a09c… 不变>
              STARKNET_DUAL_SETTLEMENT_ADDRESS=$DUAL
              STARKNET_CLAIM_HELPER_ADDRESS=<payout 0x40237293… 不变>
              STARKNET_TABLE_REGISTRY_ADDRESS=$REG
  client/.env.production：VITE_POKER_VAULT_ADDRESS=$VAULT
              VITE_POKER_VAULT_ANONYMIZER_ADDRESS=$ANON
              （其余 VITE_* 不变）

迁移（主网 vault 存量 9.47 STRK 筹码，2026-09-19 快照）：
  公告玩家在旧 vault 0x3f4ef706… 公开 withdraw 后在新 vault 重新买入；
  旧 vault/旧 anonymizer/旧 dual v5 原地保留服务历史提现与认领。

开放门槛（切换前确认）：
  - STARKNET_DAPV_SETTLE_ENTRY 保持 v2（fact-registry 腿，行为与 v5 等价）；
    切 snip36 前必须过 G2：主网真实 proved 交易实测 proof_facts 修正
    virtual_snos_program_hash（snops dump-proof-facts 对拍）。
  - 私密领取 Ready/Avnu paymaster 156（钱包侧回归，见 DEPLOYMENTS.md
    2026-09-19 章节）不影响本批合约，但影响私密出金 UX。
EOF
printf 'MAINNET_VAULT=%s\nMAINNET_ANONYMIZER=%s\nMAINNET_DUAL_V6=%s\nMAINNET_REGISTRY=%s\n' \
  "$VAULT" "$ANON" "$DUAL" "$REG"
