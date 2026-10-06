#!/usr/bin/env bash
# 注入钱包 bot 连打 N 局链上结算游戏 + 逐笔回执对账（回归/压测用）。
#
# 流程：前置检查（devnet / 服务器 / snops / vault 快照）→ 钱包准备（首次
# 自动创建两个钱包并真实入金，凭据落 WALLET_ENV，gitignored）→ 驱动循环
# （devnet 看门狗 + 空座自动重注入 POST /api/dev/bot）→ 对账（每笔
# "dual atomic settle ok" 的回执必须 SUCCEEDED）。
#
# 用法：
#   scripts/play_hands.sh [局数]      # 默认 100；从脚本启动时刻起新打 N 局
#   scripts/play_hands.sh --fresh 50  # 忽略已存钱包，重新创建后跑 50 局
#
# 环境变量：
#   DEVNET_URL / DEVNET_PORT   devnet 地址（默认 http://127.0.0.1:5051，同 dev.sh）
#   PORT                       游戏服务器端口（默认 9001，同 dev.sh）
#   WALLET_ENV                 钱包凭据文件（默认 $ROOT/.env.play，已被 /.env* 忽略）
#   STARKNET_STRK_ADDRESS      STRK 合约（默认规范地址）
#
# 依赖：scripts/dev.sh 已拉起完整环境（--no-client 即可）；snops 构建产物。
# 退出码：0 成功；1 stall/对账失败；2 devnet/前置检查失败。
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_PORT="${DEVNET_PORT:-5051}"
DEVNET_URL="${DEVNET_URL:-http://127.0.0.1:${DEVNET_PORT}}"
API="${API:-http://127.0.0.1:${PORT:-9001}}"
WALLET_ENV="${WALLET_ENV:-$ROOT/.env.play}"

log() { echo "[play] $*"; }
die() { echo "[play] $*" >&2; exit 1; }

# ---- 参数 ----
TARGET=""
FRESH=0
for arg in "$@"; do
  case "$arg" in
    --fresh) FRESH=1 ;;
    *[!0-9]*) die "参数须为局数（数字）或 --fresh: $arg" ;;
    "") ;;
    *) TARGET="$arg" ;;
  esac
done
TARGET="${TARGET:-100}"
OUT_DIR="${PLAY_OUT_DIR:-/tmp/play_hands}"
mkdir -p "$OUT_DIR"

SNOPS="$ROOT/target/release/snops"
[[ -x "$SNOPS" ]] || SNOPS="$ROOT/target/debug/snops"
STRK_ADDRESS="${STARKNET_STRK_ADDRESS:-0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d}"

# ---- 前置检查 ----
curl -sf "$DEVNET_URL/is_alive" >/dev/null 2>&1 || {
  die "devnet 未运行（${DEVNET_URL}）。先跑 scripts/dev.sh（--no-client --keep-devnet 可保留）"
}
curl -sf "$API/" >/dev/null 2>&1 || {
  die "游戏服务器未运行（${API}）。先跑 scripts/dev.sh"
}
[[ -x "$SNOPS" ]] || die "未找到 snops（target/{debug,release}/snops），先: cargo build -p texas --bin snops"
[[ -f "$ROOT/texas/.env.dev.local" ]] || die "缺少 $ROOT/texas/.env.dev.local（先完整跑一次 scripts/dev.sh 部署合约）"
VAULT=$(grep -E '^STARKNET_VAULT_ADDRESS=' "$ROOT/texas/.env.dev.local" | cut -d= -f2- | tr -d '[:space:]')
[[ -n "$VAULT" ]] || die "环境快照里没有 STARKNET_VAULT_ADDRESS"

# funder（发现 11 修复，2026-10-02）：已部署的 .env.dev 账户代充
# `deposit_for(bot)`——bot 钱包不再需要自部署/自 approve/自 deposit
# （devnet 重建后陈旧 WALLET_ENV 的「未部署地址」断腿整类消除）。
ENV_DEV="${ENV_DEV:-$ROOT/.env.dev}"
[[ -f "$ENV_DEV" ]] || die "缺少 $ENV_DEV（funder 账户；先完整跑一次 scripts/dev.sh）"
FUNDER_ADDR=$(grep -E '^ADDRESS=' "$ENV_DEV" | head -1 | cut -d= -f2- | tr -d '[:space:]')
FUNDER_PK=$(grep -E '^PRIVATE_KEY=' "$ENV_DEV" | head -1 | cut -d= -f2- | tr -d '[:space:]')
[[ -n "$FUNDER_ADDR" && -n "$FUNDER_PK" ]] || die "$ENV_DEV 缺 ADDRESS/PRIVATE_KEY（funder）"

# ---- 钱包准备：复用已存凭据，或创建两个钱包并由 funder 代充入金 ----
# （发现 11 修复：代充走已部署 funder 的 `vault.deposit_for(bot)`，bot 钱包
# 无需自部署——空 depositTxHash 注入 /api/dev/bot 时 verify_deposit 退化为
# 纯 chip_balance 校验（私密买入同语义），代充入账即为权威证明。）
prepare_wallets() {
  local amt_wei=90000000000000000000   # 90 STRK/钱包（100 减部署费后仍够）
  mkdir -p "$(dirname "$WALLET_ENV")"
  : > "$WALLET_ENV"
  # funder approve STRK→vault（代充前置；幂等，重试 3）。
  local tx i
  for i in 1 2 3; do
    tx=$("$SNOPS" --url "$DEVNET_URL" --pk "$FUNDER_PK" --addr "$FUNDER_ADDR" invoke \
      --contract "$STRK_ADDRESS" --fn approve --calldata "$VAULT,$((amt_wei * 4)),0" 2>&1 | sed -n 's/^TX=//p')
    [[ -n "$tx" ]] && break
    sleep 3
  done
  [[ -n "$tx" ]] || die "funder approve 失败（funder 余额见 dev.sh 的 OWNER 充值）"
  for W in A B; do
    log "创建钱包 ${W}（deploy_wallet.sh new）…"
    local out addr pk
    out=$("$ROOT/scripts/deploy_wallet.sh" new) || die "钱包 $W 创建失败"
    addr=$(sed -n 's/^ADDRESS=//p' <<<"$out")
    pk=$(sed -n 's/^PRIVATE_KEY=//p' <<<"$out")
    [[ -n "$addr" && -n "$pk" ]] || die "钱包 $W 凭据解析失败"
    echo "${W}_ADDR=$addr" >> "$WALLET_ENV"
    echo "${W}_PK=$pk" >> "$WALLET_ENV"
    # funder 代充：deposit_for(bot)（幂等，重试 3）。
    for i in 1 2 3; do
      tx=$("$SNOPS" --url "$DEVNET_URL" --pk "$FUNDER_PK" --addr "$FUNDER_ADDR" invoke \
        --contract "$VAULT" --fn deposit_for --calldata "$addr,$amt_wei,0" 2>&1 | sed -n 's/^TX=//p')
      [[ -n "$tx" ]] && break
      sleep 3
    done
    [[ -n "$tx" ]] || die "钱包 $W funder 代充失败（funder STRK 余额/approve 见上）"
    echo "${W}_TX=$tx" >> "$WALLET_ENV"
    log "钱包 $W=$addr funder 代充 tx=$tx"
  done
}

if [[ "$FRESH" == 1 || ! -f "$WALLET_ENV" ]]; then
  prepare_wallets
fi
# shellcheck disable=SC1090
source "$WALLET_ENV"
for V in A_ADDR A_PK A_TX B_ADDR B_PK B_TX; do
  [[ -n "${!V:-}" ]] || die "$WALLET_ENV 缺少 ${V}（用 --fresh 重建钱包）"
done

# ---- 驱动循环 ----
LOG=/tmp/texas-server.log
OFF=$(wc -c < "$LOG" | tr -d ' ')

devnet_alive() { curl -sf "$DEVNET_URL/is_alive" >/dev/null 2>&1; }
settled_count() { tail -c +"$((OFF + 1))" "$LOG" | grep -ac "dual atomic settle ok" || true; }
settled_txs() { tail -c +"$((OFF + 1))" "$LOG" | grep -aoE "dual atomic settle ok: tx=0x[0-9a-f]+" | sed 's/.*tx=//'; }

max_seq() {
  curl -s --max-time 5 "$API/api/tables/1/history" | python3 -c '
import json, sys
try: h = json.load(sys.stdin)
except Exception: h = []
print(max((r.get("handSeq", 0) for r in h), default=0))'
}

seated() {
  curl -s --max-time 5 "$API/api/tables/1" | python3 -c '
import json, sys
try: d = json.load(sys.stdin)
except Exception: d = {}
print(",".join((w or "").lower() for w in (d.get("players") or {}).values()))'
}

inject() {
  # 空 depositTxHash = verify_deposit 走纯 chip_balance 校验（funder 代充
  # 语义）；$2 留参兼容旧调用。
  curl -s --max-time 10 -X POST "$API/api/dev/bot" -H 'Content-Type: application/json' \
    -d "{\"wallet\":\"$1\",\"depositTxHash\":\"\",\"seatId\":$3}"
}

BASE_SEQ=$(max_seq)
LAST_SEQ=$BASE_SEQ
LAST_CHANGE=$(date +%s)
log "开始：devnet=$DEVNET_URL api=$API 目标 ${TARGET} 局（起点 handSeq=${BASE_SEQ}）"
while true; do
  # devnet 看门狗：链挂了立即停，避免静默积累无法结算的手。
  devnet_alive || { log "FATAL: devnet 掉线（hands=$((LAST_SEQ - BASE_SEQ)) settled=$(settled_count)）"; exit 2; }

  NOW=$(date +%s)
  SEQ=$(max_seq)
  DONE_H=$((SEQ - BASE_SEQ))
  if (( SEQ > LAST_SEQ )); then
    log "$(date +%T) hands=$DONE_H/$TARGET settled=$(settled_count)"
    LAST_SEQ=$SEQ
    LAST_CHANGE=$NOW
  fi
  if (( DONE_H >= TARGET )); then
    log "完成 $DONE_H 局，链上结算 $(settled_count) 笔 — 对账…"
    settled_txs > "$OUT_DIR/settle_txs.txt"
    break
  fi
  if (( NOW - LAST_CHANGE > 480 )); then
    log "STALLED：8 分钟无新手（hands=$DONE_H settled=$(settled_count)），最近异常："
    tail -c +"$((OFF + 1))" "$LOG" | grep -aE " ERROR |panic|unprovable|sub-BB" | tail -10
    settled_txs > "$OUT_DIR/settle_txs.txt"
    break
  fi
  # 空座重注入（A→座位1，B→座位2）；注入失败多为服务器侧无该钱包余额
  # 记录（devnet 重建后余额清零），此时用 --fresh 重建钱包并由 funder 代充。
  S=$(seated)
  for pair in "A 1" "B 2"; do
    set -- $pair; W=$1; SEAT=$2
    addr_var="${W}_ADDR"; tx_var="${W}_TX"
    addr="${!addr_var}"; tx="${!tx_var}"
    al=$(echo "$addr" | tr 'A-Z' 'a-z')
    if ! echo ",$S," | grep -qi ",$al,"; then
      r=$(inject "$addr" "$tx" "$SEAT")
      echo "$r" | grep -q '"started":true' \
        && log "注入 $W → 座位 $SEAT" \
        || log "注入 $W 失败: ${r}（入金 tx 失效时用 --fresh 重建钱包）"
    fi
  done
  sleep 3
done

# ---- 对账：每笔结算 tx 的链上回执必须 SUCCEEDED ----
TOTAL=0; OKN=0
FAILS="$OUT_DIR/receipt_failures.txt"
: > "$FAILS"
while read -r tx; do
  [[ -n "$tx" ]] || continue
  TOTAL=$((TOTAL + 1))
  st=$(curl -s --max-time 10 "$DEVNET_URL" -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"starknet_getTransactionReceipt","params":{"transaction_hash":"'"$tx"'"}}' \
    | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("UNREACHABLE"); raise SystemExit
r = d.get("result") or {}
print(r.get("execution_status") or r.get("status") or "UNKNOWN")')
  if [[ "$st" == "SUCCEEDED" ]]; then OKN=$((OKN + 1)); else
    echo "$tx $st" >> "$FAILS"
  fi
done < "$OUT_DIR/settle_txs.txt"

log "DONE 本局手数=$DONE_H 结算 tx=$TOTAL 回执成功=$OKN"
if [[ -s "$FAILS" ]]; then
  log "回执失败明细（${FAILS}）："
  head -20 "$FAILS"
  exit 1
fi
(( TOTAL > 0 )) || { log "没有任何链上结算记录"; exit 1; }
exit 0
