#!/usr/bin/env bash
# 一键本地开发环境（dev 模式）。
#
# 流程：starknet-devnet（--seed 0, :5051）→ 账户 = 根目录 .env.dev
# （ADDRESS/PRIVATE_KEY，自动 /mint 充值 + 部署账户）→ 合约构建 + devnet
# 部署 → 生成 texas/.env.dev.local（地址快照）→ 以本地 prover
# （TEXAS_PROVER_MODE=dev）启动 texas 服务器，连接本地开发网提交。
#
# 用法：
#   scripts/dev.sh                  # 完整流程（清理旧实例 + 构建 + 部署 + 服务器 + 前端）
#   scripts/dev.sh --no-client      # 只起 devnet + 服务器（不拉前端）
#   scripts/dev.sh --skip-build     # 跳过 scarb/cargo 构建（复用已有产物）
#   scripts/dev.sh --skip-deploy    # 跳过部署（复用运行中的 devnet 与
#                                   # texas/.env.dev.local 里的地址快照；
#                                   # devnet 重启后地址会变，勿混用）
#   scripts/dev.sh --keep-devnet    # 脚本退出时不关 devnet
#   scripts/dev.sh --skip-wasm      # 跳过 client-wasm 构建（默认仅缺失/源码过期时重建）
#   scripts/dev.sh --site           # 一并构建并预览官网静态站（website/，:8080）
#   scripts/dev.sh fund <地址> [n]   # 给任意地址充值 n 个 STRK（钱包联调用，
#                                   # 需 devnet 已在运行；默认 100 STRK）。
#                                   # 等价的独立脚本: scripts/fund_devnet.sh
#   scripts/dev.sh --debug          # 服务器用 debug 构建（默认 release，
#                                   # 递归证明在 debug 下极慢，仅排查用）
#
# 前端：默认一并拉起 vite（client/），并生成 client/.env.development.local
# （gitignored）：RPC 指向本地 devnet 5051、合约地址快照、浏览器直签账户
# （devnet seed-0 预充值账户 #1）。要插真实钱包联调时删掉该文件即可。
#
# 环境变量：DEVNET_URL / DEVNET_PORT 覆盖 devnet 地址；ENV_DEV 覆盖账户
# 文件位置（默认仓库根目录 .env.dev）；SCARB_HOME 覆盖 scarb 工具链位置
# （默认 ~/.local/opt/toolchains/scarb-2.19.4）。
#
# 真实钱包联调：脚本会把 Argent(Ready) 钱包的智能账户类预声明进 devnet
# （官方 v0.4.0 产物，scripts/assets/argent/）；钱包部署费从反事实账户
# 地址自身余额扣，DEV_EXTRA_FUND（写在 .env.dev）配置的地址每次启动自动
# 充值 10,000 STRK。
# 注意：Ready 插件按 chain id 记账户部署状态，devnet 与 Sepolia 同为
# SN_SEPOLIA——若该账户在真 Sepolia 已部署，插件会跳过部署步骤、直接发
# invoke 而报 "not deployed"。解决：把插件网络也切到本地 devnet（内置
# Devnet 网络固定指向 localhost:5050，可用 DEVNET_PORT=5050 运行本脚本
# 对齐，或在插件里添加自定义网络 http://127.0.0.1:5051）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_URL="${DEVNET_URL:-http://127.0.0.1:5051}"
DEVNET_PORT="${DEVNET_PORT:-5051}"
ENV_DEV="${ENV_DEV:-$ROOT/.env.dev}"
SCARB_HOME="${SCARB_HOME:-$HOME/.local/opt/toolchains/scarb-2.19.4}"
ENV_FILE="$ROOT/texas/.env.dev.local"
PROFILE=release
SKIP_BUILD=0
SKIP_DEPLOY=0
KEEP_DEVNET=0
NO_CLIENT=0
SKIP_WASM=0
SITE=0

# ---------- fund 子命令：给任意地址充值 STRK（真实钱包部署前必做）----------
# 钱包插件的智能账户（Argent/Ready）部署费从反事实账户地址自身余额扣，
# 该地址随 passkey/盐随机生成，只能在连接后从钱包 UI 读到再充值：
#   scripts/dev.sh fund <地址> [STRK数量]（默认 100 STRK）
# 充值逻辑独立成 scripts/fund_devnet.sh（可脱离本脚本单独跑），这里委托；
# 须在参数解析之前处理，避免被下面的开关白名单拒绝。
if [[ "${1:-}" == "fund" ]]; then
  shift
  # DEVNET_URL/DEVNET_PORT 是本脚本的局部变量（未 export），显式传下去。
  DEVNET_URL="$DEVNET_URL" DEVNET_PORT="$DEVNET_PORT" \
    exec "$ROOT/scripts/fund_devnet.sh" "$@"
fi

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=1 ;;
    --skip-deploy) SKIP_DEPLOY=1 ;;
    --keep-devnet) KEEP_DEVNET=1 ;;
    --no-client) NO_CLIENT=1 ;;
    --skip-wasm) SKIP_WASM=1 ;;
    --site) SITE=1 ;;
    --debug) PROFILE=debug ;;
    *) echo "未知参数: $arg"; exit 1 ;;
  esac
done

log() { echo "[dev] $*"; }

# ---------- 0) 停掉旧实例（上次运行的 texas 服务器 / 前端 / devnet）----------
# texas 的 cmdline 可能是绝对路径（手动启动）或相对路径（cargo run 生成），
# 两种都覆盖；`target/*/texas` 名称唯一，误伤面可控。pkill 无匹配时返回
# 非零，`|| true` 防止 set -e 中断。
log "清理旧实例…"
pkill -f "target/release/texas" 2>/dev/null || true
pkill -f "target/debug/texas" 2>/dev/null || true
pkill -f "cargo run -p texas" 2>/dev/null || true
pkill -f "$ROOT/client" 2>/dev/null || true
# --skip-deploy 复用运行中的 devnet（地址快照仍有效）；完整流程则连同
# 旧 devnet 一起停（合约地址随新 devnet 重新部署生成）。
if [[ "$SKIP_DEPLOY" != 1 ]]; then
  pkill -f starknet-devnet 2>/dev/null || true
fi
sleep 1

# ---------- 1) starknet devnet ----------
DEVNET_PID=""
if curl -sf "$DEVNET_URL/is_alive" >/dev/null 2>&1; then
  log "devnet 已在运行: $DEVNET_URL"
else
  command -v starknet-devnet >/dev/null 2>&1 || {
    echo "缺少 starknet-devnet（pip install starknet-devnet）"; exit 1; }
  log "启动 starknet-devnet (seed 0, port $DEVNET_PORT)…"
  starknet-devnet --seed 0 --port "$DEVNET_PORT" >/tmp/starknet-devnet.log 2>&1 &
  DEVNET_PID=$!
  for _ in $(seq 1 60); do
    curl -sf "$DEVNET_URL/is_alive" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -sf "$DEVNET_URL/is_alive" >/dev/null 2>&1 || {
    echo "devnet 启动超时，日志见 /tmp/starknet-devnet.log"; exit 1; }
  log "devnet 已启动 (pid $DEVNET_PID, 日志 /tmp/starknet-devnet.log)"
fi
cleanup() {
  [[ -n "${CLIENT_PID:-}" ]] && kill "$CLIENT_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null
  [[ -n "${SITE_PID:-}" ]] && kill "$SITE_PID" 2>/dev/null
  if [[ -n "$DEVNET_PID" ]] && [[ "$KEEP_DEVNET" != 1 ]]; then
    kill "$DEVNET_PID" 2>/dev/null || true
    log "devnet 已停止（--keep-devnet 可保留）"
  fi
}
trap cleanup EXIT

# ---------- 2) owner/operator 账户：根目录 .env.dev（ADDRESS/PRIVATE_KEY）----------
[[ -f "$ENV_DEV" ]] || { echo "缺少账户文件 ${ENV_DEV}（需要 ADDRESS= / PRIVATE_KEY= 两行）"; exit 1; }
OWNER=$(grep -E '^ADDRESS=' "$ENV_DEV" | head -1 | cut -d= -f2- | tr -d '[:space:]')
OPKEY=$(grep -E '^PRIVATE_KEY=' "$ENV_DEV" | head -1 | cut -d= -f2- | tr -d '[:space:]')
[[ -n "$OWNER" && -n "$OPKEY" ]] || {
  echo "$ENV_DEV 里未找到 ADDRESS / PRIVATE_KEY"; exit 1; }
log "owner/operator = $ENV_DEV 账户: $OWNER"

# ---------- 3) 构建（合约 + snops + 服务器）----------
if [[ "$SKIP_BUILD" != 1 ]]; then
  if [[ -x "$SCARB_HOME/bin/scarb" ]]; then
    export PATH="$SCARB_HOME/bin:$PATH"
  fi
  command -v scarb >/dev/null 2>&1 || { echo "缺少 scarb（${SCARB_HOME}）"; exit 1; }
  log "构建 Cairo 合约（scarb build）…"
  (cd "$ROOT/poker_contracts" && scarb build)
  log "构建 snops + 服务器（cargo build -p texas）…"
  cargo build -p texas --bin snops
  cargo build -p texas --"$PROFILE"
else
  log "跳过构建"
fi
SNOPS="$ROOT/target/debug/snops"
[[ -x "$SNOPS" ]] || SNOPS="$ROOT/target/release/snops"
[[ -x "$SNOPS" ]] || { echo "找不到 snops 产物（target/{debug,release}/snops），请先构建"; exit 1; }

# ---------- 3b) client-wasm（前端 link:../client-wasm/pkg 的构建产物）----------
# pkg/ 已 gitignore：克隆后首次必建；此后仅当 src / Cargo.toml / Cargo.lock 比
# 产物新时才重建（wasm-pack 全量编译不便宜，日常重启不重复付）。
# --skip-wasm 显式跳过；--no-client 时前端不启动，用不到 wasm。
build_wasm() {
  command -v wasm-pack >/dev/null 2>&1 || { echo "缺少 wasm-pack（cargo install wasm-pack）"; exit 1; }
  log "构建 client-wasm（wasm-pack build --target web）…"
  wasm-pack build "$ROOT/client-wasm" --target web >>/tmp/texas-wasm.log 2>&1 || {
    echo "client-wasm 构建失败，日志见 /tmp/texas-wasm.log"
    tail -20 /tmp/texas-wasm.log
    exit 1
  }
}
WASM_STAMP="$ROOT/client-wasm/pkg/client_wasm_bg.wasm"
if [[ "$NO_CLIENT" == 1 ]]; then
  log "--no-client：跳过 client-wasm"
elif [[ "$SKIP_WASM" == 1 ]]; then
  log "跳过 client-wasm 构建（--skip-wasm）"
elif [[ ! -f "$WASM_STAMP" ]]; then
  build_wasm
  log "client-wasm 已构建: $ROOT/client-wasm/pkg"
elif [[ -n "$(find "$ROOT/client-wasm/src" "$ROOT/client-wasm/Cargo.toml" "$ROOT/client-wasm/Cargo.lock" -newer "$WASM_STAMP" -print -quit 2>/dev/null)" ]]; then
  build_wasm
  log "client-wasm 已重建: $ROOT/client-wasm/pkg"
else
  log "client-wasm 产物已是最新，跳过"
fi

# ---------- 4) 账户上链准备 + 部署合约到 devnet ----------
if [[ "$SKIP_DEPLOY" != 1 ]]; then
  # 4a) 充值 STRK（费用代币；重复充值无害）。
  #     新版 devnet：devnet_mint JSON-RPC；旧版：HTTP POST /mint。
  MINT_AMT=10000000000000000000000   # 10,000 STRK（FRI）
  mint_strk() {
    curl -sf "$DEVNET_URL" -X POST -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"devnet_mint","params":{"address":"'"$1"'","amount":'"$2"',"unit":"FRI"}}' \
        >/dev/null 2>&1 \
      || curl -sf -X POST "$DEVNET_URL/mint" -H 'Content-Type: application/json' \
        -d '{"address":"'"$1"'","amount":'"$2"'}' >/dev/null 2>&1
  }
  if mint_strk "$OWNER" "$MINT_AMT"; then
    log "已为 $OWNER 充值 10,000 STRK"
  else
    log "警告: 充值失败（devnet_mint 与 /mint 均不可用；账户可能已有余额，继续）"
  fi
  # 4a-b) 真实钱包联调地址自动充值：devnet 重建即清零，而浏览器 passkey
  #       钱包的反事实地址固定不变——不预充，钱包首连部署账户必报余额
  #       不足。地址写在 ENV_DEV 的 DEV_EXTRA_FUND=（空格/逗号分隔多个）。
  EXTRA_FUND=$(grep -E '^DEV_EXTRA_FUND=' "$ENV_DEV" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '[:space:]' || true)
  for waddr in $(echo "$EXTRA_FUND" | tr ' ,' '  '); do
    [[ -n "$waddr" ]] || continue
    if mint_strk "$waddr" "$MINT_AMT"; then
      log "已为联调钱包 $waddr 充值 10,000 STRK"
    else
      log "警告: 联调钱包 $waddr 充值失败"
    fi
  done
  # 4b) 账户未部署则先 deploy_account（.env.dev 账户是 Sepolia deployer，
  #     在全新 devnet 上不存在；OZ 类 = devnet 内置账户类，无需 declare）。
  #     新旧 devnet 的 block_id 形式不同：先试裸 "latest"，再试对象形式。
  CLASS_AT=$(curl -sf "$DEVNET_URL" -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"starknet_getClassHashAt","params":["latest","'"$OWNER"'"]}' 2>/dev/null) \
    || CLASS_AT=$(curl -sf "$DEVNET_URL" -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"starknet_getClassHashAt","params":[{"block_tag":"latest"},"'"$OWNER"'"]}' 2>/dev/null) \
    || CLASS_AT=""
  if echo "$CLASS_AT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
h = d.get("result") if isinstance(d, dict) else None
sys.exit(0 if h not in (None, "", "0x0", "0x00") else 1)
' 2>/dev/null; then
    log "账户已在 devnet 部署，跳过 deploy-acct"
  else
    log "部署 .env.dev 账户（snops deploy-acct，OZ salt 0）…"
    "$SNOPS" --url "$DEVNET_URL" --pk "$OPKEY" deploy-acct >>/tmp/devnet-deploy.log 2>&1 || {
      echo "账户部署失败，日志见 /tmp/devnet-deploy.log（若 class hash 未在 devnet 声明，请检查 devnet 版本）"
      tail -5 /tmp/devnet-deploy.log
      exit 1
    }
  fi
  # 4c) 预声明 Argent(Ready) 钱包账户类：钱包插件的智能账户类只声明在
  #     公链上（katana 会内置、starknet-devnet 不会），缺了它钱包首连
  #     部署账户直接报 "Class ... is not declared"。产物是 Argent 官方
  #     仓库 v0.4.0 的类（sierra hash 与线上/class 一致）；casm hash 若
  #     因编译器版本差异不匹配，snops declare 会从报错里提取期望值重试。
  ARGENT_CLASS=0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f
  ARGENT_CASM_HASH=0x7a663375245780bd307f56fde688e33e5c260ab02b76741a57711c5b60d47f6
  ARGENT_SIERRA="$ROOT/scripts/assets/argent/ArgentAccount.contract_class.json"
  ARGENT_CASM="$ROOT/scripts/assets/argent/ArgentAccount.compiled_contract_class.json"
  ARGENT_AT=$(curl -sf "$DEVNET_URL" -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"starknet_getClass","params":["latest","'"$ARGENT_CLASS"'"]}' 2>/dev/null) \
    || ARGENT_AT=$(curl -sf "$DEVNET_URL" -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"starknet_getClass","params":[{"block_tag":"latest"},"'"$ARGENT_CLASS"'"]}' 2>/dev/null) \
    || ARGENT_AT=""
  if echo "$ARGENT_AT" | grep -q '"sierra_program"'; then
    log "Argent 钱包账户类已在 devnet 声明，跳过"
  else
    [[ -f "$ARGENT_SIERRA" && -f "$ARGENT_CASM" ]] || {
      echo "缺少 Argent 类产物（${ARGENT_SIERRA}）"; exit 1; }
    log "预声明 Argent 钱包账户类（${ARGENT_CLASS}）…"
    "$SNOPS" --url "$DEVNET_URL" --pk "$OPKEY" --addr "$OWNER" declare \
      --class "$ARGENT_SIERRA" --compiled "$ARGENT_CASM" \
      --compiled-hash "$ARGENT_CASM_HASH" >>/tmp/devnet-deploy.log 2>&1 || {
      echo "Argent 类声明失败，日志见 /tmp/devnet-deploy.log"
      tail -10 /tmp/devnet-deploy.log
      exit 1
    }
    log "Argent 钱包账户类已声明（真实钱包可连接）"
  fi
  # 4d) 合约部署（vault 绑定规范 STRK，现代接线）。
  log "部署合约到 devnet（poker_contracts/scripts/local_deploy.sh）…"
  OWNER="$OWNER" OPKEY="$OPKEY" URL="$DEVNET_URL" \
    "$ROOT/poker_contracts/scripts/local_deploy.sh" >/tmp/devnet-deploy.log 2>&1 || {
    echo "部署失败，日志见 /tmp/devnet-deploy.log"; tail -20 /tmp/devnet-deploy.log; exit 1; }
  # shellcheck disable=SC1091
  source /tmp/starknet_e2e_env
  log "部署完成: VAULT=$STARKNET_VAULT_ADDRESS DUAL=$STARKNET_DUAL_SETTLEMENT_ADDRESS"
else
  if [[ -f "$ENV_FILE" ]]; then
    log "跳过部署，复用 $ENV_FILE 的地址快照"
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    STARKNET_RPC_URL="$DEVNET_URL"
  else
    echo "--skip-deploy 但 $ENV_FILE 不存在，请先完整运行一次"; exit 1
  fi
fi

# ---------- 5) 生成服务器环境（本地 prover + 本地开发网提交）----------
STRK="${STARKNET_STRK_ADDRESS:-0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d}"
DUAL="${STARKNET_DUAL_SETTLEMENT_ADDRESS:-}"
SETTLE="${STARKNET_SETTLEMENT_ADDRESS:-}"
VAULT="${STARKNET_VAULT_ADDRESS:-}"
REGISTRY="${STARKNET_TABLE_REGISTRY_ADDRESS:-}"
cat > "$ENV_FILE" <<EOF
# 由 scripts/dev.sh 生成（本地 devnet 部署快照）——devnet 重建后地址会变。
# dev 模式：TEXAS_ENV=dev → TEXAS_PROVER_MODE 缺省即本地 prover；
# 这里显式写出便于对照。proved 实验入口见文件尾部注释。
PORT=${PORT:-9001}
JWT_SECRET=devnet-secret-for-local-e2e
TEXAS_ENV=dev
TEXAS_PROVER_MODE=dev
TEXAS_DEV_BOT_ENABLED=1
RUST_LOG=info
STARKNET_RPC_URL=$DEVNET_URL
STARKNET_CHAIN_ID=SN_SEPOLIA
STARKNET_STRK_ADDRESS=$STRK
STARKNET_VAULT_ADDRESS=$VAULT
STARKNET_SETTLEMENT_ADDRESS=$SETTLE
STARKNET_DUAL_SETTLEMENT_ADDRESS=$DUAL
STARKNET_TABLE_REGISTRY_ADDRESS=$REGISTRY
STARKNET_OPERATOR_ADDRESS=$OWNER
STARKNET_OPERATOR_PRIVATE_KEY=$OPKEY
STARKNET_AUTH_STRICT=false
# snip36 = 每手结束后进程内本地递归出证（hand_verify_native），失败自动
# 回退 dual 线性结算；结算提交走 register_hand + verify_and_settle_dapv_stark。
STARKNET_SETTLEMENT_MODE=${STARKNET_SETTLEMENT_MODE:-snip36}
STARKNET_DAPV_SETTLE_ENTRY=v2
STARKNET_TREASURY_ADDRESS=$OWNER
STARKNET_RAKE_BPS=500
STARKNET_RAKE_CAP=1000
BETTING_TIMEOUT_SECS=90
BOT_LOOP_SECS=0
# ---- proved 模式实验（本地 prover 闭环）----
# 取消注释后：批次 attestation 进程内 host ρ-fold 校验（LocalBatchProver），
# settlement 电路 fact 由 operator 直登（register_settlement_fact），
# 无需外部 prover 服务。注意 v2 私密结算入口还需要 dual.claim_helper
# 与赢家 payout commitment 接线（见 DEPLOYMENTS.md）——裸 devnet 缺这些
# 时 proved 段构建失败，结算自动回退 linear（行为与线上回退语义一致）。
# STARKNET_SETTLE_MODE=proved
EOF
log "服务器环境已生成: $ENV_FILE"

# ---------- 5b) 前端环境（client/.env.development.local，gitignored）----------
CLIENT_ENV="$ROOT/client/.env.development.local"
if [[ "$NO_CLIENT" != 1 ]]; then
  # 不注入任何直签/测试账户：身份一律来自真实连接的钱包（P1-2 身份绑定以
  # 买入同笔 vault.set_session_tx_pk 登记为准）。历史注入方案（VITE_DEV_
  # ACCOUNT* / ?dev=N）已移除；devAccount.ts 模块保留但无 env 即不激活。
  cat > "$CLIENT_ENV" <<EOF
# 由 scripts/dev.sh 生成——本地 devnet 联调配置（覆盖 client/.env.development）。
# 不注入任何测试账户：身份一律来自真实连接的钱包。
VITE_STARKNET_RPC_URL=$DEVNET_URL
VITE_STARKNET_RPC_URLS=$DEVNET_URL
VITE_STARKNET_CHAIN_ID=0x534e5f5345504f4c4941
VITE_STRK_TOKEN_ADDRESS=$STRK
VITE_POKER_VAULT_ADDRESS=$VAULT
VITE_POKER_SETTLEMENT_ADDRESS=$SETTLE
VITE_SERVER_PORT=${PORT:-9001}
# pSTRK/swap/私密池已退役：本地 devnet 不部署 anonymizer，走公开买入路径
VITE_POKER_VAULT_ANONYMIZER_ADDRESS=
VITE_STRK20_POOL_ADDRESS=
EOF
  log "前端环境已生成: ${CLIENT_ENV}（无注入账户，使用真实钱包）"
fi

# ---------- 6) 启动（服务器 + 前端；Ctrl-C 一并停 devnet）----------
PORT="${PORT:-9001}"
# 端口兜底：步骤 0 之后仍占用目标端口的，视为漏网旧实例，直接停掉；
# 停不掉（权限等）再报错让用户处理。
if lsof -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  log "端口 $PORT 仍被占用，停止占用进程…"
  kill $(lsof -tiTCP:"$PORT" -sTCP:LISTEN) 2>/dev/null || true
  sleep 1
fi
if lsof -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "端口 $PORT 仍被占用且无法停止。手动处理后重试，或用 PORT=<其他端口> 运行。"
  exit 1
fi
log "启动 texas 服务器（${PROFILE}，连接 ${DEVNET_URL}，端口 ${PORT}）…"
cd "$ROOT"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

if [[ "$NO_CLIENT" != 1 ]]; then
  if [[ ! -d "$ROOT/client/node_modules" ]]; then
    log "安装前端依赖（pnpm install）…"
    (cd "$ROOT/client" && pnpm install)
  fi
  log "启动前端（vite，代理 → http://127.0.0.1:${PORT}）…"
  (
    cd "$ROOT/client" &&
    GAME_SERVER_URL="http://127.0.0.1:${PORT}" exec ./node_modules/.bin/vite
  ) >>/tmp/texas-client.log 2>&1 &
  CLIENT_PID=$!
fi

cargo run -p texas --bin texas --"$PROFILE" >>/tmp/texas-server.log 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 180); do
  curl -sf "http://127.0.0.1:${PORT}/" >/dev/null 2>&1 && break
  kill -0 "$SERVER_PID" 2>/dev/null || {
    echo "服务器启动失败，日志见 /tmp/texas-server.log"
    tail -20 /tmp/texas-server.log
    exit 1
  }
  sleep 1
done
curl -sf "http://127.0.0.1:${PORT}/" >/dev/null 2>&1 || {
  echo "服务器启动超时（180s），日志见 /tmp/texas-server.log"
  exit 1
}
log "游戏服务器就绪: http://127.0.0.1:${PORT}（日志 /tmp/texas-server.log）"
if [[ -n "${CLIENT_PID:-}" ]]; then
  log "前端就绪: http://localhost:5173（端口占用时 vite 自动顺延，日志 /tmp/texas-client.log）"
fi

# ---------- 6b) 官网静态站（--site）：构建 + 静态预览，失败不影响游戏联调 ----------
if [[ "$SITE" == 1 ]]; then
  SITE_PORT="${SITE_PORT:-8080}"
  log "构建官网（python3 website/build.py）…"
  if python3 "$ROOT/website/build.py" >>/tmp/texas-site.log 2>&1; then
    ( cd "$ROOT/website/dist" && exec python3 -m http.server "$SITE_PORT" ) >>/tmp/texas-site.log 2>&1 &
    SITE_PID=$!
    log "官网预览: http://127.0.0.1:${SITE_PORT}（日志 /tmp/texas-site.log）"
  else
    log "警告: 官网构建失败（不影响游戏联调），日志 /tmp/texas-site.log"
  fi
fi
log "全部已启动；Ctrl-C 一次性停止（前端 + 服务器 + devnet）"
log "提示: 真实钱包（Ready/Argent）首连报余额不足时，先充值反事实地址: scripts/dev.sh fund <钱包地址> 100"
wait
