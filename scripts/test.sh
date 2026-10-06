#!/usr/bin/env bash
# 一键测试环境：texas 服务器 + 前端（client/）一并拉起，按所选链自动切换
# 服务器与前端配置。
#
# 用法：
#   scripts/test.sh                      # 默认 sepolia（服务器 + 前端）
#   scripts/test.sh sepolia              # Starknet Sepolia 测试网（在网合约，
#                                        #   地址见 poker_contracts/DEPLOYMENTS.md；
#                                        #   服务器环境 = texas/.env.test）
#   scripts/test.sh zchain               # 自研 zchain：嵌入式 appchain 结算出口
#                                        #   （STARKNET_SETTLEMENT_EXIT=appchain）+
#                                        #   ZChain 钱包扩展（window.zchain）身份/
#                                        #   买入；不连 Starknet RPC，零外部依赖
#   scripts/test.sh sepolia --no-client  # 只起服务器
#   scripts/test.sh --debug              # debug 构建（证明极慢，仅排查用）
#   scripts/test.sh --no-build           # 跳过 cargo build（复用已有产物）
#
# 可选环境变量：
#   PORT=<端口>            服务器端口（默认 9001，前后端代理同步）
#   ENV_FILE=<env 文件>    sepolia 模式的服务器环境来源（默认 texas/.env.test）
#   ZCHAIN_ENV_FILE=<文件> zchain 模式的自定义服务器环境（如 4 节点部署的
#                          texas/.env.dev4z——其 STARKNET_* 地址所需的基础
#                          设施须自行保证在运行）；默认嵌入式 appchain
#
# 前端：自动生成 client/.env.development.local（gitignored，devnet/deploy
# 残留会被覆盖）——RPC 节点与合约地址随链切换：
#   sepolia = VITE_STARKNET_RPC_URLS 指向公共 Sepolia 节点 + 在网合约地址；
#   zchain  = 显式清空全部 Starknet 合约/RPC 注入（登录/买入走 ZChain 钱包
#             扩展，服务端对无 depositTxHash 的入座跳过链上核验）。
#
# 语义钉死（配置文件误写以这里为准）：
#   sepolia: TEXAS_ENV=test、TEXAS_PROVER_MODE=remote、
#            STARKNET_SETTLEMENT_EXIT=starknet（默认值是 appchain——那是
#            dev 语义；连真实 Sepolia 结算必须显式走 legacy calldata 出口）
#   zchain:  TEXAS_ENV=dev、TEXAS_PROVER_MODE=dev、STARKNET_SETTLEMENT_EXIT=appchain
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE=release
NO_CLIENT=0
CHAIN=""
BUILD=1

for arg in "$@"; do
  case "$arg" in
    sepolia|zchain) CHAIN="$arg" ;;
    --no-client) NO_CLIENT=1 ;;
    --debug) PROFILE=debug ;;
    --no-build|--skip-build) BUILD=0 ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: ${arg}（用法见文件头注释或 scripts/test.sh --help）"; exit 1 ;;
  esac
done
CHAIN="${CHAIN:-sepolia}"

log() { echo "[test:$CHAIN] $*"; }

# ---------- 0) 停掉旧实例（上次运行的 texas 服务器 / 前端）----------
# 与 dev.sh 同一套清理：cmdline 可能是绝对路径（手动启动）或相对路径
# （cargo run 生成）；pkill 无匹配返回非零，|| true 防 set -e 中断。
log "清理旧实例…"
pkill -f "target/release/texas" 2>/dev/null || true
pkill -f "target/debug/texas" 2>/dev/null || true
pkill -f "cargo run -p texas" 2>/dev/null || true
pkill -f "$ROOT/client" 2>/dev/null || true
sleep 1

# ---------- 1) 构建 ----------
if [[ "$BUILD" == 1 ]]; then
  log "构建服务器（cargo build -p texas --${PROFILE}）…"
  cargo build -p texas --"$PROFILE"
else
  log "跳过构建"
fi

# ---------- 2) 服务器环境（按链切换）----------
# 调用方显式指定的 PORT 优先级最高：env 文件里的 PORT= 不能覆盖它。
PORT_USER="${PORT:-}"
if [[ "$CHAIN" == "sepolia" ]]; then
  ENV_FILE="${ENV_FILE:-$ROOT/texas/.env.test}"
  [[ -f "$ENV_FILE" ]] || {
    echo "缺少配置文件 ${ENV_FILE}（参考仓库内 texas/.env.test 或 DEPLOYMENTS.md 自行填写）"
    exit 1
  }
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
  # test 模式语义钉死：环境标记 test、prover 走向 remote（未配
  # STARKNET_PROVER_URL 时 proved 自动回退 linear）、结算出口 starknet。
  export TEXAS_ENV=test
  export TEXAS_PROVER_MODE=remote
  export STARKNET_SETTLEMENT_EXIT=starknet
else
  if [[ -n "${ZCHAIN_ENV_FILE:-}" ]]; then
    [[ -f "$ZCHAIN_ENV_FILE" ]] || { echo "ZCHAIN_ENV_FILE=$ZCHAIN_ENV_FILE 不存在"; exit 1; }
    log "使用自定义 zchain 服务器环境: $ZCHAIN_ENV_FILE"
    set -a
    # shellcheck disable=SC1090
    source "$ZCHAIN_ENV_FILE"
    set +a
  else
    # 嵌入式 appchain：不设 STARKNET_RPC_URL → 服务器进入 "Starknet dev
    # mode"（买入/登录跳过链上核验），结算经嵌入式 sequencer 出口。
    export TEXAS_ENV=dev
    export TEXAS_PROVER_MODE=dev
    export TEXAS_DEV_BOT_ENABLED=1
    export STARKNET_SETTLEMENT_EXIT=appchain
    export STARKNET_AUTH_STRICT=false
    export JWT_SECRET="${JWT_SECRET:-devnet-secret-for-local-e2e}"
    export RUST_LOG="${RUST_LOG:-info}"
    export BETTING_TIMEOUT_SECS="${BETTING_TIMEOUT_SECS:-90}"
    export BOT_LOOP_SECS=0
  fi
  PORT="${PORT:-9001}"
fi
PORT="${PORT_USER:-${PORT:-9001}}"
export PORT

# ---------- 3) 前端环境（client/.env.development.local，gitignored）----------
CLIENT_ENV="$ROOT/client/.env.development.local"
if [[ "$NO_CLIENT" != 1 ]]; then
  if [[ "$CHAIN" == "sepolia" ]]; then
    RPC="${STARKNET_RPC_URL:-https://starknet-sepolia-rpc.publicnode.com}"
    cat > "$CLIENT_ENV" <<EOF
# 由 scripts/test.sh sepolia 生成（Sepolia 联调配置，覆盖 client/.env.development）。
# 不注入任何测试账户：身份一律来自真实连接的钱包。
# 注意：不要把 blastapi 加进列表——已停服且无 CORS 头（2026-09）。
VITE_STARKNET_RPC_URL=$RPC
VITE_STARKNET_RPC_URLS=$RPC
VITE_STARKNET_CHAIN_ID=0x534e5f5345504f4c4941
# 筹码锚定规范 STRK（pSTRK 已退役；与 texas/.env.test 同源）
VITE_STRK_TOKEN_ADDRESS=${STARKNET_STRK_ADDRESS:-0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d}
VITE_POKER_VAULT_ADDRESS=${STARKNET_VAULT_ADDRESS:-}
VITE_POKER_SETTLEMENT_ADDRESS=${STARKNET_SETTLEMENT_ADDRESS:-}
VITE_SERVER_PORT=${PORT}
# anonymizer/私密池不入此文件——回落 client/.env.development 的 Sepolia 在网值
EOF
  else
    cat > "$CLIENT_ENV" <<EOF
# 由 scripts/test.sh zchain 生成（ZChain 联调配置，覆盖 client/.env.development）。
# 身份/登录/买入全部走 ZChain 钱包扩展（window.zchain）：显式清空 Starknet
# 注入，避免回落到 .env.development 的 Sepolia 地址。结算出口 appchain，
# 服务端对无 depositTxHash 的入座跳过链上核验。
VITE_STARKNET_RPC_URL=
VITE_STARKNET_RPC_URLS=
VITE_STRK_TOKEN_ADDRESS=
VITE_POKER_VAULT_ADDRESS=
VITE_POKER_SETTLEMENT_ADDRESS=
VITE_POKER_VAULT_ANONYMIZER_ADDRESS=
VITE_STRK20_POOL_ADDRESS=
VITE_DEV_ACCOUNT_ADDRESS=
VITE_DEV_ACCOUNT_PRIVATE_KEY=
VITE_SERVER_PORT=${PORT}
EOF
  fi
  log "前端环境已生成: ${CLIENT_ENV}"
fi

# ---------- 4) 启动（前端 + 服务器；Ctrl-C 一并停止）----------
# 端口兜底：清理后仍占用目标端口的视为漏网旧实例，停掉；停不掉再报错。
if lsof -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  log "端口 $PORT 仍被占用，停止占用进程…"
  kill $(lsof -tiTCP:"$PORT" -sTCP:LISTEN) 2>/dev/null || true
  sleep 1
fi
if lsof -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "端口 $PORT 仍被占用且无法停止。手动处理后重试，或用 PORT=<其他端口> 运行。"
  exit 1
fi

cleanup() {
  [[ -n "${CLIENT_PID:-}" ]] && kill "$CLIENT_PID" 2>/dev/null
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null
}
trap cleanup EXIT

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

log "启动 texas 服务器（${PROFILE}，${CHAIN}，端口 ${PORT}）…"
cd "$ROOT"
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
if [[ "$CHAIN" == "zchain" && -z "${ZCHAIN_ENV_FILE:-}" ]]; then
  log "zchain 嵌入式模式：无 Starknet RPC，链上核验跳过；结算出口 appchain"
fi
if [[ -n "${CLIENT_PID:-}" ]]; then
  log "前端就绪: http://localhost:5173（端口占用时 vite 自动顺延，日志 /tmp/texas-client.log）"
  if [[ "$CHAIN" == "zchain" ]]; then
    log "提示: zchain 模式需浏览器装有 ProofPlay Wallet 扩展（window.zchain）；登录/买入经扩展弹窗签名"
  fi
fi
log "全部已启动；Ctrl-C 一次性停止（前端 + 服务器）"
wait
