#!/usr/bin/env bash
# 钱包部署脚本：把真实钱包（Argent/Ready）在本地开发网上的反事实账户
# 推过"部署"这一步，或绕过钱包直接部署一个脚本托管的 OZ 测试账户。
#
# 背景：Ready 插件没有独立的"部署账户"按钮——反事实账户的 deploy_account
# 藏在第一笔交易里，且有前置条件，缺一个钱包就静默失败、UI 上什么都不
# 出现（看起来就是"找不到部署入口"）：
#   1) 账户类已声明进 devnet（starknet-devnet 不预置 Argent 类；
#      scripts/dev.sh 全量流程会声明，--skip-deploy / 手动起的 devnet 没有）
#   2) 反事实地址自身有 STRK（部署费从该地址余额扣，地址在钱包 UI 里读）
#   3) 钱包插件网络指向本 devnet（插件内置 "Devnet" 网络固定 5050，
#      本仓库默认 5051——要么 DEVNET_PORT=5050 跑 dev.sh，要么在插件里
#      添加自定义网络 http://127.0.0.1:<端口>）
# 本脚本逐项检查并自动修复 1/2（声明类、充值），第 3 项在结尾给出指引。
#
# 用法：
#   scripts/deploy_wallet.sh <地址>        # 体检 + 自动修复（推荐：钱包连接
#                                         # 后从 UI 读出地址传进来）
#   scripts/deploy_wallet.sh check <地址>  # 同上但只读，不改任何状态
#   scripts/deploy_wallet.sh new           # 绕过钱包，直接部署一个 OZ 测试
#                                         # 账户（API/后端联调用；无法导入
#                                         # 浏览器钱包插件）
#
# 无法代部署的原因：钱包插件的账户私钥/盐在钱包内部（passkey 或助记词
# 派生），脚本拿不到、也签不了 deploy_account。钱包报 "not deployed"
# （该账户在真 Sepolia 已部署，插件按 chain id 误判已部署而跳过）时，
# 在钱包里针对 devnet 新建一个账户再用。
#
# 环境变量：DEVNET_URL / DEVNET_PORT / ENV_DEV / SCARB_HOME / STARKNET_
# STRK_ADDRESS，语义与 scripts/dev.sh、scripts/fund_devnet.sh 一致。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_PORT="${DEVNET_PORT:-5051}"
DEVNET_URL="${DEVNET_URL:-http://127.0.0.1:${DEVNET_PORT}}"
ENV_DEV="${ENV_DEV:-$ROOT/.env.dev}"
SCARB_HOME="${SCARB_HOME:-$HOME/.local/opt/toolchains/scarb-2.19.4}"

# 与 scripts/dev.sh 预声明一致的 Argent(Ready) 官方 v0.4.0 账户类。
ARGENT_CLASS=0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f
ARGENT_CASM_HASH=0x7a663375245780bd307f56fde688e33e5c260ab02b76741a57711c5b60d47f6
ARGENT_SIERRA="$ROOT/scripts/assets/argent/ArgentAccount.contract_class.json"
ARGENT_CASM="$ROOT/scripts/assets/argent/ArgentAccount.compiled_contract_class.json"

SNOPS="$ROOT/target/release/snops"
[[ -x "$SNOPS" ]] || SNOPS="$ROOT/target/debug/snops"
STRK_ADDRESS="${STARKNET_STRK_ADDRESS:-0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d}"

log() { echo "[wallet] $*"; }
die() { echo "[wallet] $*" >&2; exit 1; }

usage() {
  cat >&2 <<EOF
用法:
  scripts/deploy_wallet.sh <地址>        # 钱包反事实账户部署体检 + 自动修复
  scripts/deploy_wallet.sh check <地址>  # 同上但只读，不改任何状态
  scripts/deploy_wallet.sh new           # 直接部署一个 OZ 测试账户（不经钱包）
EOF
  exit 1
}

require_devnet() {
  curl -sf "$DEVNET_URL/is_alive" >/dev/null 2>&1 || {
    die "devnet 未运行（${DEVNET_URL}）。先跑 scripts/dev.sh（--keep-devnet 保留），或: starknet-devnet --seed 0 --port $DEVNET_PORT"
  }
}

snops_or_die() {
  [[ -x "$SNOPS" ]] || {
    die "未找到 snops（target/{debug,release}/snops）。先跑一次 scripts/dev.sh，或: cargo build -p texas --bin snops"
  }
}

fund_addr() { "$ROOT/scripts/fund_devnet.sh" "$1" "${2:-100}"; }

# JSON-RPC POST；$3 为可选备选 params（新旧 devnet 的 block_id 形式不同：
# 先试裸 "latest"，再试对象形式，与 dev.sh 同一套兜底）。失败输出空串。
rpc() {
  curl -sf "$DEVNET_URL" -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"'"$1"'","params":'"$2"'}' 2>/dev/null \
    || curl -sf "$DEVNET_URL" -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"'"$1"'","params":'"$3"'}' 2>/dev/null \
    || true
}

get_class_at() {  # <地址> → 已部署的 class hash；未部署/查询失败输出空
  rpc starknet_getClassHashAt '["latest","'"$1"'"]' '[{"block_tag":"latest"},"'"$1"'"]' \
    | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
r = d.get("result") if isinstance(d, dict) else None
if isinstance(r, str) and r not in ("", "0x0", "0x00"):
    print(r)
'
}

argent_class_declared() {  # 退出码 0 = Argent 账户类已在 devnet 声明
  rpc starknet_getClass '["latest","'"$ARGENT_CLASS"'"]' '[{"block_tag":"latest"},"'"$ARGENT_CLASS"'"]' \
    | grep -q '"sierra_program"'
}

balance_fri() {  # <地址> → STRK 余额 u256 低位段（hex FRI）；不可用输出空
  [[ -x "$SNOPS" ]] || return 0
  "$SNOPS" --url "$DEVNET_URL" call --contract "$STRK_ADDRESS" \
    --fn balance_of --calldata "$1" 2>/dev/null \
    | head -1 | grep -oE '0x[0-9a-f]+' || true
}

# 声明 Argent 账户类（复用 dev.sh 的 owner + 类产物；snops 内部含 casm
# hash 不匹配时从报错提取期望值重试的逻辑）。
declare_argent() {
  snops_or_die
  [[ -f "$ARGENT_SIERRA" && -f "$ARGENT_CASM" ]] || {
    die "缺少 Argent 类产物（${ARGENT_SIERRA}）"
  }
  [[ -f "$ENV_DEV" ]] || { die "缺少账户文件 ${ENV_DEV}（声明类需要 owner 账户签名）"; }
  local owner opkey obal
  owner=$(grep -E '^ADDRESS=' "$ENV_DEV" | head -1 | cut -d= -f2- | tr -d '[:space:]')
  opkey=$(grep -E '^PRIVATE_KEY=' "$ENV_DEV" | head -1 | cut -d= -f2- | tr -d '[:space:]')
  [[ -n "$owner" && -n "$opkey" ]] || die "$ENV_DEV 里未找到 ADDRESS / PRIVATE_KEY"
  # owner 兜底（幂等）：部署费/声明 gas 都从 owner 自身余额扣，先充值再部署。
  obal=$(balance_fri "$owner")
  if [[ -z "$obal" || "$obal" == "0x0" || "$obal" == "0x00" ]]; then
    fund_addr "$owner" 100
  fi
  if [[ -z "$(get_class_at "$owner")" ]]; then
    log "owner 账户 $owner 未部署，先 deploy-acct…"
    "$SNOPS" --url "$DEVNET_URL" --pk "$opkey" deploy-acct >>/tmp/devnet-deploy.log 2>&1 \
      || { tail -5 /tmp/devnet-deploy.log; die "owner 部署失败（日志 /tmp/devnet-deploy.log）"; }
  fi
  log "声明 Argent 账户类（${ARGENT_CLASS}）…"
  "$SNOPS" --url "$DEVNET_URL" --pk "$opkey" --addr "$owner" declare \
    --class "$ARGENT_SIERRA" --compiled "$ARGENT_CASM" \
    --compiled-hash "$ARGENT_CASM_HASH" >>/tmp/devnet-deploy.log 2>&1 \
    || { tail -5 /tmp/devnet-deploy.log; die "Argent 类声明失败（日志 /tmp/devnet-deploy.log）"; }
  log "Argent 账户类已声明"
}

# 钱包反事实账户体检：<地址> fix(1=自动修复 / 0=只读)。
run_for_addr() {
  local addr="$1" fix="$2" class bal argent_ok
  [[ "$addr" =~ ^0x[0-9a-fA-F]+$ ]] || { die "地址格式不对（须 0x 开头的十六进制）: $addr"; }
  require_devnet

  class=$(get_class_at "$addr")
  bal=$(balance_fri "$addr")
  if argent_class_declared; then argent_ok=1; else argent_ok=0; fi

  log "devnet: ${DEVNET_URL}（目标地址 ${addr}）"
  if [[ -n "$class" ]]; then
    log "① 账户已部署（class ${class}）"
  else
    log "① 账户未部署（反事实账户的预期状态，部署藏在钱包第一笔交易里）"
  fi
  if [[ "$argent_ok" == 1 ]]; then
    log "② Argent 账户类已在 devnet 声明"
  else
    log "② Argent 账户类未声明（钱包部署会报 Class not declared）"
  fi
  if [[ -n "$bal" ]]; then
    log "③ STRK 余额: $(python3 -c "print(f'{int(\"$bal\", 16) / 10**18:,.4f}')")（部署费从这里扣）"
  else
    log "③ STRK 余额: 查询不可用（缺 snops 产物）"
  fi

  if [[ -n "$class" ]]; then
    log "无需操作：账户已部署，钱包里直接发起交易即可。"
    return 0
  fi

  # 未部署 → 补前置（fix 模式动手，check 模式只给命令）。
  if [[ "$argent_ok" != 1 ]]; then
    if [[ "$fix" == 1 ]]; then
      declare_argent
    else
      log "→ 修复: scripts/dev.sh（全量流程会预声明），或 scripts/deploy_wallet.sh $addr"
    fi
  fi
  if [[ -z "$bal" || "$bal" == "0x0" || "$bal" == "0x00" ]]; then
    if [[ "$fix" == 1 ]]; then
      fund_addr "$addr" 100
    else
      log "→ 修复: scripts/fund_devnet.sh $addr 100"
    fi
  fi

  cat <<EOF

下一步（钱包里的"部署入口"）：
  Ready/Argent 插件没有独立的部署按钮：钱包切到指向本 devnet 的网络后，
  发任意一笔交易（登录游戏后买入即可），插件自动 deploy_account。注意：
  · 插件内置 "Devnet" 网络固定指向 localhost:5050，本仓库默认 5051——
    要么 DEVNET_PORT=5050 重跑 scripts/dev.sh，要么在插件里添加自定义
    网络 http://127.0.0.1:$DEVNET_PORT
  · 钱包报 "not deployed"（账户在真 Sepolia 已部署，插件按 chain id
    SN_SEPOLIA 误判已部署而跳过部署）→ 在钱包里针对 devnet 新建一个账户
  · 钱包报 "Class ... is not declared" 且 class 不是 $ARGENT_CLASS
    → 钱包用了更新版账户类：把该类产物放进 scripts/assets/argent/ 后
      重跑 scripts/dev.sh（或本脚本）
EOF
}

# 绕过钱包直接部署一个 OZ 测试账户：gen-key → 充值 → deploy-acct。
cmd_new() {
  snops_or_die
  require_devnet
  local gen pk pub addr out dep_addr tx vclass
  # gen-key 本身离线，但 clap 里 --url 是全局必填参数，随便传一个即可。
  gen=$("$SNOPS" --url "$DEVNET_URL" gen-key)
  pk=$(sed -n 's/^PRIVATE_KEY=//p' <<<"$gen")
  pub=$(sed -n 's/^PUBLIC_KEY=//p' <<<"$gen")
  addr=$(sed -n 's/^ADDRESS=//p' <<<"$gen")
  [[ -n "$pk" && -n "$addr" ]] || die "gen-key 输出异常: $gen"
  log "新账户地址: $addr"
  fund_addr "$addr" 100
  log "部署账户（OZ 类，salt 0）…"
  out=$("$SNOPS" --url "$DEVNET_URL" --pk "$pk" deploy-acct 2>&1) \
    || { echo "$out" | tail -5; die "deploy_account 失败"; }
  dep_addr=$(sed -n 's/^ADDRESS=//p' <<<"$out")
  tx=$(sed -n 's/^TX=//p' <<<"$out")
  [[ -n "$dep_addr" ]] || die "deploy_account 输出异常: $out"
  if [[ "$(echo "$dep_addr" | tr '[:upper:]' '[:lower:]')" != "$(echo "$addr" | tr '[:upper:]' '[:lower:]')" ]]; then
    log "警告: 部署地址 $dep_addr 与预测地址 $addr 不一致"
  fi
  vclass=$(get_class_at "$dep_addr")
  [[ -n "$vclass" ]] || log "警告: 部署后查询不到 class（可能未上链，看 /tmp/devnet-deploy.log）"
  log "已部署（tx ${tx}）"

  cat <<EOF

=== 新钱包凭据（只在本 devnet 有效；devnet 重建后重跑本命令重新部署） ===
PRIVATE_KEY=$pk
PUBLIC_KEY=$pub
ADDRESS=$dep_addr

用途：
  · API/后端联调：直接用这个账户签名发交易（snops invoke/call 等）
  · 写进 $ENV_DEV 的 ADDRESS= / PRIVATE_KEY= 可当 owner/operator
  · 加进 $ENV_DEV 的 DEV_EXTRA_FUND=（空格分隔）可随 scripts/dev.sh
    每次启动自动充值
  · 这是 OZ 账户，导不进浏览器钱包插件——要连前端请用 Ready 真实账户
    （\`scripts/deploy_wallet.sh <钱包地址>\` 做部署前体检）
EOF
}

case "${1:-}" in
  new)   cmd_new ;;
  check) [[ -n "${2:-}" ]] || usage; run_for_addr "$2" 0 ;;
  0x*)   run_for_addr "$1" 1 ;;
  *)     usage ;;
esac
