#!/usr/bin/env bash
# e2e 巡检看护（M3-1，重建项——原巡检自动化已删除，见 /tmp/poker-air-e2e-
# findings.md:47）。对 1000 手 e2e 长跑做周期性体检 + 进度台账 + 停滞处置。
#
# 与栈内既有看护的分工（不重复造轮）：
#   - mjs（zchain/scripts/poker_air_browser.mjs）：浏览器会话内 stall-watch
#     （15min 警告 + 截图；连续 3 次主动 exit 3——发现 8 升级策略已实现，
#     未提交改动待过目）；
#   - dev_poker_air.sh 的 browser-supervisor：mjs 进程退出后自动重启新
#     attempt（发现 7 的「杀浏览器触发新 attempt」恢复手法）；
#   - 本脚本：**run 级巡检**——栈健康（进程/日志活性）+ 桥锚定进度台账 +
#     跨会话停滞判定与处置。三者互补，本脚本不替代前两者。
#
# 用法：
#   scripts/e2e_patrol.sh --run-dir /tmp/poker-air-zchain-1000-run4 [--watch]
#     --run-dir <dir>            dev_poker_air.sh 的 RUN_DIR（必填）
#     --watch                    常驻巡检（缺省跑一轮体检即退出，供 cron）
#     --interval <secs>          巡检间隔（--watch，默认 60）
#     --stall-mins <mins>        桥进度停滞阈值（默认 20；mjs 内部 15min
#                                警告是会话级，run 级留裕量）
#     --kill-browser-on-stall    停滞时杀浏览器触发 supervisor 新 attempt
#                                （发现 7 实证恢复手法；默认只告警）
#     --target <hands>           目标手数（默认 1000；达到即退出 0）
#
# 体检面：texas / zchain / browser-supervisor 三进程在位（pgrep）；texas
# 日志有增量（活性）；bridge 日志解析「<锚定>/<目标>」最新进度。任一失败
# 记台账并影响退出码（健康失败 = 2）；停滞 = 台账 STALL 事件（可选处置）。
# 退出码：0 达标/正常；1 用法错误；2 栈健康失败。
# 台账：$RUN_DIR/patrol.log（追加；一行一体检：ts hands status）。
set -u

RUN_DIR="" WATCH=0 INTERVAL=60 STALL_MINS=20 KILL_ON_STALL=0 TARGET=1000
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-dir) RUN_DIR="${2:?--run-dir 缺参数}"; shift 2 ;;
    --watch) WATCH=1; shift ;;
    --interval) INTERVAL="${2:?--interval 缺参数}"; shift 2 ;;
    --stall-mins) STALL_MINS="${2:?--stall-mins 缺参数}"; shift 2 ;;
    --kill-browser-on-stall) KILL_ON_STALL=1; shift ;;
    --target) TARGET="${2:?--target 缺参数}"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done
[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || { echo "--run-dir 目录不存在: $RUN_DIR" >&2; exit 1; }

PATROL_LOG="$RUN_DIR/patrol.log"
BRIDGE_LOG="$RUN_DIR/bridge.log"
TEXAS_LOG="$RUN_DIR/texas-server.log"
STALL_SECS=$((STALL_MINS * 60))
BASE_HANDS=-1
BASE_CHANGE=$(date +%s)

log() { echo "[$(date '+%F %T')] $*" | tee -a "$PATROL_LOG"; }

# 桥进度：bridge.log 尾部最新的「<n>/<target>」（poker_air_bridge 打印形态；
# 容错：无匹配返回空，调用方按 0 进度处理）。
bridge_hands() {
  tail -n 400 "$BRIDGE_LOG" 2>/dev/null \
    | grep -aoE '[0-9]+/'"$TARGET" \
    | tail -1 | cut -d/ -f1
}

proc_alive() { pgrep -f "$1" >/dev/null 2>&1; }

# 单轮体检：0 = 健康；2 = 栈健康失败（进程缺失/日志冻结）。停滞不在此
# 判定（跨轮状态，见 watch 循环）。
one_round() {
  local now hands errs=0
  now=$(date +%s)

  # 1) 进程面。
  local miss=""
  proc_alive "target/release/texas" || miss="$miss texas"
  proc_alive "zchain.*poker-air" || miss="$miss zchain"
  if [[ -f "$RUN_DIR/browser-supervisor.pid" && ! -f "$RUN_DIR/browser.done" ]]; then
    proc_alive "poker_air_browser.mjs" || miss="$miss browser-mjs"
  fi
  if [[ -n "$miss" ]]; then
    log "HEALTH-FAIL 进程缺失:${miss}"
    errs=2
  fi

  # 2) 日志活性：texas 日志 10 分钟无增量 = 冻结嫌疑（空转/挂死）。
  if [[ -f "$TEXAS_LOG" ]]; then
    local mtime now_delta
    mtime=$(stat -f %m "$TEXAS_LOG" 2>/dev/null || echo 0)
    now_delta=$((now - mtime))
    if (( now_delta > 600 )); then
      log "HEALTH-WARN texas 日志 ${now_delta}s 无增量（>600s）"
      [[ $errs -eq 0 ]] && errs=2
    fi
  fi

  # 3) 进度台账 + 停滞判定。
  hands=$(bridge_hands)
  hands="${hands:-0}"
  if (( BASE_HANDS < 0 )); then
    BASE_HANDS=$hands
    log "START hands=$hands/$TARGET"
  fi
  if (( hands > BASE_HANDS )); then
    BASE_HANDS=$hands
    BASE_CHANGE=$now
    log "PROGRESS hands=$hands/$TARGET"
  elif (( now - BASE_CHANGE >= STALL_SECS )); then
    log "STALL hands=$hands/$TARGET 已 ${STALL_MINS}min 无进展（最近异常：）"
    tail -n 60 "$TEXAS_LOG" 2>/dev/null | grep -aE " ERROR |panic|stall|FAILED" | tail -5 | tee -a "$PATROL_LOG"
    if (( KILL_ON_STALL )); then
      log "STALL-处置 杀浏览器触发 supervisor 新 attempt（发现 7 恢复手法）"
      pkill -f "poker_air_browser.mjs" 2>/dev/null || true
      BASE_CHANGE=$now
    fi
  else
    log "OK hands=$hands/$TARGET（停滞判定 $( ((STALL_SECS - (now - BASE_CHANGE)) / 60 + 1) )min 后）"
  fi

  # 4) 达标即停。
  if (( BASE_HANDS >= TARGET )); then
    log "TARGET-REACHED hands=$BASE_HANDS/$TARGET"
    return 0
  fi
  return $errs
}

if [[ ! -f "$BRIDGE_LOG" ]]; then
  echo "bridge 日志不存在: $BRIDGE_LOG（RUN_DIR 是否正确？）" >&2
  exit 1
fi

if (( ! WATCH )); then
  one_round
  exit $?
fi

log "WATCH 启动 interval=${INTERVAL}s stall=${STALL_MINS}min kill_on_stall=$KILL_ON_STALL target=$TARGET"
while true; do
  one_round; rc=$?
  if (( rc == 0 )); then
    log "达标退出（exit 0）"
    exit 0
  fi
  sleep "$INTERVAL"
done
