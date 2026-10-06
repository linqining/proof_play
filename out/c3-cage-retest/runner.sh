#!/usr/bin/env bash
# runner.sh —— C3 笼内复测编排（本机侧）。SSH 对 stark 有 DPI 放行窗口限制，
# 策略沿用 out/resource-isolation/run_on_window.sh：轮询 banner → ControlMaster
# 复用连接（断线后服务端进程不受影响，collect 可在后续窗口收证）。
#
# 用法：
#   runner.sh push [K]   # 推送+预检+起笼内服务（K 默认 64）
#   runner.sh collect [K] # 收证（服务跑完后调用；断线重连后也可用）
set -u
BASE=/Users/mac/projects/poker_texas_air/out/c3-cage-retest
K="${2:-64}"
SSHO=(-o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=5
      -o ControlMaster=auto -o ControlPath="$HOME/.ssh/cm-c3" -o ControlPersist=900s)
UNIT="fold-c3-k${K}"
log(){ echo "[$(date +%H:%M:%S)] $*"; }

ensure_conn() {
  ssh "${SSHO[@]}" stark 'true' 2>/dev/null && return 0
  local end=$((SECONDS+1500)) b
  while [ $SECONDS -lt $end ]; do
    b=$( (printf ''; sleep 2) | nc -w 4 8.218.68.215 22 2>/dev/null | head -1)
    if [ -n "$b" ]; then
      log "BANNER: $b"
      ssh "${SSHO[@]}" stark 'true' 2>/dev/null && return 0
      log "banner 后握手仍被重置，继续轮询"
    fi
    sleep 10
  done
  return 9
}

case "${1:-push}" in
push)
  log "推送 + 预检 + 起服务 (K=$K)"
  ensure_conn || { log "25 分钟内无放行窗口"; exit 9; }
  shasum -a 256 "$BASE/fold_batch_test" "$BASE/prove-hand" || true
  tar czf - -C "$BASE" fold_batch_test prove-hand cage-run.sh canonical_small.json cairo.tar.gz | timeout 420 ssh "${SSHO[@]}" stark "
    set -e
    mkdir -p /root/.zmonad-tmp/fold-c3 && tar xzf - -C /root/.zmonad-tmp/fold-c3
    cd /root/.zmonad-tmp/fold-c3 && chmod +x cage-run.sh fold_batch_test prove-hand
    if [ -e /Users ]; then echo PREEXISTING_USERS; else echo NO_USERS; fi
    mkdir -p '/Users/mac/projects/poker_texas_air/poker_contracts/hand-verify-native/output/fold-batch-test' \
             '/Users/mac/projects/poker_texas_air/proving-tool/params'
    cp -f canonical_small.json '/Users/mac/projects/poker_texas_air/proving-tool/params/'
    sha256sum fold_batch_test prove-hand
    echo '---prover-busy-check---'
    systemctl list-units --no-legend 'monad-leaf@*.service' 'monad-fold@*.service' --state=running || echo none-running
    echo '---start---'
    systemd-run --unit=${UNIT} --collect \
      -p Slice=zchain-recursion.slice -p MemoryMax=4600M -p MemorySwapMax=0 \
      -p CPUQuota=300% -p CPUWeight=60 -p IOWeight=60 -p Nice=5 \
      -p LogRateLimitIntervalSec=30 -p TimeoutStartSec=1800 \
      /bin/bash /root/.zmonad-tmp/fold-c3/cage-run.sh ${K}
    systemctl is-active ${UNIT}.service
  " 2>&1 | tee "$BASE/push_start.log"
  log "push 阶段退出（服务已在服务器侧独立运行，断线不影响）"
  ;;
collect)
  log "收证 (K=$K)"
  ensure_conn || { log "25 分钟内无放行窗口"; exit 9; }
  timeout 1200 ssh "${SSHO[@]}" stark "
    for i in \$(seq 1 150); do
      systemctl is-active --quiet ${UNIT}.service 2>/dev/null || break
      sleep 5
    done
    systemctl is-active ${UNIT}.service 2>/dev/null || true
    systemctl show ${UNIT}.service -p Result -p ExecMainStatus 2>/dev/null
    echo '===verdict==='
    cat /root/.zmonad-tmp/fold-c3/verdict-k${K}.txt 2>/dev/null || echo NO_VERDICT
    echo '===t7 full log==='
    cat /root/.zmonad-tmp/fold-c3/t7-k${K}.log 2>/dev/null || echo NO_T7LOG
    echo '===journal tail==='
    journalctl -u ${UNIT}.service --no-pager -n 30 2>/dev/null | tail -30 || true
  " 2>&1 | tee "$BASE/result-k${K}.log"
  log "collect 完成，结果见 $BASE/result-k${K}.log"
  ;;
esac
