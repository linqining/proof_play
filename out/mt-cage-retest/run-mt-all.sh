#!/usr/bin/env bash
# run-mt-all.sh —— 服务器侧驱动：四场景顺序入笼（每场景独立 systemd 单元，各自采样）
# 场景：k64=单桌 K=64 回归 / mt8=T=8×8人 ΣK=64 最坏形状 / mt2a=T=2 异人数 / mt2b=T=2 同规模
set -u
BASE=/root/.zmonad-tmp/fold-mt
run() {
  local name="$1" filter="$2" perf="${3:-}"
  systemctl reset-failed "fold-mt-${name}" 2>/dev/null || true
  if [ -n "$perf" ]; then
    systemd-run --wait --collect --unit="fold-mt-${name}" \
      -p Slice=zchain-recursion.slice -p MemoryMax=4600M -p MemorySwapMax=0 \
      -p CPUQuota=300% -p CPUWeight=60 -p IOWeight=60 -p Nice=5 \
      -p LogRateLimitIntervalSec=30 -p TimeoutStartSec=1800 \
      /bin/bash "$BASE/cage-run-mt.sh" "$name" "$filter" "$perf"
  else
    systemd-run --wait --collect --unit="fold-mt-${name}" \
      -p Slice=zchain-recursion.slice -p MemoryMax=4600M -p MemorySwapMax=0 \
      -p CPUQuota=300% -p CPUWeight=60 -p IOWeight=60 -p Nice=5 \
      -p LogRateLimitIntervalSec=30 -p TimeoutStartSec=1800 \
      /bin/bash "$BASE/cage-run-mt.sh" "$name" "$filter"
  fi
  echo "[driver] $name exit=$?"
}
run k64 t7 64
run mt8 m9_1c
run mt2a m9_1a
run mt2b m9_1b
touch "$BASE/ALL_DONE"
