#!/usr/bin/env bash
# run_on_window2.sh —— 阶段2：窗口内 勘察详查（只读）→ 修复后门禁真跑
set -u
BASE=/Users/mac/projects/poker_texas_air/out/resource-isolation
SSHO=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5
      -o ControlMaster=auto -o ControlPath="$HOME/.ssh/cm-stark-run" -o ControlPersist=300s)
log(){ echo "[$(date +%H:%M:%S)] $*"; }

end=$((SECONDS+2100))   # 捕捉期 35 分钟
while [ $SECONDS -lt $end ]; do
  b=$( (printf ''; sleep 2) | nc -w 4 8.218.68.215 22 2>/dev/null | head -1)
  if [ -z "$b" ]; then sleep 10; continue; fi
  log "BANNER: $b —— 只读详查"
  timeout 30 ssh "${SSHO[@]}" stark 'bash -s' < "$BASE/detail_fetch.sh" > "$BASE/detail_output.txt" 2>&1
  if ! grep -q "DETAIL DONE" "$BASE/detail_output.txt"; then
    log "detail 未完整（窗口关闭），继续探针"; sleep 5; continue
  fi
  log "detail 完成 —— 门禁真跑"
  timeout 240 bash /Users/mac/projects/poker_texas_air/scripts/check_resource_isolation.sh \
    > "$BASE/check_output.txt" 2>&1
  crc=$?
  log "check exit=$crc"
  exit $crc
done
log "35 分钟内未再遇到放行窗口"
exit 9
