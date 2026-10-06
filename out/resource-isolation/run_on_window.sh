#!/usr/bin/env bash
# run_on_window.sh —— stark ssh 放行窗口内原子完成: 勘察 → 推送+安装 → 门禁
# 背景: 本机出口对 SSH 协议 DPI 重置，窗口极短(~30s)。banner 一出现立即行动，
#       并用 ControlMaster 连接复用让后续 ssh 不再经历 banner 握手。
set -u
BASE=/Users/mac/projects/poker_texas_air/out/resource-isolation
SSHO=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5
      -o ControlMaster=auto -o ControlPath="$HOME/.ssh/cm-stark-run" -o ControlPersist=300s)
log(){ echo "[$(date +%H:%M:%S)] $*"; }

end=$((SECONDS+2400))   # 捕捉期 40 分钟
while [ $SECONDS -lt $end ]; do
  b=$( (printf ''; sleep 2) | nc -w 4 8.218.68.215 22 2>/dev/null | head -1)
  if [ -z "$b" ]; then sleep 10; continue; fi
  log "BANNER: $b —— 立即勘察"
  timeout 25 ssh "${SSHO[@]}" stark 'bash -s' < "$BASE/survey_stark.sh" > "$BASE/survey_output.txt" 2>&1
  if ! grep -q "SURVEY DONE" "$BASE/survey_output.txt"; then
    log "survey 未完整输出（窗口关闭），继续探针"; sleep 5; continue
  fi
  log "survey 完成 —— 单连接推送+安装"
  tar czf - -C "$BASE/server" . | timeout 240 ssh "${SSHO[@]}" stark \
    'mkdir -p /root/.zmonad-tmp && tar xzf - -C /root/.zmonad-tmp && bash /root/.zmonad-tmp/install_resource_isolation.sh' \
    > "$BASE/install_output.txt" 2>&1
  irc=$?
  log "install exit=$irc"
  timeout 240 bash /Users/mac/projects/poker_texas_air/scripts/check_resource_isolation.sh \
    > "$BASE/check_output.txt" 2>&1
  crc=$?
  log "check exit=$crc"
  exit $(( irc || crc ))
done
log "40 分钟内未再遇到放行窗口"
exit 9
