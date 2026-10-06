#!/usr/bin/env bash
# cage-run-mt.sh —— 多桌形状笼内单场景执行（须在 systemd-run 起的 fold-mt-<name>.service 内）
# 用法：cage-run-mt.sh <name> <test_filter> [FOLD_PERF_ONLY值]
# 单元属性同 monad-fold@.service 探针纪律：Slice=zchain-recursion.slice、
# MemoryMax=4600M、MemorySwapMax=0、CPUQuota=300%、Nice=5。
# 采样：内核无 memory.peak，100ms 轮询本单元 memory.current 取峰；texas 漂移探针 <10%。
# 判定：4600M 内完成 + oom_kill=0 + texas active 且漂移<10% + steps 与本地一致。
set -u
NAME="$1"; FILTER="$2"; PERF="${3:-}"
BASE=/root/.zmonad-tmp/fold-mt
CG="/sys/fs/cgroup/zchain.slice/zchain-recursion.slice/fold-mt-${NAME}.service"
BIN="$BASE/fold_batch_test"
export HAND_VERIFY_FOLD_SRC="$BASE/cairo/src/fold_batch.cairo"
export HAND_VERIFY_PROVE_HAND="$BASE/prove-hand"
[ -n "$PERF" ] && export FOLD_PERF_ONLY="$PERF"
cd "$BASE"
tx_base=$(systemctl show texas.service -p MemoryCurrent --value)
echo "name=$NAME filter=$FILTER perf=${PERF:-none} tx_base=$tx_base tx_active_start=$(systemctl is-active texas.service)" > "$BASE/verdict-mt-${NAME}.txt"
"$BIN" $FILTER --ignored --nocapture > "$BASE/log-mt-${NAME}.txt" 2>&1 &
PID=$!
peak=0; tx_peak=$tx_base; tx_min=$tx_base
while kill -0 "$PID" 2>/dev/null; do
  cur=$(cat "$CG/memory.current" 2>/dev/null || echo 0)
  [ "$cur" -gt "$peak" ] && peak=$cur
  tx=$(systemctl show texas.service -p MemoryCurrent --value 2>/dev/null || echo "$tx_base")
  [ "$tx" -gt "$tx_peak" ] && tx_peak=$tx
  [ "$tx" -lt "$tx_min" ] && tx_min=$tx
  echo "$(date +%H:%M:%S.%3N) cg=$cur tx=$tx" >> "$BASE/samples-mt-${NAME}.log"
  sleep 0.1
done
wait "$PID"; rc=$?
oom=$(awk '/^oom_kill/{print $2}' "$CG/memory.events" 2>/dev/null || echo NA)
{
  echo "exit=$rc"
  echo "cage_peak_bytes=$peak ($(( peak / 1048576 )) MiB / 4600M 单元帽 $(( peak * 100 / 4823449600 ))%)"
  echo "cage_oom_kills=${oom:-NA}"
  tx_end=$(systemctl show texas.service -p MemoryCurrent --value)
  echo "tx_base=$tx_base tx_min=$tx_min tx_peak=$tx_peak tx_end=$tx_end tx_active_end=$(systemctl is-active texas.service)"
  awk -v b="$tx_base" -v p="$tx_peak" -v m="$tx_min" 'BEGIN{d=(p>b)?(p-b)*100/b:(b-m)*100/b; printf "tx_drift_pct=%.2f\n", d}'
} >> "$BASE/verdict-mt-${NAME}.txt"
echo "===log tail===" >> "$BASE/verdict-mt-${NAME}.txt"
tail -15 "$BASE/log-mt-${NAME}.txt" >> "$BASE/verdict-mt-${NAME}.txt"
exit "$rc"
