#!/usr/bin/env bash
# cage-run.sh —— C3 笼内复测（须在 systemd-run 起的 fold-c3-k<K>.service 内执行）
# 单元属性对齐 monad-fold@.service 模板：Slice=zchain-recursion.slice、
# MemoryMax=4600M、MemorySwapMax=0、CPUQuota=300%、CPUWeight/IOWeight=60、Nice=5。
# 采样：内核 6.6 无 cgroup memory.peak，按 100ms 轮询本单元 memory.current 取峰值；
# texas.service MemoryCurrent 全程漂移探针（门禁 <10%）。
# 判定门（工程报告 monad-fold@ 模板注释同口径）：4600M 内完成 + cgroup 无 oom_kill
# + texas active 且漂移<10% + steps 与本机 T7 基线一致。
set -u
K="${1:-64}"
BASE=/root/.zmonad-tmp/fold-c3
CG="/sys/fs/cgroup/zchain.slice/zchain-recursion.slice/fold-c3-k${K}.service"
BIN="$BASE/fold_batch_test"
export HAND_VERIFY_FOLD_SRC="$BASE/cairo/src/fold_batch.cairo"
export HAND_VERIFY_PROVE_HAND="$BASE/prove-hand"
export FOLD_PERF_ONLY="$K"
cd "$BASE"
tx_base=$(systemctl show texas.service -p MemoryCurrent --value)
echo "k=$K tx_base=$tx_base tx_active_start=$(systemctl is-active texas.service)" > "$BASE/verdict-k${K}.txt"
"$BIN" t7_perf_sweep_steps_gate --ignored --nocapture > "$BASE/t7-k${K}.log" 2>&1 &
PID=$!
peak=0; tx_peak=$tx_base; tx_min=$tx_base
while kill -0 "$PID" 2>/dev/null; do
  cur=$(cat "$CG/memory.current" 2>/dev/null || echo 0)
  [ "$cur" -gt "$peak" ] && peak=$cur
  tx=$(systemctl show texas.service -p MemoryCurrent --value 2>/dev/null || echo "$tx_base")
  [ "$tx" -gt "$tx_peak" ] && tx_peak=$tx
  [ "$tx" -lt "$tx_min" ] && tx_min=$tx
  echo "$(date +%H:%M:%S.%3N) cg=$cur tx=$tx" >> "$BASE/samples-k${K}.log"
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
} >> "$BASE/verdict-k${K}.txt"
echo "===t7-k${K}.log tail===" >> "$BASE/verdict-k${K}.txt"
tail -25 "$BASE/t7-k${K}.log" >> "$BASE/verdict-k${K}.txt"
# 传播测试退出码：systemd 单元 Result 必须反映测试成败（否则失败轮也显 success）
exit "$rc"
