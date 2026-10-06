#!/usr/bin/env bash
# alert-batch-poster.sh —— batch-poster status 端点告警拉取（只读，不写任何状态）。
#
# 分工：阈值判定在 daemon 侧（TEXAS_POSTER_ALERT_* env → batch-poster/src/
# status.rs AlertThresholds，阈值语义与校准方法见 docs/BATCH_POSTER_OPS.md §5）；
# 本脚本只拉取端点 JSON、评估 `alerts` 数组，把结论翻译成退出码供
# cron/监控面消费：
#   0 = OK（alerts 空）
#   1 = WARN（有告警项）
#   2 = CRIT（端点不可达 / JSON 不可解析 / txmgr 熔断停发）
#
# 用法：scripts/alert-batch-poster.sh
# 环境变量：
#   ALERT_BATCH_POSTER_URL    默认 http://127.0.0.1:7331/（service 单元只绑回环）
#   ALERT_BATCH_POSTER_TIMEOUT 默认 5（秒）

set -euo pipefail
command -v python3 >/dev/null 2>&1 || { echo "error: python3 不存在" >&2; exit 2; }

STATUS_URL="${ALERT_BATCH_POSTER_URL:-http://127.0.0.1:7331/}"
TIMEOUT_SECS="${ALERT_BATCH_POSTER_TIMEOUT:-5}"

body="$(curl -fsS --max-time "$TIMEOUT_SECS" "$STATUS_URL" 2>/dev/null)" || {
  echo "CRIT batch-poster status 端点不可达: ${STATUS_URL}（进程挂了/端口漂移）"
  exit 2
}

python3 - "$body" <<'PYEOF'
import json
import sys

try:
    st = json.loads(sys.argv[1])
except json.JSONDecodeError as exc:
    print(f"CRIT status JSON 解析失败: {exc}")
    sys.exit(2)

alerts = st.get("alerts")
if alerts is None:
    # 端点响应缺 alerts 字段 = daemon 版本过旧（告警面未上线）——监控缺口
    # 本身必须可见，不放空。
    print("WARN 端点响应无 alerts 字段（daemon 版本过旧，缺告警面）")
    sys.exit(1)

if not isinstance(alerts, list):
    print(f"CRIT alerts 字段形状异常（预期数组，得 {type(alerts).__name__}）")
    sys.exit(2)

codes = [a.get("code", "?") for a in alerts]
if "txmgr_halted" in codes:
    detail = "; ".join(str(a.get("detail", "")) for a in alerts)
    print(f"CRIT txmgr 熔断停发（fail-closed，需人工对账后 resume）: {detail}")
    sys.exit(2)

if codes:
    joined = "; ".join(f"{a.get('code')}({a.get('detail', '')})" for a in alerts)
    print(f"WARN {joined}")
    sys.exit(1)

print(
    "OK "
    f"pending_tasks={st.get('pending_tasks')} "
    f"pending_batches={st.get('pending_batches')} "
    f"oldest_batch_age_secs={st.get('oldest_batch_age_secs')} "
    f"in_flight_txs={st.get('in_flight_txs')} "
    f"draining={st.get('draining')}"
)
PYEOF
