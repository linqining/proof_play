#!/usr/bin/env bash
# batch-poster-smoke.sh —— batch-poster 干跑冒烟（**不触发真实出证/上链**）。
#
# 覆盖（docs/BATCH_POSTER_OPS.md §6「启用 fold 前先干跑」口径）：
#   1. 单元面：cargo test -p batch-poster --lib —— PosterConfig::validate
#      （K≤64 且 2 的幂 fail-closed，batch.rs check_batch_size 同政策）、
#      plan_batch_size 攒批规划、运营默认值定版、告警阈值评估（tests 见
#      batch-poster/src/{config,batch,status}.rs）；
#   2. 钉扎对拍：proving-tool/prove-batch.sh 的 EXPECTED_PH ↔
#      batch-poster/src/config.rs FoldConfig::default program_hash 同值
#      （「改程序源码换哈希时三处同步」纪律的冒烟锚；第三处 =
#      stark_final.rs 钉扎，改动时人工核对）；
#   3. status 只读探测：临时 WAL/sidecar 上跑 `batch-poster status`，
#      校验监控最小集 JSON 字段齐全（survey §9.7）。
#
# 真机出证（prove-batch.sh，~52s/批 @K=64）是**手动验收项**，本脚本绝不
# 执行它——prove-batch.sh 头注同口径。

set -euo pipefail
command -v python3 >/dev/null 2>&1 || { echo "FAIL python3 不存在" >&2; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "FAIL cargo 不存在" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== 1/3 单元面：cargo test -p batch-poster --lib"
cargo test -p batch-poster --lib

echo "== 2/3 钉扎对拍：EXPECTED_PH ↔ FoldConfig::default"
SCRIPT_PH="$(grep -o 'EXPECTED_PH="0x[0-9a-fA-F]*"' proving-tool/prove-batch.sh \
  | head -1 | sed 's/^EXPECTED_PH="//; s/"$//')"
CONFIG_PH="$(grep -A1 'expected_program_hash:' batch-poster/src/config.rs \
  | grep -o '0x[0-9a-fA-F]\{64\}' | head -1)"
[ -n "$SCRIPT_PH" ] || { echo "FAIL prove-batch.sh 未找到 EXPECTED_PH 钉扎行" >&2; exit 1; }
[ -n "$CONFIG_PH" ] || { echo "FAIL config.rs 未找到 program_hash 钉扎值" >&2; exit 1; }
if [ "$SCRIPT_PH" != "$CONFIG_PH" ]; then
  echo "FAIL 钉扎失配: prove-batch.sh=$SCRIPT_PH config.rs=$CONFIG_PH" >&2
  echo "     （换程序哈希时 prove-batch.sh / config.rs / stark_final.rs 三处必须同步）" >&2
  exit 1
fi
echo "OK 钉扎同值: $SCRIPT_PH"

echo "== 3/3 status 只读探测（临时 WAL/sidecar，不触网）"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
: > "$TMP/queue.jsonl"
BIN="${BATCH_POSTER_BIN:-$ROOT/target/debug/batch-poster}"
if [ ! -x "$BIN" ]; then
  echo "   二进制缺失，先构建：cargo build -p batch-poster"
  cargo build -p batch-poster
fi
TEXAS_POSTER_QUEUE_WAL="$TMP/queue.jsonl" \
TEXAS_POSTER_SIDECAR_DIR="$TMP/poster-sidecar" \
  "$BIN" status > "$TMP/status.json"
python3 - "$TMP/status.json" <<'PYEOF'
import json
import sys

st = json.load(open(sys.argv[1]))
required = [
    "pending_tasks",
    "pending_batches",
    "oldest_batch_age_secs",
    "in_flight_txs",
    "txmgr_halted",
    "draining",
    "operator_balance",
]
missing = [k for k in required if k not in st]
assert not missing, f"status JSON 缺字段 {missing}（survey §9.7 监控最小集）"
snapshot = {k: st[k] for k in required}
print("OK status 只读探测：监控最小集字段齐全", snapshot)
PYEOF

echo "SMOKE PASS：单元面 + 钉扎对拍 + status 探测全部通过（真实出证仍属手动验收项）"
