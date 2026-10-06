#!/usr/bin/env bash
# =============================================================================
# fold-batch-e2e-smoke.sh —— 自定义折叠「攒批 → 出证 → L1 提交面」全链路真跑
# 冒烟（**出证真实、上链 dry**）。
#
# 三层（对应 2026-10-01 首次全链路真跑验证，修复见 batch-poster/src/proof.rs）：
#   Tier 1  proving-tool/prove-batch.sh <K> 真出证（两阶段 + 电路↔宿主
#           batch_fact/批根逐字对拍，fail-closed）。
#   Tier 2  batch-poster daemon：queue WAL 攒批 → ScriptProofSource 真出证
#           → program_hash 钉扎对拍（64 位补零口径）→ 双宿主 keccak 批根
#           交叉核对 → MonadProofEnvelope spool；提交腿打本地
#           starknet-devnet（dummy operator → txmgr 卡头 = dry 边界）。
#   Tier 3  zchain monad_settlementd --mode settle：消费 spool（ingest+parse）
#           → 链身份闸门 → 签名提交打内嵌 EVM stub（eth_sendRawTransaction
#           一律拒绝 = 保证不真实上链）→ 状态机 awaiting verification +
#           状态文件落盘。
#
# 用法：scripts/fold-batch-e2e-smoke.sh [K]        # K ∈ {1,2,4}，默认 2
#   K=2 全程 ~3 分钟（两阶段两轮真出证）；K=64 内存 ~3.7GiB 勿在冒烟跑。
# 环境变量：
#   ZCHAIN_ROOT   zchain 仓路径（缺省 ../zchain；不可用时跳过 Tier 3）
#   DEVNET_BIN    starknet-devnet 可执行（缺省 ~/.local/bin/starknet-devnet）
# 前置：proving-tool/target/release/prove-hand（先 cargo build --release
#       -p prove-tool）、cargo（batch-poster debug 构建）、python3。
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K="${1:-2}"
ZCHAIN_ROOT="${ZCHAIN_ROOT:-$ROOT/../zchain}"
DEVNET_BIN="${DEVNET_BIN:-$HOME/.local/bin/starknet-devnet}"
WORK="$(mktemp -d /tmp/fold-batch-e2e.XXXXXX)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  pkill -f "evm_stub_fold_e2e" 2>/dev/null || true
}
trap cleanup EXIT
BASE="$ROOT/proving-tool/params/base_hand_inputs.e2e.json"
[[ -f "$BASE" ]] || { echo "FAIL 缺 $BASE（确定性 102 词 settle wire 语料）" >&2; exit 1; }
[[ -x "$ROOT/proving-tool/target/release/prove-hand" ]] || {
  echo "FAIL proving-tool/target/release/prove-hand 缺失（先：cd proving-tool && cargo build --release -p prove-tool）" >&2; exit 1; }

echo "== Tier 1/3  prove-batch.sh K=$K 真出证（两阶段 + 对拍）"
( cd "$ROOT/proving-tool" && ./prove-batch.sh "$K" "$BASE" "$WORK/tier1" ) > "$WORK/tier1.log" 2>&1 \
  || { echo "FAIL prove-batch.sh 非零退出（对拍/验证 fail-closed），日志 $WORK/tier1.log" >&2; tail -20 "$WORK/tier1.log" >&2; exit 1; }
grep -q "prove-batch: OK" "$WORK/tier1.log" || { echo "FAIL Tier1 未打 OK 行" >&2; exit 1; }
echo "   OK manifest=$(ls "$WORK/tier1/manifest.json")"

echo "== Tier 2/3  batch-poster daemon：攒批 → 真出证 → envelope spool（提交 dry）"
cargo build -p batch-poster > /dev/null 2>&1
python3 - "$WORK" "$K" <<'PYEOF'
# 队列 WAL：条目 fold_statement 直接取 Tier 1 manifest 的 statements
#（确定性语料 → poster 复证批根与双宿主对拍必然一致）。
import json, sys, time
work, k = sys.argv[1], int(sys.argv[2])
m = json.load(open(f"{work}/tier1/manifest.json"))
stmts = m["statements"]
assert len(stmts) == k, f"manifest 手数 {len(stmts)} != K={k}"
lines = []
for i, st in enumerate(stmts):
    leg = {"selector": "0x1", "calldata": ["0xdeadbeef"]}
    task = {
        "key": {"table_id": 1, "hand_id": 101 + i},
        "route": "Dual",
        "dapv_entry": "v2",
        "payload": {
            "register": leg, "settle": leg,
            "fold_statement": {"program_hash": st["program_hash"],
                               "hand_binding": st["hand_binding"], "fact": st["fact"]},
        },
        "legacy_fallback": None, "created_at": int(time.time()),
    }
    lines.append(json.dumps({"seq": i + 1,
                             "event": {"type": "enqueued", "task": task}}))
open(f"{work}/queue.jsonl", "w").write("\n".join(lines) + "\n")
PYEOF
if [[ ! -x "$DEVNET_BIN" ]]; then echo "FAIL starknet-devnet 缺失（$DEVNET_BIN）——Tier 2 提交面需要可探活的 RPC" >&2; exit 1; fi
"$DEVNET_BIN" --host 127.0.0.1 --port 5099 --seed 7 > "$WORK/devnet.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do
  curl -sf -m 2 -X POST http://127.0.0.1:5099 -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"starknet_chainId","params":[]}' > /dev/null 2>&1 && break
  sleep 1
done
mkdir -p "$WORK/sidecar" "$WORK/spool" "$WORK/poster-work"
env \
  TEXAS_POSTER_QUEUE_WAL="$WORK/queue.jsonl" \
  TEXAS_POSTER_SIDECAR_DIR="$WORK/sidecar" \
  TEXAS_MONAD_SPOOL_DIR="$WORK/spool" \
  TEXAS_POSTER_FOLD_ENABLED=1 \
  TEXAS_POSTER_PROVE_SCRIPT="$ROOT/proving-tool/prove-batch.sh" \
  TEXAS_POSTER_PROVE_BASE_INPUT="$BASE" \
  TEXAS_POSTER_PROVE_WORK_DIR="$WORK/poster-work" \
  TEXAS_POSTER_MIN_BATCH_HANDS="$K" \
  TEXAS_POSTER_MAX_BATCH_HANDS="$K" \
  STARKNET_RPC_URL=http://127.0.0.1:5099 \
  STARKNET_OPERATOR_ADDRESS=0x1 \
  STARKNET_OPERATOR_PRIVATE_KEY=0x1 \
  TEXAS_POSTER_OPERATOR=0x1 \
  TEXAS_POSTER_LEGACY_SETTLEMENT=0x2 \
  TEXAS_POSTER_DUAL_SETTLEMENT=0x3 \
  timeout 240 "$ROOT/target/debug/batch-poster" run --bind 127.0.0.1:17331 \
  > "$WORK/tier2.log" 2>&1 || true
ENV_FILE=$(ls "$WORK/spool"/*.json 2>/dev/null | head -1)
[[ -n "$ENV_FILE" ]] || { echo "FAIL Tier2 未产出 envelope（日志 $WORK/tier2.log）" >&2; grep "batch-poster" "$WORK/tier2.log" | tail -5 >&2; exit 1; }
python3 - "$ENV_FILE" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
expected = {"version", "acc_prev", "batch_fact", "keccak_root",
            "output_commit", "program_hash", "proof_bz2_b64", "created_at"}
missing = expected - set(d)
assert not missing, f"envelope 缺字段 {missing}"
ph = d["program_hash"].removeprefix("0x")
assert len(ph) == 64, f"program_hash 未补零到 64 位: {d['program_hash']}"
assert len(d["proof_bz2_b64"]) > 1_000_000, "proof 体量异常"
print(f"   OK envelope keccak_root={d['keccak_root'][:18]}… proof={len(d['proof_bz2_b64'])//1024}KiB")
PYEOF
echo "   OK envelope 落盘（提交腿在 devnet 上 dry：dummy operator 卡头即边界）"

echo "== Tier 3/3  zchain monad_settlementd --mode settle 消费 spool（提交 dry）"
SETTLED_BIN=""
for c in "$ZCHAIN_ROOT/target/debug/monad_settlementd" "$ZCHAIN_ROOT/target/release/monad_settlementd"; do
  [[ -x "$c" ]] && SETTLED_BIN="$c" && break
done
if [[ -z "$SETTLED_BIN" ]]; then
  if [[ -d "$ZCHAIN_ROOT" ]]; then
    ( cd "$ZCHAIN_ROOT" && cargo build -p monad-settlement ) > /dev/null 2>&1 \
      && SETTLED_BIN="$ZCHAIN_ROOT/target/debug/monad_settlementd"
  fi
fi
if [[ -z "$SETTLED_BIN" || ! -x "$SETTLED_BIN" ]]; then
  echo "   SKIP（zchain monad_settlementd 不可用：ZCHAIN_ROOT=$ZCHAIN_ROOT）"
else
  cat > "$WORK/evm_stub.py" <<'PYEOF'
# EVM JSON-RPC 桩：只读应答固定值；eth_sendRawTransaction 一律拒绝（dry 上链边界）。
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
READONLY = {"eth_chainId": "0x7e2", "eth_blockNumber": "0x1", "eth_gasPrice": "0x1",
            "eth_getTransactionCount": "0x0", "eth_getBalance": "0x0"}
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = body.get("method", "")
        if method == "eth_sendRawTransaction":
            out = {"jsonrpc": "2.0", "id": body.get("id"),
                   "error": {"code": -32003, "message": "dry-run stub: tx rejected"}}
        elif method in READONLY:
            out = {"jsonrpc": "2.0", "id": body.get("id"), "result": READONLY[method]}
        else:
            out = {"jsonrpc": "2.0", "id": body.get("id"),
                   "error": {"code": -32000, "message": f"dry-run stub: {method} rejected"}}
        resp = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)
    def log_message(self, *a):
        pass
HTTPServer(("127.0.0.1", 5998), H).serve_forever()
PYEOF
  python3 "$WORK/evm_stub.py" > /dev/null 2>&1 &
  PIDS+=($!)
  sleep 1
  SETTLE_KEY="0x$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  ( cd "$ZCHAIN_ROOT" && env MONAD_SETTLE_KEY="$SETTLE_KEY" timeout 25 \
      "$SETTLED_BIN" --mode settle \
      --l1-rpc http://127.0.0.1:5998 --expected-chain-id 2018 \
      --settle-key-env MONAD_SETTLE_KEY \
      --stark-verifier 0x000000000000000000000000000000000000dEaD \
      --settle-inbox "$WORK/spool" \
      --state-file "$WORK/settle-dispatch-state.json" \
      --poll-interval-ms 2000 ) > "$WORK/tier3.log" 2>&1 || true
  grep -q "new envelope(s) enqueued" "$WORK/tier3.log" \
    || { echo "FAIL Tier3 未消费 envelope（日志 $WORK/tier3.log）" >&2; tail -5 "$WORK/tier3.log" >&2; exit 1; }
  grep -q "tx rejected" "$WORK/tier3.log" || { echo "FAIL Tier3 提交未触达 dry 边界" >&2; exit 1; }
  [[ -f "$WORK/settle-dispatch-state.json" ]] || { echo "FAIL Tier3 状态文件未落盘" >&2; exit 1; }
  echo "   OK ingest+parse 通过；提交在 stub 处 dry 拒绝；状态机 awaiting verification"
fi

echo ""
echo "fold-batch-e2e-smoke: PASS (K=${K}, artifacts ${WORK})"
