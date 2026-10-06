#!/usr/bin/env bash
# P2-M2 结算电路端到端验证（prove-hand 管线）：
#   1. Rust 参考实现（starknet_crypto）生成 fixtures（inputs + 期望公开段）；
#   2. Cairo1 电路（settlement_private.cairo）经 prove-hand：编译 → Cairo VM
#      见证 → Stwo 证明 → 独立 verify；
#   3. 跨语言对齐：证明的公开段与 Rust 期望逐 felt 比对；
#   4. 负例：registered_digest 篡改 → 电路中止 → 不得产出证明。
# Span ABI（2026-09-30 重构 + 9 人桌）：inputs = [102] ++ settle wire 102 词
# （flat [len, elements…] 摊平，与 combined / batch 同约定）。
# 用法：proving-tool/scripts/prove-settlement.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_FIXTURES="${OUT_FIXTURES:-/tmp/settlement-prove}"
OUT_PROVE="${OUT_PROVE:-$ROOT/proving-tool/output/settlement}"

echo "[1/4] 生成 Rust 参考夹具（starknet_crypto）"
SETTLEMENT_PROVE_FIXTURES_OUT="$OUT_FIXTURES" \
    cargo test -q -p poker_texas_air --lib settlement_private_circuit::tests::write_prove_hand_fixtures

echo "[2/4] prove-hand：Cairo VM 见证 + Stwo 证明 + verify"
time "$ROOT/proving-tool/prove-hand.sh" \
    --program "$ROOT/proving-tool/src/settlement_private.cairo" \
    --inputs "$OUT_FIXTURES/settlement_inputs.json" \
    --out-dir "$OUT_PROVE"

echo "[3/4] 跨语言对齐：公开段 vs Rust 期望"
python3 - "$OUT_PROVE/public_outputs.json" "$OUT_FIXTURES/settlement_expected_outputs.json" <<'EOF'
import json, sys
public = json.load(open(sys.argv[1]))["output"]
expected = json.load(open(sys.argv[2]))
magic = expected[0]
idx = public.index(magic)  # 公开段头部是 runner 的长度/参数回显，从 MAGIC 定位
got = public[idx : idx + len(expected)]
assert got == expected, f"public segment mismatch:\n got      ={got}\n expected={expected}"
print(f"OK: {len(expected)} felts aligned from MAGIC (head echo = {idx} word(s))")
EOF

echo "[4/4] 负例：registered_digest 篡改必须中止（不得产出证明）"
python3 - "$OUT_FIXTURES/settlement_inputs.json" "$OUT_FIXTURES/settlement_expected_outputs.json" <<'EOF'
import json, sys
inputs = json.load(open(sys.argv[1]))
expected = json.load(open(sys.argv[2]))
inputs[2] = expected[0]  # 把 registered_digest（flat[2] = [len]++wire[1]）换成 MAGIC → digest 必不匹配
json.dump(inputs, open(sys.argv[1] + ".tampered", "w"))
EOF
if "$ROOT/proving-tool/prove-hand.sh" \
    --program "$ROOT/proving-tool/src/settlement_private.cairo" \
    --inputs "$OUT_FIXTURES/settlement_inputs.json.tampered" \
    --out-dir "$OUT_PROVE.tampered" > /dev/null 2>&1; then
    echo "FAIL: tampered digest produced a proof" >&2
    exit 1
fi
echo "OK: tampered digest rejected (run aborted, no proof)"

echo "[4b/4] 负例：非法默认动作（auto FOLD 篡改为 Check）必须中止——#18 Phase C 切片 2"
python3 - "$OUT_FIXTURES/settlement_inputs.json" <<'PYEOF'
import json, sys
inputs = json.load(open(sys.argv[1]))
# settle wire 词条区起点 = 42（flat 再 +1 长度前缀）；槽 1 = auto FOLD 的
# 合法性词（kind=2 | owed=500·4 | …）。把 kind 位（低 2 位）从 2 改成 0
# （声称 Check）→ 电路规则必须拒绝。
idx = 1 + 42 + 3  # 槽 1 的合法性词（flat：42=log0, 43=leg0, 44=log1, 45=leg1）
leg = int(inputs[idx], 16)
assert leg % 4 == 2, f"fixture leg kind expected 2 (FOLD), got {leg % 4}"
inputs[idx] = hex(leg - 2)  # kind: 2 → 0（谎称 Check）
json.dump(inputs, open(sys.argv[1] + ".illegal", "w"))
PYEOF
if "$ROOT/proving-tool/prove-hand.sh" \
    --program "$ROOT/proving-tool/src/settlement_private.cairo" \
    --inputs "$OUT_FIXTURES/settlement_inputs.json.illegal" \
    --out-dir "$OUT_PROVE.illegal" > /dev/null 2>&1; then
    echo "FAIL: illegal auto action produced a proof" >&2
    exit 1
fi
echo "OK: illegal default action rejected (legal-default constraint live)"
echo "ALL PASS ✔"
