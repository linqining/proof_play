#!/usr/bin/env bash
# =============================================================================
# prove-batch.sh —— L1 批量终证腿入口包装（单跑单证 → 单个 STARK 终证）。
#
# 两阶段流程（stark-recursion/src/bin/batch_inputs.rs 生成输入/清单）：
#   阶段 A：合成 K 手占位输入 → 出证 → 取 program_hash 与真实公开段
#   阶段 B：host 派生语句/keccak 批根 → 带真实链尾（acc/hi/lo）二次出证
#           → 电路内 batch_fact 与宿主镜像逐字对拍（fail-closed）
#
# 参数钉扎：
#   - 程序：proving-tool/src/settlement_batch_private.cairo（9 人桌迁移
#     2026-09-30：HAND_INPUT_LEN 98→102、批段 16→17 词；基础手输入须为
#     102 词、全席非零参与者语料）
#     program_hash = 0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d
#     （K=1 真出证重钉；改程序源码必换哈希 → 同步更新 stark-recursion
#      stark_final.rs 与 fact-verify 的钉扎常量）
#   - 证明参数：params/canonical_small.json（≤6G 内存硬约束的成立前提；
#     K=1 实测 1.87 GiB，K=64 实测 3.69 GiB，/usr/bin/time -l 2026-09-29）
#
# 用法：proving-tool/prove-batch.sh <K> <base_hand_inputs.json> <out_dir> [acc_hex]
#   K ∈ {1,2,4,…,64}；acc_hex = 累加链接入（批 n-1 的 fact；缺省 0x0 = genesis）
# 退出码：对拍失败 / 验证失败非 0（fail-closed）。
#
# 运维边界（2026-10-01）：本脚本是**真机出证腿**（~52s/批 @K=64，手动验收
# 项，不进自动化冒烟）；干跑对拍（参数/路径/EXPECTED_PH↔poster 配置钉扎）
# 用 scripts/batch-poster-smoke.sh；daemon 侧钉扎同值见
# batch-poster/src/config.rs FoldConfig::default——改程序源码换哈希时
# 三处（EXPECTED_PH 行 / config.rs / stark_final.rs 钉扎）必须同步。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

K="${1:?用法: prove-batch.sh <K> <base_hand_inputs.json> <out_dir> [acc_hex]}"
BASE="${2:?base_hand_inputs.json 缺失}"
OUT="${3:?out_dir 缺失}"
ACC="${4:-0x0}"
BIN=./target/release/prove-hand
PARAMS=params/canonical_small.json
STARK_RECURSION=../stark-recursion

python3 -c "k=int('${K}'); assert 1<=k<=64 and k & (k-1)==0, 'K 必须是 1..64 的 2 的幂'" \
  || { echo "error: K=${K} 非法" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "error: $BIN 不存在（先 cargo build --release）" >&2; exit 1; }
[[ -f "$BASE" ]] || { echo "error: $BASE 不存在" >&2; exit 1; }
[[ -f "$PARAMS" ]] || { echo "error: $PARAMS 不存在" >&2; exit 1; }

mkdir -p "$OUT"

echo "==> [阶段 A] 合成 ${K} 手 + 占位链尾出证"
cargo run -q -p stark-recursion --bin batch-inputs --manifest-path "$STARK_RECURSION/Cargo.toml" -- \
  --phase a --base-input "$BASE" --hands "$K" --out-inputs "$OUT/in_a.json"
"$BIN" --program src/settlement_batch_private.cairo --inputs "$OUT/in_a.json" \
  --params "$PARAMS" --out-dir "$OUT/run_a"

PH=$(python3 -c "import json;print('0x%064x' % int(json.load(open('$OUT/run_a/public_outputs.json'))['program_hash'],16))")
echo "    program_hash = $PH"
EXPECTED_PH="0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d"
if [[ "$PH" != "$EXPECTED_PH" ]]; then
  echo "error: program_hash ${PH} != pinned ${EXPECTED_PH} (program source drift - update stark_final.rs / fact-verify pinning first)" >&2
  exit 1
fi

echo "==> [阶段 B] host 派生批根/链尾 → 真实链尾出证"
cargo run -q -p stark-recursion --bin batch-inputs --manifest-path "$STARK_RECURSION/Cargo.toml" -- \
  --phase b --base-input "$BASE" --hands "$K" --acc "$ACC" \
  --program-hash "$PH" --from-output "$OUT/run_a/public_outputs.json" \
  --out-inputs "$OUT/in_b.json" --out-manifest "$OUT/manifest.json"

"$BIN" --program src/settlement_batch_private.cairo --inputs "$OUT/in_b.json" \
  --params "$PARAMS" --out-dir "$OUT/run_b"

echo "==> [对拍] 电路内 batch_fact / 根回显 ↔ 宿主镜像"
python3 - "$OUT/manifest.json" "$OUT/run_b/public_outputs.json" <<'EOF'
import json, sys
m = json.load(open(sys.argv[1])); o = json.load(open(sys.argv[2]))
n = lambda s: int(s, 16)
tail = [n(x) for x in o['output'][-4:]]
assert tail[0] == n(m['acc_prev']), "acc 回显不符"
assert tail[1] == n(m['root_hi']) and tail[2] == n(m['root_lo']), "批根 hi/lo 回显不符"
assert tail[3] == n(m['expected_batch_fact']), "电路内 batch_fact != 宿主镜像"
assert len({s['hand_binding'] for s in m['statements']}) == m['k'], "binding 重复"
print(f"[OK] K={m['k']} acc_prev={m['acc_prev'][:18]}… root=0x{m['keccak_batch_root'][2:18]}… batch_fact=0x{m['expected_batch_fact'][2:18]}… 电路↔宿主逐字一致")
EOF

echo "prove-batch: OK -> ${OUT} (proof = ${OUT}/run_b/proof.json, manifest = ${OUT}/manifest.json)"
