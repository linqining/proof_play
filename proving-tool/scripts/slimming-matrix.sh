#!/usr/bin/env bash
# #0 证明瘦身实测（SNIP36_INTEGRATION.md §5 #0）：
# 对 settlement_private 电路，扫描 FRI 参数矩阵，逐一测
#   security_bits / proof.json / cairo_serde felts / bincode 原始字节 /
#   bzip2 wire 字节 / prove+verify 耗时，落盘 JSON + Markdown 表。
#
# 安全公式（stwo FriConfig::security_bits）：pow_bits + log_blowup × n_queries。
# 生产默认（p0）= 26 + 1×70 = 96 bit；瘦身的正确方向是 b↑q↓（等安全换尺寸），
# 朴素 70→30 在 blowup=1 下只剩 56 bit——本矩阵将其列为对照组。
#
# 用法：proving-tool/scripts/slimming-matrix.sh [输出目录]
#   缺省输出 proving-tool/output/slimming/；夹具缺失时先走 prove-settlement 的
#   第一步自动生成。已验证的证明会经 prove-hand --check-only 复核。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/proving-tool/output/slimming}"
FIXTURES="${OUT_FIXTURES:-/tmp/settlement-prove}"
PROGRAM="$ROOT/proving-tool/src/settlement_private.cairo"
INPUTS="$FIXTURES/settlement_inputs.json"
PROVE="$ROOT/proving-tool/prove-hand.sh"

mkdir -p "$OUT"
if [[ ! -f "$INPUTS" ]]; then
    echo "[fixtures] 生成 settlement 输入夹具"
    SETTLEMENT_PROVE_FIXTURES_OUT="$FIXTURES" \
        cargo test -q --manifest-path "$ROOT/Cargo.toml" -p poker_texas_air \
        --lib settlement_private_circuit::tests::write_prove_hand_fixtures
fi

# name | pow_bits | log_blowup | n_queries | fold_step | log_last_layer | 备注
CONFIGS=(
  "p0-default-96    26 1 70 1 0  生产默认（96bit 基线）"
  "p1-q30-b1-56     26 1 30 1 0  对照组：朴素 70→30，安全塌到 56bit"
  "p2-b2-q35-96     26 2 35 1 0  等安全瘦身（b↑q↓，96bit）"
  "p3-b2-q35-fs4-96 26 2 35 4 0  等安全 + 折叠步 4（层更少）"
  "p4-b3-q24-98     26 3 24 1 0  b=3 收紧"
  "p5-b4-q18-98     26 4 18 1 0  b=4 收紧"
  "p6-b2-q47-fs2    26 2 47 2 0  加强参照（120bit）"
  "p7-b2-q35-llb3   26 2 35 1 3  末层度界 3（粗末层）"
)

printf "%-18s %6s %10s %12s %12s %12s %10s %8s %8s\n" \
  config sec_bits json felts u32x4 bincode bz2 prove_ms verify_ms
for cfg in "${CONFIGS[@]}"; do
  read -r name pow blow q fs llb note <<< "$cfg"
  params="$OUT/params-$name.json"
  cat > "$params" <<EOF
{
  "channel_hash": "blake2s",
  "channel_salt": 0,
  "fri_config": {
    "pow_bits": $pow,
    "log_last_layer_degree_bound": $llb,
    "log_blowup_factor": $blow,
    "n_queries": $q,
    "fold_step": $fs
  },
  "preprocessed_trace": "canonical",
  "store_polynomials_coefficients": false,
  "include_all_preprocessed_columns": false,
  "opt_n_id_to_big_components": null,
  "lifting_size_policy": "auto"
}
EOF
  dir="$OUT/$name"
  echo "[run] $name ($note)"
  if ! "$PROVE" --program "$PROGRAM" --inputs "$INPUTS" \
      --params "$params" --all-formats --out-dir "$dir" > "$dir.log" 2>&1; then
      # 单配置失败（如 b=4 内存耗尽被 OOM-kill）记为数据点，不中断矩阵。
      echo "$name                       FAIL（见 $dir.log；常见：高 blowup 内存不足）"
      continue
  fi
  # 证明可独立验证（fail-closed：参数换了的证明必须仍过 verify）
  "$PROVE" --check-only --proof "$dir/proof.json" --params "$params" \
      --out-dir "$dir" >> "$dir.log" 2>&1

  python3 - "$dir/summary.json" "$name" <<'PYEOF'
import json, sys
s = json.load(open(sys.argv[1]))
fri, sz, t = s["prover_params"]["fri_config"], s.get("sizes", {}), s["timings_ms"]
print(f"{sys.argv[2]:<18} {s['security_bits']:<6} "
      f"{sz.get('json_bytes',0):>10} {sz.get('cairo_serde_felts',0):>12} "
      f"{sz.get('snip36_u32_words_x4',0):>12} {sz.get('bincode_raw_bytes',0):>12} "
      f"{sz.get('binary_bz2_bytes',0):>12} {t['prove']:>8} {t['verify']:>8}")
PYEOF
done
echo
echo "done: artifacts under $OUT"
