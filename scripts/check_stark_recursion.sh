#!/usr/bin/env bash
# stark-recursion 门禁：递归聚合链 crate 测试全绿（以退出码判定，无手工判读）。
#
# 终证路线（2026-09-29 裁定）：终证 = 单个 STARK 终证（L1 批证明腿），
# Groth16 全出局（仅作对照基线，feature groth16-baseline 隔离）。
#
# 默认门禁（终证路径，无 Groth16）：
#   - lib 单测：host 公式镜像（fact/keccak 根/H1/split-join/batch_fact 镜像）、
#     折叠计划、累加链接（batch_fact 链头语义）、L1 终证输出解析/全链验证、
#     submitFinalProof STARK calldata 金字节、wire 类型对齐、内存预算闸门
#     （含 K=64 实测锚点 3.69GiB）；
#   - tests/final_k2（K=2 默认门禁样本，<10 分钟预算，实测 <1s）：批语句 →
#     keccak 根 → L1 终证语句面 → 电路内链接对拍 → 双批累加链（换链拒绝）→
#     STARK calldata + FinalEnvelope 往返 → mock 折叠树语句面。
#
# 对照基线门禁（--baseline 时追加；真 Groth16 出证，~8 分钟）：
#   cargo test -p stark-recursion --features groth16-baseline
#
# 用法：bash scripts/check_stark_recursion.sh [--baseline] [额外 cargo test 参数]
# 退出码：cargo test 的退出码（0 = 全绿）。
set -uo pipefail
cd "$(dirname "$0")/.."

BASELINE=0
if [ "${1:-}" = "--baseline" ]; then
  BASELINE=1
  shift
fi

echo "[check_stark_recursion] cargo test -p stark-recursion $*"
cargo test -p stark-recursion "$@"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "[check_stark_recursion] FAIL (exit=$rc)"
  exit "$rc"
fi

if [ "$BASELINE" -eq 1 ]; then
  echo "[check_stark_recursion] cargo test -p stark-recursion --features groth16-baseline $*（对照基线，含 K=2 Groth16 真出证）"
  cargo test -p stark-recursion --features groth16-baseline "$@"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[check_stark_recursion] BASELINE FAIL (exit=$rc)"
    exit "$rc"
  fi
fi

echo "[check_stark_recursion] OK"
