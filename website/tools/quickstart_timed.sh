#!/usr/bin/env bash
# WEB-ACC-3：quickstart 本机计时器。
#
# 按 website/content/docs/getting-started/quickstart.md 的步骤逐步计时并输出
# 总墙钟（quickstart 文档步骤 = 克隆 → 构建 → 3 节点 devnet → 一手带真实证明
# → 验证）。克隆步骤在本机场景不适用（已在本仓库内），故从构建起算并如实
# 标注；"干净环境（新 clone + 无 cargo 缓存）需另行测量"见 website/ACCEPTANCE.md。
#
# 用法（任意目录）：
#   website/tools/quickstart_timed.sh                 # 温缓存模式（现状构建）
#   website/tools/quickstart_timed.sh --partial-clean # 先 cargo clean -p zchain -p poker_l1
#                                                     #  （模拟部分干净度；完整
#                                                     #  cargo clean 全量重建太慢，不做）
# 环境变量：
#   QUICKSTART_TIMED_JSON=<path>  额外写出 JSON 结果
# 退出码：0 = 全部步骤成功；1 = 任一步骤失败。

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

MODE="warm"
if [ "${1:-}" = "--partial-clean" ]; then
  MODE="partial-clean"
fi

# ---- 计时辅助（秒，1 位小数）----
S_TOTAL=${S_TOTAL:-0}
declare -a STEP_NAMES=()
declare -a STEP_SECS=()

timed() {
  local name="$1"; shift
  local t0 t1 rc
  echo ""
  echo "=== [$name] $*"
  t0=$(python3 -c 'import time;print(time.time())')
  "$@"
  rc=$?
  t1=$(python3 -c 'import time;print(time.time())')
  if [ "$rc" -ne 0 ]; then
    echo "=== [$name] FAILED (exit $rc)" >&2
    exit 1
  fi
  local secs
  secs=$(python3 -c "print(f'{$t1 - $t0:.1f}')")
  STEP_NAMES+=("$name")
  STEP_SECS+=("$secs")
  S_TOTAL=$(python3 -c "print(f'{$S_TOTAL + $secs:.1f}')")
  echo "=== [$name] OK: ${secs}s"
}

echo "quickstart_timed: repo=$ROOT mode=$MODE"
echo "note: 克隆步骤不适用（已在本仓库内），计时从构建起算（如实标注）"

if [ "$MODE" = "partial-clean" ]; then
  # 模拟部分干净度：清掉 zchain 与 poker_l1 的 release 工件（下游 zchain/
  # poker-appchain/loadtest 会被迫重建）。注意 nightly cargo 需显式 --release，
  # 否则只清 dev profile（"Removed 0 files"，等于没清——本机 cargo
  # 1.97.0-nightly 实测）。
  timed "0a partial-clean (release)" cargo clean --release -p zchain -p poker_l1
fi

# 步骤 1：构建（quickstart §1；克隆不适用见上）
timed "1 cargo build --release --bin zchain" cargo build --release --bin zchain

# 步骤 2：3 节点 devnet（quickstart §2；release 二进制路径见文档说明）
timed "2 multi_node_e2e.sh 3" env ZCHAIN_BIN="$ROOT/target/release/zchain" "$ROOT/scripts/multi_node_e2e.sh" 3

# 步骤 3a：单桌演示 loadtest（quickstart §3）
timed "3a loadtest" cargo run -p poker-appchain --release --bin loadtest

# 步骤 3b：完整一手 E2E（真实 stwo 出证；poker-appchain-texasair 是自带
# lockfile/target 的独立 crate，必须在其目录内调用——文档按 -p 书写，此处
# 如实采用等价的可执行形式）
timed "3b e2e_full_hand" cargo test --release --manifest-path "$ROOT/poker-appchain-texasair/Cargo.toml" --test e2e_full_hand -- --nocapture

# 步骤 4：验证（适配器 crate 负例回归全套；perf_baseline 标 #[ignore] 不计入）
timed "4 cargo test (texasair suite)" cargo test --release --manifest-path "$ROOT/poker-appchain-texasair/Cargo.toml"

# ---- 汇总 ----
echo ""
echo "=== quickstart_timed summary (mode=$MODE) ==="
for i in "${!STEP_NAMES[@]}"; do
  printf '%-45s %8ss\n' "${STEP_NAMES[$i]}" "${STEP_SECS[$i]}"
done
printf '%-45s %8ss\n' "TOTAL (excludes git clone; see notes)" "${S_TOTAL}"
echo "=== notes: 干净环境（新 clone / 无 cargo 缓存）需另行测量；本次为 $MODE 模式 ==="

if [ -n "${QUICKSTART_TIMED_JSON:-}" ]; then
  python3 - "$QUICKSTART_TIMED_JSON" "$MODE" "$S_TOTAL" "${STEP_NAMES[@]}" "${STEP_SECS[@]}" <<'PYEOF'
import json, sys
out, mode, total, *rest = sys.argv[1:]
steps = list(zip(rest[: len(rest) // 2], rest[len(rest) // 2:]))
json.dump({"mode": mode, "total_s": float(total), "steps": [{"name": n, "seconds": float(s)} for n, s in steps]},
          open(out, "w"), ensure_ascii=False, indent=2)
PYEOF
fi
exit 0
