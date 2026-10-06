#!/usr/bin/env bash
# pin_fold_program_hash.sh —— D3b 自动化：fold 批程序哈希发布钉扎。
#
# 每次发布跑一次（幂等）：K=1 真出证提取实测 program_hash → 自动更新
# stark_final.rs 的 FOLD_BATCH_PROGRAM_HASH_HEX → 复跑在库测试验证钉扎。
# 不需要人工读哈希、填常量；程序源码（fold_batch.cairo）未变时为无操作。
#
# 原理：program_hash 只钉程序（源码 + prove-hand 编译器版本），不钉输入与
# prover 参数（combined 侧 2026-09-29 三组参数一致已实证）——故 K=1 最小批
# 出证即为发布哈希。改了 fold_batch.cairo 必然换哈希，本脚本自动改钉。
#
# 部署提醒：落库后合约侧由 owner 调 set_fold_program_hash(<打印的哈希>)；
# 链下 fact-verify 用 fact-verify <proof.json> --expect-program-hash <哈希>。
#
# 用法：bash scripts/pin_fold_program_hash.sh
# 退出码：0 = 钉扎一致或已更新且测试全绿；非 0 = 出证失败/写失败/测试红。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CONST_FILE="$ROOT/stark-recursion/src/stark_final.rs"
SUMMARY="$ROOT/poker_contracts/hand-verify-native/output/fold-batch-test/t7-k1/public_outputs.json"

cd "$ROOT"

# 1) 出证工具（prove-hand 烙死了 corelib 绝对路径，本机构建即发布口径）
if [ ! -x proving-tool/target/release/prove-hand ]; then
  echo "== 构建 prove-hand =="
  (cd proving-tool && cargo build --release)
fi

# 2) K=1 最小批真出证（含 T7 断言：K=1 ≤ combined 12,160 + keyagg 1,628 验收线）
echo "== K=1 真出证（FOLD_PERF_ONLY=1 跑 t7） =="
FOLD_PERF_ONLY=1 cargo test --release -p hand-verify-native \
  --test fold_batch_test t7 -- --ignored --nocapture | tail -6

# 3) 提取实测哈希（prove-hand 写 public_outputs.json 的 "program_hash"）；
#    归一化到 felt_to_hex 口径：0x + 恰好 64 位十六进制（前导补零——prove-hand
#    的 "0x{:x}" 会吞掉前导零，combined 钉值 0x05c4… 即补零形态）
HASH=$(python3 -c "import json; print('0x' + json.load(open('$SUMMARY'))['program_hash'][2:].zfill(64))")
case "$HASH" in 0x[0-9a-f]*) ;; *) echo "FATAL: 提取到非预期哈希格式: $HASH" >&2; exit 1;; esac
echo "实测 program_hash = $HASH"

# 4) 幂等比对（空串 = fail-closed 待钉状态，与「常量缺失」区分开）
if ! CURRENT=$(python3 - "$CONST_FILE" <<'EOF'
import re, sys
m = re.search(r'FOLD_BATCH_PROGRAM_HASH_HEX: &str = "([^"]*)"', open(sys.argv[1]).read())
if not m:
    sys.exit(1)
print(m.group(1))
EOF
); then echo "FATAL: 未找到 FOLD_BATCH_PROGRAM_HASH_HEX 常量" >&2; exit 1; fi
if [ "$CURRENT" = "$HASH" ]; then
  # 注意：macOS bash 3.2 会把紧邻的多字节字符吞进变量名（$HASH）→ 报
  # unbound variable，故变量后必须跟 ASCII 字符
  echo "钉值未变: $HASH ——程序源码与上次发布一致，无操作"
  exit 0
fi

# 5) 自动改钉（只动常量字符串，一处）
python3 - "$CONST_FILE" "$HASH" <<'EOF'
import re, sys
path, new = sys.argv[1], sys.argv[2]
s = open(path).read()
s2, n = re.subn(r'(FOLD_BATCH_PROGRAM_HASH_HEX: &str = )"[^"]*"', rf'\g<1>"{new}"', s, count=1)
assert n == 1, "FOLD_BATCH_PROGRAM_HASH_HEX 替换点数 != 1"
open(path, "w").write(s2)
EOF
echo "已改钉: \"${CURRENT:-<空串 fail-closed>}\" -> $HASH"

# 6) 验证：在库测试（含钉扎两态测试：访问器必须精确还原钉值）
cargo test -p stark-recursion --lib 2>&1 | tail -3

echo "== 完成 =="
echo "  stark-recursion 钉扎: FOLD_BATCH_PROGRAM_HASH_HEX = $HASH"
echo "  部署时 owner 调:      set_fold_program_hash($HASH)"
echo "  链下 fact-verify:     --expect-program-hash $HASH"
