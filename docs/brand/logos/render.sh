#!/usr/bin/env bash
# ProofPlay logo 出图与自检管线。可重跑: 改 build.py 里的几何后执行本脚本即可。
#
#   ./render.sh            生成 SVG + PNG 并跑全部断言
#
# 为什么要有断言 (都是踩过的坑):
#  1. 深浅底必须比 md5。只换 CSS/颜色而不改几何时, 夜场会静默产出与纸白逐字节
#     相同的假图; 光看图看不出来, 板子却会被当成验收依据。
#  2. 开口靠 stroke-dasharray 实现。librsvg 对 pathLength 支持不完整, 一旦哪天
#     有人改回 pathLength 写法, dash 会静默失效, 图变成"没有开口的圆", 肉眼在
#     小尺寸下分辨不出来。
#  3. 字标必须是路径。历史草案用 <text font-family="-apple-system">, 换机器就
#     变形; 任何 <text> 出现在 logo 生产文件里都是回归。
set -euo pipefail
cd "$(dirname "$0")"

python3 build.py

fail() { echo "ASSERT FAIL: $1" >&2; exit 1; }

# --- 渲染 PNG (评审板 + 生产文件) ---
for f in out/boards/*.svg out/*/favicon.svg out/*/app-icon.svg; do
    [ -e "$f" ] || continue
    rsvg-convert -f png -o "${f%.svg}.png" "$f"
done
for d in a b c pic-d pic-e pic-f pic-g pic-h pic-i; do
    rsvg-convert -w 1600 -f png -o "out/$d/logo-dark.png" "out/$d/logo-dark.svg"
    rsvg-convert -w 1600 -f png -o "out/$d/logo-light.png" "out/$d/logo-light.svg"
done

# --- 断言 1: 同一方案的深浅底不得逐字节相同 ---
for d in a b c pic-d pic-e pic-f pic-g pic-h pic-i; do
    for pair in "logo-dark logo-light" "mark-dark mark-light" "stack-dark stack-light"; do
        set -- $pair
        [ -f "out/$d/$1.svg" ] && [ -f "out/$d/$2.svg" ] || continue
        h1=$(md5 -q "out/$d/$1.svg"); h2=$(md5 -q "out/$d/$2.svg")
        [ "$h1" != "$h2" ] || fail "$d: $1 与 $2 内容完全相同 (双底未生效)"
    done
done

# --- 断言 2: 开口必须存在 ---
grep -q 'stroke-dasharray' out/b/logo-dark.svg || fail "b: 字腔开口丢失 (无 stroke-dasharray)"
grep -q 'stroke-dasharray' out/a/logo-dark.svg || fail "a: 方印开口丢失"
grep -q 'pathLength' out/*/*.svg && fail "检测到 pathLength: librsvg 支持不完整, 改用真实用户单位"

# --- 断言 3: logo 生产文件里不允许出现 <text> ---
for d in a b c pic-d pic-e pic-f pic-g pic-h pic-i; do
    for f in mark-dark mark-light mark-mono app-icon favicon; do
        [ -f "out/$d/$f.svg" ] || continue
        grep -q '<text' "out/$d/$f.svg" && fail "$d/$f: 标志里出现 <text>, 字标必须是路径"
    done
done

# --- 断言 4: 每个 SVG 都能被栅格化器解析 ---
# 注意: rsvg-convert 拒绝把 /dev/null 当输出 ("目标文件不是普通文件"), 用临时文件。
CHK=$(mktemp -t rsvgchk).png
for f in $(find out -name '*.svg'); do
    rsvg-convert -f png -o "$CHK" "$f" || fail "$f 解析失败"
done
rm -f "$CHK"

echo "ALL ASSERTIONS PASSED"
echo "  boards  -> out/boards/"
echo "  assets  -> out/{a,b,c}/ + out/pic-{d..i}/"
