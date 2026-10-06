#!/usr/bin/env python3
"""可访问性规则检查（WEB-ACC-1）。

正则级检查 dist/ 全部 HTML：
  1. 所有 <img> 带 alt 属性；
  2. 表单控件（input/select/textarea）有 label（label[for]、包裹式或 aria-label）；
  3. 标题层级不跳级（h1 -> h3 即违规）；
  4. 每页有 viewport meta 与 <html lang=>；
  5. 每个 HTML 恰好一个 <h1>；
  6. 色彩对比：内置官网调色板组合，计算 WCAG 对比度并断言 >= 4.5。

用法：python3 website/tools/check_a11y.py [dist_dir]
退出码：0 = 全部通过；1 = 有问题。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

WEBSITE = Path(__file__).resolve().parent.parent
DEFAULT_DIST = WEBSITE / "dist"

IMG_RE = re.compile(r"<img\b[^>]*>", re.I)
CTRL_RE = re.compile(r"<(?:input|select|textarea)\b[^>]*>", re.I)
HEAD_RE = re.compile(r"<h([1-6])\b", re.I)
VIEWPORT_RE = re.compile(r'<meta\s+name="viewport"', re.I)
LANG_RE = re.compile(r"<html\s+[^>]*lang\s*=\s*[\"'][^\"']+[\"']", re.I)
LABEL_FOR_RE = re.compile(r"""<label\b[^>]*for\s*=\s*["']([^"']+)["']""", re.I)
ID_RE = re.compile(r"""id\s*=\s*["']([^"']+)["']""", re.I)

# 官网调色板：从 assets/css/main.css 实际解析，纸白与夜场两套底各自校验。
# 以前这里是硬编码的一份夜场色 —— 改版成纸白默认后，它会继续对着旧色打分并报
# "all rules passed"，等于一个说谎的验收闸门。必须跟着 CSS 走。
CSS_PATH = Path(__file__).resolve().parent.parent / "assets" / "css" / "main.css"
_TOKEN_RE = re.compile(r"(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{3,8}|rgba?\([^)]*\))\s*;")
_RGB_RE = re.compile(r"rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)")


def _to_rgba(val: str) -> tuple[float, float, float, float]:
    m = _RGB_RE.match(val)
    if m:
        a = m.group(4)
        return float(m.group(1)), float(m.group(2)), float(m.group(3)), float(a) if a is not None else 1.0
    h = val.lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), 1.0


def composite(fg: str, bg: str) -> str:
    """把 rgba 叠到具体底色上得到实色 —— 半透明 tint 底（--felt-w 等）必须先合成再算对比度。"""
    r, g, b, a = _to_rgba(fg)
    if a >= 1.0:
        return fg
    br, bg2, bb, _ = _to_rgba(bg)
    mix = lambda x, y: x * a + y * (1 - a)
    return "#%02x%02x%02x" % (round(mix(r, br)), round(mix(g, bg2)), round(mix(b, bb)))


def parse_tokens(block: str) -> dict[str, str]:
    return {n.lstrip("-"): v for n, v in _TOKEN_RE.findall(block)}


def load_palettes() -> dict[str, dict[str, str]]:
    css = CSS_PATH.read_text(encoding="utf-8")
    out: dict[str, dict[str, str]] = {}
    m = re.search(r":root\s*\{(.*?)\n\}", css, re.S)
    if m:
        out["paper"] = parse_tokens(m.group(1))
    for m in re.finditer(r"html\[data-ground=\"(\w+)\"\]\s*\{(.*?)\n\s*\}", css, re.S):
        out[m.group(1)] = out.get(m.group(1), {}) | parse_tokens(m.group(2))
    return out


PALETTE_KEYS = {
    "bg": "--bg", "bg-soft": "--bg-soft", "surface": "--surface",
    "text": "--text", "muted": "--muted", "muted-2": "--muted-2",
    "felt": "--felt", "play": "--play", "real": "--real",
    "danger": "--danger", "amb": "--amb", "code-bg": "--code-bg",
    "nav-active-text": "--nav-active-text", "surface-2": "--surface-2",
    "felt-w": "--felt-w", "play-w": "--play-w", "real-w": "--real-w",
    "danger-w": "--danger-w", "amb-w": "--amb-w",
}
CONTRAST_PAIRS = [
    ("text on bg", "text", "bg"),
    ("text on surface", "text", "surface"),
    ("text on surface-2", "text", "surface-2"),
    ("muted on bg", "muted", "bg"),
    ("muted on bg-soft", "muted", "bg-soft"),
    ("muted on surface", "muted", "surface"),
    ("muted-2 on bg", "muted-2", "bg"),          # 次级文字/表头，最容易被忽略的一档
    ("muted-2 on surface", "muted-2", "surface"),
    ("muted-2 on code-bg", "muted-2", "code-bg"),
    ("felt on bg", "felt", "bg"),
    ("felt on surface", "felt", "surface"),
    ("play on bg", "play", "bg"),
    ("play on surface", "play", "surface"),
    ("real on bg", "real", "bg"),
    ("real on surface", "real", "surface"),
    ("danger on bg", "danger", "bg"),
    ("danger on surface", "danger", "surface"),
    ("amb on bg", "amb", "bg"),
    ("nav-active-text on felt", "nav-active-text", "felt"),
    # 状态丸 / 横幅真正被读的是"前景色 + 同族半透明 tint 底"，必须合成后再算。
    ("felt on felt-w", "felt", "felt-w", "surface"),
    ("play on play-w", "play", "play-w", "surface"),
    ("real on real-w", "real", "real-w", "surface"),
    ("danger on danger-w", "danger", "danger-w", "surface"),
    ("amb on amb-w", "amb", "amb-w", "surface"),
    ("muted-2 on surface-2", "muted-2", "surface-2"),   # 表头真实配色
]
# 品牌硬规则要求 ≥5.2:1；WCAG AA 正文底线是 4.5，这里按更严的品牌线卡。
MIN_CONTRAST = 5.2


def _chan(c: float) -> float:
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hexs: str) -> float:
    h = hexs.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * _chan(r) + 0.7152 * _chan(g) + 0.0722 * _chan(b)


def contrast(fg: str, bg: str) -> float:
    la, lb = luminance(fg), luminance(bg)
    if la < lb:
        la, lb = lb, la
    return (la + 0.05) / (lb + 0.05)


def check_file(f: Path) -> list[str]:
    issues: list[str] = []
    text = f.read_text(encoding="utf-8", errors="replace")
    rel = f

    # 1. img alt
    for img in IMG_RE.findall(text):
        if not re.search(r"""\balt\s*=\s*["'][^"']*["']""", img, re.I):
            issues.append("%s: <img> without alt: %s" % (rel, img[:80]))

    # 2. form labels
    controls = CTRL_RE.findall(text)
    if controls:
        label_fors = set(LABEL_FOR_RE.findall(text))
        for tag in controls:
            m_id = re.search(r"""id\s*=\s*["']([^"']+)["']""", tag, re.I)
            cid = m_id.group(1) if m_id else None
            ok = (
                "aria-label=" in tag
                or "aria-labelledby=" in tag
                or (cid is not None and cid in label_fors)
                or 'type="hidden"' in tag
                or "disabled" in tag and False  # disabled 也不能免 label；此处显式不豁免
            )
            if not ok:
                issues.append("%s: form control without label: %s" % (rel, tag[:80]))

    # 3. heading hierarchy（页内顺序，不允许跳级）
    levels = [int(m) for m in HEAD_RE.findall(text)]
    for prev, cur in zip(levels, levels[1:]):
        if cur > prev + 1:
            issues.append("%s: heading level jump h%d -> h%d" % (rel, prev, cur))

    # 4. viewport / lang
    if not VIEWPORT_RE.search(text):
        issues.append("%s: missing viewport meta" % rel)
    if not LANG_RE.search(text):
        issues.append("%s: missing html lang" % rel)

    # 5. single h1
    if levels.count(1) != 1:
        issues.append("%s: expected exactly 1 h1, found %d" % (rel, levels.count(1)))

    return issues


def main() -> int:
    dist = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DIST
    if not dist.is_dir():
        print("dist not found: %s" % dist)
        return 2
    issues: list[str] = []
    files = sorted(dist.rglob("*.html"))
    for f in files:
        issues += check_file(f)

    # 6. contrast — 每套底各自跑一遍，缺 token 直接算问题而不是静默跳过
    palettes = load_palettes()
    if not palettes:
        issues.append("contrast: 无法从 %s 解析 :root" % CSS_PATH)
    contrast_rows: list[tuple[str, str, float]] = []
    for ground, raw in sorted(palettes.items()):
        pal = {k: raw.get(v.lstrip("-")) for k, v in PALETTE_KEYS.items()}
        for spec in CONTRAST_PAIRS:
            name, fgk, bgk = spec[0], spec[1], spec[2]
            basek = spec[3] if len(spec) > 3 else None
            fg, bg = pal.get(fgk), pal.get(bgk)
            if not fg or not bg:
                issues.append("contrast: %s 底缺 token，无法校验 %s" % (ground, name))
                continue
            if basek:
                base = pal.get(basek)
                if not base:
                    issues.append("contrast: %s 底缺基色 %s（%s）" % (ground, basek, name))
                    continue
                bg = composite(bg, base)   # 半透明 tint 先合成实色
            fg = composite(fg, bg)
            ratio = contrast(fg, bg)
            contrast_rows.append((ground, name, ratio))
            if ratio < MIN_CONTRAST:
                issues.append("contrast: [%s] %s = %.2f (< %.1f)" % (ground, name, ratio, MIN_CONTRAST))

    print("a11y: checked %d pages" % len(files))
    print("contrast (品牌线 minimum %.1f, 逐底面):" % MIN_CONTRAST)
    for ground in sorted(palettes):
        rows = [r for r in contrast_rows if r[0] == ground]
        if not rows:
            continue
        print("  ── %s（最低 %.2f：%s）" % (ground, min(r[2] for r in rows),
                                          min(rows, key=lambda r: r[2])[1]))
        for _, name, ratio in sorted(rows, key=lambda r: r[2]):
            print("    %5.2f  %s" % (ratio, name))
    if issues:
        print("A11Y ISSUES: %d" % len(issues))
        for i in issues:
            print("  " + i)
        return 1
    print("a11y check: all rules passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
