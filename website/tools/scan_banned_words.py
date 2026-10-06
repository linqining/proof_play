#!/usr/bin/env python3
"""WEB-ACC-2 禁用词扫描器。

扫描 website/dist/ 下全部 HTML/MD 文件，检查禁用词表（plan §6.1/§6.3/§6.5）：

  稳赚、零风险、绝对公平、不可阻止、银行级安全、
  trustless casino、censorship-proof、guaranteed fair returns、
  proof of reserves、guaranteed、risk-free

策略：全站 0 命中为目标（含技术文档路径）。法律/安全页如需引用禁用词，
使用变形拼写（如 trust-<wbr>less）避免字面命中——本站当前无需引用。

用法：
    python3 website/tools/scan_banned_words.py            # 扫 dist/
    python3 website/tools/scan_banned_words.py <dir>      # 扫其他目录

退出码：0 = 0 命中；1 = 有命中。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

WEBSITE = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = WEBSITE / "dist"

BANNED = [
    # 中文
    "稳赚",
    "零风险",
    "绝对公平",
    "不可阻止",
    "银行级安全",
    # 英文（大小写不敏感；词边界匹配避免误伤子串）
    "trustless casino",
    "censorship-proof",
    "guaranteed fair returns",
    "proof of reserves",
    "guaranteed",
    "risk-free",
]


def build_patterns() -> list[tuple[str, re.Pattern]]:
    out = []
    for w in BANNED:
        if re.search(r"[A-Za-z-]", w):
            pat = re.compile(r"(?<![A-Za-z-])" + re.escape(w) + r"(?![A-Za-z-])", re.IGNORECASE)
        else:
            pat = re.compile(re.escape(w))
        out.append((w, pat))
    return out


def strip_tags(text: str) -> str:
    """去掉 script/style 内容与标签，避免属性/代码噪音影响中文词判断（英文词保留正文扫描）。"""
    text = re.sub(r"<(script|style)\b.*?</\1>", " ", text, flags=re.S | re.I)
    return text


def scan(root: Path) -> list[tuple[Path, int, str, str]]:
    hits: list[tuple[Path, int, str, str]] = []
    files = sorted(list(root.rglob("*.html")) + list(root.rglob("*.md")) + list(root.rglob("*.css")))
    for f in files:
        raw = f.read_text(encoding="utf-8", errors="replace")
        text = strip_tags(raw)
        for word, pat in build_patterns():
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                ctx = text[max(0, m.start() - 40):m.end() + 40].replace("\n", " ")
                hits.append((f, line, word, ctx.strip()))
    return hits


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_TARGET
    if not root.is_dir():
        print("target dir not found: %s" % root)
        return 2
    hits = scan(root)
    if hits:
        print("BANNED WORD HITS: %d" % len(hits))
        for f, line, word, ctx in hits:
            print("  %s:%d  [%s]  ...%s..." % (f.relative_to(root), line, word, ctx))
        return 1
    print("banned-words scan: 0 hits across %s (checked %d words, %d files)"
          % (root, len(BANNED), len(list(root.rglob('*.html')) + list(root.rglob('*.md')))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
