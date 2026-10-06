#!/usr/bin/env python3
"""断链检查器（WEB-ACC-1）。

从 dist/index.html 出发全图遍历站内链接：
  - 根绝对路径（/product/）与相对路径（./x/，../y）解析到 dist 内文件；
  - 目录式 URL 自动尝试 <dir>/index.html；
  - #fragment 对目标文件内的 id=/name= 校验；
  - 外链（http/https/mailto）只做格式检查，不请求网络。

用法：
    python3 website/tools/check_links.py [dist_dir]

退出码：0 = 0 断链；1 = 有断链。
"""

from __future__ import annotations

import re
import sys
import posixpath
from pathlib import Path
from urllib.parse import urlparse

WEBSITE = Path(__file__).resolve().parent.parent
DEFAULT_DIST = WEBSITE / "dist"

LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)
ID_RE = re.compile(r"""id\s*=\s*["']([^"']+)["']|name\s*=\s*["']([^"']+)["']""", re.I)

SKIP_PREFIXES = ("mailto:", "tel:", "data:", "javascript:")


def load_ids(f: Path) -> set[str]:
    try:
        text = f.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    return {a or b for a, b in ID_RE.findall(text)}


def resolve(base_file: Path, url: str) -> Path | None:
    """把页面内 URL 解析为 dist 内的目标文件；无法解析返回 None。"""
    u = urlparse(url)
    if u.scheme or url.startswith("//"):
        return None  # 外链：格式检查在调用方
    path = u.path
    base_dir = base_file.parent
    if path.startswith("/"):
        target = ROOT / path.lstrip("/")
    else:
        target = (base_dir / path)
    target = target.resolve() if not target.is_dir() else target
    # 归一化 ..
    target = Path(posixpath.normpath(str(target)))
    return target


ROOT = None  # set in main


def target_file_for(p: Path) -> Path | None:
    """目录 -> 目录/index.html；无扩展名文件名同样尝试加 /index.html。"""
    if p.is_dir():
        cand = p / "index.html"
        return cand if cand.exists() else None
    if p.exists():
        return p
    cand = Path(str(p) + "/index.html")
    return cand if cand.exists() else None


def main() -> int:
    global ROOT
    dist = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DIST
    if not dist.is_dir():
        print("dist not found: %s" % dist)
        return 2
    ROOT = dist.resolve()

    start = dist / "index.html"
    if not start.exists():
        print("missing dist/index.html")
        return 2

    visited: set[Path] = set()
    queue: list[Path] = [start.resolve()]
    broken: list[str] = []
    checked_internal = 0
    external = 0

    ext_ok = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.I)

    while queue:
        f = queue.pop(0)
        if f in visited:
            continue
        visited.add(f)
        text = f.read_text(encoding="utf-8", errors="replace")
        for url in LINK_RE.findall(text):
            url = url.strip()
            if not url or any(url.startswith(p) for p in SKIP_PREFIXES):
                continue
            if url.startswith(("http://", "https://", "//")):
                if not ext_ok.match(url if not url.startswith("//") else "https:" + url):
                    broken.append("%s -> bad external URL format: %s" % (f.relative_to(dist), url))
                else:
                    external += 1
                continue
            if url.startswith("#"):
                frag = url[1:]
                ids = load_ids(f)
                if frag and frag not in ids:
                    broken.append("%s -> missing fragment %s (same file)" % (f.relative_to(dist), url))
                continue
            checked_internal += 1
            target = resolve(f, url)
            if target is None or not str(target).startswith(str(ROOT)):
                broken.append("%s -> escapes dist root: %s" % (f.relative_to(dist), url))
                continue
            tf = target_file_for(target)
            if tf is None:
                broken.append("%s -> NOT FOUND: %s" % (f.relative_to(dist), url))
                continue
            frag = urlparse(url).fragment
            if frag and frag not in load_ids(tf):
                broken.append("%s -> missing fragment %s in %s" % (f.relative_to(dist), url, tf.relative_to(dist)))
            if tf.suffix == ".html" and tf not in visited:
                queue.append(tf)

    print("checked %d internal links across %d pages; %d external (format-only)"
          % (checked_internal, len(visited), external))
    if broken:
        print("BROKEN LINKS: %d" % len(broken))
        for b in broken:
            print("  " + b)
        return 1
    print("link check: 0 broken links")
    return 0


if __name__ == "__main__":
    sys.exit(main())
