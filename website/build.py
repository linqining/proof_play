#!/usr/bin/env python3
"""ProofPlay Poker 官网/文档站静态构建器。

只用 Python 3 标准库，无任何第三方依赖：

    python3 website/build.py

输入：
  website/content/     markdown 页面（带 YAML-lite front matter）
  website/templates/   HTML 模板（base / docs）
  website/assets/      静态资源（css / img），原样拷贝
  website/media-kit/   宣传素材包，原样拷贝到 dist/media-kit/

输出：website/dist/

约定：
  - content/index.md            -> dist/index.html            （路由 /）
  - content/<name>.md           -> dist/<name>/index.html     （路由 /<name>/）
  - content/docs/<sec>/<p>.md   -> dist/docs/<sec>/<p>/index.html
  - 站内链接一律使用根绝对路径（如 /docs/protocol/abi/），README 说明用
    `python3 -m http.server` 或任意静态托管部署。
"""

from __future__ import annotations

import html as html_mod
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONTENT = ROOT / "content"
TEMPLATES = ROOT / "templates"
ASSETS = ROOT / "assets"
MEDIA_KIT = ROOT / "media-kit"
DIST = ROOT / "dist"

# ---------------------------------------------------------------------------
# 站点事实基线（与 zchain 仓库 docs/plan-appchain-v1.md §6.1 一致；版本号集中在这一处）
# ---------------------------------------------------------------------------

SITE = {
    "NAME": "ProofPlay Poker",
    "NETWORK": "devnet",
    "NETWORK_FULL": "zchain-poker-devnet",
    "DOCS_VERSION": "v1.3.0-alpha",
    "ABI_VERSION": "v1.3",
    "FOOTER_VERSION": "docs v1.3.0-alpha (ABI v1.3)",
    "SITE_VERSION": "site v0.1.0 (media-kit v0.1)",
    "URL_BASE": "https://zchain.example",  # §6.1：上线前替换为已过 DNS/TLS/品牌审核的域名
    "DOCS_BASE": "https://docs.zchain.example",
    "REPO_URL": "https://zchain.example/repo",  # 占位：公开仓库地址待品牌评审后固定
    "YEAR": "2026",
}

# 官网 13 个信息架构路由（plan §6.2）
NAV = [
    ("首页", "/", "home"),
    ("产品", "/product/", "product"),
    ("技术", "/technology/", "technology"),
    ("证明", "/proofs/", "proofs"),
    ("浏览器", "/explorer/", "explorer"),
    ("开发者", "/developers/", "developers"),
    ("文档", "/docs/", "docs"),
    ("路线图", "/roadmap/", "roadmap"),
    ("安全", "/security/", "security"),
    ("透明度", "/transparency/", "transparency"),
    ("社区", "/community/", "community"),
    ("法务", "/legal/", "legal"),
    ("状态", "/status/", "status"),
]

# 文档站 13 个板块（plan §6.4）
DOC_SECTIONS = [
    ("getting-started", "快速开始"),
    ("concepts", "核心概念"),
    ("protocol", "协议规范"),
    ("architecture", "系统架构"),
    ("developers", "开发者指南"),
    ("validators", "验证者指南"),
    ("operators", "运营方指南"),
    ("proofs", "证明系统"),
    ("security", "安全"),
    ("economics", "经济模型"),
    ("api-reference", "API 参考"),
    ("changelog", "变更日志"),
    ("legal", "法务与合规"),
]

# ---------------------------------------------------------------------------

def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


SLUG_RE = re.compile(r"[^\w\u4e00-\u9fff]+")


def slugify(text: str) -> str:
    s = SLUG_RE.sub("-", text.strip().lower())
    return s.strip("-") or "section"


def parse_front_matter(src: str):
    """YAML-lite front matter：--- 包夹的 `key: value` 行。返回 (meta, body)。"""
    meta = {}
    body = src
    if src.startswith("---"):
        end = src.find("\n---", 3)
        if end != -1:
            block = src[3:end].strip("\n")
            for line in block.splitlines():
                line = line.rstrip()
                if not line or line.lstrip().startswith("#"):
                    continue
                if ":" not in line:
                    continue
                k, _, v = line.partition(":")
                meta[k.strip()] = v.strip()
            body = src[end + 4:].lstrip("\n")
    for k in ("sample", "custody", "toc"):
        if k in meta:
            meta[k] = meta[k].lower() in ("true", "yes", "1", "on")
    return meta, body


# ---------------------------------------------------------------------------
# 极简 Markdown 渲染（标题/段落/列表/表格/引用/代码栅栏/行内样式/原生 HTML 块）
# ---------------------------------------------------------------------------

_CODE_TOKEN = "\x02{}\x03"
_TAG_TOKEN = "\x04{}\x05"

# 行内级信任标签：markdown 文本/表格单元格中允许原样输出（链接/加粗/代码、st 状态徽章、换行等）
_TRUSTED_TAG_RE = re.compile(r"</?(span|br|wbr|sub|sup|a|strong|em|code)\b[^>]*>", re.I)
_ENTITY_RE = re.compile(r"&(amp;)?(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);")


def _inline(text: str) -> str:
    """行内格式：保护 code span 与信任标签，转义 HTML，再加粗/斜体/链接，最后还原。

    源文件里手写的字符实体（&gt; / &#183; 等）保持为实体，不双重转义。
    """
    codes: list[str] = []

    def stash(m: "re.Match[str]") -> str:
        codes.append("<code>" + html_mod.escape(m.group(1), quote=False) + "</code>")
        return _CODE_TOKEN.format(len(codes) - 1)

    text = re.sub(r"`([^`]+)`", stash, text)

    tags: list[str] = []

    def stash_tag(m: "re.Match[str]") -> str:
        tags.append(m.group(0))
        return _TAG_TOKEN.format(len(tags) - 1)

    text = _TRUSTED_TAG_RE.sub(stash_tag, text)

    text = html_mod.escape(text, quote=False)
    text = _ENTITY_RE.sub(r"&\2;", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", text)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)\s]+)\)",
        lambda m: '<a href="%s">%s</a>'
        % (html_mod.escape(m.group(2), quote=True), m.group(1)),
        text,
    )
    for i, c in enumerate(codes):
        text = text.replace(_CODE_TOKEN.format(i), c)
    for i, t in enumerate(tags):
        text = text.replace(_TAG_TOKEN.format(i), t)
    return text


_NUM_UNIT = (
    r"(?:%|‰|x|倍|位|项|条|个|次|手|桌|人|家|篇|节|级|档|元|"
    r"ms|us|ns|s|分钟|小时|秒|天|周|月|年|bps|gas|STRK|PLAY|TPS|QPS)?"
)
_NUM_CELL = re.compile(rf"^[<>=~]?\s*[\d,]*\.?\d+\s*{_NUM_UNIT}\s*[)）]?\+?$")


def _is_num_cell(raw: str) -> bool:
    """判断一个 Markdown 表格单元是否为"量"（可贴右），而不是"标识符"。

    0x… 开头的哈希与含省略号的地址必须留在左对齐：它们是被查的键，不是被加的数。
    """
    t = raw.strip().strip("`").strip()
    if not t or t.lower().startswith("0x") or "…" in t or "..." in t:
        return False
    return bool(_NUM_CELL.match(t))


def numeric_columns(thead: list[str], rows: list[list[str]]) -> set[int]:
    """整列每个非空单元格都是数字时，该列下标进入集合。"""
    num: set[int] = set()
    for i in range(len(thead)):
        vals = [r[i] for r in rows if i < len(r) and r[i].strip()]
        if vals and all(_is_num_cell(v) for v in vals):
            num.add(i)
    return num


def render_markdown(src: str) -> str:
    lines = src.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    para: list[str] = []
    thead: list[str] | None = None
    list_kind: str | None = None
    list_items: list[str] = []

    def flush_para() -> None:
        if para:
            out.append("<p>" + _inline("\n".join(para)) + "</p>")
            para.clear()

    def flush_table() -> None:
        nonlocal thead
        if thead is None:
            return
        rows = pending_rows()
        num = numeric_columns(thead, rows)

        def cell(tag: str, i: int, text: str) -> str:
            cls = f' class="num"' if i in num else ""
            return f"<{tag}{cls}>" + _inline(text) + f"</{tag}>"

        parts = ["<table>", "<thead><tr>"]
        parts += [cell("th", i, c) for i, c in enumerate(thead)]
        parts.append("</tr></thead>")
        if rows:
            parts.append("<tbody>")
            for r in rows:
                parts.append(
                    "<tr>" + "".join(cell("td", i, c) for i, c in enumerate(r)) + "</tr>")
            parts.append("</tbody>")
        parts.append("</table>")
        out.append("".join(parts))
        thead = None
        rows_buf.clear()

    rows_buf: list[list[str]] = []

    def pending_rows() -> list[list[str]]:
        return rows_buf

    def flush_list() -> None:
        nonlocal list_kind, list_items
        if list_kind:
            tag = "ol" if list_kind == "ol" else "ul"
            out.append("<%s class=\"%s-list\">" % (tag, list_kind) + "".join(list_items) + "</%s>" % tag)
            list_kind = None
            list_items = []

    def split_row(line: str) -> list[str]:
        cells = line.strip().strip("|").split("|")
        return [c.strip() for c in cells]

    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = raw.rstrip()

        # fenced code block
        m = re.match(r"^```(\S*)\s*$", line)
        if m:
            flush_para(); flush_table(); flush_list()
            lang = m.group(1)
            i += 1
            code: list[str] = []
            while i < n and not lines[i].startswith("```"):
                code.append(lines[i])
                i += 1
            cls = ' class="language-%s"' % lang if lang else ""
            out.append("<pre><code%s>%s</code></pre>" % (cls, html_mod.escape("\n".join(code), quote=False)))
            i += 1
            continue

        # raw HTML block：从行首为 < 的那行起，吃到空行（或下一个 Markdown 块）为止。
        # 旧口径只吃"连续以 < 开头的行"，于是 <li> 内部软换行的续行会截断这个块，
        # 剩下的文本被当成新段落，行尾的 </li> 被转义成页面上的字面量（proofs 页就是这样）。
        if line.lstrip().startswith("<"):
            flush_para(); flush_table(); flush_list()
            block: list[str] = []
            while i < n and lines[i].strip():
                s = lines[i].lstrip()
                if block and (s.startswith("#") or s.startswith("```")):
                    break
                block.append(lines[i])
                i += 1
            out.append("\n".join(block))
            continue

        if not line.strip():
            flush_para(); flush_table(); flush_list()
            i += 1
            continue

        # horizontal rule
        if re.match(r"^-{3,}$", line.strip()) or re.match(r"^\*{3,}$", line.strip()):
            flush_para(); flush_table(); flush_list()
            out.append("<hr>")
            i += 1
            continue

        # heading
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            flush_para(); flush_table(); flush_list()
            level = len(m.group(1))  # 文档标题是 h1，## -> h2，保持层级连续
            title = m.group(2).strip()
            sid = slugify(title)
            out.append("<h%d id=\"%s\">%s</h%d>" % (level, sid, _inline(title), level))
            i += 1
            continue

        # table header + separator
        if line.lstrip().startswith("|") and i + 1 < n and re.match(r"^\s*\|[\s:|-]+\|?\s*$", lines[i + 1]):
            flush_para(); flush_list()
            thead = split_row(line)
            rows_buf.clear()
            i += 2
            continue
        if thead is not None and line.lstrip().startswith("|"):
            rows_buf.append(split_row(line))
            i += 1
            continue
        flush_table()

        # blockquote
        if line.lstrip().startswith(">"):
            flush_para(); flush_list()
            quote: list[str] = []
            while i < n and lines[i].lstrip().startswith(">"):
                quote.append(lines[i].lstrip()[1:].lstrip())
                i += 1
            out.append("<blockquote>" + _inline(" ".join(q for q in quote if q)) + "</blockquote>")
            continue

        # lists
        m = re.match(r"^(\s*)[-*]\s+(.*)$", raw)
        if m and not re.match(r"^\s*[-*]\s+$", raw):
            flush_para(); flush_table()
            if list_kind not in (None, "ul"):
                flush_list()
            list_kind = "ul"
            item = m.group(2)
            task = ""
            if item.startswith("[ ] "):
                task = " task task-open"
                item = item[4:]
            elif item.startswith("[x] ") or item.startswith("[X] "):
                task = " task task-done"
                item = item[4:]
            list_items.append("<li class=\"li%s\">%s</li>" % (task, _inline(item)))
            i += 1
            continue
        m = re.match(r"^(\s*)\d+[.)]\s+(.*)$", raw)
        if m:
            flush_para(); flush_table()
            if list_kind not in (None, "ol"):
                flush_list()
            list_kind = "ol"
            list_items.append("<li class=\"li\">" + _inline(m.group(2)) + "</li>")
            i += 1
            continue

        para.append(line.strip())
        i += 1

    flush_para(); flush_table(); flush_list()
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 模板渲染（[[KEY]] 占位符，避免与页面内容中的 $ / {} 冲突）
# ---------------------------------------------------------------------------

def render_template(tpl: str, mapping: dict) -> str:
    out = tpl
    for k, v in mapping.items():
        out = out.replace("[[%s]]" % k, v)
    return out


def build_nav(active: str) -> str:
    parts = ['<ul class="nav-list">']
    for label, href, key in NAV:
        cls = ' class="active"' if key == active else ""
        parts.append('<li><a href="%s"%s>%s</a></li>' % (href, cls, label))
    parts.append("</ul>")
    return "".join(parts)


def env_strip_html() -> str:
    """每个页面页眉固定显示：网络环境徽章 + 资产类型说明 + 最终性图例（plan §6 前言/§6.2）。"""
    return (
        '<div class="env-strip" role="note" aria-label="网络环境与最终性说明">'
        '<span class="chip chip-net">devnet &#183; zchain-poker-devnet</span>'
        '<span class="chip chip-assets">PLAY 娱乐筹码 &#183; REAL 托管映射 &#183; v1 托管网络</span>'
        '<details class="fin-legend"><summary>finality: soft accepted &#8594; BFT ordered &#8594; proven '
        '&#8594; finalized/claimable</summary>'
        '<div class="fin-legend-body">四种状态来自技术方案 &#167;5.1。v1 当前实际达到 '
        '<strong>soft accepted</strong>（桌级软确认）与 <strong>proven</strong>（批次证明）；'
        'BFT ordered 与 finalized/claimable 属于 v1.5 / Phase 2 路线图，尚未上线。'
        '软确认不代表最终确认，也不能单独授权 REAL 提现。</div></details>'
        '</div>'
    )


def footer_html(docs_mode: bool) -> str:
    links = "".join('<a href="%s">%s</a>' % (h, l) for l, h, _ in NAV[1:])
    ver = SITE["FOOTER_VERSION"] if docs_mode else SITE["SITE_VERSION"] + " &#183; " + SITE["FOOTER_VERSION"]
    return (
        '<footer class="site-footer"><div class="wrap footer-grid">'
        '<div><p class="footer-brand"><img src="/assets/img/logo.svg" alt="" width="28" height="28"> '
        + SITE["NAME"] + ' · 明局</p><p>Every game, proven. 面向扑克场景的专用 Appchain。'
        '当前为 devnet 托管网络，'
        'PLAY 用于测试与娱乐；REAL 提现受托管与 finality 门槛约束。</p></div>'
        '<div class="footer-links"><h2 class="footer-h">站点</h2>' + links + "</div>"
        '<div class="footer-meta"><h2 class="footer-h">版本与仓库</h2>'
        '<p>' + ver + '</p>'
        '<p><a href="' + SITE["REPO_URL"] + '" rel="noopener">代码仓库（占位地址）</a></p>'
        '<p>上线前域名 ' + SITE["URL_BASE"] + ' 为占位（plan &#167;6.1）。</p>'
        '<p>&#169; ' + SITE["YEAR"] + " " + SITE["NAME"] + " 项目（历史工作名 ZChain）</p>"
        "</div></div></footer>"
    )


def sample_banner(text: str = "") -> str:
    body = text or (
        "本页为<strong>接口就绪的静态层</strong>，全部数据为 <strong>SAMPLE DATA / devnet</strong> 示例，"
        "非实时、非承诺。生产数据将由独立的 portal 服务（explorer / status / transparency / proof portal）提供；"
        "本站只定义页面结构与数据口径。"
    )
    return (
        '<div class="banner banner-sample"><span class="banner-tag">SAMPLE DATA / devnet</span>'
        "<p>" + body + "</p></div>"
    )


def custody_banner() -> str:
    return (
        '<div class="banner banner-custody"><span class="banner-tag">CUSTODIAL / v1</span>'
        "<p>v1 是<strong>托管式网络</strong>：REAL 是运营方托管的真实资产映射，充值、提现均受运营方流程与 "
        "finality 门槛约束；无信任提现（permissionless claim）需等 Vault verifier 上线（Phase 2）。"
        "涉及 REAL 的任何操作请先阅读<a href=\"/legal/\">法务与风险披露</a>。</p></div>"
    )


# ---------------------------------------------------------------------------
# 页面收集与输出
# ---------------------------------------------------------------------------

def out_path_for(rel: Path) -> Path:
    if rel.name == "index.md":
        return DIST / rel.parent / "index.html"
    return DIST / rel.parent / rel.stem / "index.html"


def url_for(rel: Path) -> str:
    p = out_path_for(rel).relative_to(DIST)
    d = p.parent
    return "/" if str(d) == "." else "/" + d.as_posix() + "/"


def collect_docs_sidebar(current_url: str) -> str:
    parts = ['<nav class="docs-side" aria-label="文档目录">']
    for sec_key, sec_label in DOC_SECTIONS:
        sec_dir = CONTENT / "docs" / sec_key
        if not sec_dir.is_dir():
            continue
        pages = sorted(sec_dir.glob("*.md"), key=lambda p: (p.name != "index.md", p.name))
        entries = []
        for p in pages:
            u = url_for(p.relative_to(CONTENT))
            meta, _ = parse_front_matter(read(p))
            label = meta.get("title", p.stem)
            cls = ' class="active"' if u == current_url else ""
            entries.append('<li><a href="%s"%s>%s</a></li>' % (u, cls, html_mod.escape(label, quote=False)))
        if entries:
            parts.append(
                '<div class="docs-side-group"><p class="docs-side-h">'
                '<a href="/docs/%s/">%s</a></p><ul>%s</ul></div>'
                % (sec_key, sec_label, "".join(entries))
            )
    parts.append("</nav>")
    return "".join(parts)


def breadcrumb_html(meta: dict, url: str) -> str:
    m = re.match(r"^/docs/([^/]+)/", url)
    if not m:
        return ""
    sec_key = m.group(1)
    sec_label = dict(DOC_SECTIONS).get(sec_key, sec_key)
    return (
        '<nav class="breadcrumb" aria-label="面包屑"><a href="/docs/">文档</a>'
        '<span aria-hidden="true">/</span><a href="/docs/%s/">%s</a>'
        '<span aria-hidden="true">/</span><span aria-current="page">%s</span></nav>'
        % (sec_key, sec_label, html_mod.escape(meta.get("title", ""), quote=False))
    )


def build_page(rel: Path, tpl_base: str, tpl_docs: str) -> None:
    meta, body_src = parse_front_matter(read(CONTENT / rel))
    title = meta.get("title", rel.stem)
    url = url_for(rel)
    is_docs = url.startswith("/docs/") and url != "/docs/"
    body_html = render_markdown(body_src)

    banners = ""
    if meta.get("sample"):
        banners += sample_banner(meta.get("sample-note", ""))
    if meta.get("custody"):
        banners += custody_banner()

    desc = meta.get(
        "description",
        "ProofPlay Poker：让游戏自己证明公平。牌面保持私密，洗牌、动作与结算留下可复验证据；"
        "底层网络与协议标识暂时沿用 ZChain。",
    )

    # 首页 page-head 由 hero 自带 h1 承担，避免标题重复渲染
    if url == "/":
        page_head = ""
    else:
        page_head = (
            '<div class="page-head">'
            '<h1 class="page-title">' + html_mod.escape(title, quote=False) + "</h1>"
            + breadcrumb_html(meta, url)
            + '<p class="page-lead">' + _inline(meta.get("lead", "")) + "</p></div>"
        )

    title_tag = html_mod.escape(title, quote=True)
    if title != SITE["NAME"]:
        title_tag += " - " + html_mod.escape(SITE["NAME"], quote=True)

    mapping = {
        "LANG": meta.get("lang", "zh-CN"),
        "TITLE": title_tag,
        "DESCRIPTION": html_mod.escape(desc, quote=True),
        "FOOTER_VERSION": SITE["FOOTER_VERSION"],
        "NAV": build_nav(meta.get("section", url.rstrip("/").split("/")[1] if url != "/" else "home")),
        "ENV_STRIP": env_strip_html(),
        "FOOTER": footer_html(is_docs),
        "PAGE_HEAD": page_head,
        "PAGE_TITLE": html_mod.escape(title, quote=False),
        "PAGE_LEAD": _inline(meta.get("lead", "")),
        "BANNERS": banners,
        "BODY": body_html,
        "BRAND_URL": SITE["URL_BASE"],
    }
    if is_docs:
        mapping["SIDEBAR"] = collect_docs_sidebar(url)
        mapping["BREADCRUMB"] = breadcrumb_html(meta, url)
        tpl = tpl_docs
    else:
        mapping["SIDEBAR"] = ""
        mapping["BREADCRUMB"] = ""
        tpl = tpl_base

    out = out_path_for(rel)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_template(tpl, mapping), encoding="utf-8")


def copy_tree(src: Path, dst: Path) -> None:
    if not src.is_dir():
        return
    shutil.copytree(src, dst, dirs_exist_ok=True)


def main() -> int:
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)

    tpl_base = read(TEMPLATES / "base.html")
    tpl_docs = read(TEMPLATES / "docs.html")

    pages = sorted(p.relative_to(CONTENT) for p in CONTENT.rglob("*.md"))
    for rel in pages:
        build_page(rel, tpl_base, tpl_docs)

    copy_tree(ASSETS, DIST / "assets")
    copy_tree(MEDIA_KIT, DIST / "media-kit")

    n_html = len(list(DIST.rglob("*.html")))
    print("built %d pages into %s" % (n_html, DIST))
    return 0


if __name__ == "__main__":
    sys.exit(main())
