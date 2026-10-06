#!/usr/bin/env python3
"""全站逐页出图。

为什么要起 HTTP：站内链接是根绝对路径（/assets/...、/docs/...），
file:// 打开会整站断链，截出来的是无样式页面且不报错。

为什么用 iframe 探针量高度：headless Chrome 的 --screenshot 只截窗口，
没有整页参数；给 41 个页面各来一趟「量高 + 截图」就是 82 次启动。
探针页与站点同源，一个页面里塞 41 个 iframe 一次拿全高度，降到 42 次。

产物：design/site/pages/desktop/<slug>.png、.../mobile/<slug>.png
只写 dist/（已 gitignore）与 design/site/pages/，不碰任何入库源文件。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent            # website/tools
WEB = HERE.parent                                  # website
DIST = WEB / "dist"
DEST = WEB.parent / "design" / "site" / "pages"
PORT = int(os.environ.get("PORT", "8765"))
BASE = f"http://127.0.0.1:{PORT}"


def find_chrome() -> str:
    env = os.environ.get("ZCHAIN_CFT_CHROME")
    if env:
        return env
    for root in (Path("/tmp/chrome"), Path.home() / "Library/Caches"):
        if not root.exists():
            continue
        for cand in root.glob("**/Google Chrome for Testing"):
            return str(cand)
    sys.exit("Chrome for Testing 未找到；请设置 ZCHAIN_CFT_CHROME")


def chrome_flags() -> list[str]:
    """所有 Chrome 启动共用的参数。

    --user-data-dir 必须给：ZCHAIN_CFT_CHROME 可以指向系统 Chrome
    （当 Chrome for Testing 的 GPU 子进程被环境打断时的退路），
    不带独立 profile 会直接附着到用户正在运行的那个实例上，
    --screenshot 就什么也不写、也不报错。
    """
    global _PROFILE
    if _PROFILE is None:
        _PROFILE = Path(tempfile.mkdtemp(prefix="zchain-shoot-"))
    return ["--headless", "--disable-gpu", "--no-first-run",
            "--disable-dev-shm-usage", f"--user-data-dir={_PROFILE}"]


_PROFILE: Path | None = None


# 探针失败时的兜底出图高度：要大于最长页，尾部由 trim() 精确裁掉。
DEFAULT_H = {1280: 6500, 390: 9500}


def routes() -> list[tuple[str, str]]:
    """dist 下每个 index.html → (站点路由, slug)"""
    out = []
    for f in sorted(DIST.rglob("index.html")):
        rel = f.parent.relative_to(DIST).as_posix()
        if rel == ".":
            out.append(("/", "home"))
        else:
            out.append(("/" + rel + "/", rel.replace("/", "-")))
    return out


def measure(chrome: str, rs: list[tuple[str, str]], vw: int) -> dict[str, int]:
    """一个同源探针页塞满 iframe，一次读回所有页面高度。

    坑：iframe 不设 width 时默认只有 300px，正文被压成窄栏后
    scrollHeight 会虚高近 2 倍（首轮全站因此带了几千 px 尾部空白）。
    必须显式给到与截图一致的视口宽度。
    """
    frames = "".join(
        f'<iframe data-slug="{quote(slug)}" src="{quote(url)}"></iframe>'
        for url, slug in rs
    )
    probe = f"""<!DOCTYPE html><meta charset="utf-8"><body style="margin:0">
<style>iframe{{display:block;width:{vw}px;height:1000px;border:0}}</style>
{frames}
<script>
window.addEventListener("load", function () {{
  setTimeout(function () {{
    var out = {{}};
    Array.prototype.forEach.call(document.querySelectorAll("iframe"), function (fr) {{
      try {{
        var d = fr.contentDocument.documentElement;
        out[decodeURIComponent(fr.dataset.slug)] =
          Math.max(d.scrollHeight, d.offsetHeight);
      }} catch (e) {{ out[decodeURIComponent(fr.dataset.slug)] = 0; }}
    }});
    var s = document.createElement("div");
    s.id = "__heights";
    s.textContent = JSON.stringify(out);
    document.body.appendChild(s);
  }}, 2500);
}});
</script></body>"""
    (DIST / "__probe.html").write_text(probe, encoding="utf-8")
    try:
        try:
            html = subprocess.run(
                [chrome, *chrome_flags(), "--hide-scrollbars",
                 f"--window-size={vw + 40},1000",
                 "--virtual-time-budget=12000", "--dump-dom", f"{BASE}/__probe.html"],
                capture_output=True, text=True,
                timeout=int(os.environ.get("PROBE_TIMEOUT", "90")),
            ).stdout
        except subprocess.TimeoutExpired:
            # 量高探针只是优化，不是必需：机器负载高时它会超时。
            # 回退成"按足够高的窗口出图 + trim() 裁尾"，结果同样正确，只是慢一点、临时文件大一点。
            print(f"  ! 探针超时（{vw}px），改用固定高度 + 裁尾", file=sys.stderr)
            return {}
    finally:
        (DIST / "__probe.html").unlink(missing_ok=True)

    m = re.search(r'<div id="__heights">(.*?)</div>', html, re.S)
    if not m:
        print("  ! 探针未返回高度，全部回退 1600px", file=sys.stderr)
        return {slug: 1600 for _, slug in rs}
    raw = json.loads(m.group(1).replace("&quot;", '"').replace("&amp;", "&"))
    # 夹逼：太短的页面按视口出，超长页截断到 12000 避免内存爆
    return {k: min(max(int(v or 0), vw == 390 and 900 or 820), 12000)
            for k, v in raw.items()}


def shoot(chrome: str, url: str, w: int, h: int, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [chrome, *chrome_flags(), "--hide-scrollbars",
         f"--window-size={w},{h}", "--virtual-time-budget=3500",
         f"--screenshot={out}", url],
        capture_output=True, text=True, timeout=120,
    )


def trim(path: Path, pad: int = 44) -> int:
    """把尾部纯背景空白裁掉，只留 pad px。探针偶发虚高，出图必须干净。"""
    from PIL import Image

    with Image.open(path) as im:
        h = im.height
        if h < 200:
            return h
        strip = im.convert("L").resize((6, h), Image.BILINEAR)
        px = strip.load()
        rows = [sum(px[x, y] for x in range(6)) / 6.0 for y in range(h)]
        bg = rows[-1]
        content = [i for i, v in enumerate(rows) if abs(v - bg) > 4]
        end = (max(content or [0]) + pad)
        if end >= h - 8:
            return h
        im.crop((0, 0, im.width, min(end, h))).save(path)
        return min(end, h)


def apply_ground(ground: str) -> int:
    """给 dist 里每个 <html> 打 data-ground。

    坑：ledger.css 的夜场是 html[data-ground="night"] 选择器，而站点模板的
    <html lang="zh-CN"> 根本没有这个属性 —— 只改 CSS 不写属性，夜场那轮会
    静默出一堆和纸白逐字节相同的假图（首轮就是这样）。dist 是构建产物，改它安全。
    """
    n = 0
    for f in DIST.rglob("*.html"):
        t = f.read_text(encoding="utf-8")
        new = re.sub(
            r'<html([^>]*)>',
            lambda m: "<html" + re.sub(r'\s*data-ground="[^"]*"', '', m.group(1))
                      + f' data-ground="{ground}">' if ground != "paper"
                      else "<html" + re.sub(r'\s*data-ground="[^"]*"', '', m.group(1)) + ">",
            t, count=1)
        if new != t:
            f.write_text(new, encoding="utf-8")
        n += 1
    return n


_TH = re.compile(r"<th[^>]*>(.*?)</th>", re.S)
_TR = re.compile(r"<tr\b[^>]*>.*?</tr>", re.S)
_TD = re.compile(r"<td\b([^>]*)>", re.S)
_TAG = re.compile(r"<[^>]+>")


def label_tables(html: str) -> str:
    """给每个 <td> 补 data-label（取该列 <th> 文本），并给表打 data-labeled。

    移动端的「凭证行卡」需要每格知道自己列的表头，纯 CSS 取不到兄弟元素文本，
    所以必须有这个属性。这里只改 dist；落地要把它做进 build.py 的 emit_table
    （见 design/site/README.md「移动落地补丁」）。没有 thead 的表原样跳过，
    CSS 侧有 table:not([data-labeled]) 的横滚兜底。
    """
    def one(m: re.Match) -> str:
        block = m.group(0)
        head = re.search(r"<thead\b[^>]*>.*?</thead>", block, re.S)
        if not head:
            return block
        cols = [_TAG.sub("", t).strip() for t in _TH.findall(head.group(0))]
        if not cols:
            return block

        def fix_row(rm: re.Match) -> str:
            row = rm.group(0)
            if "<td" not in row:
                return row                      # thead 行或纯表头行
            i = -1

            def fix_td(tm: re.Match) -> str:
                nonlocal i
                i += 1
                attrs = tm.group(1)
                if i >= len(cols) or not cols[i] or "data-label" in attrs:
                    return tm.group(0)
                lab = cols[i].replace('"', "&quot;")
                return f"<td{attrs} data-label=\"{lab}\">"

            return _TD.sub(fix_td, row)

        body = re.sub(r"<tbody\b[^>]*>.*?</tbody>",
                      lambda b: _TR.sub(fix_row, b.group(0)), block, flags=re.S)
        body = body.replace("<table>", '<table data-labeled="1">', 1)
        return body

    return re.sub(r"<table\b.*?</table>", one, html, flags=re.S)


# 横滑轨要把「当前项」滚进视野：静态截图看不到滚动位置，评审图必须体现这一点。
# 这 7 行同时就是落地所需的 JS（写进 README）。
# 注意：scrollLeft 必须设在「真正会滚的那个容器」上。导航的滚动容器是 .site-nav，
# 而 .nav-list 是 width:max-content 的被卷内容 —— 设在它身上等于没设（首轮就是这样）。
RAIL_JS = """<script>
(function(){
function sc(e){while(e&&e!==document.body){var o=getComputedStyle(e).overflowX;
  if(o==="auto"||o==="scroll")return e;e=e.parentElement}return null}
function one(sel){var a=document.querySelector(sel+" a.active");if(!a)return;
  var t=sc(a.parentElement)||a.parentElement;if(!t)return;
  /* 用 rect 差值而不是 offsetLeft：.site-header 是 position:sticky，会当 offsetParent，
     offsetLeft 就把头部偏移一起算进去，靠后的项会滚过头。 */
  var tb=t.getBoundingClientRect(), ab=a.getBoundingClientRect();
  t.scrollLeft+=ab.left-tb.left-(t.clientWidth-ab.width)/2;}
function fit(){one(".site-nav .nav-list");one(".docs-side ul");}
/* load 与 DOMContentLoaded 各跑一次：只挂 load 会让「active 是否在视野内」
   变成审计侧的时序竞态（实测同一份 CSS 两次结果不同）。 */
window.addEventListener("load",function(){setTimeout(fit,120)});
if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",function(){setTimeout(fit,60)});}
else{setTimeout(fit,60);}
})();
</script>"""


def apply_mobile_layer() -> None:
    """把移动体系层 + data-label + 轨道定位脚本叠进 dist（预览专用，不碰入库文件）。"""
    layer = DEST.parent / "ledger-mobile.css"
    if not layer.exists():
        sys.exit(f"缺少移动体系层 {layer}")
    css = (WEB / "assets" / "css" / "main.css").read_text(encoding="utf-8")
    (DIST / "assets" / "css" / "main.css").write_text(
        css + "\n\n" + layer.read_text(encoding="utf-8"), encoding="utf-8")
    n = 0
    for f in DIST.rglob("*.html"):
        t = f.read_text(encoding="utf-8")
        new = label_tables(t)
        if "</body>" in new:
            new = new.replace("</body>", RAIL_JS + "</body>", 1)
        if new != t:
            f.write_text(new, encoding="utf-8")
            n += 1
    print(f"  ⚠ 预览叠加：ledger-mobile.css 已并入 dist/main.css，"
          f"{n} 个页面已注入 data-label 与轨道定位脚本（入库文件未改）")


def main() -> int:
    if not (DIST / "index.html").exists():
        sys.exit("dist/ 未构建；先跑 python3 website/build.py")
    src_css = (WEB / "assets" / "css" / "main.css").read_text(encoding="utf-8")
    dist_css = DIST / "assets" / "css" / "main.css"
    if not dist_css.exists():
        sys.exit("dist 里没有 main.css；重跑 python3 website/build.py")

    mobile = bool(os.environ.get("MOBILE"))
    ground = os.environ.get("GROUND", "paper")
    vw = int(os.environ.get("VW", "390" if mobile else "1280"))

    if dist_css.read_text(encoding="utf-8") != src_css:
        if not mobile:
            sys.exit("dist/assets/css/main.css 与入库源不一致（dist 过期）；重跑 python3 website/build.py")
    elif mobile:
        apply_mobile_layer()
    elif not mobile:
        print("出图即入库 website/assets/css/main.css 的真实渲染（不再有 overlay 分支）")

    rs = routes()
    print(f"  data-ground={ground} 已写入 {apply_ground(ground)} 个页面")
    # 夜场只出顶层页：docs 29 篇正文结构同构，两套底各出一遍只会让评审台变两倍长
    if os.environ.get("TOPLEVEL"):
        rs = [r for r in rs if r[0].strip("/").count("/") == 0]
    if mobile:
        suffix = "" if ground == "paper" else f"-{ground}"
        if vw != 390:
            suffix += f"-{vw}"
        desk = DEST / f"mobile{suffix}"
    else:
        desk = DEST / ("desktop" if ground == "paper" else f"desktop-{ground}")
    print(f"{'mobile' if mobile else 'desktop'} · {ground} · {vw}px · {len(rs)} 个页面；起 HTTP :{PORT}")
    handler = partial(SimpleHTTPRequestHandler, directory=str(DIST))
    handler.log_message = lambda *a, **k: None
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    chrome = find_chrome()

    try:
        heights = measure(chrome, rs, vw)
        shutil.rmtree(desk, ignore_errors=True)
        for url, slug in rs:
            h = heights.get(slug) or DEFAULT_H.get(vw, 6500)
            out = desk / f"{slug}.png"
            shoot(chrome, BASE + quote(url), vw, h, out)
            print(f"  {slug:<38} {h}px → {trim(out)}px")
    finally:
        srv.shutdown()

    n = len(list(desk.glob("*.png")))
    print(f"\n完成：{ground} {vw}px 共 {n} 张 → {desk.relative_to(DEST.parent.parent)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
