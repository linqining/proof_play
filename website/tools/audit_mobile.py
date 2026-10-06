#!/usr/bin/env python3
"""移动端还原度走查（可复用，不是一次性脚本）。

为什么不用看图代替：41 页 × 每项 5 个断言，人眼看第 3 页就开始漏。
横向溢出、触控下限、凭证卡缺标签这三类是**可判定的**，必须程序化全量跑。

用法：python3 website/tools/audit_mobile.py
前置：先跑 `python3 website/build.py && MOBILE=1 python3 website/tools/cdp_shoot.py`
      （本脚本读的是叠加后的 dist，所以必须在出图后立刻跑，否则量的是基线态）
"""
import json
import os
import pathlib
import sys
import threading
import time
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
WEB = HERE.parent
DIST = WEB / "dist"
PORT = int(os.environ.get("PORT", "8780"))
BASE = f"http://127.0.0.1:{PORT}"
VW = int(os.environ.get("VW", "390"))

sys.path.insert(0, str(HERE))
from cdp_shoot import WS, cdp_ws, launch_chrome, staged_dist   # noqa: E402

# 在浏览器里跑的探针：返回一页的全部断言结果
PROBE = r"""
(function(vw){
  var out={};
  out.overflow = Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) - vw;
  var q=function(s){return Array.prototype.slice.call(document.querySelectorAll(s))};

  // 触控下限：只查导航/文档轨/按钮这类「控件」，正文内联链接随文本流不计
  var taps=[];
  q('.nav-list a, .docs-side a, .btn, button, .ground-toggle, input, select').forEach(function(e){
    var r=e.getBoundingClientRect();
    if(!r.width && !r.height) return;
    if(r.width>vw+2) return;                 // 溢出元素由 overflow 断言负责
    if(Math.min(r.height, r.width) < 40) taps.push(
      Math.round(Math.min(r.height,r.width))+'px '+e.tagName+'.'+String(e.className||'').trim().split(/\s+/)[0]);
  });
  out.taps = taps.slice(0,4);
  out.tapCount = taps.length;

  // 凭证行卡：标签覆盖率
  var tables=q('table'), labeled=q('table[data-labeled]'), bare=0, tds=0;
  tables.forEach(function(t){ t.querySelectorAll('tbody td, tr td').forEach(function(td){
    tds++; if(!td.hasAttribute('data-label')) bare++; }); });
  out.tables=tables.length; out.labeledTables=labeled.length; out.tds=tds; out.unlabeledTds=bare;

  // chip 轨：可滑 + active 在视野内
  var nav=document.querySelector('.site-nav');
  if(nav){ var a=nav.querySelector('a.active');
    out.railScrollable = nav.scrollWidth > nav.clientWidth + 2;
    out.railContentW = nav.scrollWidth;
    out.activeVisible = a ? (a.getBoundingClientRect().right <= nav.getBoundingClientRect().right+1
                             && a.getBoundingClientRect().left >= nav.getBoundingClientRect().left-1) : null;
  }
  var ds=document.querySelector('.docs-side ul');
  if(ds){ var d=ds.querySelector('a.active');
    out.docsActiveVisible = d ? (d.getBoundingClientRect().right <= ds.getBoundingClientRect().right+1
                                 && d.getBoundingClientRect().left >= ds.getBoundingClientRect().left-1) : null;
  }
  // 字号分两层：正文/表格 ≥12px；微标签（状态丸、chip、kicker、表头）是这套体系
  // 刻意保留的 9.5–10px 大写等宽层，只要求 ≥9.5px。混用一条线会把设计意图报成缺陷。
  var MICRO=/\b(st|st-ok|st-bad|st-info|st-muted|st-warn|chip|docs-kicker|card-kicker|footer-h|banner-tag|tagline-en|breadcrumb|nav-list|docs-side-h|board-)/;
  var tiny=[], microTiny=[];
  q('p, li, td, th, a, h1, h2, h3, h4, span, summary, dd, dt').forEach(function(e){
    if(!e.textContent.trim()) return;
    if(e.querySelector('p,li,td,th,h1,h2,h3')) return;   // 只量叶子节点
    var fs=parseFloat(getComputedStyle(e).fontSize);
    var cls=String(e.className||'')+' '+String((e.closest('[class]')||{}).className||'');
    if(MICRO.test(cls) || getComputedStyle(e).letterSpacing!=='0px'){
      if(fs < 9.4) microTiny.push(Math.round(fs*10)/10+'px '+e.tagName+'.'+String(e.className||'').trim().split(/\s+/)[0]);
    } else if(fs < 11.9) {
      tiny.push(Math.round(fs*10)/10+'px '+e.tagName+'.'+String(e.className||'').trim().split(/\s+/)[0]);
    }
  });
  out.tiny=tiny.slice(0,3); out.tinyCount=tiny.length;
  out.microTiny=microTiny.slice(0,3); out.microTinyCount=microTiny.length;

  // 横向出血：真正跑到视口外的元素（排除滚动容器内的正常内容）
  var bleed=[];
  q('body *').forEach(function(e){
    var p=e.parentElement, sc=false;
    while(p){ if(/(auto|scroll|hidden)/.test(getComputedStyle(p).overflowX)){sc=true;break} p=p.parentElement; }
    if(sc) return;
    var r=e.getBoundingClientRect();
    if(r.right>vw+2 && r.width>10) bleed.push(Math.round(r.right)+'px '+e.tagName+'.'+String(e.className||'').trim().split(/\s+/)[0]);
  });
  bleed.sort(function(a,b){return parseInt(b)-parseInt(a)});
  out.bleed=bleed.slice(0,4); out.bleedCount=bleed.length;

  // 「药丸被拉成通栏色条」：凭证行卡的 td 是 grid，子项默认 justify-self:stretch。
  // 带底色的小元素（状态丸 / chip）一旦铺满值列，桌面语义就没了。
  // 溢出、触控、字号三条断言都抓不到它——它不溢出、不难点、字号也对。
  // 注意基准是**值列那一格**，不是整个 td：td 宽 342 而值列只有 ~232，
  // 用整个 td 算比例最高才 0.68，会把这条断言变成永远不触发（第一版就是这样）。
  var stretch=[];
  q('table td > *').forEach(function(e){
    var cs=getComputedStyle(e), txt=(e.textContent||'').trim();
    if(!txt || txt.length>24) return;
    if(cs.backgroundColor==='rgba(0, 0, 0, 0)' || cs.backgroundColor==='transparent') return;
    var td=e.parentElement, tdc=getComputedStyle(td);
    var tracks=(tdc.gridTemplateColumns||'').split(/\s+/).filter(function(s){return /px$/.test(s)})
                .map(parseFloat);
    var col=tracks.length>1 ? tracks[tracks.length-1]
          : td.getBoundingClientRect().width - parseFloat(tdc.paddingLeft) - parseFloat(tdc.paddingRight);
    var w=e.getBoundingClientRect().width;
    if(col>0 && w/col >= 0.85 && !/^(start|center)$/.test(cs.justifySelf))
      stretch.push(Math.round(w/col*100)+'% '+e.tagName+'.'+String(e.className||'').trim().split(/\s+/)[0]);
  });
  out.stretch=stretch.slice(0,4); out.stretchCount=stretch.length;
  return out;
})
"""


def probe(ws, sid, url, vw):
    ws.call(sid, "Page.enable")
    ws.call(sid, "Emulation.setDeviceMetricsOverride",
            {"width": vw, "height": 900, "deviceScaleFactor": 1, "mobile": True})
    ws.call(sid, "Page.navigate", {"url": url})
    for _ in range(60):
        v = ws.call(sid, "Runtime.evaluate",
                    {"expression": "document.readyState", "returnByValue": True}, timeout=20)
        if v.get("result", {}).get("value") == "complete":
            break
        time.sleep(0.2)
    # 轨道定位脚本要等它生效；固定 sleep 会把它变成时序竞态（实测同一份 CSS 两次结果不同）。
    # 做法：跑探针，若 active 判为不可见就再等一轮重测，最多 5 次。
    d = None
    for _ in range(5):
        ws.call(sid, "Runtime.evaluate",
                {"expression": "new Promise(r=>setTimeout(()=>r(1),400))"}, timeout=20)
        r = ws.call(sid, "Runtime.evaluate",
                    {"expression": f"({PROBE})({vw})", "returnByValue": True}, timeout=40)
        v = r["result"]["value"]
        d = json.loads(v) if isinstance(v, str) else v
        if d.get("activeVisible") is not False and d.get("docsActiveVisible") is not False:
            break
    return d


def main() -> int:
    # 审计跑在私有副本上：dist 是共享构建产物，实测有并行会话在重建它，
    # 直接读 dist 会量到「刚被别人清掉叠加层」的基线态还全绿。
    serve = staged_dist(mobile=True, ground="paper")
    css = (serve / "assets" / "css" / "main.css").read_text(encoding="utf-8")
    if "凭证行" not in css:
        sys.exit("副本里没有移动体系层；检查 design/site/ledger-mobile.css")
    rs = []
    for f in sorted(serve.rglob("index.html")):
        rel = f.parent.relative_to(serve).as_posix()
        rs.append(("/", "home") if rel == "." else ("/" + rel + "/", rel.replace("/", "-")))
    only = [s.strip() for s in os.environ.get("SLUGS", "").split(",") if s.strip()]
    if only:                       # 定点复跑用：改一条 CSS 后只想验 explorer/status 这类页
        want = set(only)
        picked = [r for r in rs if r[1] in want]
        if not picked:
            sys.exit(f"SLUGS 没匹配到任何页；例：{', '.join(s for _, s in rs[:6])}…")
        rs = picked
    handler = partial(SimpleHTTPRequestHandler, directory=str(serve))
    handler.log_message = lambda *a, **k: None
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    proc = launch_chrome()
    ws = cdp_ws()
    fails = []
    rows = []
    try:
        for url, slug in rs:
            t = ws.call(None, "Target.createTarget", {"url": "about:blank"})
            tid = t["targetId"]
            sid = ws.call(None, "Target.attachToTarget",
                          {"targetId": tid, "flatten": True})["sessionId"]
            d = probe(ws, sid, BASE + url, VW)
            ws.call(None, "Target.closeTarget", {"targetId": tid})

            bad = []
            if d["overflow"] > 1:
                bad.append(f"横向溢出 +{d['overflow']}px")
            if d["bleedCount"]:
                bad.append(f"视口外元素 {d['bleedCount']} 个（最远 {d['bleed'][0]}）")
            if d["tapCount"]:
                bad.append(f"触控 <40px 共 {d['tapCount']} 个（{d['taps'][0]}）")
            if d["tables"] and d["labeledTables"] != d["tables"] and d["unlabeledTds"]:
                bad.append(f"凭证卡 {d['labeledTables']}/{d['tables']} 表有标签，{d['unlabeledTds']} 格缺")
            if d.get("activeVisible") is False:
                bad.append("导航 active 不在视野内")
            if d.get("docsActiveVisible") is False:
                bad.append("docs 小节 active 不在视野内")
            if d["tinyCount"]:
                bad.append(f"正文 <12px 共 {d['tinyCount']} 个（{d['tiny'][0]}）")
            if d.get("microTinyCount"):
                bad.append(f"微标签 <9.5px 共 {d['microTinyCount']} 个")
            if d.get("stretchCount"):
                bad.append(f"状态丸/chip 被拉成通栏 {d['stretchCount']} 个（{d['stretch'][0]}）")
            rows.append((slug, d, bad))
            if bad:
                fails.append((slug, bad))
            print(f"  {'✗' if bad else '✓'} {slug:<38} "
                  f"ovf={d['overflow']:+d} tables={d['labeledTables']}/{d['tables']}"
                  f"{'  ' + '; '.join(bad) if bad else ''}")
    finally:
        ws.sock.close()
        proc.terminate()
        for _ in range(20):
            if proc.poll() is not None:
                break
            time.sleep(0.5)
        if proc.poll() is None:
            proc.kill()
        srv.shutdown()

    print(f"\n{VW}px 审计：{len(rows)} 页，{len(fails)} 页有未达项")
    for slug, bad in fails:
        for b in bad:
            print(f"  - {slug}: {b}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
