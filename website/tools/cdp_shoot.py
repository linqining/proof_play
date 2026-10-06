#!/usr/bin/env python3
"""通过 CDP 复用「有头 Chrome」批量出图。

为什么不用 --headless：这台机器上 headless Chrome（含 Chrome for Testing bundle）
会在 gpu_data_manager_impl_private.cc:417 直接 SIGTRAP 自杀，连 about:blank 都起不来，
加 --disable-gpu / --no-sandbox / swiftshader / --disable-breakpad 均无效。
有头 Chrome 正常，所以这里起一个 --window-position 挪到屏幕外的实例，
用 CDP 的 Emulation.setDeviceMetricsOverride 做真实移动视口仿真，
再用 Page.captureScreenshot(captureBeyondViewport) 一次拿整页 —— 不需要高度探针。

用法：
  python3 website/tools/cdp_shoot.py                      # 全部页面 @1280 纸白 → pages/desktop/
  GROUND=night TOPLEVEL=1 python3 website/tools/cdp_shoot.py   # 一级页夜场 → pages/desktop-night/
  MOBILE=1 python3 website/tools/cdp_shoot.py             # 全部页面 @390 → pages/mobile/
  VW=360,430 SLUGS=explorer,docs-protocol-abi,home ...    # 多档位抽查
"""
import base64
import json
import os
import pathlib
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlparse

HERE = pathlib.Path(__file__).resolve().parent
WEB = HERE.parent
DIST = WEB / "dist"
DEST = WEB.parent / "design" / "site" / "pages"
PORT = int(os.environ.get("PORT", "8770"))
CDP_PORT = int(os.environ.get("CDP_PORT", "9333"))
BASE = f"http://127.0.0.1:{PORT}"
CHROME = os.environ.get(
    "CHROME_BIN", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1")


# ---------------------------------------------------------------- WebSocket
class WS:
    """最小可用的客户端 WebSocket：够跑 CDP，不引第三方依赖。"""

    def __init__(self, url: str):
        u = urlparse(url)
        self.sock = socket.create_connection((u.hostname, u.port or 80), timeout=60)
        key = base64.b64encode(os.urandom(16)).decode()
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        req = (f"GET {path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("WebSocket 握手失败")
            buf += chunk
        if b"101" not in buf.split(b"\r\n")[0]:
            raise RuntimeError("WebSocket 握手非 101")
        self.buf = buf.split(b"\r\n\r\n", 1)[1]
        self._id = 0

    def _frame(self, payload: bytes) -> bytes:
        n = len(payload)
        head = bytearray([0x81])                       # FIN + text
        if n < 126:
            head.append(0x80 | n)
        elif n < 65536:
            head.append(0x80 | 126); head += n.to_bytes(2, "big")
        else:
            head.append(0x80 | 127); head += n.to_bytes(8, "big")
        mask = os.urandom(4)
        return bytes(head) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

    def _need(self, k: int) -> bytes:
        while len(self.buf) < k:
            chunk = self.sock.recv(1 << 16)
            if not chunk:
                raise RuntimeError("WebSocket 连接断开")
            self.buf += chunk
        out, self.buf = self.buf[:k], self.buf[k:]
        return out

    def _recv_frame(self):
        hdr = self._need(2)
        ln = hdr[1] & 0x7F
        if ln == 126:
            ln = int.from_bytes(self._need(2), "big")
        elif ln == 127:
            ln = int.from_bytes(self._need(8), "big")
        payload = self._need(ln)
        return json.loads(payload.decode("utf-8", "replace")) if payload else {}

    def call(self, sid, method, params=None, timeout=90):
        self._id += 1
        mid = self._id
        msg = {"id": mid, "method": method, "params": params or {}}
        if sid:
            msg["sessionId"] = sid
        self.sock.sendall(self._frame(json.dumps(msg).encode()))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                obj = self._recv_frame()
            except (RuntimeError, json.JSONDecodeError):
                continue
            if obj.get("id") == mid:
                if "error" in obj:
                    raise RuntimeError(f"{method}: {obj['error']}")
                return obj.get("result", {})
        raise TimeoutError(method)


# ---------------------------------------------------------------- chrome
def launch_chrome(vw: int = 430) -> subprocess.Popen:
    profile = tempfile.mkdtemp(prefix="zchain-cdp-")
    p = subprocess.Popen(
        [CHROME, f"--user-data-dir={profile}", f"--remote-debugging-port={CDP_PORT}",
         "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
         "--disable-sync", "--metrics-recording-only", "--mute-audio",
         "--hide-scrollbars", f"--window-size={max(vw, 430)},900",
         "--window-position=-32000,-32000", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        time.sleep(0.5)
        if p.poll() is not None:
            sys.exit(f"Chrome 启动失败 rc={p.returncode}；确认 {CHROME} 可执行")
        try:
            if urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=2).status == 200:
                return p
        except Exception:
            pass
    p.kill()
    sys.exit("Chrome DevTools 端口 40s 未就绪")


def cdp_ws() -> WS:
    d = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=5).read())
    return WS(d["webSocketDebuggerUrl"])


def shoot_page(ws: WS, url: str, vw: int, dsf: int, out: pathlib.Path,
               device: bool = True) -> int:
    t = ws.call(None, "Target.createTarget", {"url": "about:blank"})
    tid = t["targetId"]
    sid = ws.call(None, "Target.attachToTarget", {"targetId": tid, "flatten": True})["sessionId"]
    try:
        ws.call(sid, "Page.enable")
        ws.call(sid, "Runtime.enable")
        ws.call(sid, "Network.enable")
        ws.call(sid, "Emulation.setDeviceMetricsOverride",
                {"width": vw, "height": 900, "deviceScaleFactor": dsf, "mobile": device})
        if device:
            ws.call(sid, "Emulation.setUserAgentOverride", {"userAgent": UA})
        ws.call(sid, "Page.navigate", {"url": url})
        for _ in range(120):
            r = ws.call(sid, "Runtime.evaluate",
                        {"expression": "document.readyState", "returnByValue": True}, timeout=20)
            if r.get("result", {}).get("value") == "complete":
                break
            time.sleep(0.25)
        ws.call(sid, "Runtime.evaluate",
                {"expression": "new Promise(r=>setTimeout(()=>r(1),400))"}, timeout=20)
        h = ws.call(sid, "Runtime.evaluate", {"expression": (
            "Math.max(document.documentElement.scrollHeight,"
            " document.body.scrollHeight, document.body.offsetHeight)"),
            "returnByValue": True}, timeout=20)["result"]["value"]
        # 不用 captureBeyondViewport：它会把横向滚动轨（chip 导航 / 凭证表）的
        # 完整内容也算进画幅，explorer 因此从 390 变成 651 CSS px 宽。
        # 改成把视口高度拉到全文高度后按视口截图，宽度恒等于 vw。
        ws.call(sid, "Emulation.setDeviceMetricsOverride",
                {"width": vw, "height": min(int(h), 16000), "deviceScaleFactor": dsf, "mobile": True})
        ws.call(sid, "Runtime.evaluate",
                {"expression": "new Promise(r=>requestAnimationFrame(()=>r(1)))"}, timeout=20)
        shot = ws.call(sid, "Page.captureScreenshot", {"format": "png"}, timeout=120)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(base64.b64decode(shot["data"]))
        return int(h)
    finally:
        ws.call(None, "Target.closeTarget", {"targetId": tid})


def routes():
    out = []
    for f in sorted(DIST.rglob("index.html")):
        rel = f.parent.relative_to(DIST).as_posix()
        out.append(("/", "home") if rel == "." else ("/" + rel + "/", rel.replace("/", "-")))
    return out


def staged_dist(mobile: bool, ground: str) -> pathlib.Path:
    """把 dist 复制到私有临时目录，叠加只发生在副本上。

    为什么要副本：dist 是共享构建产物。实测有并行会话在跑 build.py，
    直接改 dist 会出现「刚注入完就被别人清空」的竞态 —— 出图和审计都拿到基线态，
    而且不报错。副本让一次运行看到的是一个固定快照。
    """
    import shutil
    if not (DIST / "index.html").exists():
        sys.exit("dist/ 未构建；先跑 python3 website/build.py")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="zchain-dist-"))
    d = tmp / "dist"
    shutil.copytree(DIST, d)
    sys.path.insert(0, str(HERE))
    import site_shoot
    site_shoot.DIST = d                       # 叠加函数按副本走
    if mobile:
        src = (WEB / "assets" / "css" / "main.css").read_text(encoding="utf-8")
        (d / "assets" / "css" / "main.css").write_text(src, encoding="utf-8")
        site_shoot.apply_mobile_layer()
    site_shoot.apply_ground(ground)
    return d


def main() -> int:
    # BOARD 模式：出非站点页（如体系板），SERVE 指静态根目录，PAGES 给 "路径:slug" 列表。
    # 体系板用相对路径引 ../../website/...，所以根目录必须是仓库根而不是 dist。
    board = os.environ.get("BOARD")
    ground = os.environ.get("GROUND", "paper")
    mobile = bool(os.environ.get("MOBILE"))
    if board:
        serve = WEB.parent
        rs = [("/" + p.split(":")[0].lstrip("/"), p.split(":")[1]) for p in board.split(",")]
    else:
        serve = staged_dist(mobile, ground)
        rs = []
        for f in sorted(serve.rglob("index.html")):
            rel = f.parent.relative_to(serve).as_posix()
            rs.append(("/", "home") if rel == "." else ("/" + rel + "/", rel.replace("/", "-")))

    # BOARD 必须默认 390：板子靠媒体查询排版，用桌面视口出图 = 出一张没触发移动层的假图
    vws = [int(x) for x in os.environ.get("VW", "390" if (mobile or board) else "1280").split(",")]
    dsf = int(os.environ.get("DSF", "2"))
    only = os.environ.get("SLUGS")

    if only:
        want = {s.strip() for s in only.split(",") if s.strip()}
        rs = [r for r in rs if r[1] in want]
    if os.environ.get("TOPLEVEL"):
        rs = [r for r in rs if r[0].strip("/").count("/") == 0]

    handler = partial(SimpleHTTPRequestHandler, directory=str(serve))
    handler.log_message = lambda *a, **k: None
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    proc = launch_chrome(max(vws))
    ws = cdp_ws()
    total = 0
    try:
        for vw in vws:
            if board:
                outdir = DEST.parent / "png"
            elif mobile:
                parts = ["mobile"]
                if ground != "paper":
                    parts.append(ground)
                if vw != 390:
                    parts.append(str(vw))
                outdir = DEST / "-".join(parts)
            else:
                # 桌面目录名与 site_shoot.py 保持一致：design/review/build.py 按这两个名字收图。
                outdir = DEST / ("desktop" if ground == "paper" else f"desktop-{ground}")
            if not only and not board:        # 全量跑才清空，抽查与体系板不动已有图
                shutil.rmtree(outdir, ignore_errors=True)
            print(f"{'移动' if mobile else '桌面'}视口 {vw}px · {ground} · {len(rs)} 页 → {outdir.name}/")
            for url, slug in rs:
                name = f"{slug}-{ground}" if board else slug
                # 板子的底面由 ?g= 决定；不传就会拿模板里写死的 paper，
                # 夜场那轮会静默出一张与纸白逐字节相同的假图。
                q = f"?g={ground}" if board else ""
                h = shoot_page(ws, BASE + quote(url) + q, vw, dsf,
                               outdir / f"{name}.png", device=mobile)
                print(f"  {name:<38} {h}px")
                total += 1
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
    print(f"\n完成：{total} 张 → design/site/pages/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
