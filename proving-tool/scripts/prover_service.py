#!/usr/bin/env python3
"""P2-M2 结算电路 prover 服务（STARKNET_PROVER_URL 的服务端形态）。

协议（与 texas/src/starknet/settlement_prover.rs::HttpSettlementProver 对齐）：
  GET  /          -> {"ok": true, "service": ..., "program": ...}
  POST /          -> body {"circuit": "settlement_private", "hand_id": N,
                           "inputs": ["0x..", ...]}（Span ABI，2026-09-30 重构 +
                           9 人桌：103 个 felt = [102 长度前缀] ++ settle wire
                           102 词 = 41 标量 + 1 计数 + 60 动作词条打包词，
                           [len, elements…] 摊平，序同 settlement_stmt 布局；#18 Phase B/C）
                   -> {"ok": true, "output": [hex...], "program_hash": "0x.."}
                    （电路断言失败/证明失败 → 非 200 + {"ok": false, "error": ..}）

内部调 prove-hand（Cairo VM → Stwo prove → verify）。witness 只在临时目录
短暂落盘后删除；对外只返回公开段。启动：
  proving-tool/scripts/prover_service.py            # 默认 127.0.0.1:8091
  PROVER_SERVICE_PORT=8091 ...（首次运行会自动构建 nightly 工具链）
"""
import json
import os
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # proving-tool/
PROGRAM = os.path.join(ROOT, "src", "settlement_private.cairo")
MANIFEST = os.path.join(ROOT, "Cargo.toml")
UPSTREAM_TIMEOUT_SECS = 45


def _run_prove(inputs: list) -> dict:
    if not os.path.exists(PROGRAM):
        raise RuntimeError(f"circuit program missing: {PROGRAM}")
    with tempfile.TemporaryDirectory(prefix="settlement-prove-") as tmp:
        inputs_path = os.path.join(tmp, "inputs.json")
        with open(inputs_path, "w") as f:
            json.dump(inputs, f)
        env = dict(os.environ, RUSTUP_TOOLCHAIN="nightly-2026-01-15")
        subprocess.run(
            ["cargo", "run", "--quiet", "--release", "--manifest-path", MANIFEST,
             "--bin", "prove-hand", "--",
             "--program", PROGRAM, "--inputs", inputs_path, "--out-dir", tmp],
            check=True, env=env, timeout=UPSTREAM_TIMEOUT_SECS,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        with open(os.path.join(tmp, "public_outputs.json")) as f:
            public = json.load(f)
    return {"ok": True, "output": public["output"], "program_hash": public["program_hash"]}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self._json({"ok": True, "service": "settlement_private prover",
                    "circuit": "settlement_private"})

    def do_POST(self):  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            if body.get("circuit") != "settlement_private":
                return self._json({"ok": False, "error": "unknown circuit"}, 404)
            inputs = body.get("inputs")
            if not isinstance(inputs, list) or not inputs:
                return self._json({"ok": False, "error": "missing inputs"}, 400)
            self._json(_run_prove(inputs))
        except subprocess.CalledProcessError as e:
            # 电路断言失败（digest 不匹配/非零和等）→ Cairo VM 中止，无证明
            self._json({"ok": False, "error": f"prove failed (exit {e.returncode})"}, 422)
        except subprocess.TimeoutExpired:
            self._json({"ok": False, "error": "prove timed out"}, 504)
        except Exception as e:  # noqa: BLE001
            self._json({"ok": False, "error": str(e)}, 500)

    def _json(self, obj, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def log_message(self, fmt, *args):  # 静默默认访问日志
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PROVER_SERVICE_PORT", "8091"))
    print(f"[prover_service] settlement_private circuit on http://127.0.0.1:{port}")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
