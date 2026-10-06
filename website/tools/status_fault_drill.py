#!/usr/bin/env python3
"""WEB-ACC-6 静态层故障注入演练（可本机复现，不依赖 status 后端）。

对 website/content/status.md 的组件状态表注入 4 个故障变体：

  1. sequencer_down   Sequencer major outage
  2. prover_backlog   Prover degraded（证明积压）
  3. rpc_degraded     RPC degraded
  4. withdraw_delay   提现服务 degraded（打款延迟/排队）

每个变体：把站点（build.py + templates + content + assets）拷贝到临时目录，
改写 status.md（受影响组件状态徽章 + 影响范围文案 + 事故记录区新增含
影响范围/开始时间/恢复字段的 DRILL 行），运行 build.py，然后断言渲染出的
dist/status/index.html 包含：

  a. 受影响组件标记（st-warn / st-bad 徽章 + 变更后状态词）；
  b. 影响范围文案（组件行说明 + 事故行"影响范围"单元格）；
  c. 恢复记录区（事故记录表含 DRILL 行：开始时间 + 恢复进度 + 演练标注）；
  d. 未受影响组件保持原状；
  e. SAMPLE DATA / devnet 标注仍在（演练页也不冒充真实数据）。

另做基线断言：未注入的构建里各组件保持原状态、事故表含 影响范围 列。

全程只在临时目录构建（不改 dist/），演练页永不入站。退出码 0 = 全过。

用法：python3 website/tools/status_fault_drill.py
"""

from __future__ import annotations

import html as html_mod
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
SITE = TOOLS.parent
REPO = SITE.parent
STATUS_MD = SITE / "content" / "status.md"

# 故障变体定义：组件行定位子串 →（目标状态类，目标状态词，行内说明/影响范围文案）
VARIANTS = [
    {
        "id": "sequencer_down",
        "label": "Sequencer down（出块停止）",
        "component": "Sequencer（软确认链）",
        "status_class": "st-bad",
        "status_text": "major outage",
        "component_note": "演练：出块与软确认暂停，结算确认与 proven 水位推进受影响",
        "affected": "Sequencer（软确认链）；结算确认与 proven 水位推进",
        "impact": "全链出块停止，软确认与证明管道受影响",
        "advice": "演练：请勿发起新的桌局与结算操作",
        "recovery": "恢复中（演练注入，非真实事故）",
    },
    {
        "id": "prover_backlog",
        "label": "Prover 积压（proven 水位延迟）",
        "component": "Prover（证明管道）",
        "status_class": "st-warn",
        "status_text": "degraded",
        "component_note": "演练：证明积压，proven 水位延迟增大；软确认与出块不受影响",
        "affected": "Prover（证明管道）；proven 批次推进",
        "impact": "手结束 → proof-ready 延迟增大；软确认与出块不受影响",
        "advice": "演练：soft 确认照常，proven 之前不影响桌内进行",
        "recovery": "恢复中——积压消化中（演练注入，非真实事故）",
    },
    {
        "id": "rpc_degraded",
        "label": "RPC 降级（查询延迟/错误）",
        "component": "RPC（devnet）",
        "status_class": "st-warn",
        "status_text": "degraded",
        "component_note": "演练：查询延迟升高、部分请求错误；出块与结算不受影响",
        "affected": "RPC（devnet）；第三方查询与钱包同步",
        "impact": "查询延迟升高、部分请求错误；出块与结算不受影响",
        "advice": "演练：客户端可重试或稍后同步",
        "recovery": "恢复中（演练注入，非真实事故）",
    },
    {
        "id": "withdraw_delay",
        "label": "提现延迟（打款排队）",
        "component": "提现服务（托管打款）",
        "status_class": "st-bad",
        "status_text": "major outage",
        "component_note": "演练：提现打款排队延迟增大，处理窗口延长；链上资产与证明状态不受影响",
        "affected": "提现服务（托管打款）；REAL 提现打款窗口",
        "impact": "提现打款延迟增大；链上资产与证明状态不受影响",
        "advice": "演练：提现请求会被排队处理，请参考透明度报告的 SLA 说明",
        "recovery": "恢复中——队列消化中（演练注入，非真实事故）",
    },
]

DRILL_TAG = "演练注入，非真实事故"


def split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def inject(src: str, v: dict) -> str:
    """把故障变体 v 注入 status.md 源码，返回改写后的全文。"""
    lines = src.split("\n")
    out: list[str] = []
    hit_component = False
    hit_incident_table = False
    inserted_incident = False
    i = 0
    while i < len(lines):
        line = lines[i]
        # 组件状态表行：| 组件 | 状态徽章 | 说明 |
        if line.lstrip().startswith("|") and v["component"] in line and "st-" in line:
            cells = split_row(line)
            if len(cells) >= 3:
                cells[1] = f'<span class="st {v["status_class"]}">{v["status_text"]}</span>'
                cells[2] = v["component_note"]
                out.append("| " + " | ".join(cells) + " |")
                hit_component = True
                i += 1
                continue
        # 事故记录表头（| 日期 | 影响范围 | 影响 | ...）
        if line.lstrip().startswith("|") and "日期" in line and "影响范围" in line:
            out.append(line)
            hit_incident_table = True
            i += 1
            continue
        # 事故表分隔行之后插入 DRILL 行
        if hit_incident_table and not inserted_incident and re.match(r"^\s*\|[\s:|-]+\|?\s*$", line):
            out.append(line)
            out.append(
                f"| DRILL-{v['id']}（{DRILL_TAG}） | {v['affected']} | {v['impact']}；"
                f"{v['advice']} | 02:00 | {v['recovery']} | 无（演练） |"
            )
            inserted_incident = True
            i += 1
            continue
        out.append(line)
        i += 1
    if not hit_component:
        raise SystemExit(f"[{v['id']}] 组件行未找到: {v['component']}")
    if not (hit_incident_table and inserted_incident):
        raise SystemExit(f"[{v['id']}] 事故记录表未找到或未插入 DRILL 行")
    return "\n".join(out)


def assert_contains(html: str, needle: str, what: str, errors: list[str]) -> None:
    if needle not in html:
        errors.append(f"{what}: 页面缺少 {needle!r}")


def check_variant(site_copy: Path, v: dict) -> list[str]:
    """注入变体 → 构建 → 断言。返回断言错误列表（空 = 过）。"""
    status = (site_copy / "content" / "status.md").read_text(encoding="utf-8")
    (site_copy / "content" / "status.md").write_text(inject(status, v), encoding="utf-8")
    subprocess.run(
        [sys.executable, str(site_copy / "build.py")],
        check=True, capture_output=True,
    )
    page = (site_copy / "dist" / "status" / "index.html").read_text(encoding="utf-8")
    errors: list[str] = []

    # 找到受影响组件所在表格行（渲染后 <tr>…</tr>）
    row_re = re.compile(r"<tr>.*?</tr>", re.S)
    comp_row = None
    for m in row_re.finditer(page):
        if v["component"] in m.group(0) and "<td>" in m.group(0):
            comp_row = m.group(0)
            break
    if comp_row is None:
        errors.append(f"[{v['id']}] 渲染页找不到组件行: {v['component']}")
    else:
        # a. 受影响组件标记
        assert_contains(comp_row, f'class="st {v["status_class"]}"', f"[{v['id']}] a-受影响组件状态徽章", errors)
        assert_contains(comp_row, v["status_text"], f"[{v['id']}] a-受影响组件状态词", errors)
        # b. 影响范围文案（组件行说明）
        assert_contains(comp_row, v["component_note"], f"[{v['id']}] b-组件行影响说明", errors)

    # b/c. 事故记录区：DRILL 行含 影响范围/开始时间/恢复/演练标注
    incident_row = None
    for m in row_re.finditer(page):
        if f"DRILL-{v['id']}" in m.group(0):
            incident_row = m.group(0)
            break
    if incident_row is None:
        errors.append(f"[{v['id']}] c-事故记录区缺少 DRILL-{v['id']} 行")
    else:
        assert_contains(incident_row, v["affected"], f"[{v['id']}] b-事故行影响范围", errors)
        assert_contains(incident_row, v["impact"], f"[{v['id']}] b-事故行影响描述", errors)
        assert_contains(incident_row, "02:00", f"[{v['id']}] c-事故行开始时间", errors)
        assert_contains(incident_row, v["recovery"], f"[{v['id']}] c-事故行恢复进度", errors)
        assert_contains(incident_row, DRILL_TAG, f"[{v['id']}] c-事故行演练标注", errors)

    # 事故表表头含 影响范围 列（模板字段）
    if "影响范围" not in page:
        errors.append(f"[{v['id']}] 事故记录表缺少 影响范围 列")

    # e. SAMPLE DATA 标注仍在（演练页不冒充真实数据）
    assert_contains(page, "SAMPLE DATA / devnet", f"[{v['id']}] e-SAMPLE DATA 标注", errors)

    # d. 未受影响组件保持原状（每变体抽查一个与本故障无关的组件）
    unchanged_probe = {
        "sequencer_down": ("RPC（devnet）", "st-ok"),
        "prover_backlog": ("Sequencer（软确认链）", "st-ok"),
        "rpc_degraded": ("Sequencer（软确认链）", "st-ok"),
        "withdraw_delay": ("Sequencer（软确认链）", "st-ok"),
    }[v["id"]]
    probe_row = None
    for m in row_re.finditer(page):
        if unchanged_probe[0] in m.group(0) and "<td>" in m.group(0):
            probe_row = m.group(0)
            break
    if probe_row is None:
        errors.append(f"[{v['id']}] d-抽查行未找到: {unchanged_probe[0]}")
    else:
        assert_contains(probe_row, f'class="st {unchanged_probe[1]}"', f"[{v['id']}] d-未受影响组件保持原状", errors)
    return errors


def fresh_site_copy(tmp: Path) -> Path:
    dst = tmp / "site"
    dst.mkdir(parents=True)
    shutil.copy2(SITE / "build.py", dst / "build.py")
    for d in ("templates", "content", "assets", "media-kit"):
        src = SITE / d
        if src.is_dir():
            shutil.copytree(src, dst / d)
    return dst


def main() -> int:
    results = []
    all_errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="zchain_status_drill_") as td:
        tmp = Path(td)
        # 基线（无注入）断言
        base = fresh_site_copy(tmp / "baseline")
        base.mkdir(parents=True, exist_ok=True)
        subprocess.run([sys.executable, str(base / "build.py")], check=True, capture_output=True)
        base_page = (base / "dist" / "status" / "index.html").read_text(encoding="utf-8")
        base_errors: list[str] = []
        assert_contains(base_page, "影响范围", "基线-事故表含 影响范围 列", base_errors)
        for comp, cls in [
            ("Sequencer（软确认链）", "st-ok"),
            ("Prover（证明管道）", "st-ok"),
            ("RPC（devnet）", "st-ok"),
            ("提现服务（托管打款）", "st-warn"),
        ]:
            found = False
            for m in re.finditer(r"<tr>.*?</tr>", base_page, re.S):
                row = m.group(0)
                if comp in row and f'class="st {cls}"' in row:
                    found = True
                    break
            if not found:
                base_errors.append(f"基线-组件状态不符: {comp} 应为 {cls}")
        results.append({"variant": "baseline", "pass": not base_errors, "errors": base_errors})
        all_errors += base_errors

        for v in VARIANTS:
            site_copy = fresh_site_copy(tmp / v["id"])
            site_copy.mkdir(parents=True, exist_ok=True)
            errs = check_variant(site_copy, v)
            results.append({"variant": v["id"], "label": v["label"], "pass": not errs, "errors": errs})
            all_errors += errs

    print(json.dumps({"drill": "WEB-ACC-6 静态层故障注入演练", "results": results}, ensure_ascii=False, indent=2))
    n_pass = sum(1 for r in results if r["pass"])
    print(f"== {n_pass}/{len(results)} 过（4 故障变体 + 基线）")
    if all_errors:
        for e in all_errors:
            print("FAIL:", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
