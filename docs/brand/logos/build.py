#!/usr/bin/env python3
"""ProofPlay 母品牌标志方向生成器 (logo direction generator).

用法:  python3 build.py            # 生成 out/ 下全部产物
本文件是唯一几何源: 改数字后重跑即可, 不要手改 out/*.svg

产物:
  out/<a|b|c>/*.svg   生产文件 (mark / logo / stack / app-icon, 深浅底 + 单色)
  out/boards/*.svg    评审板
  out/_proof-sheet.svg 几何迭代草图

设计约束来自 docs/brand/BRAND_STRATEGY_ZCHAIN_REBRAND.md 第 6 节:
  - 不使用 Z / 链环 / 扑克牌外形 / 花色 / 盾牌
  - 16-24px、单色、打印、favicon 必须成立
  - 字标为定制几何字形, 不依赖任何商业或系统字体 (旧草案用 -apple-system 渲染
    <text>, 换机器就变形, 不是可用 logo; 这里全部输出为路径)
  - 绿色=验证语义; 金色只属于资金与结算, 因此不进入标志

字腔开口 (dash gap) 一律用真实用户单位计算, 不使用 pathLength:
  librsvg 2.60 对 pathLength 支持不完整, 用了会静默渲染成"没有开口"的假图,
  而假图在看板时无法与正确产物区分。
"""

import math
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

INK = "#101512"
PAPER = "#F3F0E7"
GREEN = "#18A66A"
GREEN_D = "#0E7A4E"
MUTED = "#93A29A"
LINE = "#314139"
PANEL = "#17201B"
SUB_LIGHT = "#5B675F"

# ---------------------------------------------------------------- geometry ---


def n(v):
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def rr_path(x0, y0, x1, y1, rx):
    """顺时针圆角矩形, 起点在顶边左端 (x0+rx, y0)."""
    a = f"A {n(rx)} {n(rx)} 0 0 1"
    return (
        f"M {n(x0 + rx)} {n(y0)} L {n(x1 - rx)} {n(y0)} {a} {n(x1)} {n(y0 + rx)} "
        f"L {n(x1)} {n(y1 - rx)} {a} {n(x1 - rx)} {n(y1)} "
        f"L {n(x0 + rx)} {n(y1)} {a} {n(x0)} {n(y1 - rx)} "
        f"L {n(x0)} {n(y0 + rx)} {a} {n(x0 + rx)} {n(y0)} Z"
    )


def rr_perimeter(x0, y0, x1, y1, rx):
    w, h = x1 - x0, y1 - y0
    return 2 * (w - 2 * rx) + 2 * (h - 2 * rx) + 2 * math.pi * rx


def ring_cut_pos(x0, y0, x1, y1, rx, side="tr"):
    """闭合圆角矩形上某条边中点的位置 (自顶边起点顺时针量).

    tr = 右上角弧中点(1:30) / right = 右竖边中点(3:00) / left = 左竖边中点(9:00)
    """
    A, B = (x1 - x0 - 2 * rx), (y1 - y0 - 2 * rx)
    Q = math.pi * rx / 2.0
    return {"tr": A + Q / 2.0,
            "right": A + Q + B / 2.0,
            "left": A + B + 2 * Q + B / 2.0}[side]


def dash_gap(perimeter, center, gap):
    """返回 (dasharray, dashoffset): 在 center 处留出长度 gap 的开口."""
    g = min(gap, perimeter * 0.45)
    dash = perimeter - g
    off = (dash - (center - g / 2.0)) % perimeter
    return f"{n(dash)} {n(g)}", n(off)


def stroke_attrs(sw, color):
    return (f'fill="none" stroke="{color}" stroke-width="{n(sw)}" '
            f'stroke-linecap="butt" stroke-linejoin="miter"')


def plain_path(d, sw, color):
    return f'<path d="{d}" {stroke_attrs(sw, color)}/>'


def cut_path(d, sw, color, perim, center, gap):
    da, do = dash_gap(perim, center, gap)
    return (f'<path d="{d}" {stroke_attrs(sw, color)} '
            f'stroke-dasharray="{da}" stroke-dashoffset="{do}"/>')


# --------------------------------------------------------------- wordmark ----
# 原生坐标: 大写高 100 (centerline y 0..100, 基线 y=100), x-height 顶 y=30, 降部 y=128.

CH, XT, DESC = 100.0, 30.0, 128.0

TYPE_A = dict(w=13.0, track=10.0, rx_ratio=0.50, bowl_rc=0.50, arm_r=21.5,
              hook_r=20.0, bowl_drop=56.0, desc=121.0, gap=0.0, bowl_w=48.0)
TYPE_B = dict(w=15.0, track=7.5, rx_ratio=0.27, bowl_rc=0.30, arm_r=18.0,
              hook_r=17.0, bowl_drop=57.0, desc=119.0, gap=21.0, bowl_w=49.0)


def glyph(ch, t, cut_round=False):
    """返回 (子路径列表, 视觉宽度). 子路径 = dict(d, perim, cut).

    cut_round: 是否在 o/a 的字腔上也开口。字标默认关闭——实测开口落在 o/a 上
    会被读成 c/u, 破坏识读; 开口只保留在两个大写 P 的字腔上, 作为品牌签名。
    图符 (B 的 o) 单独开启。
    """
    w, hw = t["w"], t["w"] / 2.0
    out = []

    def sub(d, perim=0.0, cut=None):
        out.append({"d": d, "perim": perim, "cut": cut})

    if ch == "P":
        bh = t["bowl_drop"] - hw
        rc = min(t["bowl_rc"] * bh, bh / 2.0)
        bx = hw + t["bowl_w"] - rc
        right = max(bh - 2 * rc, 0.0)
        a = f"A {n(rc)} {n(rc)} 0 0 1"
        sub(f"M {n(hw)} 0 L {n(hw)} {n(CH)}")
        sub(f"M {n(hw)} {n(hw)} L {n(bx)} {n(hw)} {a} {n(bx + rc)} {n(hw + rc)} "
            f"L {n(bx + rc)} {n(hw + rc + right)} {a} {n(bx)} {n(hw + bh)} "
            f"L {n(hw)} {n(hw + bh)}",
            (bx - hw) * 2 + math.pi * rc + right,
            (bx - hw) + math.pi * rc / 4.0)
        return out, bx + rc + hw

    if ch == "r":
        ar = t["arm_r"]
        sub(f"M {n(hw)} {n(XT)} L {n(hw)} {n(CH)}")
        sub(f"M {n(hw)} {n(XT + ar)} A {n(ar)} {n(ar)} 0 0 0 "
            f"{n(hw + ar)} {n(XT)}")
        return out, hw + ar + hw

    if ch in ("o", "a"):
        d_cl = CH - XT - w
        x0, y0 = hw, XT + hw
        x1, y1 = hw + d_cl, XT + hw + d_cl
        rx = t["rx_ratio"] * d_cl
        # 开口方向与 A 的方印一致: 一律落在 1:30 (右上角弧中点)
        sub(rr_path(x0, y0, x1, y1, rx), rr_perimeter(x0, y0, x1, y1, rx),
            ring_cut_pos(x0, y0, x1, y1, rx, "tr") if cut_round else None)
        if ch == "a":
            sub(f"M {n(x1)} {n(XT)} L {n(x1)} {n(CH)}")
        return out, d_cl + w

    if ch == "f":
        sx, hr = hw + 14.0, t["hook_r"]
        a = f"A {n(hr)} {n(hr)} 0 0 1"
        sub(f"M {n(sx)} {n(CH)} L {n(sx)} {n(XT - hw)} {a} "
            f"{n(sx + hr)} {n(XT - hw - hr)}")
        cb0, cb1 = sx - hr * 0.7, sx + hr + 2.0
        sub(f"M {n(cb0)} {n(XT)} L {n(cb1)} {n(XT)}")
        return out, max(cb1, sx + hr)

    if ch == "l":
        sub(f"M {n(hw)} 0 L {n(hw)} {n(CH)}")
        return out, w

    if ch == "y":
        ty, jx, jy = XT + 3.6, 35.0, 92.0
        rx0 = 70 - hw
        dyv = jy - ty
        ex = jx + (jx - rx0) * (t["desc"] - jy) / dyv
        sub(f"M {n(hw)} {n(ty)} L {n(jx)} {n(jy)}")
        sub(f"M {n(rx0)} {n(ty)} L {n(ex)} {n(t['desc'])}")
        return out, 70.0

    raise ValueError(ch)


KERN = {("o", "P"): -6.0, ("f", "P"): -5.0, ("P", "l"): -2.0, ("l", "a"): -3.0,
        ("a", "y"): -2.0}


def wordmark(text, t, color, scale=1.0, x=0.0, y=0.0, cut=False):
    """生成字标 <g>. 返回 (svg, 缩放后视觉宽度)."""
    tt = dict(t)
    if not cut:
        tt["gap"] = 0.0
    pen, parts = 0.0, []
    for i, ch in enumerate(text):
        subs, gw = glyph(ch, tt)
        gp = []
        for s in subs:
            if s["cut"] is not None and tt["gap"] > 0:
                gp.append(cut_path(s["d"], tt["w"], color, s["perim"], s["cut"],
                                   tt["gap"]))
            else:
                gp.append(plain_path(s["d"], tt["w"], color))
        parts.append(f'<g transform="translate({n(pen)} 0)">{"".join(gp)}</g>')
        pen += gw
        if i < len(text) - 1:
            pen += tt["track"] + KERN.get((ch, text[i + 1]), 0.0)
    g = f'<g transform="translate({n(x)} {n(y)}) scale({n(scale)})">{"".join(parts)}</g>'
    return g, pen * scale


# ------------------------------------------------------------------- marks ---

def mark_a(sw=12.0, gap=20.0):
    """证印 Open Seal: 右上开口的方印 + 指向开口的验证笔."""
    hw = sw / 2.0
    x0, y0, x1, y1 = 16.0 + hw, 16.0 + hw, 80.0 - hw, 80.0 - hw
    rx = 18.0
    ring = cut_path(rr_path(x0, y0, x1, y1, rx), sw, "RING",
                    rr_perimeter(x0, y0, x1, y1, rx),
                    ring_cut_pos(x0, y0, x1, y1, rx), gap)
    tick = plain_path("M 33.5 48.5 L 44 59.5 L 65 36.5", sw, "TICK")
    return ring, tick


def mark_c(sw=11.0):
    """双面 Private/Public: 一枚证卡, 上段实心=牌面私密, 下段明线=结果可验.

    左右对半分会被读成字母 B/D, 故改为上下分段: 读起来是一张卡配一张收据。
    """
    hw = sw / 2.0
    x0, y0, x1, y1 = 16.0 + hw, 16.0 + hw, 80.0 - hw, 80.0 - hw
    rx = 14.0
    frame = plain_path(rr_path(x0, y0, x1, y1, rx), sw, "FRAME")
    irx = max(rx - hw, 2.0)
    band_y = y0 + (y1 - y0) * 0.34
    solid = (f'<path d="M {n(x0)} {n(y0 + irx)} A {n(irx)} {n(irx)} 0 0 1 '
             f'{n(x0 + irx)} {n(y0)} L {n(x1 - irx)} {n(y0)} '
             f'A {n(irx)} {n(irx)} 0 0 1 {n(x1)} {n(y0 + irx)} '
             f'L {n(x1)} {n(band_y)} L {n(x0)} {n(band_y)} Z" fill="FRAME"/>')
    bar = plain_path(f"M {n(x0 + 9)} {n(y1 - 13)} L {n(x1 - 17)} {n(y1 - 13)}",
                     sw - 2.0, "TICK")
    return solid + frame + bar


# ------------------------------------------------------------------ palette --

def colors(dark, mono):
    if mono:
        c = "currentColor"
        return dict(bg=None, word=c, ring=c, tick=c, sub=c)
    if dark:
        return dict(bg=INK, word=PAPER, ring=PAPER, tick=GREEN, sub=MUTED)
    return dict(bg=PAPER, word=INK, ring=INK, tick=GREEN_D, sub=SUB_LIGHT)


TYPE = {"a": TYPE_A, "b": TYPE_B, "c": TYPE_A}
HAS_MARK = {"a": True, "b": False, "c": True}
MARK_VIS = (16.0, 80.0)
PAD = 24.0
CJK = "PingFang SC, Hiragino Sans GB, Microsoft YaHei, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, monospace"


def mark_svg(direction, dark, mono):
    C = colors(dark, mono)
    if direction == "a":
        ring, tick = mark_a(12.0)
        return ring.replace("RING", C["ring"]) + tick.replace("TICK", C["tick"])
    return mark_c(11.0).replace("FRAME", C["ring"]).replace("TICK", C["tick"])


def mark_body(direction):
    """mark 的原始路径, 颜色取夜场值 (PAPER + GREEN)."""
    if direction != "b":
        return mark_svg(direction, True, False)
    t = TYPE_B
    subs, gw = glyph("o", t, cut_round=True)
    s = subs[0]
    da, do = dash_gap(s["perim"], s["cut"], t["gap"])
    return (f'<path d="{s["d"]}" {stroke_attrs(t["w"], PAPER)} '
            f'stroke-dasharray="{da}" stroke-dashoffset="{do}"/>')


# 视觉包围盒 (含描边宽度), 用于把 mark 归一化到任意目标尺寸
MARK_BBOX = {"a": (16.0, 16.0, 80.0, 80.0),
             "b": (0.0, 30.0, 70.0, 100.0),
             "c": (16.0, 16.0, 80.0, 80.0)}


def mark_scaled(direction, size, dark=True, mono=False, x=0.0, y=0.0):
    """把 mark 的视觉内容缩放到 size×size, 左上角落在 (x, y)."""
    body = mark_body(direction)
    if mono:
        body = body.replace(PAPER, "currentColor").replace(GREEN, "currentColor")
    elif not dark:
        body = body.replace(PAPER, INK).replace(GREEN, GREEN_D)
    bx0, by0, bx1, by1 = MARK_BBOX[direction]
    s = size / (bx1 - bx0)
    return (f'<g transform="translate({n(x - bx0 * s)} {n(y - by0 * s)}) '
            f'scale({n(s)})">{body}</g>')


def _wm(direction, scale, x, y, dark, mono):
    return wordmark("ProofPlay", TYPE[direction], colors(dark, mono)["word"],
                    scale=scale, x=x, y=y, cut=(direction == "b"))


def svg_doc(w, h, body, title, bg=None):
    rect = f'<rect width="{n(w)}" height="{n(h)}" fill="{bg}"/>' if bg else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{n(w)}" height="{n(h)}" '
            f'viewBox="0 0 {n(w)} {n(h)}" role="img" aria-label="{title}">{rect}{body}</svg>')


# ------------------------------------------------------------------ lockups --

def logo_horizontal(direction, dark=False, mono=False, tagline=False, sub=False,
                    mscale=1.6, wscale=1.0):
    """主锁定式: 方印视觉高度 = 字标大写高 (102.4 : 100), 二者共用同一基线."""
    C = colors(dark, mono)
    vis = MARK_VIS[1] - MARK_VIS[0]
    mark_h = vis * mscale
    cap_h = CH * wscale
    has_mark = HAS_MARK[direction]
    base_y = max(cap_h, mark_h) if has_mark else cap_h
    body, x = "", PAD
    if has_mark:
        gx = x - MARK_VIS[0] * mscale
        gy = PAD + base_y - mark_h - MARK_VIS[0] * mscale
        body += (f'<g transform="translate({n(gx)} {n(gy)}) scale({n(mscale)})">'
                 + mark_svg(direction, dark, mono) + "</g>")
        x += mark_h + 30.0
    wm_y = PAD + base_y - cap_h
    wm, wm_w = _wm(direction, wscale, x, wm_y, dark, mono)
    body += wm
    desc_y = wm_y + DESC * wscale
    line_y = desc_y + 34.0
    if sub:
        body += (f'<text x="{n(x)}" y="{n(line_y)}" font-family="{CJK}" font-size="26" '
                 f'font-weight="700" letter-spacing="14" fill="{C["sub"]}">明局</text>')
    if tagline:
        body += (f'<text x="{n(x + wm_w)}" y="{n(line_y)}" text-anchor="end" '
                 f'font-family="{MONO}" font-size="15" letter-spacing="3" '
                 f'fill="{C["sub"]}">EVERY ROUND, PROVEN.</text>')
    bottom = line_y + 10.0 if (sub or tagline) else desc_y + PAD
    return svg_doc(x + wm_w + PAD, bottom + PAD - 6, body, "ProofPlay", C["bg"])


def logo_stacked(direction, dark=False, mono=False, mscale=1.9, wscale=0.72):
    C = colors(dark, mono)
    has_mark = HAS_MARK[direction]
    _, wm_w = _wm(direction, wscale, 0, 0, dark, mono)
    vis = MARK_VIS[1] - MARK_VIS[0]
    w = max(PAD * 2 + (vis * mscale if has_mark else 0), PAD * 2 + wm_w)
    body, y = "", PAD
    if has_mark:
        body += (f'<g transform="translate({n((w - vis * mscale) / 2 - MARK_VIS[0] * mscale)} '
                 f'{n(y - MARK_VIS[0] * mscale)}) scale({n(mscale)})">'
                 + mark_svg(direction, dark, mono) + "</g>")
        y += vis * mscale + 30
    body += _wm(direction, wscale, (w - wm_w) / 2.0, y, dark, mono)[0]
    ly = y + DESC * wscale + 34.0
    body += (f'<text x="{n(w / 2)}" y="{n(ly)}" text-anchor="middle" font-family="{CJK}" '
             f'font-size="24" font-weight="700" letter-spacing="12" '
             f'fill="{C["sub"]}">明局</text>')
    return svg_doc(w, ly + 18, body, "ProofPlay stacked", C["bg"])


def mark_only(direction, dark=False, mono=False, box=140.0):
    C = colors(dark, mono)
    inner = box - 2 * PAD
    return svg_doc(box, box, mark_scaled(direction, inner, dark, mono, PAD, PAD),
                   "ProofPlay mark", C["bg"])


def app_icon(direction, px=512.0):
    """应用图块: 深色圆角砖 + 反白 mark (视觉占 58%)."""
    inner = px * 0.58
    off = (px - inner) / 2.0
    return svg_doc(px, px, f'<rect width="{n(px)}" height="{n(px)}" '
                   f'rx="{n(px * 0.225)}" fill="{INK}"/>'
                   + mark_scaled(direction, inner, True, False, off, off),
                   "ProofPlay app icon")


# ---------------------------------------------------------------- embedding --

_SZ = re.compile(r'width="([\d.]+)" height="([\d.]+)"')


def embed(doc, x, y, scale=1.0):
    """把整份 svg 作为嵌套 svg 放进板子 (保留各自背景)."""
    m = _SZ.search(doc)
    w, h = float(m.group(1)) * scale, float(m.group(2)) * scale
    vb = re.search(r'viewBox="[^"]+"', doc).group(0)
    inner = doc[doc.index(">") + 1:].replace("</svg>", "", 1)
    return (f'<svg x="{n(x)}" y="{n(y)}" width="{n(w)}" height="{n(h)}" {vb} '
            f'preserveAspectRatio="xMidYMid meet">{inner}</svg>')


# ------------------------------------------------------------------- boards --

def label(x, y, s, fill=MUTED, sz=13):
    return txt(x, y, s, f'font-family="{MONO}" font-size="{sz}" letter-spacing="2" '
                        f'font-weight="700" fill="{fill}"')


def txt(x, y, s, attrs, anchor="start"):
    s = s.replace("&", "&amp;").replace("<", "&lt;")
    return f'<text x="{n(x)}" y="{n(y)}" text-anchor="{anchor}" {attrs}>{s}</text>'


def cjk(x, y, s, sz=16, fill=PAPER, weight=400, anchor="start"):
    return txt(x, y, s, f'font-family="{CJK}" font-size="{sz}" '
                        f'font-weight="{weight}" fill="{fill}"', anchor)


def wrap(s, width=52):
    out, line = [], ""
    for ch in s:
        line += ch
        if len(line) >= width and ch in "，。；、 ）/":
            out.append(line)
            line = ""
    if line:
        out.append(line)
    return out or [""]


def size_row(direction, x, y, dark=True):
    """16/24/32/48 实尺寸一排 (按视觉内容归一化, 不是按 96 盒)."""
    b = []
    for i, px in enumerate((16, 24, 32, 48)):
        b.append(mark_scaled(direction, px, dark, False, x + i * 86, y))
        b.append(label(x + i * 86, y + px + 22, f"{px}px", MUTED, 11))
    return "".join(b)


def dim(doc):
    m = _SZ.search(doc)
    return float(m.group(1)), float(m.group(2))


def fit(doc, maxw, maxs=1.0):
    return min(maxs, maxw / dim(doc)[0])


def board(direction, title_cn, concept, uses, risks, rel):
    W, L, R, LW, RW = 1500, 64, 860, 740, 576
    b = []
    b.append(label(L, 56, f"PROOFPLAY / LOGO DIRECTION {direction.upper()}  ·  {title_cn}",
                   GREEN, 15))
    b.append(label(L, 84, concept, MUTED, 15))
    top = 104
    b.append(f'<line x1="{L}" y1="{top}" x2="{W - 64}" y2="{top}" stroke="{LINE}"/>')
    ly = ry = top + 34

    rows = [("PRIMARY LOCKUP / DARK  主锁定式 · 夜场",
             logo_horizontal(direction, dark=True, tagline=True)),
            ("PRIMARY LOCKUP / LIGHT  主锁定式 · 纸白",
             logo_horizontal(direction, dark=False, tagline=True)),
            ("BILINGUAL  中英副排（明局暂用系统黑体，需单独设计）",
             logo_horizontal(direction, dark=False, sub=True))]
    for cap, doc in rows:
        b.append(label(L, ly, cap))
        s = fit(doc, LW)
        b.append(embed(doc, L, ly + 16, s))
        ly += 16 + dim(doc)[1] * s + 34
    b.append(label(L, ly, "SMALL SIZE  实尺寸 16 / 24 / 32 / 48 px"))
    b.append(size_row(direction, L, ly + 20))
    ly += 20 + 48 + 34

    b.append(label(R, ry, "MONOCHROME  单色 currentColor（印刷 / 刺绣 / 传真）"))
    doc = logo_horizontal(direction, mono=True)
    s = min(fit(doc, RW - 48), 120.0 / dim(doc)[1])
    hh = dim(doc)[1] * s
    b.append(f'<rect x="{R}" y="{n(ry + 16)}" width="{RW}" height="{n(hh + 40)}" rx="8" '
             f'fill="{PAPER}"/>')
    b.append(f'<g style="color:{INK}">' + embed(doc, R + 24, ry + 36, s) + "</g>")
    ry += 16 + hh + 40 + 30
    b.append(label(R, ry, "STACKED  纵向锁定式"))
    doc = logo_stacked(direction, dark=True)
    s = fit(doc, RW)
    b.append(embed(doc, R, ry + 16, s))
    ry += 16 + dim(doc)[1] * s + 30
    b.append(label(R, ry, "MARK · APP ICON  图符（夜 / 纸）与应用图块"))
    for i, doc in enumerate((mark_only(direction, dark=True),
                             mark_only(direction, dark=False),
                             app_icon(direction, 140.0))):
        b.append(embed(doc, R + i * 150, ry + 16, 1.0))
    ry += 16 + 140 + 34
    b.append(label(R, ry, "USE  适用"))
    for i, s2 in enumerate(uses):
        b.append(cjk(R, ry + 28 + i * 25, "· " + s2, 16))
    ry += 28 + len(uses) * 25 + 12
    b.append(label(R, ry, "RISK  风险"))
    for i, s2 in enumerate(risks):
        b.append(cjk(R, ry + 28 + i * 25, "· " + s2, 16, MUTED))
    ry += 28 + len(risks) * 25 + 20

    H = int(max(ly, ry) + 70)
    b.insert(0, f'<rect width="{W}" height="{H}" fill="{INK}"/>')
    b.append(f'<line x1="{L}" y1="{H - 46}" x2="{W - 64}" y2="{H - 46}" stroke="{LINE}"/>')
    b.append(label(L, H - 22,
                   "GENERATED BY docs/brand/logos/build.py — 字标全部为路径，不依赖任何字体",
                   "#66756D", 12))
    write(rel, svg_doc(W, H, "".join(b), f"ProofPlay direction {direction}"))


MASTER_COLS = [
    ("a", "A  证印 / Open Seal", "线 · 符号领先 · 策略文档 §6.1 授权概念"),
    ("b", "B  开字 / Open-Counter", "字 · 字标即符号 · 协议与开发者侧"),
    ("c", "C  双面 / Private & Public", "块 · 图块领先 · 产品与玩家侧"),
]

MASTER_NOTES = {
    "a": ("直接落在 §6.1 授权的开放证印上；16px 与单色最稳；B2C 与 B2B 通吃；"
          "动效天然——每局验证完成时开口闭合 120–180ms。",
          "与通用 verified 徽章同族，独占性要靠字标扛；符号偏理性，游戏张力最弱。"),
    "b": ("一个资产走天下，不必维护符号与字标的对齐；开口字腔即不做黑箱，"
          "含义只有这一种读法；协议与开发者侧气质最正。",
          "没有独立图符，app 图标只能截取开口的 o；普通玩家侧温度最低。"),
    "c": ("三套里唯一用正形（实心）的方向，图块感最强；直接编码 §6.4 的 "
          "Secret/Public 双层；最像游戏产品。",
          "语义需要一句解释才读得懂；下沿明线在 16px 退化；与可验证的字面联系最远。"),
}

MASTER_REC = ("以 A 为母品牌主标志（概念已被 §6.1 授权，且小尺寸与单色最稳），"
              "三套共用同一副定制几何字标骨架、只有收口方式不同；"
              "B 的开口字腔降级为 ProofPlay Protocol 与文档、开发者侧的次级锁定式；"
              "C 不进母品牌，转给扑克产品图标或发布活动物料。")


def master_board(rel):
    W = 1700
    b = []
    b.append(label(64, 56, "PROOFPLAY / 明局 · MASTERBRAND LOGO · 三套方向  2026-09-27",
                   GREEN, 15))
    b.append(cjk(64, 92, "同一套策略约束（§6.1 开放证印 / §6.2 五不原则 / 16px 与单色必须成立）"
                         "下的三种解法：线、字、块", 20, PAPER, 700))
    b.append(f'<line x1="64" y1="112" x2="{W - 64}" y2="112" stroke="{LINE}"/>')
    xw = (W - 128) / 3.0
    cw = xw - 24
    inner = cw - 56
    cards, cols = [], []
    for i, (d, name, sub) in enumerate(MASTER_COLS):
        x = 64 + i * xw
        cx = x + 28
        y = 190
        e = [cjk(cx, y, name, 22, PAPER, 800), label(cx, y + 24, sub, MUTED, 11)]
        y += 48
        for doc in (logo_horizontal(d, dark=True), logo_horizontal(d, dark=False)):
            s = fit(doc, inner)
            e.append(embed(doc, cx, y, s))
            y += dim(doc)[1] * s + 22
        doc = logo_horizontal(d, mono=True)
        s = min(fit(doc, inner - 32), 108.0 / dim(doc)[1])
        hh = dim(doc)[1] * s
        e.append(f'<rect x="{n(cx)}" y="{n(y)}" width="{inner}" height="{n(hh + 28)}" '
                 f'rx="6" fill="{PAPER}"/>')
        e.append(f'<g style="color:{INK}">' + embed(doc, cx + 16, y + 14, s) + "</g>")
        y += hh + 28 + 26
        e.append(label(cx, y, "MARK · 16 / 24 / 32 / 48 px"))
        e.append(size_row(d, cx, y + 16))
        y += 16 + 48 + 32
        e.append(label(cx, y, "APP ICON · STACKED"))
        e.append(embed(app_icon(d, 140.0), cx, y + 16, 0.5))
        doc = logo_stacked(d, dark=True)
        s = fit(doc, inner - 96)
        e.append(embed(doc, cx + 92, y + 16, s))
        y += max(70, dim(doc)[1] * s) + 16 + 30
        e.append(label(cx, y, "STRENGTH", GREEN, 12))
        for k, line in enumerate(wrap(MASTER_NOTES[d][0], 26)):
            e.append(cjk(cx, y + 24 + k * 22, line, 15))
        y += 24 + 3 * 22 + 8
        e.append(label(cx, y, "WEAKNESS", MUTED, 12))
        for k, line in enumerate(wrap(MASTER_NOTES[d][1], 26)):
            e.append(cjk(cx, y + 24 + k * 22, line, 15, MUTED))
        y += 24 + 3 * 22 + 16
        cards.append((x, y - 146))
        cols.append(e)
    card_h = max(c[1] for c in cards)
    for x, _ in cards:
        b.append(f'<rect x="{n(x)}" y="146" width="{n(cw)}" height="{n(card_h)}" rx="10" '
                 f'fill="{PANEL}" stroke="{LINE}"/>')
    for e in cols:
        b.extend(e)
    rec_y = 146 + card_h + 40
    b.append(f'<rect x="64" y="{n(rec_y)}" width="{W - 128}" height="122" rx="10" '
             f'fill="{GREEN}" fill-opacity="0.10" stroke="{GREEN}"/>')
    b.append(label(90, rec_y + 30, "RECOMMENDATION  推荐", GREEN, 14))
    for k, line in enumerate(wrap(MASTER_REC, 100)):
        b.append(cjk(90, rec_y + 60 + k * 23, line, 16))
    H = rec_y + 122 + 44
    b.insert(0, f'<rect width="{W}" height="{H}" fill="{INK}"/>')
    b.append(label(64, H - 16,
                   "定名前不投产：商标 / 域名 / 母语语义清查未完成前，这些只作为内部原型资产",
                   "#66756D", 12))
    write(rel, svg_doc(W, H, "".join(b), "ProofPlay logo directions"))


# ---------------------------------------------------------------------- io ---

def write(rel, text):
    path = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


def proof_sheet():
    body = ""
    y = 70.0
    for name, t, cut in (("A  w13 track10", TYPE_A, False),
                         ("B  w15 track7.5 cut", TYPE_B, True)):
        wm, w = wordmark("ProofPlay", t, INK, scale=1.0, x=20, y=y, cut=cut)
        body += wm + label(20, y - 26, f"{name}  width={n(w)}", "#888888", 13)
        y += 200
    ring, tick = mark_a()
    ma = ring.replace("RING", INK) + tick.replace("TICK", GREEN_D)
    body += f'<g transform="translate(20 {n(y)})">{ma}</g>'
    body += f'<g transform="translate(150 {n(y)})">{mark_c().replace("FRAME", INK).replace("TICK", GREEN_D)}</g>'
    body += f'<g transform="translate(280 {n(y)})">{mark_c(sw=14).replace("FRAME", INK).replace("TICK", GREEN_D)}</g>'
    for i, px in enumerate((16, 24, 32, 48)):
        body += mark_scaled("a", px, False, False, 430 + i * 86, y)
        body += mark_scaled("b", px, False, False, 430 + i * 86, y + 60)
        body += mark_scaled("c", px, False, False, 430 + i * 86, y + 120)
    return svg_doc(820, y + 230, body, "proof sheet")


# ========================================================== 纯图形方向 (第二路 v3) ==
# 母品牌不与扑克绑定: 牌、花色、牌桌、筹码全部撤掉。
# 只留任何游戏都成立的三件事: 暗箱被打开 / 一局由两方各执一半 / 这一局被记下来。
#
# v1 被否的原因: 为了极简把识别特征删光, 两个圆角矩形读不出任何东西。
# v2 用牌语把"读得出"解决了, 但代价是绑死扑克。v3 换一套同样"一眼读得出"、
# 但与游戏品类无关的物件: 箱子 / 被切开的一局 / 棋盘与子。
#
# 占位符必须是 __A__ / __B__: 单个字母 "A" 会把路径里的圆弧指令 A rx ry 一起
# 替换掉, 图形静默消失。

def _rot(ang, cx, cy):
    return f'<g transform="rotate({n(ang)} {n(cx)} {n(cy)})">'


def _rot_bbox(x0, y0, x1, y1, ang, cx, cy):
    """旋转后包围盒: 图符归一化必须用旋转后的真实边界, 否则会被裁掉."""
    a = math.radians(ang)
    ca, sa = math.cos(a), math.sin(a)
    xs, ys = [], []
    for px, py in ((x0, y0), (x1, y0), (x1, y1), (x0, y1)):
        dx, dy = px - cx, py - cy
        xs.append(cx + dx * ca - dy * sa)
        ys.append(cy + dx * sa + dy * ca)
    return (min(xs), min(ys), max(xs), max(ys))


def _rr(x0, y0, x1, y1, r=6.0):
    return rr_path(x0, y0, x1, y1, r)


def pic_openbox(detail="full"):
    """开盖: 一只敞口的箱, 盖子整个被掀起悬在上方, 箱里那一条是证据.

    读法: 品牌承诺的直接图形 —— 不要求你相信, 因为盖子是开的。
    箱子必须画成"看得见里面"的敞口容器(粗壁 U 形), 上一版画成实心方块,
    结果读成保险箱/公文包, 完全没有"打开"的意思。
    """
    walls = (f'<path d="M 22 44 L 22 74 A 10 10 0 0 0 32 84 L 64 84 '
             f'A 10 10 0 0 0 74 74 L 74 44" ' + stroke_attrs(11, "__A__") + "/>")
    lid = (_rot(-7, 48, 25) + f'<path d="{_rr(16, 16, 80, 34, 9)}" fill="__A__"/></g>')
    content = (f'<path d="M 35 68 L 61 68" '
               + stroke_attrs(11, "__B__").replace('stroke-linecap="butt"',
                                                   'stroke-linecap="round"') + "/>")
    return walls + content + lid, (14.0, 12.0, 82.0, 86.0)


def pic_split(detail="full"):
    """两半: 一个圆被一刀切开, 两半沿切口滑开, 其中一半是绿的.

    读法: 任何一方单独握着都不是一局 —— 对应"把运营方从信任闭环里移除"。
    圆 = 一局 (round), 所以中文名"明局"也挂得住。
    """
    r = 27.0
    lo = f'<path d="M {n(48 - r)} 48 A {n(r)} {n(r)} 0 0 0 {n(48 + r)} 48 Z" fill="__A__"/>'
    hi = f'<path d="M {n(48 - r)} 48 A {n(r)} {n(r)} 0 0 1 {n(48 + r)} 48 Z" fill="__B__"/>'
    body = (_rot(-28, 48, 48)
            + f'<g transform="translate(0 5)">{lo}</g>'
            + f'<g transform="translate(0 -5)">{hi}</g></g>')
    return body, (14.0, 14.0, 82.0, 82.0)


def pic_tally(detail="full"):
    """刻痕 Tally: 三道计数刻痕, 被一道斜线划上 = 记下了.

    读法: 最古老的"有账可查"。任何游戏都只关心一件事 —— 这一局有没有被记下来,
    而记下来的东西才能被复验。斜线是绿的: 那条是被验证的记账。
    """
    bars = stroke_attrs(13, "__A__")
    n = 3 if detail == "full" else 2
    xs = (28, 48, 68)[:n]
    body = "".join(f'<path d="M {x} 20 L {x} 76" {bars}/>' for x in xs)
    slash = (f'<path d="M 16 64 L 80 28" '
             + stroke_attrs(13, "__B__").replace('stroke-linecap="butt"',
                                                 'stroke-linecap="round"') + "/>")
    return body + slash, (12.0, 14.0, 84.0, 82.0)


def pic_ruler(detail="full"):
    """标尺 The Ruler: 一把带刻度的尺, 斜着压下来, 绿色那格正在被量.

    读法: 品牌把尺子交给玩家 —— 每一局你自己量, 不用信任何人给你的结论。
    上一版"照"(两束发散线+地线)被推翻: 读成字母 A / 帐篷, 完全没有光的意思。
    注意: 这里不能用变量名 n, 会覆盖同名的数字格式化函数。
    """
    cnt = 5 if detail == "full" else 3
    xs = (22, 36, 50, 64, 78)[:cnt]
    ticks = "".join(f'M {x} 42 L {x} {42 + (9 if i % 2 == 0 else 15)}'
                    for i, x in enumerate(xs))
    gx = 64 if cnt == 5 else xs[-1]
    glen = 30 if cnt == 5 else 26
    body = (_rot(-8, 48, 34)
            + f'<path d="{_rr(12, 26, 84, 42, 6)}" fill="__A__"/>'
            + f'<path d="{ticks}" {stroke_attrs(6, "__A__")}/>'
            + f'<path d="M {gx} 42 L {gx} {42 + glen}" '
            + stroke_attrs(7, "__B__").replace('stroke-linecap="butt"',
                                               'stroke-linecap="round"') + "/>"
            + f'<circle cx="{n(gx)}" cy="{n(42 + glen + 10)}" r="8" fill="__B__"/></g>')
    box = _rot_bbox(12, 26, 84, 42 + glen + 18, -8, 48, 34)
    return body, box


def pic_seesaw(detail="full"):
    """跷跷板 Seesaw: 一根杠杆支在中间, 两端各坐着一方, 绿的那端这局高.

    读法: ProofPlay 的 Play —— 博弈本来就是有输赢的, 品牌承诺不是"没有胜负",
    而是"杠杆支在哪里看得见"。支点就是规则与证据。
    """
    beam = (f'<path d="M 14 62 L 82 40" '
            + stroke_attrs(11, "__A__").replace('stroke-linecap="butt"',
                                                 'stroke-linecap="round"') + "/>")
    ful = f'<path d="M 40 84 L 48 56 L 56 84 Z" fill="__A__"/>'
    left = f'<circle cx="22" cy="50" r="10" fill="__A__"/>' if detail == "full" else ""
    right = f'<circle cx="74" cy="28" r="11" fill="__B__"/>'
    return beam + ful + left + right, (10.0, 16.0, 86.0, 84.0)


def pic_gamepad(detail="full"):
    """手柄 / Gamepad P: 一只极简游戏手柄, 顶部引出的连线向上卷起绕成字母 P.

    读法: 手柄 = 任何游戏(不绑扑克), P = ProofPlay; P 不是贴上去的字母,
    是手柄自己的线 —— Play 与 Proof 本来就是一条线。
    绿色那颗是确认键: 验证是游戏里自带的动作。
    """
    sw = 10.0
    pad = f'<path d="{_rr(16, 46, 80, 78, 15)}" ' + stroke_attrs(sw, "__A__") + "/>"
    stem = f'<path d="M 48 46 L 48 12" ' + stroke_attrs(sw, "__A__") + "/>"
    bowl = f'<path d="M 48 12 A 13 13 0 1 1 48 38" ' + stroke_attrs(sw, "__A__") + "/>"
    cross = ""
    if detail == "full":
        cross = (f'<path d="M 28 62 L 40 62 M 34 56 L 34 68" '
                 + stroke_attrs(6.5, "__A__").replace('stroke-linecap="butt"',
                                                       'stroke-linecap="round"') + "/>")
    button = f'<circle cx="64" cy="62" r="6.5" fill="__B__"/>'
    return pad + stem + bowl + cross + button, (11.0, 8.0, 85.0, 84.0)


PIC = {
    "d": ("开盖 / Open Box", "敞口的箱，盖被整个掀起，箱里那一条是证据",
          "不要求你相信：盖子是开的"),
    "e": ("两半 / Split Round", "一局被一刀切成两半，两半滑开，一半是绿的",
          "任何一方单独握着都不是一局"),
    "f": ("刻痕 / Tally", "三道计数刻痕，被一道斜线划上",
          "最古老的有账可查：这一局被记下来了"),
    "g": ("标尺 / The Ruler", "一把带刻度的尺，斜着压下来，绿色那格正在被量",
          "把尺子交给玩家：每一局你自己量"),
    "h": ("跷跷板 / Seesaw", "杠杆支在中间，两端各坐一方，绿的那端这局高",
          "博弈有输赢，但支点在哪里看得见"),
    "i": ("手柄 / Gamepad P", "极简游戏手柄，顶部引出的线向上绕成字母 P",
          "P 不是贴上去的字母：Play 与 Proof 是一条线"),
}

PIC_FN = {"d": pic_openbox, "e": pic_split, "f": pic_tally,
          "g": pic_ruler, "h": pic_seesaw, "i": pic_gamepad}
PIC_SMALL = {"d": "simple", "e": "full", "f": "simple", "g": "full",
             "h": "simple", "i": "simple"}


def pic_body(key, detail="full"):
    body, _box = PIC_FN[key](detail)
    return body.replace("__A__", PAPER).replace("__B__", GREEN)


def pic_bbox(key, detail="full"):
    return PIC_FN[key](detail)[1]


def pic_scaled(key, size, dark=True, mono=False, x=0.0, y=0.0, detail="full"):
    body = pic_body(key, detail)
    if mono:
        body = body.replace(PAPER, "currentColor").replace(GREEN, "currentColor")
    elif not dark:
        body = body.replace(PAPER, INK).replace(GREEN, GREEN_D)
    bx0, by0, bx1, by1 = pic_bbox(key, detail)
    s = size / (bx1 - bx0)
    return (f'<g transform="translate({n(x - bx0 * s)} {n(y - by0 * s)}) '
            f'scale({n(s)})">{body}</g>')


def pic_mark(key, dark=True, mono=False, box=160.0, detail="full"):
    C = colors(dark, mono)
    inner = box - 2 * PAD
    return svg_doc(box, box, pic_scaled(key, inner, dark, mono, PAD, PAD, detail),
                   "ProofPlay pictorial mark", C["bg"])


def pic_app_icon(key, px=512.0):
    inner = px * 0.52
    off = (px - inner) / 2.0
    return svg_doc(px, px, f'<rect width="{n(px)}" height="{n(px)}" '
                   f'rx="{n(px * 0.225)}" fill="{INK}"/>'
                   + pic_scaled(key, inner, True, False, off, off),
                   "ProofPlay app icon")


def pic_lockup(key, dark=False, wscale=1.0):
    """图符 + 字标: 图符视觉高 = 字标大写高, 与第一路同一套基线规则."""
    C = colors(dark, False)
    mark_h = 102.4
    cap_h = CH * wscale
    base_y = max(cap_h, mark_h)
    body = pic_scaled(key, mark_h, dark, False, PAD, PAD + base_y - mark_h)
    x = PAD + mark_h + 30.0
    wm, wm_w = wordmark("ProofPlay", TYPE_A, C["word"], scale=wscale, x=x,
                        y=PAD + base_y - cap_h)
    return svg_doc(x + wm_w + PAD, PAD + base_y + (DESC - CH) * wscale + PAD,
                   body + wm, "ProofPlay", C["bg"])


def pic_sizes(key, x, y, dark=True):
    """实尺寸一排: <=24px 走简化版."""
    b = []
    for i, px in enumerate((16, 24, 32, 48)):
        detail = PIC_SMALL[key] if px <= 24 else "full"
        b.append(pic_scaled(key, px, dark, False, x + i * 86, y, detail))
        b.append(label(x + i * 86, y + px + 22,
                       f"{px}px" + ("·简" if detail == "simple" else ""), MUTED, 11))
    return "".join(b)


def pictorial_proof():
    w = 20 + (len(PIC) - 1) * 294 + 268 + 120 + 20
    b = [f'<rect width="{w}" height="330" fill="{INK}"/>']
    for i, k in enumerate(PIC):
        ox = 20 + i * 294
        b.append(f'<g transform="translate({n(ox)} 20)">{pic_scaled(k, 250, True, False, 0, 0)}</g>')
        b.append(f'<g transform="translate({n(ox + 268)} 120)">'
                 f'{pic_scaled(k, 120, False, False, 0, 0)}</g>')
        b.append(label(ox, 310, k, "#888888", 12))
    return svg_doc(w, 330, "".join(b), "pictorial proof")


def pictorial_board(rel):
    W = 2060
    b = []
    b.append(label(64, 56, "PROOFPLAY / 纯图形方向 第二路 v3  ·  母品牌不绑定扑克: 牌/花色/牌桌/筹码全部撤掉",
                   GREEN, 15))
    b.append(cjk(64, 92, "换成任何游戏都成立的六件事：暗箱被打开 / 一局由两方各执一半 / 这一局被记下来 / 有把尺 / 支点看得见 / 手柄引出线就是 P",
                 20, PAPER, 700))
    b.append(f'<line x1="64" y1="112" x2="{W - 64}" y2="112" stroke="{LINE}"/>')
    cols = list(PIC.keys())
    cw = (W - 128 - (len(cols) - 1) * 24) / float(len(cols))
    blocks = []
    for i, k in enumerate(cols):
        x = 64 + i * (cw + 24)
        cx = x + 22
        y = 190
        e = [cjk(cx, y, f"{'ABCDEFGH'[i]}  {PIC[k][0]}", 19, PAPER, 800)]
        yy = y + 24
        for line in wrap(PIC[k][1], 13):
            e.append(cjk(cx, yy, line, 12.5, MUTED))
            yy += 19
        for line in wrap("寓意 · " + PIC[k][2], 13):
            e.append(cjk(cx, yy, line, 12.5, GREEN))
            yy += 19
        y = yy + 8
        box = cw - 44
        e.append(embed(pic_mark(k, dark=True, box=box), cx, y, 1.0))
        y += box + 18
        e.append(embed(pic_mark(k, dark=False, box=box), cx, y, 1.0))
        y += box + 24
        e.append(label(cx, y, "16 / 24 / 32 / 48 px（≤24 用简化版）"))
        e.append(pic_sizes(k, cx, y + 16))
        y += 16 + 48 + 34
        e.append(label(cx, y, "APP ICON · LOCKUP"))
        e.append(embed(pic_app_icon(k, 140.0), cx, y + 16, 0.42))
        lk = pic_lockup(k, dark=True)
        s = 0.36
        e.append(embed(lk, cx + 70, y + 16, s))
        y += max(60, dim(lk)[1] * s) + 16 + 24
        blocks.append((x, y - 146, e))
    card_h = max(h for _, h, _ in blocks)
    for x, h, _ in blocks:
        b.append(f'<rect x="{n(x)}" y="146" width="{n(cw)}" height="{n(h)}" rx="10" '
                 f'fill="{PANEL}" stroke="{LINE}"/>')
    for _, _, e in blocks:
        b.extend(e)
    H = 146 + card_h + 96
    b.insert(0, f'<rect width="{W}" height="{H}" fill="{INK}"/>')
    b.append(label(64, H - 40,
                   "字标沿用第一路的定制几何骨架 (路径, 不依赖字体) · 所有隐喻都与游戏品类无关",
                   "#66756D", 12))
    write(rel, svg_doc(W, H, "".join(b), "ProofPlay pictorial directions v3"))


def pictorial_assets():
    for k in PIC:
        pre = f"pic-{k}/"
        write(pre + "mark-dark.svg", pic_mark(k, dark=True))
        write(pre + "mark-light.svg", pic_mark(k, dark=False))
        write(pre + "mark-mono.svg", pic_mark(k, mono=True))
        write(pre + "mark-small-dark.svg", pic_mark(k, dark=True, detail="simple"))
        write(pre + "app-icon.svg", pic_app_icon(k))
        write(pre + "logo-dark.svg", pic_lockup(k, dark=True))
        write(pre + "logo-light.svg", pic_lockup(k, dark=False))


# ---------------------------------------------------------------------- io ---

def write(rel, text):
    path = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


def proof_sheet():
    body = ""
    y = 70.0
    for name, t, cut in (("A  w13 track10", TYPE_A, False),
                         ("B  w15 track7.5 cut", TYPE_B, True)):
        wm, w = wordmark("ProofPlay", t, INK, scale=1.0, x=20, y=y, cut=cut)
        body += wm + label(20, y - 26, f"{name}  width={n(w)}", "#888888", 13)
        y += 200
    ring, tick = mark_a()
    ma = ring.replace("RING", INK) + tick.replace("TICK", GREEN_D)
    body += f'<g transform="translate(20 {n(y)})">{ma}</g>'
    body += f'<g transform="translate(150 {n(y)})">{mark_c().replace("FRAME", INK).replace("TICK", GREEN_D)}</g>'
    body += f'<g transform="translate(280 {n(y)})">{mark_c(sw=14).replace("FRAME", INK).replace("TICK", GREEN_D)}</g>'
    for i, px in enumerate((16, 24, 32, 48)):
        body += mark_scaled("a", px, False, False, 430 + i * 86, y)
        body += mark_scaled("b", px, False, False, 430 + i * 86, y + 60)
        body += mark_scaled("c", px, False, False, 430 + i * 86, y + 120)
    return svg_doc(820, y + 230, body, "proof sheet")


DIRECTIONS = {
    "a": ("证印 / Open Seal", "线 · 符号领先 · §6.1 授权概念",
          ["官网首屏 / 应用图块 / 牌桌中心 / 白牌授权页",
           "单色印刷、刺绣、刻字均可直接使用",
           "16px 起即成立，可直接当 favicon"]),
    "b": ("开字 / Open-Counter Type", "字 · 字标即符号 · 协议与开发者侧",
          ["文档、CLI、GitHub、SDK、邮件签名等一处一份的场合",
           "不需要额外维护符号与字标的对齐关系",
           "开口字腔=不做黑箱，含义读法唯一"]),
    "c": ("双面 / Private & Public", "块 · 图块领先 · 产品与玩家侧",
          ["应用图块、加载态、牌桌角标、周边物料",
           "唯一用正形（实心）的方向，图块辨识度最高",
           "直接编码 §6.4 的 Secret/Public 双层"]),
}

RISKS = {
    "a": ["与通用 verified 徽章同族，识别独占性依赖字标",
          "符号偏理性，游戏张力是三套里最弱的"],
    "b": ["没有独立图符，app 图标只能截取开口的 o",
          "24px 以下开口开始糊，需备无开口副版",
          "气质偏基础设施，普通玩家侧温度最低"],
    "c": ["语义需要一句解释才能读懂，首次接触有理解成本",
          "右半账格在 16px 退化，最小可用尺寸约 24px",
          "离“可验证”这一核心承诺的字面联系最远"],
}


def main():
    os.makedirs(OUT, exist_ok=True)
    write("_proof-sheet.svg", proof_sheet())
    for d, (name, concept, uses) in DIRECTIONS.items():
        pre = f"{d}/"
        write(pre + "logo-dark.svg", logo_horizontal(d, dark=True, tagline=True))
        write(pre + "logo-light.svg", logo_horizontal(d, dark=False, tagline=True))
        write(pre + "logo-mono.svg", logo_horizontal(d, mono=True))
        write(pre + "logo-bilingual-light.svg", logo_horizontal(d, dark=False, sub=True))
        write(pre + "logo-bilingual-dark.svg", logo_horizontal(d, dark=True, sub=True))
        write(pre + "stack-dark.svg", logo_stacked(d, dark=True))
        write(pre + "stack-light.svg", logo_stacked(d, dark=False))
        write(pre + "mark-dark.svg", mark_only(d, dark=True))
        write(pre + "mark-light.svg", mark_only(d, dark=False))
        write(pre + "mark-mono.svg", mark_only(d, mono=True))
        write(pre + "app-icon.svg", app_icon(d))
        write(pre + "favicon.svg", mark_only(d, dark=True, box=64))
        board(d, name, concept, uses, RISKS[d], f"boards/{d}-board.svg")
    master_board("boards/master.svg")
    pictorial_assets()
    pictorial_board("boards/pictorial.svg")
    write("_pic-proof.svg", pictorial_proof())
    print("generated ->", OUT)


if __name__ == "__main__":
    main()
