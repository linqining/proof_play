/*
 * explorer-live.js — 区块浏览器实时层（devnet replay 网关，只读）。
 *
 * 行为约定（fail-silent）：
 * - 页面加载后 fetch 同源 /api/v1/status、/api/v1/frames?limit=5 与
 *   /api/v1/settlements?limit=5（2s AbortController 超时）；
 * - 成功 → 用实时数据重绘页面表格、隐藏 SAMPLE DATA 徽标、显示
 *   "实时数据 · replay 网关"徽标；
 * - 失败/超时/无网关 → 静默保留 SAMPLE DATA 静态层，页面现状完全不变。
 *
 * 诚实口径：这里的"实时"仅指 devnet replay 网关（WAL 重放只读视图），
 * 不构成对生产数据服务的任何承诺。
 */
(function () {
  "use strict";

  var FETCH_TIMEOUT_MS = 2000;

  function fetchJson(path) {
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, FETCH_TIMEOUT_MS);
    return fetch(path, { signal: ctrl.signal, headers: { "Accept": "application/json" } })
      .then(function (resp) {
        if (!resp.ok) { throw new Error("http " + resp.status); }
        return resp.json();
      })
      .finally(function () { clearTimeout(timer); });
  }

  function el(tag, text, cls) {
    var node = document.createElement(tag);
    if (text !== null && text !== undefined) { node.textContent = text; }
    if (cls) { node.className = cls; }
    return node;
  }

  function shortHex(hex) {
    if (typeof hex !== "string" || hex.length <= 16) { return hex || ""; }
    return hex.slice(0, 8) + "…" + hex.slice(-8);
  }

  function levelCell(level) {
    // 与静态层徽章同款样式（.st），文案与确认层级口径一致
    var span = el("span", level, level === "proven" ? "st st-ok" : "st st-info");
    return span;
  }

  function fillTable(marker, headCells, rows) {
    var anchor = document.querySelector('[data-explorer="' + marker + '"]');
    if (!anchor) { return; }
    var table = anchor.nextElementSibling;
    while (table && table.tagName !== "TABLE") { table = table.nextElementSibling; }
    if (!table) { return; }
    var thead = document.createElement("thead");
    var headRow = document.createElement("tr");
    headCells.forEach(function (h) { headRow.appendChild(el("th", h)); });
    thead.appendChild(headRow);
    var tbody = document.createElement("tbody");
    rows.forEach(function (cells) {
      var tr = document.createElement("tr");
      cells.forEach(function (c) {
        var td = document.createElement("td");
        if (c instanceof Node) { td.appendChild(c); } else { td.textContent = c; }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.replaceChildren(thead, tbody);
  }

  function tsToUtc(ms) {
    var d = new Date(Number(ms));
    return isNaN(d.getTime()) ? "" : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
  }

  function apply(status, frames, settlements) {
    var watermark = status.watermark;
    var levelOf = function (frameIndex) {
      return (watermark !== null && watermark !== undefined && frameIndex <= watermark)
        ? "proven" : "soft_accepted";
    };

    // 最近的块 ← frames（帧即软确认链视图；层级由水位推导）
    fillTable("blocks",
      ["高度 (帧)", "时间 (UTC)", "操作", "状态根", "层级"],
      frames.frames.map(function (f) {
        return [
          String(f.index),
          tsToUtc(f.ts_ms),
          f.op,
          "0x" + shortHex(f.state_root),
          levelCell(levelOf(f.index))
        ];
      })
    );

    // 手牌与结算 ← settlements
    fillTable("settlements",
      ["帧", "桌", "pot", "rake", "hand binding", "结算层级"],
      settlements.settlements.map(function (s) {
        return [
          String(s.frame_index),
          String(s.table_id),
          s.pot.toLocaleString("en-US"),
          String(s.rake_total),
          "0x" + shortHex(s.hand_binding),
          levelCell(s.level)
        ];
      })
    );

    // Checkpoint / 水位（只更新前两行的值列）
    var checkpoint = document.querySelector('[data-explorer="checkpoint"]');
    if (checkpoint) {
      var table = checkpoint.nextElementSibling;
      while (table && table.tagName !== "TABLE") { table = table.nextElementSibling; }
      if (table && table.tBodies.length && table.tBodies[0].rows.length >= 2) {
        table.tBodies[0].rows[0].cells[1].textContent =
          (watermark === null || watermark === undefined ? "无 proven log" : watermark)
          + " / " + status.frame_count + "（缺口见 /api/v1/batch_roots）";
        table.tBodies[0].rows[1].cells[1].textContent =
          status.latest_batch_root ? "0x" + status.latest_batch_root : "无批次根记录";
      }
    }

    // 徽标切换：隐藏 SAMPLE DATA 横幅，显示实时徽标
    document.querySelectorAll(".banner-sample").forEach(function (b) { b.hidden = true; });
    var live = document.querySelector(".explorer-live");
    if (live) {
      live.hidden = false;
      var note = document.getElementById("explorer-live-note");
      if (note) {
        note.textContent = "chain head #" + (status.chain_head.index ?? "–")
          + " · watermark " + (watermark === null || watermark === undefined ? "无" : watermark)
          + "（" + status.watermark_source + "）· 数据来源：devnet replay 网关（WAL 只读重放）";
      }
    }
  }

  function load() {
    Promise.all([
      fetchJson("/api/v1/status"),
      fetchJson("/api/v1/frames?limit=5"),
      fetchJson("/api/v1/settlements?limit=5")
    ]).then(function (all) { apply(all[0], all[1], all[2]); })
      .catch(function () { /* 静默：无网关/超时 → 保留 SAMPLE DATA 静态层 */ });
  }

  function ready() {
    var btn = document.getElementById("explorer-refresh");
    if (btn) {
      btn.addEventListener("click", function () { load(); });
    }
    load();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ready);
  } else {
    ready();
  }
})();
