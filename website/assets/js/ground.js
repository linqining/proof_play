/* 纸白 / 夜场切换。首帧的 data-ground 由模板内联脚本决定（见 templates/*.html），
   这里只负责按钮状态、切换与记忆。零依赖，与 explorer-live.js 一样直接拷进 dist。 */
(function () {
  "use strict";
  var KEY = "zchain-ground";
  var root = document.documentElement;

  function current() { return root.getAttribute("data-ground") === "night" ? "night" : "paper"; }

  function paint() {
    var g = current();
    document.querySelectorAll("[data-ground-toggle]").forEach(function (btn) {
      var lab = btn.querySelector(".ground-toggle-label");
      if (lab) lab.textContent = g === "night" ? "夜场" : "纸白";
      btn.setAttribute("aria-pressed", String(g === "night"));
      btn.title = g === "night" ? "切换到纸白底（当前：夜场）" : "切换到夜场底（当前：纸白）";
    });
  }

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest ? ev.target.closest("[data-ground-toggle]") : null;
    if (!btn) return;
    var next = current() === "night" ? "paper" : "night";
    root.setAttribute("data-ground", next);
    try { localStorage.setItem(KEY, next); } catch (e) { /* 隐私模式下写不了，忽略 */ }
    paint();
  });

  // 未手动选择过时跟随系统偏好实时变化
  if (window.matchMedia) {
    try {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function (ev) {
        var saved = null;
        try { saved = localStorage.getItem(KEY); } catch (e) { saved = null; }
        if (saved) return;
        root.setAttribute("data-ground", ev.matches ? "night" : "paper");
        paint();
      });
    } catch (e) { /* 老浏览器不支持 addEventListener 形式的 matchMedia */ }
  }

  paint();
})();
