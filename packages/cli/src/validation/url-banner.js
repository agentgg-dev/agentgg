// Injected into every page in the live-validation sandbox before the page's own
// scripts, so the recorded video shows which URL each step is on. aria-hidden
// keeps it out of the accessibility snapshot the reproduce agent reads, and the
// interval catches same-document navigations (pushState, hash changes).
(() => {
  if (window.top !== window.self) return;
  const ID = "__agentgg_url_banner__";
  const install = () => {
    const root = document.documentElement;
    if (!root) return;
    let el = document.getElementById(ID);
    if (!el) {
      el = document.createElement("div");
      el.id = ID;
      el.setAttribute("aria-hidden", "true");
      el.style.cssText = [
        "position:fixed",
        "top:0",
        "left:0",
        "right:0",
        "z-index:2147483647",
        "background:#111",
        "color:#7CFC7C",
        "font:12px/20px monospace",
        "height:20px",
        "padding:0 8px",
        "overflow:hidden",
        "white-space:nowrap",
        "text-overflow:ellipsis",
        "pointer-events:none",
      ].join(";");
      root.appendChild(el);
    }
    if (el.textContent !== location.href) el.textContent = location.href;
  };
  install();
  document.addEventListener("DOMContentLoaded", install);
  setInterval(install, 250);
})();
