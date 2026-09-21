// Injected into every page in the live-validation sandbox before the page's own
// scripts, so the recorded video shows where each step went and what it called.
// Two rows: the current URL, and the newest fetch/XHR call with its status.
// Top-level navigations never reach the hooks; row one already shows them.
// aria-hidden keeps the strip out of the accessibility snapshot the reproduce
// agent reads, and the interval catches same-document navigations and pages
// that replace the document body.
(() => {
  if (window.top !== window.self) return;
  const ID = "__agentgg_url_banner__";
  const HEIGHT = 40;
  const ROW = "font:12px/20px monospace;height:20px;padding:0 8px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis";
  const OK = "#7CFC7C";
  const PENDING = "#FFD166";
  const FAILED = "#FF6B6B";

  let latest = null;
  let calls = 0;

  const path = (url) => {
    try {
      const parsed = new URL(String(url), location.href);
      const sameOrigin = parsed.origin === location.origin;
      return (sameOrigin ? "" : parsed.origin) + parsed.pathname + parsed.search;
    } catch {
      return String(url);
    }
  };

  const started = (method, url) => {
    calls++;
    latest = { method: String(method || "GET").toUpperCase(), path: path(url), status: null, n: calls };
    render();
    return latest;
  };

  const finished = (call, status) => {
    call.status = status;
    if (call === latest) render();
  };

  // The strip reserves its own space instead of covering the app: the page is
  // pushed down by exactly the strip's height.
  const reserve = (root) => {
    if (root.style.getPropertyValue("padding-top") !== `${HEIGHT}px`) {
      root.style.setProperty("padding-top", `${HEIGHT}px`, "important");
    }
  };

  const build = (root) => {
    const el = document.createElement("div");
    el.id = ID;
    el.setAttribute("aria-hidden", "true");
    el.style.cssText = [
      "position:fixed",
      "top:0",
      "left:0",
      "right:0",
      `height:${HEIGHT}px`,
      "z-index:2147483647",
      "background:#111",
      "pointer-events:none",
    ].join(";");
    const url = document.createElement("div");
    url.style.cssText = `${ROW};color:${OK}`;
    const net = document.createElement("div");
    net.style.cssText = `${ROW};color:${PENDING};border-top:1px solid #333`;
    el.appendChild(url);
    el.appendChild(net);
    root.appendChild(el);
    return el;
  };

  const render = () => {
    const root = document.documentElement;
    if (!root) return;
    reserve(root);
    const el = document.getElementById(ID) ?? build(root);
    const [url, net] = el.children;
    if (!url || !net) return;
    if (url.textContent !== location.href) url.textContent = location.href;
    const line = latest
      ? `[${latest.n}] ${latest.method} ${latest.path} ${latest.status ?? "..."}`
      : "no fetch or XHR yet";
    if (net.textContent !== line) net.textContent = line;
    const color = !latest || latest.status === null
      ? PENDING
      : latest.status === "failed" || Number(latest.status) >= 400
        ? FAILED
        : OK;
    net.style.color = color;
  };

  const nativeFetch = window.fetch;
  if (typeof nativeFetch === "function") {
    window.fetch = function (input, init) {
      let call = null;
      try {
        const url = typeof input === "string" ? input : (input && input.url) || "";
        const method = (init && init.method) || (input && input.method) || "GET";
        call = started(method, url);
      } catch {
        // Never let the banner break the page's own request.
      }
      const result = nativeFetch.apply(this, arguments);
      if (!call) return result;
      return result.then(
        (response) => {
          finished(call, response.status);
          return response;
        },
        (error) => {
          finished(call, "failed");
          throw error;
        },
      );
    };
  }

  const XHR = window.XMLHttpRequest;
  if (typeof XHR === "function") {
    const open = XHR.prototype.open;
    const send = XHR.prototype.send;
    XHR.prototype.open = function (method, url) {
      this.__agentggCall = { method, url };
      return open.apply(this, arguments);
    };
    XHR.prototype.send = function () {
      const pending = this.__agentggCall;
      if (pending) {
        const call = started(pending.method, pending.url);
        this.addEventListener("loadend", () => finished(call, this.status || "failed"));
      }
      return send.apply(this, arguments);
    };
  }

  render();
  document.addEventListener("DOMContentLoaded", render);
  setInterval(render, 250);
})();
