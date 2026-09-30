// Injected into every page in the live-validation sandbox before the page's own
// scripts, so the recorded video shows where each step went and what it called.
// Rows: the current URL, the newest fetch/XHR call with its status, the injected
// payload when a query value carries HTML metacharacters, and a red "XSS fired"
// line when the page calls alert/prompt/confirm/print. A native dialog is
// invisible to a screenshot or a video, so without the override an XSS that
// pops one leaves no proof in the recording. The override is class-agnostic: it
// applies to every reproduce session, not one vulnerability type.
// Top-level navigations never reach the fetch hooks; row one already shows them.
// aria-hidden keeps the strip out of the accessibility snapshot the reproduce
// agent reads, and the interval catches same-document navigations and pages
// that replace the document body.
(() => {
  if (window.top !== window.self) return;
  const ID = "__agentgg_url_banner__";
  const ROW =
    "font:12px/20px monospace;padding:0 8px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis";
  const OK = "#7CFC7C";
  const PENDING = "#FFD166";
  const FAILED = "#FF6B6B";
  const FIRED = "#FF3B3B";

  let latest = null;
  let calls = 0;
  // Set by the alert/prompt/confirm/print override the first time the page runs
  // one, which for a reproduced XSS is the proof itself.
  let firedMessage = null;

  // The query value that carries HTML metacharacters, so the recording names
  // what was injected without hardcoding any one parameter (offset, q, ...).
  const injectedParam = () => {
    try {
      for (const [name, value] of new URL(location.href).searchParams) {
        if (/[<>"']/.test(value)) return name + ": " + value;
      }
    } catch {
      // A malformed URL is not worth breaking the banner over.
    }
    return null;
  };

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
    latest = {
      method: String(method || "GET").toUpperCase(),
      path: path(url),
      status: null,
      n: calls,
    };
    render();
    return latest;
  };

  const finished = (call, status) => {
    call.status = status;
    if (call === latest) render();
  };

  // The strip reserves its own space instead of covering the app: the page is
  // pushed down by exactly the strip's height, which grows with its rows.
  const reserve = (root, el) => {
    const h = `${el.offsetHeight}px`;
    if (root.style.getPropertyValue("padding-top") !== h) {
      root.style.setProperty("padding-top", h, "important");
    }
  };

  const addRow = (el, key, color, border) => {
    const row = document.createElement("div");
    row.dataset.row = key;
    row.style.cssText = `${ROW};color:${color}` + (border ? ";border-top:1px solid #333" : "");
    el.appendChild(row);
    return row;
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
      "z-index:2147483647",
      "background:#111",
      "pointer-events:none",
    ].join(";");
    addRow(el, "url", OK, false);
    addRow(el, "net", PENDING, true);
    root.appendChild(el);
    return el;
  };

  const setRow = (el, key, color, text, border) => {
    let row = el.querySelector(`[data-row="${key}"]`);
    if (!row) row = addRow(el, key, color, border !== false);
    if (row.textContent !== text) row.textContent = text;
    row.style.color = color;
  };

  const render = () => {
    const root = document.documentElement;
    if (!root) return;
    const el = document.getElementById(ID) ?? build(root);
    const url = el.querySelector('[data-row="url"]');
    const net = el.querySelector('[data-row="net"]');
    if (!url || !net) return;
    if (url.textContent !== location.href) url.textContent = location.href;
    const line = latest
      ? `[${latest.n}] ${latest.method} ${latest.path} ${latest.status ?? "..."}`
      : "no fetch or XHR yet";
    if (net.textContent !== line) net.textContent = line;
    net.style.color =
      !latest || latest.status === null
        ? PENDING
        : latest.status === "failed" || Number(latest.status) >= 400
          ? FAILED
          : OK;

    // Injected payload: shown only when a query value looks like an attack, and
    // labeled with the real parameter name so it reads for any XSS, not offset.
    const injected = injectedParam();
    if (injected) setRow(el, "payload", PENDING, injected);

    // XSS proof: a red row once the page proves code ran. A dialog call is
    // captured by the override below; a payload that avoids dialogs can instead
    // set `window.__agentggXss`, which is polled here. Either way the effect,
    // invisible to a screenshot on its own, shows in the recording.
    if (firedMessage === null) {
      const marks = window.__agentggXss;
      if (Array.isArray(marks) && marks.length > 0) firedMessage = String(marks[marks.length - 1]);
    }
    if (firedMessage !== null) {
      setRow(el, "fired", FIRED, `XSS fired: ${firedMessage}`);
    }

    reserve(root, el);
  };

  // Override the dialog functions so an injected alert() proves itself in the
  // recording. The message is captured; the dialog itself never blocks the run.
  const markFired = (msg) => {
    firedMessage = String(msg);
    window.__agentggXss = window.__agentggXss || [];
    window.__agentggXss.push(firedMessage);
    render();
  };
  for (const name of ["alert", "confirm", "prompt", "print"]) {
    try {
      window[name] = (msg) => {
        markFired(msg === undefined ? name + "()" : msg);
        return name === "confirm" ? true : name === "prompt" ? "" : undefined;
      };
    } catch {
      // A locked-down property is not worth breaking the page over.
    }
  }

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
