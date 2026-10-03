// A request sent with `page.request` runs outside the page and draws nothing,
// so a proof that attacks this way records a page where nothing happens. The
// sandbox runs each proof spec through this fixture module instead of
// `@playwright/test`: every such call is drawn on the page with its input and
// its answer, held long enough to read, then removed so the page the test
// asserts on is unchanged.

/** The module's file name next to the spec, and the import that reaches it. */
export const REQUEST_PANEL_FILE = "agentgg-request-panel.ts";
const REQUEST_PANEL_IMPORT = "./agentgg-request-panel";

/** Point a spec's `@playwright/test` imports at the panel module. A spec that
 *  loads Playwright some other way runs as written, with no panel. */
export function withRequestPanel(script: string): string {
  return script.replace(
    /\bfrom\s*(["'])@playwright\/test\1/g,
    (_m, quote: string) => `from ${quote}${REQUEST_PANEL_IMPORT}${quote}`,
  );
}

// Written into the sandbox as is. No backtick or dollar-brace in here: this is
// a raw template literal.
export const REQUEST_PANEL_SOURCE = String.raw`import { test as base } from "@playwright/test";
import type { APIRequestContext, APIResponse, Page } from "@playwright/test";

export * from "@playwright/test";

const PANEL_ID = "__agentgg_request_panel__";
const READ_MS = 1000;
const HOLD_MS = 1500;
// Past this many calls a test runs at full speed, inside the runner's limit.
const MAX_SHOWN = 5;
const MAX_LINE = 300;
const METHODS = ["get", "post", "put", "patch", "delete", "head", "fetch"];

const clip = (s: string): string => (s.length > MAX_LINE ? s.slice(0, MAX_LINE) + "..." : s);

function pairs(v: unknown): string {
  if (v == null) return "";
  if (typeof v !== "object") return String(v);
  const entries =
    typeof (v as { entries?: unknown }).entries === "function" && !Array.isArray(v)
      ? [...(v as { entries(): Iterable<[string, unknown]> }).entries()]
      : Object.entries(v as object);
  return entries
    .map(([k, x]) => k + "=" + (typeof x === "object" && x !== null ? JSON.stringify(x) : String(x)))
    .join("  ");
}

function describeInput(method: string, url: string, o: Record<string, unknown> | undefined): string[] {
  const lines = ["TEST REQUEST (sent outside the page)", method + " " + url];
  try {
    if (o?.params) lines.push("params  " + pairs(o.params));
    if (o?.headers) lines.push("headers  " + pairs(o.headers));
    if (o?.form) lines.push("form  " + pairs(o.form));
    if (o?.multipart) lines.push("multipart  " + pairs(o.multipart));
    if (o?.data !== undefined) {
      const d = o.data;
      lines.push(
        "data  " +
          (typeof d === "string" ? d : Buffer.isBuffer(d) ? "<" + d.length + " bytes>" : JSON.stringify(d)),
      );
    }
  } catch {
    lines.push("(body not shown)");
  }
  return lines.map(clip);
}

async function describeOutcome(res: APIResponse): Promise<string[]> {
  const lines = ["-> " + res.status() + " " + res.statusText()];
  for (const { name, value } of res.headersArray()) {
    const n = name.toLowerCase();
    if (n === "location" || n === "set-cookie") lines.push(n + ": " + value);
  }
  const type = (res.headers()["content-type"] ?? "").toLowerCase();
  if (/json|text\/plain/.test(type)) {
    try {
      lines.push((await res.text()).replace(/\s+/g, " ").trim());
    } catch {
      // A body that cannot be read is left out.
    }
  }
  return lines.map(clip);
}

async function draw(page: Page, text: string | null): Promise<void> {
  try {
    await page.evaluate(
      ([id, t]) => {
        const old = document.getElementById(id as string);
        if (t === null) {
          old?.remove();
          return;
        }
        const el = old ?? document.createElement("div");
        if (!old) {
          el.id = id as string;
          el.setAttribute("aria-hidden", "true");
          el.style.cssText =
            "position:fixed;left:0;right:0;bottom:0;z-index:2147483647;background:#111;color:#FFD166;font:14px/22px monospace;padding:10px 12px;white-space:pre-wrap;word-break:break-all;pointer-events:none;border-top:2px solid #FFD166";
          (document.body ?? document.documentElement).appendChild(el);
        }
        el.textContent = t as string;
      },
      [PANEL_ID, text],
    );
  } catch {
    // A page in the middle of a navigation cannot be drawn on.
  }
}

function show(page: Page, request: APIRequestContext): void {
  const target = request as unknown as Record<string, unknown>;
  if (target.__agentggShown) return;
  target.__agentggShown = true;
  let shown = 0;
  const pause = (ms: number) => page.waitForTimeout(ms).catch(() => undefined);
  for (const name of METHODS) {
    const original = (target[name] as (...a: unknown[]) => Promise<APIResponse>).bind(request);
    target[name] = async (url: unknown, options?: Record<string, unknown>) => {
      if (shown >= MAX_SHOWN || page.isClosed()) return original(url, options);
      shown++;
      try {
        const info = base.info();
        if (info.timeout > 0) info.setTimeout(info.timeout + READ_MS + HOLD_MS + 2000);
      } catch {
        // Outside a test there is no timeout to extend.
      }
      const req = url as { url(): string; method(): string };
      const method =
        name === "fetch"
          ? String(options?.method ?? (typeof url === "string" ? "GET" : req.method()))
          : name.toUpperCase();
      const input = describeInput(method, typeof url === "string" ? url : req.url(), options);
      await draw(page, [...input, "..."].join("\n"));
      await pause(READ_MS);
      try {
        const response = await original(url, options);
        await draw(page, [...input, ...(await describeOutcome(response))].join("\n"));
        await pause(HOLD_MS);
        return response;
      } catch (err) {
        await draw(page, [...input, clip("-> failed: " + String((err as Error)?.message ?? err))].join("\n"));
        await pause(HOLD_MS);
        throw err;
      } finally {
        await draw(page, null);
      }
    };
  }
}

export const test = base.extend({
  page: async ({ page }, use) => {
    show(page, page.request);
    await use(page);
  },
  request: async ({ request, page }, use) => {
    show(page, request);
    await use(request);
  },
});

export default test;
`;
