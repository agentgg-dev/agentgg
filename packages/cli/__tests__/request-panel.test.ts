import ts from "typescript";
import { describe, expect, it, vi } from "vitest";
import {
  REQUEST_PANEL_FILE,
  REQUEST_PANEL_SOURCE,
  withRequestPanel,
} from "../src/validation/request-panel";

type Fixture = (args: Record<string, unknown>, use: (v: unknown) => Promise<void>) => Promise<void>;

/** Runs the module the sandbox gets, with a stand-in for `@playwright/test`. */
function loadPanel(timeout = 30_000) {
  let fixtures: Record<string, Fixture> = {};
  const info = { timeout, setTimeout: vi.fn() };
  const base = {
    extend: (f: Record<string, Fixture>) => {
      fixtures = f;
      return {};
    },
    info: () => info,
  };
  const { outputText } = ts.transpileModule(REQUEST_PANEL_SOURCE, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  });
  const mod = { exports: {} };
  new Function("require", "module", "exports", outputText)(
    (id: string) => {
      if (id === "@playwright/test") return { test: base };
      throw new Error(`unexpected import ${id}`);
    },
    mod,
    mod.exports,
  );
  return { fixtures, info };
}

function fakePage(events: string[], evaluateFails = false) {
  const response = {
    status: () => 302,
    statusText: () => "Found",
    headersArray: () => [
      { name: "Set-Cookie", value: "user=alice; Path=/" },
      { name: "Location", value: "/" },
    ],
    headers: () => ({ "content-type": "text/html" }),
    text: async () => "",
  };
  const send = async (url: string) => {
    events.push(`send ${url}`);
    return response;
  };
  const request = {
    get: send,
    post: send,
    put: send,
    patch: send,
    delete: send,
    head: send,
    fetch: send,
  };
  const page = {
    request,
    isClosed: () => false,
    waitForTimeout: async (ms: number) => {
      events.push(`wait ${ms}`);
    },
    evaluate: async (_fn: unknown, [, text]: [string, string | null]) => {
      if (evaluateFails) throw new Error("Execution context was destroyed");
      events.push(text === null ? "clear" : `draw ${text}`);
    },
  };
  return { page, response };
}

async function postThroughPanel(evaluateFails = false, timeout?: number) {
  const { fixtures, info } = loadPanel(timeout);
  const events: string[] = [];
  const { page, response } = fakePage(events, evaluateFails);
  let result: unknown;
  await fixtures.page({ page }, async (p) => {
    result = await (p as typeof page).request.post("http://t/login", {
      form: { username: "' OR 1=1--", password: "x" },
    } as never);
  });
  return { events, result, response, info };
}

describe("withRequestPanel", () => {
  it("points the Playwright import at the panel module", () => {
    expect(withRequestPanel('import { test, expect } from "@playwright/test";\n')).toBe(
      'import { test, expect } from "./agentgg-request-panel";\n',
    );
  });

  it("also rewrites a single-quoted and a type-only import", () => {
    const out = withRequestPanel(
      "import { test } from '@playwright/test';\nimport type { Page } from '@playwright/test';\n",
    );
    expect(out).not.toContain("@playwright/test");
    expect(out.match(/\.\/agentgg-request-panel/g)).toHaveLength(2);
  });

  it("leaves a script without the import as it is", () => {
    const script = 'const { test } = require("playwright-core");\n';
    expect(withRequestPanel(script)).toBe(script);
  });

  it("names the module file the rewritten import resolves to", () => {
    expect(REQUEST_PANEL_FILE).toBe("agentgg-request-panel.ts");
  });
});

describe("the request panel module", () => {
  it("is valid TypeScript", () => {
    const { diagnostics } = ts.transpileModule(REQUEST_PANEL_SOURCE, { reportDiagnostics: true });
    expect(diagnostics ?? []).toEqual([]);
  });

  it("shows the request before it goes out, then the answer, then clears the panel", async () => {
    const { events, result, response } = await postThroughPanel();
    expect(result).toBe(response);
    const steps = events.map((e) => e.split(" ")[0]);
    expect(steps).toEqual(["draw", "wait", "send", "draw", "wait", "clear"]);
    expect(events[0]).toContain("POST http://t/login");
    expect(events[0]).toContain("username=' OR 1=1--");
    expect(events[3]).toContain("302");
    expect(events[3]).toContain("set-cookie: user=alice; Path=/");
  });

  it("still sends the request when the page cannot be drawn on", async () => {
    const { events, result, response } = await postThroughPanel(true);
    expect(result).toBe(response);
    expect(events).toContain("send http://t/login");
  });

  it("adds its pauses to the test timeout, so they never use the test's own time", async () => {
    const { info } = await postThroughPanel(false, 30_000);
    expect(info.setTimeout).toHaveBeenCalledWith(expect.any(Number));
    expect(info.setTimeout.mock.calls[0][0]).toBeGreaterThan(30_000);
  });

  it("stops pausing after a few requests, so a long test stays inside the runner limit", async () => {
    const { fixtures } = loadPanel();
    const events: string[] = [];
    const { page } = fakePage(events);
    await fixtures.page({ page }, async (p) => {
      for (let i = 0; i < 8; i++) await (p as typeof page).request.get(`http://t/${i}`);
    });
    const shown = events.filter((e) => e.startsWith("draw") && e.includes("..."));
    expect(shown.length).toBeLessThan(8);
    expect(events.filter((e) => e.startsWith("send"))).toHaveLength(8);
  });
});
