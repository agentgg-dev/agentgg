/**
 * Per-request deadline for LLM HTTP calls. A host can send response headers and
 * then stall on the body, and neither fetch nor the AI SDK gives up on its own.
 * Real sockets on purpose: a mocked fetch cannot show how an abort mid-body
 * surfaces.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { createOpenAI } from "@ai-sdk/openai";
import { APICallError, generateText } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildOpenRouterFetch,
  createCostMeter,
  openRouterRequestTimeoutMs,
} from "../src/providers/openrouter.js";
import { createDeadlineFetch } from "../src/request-deadline.js";

type Handler = (req: IncomingMessage, res: ServerResponse, n: number) => void;

let server: Server | undefined;
afterEach(async () => {
  vi.restoreAllMocks();
  delete process.env.OPENROUTER_REQUEST_TIMEOUT_MS;
  const s = server;
  server = undefined;
  if (!s) return;
  s.closeAllConnections();
  await new Promise<void>((resolve) => s.close(() => resolve()));
});

async function serve(handler: Handler): Promise<string> {
  let n = 0;
  const s = createServer((req, res) => handler(req, res, ++n));
  server = s;
  await new Promise<void>((resolve) => s.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
}

const hang: Handler = () => {};
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const post = { method: "POST", body: "{}" };

describe("createDeadlineFetch", () => {
  it("fails a request that gets no response headers in time, as a retryable call error", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const url = await serve(hang);
    const f = createDeadlineFetch(fetch, 100);
    const err = await f(`${url}/v1/chat/completions`, post).catch((e: unknown) => e);
    expect(APICallError.isInstance(err)).toBe(true);
    expect((err as APICallError).isRetryable).toBe(true);
    expect((err as APICallError).message).toMatch(/request timed out after/);
  });

  it("fails a body that stops arriving and names the generation id", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const url = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json", "x-generation-id": "gen-hung-1" });
      res.write(" ");
    });
    const f = createDeadlineFetch(fetch, 100);
    const res = await f(`${url}/v1/chat/completions`, post);
    const err = await res.text().catch((e: unknown) => e);
    expect(APICallError.isInstance(err)).toBe(true);
    expect((err as APICallError).isRetryable).toBe(true);
    expect((err as APICallError).message).toContain("genId=gen-hung-1");
    expect((err as APICallError).responseHeaders?.["x-generation-id"]).toBe("gen-hung-1");
    expect(warn.mock.calls.flat().join("\n")).toContain("genId=gen-hung-1");
  });

  it("leaves a response that finishes in time untouched and never fires later", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const url = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json", "x-generation-id": "gen-ok" });
      res.end('{"ok":true}');
    });
    const f = createDeadlineFetch(fetch, 100);
    const res = await f(`${url}/v1/chat/completions`, post);
    expect(res.status).toBe(200);
    expect(res.headers.get("x-generation-id")).toBe("gen-ok");
    expect(await res.json()).toEqual({ ok: true });
    await sleep(200);
    expect(warn).not.toHaveBeenCalled();
  });

  it("keeps the caller's own abort, so a cancelled scan still reads as cancelled", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const url = await serve(hang);
    const f = createDeadlineFetch(fetch, 200);
    const caller = new AbortController();
    const reason = new DOMException("scan cancelled", "AbortError");
    const pending = f(`${url}/v1/chat/completions`, { ...post, signal: caller.signal }).catch(
      (e: unknown) => e,
    );
    caller.abort(reason);
    expect(await pending).toBe(reason);
    await sleep(300);
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("a hung request inside the AI SDK", () => {
  // The SDK retries a retryable APICallError per HTTP request, so one hung
  // step of a 50-step tool loop costs one request, not the whole session.
  it("retries that one request and completes the call", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const url = await serve((_req, res, n) => {
      if (n === 1) return;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          id: "gen-2",
          object: "chat.completion",
          created: 0,
          model: "m",
          choices: [
            { index: 0, message: { role: "assistant", content: "done" }, finish_reason: "stop" },
          ],
          usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
        }),
      );
    });
    const provider = createOpenAI({
      apiKey: "k",
      baseURL: `${url}/v1`,
      fetch: createDeadlineFetch(fetch, 100),
    });
    const { text } = await generateText({ model: provider("m"), prompt: "hi" });
    expect(text).toBe("done");
  }, 15_000);
});

describe("the OpenRouter provider fetch", () => {
  it("gives up on a request that hangs past OPENROUTER_REQUEST_TIMEOUT_MS", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    process.env.OPENROUTER_REQUEST_TIMEOUT_MS = "100";
    const url = await serve(hang);
    const f = buildOpenRouterFetch({}, createCostMeter());
    const err = await f(`${url}/api/v1/chat/completions`, post).catch((e: unknown) => e);
    expect(APICallError.isInstance(err)).toBe(true);
  });

  it("waits 30 minutes when the setting is absent or not a positive number", () => {
    expect(openRouterRequestTimeoutMs(undefined)).toBe(30 * 60_000);
    expect(openRouterRequestTimeoutMs("soon")).toBe(30 * 60_000);
    expect(openRouterRequestTimeoutMs("0")).toBe(30 * 60_000);
    expect(openRouterRequestTimeoutMs("90000")).toBe(90_000);
  });
});
