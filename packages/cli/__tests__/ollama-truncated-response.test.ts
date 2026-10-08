import { describe, expect, it } from "vitest";
import { createTruncationTolerantFetch } from "../src/providers/ollama.js";

const CHAT = "http://localhost:11434/api/chat";

/** The shape ollama returns when it cuts a tool-call run short. */
const truncated = {
  created_at: "2026-01-01T00:00:00Z",
  done: false,
  message: {
    content: "",
    role: "assistant",
    tool_calls: [
      { function: { arguments: { url: "http://t/go?next=//evil" }, name: "browser_navigate" } },
      { function: { arguments: { text: "302" }, name: "browser_wait_for" } },
    ],
  },
  model: "qwen2.5:14b",
};

const complete = {
  created_at: "2026-01-01T00:00:00Z",
  done: true,
  done_reason: "stop",
  eval_count: 12,
  eval_duration: 5,
  message: { content: "hi", role: "assistant" },
  model: "qwen2.5:14b",
  total_duration: 9,
};

const reply = (payload: unknown) =>
  new Response(JSON.stringify(payload), { headers: { "content-type": "application/json" } });

const generateBody = JSON.stringify({ messages: [], stream: false });

describe("createTruncationTolerantFetch", () => {
  it("fills the counters the response schema needs on a cut-short answer", async () => {
    const f = createTruncationTolerantFetch(async () => reply(truncated));
    const got = await (await f(CHAT, { body: generateBody, method: "POST" })).json();
    expect(got.done).toBe(true);
    expect(got.eval_count).toBe(0);
    expect(got.eval_duration).toBe(0);
    expect(got.total_duration).toBe(0);
  });

  it("keeps the tool calls, so the agent loop still runs them", async () => {
    const f = createTruncationTolerantFetch(async () => reply(truncated));
    const got = await (await f(CHAT, { body: generateBody, method: "POST" })).json();
    expect(got.message.tool_calls).toHaveLength(2);
  });

  // "stop" would read as a model that chose to finish. The run was cut off.
  it("marks the answer cut short rather than a clean stop", async () => {
    const f = createTruncationTolerantFetch(async () => reply(truncated));
    const got = await (await f(CHAT, { body: generateBody, method: "POST" })).json();
    expect(got.done_reason).toBe("length");
  });

  it("leaves a finished answer untouched", async () => {
    const f = createTruncationTolerantFetch(async () => reply(complete));
    const got = await (await f(CHAT, { body: generateBody, method: "POST" })).json();
    expect(got).toEqual(complete);
  });

  // Reading a streamed body here would drain the NDJSON before the SDK sees it.
  it("never reads the body of a streamed call", async () => {
    const streamed = reply(truncated);
    const f = createTruncationTolerantFetch(async () => streamed);
    const res = await f(CHAT, { body: JSON.stringify({ stream: true }), method: "POST" });
    expect(res).toBe(streamed);
    expect(res.bodyUsed).toBe(false);
  });

  it("passes a non-chat route straight through", async () => {
    const tags = new Response("{}");
    const f = createTruncationTolerantFetch(async () => tags);
    expect(await f("http://localhost:11434/api/tags", { method: "GET" })).toBe(tags);
  });
});
