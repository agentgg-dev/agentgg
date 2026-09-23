/**
 * The reproduce loop drives browser tools from the sandbox's MCP server, which
 * never passed through the repeat guard the file tools use. A model that
 * re-issued one wait call spent all 50 steps on it, unseen, and answered
 * "no browser actions were performed".
 */
import { describe, expect, it, vi } from "vitest";
import { guardMcpTools, repeatGuard } from "../src/detectors/vercel-agent.js";

const guard = (onStall?: () => void) =>
  repeatGuard({ label: "reproduce:x", phase: "reproduce", onStall });

// biome-ignore lint/suspicious/noExplicitAny: exercising the SDK's call shape
const call = (t: any, name: string, args: unknown) => t[name].execute(args, {} as any);

describe("guarded MCP tools", () => {
  it("runs a call the loop has not made before", async () => {
    const run = vi.fn(async () => "snapshot");
    const t = guardMcpTools({ browser_snapshot: { execute: run } }, guard());

    expect(await call(t, "browser_snapshot", { time: 1 })).toBe("snapshot");
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("answers a repeat with a notice instead of running it again", async () => {
    const run = vi.fn(async () => "waited");
    const t = guardMcpTools({ browser_wait_for: { execute: run } }, guard());

    await call(t, "browser_wait_for", { time: 3 });
    const second = await call(t, "browser_wait_for", { time: 3 });

    expect(second).toContain("already ran this exact browser_wait_for call");
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("treats different arguments as a different call", async () => {
    const run = vi.fn(async () => "ok");
    const t = guardMcpTools({ browser_navigate: { execute: run } }, guard());

    await call(t, "browser_navigate", { url: "/a" });
    await call(t, "browser_navigate", { url: "/b" });

    expect(run).toHaveBeenCalledTimes(2);
  });

  it("ignores the key order of the arguments", async () => {
    const run = vi.fn(async () => "ok");
    const t = guardMcpTools({ browser_click: { execute: run } }, guard());

    await call(t, "browser_click", { ref: "e1", element: "Login" });
    await call(t, "browser_click", { element: "Login", ref: "e1" });

    expect(run).toHaveBeenCalledTimes(1);
  });

  it("reports a stall once the same call keeps coming back", async () => {
    const onStall = vi.fn();
    const t = guardMcpTools(
      { browser_wait_for: { execute: async () => "waited" } },
      guard(onStall),
    );

    for (let i = 0; i < 4; i++) await call(t, "browser_wait_for", { time: 3 });

    expect(onStall).toHaveBeenCalled();
  });

  it("leaves a tool with no execute untouched", () => {
    const bare = { description: "no execute" };
    const t = guardMcpTools({ browser_close: bare }, guard());

    expect(t.browser_close).toBe(bare);
  });
});
