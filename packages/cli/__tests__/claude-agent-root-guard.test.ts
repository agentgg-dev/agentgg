/**
 * A Claude Code session reads with Claude Code's own Read, Glob and Grep, so a
 * PreToolUse hook keeps those tools inside the scan root.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { linkDir } from "./fs-links.js";

const queryMock = vi.hoisted(() => vi.fn());
vi.mock("@anthropic-ai/claude-agent-sdk", () => ({ query: queryMock }));

const { ClaudeAgentDetector } = await import("../src/detectors/claude-agent.js");

let base: string;
let root: string;
let secret: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), "agentgg-root-guard-"));
  root = join(base, "app");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "db.ts"), "const q = 1;", "utf8");
  mkdirSync(join(base, "other"));
  secret = join(base, "other", "secret.txt");
  writeFileSync(secret, "x", "utf8");
  queryMock.mockReset();
  queryMock.mockImplementation(async function* () {
    yield { type: "result", structured_output: { findings: [] }, result: "done" };
  });
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

type Hook = (
  input: unknown,
  id: string | undefined,
  o: { signal: AbortSignal },
) => Promise<{
  hookSpecificOutput?: { permissionDecision?: string };
}>;

/** The PreToolUse hook that runAgent passed to the SDK. */
async function hook(): Promise<Hook> {
  const detector = new ClaudeAgentDetector({ apiKey: "test-key", model: "claude-opus-4-8" });
  await detector.runAgent({
    agent: { slug: "sql-injection", prompt: "Find SQL injection." },
    candidates: [{ filePath: "src/db.ts", content: "const q = 1;", hits: [] }],
    rootDir: root,
    excludePatterns: [],
    maxFileSizeKb: 512,
    maxTurns: 3,
  } as never);
  const { options } = queryMock.mock.calls[0][0];
  return options.hooks.PreToolUse[0].hooks[0];
}

async function decision(tool_name: string, tool_input: Record<string, unknown>) {
  const h = await hook();
  const out = await h(
    { hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: "t1" },
    "t1",
    { signal: new AbortController().signal },
  );
  return out.hookSpecificOutput?.permissionDecision;
}

describe("Claude Code tools stay inside the scan root", () => {
  it("allows a Read inside the root", async () => {
    expect(await decision("Read", { file_path: join(root, "src", "db.ts") })).toBeUndefined();
  });

  it("denies a Read of an absolute path outside the root", async () => {
    expect(await decision("Read", { file_path: secret })).toBe("deny");
  });

  it("denies a Read through a folder link that points outside the root", async () => {
    linkDir(join(base, "other"), join(root, "shared"));
    expect(await decision("Read", { file_path: join(root, "shared", "secret.txt") })).toBe("deny");
  });

  it("denies a Grep whose path is outside the root", async () => {
    expect(await decision("Grep", { pattern: "x", path: join(base, "other") })).toBe("deny");
  });

  it("denies a Glob whose pattern climbs out of the root", async () => {
    expect(await decision("Glob", { pattern: "../other/*" })).toBe("deny");
  });

  it("allows a Glob inside the root", async () => {
    expect(await decision("Glob", { pattern: "src/**/*.ts" })).toBeUndefined();
  });
});
