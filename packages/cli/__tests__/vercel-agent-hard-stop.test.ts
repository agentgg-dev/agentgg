/**
 * The hard stop: a loop that repeats a call, or reaches its last turn, loses
 * its tools so the model has to answer. A notice alone never ended a loop in
 * prod (2026-09-08: one call sent 49 times, then an empty answer and a failed
 * batch). Real generateText, mocked model only.
 */
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MockLanguageModelV1 } from "ai/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { hardStop, VercelAgentDetector } from "../src/detectors/vercel-agent.js";

const USAGE = { promptTokens: 10, completionTokens: 10 };
const RAW_CALL = { rawPrompt: null, rawSettings: {} };
const ANSWER = '{"findings": []}';

type Call = { mode: { type: string; toolChoice?: { type: string }; tools?: unknown[] } };

const hasTools = (c: Call) => (c.mode.tools?.length ?? 0) > 0;

async function makeRepo(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "hard-stop-"));
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(join(root, "src", "db.py"), "def get(id):\n  pass\n");
  return root;
}

/**
 * A model that calls Grep forever and answers only when it has no tools.
 * `vary` gives every call a different pattern, so the repeat guard never fires
 * and only the last-turn rule can end the loop.
 */
function toolLoopModel(calls: Call[], vary = false) {
  let n = 0;
  return new MockLanguageModelV1({
    defaultObjectGenerationMode: "json",
    doGenerate: async (options) => {
      calls.push(options as unknown as Call);
      if (options.mode.type === "regular" && options.mode.toolChoice?.type === "none") {
        return { text: ANSWER, finishReason: "stop" as const, usage: USAGE, rawCall: RAW_CALL };
      }
      n++;
      return {
        toolCalls: [
          {
            toolCallType: "function" as const,
            toolCallId: `call-${n}`,
            toolName: "Grep",
            args: JSON.stringify({ pattern: vary ? `get${n}` : "get", glob: null, path: null }),
          },
        ],
        finishReason: "tool-calls" as const,
        usage: USAGE,
        rawCall: RAW_CALL,
      };
    },
  });
}

function runAgentArgs(rootDir: string, maxTurns: number) {
  return {
    agent: { slug: "demo", prompt: "Find bugs." },
    candidates: [{ filePath: "src/db.py", content: "def get(id): ...", hits: [] }],
    rootDir,
    excludePatterns: [],
    maxFileSizeKb: 512,
    maxTurns,
  } as never;
}

const lastCall = (calls: Call[]) => calls[calls.length - 1];

describe("hard stop in the agent tool loop", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  it("takes the tools away from a stalled loop, so the batch gets an answer", async () => {
    const calls: Call[] = [];
    const root = await makeRepo();

    const findings = await new VercelAgentDetector("test", toolLoopModel(calls)).runAgent(
      runAgentArgs(root, 20),
    );

    // Before the hard stop this spent all 21 steps on the same Grep and threw
    // "ended its tool loop without writing an answer".
    expect(findings).toEqual([]);
    expect(lastCall(calls).mode.toolChoice?.type).toBe("none");
    expect(calls.length).toBeLessThan(10);
    expect(vi.mocked(console.warn).mock.calls.map((c) => String(c[0]))).toContainEqual(
      expect.stringContaining("tools off"),
    );
  });

  it("still gets an answer from a model that ignores tool_choice", async () => {
    // GLM-5.2, prod 2026-09-11: the stop fired on the last turn and the model
    // called a tool anyway, so the batch failed. A request with no tools at all
    // is the one thing it cannot ignore.
    const calls: Call[] = [];
    const root = await makeRepo();
    const model = new MockLanguageModelV1({
      defaultObjectGenerationMode: "json",
      doGenerate: async (options) => {
        const call = options as unknown as Call;
        calls.push(call);
        if (!hasTools(call)) {
          return { text: ANSWER, finishReason: "stop" as const, usage: USAGE, rawCall: RAW_CALL };
        }
        return {
          toolCalls: [
            {
              toolCallType: "function" as const,
              toolCallId: `call-${calls.length}`,
              toolName: "Grep",
              args: JSON.stringify({ pattern: `get${calls.length}`, glob: null, path: null }),
            },
          ],
          finishReason: "tool-calls" as const,
          usage: USAGE,
          rawCall: RAW_CALL,
        };
      },
    });

    const findings = await new VercelAgentDetector("test", model).runAgent(runAgentArgs(root, 3));

    expect(findings).toEqual([]);
    // The loop ran out of turns, then one more call carried no tools.
    expect(hasTools(lastCall(calls))).toBe(false);
    // Both retry shapes log this: the schema request first, free text if the
    // provider cannot do structured output. The phrase is what they share.
    expect(vi.mocked(console.warn).mock.calls.map((c) => String(c[0]))).toContainEqual(
      expect.stringContaining("after the loop ran out of turns"),
    );
  });

  it("keeps the last turn for the answer, even when the model never repeats", async () => {
    const calls: Call[] = [];
    const root = await makeRepo();

    const findings = await new VercelAgentDetector("test", toolLoopModel(calls, true)).runAgent(
      runAgentArgs(root, 3),
    );

    expect(findings).toEqual([]);
    // 3 turns of tools, then one answer turn.
    expect(calls).toHaveLength(4);
    expect(lastCall(calls).mode.toolChoice?.type).toBe("none");
  });
});

describe("hardStop", () => {
  it("leaves the tools alone while the loop is making progress", async () => {
    const stop = hardStop("test", 10);
    expect(await stop.prepareStep({ stepNumber: 0 })).toEqual({});
    expect(await stop.prepareStep({ stepNumber: 8 })).toEqual({});
  });

  it("removes the tools on the last allowed step", async () => {
    const stop = hardStop("test", 10);
    expect(await stop.prepareStep({ stepNumber: 9 })).toEqual({ toolChoice: "none" });
  });

  it("gives one warning before it removes the tools", async () => {
    const stop = hardStop("test", 10);
    stop.onStall();
    expect(await stop.prepareStep({ stepNumber: 1 })).toEqual({});
    stop.onStall();
    expect(await stop.prepareStep({ stepNumber: 2 })).toEqual({ toolChoice: "none" });
  });
});
