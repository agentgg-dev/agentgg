/**
 * End-to-end proof that `experimental_repairToolCall` is wired into the agent
 * hunt and actually rescues a batch.
 *
 * Unlike the unit tests for `resolveMangledToolName`, nothing here is stubbed
 * except the model itself: the REAL `generateText` runs, the REAL SDK raises
 * `AI_NoSuchToolError` on the mangled name, the REAL repair hook fires, and the
 * REAL Grep tool executes against a temp repo. That is the whole point — the
 * bug on prod scan 764dbd1d was not a broken helper, it was an unhandled error
 * class escaping `generateText`, so the test has to exercise that path.
 *
 * The model is an `ai/test` MockLanguageModelV1 that answers three calls:
 *   1. `regular` mode  → a tool call whose NAME carries leaked arg markup
 *   2. `object-json`   → the repair's re-ask, returning schema-valid arguments
 *   3. `regular` mode  → the final findings JSON
 */
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MockLanguageModelV1 } from "ai/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { VercelAgentDetector } from "../src/detectors/vercel-agent.js";

/** The exact tool name GLM-5 emitted on scan 764dbd1d, slug missing-access-control. */
const MANGLED =
  "Grep<arg_value>pattern</arg_key><arg_value>get_owned_provider_account_or_404</arg_value>";

const USAGE = { promptTokens: 10, completionTokens: 10 };
const RAW_CALL = { rawPrompt: null, rawSettings: {} };

/** A repo with one file the repaired Grep can actually match against. */
async function makeRepo(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "repair-e2e-"));
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(
    join(root, "src", "db.py"),
    "def get_owned_provider_account_or_404(id):\n  pass\n",
  );
  return root;
}

/** Records every call the SDK makes so the assertions can inspect the transcript. */
function mockModel(calls: Array<Record<string, unknown>>) {
  let regularCalls = 0;
  return new MockLanguageModelV1({
    defaultObjectGenerationMode: "json",
    doGenerate: async (options) => {
      calls.push(options as unknown as Record<string, unknown>);
      // The repair's re-ask: hand back arguments that satisfy GrepParameters.
      if (options.mode.type === "object-json") {
        return {
          text: '{"pattern":"get_owned_provider_account_or_404","glob":null,"path":null}',
          finishReason: "stop" as const,
          usage: USAGE,
          rawCall: RAW_CALL,
        };
      }
      regularCalls++;
      // First hunt turn: the malformed call that used to kill the batch.
      if (regularCalls === 1) {
        return {
          toolCalls: [
            {
              toolCallType: "function" as const,
              toolCallId: "call-1",
              toolName: MANGLED,
              args: '{"pattern":"get_owned_provider_account_or_404"}',
            },
          ],
          finishReason: "tool-calls" as const,
          usage: USAGE,
          rawCall: RAW_CALL,
        };
      }
      // Second hunt turn: the model has the tool result and finishes.
      return {
        text: '{"findings": []}',
        finishReason: "stop" as const,
        usage: USAGE,
        rawCall: RAW_CALL,
      };
    },
  });
}

function runAgentArgs(rootDir: string) {
  return {
    agent: { slug: "missing-access-control", prompt: "Find missing access control." },
    candidates: [{ filePath: "src/db.py", content: "def get(id): ...", hits: [] }],
    rootDir,
    excludePatterns: [],
    maxFileSizeKb: 512,
    maxTurns: 5,
  } as never;
}

describe("experimental_repairToolCall wiring (real generateText, mocked model only)", () => {
  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  it("rescues a batch whose tool name arrived wrapped in leaked arg markup", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const root = await makeRepo();

    const findings = await new VercelAgentDetector("test", mockModel(calls)).runAgent(
      runAgentArgs(root),
    );

    // Before the fix this rejected with AI_NoSuchToolError, which failed the
    // batch and cost the whole agent its sidecar.
    expect(findings).toEqual([]);

    // The repair fired: a third call exists, and it is the object-mode re-ask.
    expect(calls).toHaveLength(3);
    expect(calls.some((c) => (c.mode as { type: string }).type === "object-json")).toBe(true);
    expect(vi.mocked(console.warn).mock.calls.map((c) => String(c[0]))).toContainEqual(
      expect.stringContaining("repaired a malformed Grep call"),
    );
  });

  it("runs the REAL Grep tool with the repaired arguments", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const root = await makeRepo();

    await new VercelAgentDetector("test", mockModel(calls)).runAgent(runAgentArgs(root));

    // The final turn's prompt must carry a tool RESULT, and that result must
    // hold the grep hit from the temp repo. That can only happen if the
    // repaired call was dispatched to the real Grep implementation.
    const transcript = JSON.stringify(calls[calls.length - 1]?.prompt ?? "");
    expect(transcript).toContain("tool-result");
    expect(transcript).toContain("src/db.py");
    expect(transcript).toContain("get_owned_provider_account_or_404");
  });
});
