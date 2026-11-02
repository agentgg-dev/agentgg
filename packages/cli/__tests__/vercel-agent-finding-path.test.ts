/**
 * A finding must name a file inside the repository. One that names a file
 * outside it leaves the detector as nothing, and that file reaches no prompt.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import type { Agent } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VercelAgentDetector } from "../src/detectors/vercel-agent.js";

const SOURCE = "const query = 'SELECT * FROM t WHERE id = ' + req.query.id;";
const OUTSIDE_TEXT = "OUTSIDE_FILE_TEXT=1";

let root: string;
let outside: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentgg-finding-path-"));
  outside = mkdtempSync(join(tmpdir(), "agentgg-finding-path-outside-"));
  writeFileSync(join(root, "app.js"), SOURCE, "utf8");
  writeFileSync(join(outside, "data.txt"), OUTSIDE_TEXT, "utf8");
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(outside, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const agent = {
  slug: "sql-injection",
  name: "sql-injection",
  description: "Synthetic agent.",
  version: "0.0.1",
  noiseTier: "normal",
  where: {},
  prompt: "Stub.",
} as Agent;

/** One finding at `filePath` that quotes code found nowhere, so it asks for a re-quote. */
function answer(filePath: string): string {
  return JSON.stringify({
    findings: [
      {
        title: "SQL injection",
        vulnSlug: "sql-injection",
        agentSlug: null,
        filePath,
        lineRange: [1, 1],
        summary: "s",
        details: ["```js", "const invented = makeQuery(userInput, other);", "```"].join("\n"),
        poc: "p",
        impact: "i",
        references: [],
        confidence: 0.9,
      },
    ],
  });
}

function recorded(reply: string) {
  const prompts: string[] = [];
  const model = new MockLanguageModelV1({
    defaultObjectGenerationMode: "json",
    doGenerate: async (options) => {
      prompts.push(JSON.stringify(options.prompt));
      return {
        rawCall: { rawPrompt: null, rawSettings: {} },
        finishReason: "stop" as const,
        usage: { promptTokens: 10, completionTokens: 10 },
        text: prompts.length === 1 ? reply : JSON.stringify({ excerpts: [OUTSIDE_TEXT] }),
      };
    },
  });
  return { model, prompts };
}

const run = (model: MockLanguageModelV1) =>
  new VercelAgentDetector("openai", model).runAgent({
    agent,
    rootDir: root,
    candidates: [{ filePath: "app.js", content: SOURCE, hits: [] }],
    excludePatterns: [],
    maxFileSizeKb: 256,
    maxTurns: 5,
  });

describe("runAgent with a finding outside the repository", () => {
  it("drops a finding that names an absolute path outside the root", async () => {
    const { model, prompts } = recorded(answer(join(outside, "data.txt")));
    expect(await run(model)).toEqual([]);
    expect(prompts.some((p) => p.includes(OUTSIDE_TEXT))).toBe(false);
  });

  it("drops a finding that climbs out of the root", async () => {
    const { model, prompts } = recorded(answer(relative(root, join(outside, "data.txt"))));
    expect(await run(model)).toEqual([]);
    expect(prompts.some((p) => p.includes(OUTSIDE_TEXT))).toBe(false);
  });

  it("keeps a finding inside the root", async () => {
    const { model } = recorded(answer("app.js"));
    const findings = await run(model);
    expect(findings.map((f) => f.filePath)).toEqual(["app.js"]);
  });
});
