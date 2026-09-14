/**
 * Detection re-quotes invented code before a finding leaves the detector: one
 * extra call, only for a finding whose quoted code is not in the source.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Agent } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VercelAgentDetector } from "../src/detectors/vercel-agent.js";

const NL = "\n";
const F = "```";
const SOURCE = [
  "private String constructEquality(String[] jsonPath, Expression expected) {",
  "    int lastIndex = jsonPath.length - 1;",
  "    Object value = ((LiteralExpressionImpl) expected).getValue();",
  "    return String.format(jsonPath[lastIndex], value);",
  "}",
].join(NL);
const REAL = "Object value = ((LiteralExpressionImpl) expected).getValue();";
const INVENTED = "LiteralExpressionImpl lit = (LiteralExpressionImpl) expr;";

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentgg-requote-"));
  writeFileSync(join(root, "FilterToSqlHelper.java"), SOURCE, "utf8");
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
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

function answer(code: string): string {
  return JSON.stringify({
    findings: [
      {
        title: "SQL injection in constructEquality",
        vulnSlug: "sql-injection",
        agentSlug: null,
        filePath: "FilterToSqlHelper.java",
        lineRange: [3, 4],
        summary: "Unescaped value reaches SQL.",
        details: ["The sink:", `${F}java`, code, F].join(NL),
        poc: "p",
        impact: "i",
        references: [],
        confidence: 0.9,
      },
    ],
  });
}

/** Replies in order and records the mode of each request. */
function scripted(replies: string[]) {
  const modes: string[] = [];
  let n = 0;
  const model = new MockLanguageModelV1({
    defaultObjectGenerationMode: "json",
    doGenerate: async (options) => {
      modes.push((options.mode as { type: string }).type);
      return {
        rawCall: { rawPrompt: null, rawSettings: {} },
        finishReason: "stop" as const,
        usage: { promptTokens: 10, completionTokens: 10 },
        text: replies[Math.min(n++, replies.length - 1)],
      };
    },
  });
  return { model, modes };
}

const run = (model: MockLanguageModelV1) =>
  new VercelAgentDetector("openai", model).runAgent({
    agent,
    rootDir: root,
    candidates: [{ filePath: "FilterToSqlHelper.java", content: SOURCE, hits: [] }],
    excludePatterns: [],
    maxFileSizeKb: 256,
    maxTurns: 5,
  });

describe("runAgent re-quotes invented code", () => {
  it("makes no extra call for a real excerpt", async () => {
    const { model, modes } = scripted([answer(REAL)]);
    const [finding] = await run(model);
    expect(finding.details).toContain(REAL);
    expect(modes).toEqual(["regular"]);
  });

  it("replaces invented code with a re-quote that verifies", async () => {
    const { model, modes } = scripted([answer(INVENTED), JSON.stringify({ excerpts: [REAL] })]);
    const [finding] = await run(model);
    expect(finding.details).toContain(REAL);
    expect(finding.details).not.toContain(INVENTED);
    expect(modes).toEqual(["regular", "object-json"]);
  });

  it("keeps and marks the finding after one failed re-quote", async () => {
    const { model, modes } = scripted([
      answer(INVENTED),
      JSON.stringify({ excerpts: ["StillInvented thing = makeItUp(now);"] }),
    ]);
    const [finding] = await run(model);
    expect(finding.details).toContain(INVENTED);
    expect(finding.details).toMatch(/could not be found/);
    expect(modes).toHaveLength(2);
  });

  // JDBCDataStore quoted SQLDialect.getNameEscape correctly, and SQLDialect.java
  // was not in its batch. A batch-only check re-asked for it.
  it("makes no extra call when the quote exists in another repository file", async () => {
    writeFileSync(join(root, "SQLDialect.java"), "String nameEscape = getNameEscape();", "utf8");
    const { model, modes } = scripted([answer("String nameEscape = getNameEscape();")]);
    const [finding] = await run(model);
    expect(finding.details).not.toMatch(/could not be found/);
    expect(modes).toEqual(["regular"]);
  });
});
