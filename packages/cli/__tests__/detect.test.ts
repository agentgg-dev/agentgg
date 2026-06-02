import type { Agent } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { describe, expect, it } from "vitest";
import { buildAgentPrompt, buildPreconditionPrompt, hydrateFinding } from "../src/detect.js";
import { MultiProviderDetector } from "../src/detectors/multi-provider.js";

function makeAgent(slug = "sql-injection"): Agent {
  return {
    slug,
    name: "SQL Injection",
    description: "x",
    version: "0.1.0",
    noiseTier: "normal",
    where: {
      extensions: ["ts"],
      filePatterns: [],
      excludePatterns: [],
      useDefaultExcludes: true,
      preFilter: [],
      maxFilesPerBatch: 5,
      maxTurnsPerBatch: 30,
    },
    references: ["CWE-89"],
    prompt: "You are looking for SQL injection. Report any string-concatenated queries.",
  };
}

/**
 * Build a mock language model that returns a fixed JSON object from
 * `doGenerate`. The AI SDK's `generateObject` path consumes the `text`
 * field when `defaultObjectGenerationMode` is "json" and parses it
 * against the caller's schema.
 */
function mockModelReturning(payload: unknown): MockLanguageModelV1 {
  return new MockLanguageModelV1({
    defaultObjectGenerationMode: "json",
    doGenerate: async () => ({
      rawCall: { rawPrompt: null, rawSettings: {} },
      finishReason: "stop",
      usage: { promptTokens: 10, completionTokens: 10 },
      text: JSON.stringify(payload),
    }),
  });
}

describe("buildAgentPrompt", () => {
  const candidates = [{ filePath: "src/login.ts", content: "const x = 1;", hits: [] }];

  it("includes the agent's prompt body verbatim", () => {
    const agent = makeAgent();
    const out = buildAgentPrompt({ agent, candidates });
    expect(out).toContain(agent.prompt);
  });

  it("includes each candidate's file path and content in a fenced code block", () => {
    const out = buildAgentPrompt({ agent: makeAgent(), candidates });
    expect(out).toContain("src/login.ts");
    expect(out).toContain("```typescript");
    expect(out).toContain("const x = 1;");
  });

  it("describes the available tools (Read, Glob, and Grep)", () => {
    const out = buildAgentPrompt({ agent: makeAgent(), candidates });
    expect(out).toContain("Read, Glob, and Grep");
  });

  it("warns the model against fabricating findings", () => {
    const out = buildAgentPrompt({ agent: makeAgent(), candidates });
    expect(out).toContain("Do NOT invent findings");
  });

  it("prepends the recon brief when provided, omits it otherwise", () => {
    const withRecon = buildAgentPrompt({
      agent: makeAgent(),
      candidates,
      recon: "## Project recon\nA small JS service.",
    });
    expect(withRecon).toContain("## Project recon");

    const without = buildAgentPrompt({ agent: makeAgent(), candidates });
    expect(without).not.toContain("## Project recon");
  });
});

describe("buildPreconditionPrompt", () => {
  it("includes the agent name, description, and the relevance condition", () => {
    const out = buildPreconditionPrompt({
      agentName: "SQL Injection",
      agentDescription: "finds string-concatenated SQL",
      conditionPrompt: "Run only if the project talks to a SQL database.",
    });
    expect(out).toContain("SQL Injection");
    expect(out).toContain("finds string-concatenated SQL");
    expect(out).toContain("Run only if the project talks to a SQL database.");
  });

  it("injects the recon brief when provided", () => {
    const out = buildPreconditionPrompt({
      agentName: "x",
      agentDescription: "y",
      conditionPrompt: "z",
      recon: "## Project recon\nUses Postgres.",
    });
    expect(out).toContain("## Project recon");
  });
});

describe("hydrateFinding", () => {
  const agent = makeAgent();

  it("stamps id, agentSlug, filePath, and notifications onto the partial", () => {
    const f = hydrateFinding(
      {
        title: "SQLi in login handler",
        vulnSlug: "sql-injection",
        summary: "concatenated SQL",
        details: "Line 12 concatenates...",
        poc: "curl ...",
        impact: "any unauthenticated user can read users",
        references: [],
        confidence: 0.9,
      },
      agent,
      "src/login.ts",
    );
    expect(f.agentSlug).toBe("sql-injection");
    expect(f.filePath).toBe("src/login.ts");
    expect(f.id).toHaveLength(12);
    expect(f.notifications).toEqual([]);
    expect(f.severity).toBeUndefined();
    expect(f.summary).toBe("concatenated SQL");
    expect(f.poc).toContain("curl");
    expect(f.impact).toContain("unauthenticated");
  });

  it("produces the same id for the same (agent, file, title, lineRange)", () => {
    const partial = {
      title: "X",
      vulnSlug: "sql-injection",
      summary: "s",
      details: "d",
      poc: "p",
      impact: "i",
      references: [],
      confidence: 0.5,
      lineRange: [10, 20] as [number, number],
    };
    const a = hydrateFinding(partial, agent, "src/a.ts");
    const b = hydrateFinding(partial, agent, "src/a.ts");
    expect(a.id).toBe(b.id);
  });

  it("produces a different id when the title changes", () => {
    const base = {
      vulnSlug: "sql-injection",
      summary: "s",
      details: "d",
      poc: "p",
      impact: "i",
      references: [],
      confidence: 0.5,
    };
    const a = hydrateFinding({ ...base, title: "X" }, agent, "src/a.ts");
    const b = hydrateFinding({ ...base, title: "Y" }, agent, "src/a.ts");
    expect(a.id).not.toBe(b.id);
  });
});

describe("MultiProviderDetector", () => {
  const agent = makeAgent();

  it("has a backend name", () => {
    const detector = new MultiProviderDetector(
      "anthropic-api",
      mockModelReturning({ findings: [] }),
    );
    expect(detector.name).toBe("anthropic-api");
  });

  it("returns hydrated Findings produced by the model via runAgent", async () => {
    const model = mockModelReturning({
      findings: [
        {
          title: "SQLi in login",
          vulnSlug: "sql-injection",
          summary:
            "Login handler concatenates request body into SQL, allowing arbitrary DB access.",
          details:
            "Line 12 builds the query via string concatenation:\n```\ndb.query('SELECT * FROM users WHERE id=' + req.params.id)\n```",
          poc: "curl -X GET '/users/1%20OR%201%3D1'",
          impact: "Any unauthenticated request can read or modify the users table.",
          references: ["CWE-89"],
          confidence: 0.9,
          lineRange: [12, 12],
          filePath: null,
          agentSlug: null,
        },
      ],
    });
    const detector = new MultiProviderDetector("anthropic-api", model);
    const findings = await detector.runAgent({
      agent,
      rootDir: "/tmp/whatever",
      candidates: [{ filePath: "src/login.ts", content: "const x = 1;", hits: [] }],
      excludePatterns: [],
      maxFileSizeKb: 500,
      maxTurns: 30,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].agentSlug).toBe("sql-injection");
    // filePath falls back to the candidate path when the model returns null.
    expect(findings[0].filePath).toBe("src/login.ts");
    expect(findings[0].title).toBe("SQLi in login");
    expect(findings[0].id).toHaveLength(12);
    expect(findings[0].summary).toContain("Login handler");
    expect(findings[0].poc).toContain("curl");
  });

  it("returns [] when the model reports no findings", async () => {
    const detector = new MultiProviderDetector("openai", mockModelReturning({ findings: [] }));
    const findings = await detector.runAgent({
      agent,
      rootDir: "/tmp/whatever",
      candidates: [{ filePath: "src/safe.ts", content: "const x = 1;", hits: [] }],
      excludePatterns: [],
      maxFileSizeKb: 500,
      maxTurns: 30,
    });
    expect(findings).toEqual([]);
  });
});
