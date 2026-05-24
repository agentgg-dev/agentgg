import type { Agent } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { describe, expect, it } from "vitest";
import {
  buildDetectPrompt,
  buildHuntPrompt,
  hydrateFinding,
  type RuleHitsForFile,
} from "../src/detect.js";
import { MultiProviderDetector } from "../src/detectors/multi-provider.js";

function makeAgent(slug = "sql-injection"): Agent {
  return {
    slug,
    name: "SQL Injection",
    description: "x",
    version: "0.1.0",
    noiseTier: "normal",
    filePatterns: ["**/*.ts"],
    languages: [],
    prefilter: [],
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

describe("buildDetectPrompt", () => {
  it("includes the agent's prompt body verbatim", () => {
    const agent = makeAgent();
    const out = buildDetectPrompt(agent, "src/login.ts", "const x = 1;");
    expect(out).toContain(agent.prompt);
  });

  it("includes the file path and content in a fenced code block", () => {
    const out = buildDetectPrompt(makeAgent(), "src/login.ts", "const x = 1;");
    expect(out).toContain("src/login.ts");
    expect(out).toContain("```typescript");
    expect(out).toContain("const x = 1;");
  });

  it("warns the model against fabricating findings", () => {
    const out = buildDetectPrompt(makeAgent(), "a.ts", "");
    const flat = out.toLowerCase().replace(/\s+/g, " ");
    expect(flat).toContain("do not invent findings");
  });
});

describe("buildDetectPrompt — ruleHits augmentation", () => {
  const ruleHits: ReadonlyArray<RuleHitsForFile> = [
    {
      ruleSlug: "js-express-route",
      hits: [
        { line: 12, label: "Express route registration", snippet: 'app.get("/users", listUsers)' },
        { line: 45, label: "Auth middleware", snippet: ".use(authMiddleware)" },
      ],
    },
  ];

  it("renders a scanner-context block when ruleHits are provided", () => {
    const out = buildDetectPrompt(makeAgent(), "src/api.ts", "const x = 1;", ruleHits);
    expect(out).toContain("## Scanner pre-found candidates in this file");
    expect(out).toContain("L12 [Express route registration] (js-express-route)");
    expect(out).toContain("L45 [Auth middleware] (js-express-route)");
  });

  it("omits the scanner-context block when ruleHits is undefined", () => {
    const out = buildDetectPrompt(makeAgent(), "src/api.ts", "const x = 1;");
    expect(out).not.toContain("Scanner pre-found candidates");
  });

  it("omits the scanner-context block when ruleHits is empty", () => {
    const out = buildDetectPrompt(makeAgent(), "src/api.ts", "const x = 1;", []);
    expect(out).not.toContain("Scanner pre-found candidates");
  });

  it("filters out synthetic '(no preFilter)' hits — only meaningful labels render", () => {
    const out = buildDetectPrompt(makeAgent(), "src/api.ts", "const x = 1;", [
      {
        ruleSlug: "noop-rule",
        hits: [{ line: 1, label: "(no preFilter)", snippet: "" }],
      },
    ]);
    expect(out).not.toContain("Scanner pre-found candidates");
  });

  it("places the scanner-context block AFTER the file content and BEFORE the reporting instructions", () => {
    const out = buildDetectPrompt(makeAgent(), "src/api.ts", "const x = 1;", ruleHits);
    const contentIdx = out.indexOf("const x = 1;");
    const blockIdx = out.indexOf("## Scanner pre-found candidates");
    // "Respond with ONLY a JSON object" is the JSON-output reporting
    // instruction — single-line anchor so we don't have to renormalize
    // whitespace.
    const reportingIdx = out.indexOf("Respond with ONLY a JSON object");
    expect(contentIdx).toBeGreaterThanOrEqual(0);
    expect(blockIdx).toBeGreaterThan(contentIdx);
    expect(reportingIdx).toBeGreaterThan(blockIdx);
  });
});

describe("buildHuntPrompt", () => {
  const baseArgs = {
    excludePatterns: [],
    includePatterns: [],
    maxFileSizeKb: 500,
  };

  it("includes the agent's prompt body verbatim", () => {
    const agent = makeAgent();
    const out = buildHuntPrompt(agent, baseArgs);
    expect(out).toContain(agent.prompt);
  });

  it("describes the available tools (Read, Glob, Grep)", () => {
    const out = buildHuntPrompt(makeAgent(), baseArgs);
    expect(out).toContain("Read, Glob, Grep");
  });

  it("omits the scanner-context block when ruleHits are absent", () => {
    const out = buildHuntPrompt(makeAgent(), baseArgs);
    expect(out).not.toContain("Scanner pre-found entry points");
  });
});

describe("buildHuntPrompt — ruleHits augmentation", () => {
  const baseArgs = {
    excludePatterns: [],
    includePatterns: [],
    maxFileSizeKb: 500,
  };

  it("renders a scanner-context block when ruleHits are provided", () => {
    const ruleHits = new Map<string, ReadonlyArray<RuleHitsForFile>>([
      [
        "routes/api.ts",
        [
          {
            ruleSlug: "js-express-route",
            hits: [
              { line: 12, label: "Express route", snippet: 'app.get("/users")' },
              { line: 45, label: "Express route", snippet: 'app.post("/login")' },
            ],
          },
        ],
      ],
      [
        "routes/admin.ts",
        [
          {
            ruleSlug: "js-express-route",
            hits: [{ line: 8, label: "Express route", snippet: 'app.delete("/users/:id")' }],
          },
        ],
      ],
    ]);
    const out = buildHuntPrompt(makeAgent(), { ...baseArgs, ruleHits });
    expect(out).toContain("## Scanner pre-found entry points");
    expect(out).toContain("3 hit(s) across 2 file(s)");
    expect(out).toContain("routes/api.ts");
    expect(out).toContain("routes/admin.ts");
    expect(out).toContain("L12 [Express route] (js-express-route)");
  });

  it("sorts files alphabetically — deterministic prompt output across runs", () => {
    const ruleHits = new Map<string, ReadonlyArray<RuleHitsForFile>>([
      ["zzz.ts", [{ ruleSlug: "r", hits: [{ line: 1, label: "L", snippet: "z" }] }]],
      ["aaa.ts", [{ ruleSlug: "r", hits: [{ line: 1, label: "L", snippet: "a" }] }]],
    ]);
    const out = buildHuntPrompt(makeAgent(), { ...baseArgs, ruleHits });
    expect(out.indexOf("aaa.ts")).toBeLessThan(out.indexOf("zzz.ts"));
  });

  it("omits the block when all hits are synthetic '(no preFilter)' entries", () => {
    const ruleHits = new Map<string, ReadonlyArray<RuleHitsForFile>>([
      ["x.ts", [{ ruleSlug: "r", hits: [{ line: 1, label: "(no preFilter)", snippet: "" }] }]],
    ]);
    const out = buildHuntPrompt(makeAgent(), { ...baseArgs, ruleHits });
    expect(out).not.toContain("Scanner pre-found entry points");
  });

  it("omits the block when the ruleHits map is empty", () => {
    const out = buildHuntPrompt(makeAgent(), { ...baseArgs, ruleHits: new Map() });
    expect(out).not.toContain("Scanner pre-found entry points");
  });

  it("places the scanner-context block BEFORE the scope rules / tools description", () => {
    const ruleHits = new Map<string, ReadonlyArray<RuleHitsForFile>>([
      ["x.ts", [{ ruleSlug: "r", hits: [{ line: 1, label: "L", snippet: "x" }] }]],
    ]);
    const out = buildHuntPrompt(makeAgent(), { ...baseArgs, ruleHits });
    const blockIdx = out.indexOf("## Scanner pre-found entry points");
    const toolsIdx = out.indexOf("Read, Glob, Grep");
    expect(blockIdx).toBeGreaterThan(0);
    expect(blockIdx).toBeLessThan(toolsIdx);
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

  it("returns hydrated Findings produced by the model", async () => {
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
    const findings = await detector.detectFile({
      agent,
      filePath: "src/login.ts",
      content: "const x = 1;",
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].agentSlug).toBe("sql-injection");
    expect(findings[0].filePath).toBe("src/login.ts");
    expect(findings[0].title).toBe("SQLi in login");
    expect(findings[0].id).toHaveLength(12);
    expect(findings[0].summary).toContain("Login handler");
    expect(findings[0].poc).toContain("curl");
  });

  it("hunt() throws with a useful message — hunt mode is not supported by MultiProviderDetector", async () => {
    const detector = new MultiProviderDetector("openai", mockModelReturning({ findings: [] }));
    await expect(
      detector.hunt({
        agent,
        rootDir: "/tmp/whatever",
        excludePatterns: [],
        includePatterns: [],
        maxFileSizeKb: 500,
        maxTurns: 150,
      }),
    ).rejects.toThrow(/Hunt mode is not supported/);
  });

  it("returns [] when the model reports no findings", async () => {
    const detector = new MultiProviderDetector("openai", mockModelReturning({ findings: [] }));
    const findings = await detector.detectFile({
      agent,
      filePath: "src/safe.ts",
      content: "const x = 1;",
    });
    expect(findings).toEqual([]);
  });
});
