import type { Finding } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { describe, expect, it } from "vitest";
import { VercelAgentDetector } from "../src/detectors/vercel-agent.js";
import { buildFixPrompt, cleanFix } from "../src/fixer.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "abc123",
    agentSlug: "sql-injection",
    title: "Concatenated SQL in login handler",
    vulnSlug: "sql-injection",
    filePath: "src/login.ts",
    lineRange: [12, 14],
    summary: "Login handler builds SQL via string concatenation.",
    details: "Line 12 builds the query via string concat from `req.params.id`.",
    poc: "curl '/users/1 OR 1=1'",
    impact: "Unauthenticated read/write to users table.",
    references: ["CWE-89"],
    confidence: 0.9,
    notifications: [],
    ...overrides,
  };
}

function mockModelAnswering(text: string) {
  const prompts: string[] = [];
  const model = new MockLanguageModelV1({
    doGenerate: async (options) => {
      prompts.push(JSON.stringify(options.prompt));
      return {
        rawCall: { rawPrompt: null, rawSettings: {} },
        finishReason: "stop",
        usage: { promptTokens: 10, completionTokens: 10 },
        text,
      };
    },
  });
  return { model, prompts };
}

describe("buildFixPrompt", () => {
  it("includes the finding's narrative, its location and the file content", () => {
    const finding = makeFinding();
    const out = buildFixPrompt({ finding, fileContent: "const sql = 'SELECT * FROM users';" });
    expect(out).toContain(finding.title);
    expect(out).toContain(finding.summary);
    expect(out).toContain(finding.details);
    expect(out).toContain(finding.poc);
    expect(out).toContain(finding.impact);
    expect(out).toContain("src/login.ts (lines 12–14)");
    expect(out).toContain("const sql = 'SELECT * FROM users'");
  });

  it("gives the impact validation confirmed, not the agent's claim", () => {
    const out = buildFixPrompt({
      finding: makeFinding({
        impact: "Full database dump.",
        validation: {
          verdict: "confirmed",
          reasoning: "r",
          confirmedImpact: "Reads any user's notes.",
          unconfirmedImpact: "Full database dump.",
        },
      }),
      fileContent: "x",
    });
    expect(out).toContain("### Impact (confirmed by validation)\nReads any user's notes.");
    expect(out).not.toContain("Full database dump.");
  });

  it("quotes the validator's reasoning so the fix targets the path it traced", () => {
    const out = buildFixPrompt({
      finding: makeFinding({
        validation: { verdict: "confirmed", reasoning: "`id` reaches db.query() unescaped." },
      }),
      fileContent: "x",
    });
    expect(out).toContain("`id` reaches db.query() unescaped.");
  });
});

describe("cleanFix", () => {
  it("trims the answer", () => {
    expect(cleanFix("\n  Bind the parameter.  \n")).toBe("Bind the parameter.");
  });

  it("returns nothing for a blank answer", () => {
    expect(cleanFix(" \n\t")).toBeUndefined();
  });

  it("unwraps an answer the model put in one markdown fence", () => {
    const inner = "Bind the parameter.\n\n```ts\ndb.query(sql, [id]);\n```";
    expect(cleanFix(`\`\`\`markdown\n${inner}\n\`\`\``)).toBe(inner);
  });

  it("keeps a code fence that opens the answer", () => {
    const answer = "```ts\ndb.query(sql, [id]);\n```\nBind the parameter.";
    expect(cleanFix(answer)).toBe(answer);
  });
});

describe("VercelAgentDetector.suggestFix", () => {
  it("sends the fix prompt and returns the model's text", async () => {
    const { model, prompts } = mockModelAnswering("Bind the parameter.");
    const fix = await new VercelAgentDetector("openai", model).suggestFix({
      finding: makeFinding(),
      fileContent: "const sql = 'SELECT * FROM users';",
    });
    expect(fix).toBe("Bind the parameter.");
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("Concatenated SQL in login handler");
  });
});
