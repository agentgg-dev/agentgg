import type { Finding } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { describe, expect, it } from "vitest";
import { MultiProviderDetector } from "../src/detectors/multi-provider.js";
import { asCvssScore, buildScorePrompt, LlmScore } from "../src/scoring.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "abc123",
    agentSlug: "sql-injection",
    title: "Concatenated SQL in login handler",
    vulnSlug: "sql-injection",
    filePath: "src/login.ts",
    lineRange: [12, 14],
    summary: "Login handler builds SQL via string concatenation.",
    details:
      "Line 12 builds the query via string concat. Untrusted `req.params.id` flows in unsanitised.",
    poc: "curl '/users/1 OR 1=1'",
    impact: "Unauthenticated read/write to users table.",
    references: ["CWE-89"],
    confidence: 0.9,
    notifications: [],
    ...overrides,
  };
}

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

describe("buildScorePrompt", () => {
  it("includes the finding's narrative + the file content", () => {
    const finding = makeFinding();
    const out = buildScorePrompt({
      finding,
      fileContent: "const sql = 'SELECT * FROM users';",
    });
    expect(out).toContain(finding.title);
    expect(out).toContain(finding.summary);
    expect(out).toContain(finding.details);
    expect(out).toContain(finding.poc);
    expect(out).toContain(finding.impact);
    expect(out).toContain("const sql = 'SELECT * FROM users'");
  });

  it("references the CVSS 3.1 metric reference glossary", () => {
    const out = buildScorePrompt({
      finding: makeFinding(),
      fileContent: "x",
    });
    // Pin the prompt to the actual rubric so a reviewer can sanity-check it.
    expect(out).toContain("Attack Vector");
    expect(out).toContain("Attack Complexity");
    expect(out).toContain("Privileges Required");
    expect(out).toContain("User Interaction");
    expect(out).toContain("Scope");
  });
});

describe("asCvssScore", () => {
  it("computes the canonical 9.8 score for a pre-auth full-impact metric set", () => {
    const llm: LlmScore = {
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "U",
      confidentiality: "H",
      integrity: "H",
      availability: "H",
      justification: "Pre-auth SQLi reachable from the public endpoint.",
    };
    const score = asCvssScore(llm);
    expect(score.baseScore).toBe(9.8);
    expect(score.severity).toBe("CRITICAL");
    expect(score.vector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(score.justification).toContain("Pre-auth");
  });
});

describe("MultiProviderDetector.scoreFinding", () => {
  it("turns LLM metric choices into a full CvssScore", async () => {
    const model = mockModelReturning({
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "U",
      confidentiality: "H",
      integrity: "H",
      availability: "H",
      justification: "Unauthenticated SQLi at the login route.",
    });
    const detector = new MultiProviderDetector("anthropic-api", model, {
      providerKey: "anthropic",
    });
    const result = await detector.scoreFinding({
      finding: makeFinding(),
      fileContent: "const sql = 'SELECT * FROM users';",
    });
    expect(result.baseScore).toBe(9.8);
    expect(result.severity).toBe("CRITICAL");
    expect(result.vector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(result.metrics.attackVector).toBe("N");
    expect(result.justification).toContain("Unauthenticated SQLi");
  });

  it("propagates a lower-severity metric set into the right bucket", async () => {
    const model = mockModelReturning({
      attackVector: "L",
      attackComplexity: "H",
      privilegesRequired: "H",
      userInteraction: "R",
      scope: "U",
      confidentiality: "N",
      integrity: "N",
      availability: "L",
      justification: "Local-only race that needs an admin shell.",
    });
    const detector = new MultiProviderDetector("openai", model, {
      providerKey: "openai",
    });
    const result = await detector.scoreFinding({
      finding: makeFinding(),
      fileContent: "x",
    });
    expect(result.baseScore).toBe(1.8);
    expect(result.severity).toBe("LOW");
    expect(result.vector).toBe("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L");
  });
});
