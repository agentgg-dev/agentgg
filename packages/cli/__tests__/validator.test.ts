import type { Finding } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { describe, expect, it } from "vitest";
import { MultiProviderDetector } from "../src/detectors/multi-provider.js";
import { asValidationField, buildValidatePrompt, LlmValidation } from "../src/validator.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "abc123abc123",
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

describe("buildValidatePrompt", () => {
  it("includes the finding's narrative fields", () => {
    const finding = makeFinding();
    const out = buildValidatePrompt({
      finding,
      fileContent: "const x = 1;",
    });
    expect(out).toContain(finding.title);
    expect(out).toContain(finding.summary);
    expect(out).toContain(finding.details);
    expect(out).toContain(finding.poc);
    expect(out).toContain(finding.impact);
  });

  it("includes the file path and a line hint when lineRange is present", () => {
    const out = buildValidatePrompt({
      finding: makeFinding({ lineRange: [42, 50] }),
      fileContent: "x",
    });
    expect(out).toContain("src/login.ts");
    expect(out).toContain("42");
    expect(out).toContain("50");
  });

  it("renders 'unspecified lines' when lineRange is missing", () => {
    const out = buildValidatePrompt({
      finding: makeFinding({ lineRange: undefined }),
      fileContent: "x",
    });
    expect(out).toContain("unspecified lines");
  });

  it("embeds the full file content in a fenced code block", () => {
    const out = buildValidatePrompt({
      finding: makeFinding(),
      fileContent: "const UNIQUE_TOKEN = 1;",
    });
    expect(out).toContain("```typescript");
    expect(out).toContain("UNIQUE_TOKEN");
  });

  it("offers all four verdicts when a scope document is supplied", () => {
    const out = buildValidatePrompt({
      finding: makeFinding(),
      fileContent: "x",
      scope: "# Scope\nout_of_scope: [examples/**]",
    });
    expect(out).toContain("confirmed");
    expect(out).toContain("false-positive");
    expect(out).toContain("out-of-scope");
    expect(out).toContain("uncertain");
  });

  it("withholds the `out-of-scope` verdict when no scope is supplied", () => {
    const out = buildValidatePrompt({
      finding: makeFinding(),
      fileContent: "x",
    });
    // The schema enum lists the three remaining verdicts.
    expect(out).toMatch(/"confirmed"\s*\|\s*"false-positive"\s*\|\s*"uncertain"/);
    // And the prompt explicitly tells the model not to pick it.
    expect(out).toContain("No scope document was supplied");
  });

  it("includes scope content verbatim when supplied", () => {
    const scope = "## Out of scope\n- examples/**\n- vendor/**\nUNIQUE_SCOPE_TOKEN";
    const out = buildValidatePrompt({
      finding: makeFinding(),
      fileContent: "x",
      scope,
    });
    expect(out).toContain("UNIQUE_SCOPE_TOKEN");
    expect(out).toContain("Scope rules");
  });

  it("does not mention scope when none supplied", () => {
    const out = buildValidatePrompt({
      finding: makeFinding(),
      fileContent: "x",
    });
    expect(out).not.toContain("## Scope rules");
  });
});

describe("LlmValidation schema", () => {
  it("accepts a well-formed payload", () => {
    const parsed = LlmValidation.parse({
      verdict: "confirmed",
      reasoning: "Line 12 concatenates req.params.id without escaping.",
      confidence: 0.9,
    });
    expect(parsed.verdict).toBe("confirmed");
  });

  it("rejects an unknown verdict", () => {
    expect(() =>
      LlmValidation.parse({
        verdict: "maybe-vulnerable",
        reasoning: "x",
        confidence: 0.5,
      }),
    ).toThrow();
  });

  it("rejects confidence outside [0, 1]", () => {
    // Negative values fail the lower bound. The schema intentionally rescues
    // raw-percentage form (e.g. 75 → 0.75) for LLMs that ignore the prompt;
    // see the preprocessor in validator.ts.
    expect(() =>
      LlmValidation.parse({
        verdict: "confirmed",
        reasoning: "x",
        confidence: -0.5,
      }),
    ).toThrow();
  });
});

describe("asValidationField", () => {
  it("drops confidence (not stored on Finding.validation)", () => {
    const field = asValidationField({
      verdict: "false-positive",
      reasoning: "The middleware sanitises this above the handler.",
      confidence: 0.8,
    });
    expect(field).toEqual({
      verdict: "false-positive",
      reasoning: "The middleware sanitises this above the handler.",
    });
    expect("confidence" in field).toBe(false);
  });
});

describe("MultiProviderDetector.validateFinding", () => {
  it("returns the verdict + reasoning the model emitted", async () => {
    const model = mockModelReturning({
      verdict: "confirmed",
      reasoning: "Line 12 concatenates user input into the SQL string.",
      confidence: 0.95,
    });
    const detector = new MultiProviderDetector("anthropic-api", model);
    const result = await detector.validateFinding({
      finding: makeFinding(),
      fileContent: "db.query('SELECT * FROM users WHERE id=' + req.params.id)",
    });
    expect(result.verdict).toBe("confirmed");
    expect(result.reasoning).toContain("concatenates");
  });

  it("propagates a false-positive verdict unchanged", async () => {
    const model = mockModelReturning({
      verdict: "false-positive",
      reasoning: "The query is parameterised; the detector misread it.",
      confidence: 0.85,
    });
    const detector = new MultiProviderDetector("anthropic-api", model);
    const result = await detector.validateFinding({
      finding: makeFinding(),
      fileContent: "db.query('SELECT * FROM users WHERE id=?', [req.params.id])",
    });
    expect(result.verdict).toBe("false-positive");
  });

  it("returns an out-of-scope verdict when scope rules disqualify the finding", async () => {
    const model = mockModelReturning({
      verdict: "out-of-scope",
      reasoning: "examples/** is excluded by the supplied SECURITY.md.",
      confidence: 0.9,
    });
    const detector = new MultiProviderDetector("anthropic-api", model);
    const result = await detector.validateFinding({
      finding: makeFinding({ filePath: "examples/demo.ts" }),
      fileContent: "x",
      scope: "out_of_scope:\n  paths:\n    - examples/**",
    });
    expect(result.verdict).toBe("out-of-scope");
    expect(result.reasoning).toContain("examples");
  });

  it("rejects a model response with an invalid verdict", async () => {
    const model = mockModelReturning({
      verdict: "totally-vulnerable",
      reasoning: "x",
      confidence: 0.5,
    });
    const detector = new MultiProviderDetector("anthropic-api", model);
    await expect(
      detector.validateFinding({
        finding: makeFinding(),
        fileContent: "x",
      }),
    ).rejects.toThrow();
  });
});
