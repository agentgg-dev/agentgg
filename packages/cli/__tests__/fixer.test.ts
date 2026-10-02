import type { Finding } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { describe, expect, it } from "vitest";
import { VercelAgentDetector } from "../src/detectors/vercel-agent.js";
import { buildFixPrompt } from "../src/fixer.js";

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

function mockModelAnswering(text: string, finishReason: "stop" | "length" = "stop") {
  const prompts: string[] = [];
  const model = new MockLanguageModelV1({
    doGenerate: async (options) => {
      prompts.push(JSON.stringify(options.prompt));
      return {
        rawCall: { rawPrompt: null, rawSettings: {} },
        finishReason,
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

  it("names a live run as the proof when only the live run confirmed the finding", () => {
    const out = buildFixPrompt({
      finding: makeFinding({
        validation: { verdict: "uncertain", reasoning: "Could not trace the entry point." },
        live: {
          result: "reproduced",
          reasoning: "The login returned a session for the injected user.",
          counterevidence: "",
        },
      }),
      fileContent: "x",
    });
    expect(out).toContain("A live run reproduced the vulnerability");
    expect(out).toContain("The login returned a session for the injected user.");
    // An uncertain review is not a confirmation, so it is not quoted as one.
    expect(out).not.toContain("A reviewer confirmed");
    expect(out).not.toContain("Could not trace the entry point.");
  });

  it("shows the requests the live run sent", () => {
    const out = buildFixPrompt({
      finding: makeFinding({
        validation: { verdict: "confirmed", reasoning: "r" },
        live: {
          result: "reproduced",
          reasoning: "r",
          counterevidence: "",
          evidence: {
            screenshots: [],
            requests: [
              {
                method: "POST",
                url: "http://app.test/login",
                status: 200,
                requestBody: "user=' OR 1=1--",
              },
            ],
          },
        },
      }),
      fileContent: "x",
    });
    expect(out).toContain("POST http://app.test/login → 200");
    expect(out).toContain("user=' OR 1=1--");
  });

  it("leaves the live section out when the live run did not reproduce the finding", () => {
    const out = buildFixPrompt({
      finding: makeFinding({
        validation: { verdict: "confirmed", reasoning: "r" },
        live: { result: "error", reasoning: "The sandbox crashed.", counterevidence: "" },
      }),
      fileContent: "x",
    });
    expect(out).not.toContain("The sandbox crashed.");
  });

  it("includes the recon brief when there is one", () => {
    const out = buildFixPrompt({
      finding: makeFinding(),
      fileContent: "x",
      recon: {
        purpose: "p",
        languages: ["typescript"],
        frameworks: ["express"],
        integrations: [],
        notableDirs: [],
        summary: "An Express API backed by Postgres.",
        reconHash: "h",
        generatedAt: "2026-01-01T00:00:00.000Z",
      },
    });
    expect(out).toContain("An Express API backed by Postgres.");
    expect(out).toContain("express");
  });

  it("asks for a fix of the whole class of input, and gives the model a way out", () => {
    const out = buildFixPrompt({ finding: makeFinding(), fileContent: "x" });
    expect(out).toContain("not only the PoC");
    expect(out).toContain("valid input");
    expect(out).toContain("cannot write a correct fix");
  });
});

describe("buildFixPrompt answer format", () => {
  const prompt = (extra: object = {}) =>
    buildFixPrompt({ finding: makeFinding(), fileContent: "x", ...extra });

  it("asks for the code change as SEARCH/REPLACE blocks that are checked against the file", () => {
    const out = prompt();
    expect(out).toContain("<<<<<<< SEARCH");
    expect(out).toContain(">>>>>>> REPLACE");
    expect(out).toContain("checked against the file");
  });

  it("forbids statements about files the model cannot see, and optional extras", () => {
    const out = prompt();
    expect(out).toContain("do not state what it contains");
    expect(out).toContain("No optional hardening");
  });

  it("has no retry section on the first ask", () => {
    expect(prompt()).not.toContain("previous answer");
  });

  it("shows a rejected answer and its problems when it asks again", () => {
    const out = prompt({
      retry: {
        answer: "Bind it.\n<<<<<<< SEARCH\nnope\n=======\nx\n>>>>>>> REPLACE",
        problems: ["Block 1: the SEARCH lines do not occur in src/login.ts."],
      },
    });
    expect(out).toContain("Your previous answer was rejected");
    expect(out).toContain("Bind it.\n<<<<<<< SEARCH\nnope");
    expect(out).toContain("- Block 1: the SEARCH lines do not occur in src/login.ts.");
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

  it("rejects an answer the output limit cut off", async () => {
    const { model } = mockModelAnswering("Bind the parameter.\n```ts\ndb.que", "length");
    await expect(
      new VercelAgentDetector("openai", model).suggestFix({
        finding: makeFinding(),
        fileContent: "x",
      }),
    ).rejects.toThrow(/cut off/);
  });
});
