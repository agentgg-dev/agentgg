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

  it("asks for the blocks together, because the report shows them as one diff", () => {
    expect(prompt()).toContain("no text between them");
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

describe("buildFixPrompt live evidence", () => {
  type Req = { method: string; url: string; status: number; requestBody?: string };
  const INJECTION = "' OR '1'='1' --";
  const SCRIPT = "test('exploit', async ({ page }) => { await page.goto('/login'); });";

  /** A reproduced finding whose agent wrote `reasoning` and sent `requests`. */
  const reproduced = (requests: Req[], reasoning: string, negativeControl = "") =>
    makeFinding({
      poc: "Send the payload to the login form.",
      validation: { verdict: "confirmed", reasoning: "r" },
      live: {
        result: "reproduced",
        reasoning,
        counterevidence: "",
        negativeControl,
        evidence: { screenshots: [], requests },
      },
    });

  const SESSION: Req[] = [
    { method: "GET", url: "http://app.test/", status: 200 },
    { method: "GET", url: "http://app.test/assets/app.css", status: 200 },
    {
      method: "POST",
      url: "http://app.test/login",
      status: 302,
      requestBody: `username=${INJECTION}&password=anything`,
    },
    { method: "GET", url: "http://app.test/", status: 200 },
    {
      method: "POST",
      url: "http://app.test/login",
      status: 401,
      requestBody: "username=alice&password=wrong-password",
    },
  ];
  const prompt = (finding: Finding, extra: object = {}) =>
    buildFixPrompt({ finding, fileContent: "x", ...extra });

  describe("with the reproduction script", () => {
    const finding = reproduced(SESSION, `I sent ${INJECTION} as the username.`, "alice failed.");

    it("shows a script whose replay passed, and the negative control, in place of the requests", () => {
      const out = prompt(finding, { liveScript: { source: SCRIPT, passed: true } });
      expect(out).toContain(SCRIPT);
      expect(out).toContain("Its replay passed");
      expect(out).toContain("alice failed.");
      expect(out).not.toContain("http://app.test/login");
    });

    it("says so when the replay of the script did not pass", () => {
      const out = prompt(finding, { liveScript: { source: SCRIPT, passed: false } });
      expect(out).toContain(SCRIPT);
      expect(out).toContain("did not pass");
      expect(out).not.toContain("Its replay passed");
    });

    it("cuts a long script and says that it did", () => {
      const out = prompt(finding, { liveScript: { source: "x".repeat(20_000), passed: true } });
      expect(out).not.toContain("x".repeat(7000));
      expect(out).toContain("script cut");
    });

    it("tells the model not to repeat a credential from the script", () => {
      const out = prompt(finding, { liveScript: { source: SCRIPT, passed: true } });
      expect(out).toContain("Never repeat a credential");
    });
  });

  describe("without a script", () => {
    it("shows only the requests the agent refers to: the attack and the control", () => {
      const out = prompt(
        reproduced(
          SESSION,
          `I sent ${INJECTION} as the username and was signed in.`,
          "A login as alice with wrong-password returned 401.",
        ),
      );
      expect(out).toContain(`POST http://app.test/login → 302, payload \`username=${INJECTION}`);
      expect(out).toContain("POST http://app.test/login → 401");
      expect(out).not.toContain("GET http://app.test/ →");
      expect(out).not.toContain("app.css");
    });

    it("finds an attack that is carried in the URL, through its decoded value", () => {
      const url = "http://app.test/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E";
      const out = prompt(
        reproduced(
          [{ method: "GET", url, status: 200 }],
          "The page ran <script>alert(1)</script> from the q parameter.",
        ),
      );
      expect(out).toContain(`GET ${url} → 200`);
    });

    it("finds a request whose path the agent names", () => {
      const out = prompt(
        reproduced(
          [
            { method: "GET", url: "http://app.test/notes/1", status: 200 },
            { method: "GET", url: "http://app.test/notes/2", status: 200 },
          ],
          "As bob, I requested /notes/1 and read the note of alice.",
        ),
      );
      expect(out).toContain("GET http://app.test/notes/1 → 200");
      expect(out).not.toContain("notes/2");
    });

    it("does not take a request for a value too short to mean anything", () => {
      const out = prompt(
        reproduced(
          [{ method: "GET", url: "http://app.test/item?id=1", status: 200 }],
          "Step 1 loaded the page.",
        ),
      );
      expect(out).not.toContain("item?id=1");
    });

    it("lists a repeated request once", () => {
      const again = { method: "GET", url: "http://app.test/notes/1", status: 200 };
      const out = prompt(reproduced([again, again, again], "I requested /notes/1."));
      expect(out.match(/GET http:\/\/app\.test\/notes\/1 → 200/g)).toHaveLength(1);
    });

    it("has no request list when the agent refers to none of them", () => {
      const out = prompt(reproduced(SESSION, "The exploit worked."));
      expect(out).not.toContain("Requests");
      expect(out).toContain("The exploit worked.");
    });
  });
});

describe("buildFixPrompt with read tools", () => {
  const withTools = buildFixPrompt({ finding: makeFinding(), fileContent: "x", root: "/repo" });
  const single = buildFixPrompt({ finding: makeFinding(), fileContent: "x" });

  it("tells the model to read what the fix depends on before it writes", () => {
    expect(withTools).toContain("Read, Glob and Grep");
    expect(withTools).toContain("have not seen in this repository");
  });

  it("tells the model that its tool calls are limited, so it writes the fix when it knows it", () => {
    expect(withTools).toContain("limited number of tool calls");
    expect(single).not.toContain("limited number of tool calls");
  });

  it("lets a block edit another file, named on the line above the block", () => {
    expect(withTools).toContain("path of its file");
    expect(withTools).not.toContain("You cannot see that file");
  });

  it("keeps the fix to the one file shown when there are no tools", () => {
    expect(single).toContain("You cannot see that file");
    expect(single).not.toContain("Read, Glob and Grep");
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

  /** A model that records what each call was given. */
  function recordingModel(text: string) {
    const calls: { tools: string[]; maxTokens?: number }[] = [];
    const model = new MockLanguageModelV1({
      doGenerate: async (options) => {
        const mode = options.mode as { tools?: { name: string }[] };
        calls.push({
          tools: (mode.tools ?? []).map((t) => t.name),
          maxTokens: options.maxTokens,
        });
        return {
          rawCall: { rawPrompt: null, rawSettings: {} },
          finishReason: "stop",
          usage: { promptTokens: 10, completionTokens: 10 },
          text,
        };
      },
    });
    return { model, calls };
  }

  it("gives the model the read tools when it has a repository root", async () => {
    const { model, calls } = recordingModel("Bind the parameter.");
    const fix = await new VercelAgentDetector("openai", model).suggestFix({
      finding: makeFinding(),
      fileContent: "x",
      root: process.cwd(),
    });
    expect(fix).toBe("Bind the parameter.");
    expect(calls[0].tools.sort()).toEqual(["Glob", "Grep", "Read"]);
  });

  it("gives no tools without a repository root", async () => {
    const { model, calls } = recordingModel("Bind the parameter.");
    await new VercelAgentDetector("openai", model).suggestFix({
      finding: makeFinding(),
      fileContent: "x",
    });
    expect(calls[0].tools).toEqual([]);
  });

  it.each([
    ["with tools", process.cwd()],
    ["without tools", undefined],
  ])("limits the output of a call %s, so a search for a fix cannot run to the model's cap", async (_how, root) => {
    const { model, calls } = recordingModel("Bind the parameter.");
    await new VercelAgentDetector("openai", model).suggestFix({
      finding: makeFinding(),
      fileContent: "x",
      root,
    });
    expect(calls[0].maxTokens).toBeGreaterThan(0);
    expect(calls[0].maxTokens).toBeLessThanOrEqual(32_000);
  });

  describe("a session that ends on a tool call written as text", () => {
    const LEAKED =
      "<tool_call>Read<arg_key>path</arg_key><arg_value>src/login.ts</arg_value></tool_call>";

    /** A model that gives each answer in turn, then repeats the last one. */
    function answering(...answers: string[]) {
      let call = 0;
      return new MockLanguageModelV1({
        defaultObjectGenerationMode: "json",
        doGenerate: async () => ({
          rawCall: { rawPrompt: null, rawSettings: {} },
          finishReason: "stop",
          usage: { promptTokens: 10, completionTokens: 10 },
          text: answers[Math.min(call++, answers.length - 1)],
        }),
      });
    }
    const fixWith = (model: MockLanguageModelV1) =>
      new VercelAgentDetector("openai", model).suggestFix({
        finding: makeFinding(),
        fileContent: "x",
        root: process.cwd(),
      });

    it("asks once more with no tools, and returns that answer", async () => {
      const model = answering(LEAKED, JSON.stringify({ fix: "Bind the parameter." }));
      await expect(fixWith(model)).resolves.toBe("Bind the parameter.");
    });

    it("fails when the answer with no tools is a tool call too", async () => {
      await expect(fixWith(answering(LEAKED))).rejects.toThrow(/no fix/);
    });
  });

  it("uses fewer turns than the validator, because it reads definitions and does not trace a chain", async () => {
    const steps: number[] = [];
    const model = new MockLanguageModelV1({
      doGenerate: async () => {
        steps.push(steps.length);
        return {
          rawCall: { rawPrompt: null, rawSettings: {} },
          finishReason: "tool-calls",
          usage: { promptTokens: 10, completionTokens: 10 },
          toolCalls: [
            {
              toolCallType: "function",
              toolCallId: `c${steps.length}`,
              toolName: "Glob",
              args: JSON.stringify({ pattern: `*.x${steps.length}` }),
            },
          ],
        };
      },
    });
    await new VercelAgentDetector("openai", model, { validateMaxTurns: 50 })
      .suggestFix({ finding: makeFinding(), fileContent: "x", root: process.cwd() })
      .catch(() => {});
    // The tool loop, plus the two last-chance calls with no tools.
    expect(steps.length).toBeLessThanOrEqual(30);
  });

  it("fails when the tool session ends with no answer", async () => {
    const { model } = recordingModel("");
    await expect(
      new VercelAgentDetector("openai", model).suggestFix({
        finding: makeFinding(),
        fileContent: "x",
        root: process.cwd(),
      }),
    ).rejects.toThrow(/no fix/);
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
