/**
 * Tests for `resolveCandidatePath` in detect.ts.
 *
 * A tool-loop model that read `data/static/codefixes/loginJim.ts` often reports
 * the finding against the bare basename `loginJim.ts`. That path resolves to
 * nothing under the scan root, so scan.ts's invented-path filter discarded the
 * finding as a hallucination and the batch recorded a clean zero.
 *
 * Measured on juice-shop 2026-08-29: the SAME five `data/static/codefixes/*`
 * files produced one finding each on one run and zero on the next, purely on
 * how the model spelled the path. Five real SQL injections lost to formatting.
 *
 * The repair is deliberately conservative, because `hydrateFinding` hashes the
 * path into the finding id, and that id carries a person's triage status on the
 * platform. A path that already resolves on disk is NEVER rewritten, so no
 * finding that persists today can change id. Only a path that would otherwise
 * be dropped is repaired, and only when exactly one candidate matches.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Agent } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveCandidatePath } from "../src/detect.js";
import { VercelAgentDetector } from "../src/detectors/vercel-agent.js";

const candidates = [
  { filePath: "data/static/codefixes/loginJimChallenge_2.ts" },
  { filePath: "data/static/codefixes/loginBenderChallenge_4.ts" },
  { filePath: "routes/login.ts" },
];

describe("resolveCandidatePath", () => {
  it("repairs a bare basename to the candidate it names", () => {
    expect(resolveCandidatePath("loginJimChallenge_2.ts", candidates)).toBe(
      "data/static/codefixes/loginJimChallenge_2.ts",
    );
  });

  it("repairs a partial path to the candidate it names", () => {
    expect(resolveCandidatePath("codefixes/loginBenderChallenge_4.ts", candidates)).toBe(
      "data/static/codefixes/loginBenderChallenge_4.ts",
    );
  });

  it("returns an already-correct path unchanged", () => {
    expect(resolveCandidatePath("routes/login.ts", candidates)).toBe("routes/login.ts");
  });

  it("accepts a backslash path from a Windows-flavoured model", () => {
    expect(
      resolveCandidatePath("data\\static\\codefixes\\loginJimChallenge_2.ts", candidates),
    ).toBe("data/static/codefixes/loginJimChallenge_2.ts");
  });

  it("strips a leading ./", () => {
    expect(resolveCandidatePath("./routes/login.ts", candidates)).toBe("routes/login.ts");
  });

  describe("refuses to guess", () => {
    it("gives up when a basename matches more than one candidate", () => {
      const ambiguous = [{ filePath: "a/index.ts" }, { filePath: "b/index.ts" }];
      expect(resolveCandidatePath("index.ts", ambiguous)).toBeUndefined();
    });

    it("does not match on a partial segment", () => {
      // `login.ts` must not match `prefix-login.ts`.
      expect(resolveCandidatePath("login.ts", [{ filePath: "routes/prefix-login.ts" }])).toBe(
        undefined,
      );
    });

    it("gives up on a file that is not a candidate at all", () => {
      expect(resolveCandidatePath("src/totally/invented.ts", candidates)).toBeUndefined();
    });

    it.each([undefined, "", "   ", "(unknown)"])("gives up on %o", (raw) => {
      expect(resolveCandidatePath(raw, candidates)).toBeUndefined();
    });

    it("gives up when there are no candidates", () => {
      expect(resolveCandidatePath("login.ts", [])).toBeUndefined();
    });
  });
});

// End-to-end through the detector, because the helper alone cannot show that
// the repaired path reaches `hydrateFinding` BEFORE the finding id is hashed
// from it. A path repaired after hydration would leave the id derived from the
// wrong path, which is what makes a finding detach from its own triage status.
describe("runAgent repairs a mis-spelled path before the id is computed", () => {
  let rootDir: string;

  beforeEach(() => {
    rootDir = mkdtempSync(join(tmpdir(), "agentgg-pathfix-"));
    writeFileSync(join(rootDir, "db.ts"), "// nested file stand-in\n", "utf8");
  });
  afterEach(() => rmSync(rootDir, { recursive: true, force: true }));

  const agent = {
    slug: "sqli",
    name: "sqli",
    description: "Synthetic agent for path-repair tests.",
    version: "0.0.1",
    noiseTier: "normal",
    where: {},
    prompt: "Stub agent body. Model is mocked.",
  } as Agent;

  /** A model that answers with `findings`, no tool calls. */
  function modelReturning(findings: unknown[]) {
    return new MockLanguageModelV1({
      defaultObjectGenerationMode: "json",
      doGenerate: async () => ({
        rawCall: { rawPrompt: null, rawSettings: {} },
        finishReason: "stop" as const,
        usage: { promptTokens: 10, completionTokens: 10 },
        text: JSON.stringify({ findings }),
      }),
    });
  }

  const finding = (filePath: string) => ({
    title: "SQL injection via template literal",
    vulnSlug: "sqli",
    agentSlug: null,
    filePath,
    lineRange: [3, 5],
    summary: "Query built by interpolation.",
    details: "The id is interpolated straight into the query text.",
    poc: "Pass a quote in the id.",
    impact: "Database read.",
    references: ["CWE-89"],
    confidence: 0.9,
  });

  async function run(reportedPath: string, candidatePath: string) {
    const detector = new VercelAgentDetector("openai", modelReturning([finding(reportedPath)]));
    return detector.runAgent({
      agent,
      rootDir,
      candidates: [{ filePath: candidatePath, content: "// stub", hits: [] }],
      excludePatterns: [],
      maxFileSizeKb: 256,
      maxTurns: 3,
    });
  }

  it("rewrites a bare basename onto the candidate it names", async () => {
    const out = await run("loginJim.ts", "data/static/codefixes/loginJim.ts");
    expect(out[0]?.filePath).toBe("data/static/codefixes/loginJim.ts");
  });

  it("gives the finding the id of the repaired path, not the reported one", async () => {
    const repaired = await run("loginJim.ts", "data/static/codefixes/loginJim.ts");
    const direct = await run(
      "data/static/codefixes/loginJim.ts",
      "data/static/codefixes/loginJim.ts",
    );
    // Same vulnerability either way, so the same id: this is what keeps a
    // person's triage status attached across runs.
    expect(repaired[0]?.id).toBe(direct[0]?.id);
  });

  it("leaves a path that exists on disk alone, even if a candidate also matches", async () => {
    // `db.ts` really exists at the root here. Rewriting it to the nested
    // candidate would change an id that already persists. The disk check wins.
    const out = await run("db.ts", "src/lib/db.ts");
    expect(out[0]?.filePath).toBe("db.ts");
  });

  it("leaves an invented path untouched, so the scan filter still drops it", async () => {
    const out = await run("src/totally/invented.ts", "data/static/codefixes/loginJim.ts");
    expect(out[0]?.filePath).toBe("src/totally/invented.ts");
  });
});
