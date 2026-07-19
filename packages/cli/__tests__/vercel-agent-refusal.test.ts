/**
 * Tests for `looksLikeRefusal` in detectors/refusal.ts — the failure-path
 * classifier that distinguishes a content refusal (the model declining to
 * analyze code it read as harmful) from a genuine parse failure. On a refusal
 * `runAgent` returns 0 findings instead of throwing, so the agent completes
 * rather than failing the batch. Pure-function tests — no LLM calls.
 *
 * False positives matter: a misfire silently drops a real (but malformed)
 * result to empty and suppresses the agent's solo retry. On the Vercel path the
 * reformat runs first and softens that; the Claude path has no reformat, so
 * this classifier is the only guard. Hence three defenses: first-person
 * anchoring, capability-verb exclusion, and analysis-marker detection.
 */
import { describe, expect, it } from "vitest";
import { looksLikeRefusal } from "../src/detectors/refusal.js";

describe("looksLikeRefusal", () => {
  describe("recognizes content refusals", () => {
    it.each([
      ["I can't help analyze this exploit code."],
      ["I cannot assist with analyzing this payload."],
      ["I'm sorry, but I won't produce an analysis of this malware."],
      ["I will not help with this request."],
      ["I refuse to analyze code designed to harm users."],
      ["I'm unable to complete this security analysis."],
      ["I am unable to help with that."],
      ["I'm not comfortable analyzing this attack script."],
      ["I'm not able to assist with this."],
      ["After reviewing the request, I must decline."],
      ["I have to decline this task."],
      ["I'll decline to analyze the provided code."],
      // Curly apostrophe variant (models emit both).
      ["I’m not comfortable helping with this."],
      ["Sorry, I can’t analyze this — it’s designed to exploit users."],
    ])("matches %s", (text) => {
      expect(looksLikeRefusal(text)).toBe(true);
    });
  });

  describe("does NOT match genuine analysis or empty output", () => {
    it.each([
      // Real finding prose that mentions the same verbs, third-person — must
      // NOT be misread as a refusal.
      ["The endpoint cannot validate the token, so an attacker can forge it."],
      ["Users won't be able to reset their password without this fix."],
      ["The parser will not reject the oversized payload."],
      ["This function declines to sanitize input before the SQL query."],
      // Empty / length-cutoff completions — real failures, must still throw.
      [""],
      ["   "],
      // A normal (if malformed) findings preamble.
      ["Here are the findings I identified during my investigation:"],
      ["I found a SQL injection in src/db.ts and I can confirm it is exploitable."],
    ])("does not match %s", (text) => {
      expect(looksLikeRefusal(text)).toBe(false);
    });
  });

  describe("does NOT match capability caveats", () => {
    // The dangerous class: a real analysis that opens by declining one
    // *capability* ("I can't read the excluded file") and then reports findings
    // anyway. Reads like a refusal, is not one. Misclassifying these drops real
    // findings to empty and suppresses the agent's solo retry.
    it.each([
      [
        "I can't determine whether this is exploitable without the config, but here are the findings:",
      ],
      ["I cannot confirm the sink is reachable; findings below."],
      ["I won't flag the test fixtures. Findings:"],
      ["I'm unable to read src/config.ts (excluded), so I analyzed the rest. Findings:"],
      ["I can't access the .env file. Based on the code I did read, here are 3 findings:"],
      ["I couldn't fully trace the call chain, but I'm not able to rule out SSRF in fetchUrl."],
    ])("does not match %s", (text) => {
      expect(looksLikeRefusal(text)).toBe(false);
    });
  });

  it("only inspects the opening of the message", () => {
    // A refusal phrase buried 600+ chars deep in an otherwise-real analysis is
    // not treated as a refusal — the model refuses up front, it doesn't bury it.
    const buried = `${"x".repeat(700)} I can't analyze this.`;
    expect(looksLikeRefusal(buried)).toBe(false);
  });

  it("scans analysis markers past the 600-char window", () => {
    // The decline is up front but the findings arrive well beyond `head`, so
    // the marker scan has to cover the whole message, not just the opening.
    const lateFindings = `I can't help with some of this. ${"x".repeat(700)} severity: high`;
    expect(looksLikeRefusal(lateFindings)).toBe(false);
  });

  it("sees a code fence despite apostrophe normalization", () => {
    // Normalization rewrites backticks, so the fence marker must run against
    // the raw text. Guards a silently-dead check.
    const fenced = "I can't help with all of it.\n\n```ts\nconst q = 1;\n```";
    expect(looksLikeRefusal(fenced)).toBe(false);
  });
});
