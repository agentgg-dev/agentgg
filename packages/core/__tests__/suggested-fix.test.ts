import { describe, expect, it } from "vitest";
import { Finding, suggestedFixOf } from "../src/index.js";

const FIX = "Use a parameterized query.";

const f = (extra: object = {}) =>
  Finding.parse({
    id: "f1",
    agentSlug: "a",
    title: "t",
    vulnSlug: "sql-injection",
    filePath: "p.ts",
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    suggestedFix: FIX,
    ...extra,
  });

const live = (result: string) => ({ result, reasoning: "r" });

describe("suggestedFixOf", () => {
  it("returns the fix of a finding validation confirmed", () => {
    expect(suggestedFixOf(f({ validation: { verdict: "confirmed", reasoning: "r" } }))).toBe(FIX);
  });

  it("returns the fix when a live run reproduced an uncertain finding", () => {
    const finding = f({
      validation: { verdict: "uncertain", reasoning: "r" },
      live: live("reproduced"),
    });
    expect(suggestedFixOf(finding)).toBe(FIX);
  });

  it.each([
    "uncertain",
    "false-positive",
    "out-of-scope",
  ])("hides the fix of a %s finding", (verdict) => {
    expect(suggestedFixOf(f({ validation: { verdict, reasoning: "r" } }))).toBeUndefined();
  });

  it("hides the fix when a live run refuted a confirmed finding", () => {
    const finding = f({
      validation: { verdict: "confirmed", reasoning: "r" },
      live: live("refuted"),
    });
    expect(suggestedFixOf(finding)).toBeUndefined();
  });

  it("hides the fix of a finding that was never validated", () => {
    expect(suggestedFixOf(f())).toBeUndefined();
  });

  it("returns nothing for a confirmed finding with no fix", () => {
    const finding = f({
      suggestedFix: undefined,
      validation: { verdict: "confirmed", reasoning: "r" },
    });
    expect(suggestedFixOf(finding)).toBeUndefined();
  });
});
