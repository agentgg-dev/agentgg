import { describe, expect, it } from "vitest";
import { effectiveVerdict } from "../src/persistence";

const base = {
  id: "x",
  agentSlug: "a",
  title: "t",
  vulnSlug: "xss",
  filePath: "p",
  summary: "s",
  details: "d",
  poc: "p",
  impact: "i",
  references: [],
  confidence: 0.5,
  notifications: [],
} as any;

const withBoth = (verdict: string, result?: string) => ({
  ...base,
  ...(verdict === "none" ? {} : { validation: { verdict, reasoning: "r" } }),
  ...(result ? { live: { result, reasoning: "l", counterevidence: "c" } } : {}),
});

describe("effectiveVerdict", () => {
  it.each([
    ["confirmed", "reproduced", "confirmed"],
    ["confirmed", "inconclusive", "confirmed"],
    ["confirmed", undefined, "confirmed"],
    ["confirmed", "refuted", "uncertain"],
    ["uncertain", "reproduced", "confirmed"],
    ["uncertain", "refuted", "uncertain"],
    ["uncertain", "inconclusive", "uncertain"],
    ["false-positive", "reproduced", "uncertain"],
    ["false-positive", "refuted", "false-positive"],
    ["false-positive", undefined, "false-positive"],
    ["out-of-scope", undefined, "out-of-scope"],
    ["none", "reproduced", "confirmed"],
    ["none", "refuted", "uncertain"],
    ["none", "inconclusive", undefined],
    ["none", undefined, undefined],
  ])("static %s + live %s = %s", (verdict, result, expected) => {
    expect(effectiveVerdict(withBoth(verdict, result))).toBe(expected);
  });
});
