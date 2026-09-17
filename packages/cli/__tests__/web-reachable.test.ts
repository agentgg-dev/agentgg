import { describe, expect, it } from "vitest";
import { normalizeVulnSlug, selectWebReachable } from "../src/validation/web-reachable";

const f = (vulnSlug: string, extra: object = {}) =>
  ({
    id: vulnSlug,
    agentSlug: "x",
    title: "t",
    vulnSlug,
    filePath: "p",
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    references: [],
    confidence: 0.5,
    notifications: [],
    ...extra,
  }) as any;

describe("web-reachable gating", () => {
  it("folds sqli into sql-injection", () => {
    expect(normalizeVulnSlug("sqli")).toBe("sql-injection");
  });
  it("selects reachable classes and skips the rest", () => {
    const { selected, skipped } = selectWebReachable([f("sqli"), f("xss"), f("hardcoded-secret")]);
    expect(selected.map((x) => x.vulnSlug).sort()).toEqual(["sqli", "xss"]);
    expect(skipped.map((x) => x.vulnSlug)).toEqual(["hardcoded-secret"]);
  });
  it("excludes duplicates", () => {
    const { selected } = selectWebReachable([
      f("xss", { dedup: { duplicateOf: "y", reasoning: "r" } }),
    ]);
    expect(selected).toHaveLength(0);
  });
});
