import { afterEach, describe, expect, it, vi } from "vitest";
import { logSkips, normalizeVulnSlug, selectWebReachable } from "../src/validation/web-reachable";

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

describe("logSkips", () => {
  afterEach(() => vi.restoreAllMocks());

  it("does not blame duplicates, which the caller already filtered out", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    logSkips([f("hardcoded-secret")]);
    const line = log.mock.calls[0]?.[0] as string;
    expect(line).toContain("not web-reachable");
    expect(line).not.toContain("duplicate");
  });

  it("says nothing when every finding was reachable", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    logSkips([]);
    expect(log).not.toHaveBeenCalled();
  });
});
