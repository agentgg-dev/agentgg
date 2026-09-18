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

describe("web-reachable gating by CWE", () => {
  // The model writes vulnSlug as free text, so the same class arrives under
  // many spellings. The CWE is a controlled vocabulary that does not drift.
  it("keeps an IDOR whose slug the alias map has never seen", () => {
    const idor = f("idor-missing-authorization", { references: ["CWE-639", "CWE-862"] });
    expect(selectWebReachable([idor]).selected).toEqual([idor]);
  });

  it("reads the CWE out of a longer reference string", () => {
    const sqli = f("database-query-concatenation", { references: ["CWE-89: SQL Injection"] });
    expect(selectWebReachable([sqli]).selected).toEqual([sqli]);
  });

  it("still skips a finding whose CWE is not a web-reachable class", () => {
    const headers = f("missing-security-headers", { references: ["CWE-693", "CWE-1021"] });
    expect(selectWebReachable([headers]).skipped).toEqual([headers]);
  });

  it("falls back to the slug when the model gave no CWE", () => {
    const xss = f("reflected-xss", { references: [] });
    expect(selectWebReachable([xss]).selected).toEqual([xss]);
  });

  it("skips a finding with neither a known slug nor a web CWE", () => {
    const secret = f("hardcoded-api-key", { references: ["CWE-798"] });
    expect(selectWebReachable([secret]).skipped).toEqual([secret]);
  });

  it("does not mistake CWE-890 for CWE-89", () => {
    const other = f("something-else", { references: ["CWE-890"] });
    expect(selectWebReachable([other]).skipped).toEqual([other]);
  });
});
