import type { Finding } from "@agentgg/core";
import { describe, expect, it } from "vitest";
import { buildDedupePrompt, resolveDedup } from "../src/deduper.js";

function makeFinding(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    agentSlug: "sql-injection",
    title: `Finding ${id}`,
    vulnSlug: "sql-injection",
    filePath: "src/db.ts",
    lineRange: [10, 12],
    summary: "SQL built via string concatenation.",
    details: "details",
    poc: "poc",
    impact: "impact",
    references: [],
    confidence: 0.8,
    notifications: [],
    ...overrides,
  };
}

describe("resolveDedup", () => {
  it("returns the duplicates of a well-formed cluster, keyed to the primary", () => {
    const findings = [makeFinding("a"), makeFinding("b"), makeFinding("c")];
    const out = resolveDedup(findings, [
      { primaryId: "a", duplicateIds: ["b", "c"], reasoning: "same sink" },
    ]);
    expect(out).toEqual([
      { id: "b", duplicateOf: "a", reasoning: "same sink" },
      { id: "c", duplicateOf: "a", reasoning: "same sink" },
    ]);
  });

  it("returns nothing when there are no clusters", () => {
    const findings = [makeFinding("a"), makeFinding("b")];
    expect(resolveDedup(findings, [])).toEqual([]);
  });

  it("drops unknown primary and unknown duplicate ids", () => {
    const findings = [makeFinding("a"), makeFinding("b")];
    expect(
      resolveDedup(findings, [{ primaryId: "ghost", duplicateIds: ["b"], reasoning: "x" }]),
    ).toEqual([]);
    expect(
      resolveDedup(findings, [{ primaryId: "a", duplicateIds: ["ghost"], reasoning: "x" }]),
    ).toEqual([]);
  });

  it("ignores a self-referential duplicate id", () => {
    const findings = [makeFinding("a"), makeFinding("b")];
    const out = resolveDedup(findings, [
      { primaryId: "a", duplicateIds: ["a", "b"], reasoning: "x" },
    ]);
    expect(out).toEqual([{ id: "b", duplicateOf: "a", reasoning: "x" }]);
  });

  it("rejects a cluster whose primary is itself a duplicate elsewhere (single-primary invariant)", () => {
    const findings = [makeFinding("a"), makeFinding("b"), makeFinding("c")];
    // b is a duplicate of a, but also claims to be the primary of c — contradictory.
    const out = resolveDedup(findings, [
      { primaryId: "a", duplicateIds: ["b"], reasoning: "ab" },
      { primaryId: "b", duplicateIds: ["c"], reasoning: "bc" },
    ]);
    // a→b stands; the b→c cluster is dropped because b can't be both.
    expect(out).toEqual([{ id: "b", duplicateOf: "a", reasoning: "ab" }]);
  });

  it("assigns a duplicate to only one primary (first cluster wins)", () => {
    const findings = [makeFinding("a"), makeFinding("b"), makeFinding("c")];
    const out = resolveDedup(findings, [
      { primaryId: "a", duplicateIds: ["c"], reasoning: "ac" },
      { primaryId: "b", duplicateIds: ["c"], reasoning: "bc" },
    ]);
    expect(out).toEqual([{ id: "c", duplicateOf: "a", reasoning: "ac" }]);
  });

  it("merges duplicates from repeated clusters that share a primary", () => {
    const findings = [makeFinding("a"), makeFinding("b"), makeFinding("c")];
    const out = resolveDedup(findings, [
      { primaryId: "a", duplicateIds: ["b"], reasoning: "ab" },
      { primaryId: "a", duplicateIds: ["c"], reasoning: "ac" },
    ]);
    expect(out).toEqual([
      { id: "b", duplicateOf: "a", reasoning: "ab" },
      { id: "c", duplicateOf: "a", reasoning: "ac" },
    ]);
  });
});

describe("buildDedupePrompt", () => {
  it("lists every finding id and embeds the source when provided", () => {
    const prompt = buildDedupePrompt({
      filePath: "src/db.ts",
      findings: [makeFinding("aaa"), makeFinding("bbb")],
      fileContent: "const q = 'SELECT ' + a + b;",
    });
    expect(prompt).toContain("Finding id: aaa");
    expect(prompt).toContain("Finding id: bbb");
    expect(prompt).toContain("src/db.ts");
    expect(prompt).toContain("const q = 'SELECT ' + a + b;");
  });

  it("omits the source block when no content is given", () => {
    const prompt = buildDedupePrompt({
      filePath: "src/db.ts",
      findings: [makeFinding("aaa"), makeFinding("bbb")],
    });
    expect(prompt).not.toContain("## The source file");
  });
});
