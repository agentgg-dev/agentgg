/**
 * Quoted code in a finding must exist in the source it cites.
 *
 * A detector sometimes writes a plausible excerpt that is not in the file.
 * Across 105 findings with a code block in seven geotools runs (2026-09-13), 17
 * quoted lines were invented or paraphrased: about 1 finding in 9. Run B's
 * `constructEquality` finding quoted two lines that exist nowhere in the
 * repository, and its validator rightly refused to confirm a write-up it could
 * not reproduce.
 *
 * The match rule follows that data. Exact line matching missed 65 of 505 lines,
 * and 44 of those were correct Java reflowed onto one line, so whitespace
 * (newlines included) and // comments are ignored. A block tagged with another
 * language is not source, so it is skipped rather than flagged.
 */

import type { Finding } from "@agentgg/core";
import { describe, expect, it } from "vitest";
import {
  findUnverifiedExcerpts,
  LlmFinding,
  markExcerptsUnverified,
  repairFindingExcerpts,
  replaceExcerpts,
} from "../src/detect.js";

const NL = "\n";
const F = "```";
const details = (...parts: string[]) => parts.join(NL);

const SOURCE = [
  "private String constructEquality(String[] jsonPath, Expression expected) {",
  "    int lastIndex = jsonPath.length - 1;",
  "    Object value = ((LiteralExpressionImpl) expected).getValue();",
  "    return String.format(",
  "        jsonPath[lastIndex], value);",
  "}",
].join(NL);

describe("findUnverifiedExcerpts", () => {
  it("passes a real excerpt", () => {
    const d = details(
      "The sink:",
      `${F}java`,
      "Object value = ((LiteralExpressionImpl) expected).getValue();",
      F,
    );
    expect(findUnverifiedExcerpts(d, [SOURCE], "java")).toEqual([]);
  });

  it("flags invented lines, as in Run B", () => {
    const d = details(
      `${F}java`,
      "// line ~782",
      "LiteralExpressionImpl lit = (LiteralExpressionImpl) expr;",
      "out.write(lit.getValue().toString());",
      F,
    );
    const out = findUnverifiedExcerpts(d, [SOURCE], "java");
    expect(out).toHaveLength(1);
    expect(out[0].index).toBe(0);
  });

  it("matches correct Java that the excerpt joined onto one line", () => {
    const d = details(`${F}java`, "return String.format(jsonPath[lastIndex], value);", F);
    expect(findUnverifiedExcerpts(d, [SOURCE], "java")).toEqual([]);
  });

  it("ignores a line comment", () => {
    const d = details(`${F}java`, "int lastIndex = jsonPath.length - 1; // the last element", F);
    expect(findUnverifiedExcerpts(d, [SOURCE], "java")).toEqual([]);
  });

  it("skips a block tagged with another language, such as generated SQL", () => {
    const d = details(`${F}sql`, "SELECT * FROM t WHERE x = 'injected' OR 1=1", F);
    expect(findUnverifiedExcerpts(d, [SOURCE], "java")).toEqual([]);
  });

  it("checks an untagged block", () => {
    const d = details(F, "LiteralExpressionImpl lit = (LiteralExpressionImpl) expr;", F);
    expect(findUnverifiedExcerpts(d, [SOURCE], "java")).toHaveLength(1);
  });

  it("checks a block tagged with a short alias of the file's language", () => {
    const d = details(`${F}ts`, "const invented = definitelyNotInTheFile();", F);
    expect(findUnverifiedExcerpts(d, ["const real = 1;"], "typescript")).toHaveLength(1);
  });

  it("does not count lines too short to prove anything", () => {
    const d = details(`${F}java`, "}", "return x;", "...", F);
    expect(findUnverifiedExcerpts(d, [SOURCE], "java")).toEqual([]);
  });

  it("accepts a line quoted from another file in the batch", () => {
    const helper = "String escaped = escapeJsonLiteral(raw);";
    const d = details(`${F}java`, helper, F);
    expect(findUnverifiedExcerpts(d, [SOURCE, helper], "java")).toEqual([]);
  });

  it("reports only the failing blocks, by position", () => {
    const d = details(
      `${F}java`,
      "Object value = ((LiteralExpressionImpl) expected).getValue();",
      F,
      "and",
      `${F}java`,
      "LiteralExpressionImpl lit = (LiteralExpressionImpl) expr;",
      F,
    );
    expect(findUnverifiedExcerpts(d, [SOURCE], "java").map((b) => b.index)).toEqual([1]);
  });
});

describe("replaceExcerpts", () => {
  it("replaces only the chosen block body and leaves the rest untouched", () => {
    const d = details(
      "Intro.",
      `${F}java`,
      "keep me",
      F,
      "Middle.",
      `${F}java`,
      "invented",
      F,
      "End.",
    );
    const out = replaceExcerpts(d, new Map([[1, "real line"]]));
    expect(out).toBe(
      details("Intro.", `${F}java`, "keep me", F, "Middle.", `${F}java`, "real line", F, "End."),
    );
  });
});

describe("markExcerptsUnverified", () => {
  it("appends a plain note and keeps the original text", () => {
    const d = details("Body.", `${F}java`, "invented", F);
    const out = markExcerptsUnverified(d);
    expect(out.startsWith(d)).toBe(true);
    expect(out).toMatch(/could not be found/);
    expect(out).not.toContain("—");
  });
});

describe("details schema", () => {
  it("asks for an excerpt copied verbatim from the file", () => {
    expect(LlmFinding.shape.details.description).toMatch(/verbatim/);
  });
});

/**
 * One re-quote, then stop. Only `details` may change: the id hashes slug, path,
 * title and line range, and it carries a person's triage status.
 */
describe("repairFindingExcerpts", () => {
  const REAL = "Object value = ((LiteralExpressionImpl) expected).getValue();";
  const INVENTED = "LiteralExpressionImpl lit = (LiteralExpressionImpl) expr;";
  const finding = (code: string): Finding =>
    ({
      id: "abc123abc123",
      agentSlug: "sql-injection",
      title: "SQL injection in constructEquality",
      vulnSlug: "sql-injection",
      filePath: "FilterToSqlHelper.java",
      lineRange: [790, 804],
      summary: "s",
      details: details("The sink:", `${F}java`, code, F),
      poc: "p",
      impact: "i",
      references: [],
      confidence: 0.9,
      notifications: [],
    }) as Finding;

  it("leaves a verified excerpt alone and never re-quotes it", async () => {
    let calls = 0;
    const input = finding(REAL);
    const out = await repairFindingExcerpts(input, [SOURCE], async () => {
      calls++;
      return [REAL];
    });
    expect(out.outcome).toBe("verified");
    expect(out.finding.details).toBe(input.details);
    expect(calls).toBe(0);
  });

  it("swaps in a re-quote that verifies, and changes nothing else", async () => {
    const input = finding(INVENTED);
    const out = await repairFindingExcerpts(input, [SOURCE], async () => [REAL]);
    expect(out.outcome).toBe("requoted");
    expect(out.finding.details).toContain(REAL);
    expect(out.finding.details).not.toContain(INVENTED);
    expect({ ...out.finding, details: input.details }).toEqual(input);
  });

  it("keeps the finding and marks it when the one re-quote still fails", async () => {
    let calls = 0;
    const out = await repairFindingExcerpts(finding(INVENTED), [SOURCE], async () => {
      calls++;
      return ["StillInvented thing = makeItUp(now);"];
    });
    expect(calls).toBe(1);
    expect(out.outcome).toBe("unverified");
    expect(out.finding.details).toContain(INVENTED);
    expect(out.finding.details).toMatch(/could not be found/);
  });

  it("treats a failed re-quote call as unverified instead of throwing", async () => {
    const out = await repairFindingExcerpts(finding(INVENTED), [SOURCE], async () => {
      throw new Error("provider down");
    });
    expect(out.outcome).toBe("unverified");
  });

  it("marks the finding when no re-quote is available", async () => {
    const out = await repairFindingExcerpts(finding(INVENTED), [SOURCE]);
    expect(out.outcome).toBe("unverified");
    expect(out.finding.details).toMatch(/could not be found/);
  });
});
