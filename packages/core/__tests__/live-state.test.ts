// The viewer shows these strings verbatim, so the rules that pick them are
// pinned here: "we could not test it" must never read as "it is not real".
import { describe, expect, it } from "vitest";
import {
  isWebReachable,
  liveState,
  TIMEOUT_PREFIX,
  verdictConflict,
  verdictStory,
} from "../src/live.js";
import type { Finding, LiveValidation, Validation } from "../src/types.js";

const finding = (over: Partial<Finding> = {}): Finding =>
  ({
    id: "abc123",
    agentSlug: "js-sql-raw",
    title: "SQL injection in the login form",
    vulnSlug: "sql-injection",
    filePath: "app/login.js",
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    confidence: 0.9,
    references: [],
    ...over,
  }) as Finding;

const live = (over: Partial<LiveValidation> = {}): LiveValidation =>
  ({ result: "reproduced", reasoning: "r", counterevidence: "", ...over }) as LiveValidation;

const validation = (verdict: Validation["verdict"]): Validation =>
  ({ verdict, reasoning: "r" }) as Validation;

describe("isWebReachable", () => {
  it("accepts a known class by slug", () => {
    expect(isWebReachable(finding({ vulnSlug: "sqli" }))).toBe(true);
  });

  it("accepts an unknown slug when a CWE reference names a web class", () => {
    expect(
      isWebReachable(finding({ vulnSlug: "weird-thing", references: ["CWE-89: SQL Injection"] })),
    ).toBe(true);
  });

  it("rejects a class a browser cannot drive", () => {
    expect(isWebReachable(finding({ vulnSlug: "missing-security-headers" }))).toBe(false);
  });

  it("rejects a duplicate, which the live pass never tests", () => {
    const dup = finding({ dedup: { duplicateOf: "other", reasoning: "same root cause" } } as never);
    expect(isWebReachable(dup)).toBe(false);
  });
});

describe("liveState", () => {
  it("separates a class that cannot be tested from one that was not tested", () => {
    expect(liveState(finding({ vulnSlug: "missing-security-headers" })).kind).toBe("not-reachable");
    expect(liveState(finding()).kind).toBe("not-run");
  });

  // Each skip below is deliberate. Saying "a browser cannot drive this" about
  // a duplicate SQL injection would be plainly wrong.
  it("names a duplicate as the reason, not the vulnerability class", () => {
    const dup = finding({ dedup: { duplicateOf: "abc999", reasoning: "same" } } as never);
    expect(liveState(dup).kind).toBe("duplicate");
    expect(liveState(dup).detail).toBe("This repeats finding abc999. Only that one is tested.");
  });

  // The primary may be untested too, so the duplicate must not promise proof.
  it("does not claim the primary holds proof", () => {
    const dup = finding({ dedup: { duplicateOf: "abc999", reasoning: "same" } } as never);
    expect(liveState(dup).detail).not.toMatch(/proof/i);
  });

  it("blames the scope file only when a scope rule actually matched", () => {
    const withRule = finding({
      validation: { verdict: "out-of-scope", reasoning: "r", scopeRef: "scope.yml#self-xss" },
    } as never);
    expect(liveState(withRule).detail).toContain("scope.yml#self-xss");
    expect(verdictStory(withRule)).toContain("scope.yml#self-xss");
  });

  it("credits the reviewer when out-of-scope came from its own judgement", () => {
    const f = finding({ validation: validation("out-of-scope") });
    expect(liveState(f).kind).toBe("out-of-scope");
    expect(liveState(f).detail).toBe("The review judged this out of scope, so nothing tested it.");
    expect(liveState(f).detail).not.toMatch(/scope file/i);
    expect(verdictStory(f)).not.toMatch(/scope file/i);
  });

  it("never claims a skipped finding says something about the code", () => {
    for (const f of [
      finding({ dedup: { duplicateOf: "o", reasoning: "r" } } as never),
      finding({ validation: validation("out-of-scope") }),
      finding({ vulnSlug: "missing-security-headers" }),
      finding(),
    ]) {
      expect(liveState(f).tellsAboutCode).toBe(false);
    }
  });

  it("reads a timeout out of the inconclusive reasoning", () => {
    const f = finding({
      live: live({ result: "inconclusive", reasoning: `${TIMEOUT_PREFIX} 600s` }),
    });
    expect(liveState(f).kind).toBe("timed-out");
  });

  it("keeps a plain inconclusive apart from a timeout", () => {
    const f = finding({ live: live({ result: "inconclusive", reasoning: "no proof found" }) });
    expect(liveState(f).kind).toBe("inconclusive");
  });

  it("puts a refusal ahead of the result it carries", () => {
    const f = finding({ live: live({ result: "inconclusive", refused: true }) });
    expect(liveState(f).kind).toBe("refused");
  });

  it("marks only reproduced and refuted as statements about the code", () => {
    const kinds = ["reproduced", "refuted"] as const;
    for (const result of kinds) {
      expect(liveState(finding({ live: live({ result }) })).tellsAboutCode).toBe(true);
    }
    for (const result of ["inconclusive", "error"] as const) {
      expect(liveState(finding({ live: live({ result }) })).tellsAboutCode).toBe(false);
    }
  });
});

describe("verdictStory", () => {
  it("explains the contradiction a reader sees on an uncertain-plus-reproduced finding", () => {
    const f = finding({ validation: validation("uncertain"), live: live() });
    expect(verdictStory(f)).toBe("Static review said uncertain. The live test reproduced it.");
  });

  it("says the static verdict stands when the run itself broke", () => {
    const f = finding({ validation: validation("confirmed"), live: live({ result: "error" }) });
    expect(verdictStory(f)).toContain("The static verdict stands.");
    expect(verdictStory(f)).toContain("says nothing about the code");
  });

  it("flags the disagreement when static rejected what the live test reproduced", () => {
    const f = finding({ validation: validation("false-positive"), live: live() });
    expect(verdictStory(f)).toContain("Read both.");
  });

  it("calls a confirmed finding unsettled when the live test could not repeat it", () => {
    const f = finding({ validation: validation("confirmed"), live: live({ result: "refuted" }) });
    expect(verdictStory(f)).toContain("unsettled");
  });

  it("stops at out-of-scope without blaming a scope file that does not exist", () => {
    const f = finding({ validation: validation("out-of-scope"), live: live() });
    expect(verdictStory(f)).toBe("The review judged this out of scope and stopped there.");
  });

  it("covers a live-only finding with no static verdict", () => {
    expect(verdictStory(finding({ live: live() }))).toBe(
      "Static review reached no verdict. The live test reproduced it.",
    );
  });

  it("returns nothing when nothing has judged the finding", () => {
    expect(verdictStory(finding())).toBeUndefined();
  });
});

describe("verdictConflict", () => {
  it("is true only when the live test moved the verdict off the static one", () => {
    const moved = finding({
      validation: validation("confirmed"),
      live: live({ result: "refuted" }),
    });
    const agreed = finding({ validation: validation("confirmed"), live: live() });
    expect(verdictConflict(moved)).toBe(true);
    expect(verdictConflict(agreed)).toBe(false);
  });

  it("is false when nothing reviewed the finding statically", () => {
    expect(verdictConflict(finding({ live: live() }))).toBe(false);
  });

  it("is false when a broken run leaves the static verdict alone", () => {
    const f = finding({ validation: validation("confirmed"), live: live({ result: "error" }) });
    expect(verdictConflict(f)).toBe(false);
  });
});
