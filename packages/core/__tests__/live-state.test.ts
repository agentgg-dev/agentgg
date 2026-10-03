// The viewer shows these strings verbatim, so the rules that pick them are
// pinned here: "we could not test it" must never read as "it is not real".
import { describe, expect, it } from "vitest";
import { liveState, TIMEOUT_PREFIX, verdictConflict, verdictStory } from "../src/live.js";
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

describe("liveState", () => {
  it("calls any untested finding not-run, whatever its class", () => {
    expect(liveState(finding({ vulnSlug: "missing-security-headers" })).kind).toBe("not-run");
    expect(liveState(finding()).kind).toBe("not-run");
  });

  // Each skip below is deliberate. Saying "a browser cannot drive this" about
  // a duplicate SQL injection would be plainly wrong.
  it("names a duplicate as the reason, not the vulnerability class", () => {
    const dup = finding({ dedup: { duplicateOf: "abc999", reasoning: "same" } } as never);
    expect(liveState(dup).kind).toBe("duplicate");
    expect(liveState(dup).detail).toBe(
      "This finding duplicates finding abc999. Live tests run only on the original.",
    );
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
    expect(liveState(f).detail).toBe(
      "The review marked this finding out of scope, so it was not tested live.",
    );
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
    expect(verdictStory(f)).toBe(
      "Static review marked this finding as uncertain. The live test reproduced the issue.",
    );
  });

  it("says the static verdict stands when the run itself broke", () => {
    const f = finding({ validation: validation("confirmed"), live: live({ result: "error" }) });
    expect(verdictStory(f)).toBe(
      "Static review confirmed this finding. The live test did not complete because of an error. This does not indicate whether the issue exists. The static review verdict still applies.",
    );
  });

  it("flags the disagreement when static rejected what the live test reproduced", () => {
    const f = finding({ validation: validation("false-positive"), live: live() });
    expect(verdictStory(f)).toContain("Review both results.");
  });

  it("calls a confirmed finding unresolved when the live test could not repeat it", () => {
    const f = finding({ validation: validation("confirmed"), live: live({ result: "refuted" }) });
    expect(verdictStory(f)).toContain("unresolved");
  });

  it("stops at out-of-scope without blaming a scope file that does not exist", () => {
    const f = finding({ validation: validation("out-of-scope"), live: live() });
    expect(verdictStory(f)).toBe(
      "The review marked this finding out of scope, so it was not reviewed further.",
    );
  });

  it("covers a live-only finding with no static verdict", () => {
    expect(verdictStory(finding({ live: live() }))).toBe(
      "Static review did not reach a verdict. The live test reproduced the issue.",
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

describe("a class with nothing to reproduce", () => {
  it("is kept apart from a run that tried and failed", () => {
    const f = finding({ live: live({ result: "not-reproducible" }) });
    expect(liveState(f).kind).toBe("not-reproducible");
    expect(liveState(f).tellsAboutCode).toBe(false);
  });

  it("never claims a browser tried it", () => {
    const f = finding({ live: live({ result: "not-reproducible" }) });
    expect(liveState(f).detail).not.toMatch(/could not|failed|ran out/i);
  });
});
