import { describe, expect, it } from "vitest";
import { applyGroupVerdict, duplicatesOfRejected, membersOf, promote } from "../src/promote";

const f = (id: string, extra: object = {}) =>
  ({
    id,
    agentSlug: "a",
    vulnSlug: "xss",
    filePath: "p",
    confidence: 0.5,
    references: [],
    ...extra,
  }) as any;

describe("promotion", () => {
  it("returns the duplicates of a rejected primary", () => {
    const list = [
      f("p1", { validation: { verdict: "false-positive", reasoning: "r" } }),
      f("d1", { dedup: { duplicateOf: "p1", reasoning: "same" } }),
      f("p2", { validation: { verdict: "confirmed", reasoning: "r" } }),
      f("d2", { dedup: { duplicateOf: "p2", reasoning: "same" } }),
    ];
    expect(duplicatesOfRejected(list).map((x) => x.id)).toEqual(["d1"]);
  });

  it("promotes the first surviving duplicate and demotes the rejected primary", () => {
    const list = [
      f("p1", { validation: { verdict: "false-positive", reasoning: "r" } }),
      f("d1", {
        dedup: { duplicateOf: "p1", reasoning: "heir-vs-p1" },
        validation: { verdict: "confirmed", reasoning: "r" },
      }),
      f("d2", { dedup: { duplicateOf: "p1", reasoning: "d2-vs-p1" } }),
    ];
    const changed = promote(list, () => true);
    expect(list[1].dedup).toBeUndefined();
    expect(list[0].dedup?.duplicateOf).toBe("d1");
    expect(list[0].dedup?.reasoning).toBe("heir-vs-p1");
    expect(list[2].dedup?.duplicateOf).toBe("d1");
    expect(list[2].dedup?.reasoning).toBe("d2-vs-p1");
    expect(list[0].validation?.verdict).toBe("false-positive");
    expect(changed.map((x) => x.id).sort()).toEqual(["d1", "d2", "p1"]);
  });

  it("keeps the cluster as it is when every duplicate is rejected too", () => {
    const list = [
      f("p1", { validation: { verdict: "false-positive", reasoning: "r" } }),
      f("d1", {
        dedup: { duplicateOf: "p1", reasoning: "same" },
        validation: { verdict: "false-positive", reasoning: "r" },
      }),
    ];
    expect(promote(list, () => true)).toEqual([]);
    expect(list[1].dedup?.duplicateOf).toBe("p1");
  });

  it("does not rewrite a marker the run may not write", () => {
    const list = [
      f("p1", { validation: { verdict: "false-positive", reasoning: "r" } }),
      f("d1", {
        dedup: { duplicateOf: "p1", reasoning: "same" },
        validation: { verdict: "confirmed", reasoning: "r" },
      }),
    ];
    expect(promote(list, (x) => x.id === "never")).toEqual([]);
  });

  it("leaves a marker chain alone instead of promoting into it", () => {
    // d1 → p1 → n1: an older run marked d1 under p1, a later one marked p1
    // under n1. p1 is not a primary any more, so its group is not a cluster.
    const list = [
      f("n1", { validation: { verdict: "confirmed", reasoning: "r" } }),
      f("p1", {
        dedup: { duplicateOf: "n1", reasoning: "same" },
        validation: { verdict: "false-positive", reasoning: "r" },
      }),
      f("d1", {
        dedup: { duplicateOf: "p1", reasoning: "same" },
        validation: { verdict: "confirmed", reasoning: "r" },
      }),
    ];
    expect(duplicatesOfRejected(list)).toEqual([]);
    expect(promote(list, () => true)).toEqual([]);
    expect(list[2].dedup?.duplicateOf).toBe("p1");
  });
});

describe("applyGroupVerdict", () => {
  const group = () => [
    f("p1"),
    f("d1", { dedup: { duplicateOf: "p1", reasoning: "d1-vs-p1" } }),
    f("d2", { dedup: { duplicateOf: "p1", reasoning: "d2-vs-p1" } }),
  ];
  const confirmed = { verdict: "confirmed" as const, reasoning: "r", confirmedImpact: "ci" };
  // The primary's own claim failed; a member's claim holds.
  const failed = { ...confirmed, primaryClaimHolds: false };

  it("groups duplicates under their primary", () => {
    expect((membersOf(group()).get("p1") ?? []).map((x) => x.id)).toEqual(["d1", "d2"]);
  });

  it("orders a group's duplicates the same whatever order they were loaded in", () => {
    const [p1, d1, d2] = group();
    const ids = (list: ReturnType<typeof group>) =>
      (membersOf(list).get("p1") ?? []).map((x) => x.id);
    expect(ids([d2, p1, d1])).toEqual(["d1", "d2"]);
    expect(ids([p1, d1, d2])).toEqual(["d1", "d2"]);
  });

  it("puts the verdict on the primary when leadId is absent", () => {
    const list = group();
    const changed = applyGroupVerdict(list, list[0], confirmed, () => true);
    expect(list[0].validation).toEqual({
      verdict: "confirmed",
      reasoning: "r",
      confirmedImpact: "ci",
    });
    expect(changed.map((x) => x.id)).toEqual(["p1"]);
  });

  it("swaps to the lead when the primary's claim fails, and clears the old primary's results", () => {
    const list = group();
    list[0].validation = { verdict: "uncertain", reasoning: "stale" };
    list[0].cvss = { baseScore: 9.8 };
    list[0].severity = "CRITICAL";
    list[0].live = { result: "inconclusive", reasoning: "old" };
    const changed = applyGroupVerdict(list, list[0], { ...failed, leadId: "d1" }, () => true);
    expect(list[1].dedup).toBeUndefined();
    expect(list[1].validation?.verdict).toBe("confirmed");
    expect(list[0].dedup).toEqual({ duplicateOf: "d1", reasoning: "d1-vs-p1" });
    expect(list[0].validation).toBeUndefined();
    expect(list[0].cvss).toBeUndefined();
    expect(list[0].severity).toBeUndefined();
    expect(list[0].live).toBeUndefined();
    expect(list[2].dedup?.duplicateOf).toBe("d1");
    expect(list[2].dedup?.reasoning).toBe("d2-vs-p1");
    expect(new Set(changed.map((x) => x.id))).toEqual(new Set(["p1", "d1", "d2"]));
  });

  it("keeps the primary when its claim holds, even if a member's worse claim is confirmed", () => {
    const list = group();
    applyGroupVerdict(
      list,
      list[0],
      { ...confirmed, leadId: "d1", primaryClaimHolds: true },
      () => true,
    );
    expect(list[0].validation?.confirmedImpact).toBe("ci");
    expect(list[0].dedup).toBeUndefined();
    expect(list[1].dedup?.duplicateOf).toBe("p1");
  });

  it("does not swap when primaryClaimHolds is missing", () => {
    const list = group();
    applyGroupVerdict(list, list[0], { ...confirmed, leadId: "d1" }, () => true);
    expect(list[0].dedup).toBeUndefined();
    expect(list[1].dedup?.duplicateOf).toBe("p1");
  });

  it("ignores a leadId that is not in the group", () => {
    const list = group();
    applyGroupVerdict(list, list[0], { ...failed, leadId: "nope" }, () => true);
    expect(list[0].validation?.verdict).toBe("confirmed");
    expect(list[0].dedup).toBeUndefined();
  });

  it("ignores a leadId equal to the primary", () => {
    const list = group();
    applyGroupVerdict(list, list[0], { ...failed, leadId: "p1" }, () => true);
    expect(list[0].dedup).toBeUndefined();
    expect(list[1].dedup?.duplicateOf).toBe("p1");
  });

  it("does not swap when the run may not write a member", () => {
    const list = group();
    applyGroupVerdict(list, list[0], { ...failed, leadId: "d1" }, (x) => x.id !== "d2");
    expect(list[0].validation?.verdict).toBe("confirmed");
    expect(list[1].dedup?.duplicateOf).toBe("p1");
  });

  it("clears the demoted primary's results in promote() too", () => {
    const list = [
      f("p1", {
        validation: { verdict: "false-positive", reasoning: "r" },
        cvss: { baseScore: 9.8 },
        severity: "CRITICAL",
      }),
      f("d1", {
        dedup: { duplicateOf: "p1", reasoning: "same" },
        validation: { verdict: "confirmed", reasoning: "r" },
      }),
    ];
    promote(list, () => true);
    expect(list[0].dedup?.duplicateOf).toBe("d1");
    expect(list[0].cvss).toBeUndefined();
    expect(list[0].severity).toBeUndefined();
  });

  it.each([
    "uncertain",
    "false-positive",
    "out-of-scope",
  ] as const)("does not swap on a %s verdict, even with a leadId", (verdict) => {
    const list = group();
    applyGroupVerdict(
      list,
      list[0],
      { verdict, reasoning: "r", leadId: "d1", primaryClaimHolds: false },
      () => true,
    );
    expect(list[0].validation?.verdict).toBe(verdict);
    expect(list[0].dedup).toBeUndefined();
    expect(list[1].dedup?.duplicateOf).toBe("p1");
  });

  it("limits duplicatesOfRejected to the ids it is given", () => {
    const list = [
      f("p1", { validation: { verdict: "false-positive", reasoning: "r" } }),
      f("d1", { dedup: { duplicateOf: "p1", reasoning: "same" } }),
      f("d2", { dedup: { duplicateOf: "p1", reasoning: "same" } }),
    ];
    expect(duplicatesOfRejected(list, new Set(["d2"])).map((x) => x.id)).toEqual(["d2"]);
  });

  it("keeps the refused flag", () => {
    const list = group();
    applyGroupVerdict(
      list,
      list[0],
      { verdict: "uncertain", reasoning: "r", refused: true },
      () => true,
    );
    expect(list[0].validation).toEqual({ verdict: "uncertain", reasoning: "r", refused: true });
  });
});
