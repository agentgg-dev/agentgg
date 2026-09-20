import { describe, expect, it } from "vitest";
import { duplicatesOfRejected, promote } from "../src/promote";

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
