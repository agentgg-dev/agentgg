import { describe, expect, it } from "vitest";
import { selectForReproduce } from "../src/validation/reproduce";

const f = (vulnSlug: string, extra: object = {}) =>
  ({
    id: vulnSlug,
    agentSlug: "a",
    vulnSlug,
    filePath: "p",
    title: "t",
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    references: [],
    confidence: 0.5,
    notifications: [],
    ...extra,
  }) as any;

describe("selectForReproduce", () => {
  it("keeps web-reachable primaries without a dynamic result", () => {
    const list = [
      f("xss"),
      f("secret"),
      f("sqli", {
        validation: {
          verdict: "confirmed",
          reasoning: "r",
          dynamic: { verdict: "confirmed", reasoning: "d" },
        },
      }),
    ];
    expect(selectForReproduce(list).map((x) => x.vulnSlug)).toEqual(["xss"]);
  });

  it("drops duplicates (dedup marker) even when web-reachable", () => {
    const list = [f("xss", { dedup: { duplicateOf: "other", reasoning: "dupe" } })];
    expect(selectForReproduce(list)).toEqual([]);
  });

  it("keeps a web-reachable primary that has only a static verdict", () => {
    const list = [f("idor", { validation: { verdict: "confirmed", reasoning: "r" } })];
    expect(selectForReproduce(list).map((x) => x.vulnSlug)).toEqual(["idor"]);
  });

  it("skips findings validation marked false-positive", () => {
    const list = [f("xss", { validation: { verdict: "false-positive", reasoning: "r" } })];
    expect(selectForReproduce(list)).toEqual([]);
  });

  it("skips findings validation marked out-of-scope", () => {
    const list = [f("sqli", { validation: { verdict: "out-of-scope", reasoning: "r" } })];
    expect(selectForReproduce(list)).toEqual([]);
  });

  it("keeps an uncertain finding, since live evidence resolves the uncertainty", () => {
    const list = [f("idor", { validation: { verdict: "uncertain", reasoning: "r" } })];
    expect(selectForReproduce(list).map((x) => x.vulnSlug)).toEqual(["idor"]);
  });

  it("keeps a finding with no static validation at all", () => {
    expect(selectForReproduce([f("open-redirect")]).map((x) => x.vulnSlug)).toEqual([
      "open-redirect",
    ]);
  });
});
