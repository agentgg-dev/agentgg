import { describe, expect, it } from "vitest";
import { selectForReproduce, splitLiveReproducible } from "../src/validation/reproduce";

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
  it("keeps every primary without a live result, whatever its class", () => {
    const list = [
      f("xss"),
      f("secret"),
      f("sqli", {
        validation: { verdict: "confirmed", reasoning: "r" },
        live: { result: "reproduced", reasoning: "d", counterevidence: "" },
      }),
    ];
    expect(selectForReproduce(list).map((x) => x.vulnSlug)).toEqual(["xss", "secret"]);
  });

  it("puts a finding that names an HTTP entry point first, at an equal verdict", () => {
    const list = [
      f("secret", { poc: "The key is committed in config.yml." }),
      f("xss", { poc: "GET /search?q=<script>alert(1)</script>" }),
    ];
    expect(selectForReproduce(list).map((x) => x.vulnSlug)).toEqual(["xss", "secret"]);
  });

  it("drops duplicates (dedup marker) even when web-reachable", () => {
    const list = [f("xss", { dedup: { duplicateOf: "other", reasoning: "dupe" } })];
    expect(selectForReproduce(list)).toEqual([]);
  });

  it("keeps a web-reachable primary that has only a static verdict", () => {
    const list = [f("idor", { validation: { verdict: "confirmed", reasoning: "r" } })];
    expect(selectForReproduce(list).map((x) => x.vulnSlug)).toEqual(["idor"]);
  });

  it("keeps a lone false-positive finding, since live evidence can still resolve it", () => {
    const list = [f("xss", { validation: { verdict: "false-positive", reasoning: "r" } })];
    expect(selectForReproduce(list).map((x) => x.vulnSlug)).toEqual(["xss"]);
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

  it("keeps a false-positive finding but puts it last", () => {
    const list = [
      f("xss", { validation: { verdict: "false-positive", reasoning: "r" } }),
      f("idor", { validation: { verdict: "uncertain", reasoning: "r" } }),
      f("sqli", { validation: { verdict: "confirmed", reasoning: "r" } }),
    ];
    expect(selectForReproduce(list).map((x) => x.vulnSlug)).toEqual(["idor", "sqli", "xss"]);
  });

  it("drops out-of-scope findings", () => {
    const list = [f("sqli", { validation: { verdict: "out-of-scope", reasoning: "r" } })];
    expect(selectForReproduce(list)).toEqual([]);
  });

  it("skips a finding that already carries a live result", () => {
    const list = [f("xss", { live: { result: "refuted", reasoning: "r", counterevidence: "" } })];
    expect(selectForReproduce(list)).toEqual([]);
  });
});

describe("splitLiveReproducible", () => {
  it("holds back a finding whose agent declared its class has nothing to reproduce", () => {
    const list = [
      f("xss", { agentSlug: "xss" }),
      f("headers", { agentSlug: "missing-security-headers" }),
    ];
    const { testable, skipped } = splitLiveReproducible(
      list,
      new Set(["missing-security-headers"]),
    );
    expect(testable.map((x) => x.vulnSlug)).toEqual(["xss"]);
    expect(skipped.map((x) => x.vulnSlug)).toEqual(["headers"]);
  });

  it("tests everything when no agent opted out", () => {
    const list = [f("xss", { agentSlug: "xss" })];
    expect(splitLiveReproducible(list, new Set()).testable).toHaveLength(1);
  });
});
