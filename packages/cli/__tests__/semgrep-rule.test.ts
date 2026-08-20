import { describe, expect, it } from "vitest";
import { inspectSemgrepRule, normalizeLang } from "../src/semgrep-rule.js";

const search = `rules:
  - id: ok-search
    languages: [ts, javascript]
    message: m
    severity: WARNING
    pattern: eval($X)
`;

const taint = `rules:
  - id: ok-taint
    mode: taint
    languages: [python]
    message: m
    severity: WARNING
    pattern-sources:
      - pattern: $A
    pattern-sinks:
      - pattern: eval(...)
`;

describe("inspectSemgrepRule", () => {
  it("accepts a default-mode rule and collects its languages", () => {
    const out = inspectSemgrepRule(search);
    expect(out.unsupported).toBeNull();
    expect(out.langs && [...out.langs].sort()).toEqual(["js", "ts"]);
    expect(out.rules).toHaveLength(1);
  });

  it("accepts taint mode", () => {
    expect(inspectSemgrepRule(taint).unsupported).toBeNull();
  });

  // The whole reason this module exists: the engine runs a join rule to
  // completion, scans nothing, and reports neither an error nor a skip.
  it("refuses join mode, which the bundled engine silently no-ops", () => {
    const out = inspectSemgrepRule(`rules:
  - id: j
    mode: join
    join:
      refs:
        - rule: a.yaml
          as: a
      on:
        - 'a.$X == a.$X'
    message: m
    severity: HIGH
`);
    expect(out.unsupported).toContain("join");
  });

  it("refuses supply-chain rules, which fail the same silent way", () => {
    const out = inspectSemgrepRule(`rules:
  - id: sca
    languages: [js]
    message: m
    severity: WARNING
    pattern: eval($X)
    r2c-internal-project-depends-on:
      namespace: npm
      package: lodash
      version: "< 4.17.21"
`);
    expect(out.unsupported).toContain("r2c-internal-project-depends-on");
  });

  it.each(["step", "secrets"])("refuses mode '%s'", (mode) => {
    const out = inspectSemgrepRule(`rules:
  - id: x
    mode: ${mode}
    languages: [js]
    message: m
    severity: WARNING
    pattern: eval($X)
`);
    expect(out.unsupported).toContain(mode);
  });

  // A rule's own `paths:` filters the file list agentgg selected. Reporting
  // it is the point: silently narrower coverage is what `degraded` exists for.
  it("reports rules that carry their own paths: filter", () => {
    const out = inspectSemgrepRule(`rules:
  - id: scoped
    languages: [js]
    message: m
    severity: WARNING
    pattern: eval($X)
    paths:
      exclude:
        - "*.test.js"
`);
    expect(out.unsupported).toBeNull();
    expect(out.pathScoped).toEqual(["scoped"]);
  });

  it("returns no rules when the file does not parse", () => {
    expect(inspectSemgrepRule("rules: [oops").rules).toBeNull();
  });

  it("returns no rules when the document has no rules array", () => {
    expect(inspectSemgrepRule("something: else").rules).toBeNull();
  });

  it("reports unknown languages when a rule declares none", () => {
    const out = inspectSemgrepRule(`rules:
  - id: x
    message: m
    severity: WARNING
    pattern: eval($X)
`);
    expect(out.langs).toBeNull();
  });
});

describe("normalizeLang", () => {
  it.each([
    ["typescript", "ts"],
    ["JavaScript", "js"],
    ["py", "python"],
    ["c#", "csharp"],
    ["go", "go"],
  ])("maps %s to %s", (input, expected) => {
    expect(normalizeLang(input)).toBe(expected);
  });
});
