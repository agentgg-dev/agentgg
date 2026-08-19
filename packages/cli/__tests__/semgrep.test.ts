import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  AgentPreFilterPattern,
  getSemgrepCorePath,
  isRegexPreFilter,
  isSemgrepPreFilter,
} from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluatePreFilter } from "../src/pre-filter.js";
import {
  ensureSemgrepCore,
  getSemgrepRulesDir,
  isSemgrepSuppressed,
  resetSemgrepResolution,
  resolveSemgrepCore,
  resolveSemgrepRule,
  runSemgrepPreFilter,
  semgrepLangFor,
  semgrepRuleLanguages,
  toSemgrepHit,
} from "../src/semgrep.js";
import { SEMGREP_VERSION } from "../src/semgrep-install.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentgg-semgrep-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("AgentPreFilterPattern union", () => {
  it("accepts the regex form", () => {
    expect(AgentPreFilterPattern.parse({ regex: "foo", label: "x" })).toEqual({
      regex: "foo",
      label: "x",
    });
  });

  it("accepts the semgrepRule form", () => {
    expect(AgentPreFilterPattern.parse({ semgrepRule: "http-endpoints" })).toEqual({
      semgrepRule: "http-endpoints",
    });
  });

  it("accepts a nested rule name", () => {
    expect(AgentPreFilterPattern.parse({ semgrepRule: "auth/idor-shape" }).semgrepRule).toBe(
      "auth/idor-shape",
    );
  });

  it.each([
    "../secrets",
    "a/../b",
    "Http-Endpoints",
    "/abs/path",
    "rule.yml",
    "-leading",
  ])("rejects unsafe rule name %s", (name) => {
    expect(() => AgentPreFilterPattern.parse({ semgrepRule: name })).toThrow();
  });

  it("accepts a form this build does not know, so a newer catalog degrades", () => {
    // The point of the third union member: an agent file written against a
    // future CLI must not kill the whole agent on an older install.
    const parsed = AgentPreFilterPattern.parse({ astQuery: "foo(...)", label: "future form" });
    expect(isRegexPreFilter(parsed)).toBe(false);
    expect(isSemgrepPreFilter(parsed)).toBe(false);
  });

  it("still rejects a malformed known form rather than treating it as unknown", () => {
    // A bad semgrepRule is an authoring error, not a future form — it must
    // fail loudly instead of silently becoming a no-op.
    expect(() => AgentPreFilterPattern.parse({ semgrepRule: "Bad Name" })).toThrow();
    expect(() => AgentPreFilterPattern.parse({ regex: 42 })).toThrow();
  });
});

describe("evaluatePreFilter with an unknown form", () => {
  it("ignores it instead of mis-reading it as a regex", () => {
    const preFilter = AgentPreFilterPattern.array().parse([
      { astQuery: "foo(...)" },
      { regex: "needle" },
    ]);
    const hits = evaluatePreFilter("a needle here\nnothing\n", preFilter);
    expect(hits).toHaveLength(1);
    expect(hits[0].line).toBe(1);
  });
});

describe("resolveSemgrepRule", () => {
  it("resolves a name to a .yml under the rules dir", () => {
    writeFileSync(join(dir, "http-endpoints.yml"), "rules: []");
    expect(resolveSemgrepRule([dir], "http-endpoints")).toBe(join(dir, "http-endpoints.yml"));
  });

  it("returns null for a missing rule", () => {
    expect(resolveSemgrepRule([dir], "nope")).toBeNull();
  });

  it("resolves a .yaml rule too — the installer accepts both extensions", () => {
    writeFileSync(join(dir, "sql.yaml"), "rules: []");
    expect(resolveSemgrepRule([dir], "sql")).toBe(join(dir, "sql.yaml"));
  });

  it("prefers .yml when both exist, so resolution is deterministic", () => {
    writeFileSync(join(dir, "dup.yml"), "rules: []");
    writeFileSync(join(dir, "dup.yaml"), "rules: []");
    expect(resolveSemgrepRule([dir], "dup")).toBe(join(dir, "dup.yml"));
  });

  it("cannot reach the Semgrep registry — a pack id is just a missing file", () => {
    // The schema already rejects most of these, but resolution is the
    // second guarantee: the value is always joined to the local dir.
    expect(resolveSemgrepRule([dir], "p/typescript")).toBeNull();
  });

  it("searches the dirs in order, so a local rule shadows the catalog's", () => {
    const local = join(dir, "local");
    const catalog = join(dir, "catalog");
    mkdirSync(local);
    mkdirSync(catalog);
    writeFileSync(join(local, "shared.yml"), "rules: []");
    writeFileSync(join(catalog, "shared.yml"), "rules: []");
    expect(resolveSemgrepRule([local, catalog], "shared")).toBe(join(local, "shared.yml"));
  });

  it("falls through to a later dir when an earlier one does not hold the rule", () => {
    const local = join(dir, "local");
    const catalog = join(dir, "catalog");
    mkdirSync(local);
    mkdirSync(catalog);
    writeFileSync(join(catalog, "http-endpoints.yml"), "rules: []");
    expect(resolveSemgrepRule([local, catalog], "http-endpoints")).toBe(
      join(catalog, "http-endpoints.yml"),
    );
  });

  it("derives the rules dir from the catalog dir", () => {
    expect(getSemgrepRulesDir(join("a", "b"))).toBe(join("a", "b", "semgrep-rules"));
  });
});

describe("semgrepLangFor", () => {
  it.each([
    [".ts", "ts"],
    [".tsx", "ts"],
    [".mjs", "js"],
    [".cjs", "js"],
    [".py", "python"],
    [".go", "go"],
  ])("maps %s to %s", (ext, lang) => {
    expect(semgrepLangFor(`src/file${ext}`)).toBe(lang);
  });

  it("returns null for an extension we do not scan", () => {
    expect(semgrepLangFor("README.md")).toBeNull();
  });
});

describe("semgrepRuleLanguages", () => {
  it("reads the flow style and normalizes aliases", () => {
    const langs = semgrepRuleLanguages(
      "rules:\n  - id: x\n    languages: [typescript, javascript]\n",
    );
    expect(langs && [...langs].sort()).toEqual(["js", "ts"]);
  });

  it("reads the block style", () => {
    const langs = semgrepRuleLanguages(
      "rules:\n  - id: x\n    languages:\n      - python\n      - go\n",
    );
    expect(langs && [...langs].sort()).toEqual(["go", "python"]);
  });

  it("unions across several rules in one file", () => {
    const langs = semgrepRuleLanguages(
      "rules:\n  - id: a\n    languages: [ts]\n  - id: b\n    languages: [ruby]\n",
    );
    expect(langs && [...langs].sort()).toEqual(["ruby", "ts"]);
  });

  it("returns null when it cannot tell, so the caller scans everything", () => {
    expect(semgrepRuleLanguages("rules:\n  - id: x\n    pattern: foo()\n")).toBeNull();
  });
});

describe("isSemgrepSuppressed", () => {
  const lines = ["const a = 1;", "// nosemgrep", "export function GET() {}", "const b = 2;"];

  it("suppresses when the line above carries the marker", () => {
    expect(isSemgrepSuppressed(lines, 3)).toBe(true);
  });

  it("suppresses when the line itself carries the marker", () => {
    expect(isSemgrepSuppressed(["doThing(); // nosemgrep"], 1)).toBe(true);
  });

  it("does not suppress an unmarked line", () => {
    expect(isSemgrepSuppressed(lines, 4)).toBe(false);
  });

  it("handles line 1 without reading off the front of the array", () => {
    expect(isSemgrepSuppressed(lines, 1)).toBe(false);
  });
});

describe("resolveSemgrepCore", () => {
  it("prefers an existing AGENTGG_SEMGREP_CORE override", () => {
    const bin = join(dir, "semgrep-core");
    writeFileSync(bin, "");
    expect(resolveSemgrepCore({ AGENTGG_SEMGREP_CORE: bin })).toBe(bin);
  });

  it("falls back to PATH when the override does not exist", () => {
    expect(resolveSemgrepCore({ AGENTGG_SEMGREP_CORE: join(dir, "absent") })).toBe("semgrep-core");
  });
});

describe("ensureSemgrepCore", () => {
  beforeEach(() => {
    resetSemgrepResolution();
  });

  it("prefers AGENTGG_SEMGREP_CORE over everything else", async () => {
    const bin = join(dir, "explicit-core");
    writeFileSync(bin, "");
    let installs = 0;
    const result = await ensureSemgrepCore(
      { AGENTGG_SEMGREP_CORE: bin, AGENTGG_HOME: dir },
      {
        install: async () => {
          installs++;
          return { ok: true, path: "should-not-be-used" };
        },
      },
    );
    expect(result).toEqual({ ok: true, bin, source: "override" });
    expect(installs).toBe(0);
  });

  it("uses the cached binary without installing", async () => {
    const cached = getSemgrepCorePath(SEMGREP_VERSION, { AGENTGG_HOME: dir });
    mkdirSync(dirname(cached), { recursive: true });
    writeFileSync(cached, "");
    let installs = 0;
    const result = await ensureSemgrepCore(
      { AGENTGG_HOME: dir, PATH: "" },
      {
        install: async () => {
          installs++;
          return { ok: true, path: cached };
        },
      },
    );
    expect(result).toEqual({ ok: true, bin: cached, source: "cache" });
    expect(installs).toBe(0);
  });

  it("takes semgrep-core from PATH before downloading", async () => {
    const name = process.platform === "win32" ? "semgrep-core.exe" : "semgrep-core";
    const onPath = join(dir, name);
    writeFileSync(onPath, "");
    let installs = 0;
    const result = await ensureSemgrepCore(
      { AGENTGG_HOME: dir, PATH: dir },
      {
        install: async () => {
          installs++;
          return { ok: true, path: "should-not-be-used" };
        },
      },
    );
    expect(result).toEqual({ ok: true, bin: onPath, source: "path" });
    expect(installs).toBe(0);
  });

  it("installs when nothing is cached and PATH has nothing", async () => {
    const result = await ensureSemgrepCore(
      { AGENTGG_HOME: dir, PATH: "" },
      { install: async () => ({ ok: true, path: "/fetched/semgrep-core" }) },
    );
    expect(result).toEqual({ ok: true, bin: "/fetched/semgrep-core", source: "fetched" });
  });

  it("installs once when several callers race", async () => {
    let installs = 0;
    const install = async () => {
      installs++;
      await new Promise((r) => setTimeout(r, 10));
      return { ok: true as const, path: "/fetched/semgrep-core" };
    };
    const results = await Promise.all([
      ensureSemgrepCore({ AGENTGG_HOME: dir, PATH: "" }, { install }),
      ensureSemgrepCore({ AGENTGG_HOME: dir, PATH: "" }, { install }),
      ensureSemgrepCore({ AGENTGG_HOME: dir, PATH: "" }, { install }),
    ]);
    expect(installs).toBe(1);
    for (const r of results)
      expect(r).toEqual({ ok: true, bin: "/fetched/semgrep-core", source: "fetched" });
  });

  it("remembers a failure instead of retrying it per agent", async () => {
    let installs = 0;
    const install = async () => {
      installs++;
      return { ok: false as const, reason: "download failed" as const };
    };
    const first = await ensureSemgrepCore({ AGENTGG_HOME: dir, PATH: "" }, { install });
    const second = await ensureSemgrepCore({ AGENTGG_HOME: dir, PATH: "" }, { install });
    expect(first).toEqual({ ok: false, reason: "download failed" });
    expect(second).toEqual({ ok: false, reason: "download failed" });
    expect(installs).toBe(1);
  });

  it("reports the unsupported platform without any install attempt", async () => {
    const result = await ensureSemgrepCore(
      { AGENTGG_HOME: dir, PATH: "" },
      { install: async () => ({ ok: false, reason: "unsupported platform" }) },
    );
    expect(result).toEqual({ ok: false, reason: "unsupported platform" });
  });
});

describe("runSemgrepPreFilter", () => {
  const agentWith = (preFilter: unknown[]) =>
    ({ slug: "t", where: { preFilter } }) as unknown as Parameters<typeof runSemgrepPreFilter>[1];

  it("does nothing and spawns nothing when the agent declares no semgrep rules", async () => {
    const out = await runSemgrepPreFilter(dir, agentWith([{ regex: "x" }]), ["a.ts"], [dir], 4);
    expect(out.hits.size).toBe(0);
  });

  it("warns and skips when the named rule file is absent", async () => {
    const warnings: string[] = [];
    mkdirSync(join(dir, "rules"), { recursive: true });
    const out = await runSemgrepPreFilter(
      dir,
      agentWith([{ semgrepRule: "absent" }]),
      ["a.ts"],
      [join(dir, "rules")],
      4,
      (m) => warnings.push(m),
    );
    expect(out.hits.size).toBe(0);
    expect(warnings[0]).toMatch(/semgrep rule 'absent' not found/);
  });

  it("names every rule dir it searched when the rule is missing", async () => {
    const warnings: string[] = [];
    const local = join(dir, "local");
    const catalog = join(dir, "catalog");
    mkdirSync(local);
    mkdirSync(catalog);
    await runSemgrepPreFilter(
      dir,
      agentWith([{ semgrepRule: "absent" }]),
      ["a.ts"],
      [local, catalog],
      4,
      (m) => warnings.push(m),
    );
    expect(warnings[0]).toContain(local);
    expect(warnings[0]).toContain(catalog);
  });

  it("returns nothing when there are no files to scan", async () => {
    const out = await runSemgrepPreFilter(dir, agentWith([{ semgrepRule: "x" }]), [], [dir], 4);
    expect(out.hits.size).toBe(0);
  });
});

describe("runSemgrepPreFilter degradation", () => {
  const agentWithSemgrep = () =>
    ({
      slug: "t",
      where: { preFilter: [{ semgrepRule: "http-endpoints" }] },
    }) as unknown as Parameters<typeof runSemgrepPreFilter>[1];

  beforeEach(() => {
    resetSemgrepResolution();
    writeFileSync(join(dir, "http-endpoints.yml"), "rules:\n  - id: x\n    languages: [ts]\n");
  });

  it("reports no degradation when the agent declares no semgrep rules", async () => {
    const agent = { slug: "t", where: { preFilter: [{ regex: "x" }] } } as unknown as Parameters<
      typeof runSemgrepPreFilter
    >[1];
    const out = await runSemgrepPreFilter(dir, agent, ["a.ts"], [dir], 4);
    expect(out.degraded).toBeNull();
    expect(out.hits.size).toBe(0);
  });

  it("returns the reason when the binary cannot be resolved", async () => {
    const out = await runSemgrepPreFilter(
      dir,
      agentWithSemgrep(),
      ["a.ts"],
      [dir],
      4,
      undefined,
      {
        AGENTGG_HOME: dir,
        PATH: "",
      },
      { ensure: async () => ({ ok: false, reason: "download failed" }) },
    );
    expect(out.degraded).toBe("download failed");
    expect(out.hits.size).toBe(0);
  });

  it("reports the resolution source through onInfo so a scan can prove it ran", async () => {
    const info: string[] = [];
    await runSemgrepPreFilter(
      dir,
      agentWithSemgrep(),
      ["a.ts"],
      [dir],
      4,
      undefined,
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: async () => ({ ok: true, bin: "/fake/semgrep-core", source: "cache" }),
        onInfo: (m) => info.push(m),
      },
    );
    expect(info[0]).toBe("semgrep-core: /fake/semgrep-core (cache)");
    expect(info.some((m) => m.includes("semgrep ran 1 rule(s)"))).toBe(true);
  });

  it("stays silent through onInfo when the binary cannot be resolved", async () => {
    const info: string[] = [];
    const out = await runSemgrepPreFilter(
      dir,
      agentWithSemgrep(),
      ["a.ts"],
      [dir],
      4,
      undefined,
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: async () => ({ ok: false, reason: "download failed" }),
        onInfo: (m) => info.push(m),
      },
    );
    expect(out.degraded).toBe("download failed");
    expect(info).toEqual([]);
  });

  it("records a start failure when the binary exits non-zero", async () => {
    const warnings: string[] = [];
    // A binary that cannot load its shared libraries exits 127, and Node
    // reports no `err.code` for that. Standing in for it: `node -rules …`
    // rejects the flags and exits non-zero the same way.
    const out = await runSemgrepPreFilter(
      dir,
      agentWithSemgrep(),
      ["a.ts"],
      [dir],
      4,
      (m) => warnings.push(m),
      { AGENTGG_HOME: dir, PATH: "" },
      { ensure: async () => ({ ok: true, bin: process.execPath, source: "cache" }) },
    );
    expect(out.degraded).toBe("binary failed to start");
    expect(warnings.some((m) => m.includes("would not start"))).toBe(true);
  });

  it("never resolves the binary when no file matches the rule's language", async () => {
    let asked = 0;
    const out = await runSemgrepPreFilter(
      dir,
      agentWithSemgrep(),
      ["a.py"],
      [dir],
      4,
      undefined,
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: async () => {
          asked++;
          return { ok: false, reason: "download failed" };
        },
      },
    );
    expect(asked).toBe(0);
    expect(out.degraded).toBeNull();
  });
});

describe("toSemgrepHit", () => {
  // Shapes copied from a real `semgrep-core -json` run, including the
  // two-element tuple the engine uses for a taint endpoint.
  const taintTrace = {
    taint_source: ["CliLoc", [{ start: { line: 7 } }, "req.query"]],
    intermediate_vars: [
      { location: { start: { line: 7 } }, content: "host" },
      { location: { start: { line: 8 } }, content: "cmd" },
    ],
    taint_sink: ["CliLoc", [{ start: { line: 9 } }, "execSync(cmd)"]],
  };

  it("keeps a declared label and carries the rule message beside it", () => {
    const hit = toSemgrepHit(
      { check_id: "r", extra: { message: "Input reaches a shell sink." } },
      9,
      "Shell sink",
    );
    expect(hit.label).toBe("Shell sink");
    expect(hit.message).toBe("Input reaches a shell sink.");
  });

  it("promotes the message to the label and does not repeat it", () => {
    const hit = toSemgrepHit({ check_id: "r", extra: { message: "Input reaches a sink." } }, 9);
    expect(hit.label).toBe("Input reaches a sink.");
    expect(hit.message).toBeUndefined();
  });

  it("falls back to the check id when the rule has no message", () => {
    expect(toSemgrepHit({ check_id: "local-exec" }, 3).label).toBe("local-exec");
  });

  it("collapses a multi-line message onto one line", () => {
    const hit = toSemgrepHit({ extra: { message: "line one\n  line two" } }, 1, "l");
    expect(hit.message).toBe("line one line two");
  });

  it("keeps allow-listed metadata and drops vendor bookkeeping", () => {
    const hit = toSemgrepHit(
      {
        extra: {
          metadata: {
            cwe: "CWE-78",
            confidence: "MEDIUM",
            "semgrep.dev": { rule: { id: 1 } },
            technology: ["express"],
            license: "Commons Clause",
          },
        },
      },
      1,
      "l",
    );
    expect(hit.metadata).toEqual({ cwe: "CWE-78", confidence: "MEDIUM" });
  });

  it("joins an allow-listed array value", () => {
    const hit = toSemgrepHit({ extra: { metadata: { owasp: ["A01", "A03"] } } }, 1, "l");
    expect(hit.metadata).toEqual({ owasp: "A01, A03" });
  });

  it("omits metadata entirely when no allow-listed key is present", () => {
    const hit = toSemgrepHit({ extra: { metadata: { technology: ["express"] } } }, 1, "l");
    expect(hit.metadata).toBeUndefined();
  });

  it("flattens a dataflow trace into source, intermediates, then sink", () => {
    const hit = toSemgrepHit({ extra: { dataflow_trace: taintTrace } }, 9, "l");
    expect(hit.taint).toEqual([
      { kind: "source", line: 7, code: "req.query" },
      { kind: "through", line: 7, code: "host" },
      { kind: "through", line: 8, code: "cmd" },
      { kind: "sink", line: 9, code: "execSync(cmd)" },
    ]);
  });

  it("drops token fragments the engine reports as intermediate steps", () => {
    // A real trace on a template literal emits a lone backtick as a step.
    const hit = toSemgrepHit(
      {
        extra: {
          dataflow_trace: {
            ...taintTrace,
            intermediate_vars: [
              { location: { start: { line: 7 } }, content: "raw" },
              { location: { start: { line: 8 } }, content: "`" },
            ],
          },
        },
      },
      9,
      "l",
    );
    expect(hit.taint?.map((s) => s.code)).toEqual(["req.query", "raw", "execSync(cmd)"]);
  });

  it("drops a repeated consecutive step", () => {
    const hit = toSemgrepHit(
      {
        extra: {
          dataflow_trace: {
            ...taintTrace,
            intermediate_vars: [
              { location: { start: { line: 7 } }, content: "host" },
              { location: { start: { line: 7 } }, content: "host" },
            ],
          },
        },
      },
      9,
      "l",
    );
    expect(hit.taint?.filter((s) => s.kind === "through")).toHaveLength(1);
  });

  it("caps a long intermediate chain", () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      location: { start: { line: i + 1 } },
      content: `v${i}`,
    }));
    const hit = toSemgrepHit(
      { extra: { dataflow_trace: { ...taintTrace, intermediate_vars: many } } },
      9,
      "l",
    );
    // 6 real steps, then a marker that names the omission, so a shortened
    // path cannot be mistaken for the whole path.
    expect(hit.taint?.filter((s) => s.kind === "through")).toHaveLength(6);
    const elided = hit.taint?.filter((s) => s.kind === "elided") ?? [];
    expect(elided).toHaveLength(1);
    expect(elided[0].code).toBe("14 steps omitted");
    // The first dropped step is v6 on line 7. The sink is on line 9, and
    // pointing the marker there would name a real but unrelated line.
    expect(elided[0].line).toBe(7);
  });

  it("puts the marker between the last kept step and the sink", () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      location: { start: { line: i + 1 } },
      content: `v${i}`,
    }));
    const hit = toSemgrepHit(
      { extra: { dataflow_trace: { ...taintTrace, intermediate_vars: many } } },
      9,
      "l",
    );
    const kinds = hit.taint?.map((s) => s.kind) ?? [];
    expect(kinds[0]).toBe("source");
    expect(kinds[kinds.length - 2]).toBe("elided");
    expect(kinds[kinds.length - 1]).toBe("sink");
  });

  it("reports no taint when only one end of the path parses", () => {
    // Half a path is worse than none: the model would read the surviving
    // end as the whole story.
    const hit = toSemgrepHit(
      { extra: { dataflow_trace: { taint_source: taintTrace.taint_source } } },
      9,
      "l",
    );
    expect(hit.taint).toBeUndefined();
  });

  it("reports no taint for a pattern-mode result", () => {
    expect(toSemgrepHit({ extra: { message: "m" } }, 9, "l").taint).toBeUndefined();
  });
});
