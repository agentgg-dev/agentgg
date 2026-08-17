import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { AgentPreFilterPattern, getSemgrepCorePath } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
});

describe("resolveSemgrepRule", () => {
  it("resolves a name to a .yml under the rules dir", () => {
    writeFileSync(join(dir, "http-endpoints.yml"), "rules: []");
    expect(resolveSemgrepRule(dir, "http-endpoints")).toBe(join(dir, "http-endpoints.yml"));
  });

  it("returns null for a missing rule", () => {
    expect(resolveSemgrepRule(dir, "nope")).toBeNull();
  });

  it("cannot reach the Semgrep registry — a pack id is just a missing file", () => {
    // The schema already rejects most of these, but resolution is the
    // second guarantee: the value is always joined to the local dir.
    expect(resolveSemgrepRule(dir, "p/typescript")).toBeNull();
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
    expect(result).toEqual({ ok: true, bin });
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
    expect(result).toEqual({ ok: true, bin: cached });
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
    expect(result).toEqual({ ok: true, bin: onPath });
    expect(installs).toBe(0);
  });

  it("installs when nothing is cached and PATH has nothing", async () => {
    const result = await ensureSemgrepCore(
      { AGENTGG_HOME: dir, PATH: "" },
      { install: async () => ({ ok: true, path: "/fetched/semgrep-core" }) },
    );
    expect(result).toEqual({ ok: true, bin: "/fetched/semgrep-core" });
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
    for (const r of results) expect(r).toEqual({ ok: true, bin: "/fetched/semgrep-core" });
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
    const out = await runSemgrepPreFilter(dir, agentWith([{ regex: "x" }]), ["a.ts"], dir, 4);
    expect(out.hits.size).toBe(0);
  });

  it("warns and skips when the named rule file is absent", async () => {
    const warnings: string[] = [];
    mkdirSync(join(dir, "rules"), { recursive: true });
    const out = await runSemgrepPreFilter(
      dir,
      agentWith([{ semgrepRule: "absent" }]),
      ["a.ts"],
      join(dir, "rules"),
      4,
      (m) => warnings.push(m),
    );
    expect(out.hits.size).toBe(0);
    expect(warnings[0]).toMatch(/semgrep rule 'absent' not found/);
  });

  it("returns nothing when there are no files to scan", async () => {
    const out = await runSemgrepPreFilter(dir, agentWith([{ semgrepRule: "x" }]), [], dir, 4);
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
    const out = await runSemgrepPreFilter(dir, agent, ["a.ts"], dir, 4);
    expect(out.degraded).toBeNull();
    expect(out.hits.size).toBe(0);
  });

  it("returns the reason when the binary cannot be resolved", async () => {
    const out = await runSemgrepPreFilter(
      dir,
      agentWithSemgrep(),
      ["a.ts"],
      dir,
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

  it("never resolves the binary when no file matches the rule's language", async () => {
    let asked = 0;
    const out = await runSemgrepPreFilter(
      dir,
      agentWithSemgrep(),
      ["a.py"],
      dir,
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
