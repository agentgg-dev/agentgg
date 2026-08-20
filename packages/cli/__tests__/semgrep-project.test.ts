import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type ProjectAgentInput,
  resetSemgrepResolution,
  runSemgrepProject,
} from "../src/semgrep.js";

let dir: string;

beforeEach(() => {
  resetSemgrepResolution();
  dir = mkdtempSync(join(tmpdir(), "agentgg-sgproject-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const RULE = `rules:
  - id: eval-call
    languages: [ts]
    message: eval used
    severity: WARNING
    pattern: eval($X)
`;

/** Minimal agent shape; only `slug` and `where.preFilter` are read. */
function agentWith(slug: string, rule: string, label?: string): ProjectAgentInput["agent"] {
  const entry = label ? { semgrepRule: rule, label } : { semgrepRule: rule };
  return { slug, where: { preFilter: [entry] } } as unknown as ProjectAgentInput["agent"];
}

const ensureOk = async () => ({ ok: true as const, bin: "/fake/bin", source: "cache" as const });

/** One engine result for `relPath`, under the merged id the runner assigns. */
function result(checkId: string, relPath: string, line: number) {
  return {
    check_id: checkId,
    path: resolve(dir, relPath),
    start: { line },
    end: { line },
    extra: { message: "eval used" },
  };
}

describe("runSemgrepProject", () => {
  it("runs one process for several agents and labels each agent's hits its own way", async () => {
    writeFileSync(join(dir, "shared.yml"), RULE);
    let invocations = 0;
    const out = await runSemgrepProject(
      dir,
      [
        { agent: agentWith("alpha", "shared", "Alpha's reason"), files: ["a.ts"] },
        { agent: agentWith("beta", "shared", "Beta's reason"), files: ["a.ts"] },
      ],
      [dir],
      4,
      undefined,
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: ensureOk,
        run: async () => {
          invocations++;
          return JSON.stringify({ results: [result("agentgg-0-0-eval-call", "a.ts", 3)] });
        },
      },
    );

    expect(invocations).toBe(1);
    expect(out.byAgent.get("alpha")?.get("a.ts")?.[0].label).toBe("Alpha's reason");
    expect(out.byAgent.get("beta")?.get("a.ts")?.[0].label).toBe("Beta's reason");
  });

  it("gives an agent only the hits inside its own file set", async () => {
    writeFileSync(join(dir, "shared.yml"), RULE);
    const out = await runSemgrepProject(
      dir,
      [
        { agent: agentWith("alpha", "shared"), files: ["a.ts"] },
        { agent: agentWith("beta", "shared"), files: ["b.ts"] },
      ],
      [dir],
      4,
      undefined,
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: ensureOk,
        run: async () =>
          JSON.stringify({
            results: [
              result("agentgg-0-0-eval-call", "a.ts", 1),
              result("agentgg-0-0-eval-call", "b.ts", 2),
            ],
          }),
      },
    );

    expect([...(out.byAgent.get("alpha") ?? new Map()).keys()]).toEqual(["a.ts"]);
    expect([...(out.byAgent.get("beta") ?? new Map()).keys()]).toEqual(["b.ts"]);
  });

  it("keeps two agents' rules apart when only one declared a given rule", async () => {
    writeFileSync(join(dir, "one.yml"), RULE);
    writeFileSync(join(dir, "two.yml"), RULE.replace("eval-call", "other-call"));
    const out = await runSemgrepProject(
      dir,
      [
        { agent: agentWith("alpha", "one"), files: ["a.ts"] },
        { agent: agentWith("beta", "two"), files: ["a.ts"] },
      ],
      [dir],
      4,
      undefined,
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: ensureOk,
        // Only the FIRST rule file matched. Beta declared the second, so it
        // must come away with nothing.
        run: async () => JSON.stringify({ results: [result("agentgg-0-0-eval-call", "a.ts", 1)] }),
      },
    );

    expect(out.byAgent.get("alpha")?.size).toBe(1);
    expect(out.byAgent.has("beta")).toBe(false);
  });

  // The bug this was written for: a join rule loads, scans nothing, and
  // reports neither an error nor a skip, so the scan reads as clean.
  it("degrades the agent instead of running a join rule", async () => {
    writeFileSync(
      join(dir, "joined.yml"),
      `rules:
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
`,
    );
    const warnings: string[] = [];
    let invocations = 0;
    const out = await runSemgrepProject(
      dir,
      [{ agent: agentWith("alpha", "joined"), files: ["a.ts"] }],
      [dir],
      4,
      (m) => warnings.push(m),
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: ensureOk,
        run: async () => {
          invocations++;
          return "{}";
        },
      },
    );

    expect(out.degradedByAgent.get("alpha")).toBe("unsupported rule");
    expect(invocations).toBe(0);
    expect(warnings.some((m) => m.includes("join"))).toBe(true);
  });

  it("says so when a rule carries its own paths: filter", async () => {
    writeFileSync(
      join(dir, "scoped.yml"),
      `${RULE}    paths:
      exclude:
        - "*.spec.ts"
`,
    );
    const warnings: string[] = [];
    await runSemgrepProject(
      dir,
      [{ agent: agentWith("alpha", "scoped"), files: ["a.ts"] }],
      [dir],
      4,
      (m) => warnings.push(m),
      { AGENTGG_HOME: dir, PATH: "" },
      { ensure: ensureOk, run: async () => JSON.stringify({ results: [] }) },
    );

    expect(warnings.some((m) => m.includes("paths:"))).toBe(true);
  });

  // A per-file engine error costs one file, not the run, so it must not
  // degrade the agent — that would understate coverage instead of overstating.
  it("warns about per-file engine errors without degrading the agent", async () => {
    writeFileSync(join(dir, "shared.yml"), RULE);
    const warnings: string[] = [];
    const out = await runSemgrepProject(
      dir,
      [{ agent: agentWith("alpha", "shared"), files: ["a.ts"] }],
      [dir],
      4,
      (m) => warnings.push(m),
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: ensureOk,
        run: async () =>
          JSON.stringify({
            results: [result("agentgg-0-0-eval-call", "a.ts", 1)],
            errors: [
              {
                message: "`===` was unexpected",
                severity: "warn",
                location: { path: resolve(dir, "a.ts"), start: { line: 16 } },
              },
            ],
          }),
      },
    );

    expect(out.degradedByAgent.has("alpha")).toBe(false);
    expect(out.byAgent.get("alpha")?.size).toBe(1);
    // The file and line are the point: without them the warning names no
    // file, and the reader cannot act on it.
    expect(warnings.some((m) => m.includes("a.ts:16") && m.includes("partial parse"))).toBe(true);
  });

  it("caps the file-level messages and counts the rest", async () => {
    writeFileSync(join(dir, "shared.yml"), RULE);
    const warnings: string[] = [];
    await runSemgrepProject(
      dir,
      [{ agent: agentWith("alpha", "shared"), files: ["a.ts"] }],
      [dir],
      4,
      (m) => warnings.push(m),
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: ensureOk,
        run: async () =>
          JSON.stringify({
            results: [],
            errors: Array.from({ length: 9 }, () => ({ message: "boom" })),
          }),
      },
    );

    expect(warnings).toHaveLength(6);
    expect(warnings[5]).toContain("4 more file-level message(s)");
  });

  it("records a timeout separately from a binary that never started", async () => {
    writeFileSync(join(dir, "shared.yml"), RULE);
    const out = await runSemgrepProject(
      dir,
      [{ agent: agentWith("alpha", "shared"), files: ["a.ts"] }],
      [dir],
      4,
      undefined,
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: ensureOk,
        run: async () => {
          throw Object.assign(new Error("timeout"), { killed: true });
        },
      },
    );

    expect(out.degradedByAgent.get("alpha")).toBe("run timed out");
  });

  it("drops a result whose path was never a target", async () => {
    writeFileSync(join(dir, "shared.yml"), RULE);
    const out = await runSemgrepProject(
      dir,
      [{ agent: agentWith("alpha", "shared"), files: ["a.ts"] }],
      [dir],
      4,
      undefined,
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: ensureOk,
        run: async () =>
          JSON.stringify({
            results: [
              {
                check_id: "agentgg-0-0-eval-call",
                path: resolve(dir, "never-selected.ts"),
                start: { line: 1 },
                extra: {},
              },
            ],
          }),
      },
    );

    expect(out.byAgent.has("alpha")).toBe(false);
  });

  it("never resolves the binary when no agent declares a semgrep rule", async () => {
    let asked = 0;
    const plainAgent = {
      slug: "alpha",
      where: { preFilter: [{ regex: "x" }] },
    } as unknown as ProjectAgentInput["agent"];
    const out = await runSemgrepProject(
      dir,
      [{ agent: plainAgent, files: ["a.ts"] }],
      [dir],
      4,
      undefined,
      { AGENTGG_HOME: dir, PATH: "" },
      {
        ensure: async () => {
          asked++;
          return { ok: false as const, reason: "download failed" as const };
        },
      },
    );

    expect(asked).toBe(0);
    expect(out.degradedByAgent.size).toBe(0);
  });
});
