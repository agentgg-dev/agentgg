import { describe, expect, it } from "vitest";
import { Agent } from "@agentgg/core";
import { BUILTIN_AGENTS, BUILTIN_AGENT_ERRORS } from "../src/index.js";

describe("BUILTIN_AGENTS", () => {
  it("loads cleanly with zero parse errors", () => {
    expect(BUILTIN_AGENT_ERRORS).toEqual([]);
  });

  it("has the expected count", () => {
    expect(BUILTIN_AGENTS).toHaveLength(5);
  });

  it("every builtin passes the Agent schema", () => {
    for (const agent of BUILTIN_AGENTS) {
      Agent.parse(agent);
    }
  });

  it("every slug is unique", () => {
    const slugs = BUILTIN_AGENTS.map((a) => a.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it("every slug matches the kebab-case slug regex", () => {
    for (const a of BUILTIN_AGENTS) {
      expect(a.slug).toMatch(/^[a-z0-9][a-z0-9-]*$/);
    }
  });

  it("every agent has a non-trivial prompt body", () => {
    for (const a of BUILTIN_AGENTS) {
      expect(a.prompt.length).toBeGreaterThan(200);
    }
  });

  it("every file-mode agent declares at least one filePattern", () => {
    for (const a of BUILTIN_AGENTS) {
      if (a.mode === "file") {
        expect(a.filePatterns.length).toBeGreaterThan(0);
      }
    }
  });

  it("ships at least one hunt-mode agent", () => {
    const huntCount = BUILTIN_AGENTS.filter((a) => a.mode === "hunt").length;
    expect(huntCount).toBeGreaterThan(0);
  });

  it("every builtin is stamped with source.kind === 'builtin'", () => {
    for (const a of BUILTIN_AGENTS) {
      expect(a.source?.kind).toBe("builtin");
      expect(a.source?.path).toMatch(/\.md$/);
    }
  });

  it("includes the expected launch slugs", () => {
    const slugs = BUILTIN_AGENTS.map((a) => a.slug);
    expect(slugs).toContain("hardcoded-secrets");
    expect(slugs).toContain("sql-injection");
    expect(slugs).toContain("command-injection");
    expect(slugs).toContain("missing-access-control");
    expect(slugs).toContain("openclaw-audit-allowlist-identity");
  });
});

describe("specific builtins", () => {
  const bySlug = (s: string) => {
    const a = BUILTIN_AGENTS.find((a) => a.slug === s);
    if (!a) throw new Error(`builtin '${s}' not found`);
    return a;
  };

  it("hardcoded-secrets is file mode + precise noise tier", () => {
    const a = bySlug("hardcoded-secrets");
    expect(a.mode).toBe("file");
    expect(a.noiseTier).toBe("precise");
  });

  it("sql-injection is file mode + normal noise tier", () => {
    const a = bySlug("sql-injection");
    expect(a.mode).toBe("file");
    expect(a.noiseTier).toBe("normal");
  });

  it("command-injection is file mode + precise noise tier", () => {
    const a = bySlug("command-injection");
    expect(a.mode).toBe("file");
    expect(a.noiseTier).toBe("precise");
  });

  it("missing-access-control is hunt mode, no filePatterns", () => {
    const a = bySlug("missing-access-control");
    expect(a.mode).toBe("hunt");
    expect(a.filePatterns).toEqual([]);
  });

  it("openclaw-audit-allowlist-identity is hunt mode with GHSA references", () => {
    const a = bySlug("openclaw-audit-allowlist-identity");
    expect(a.mode).toBe("hunt");
    expect(a.filePatterns).toEqual([]);
    expect(a.references?.some((r) => r.startsWith("GHSA-"))).toBe(true);
  });

  it("no builtin carries a severity field (scoring is per-finding)", () => {
    for (const a of BUILTIN_AGENTS) {
      expect((a as Record<string, unknown>).severity).toBeUndefined();
    }
  });
});
