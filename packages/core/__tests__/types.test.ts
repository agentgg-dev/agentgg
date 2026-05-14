import { describe, expect, it } from "vitest";
import { Agent, CvssScore, Finding, FileRecord, ScopeConfig, UserConfig } from "../src/types.js";

describe("UserConfig schema", () => {
  it("accepts a valid anthropic config", () => {
    const cfg = UserConfig.parse({
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-abc", model: "claude-sonnet-4-6" },
    });
    expect(cfg.provider).toBe("anthropic");
    expect(cfg.anthropic?.apiKey).toBe("sk-ant-abc");
    expect(cfg.schemaVersion).toBe(1);
  });

  it("accepts a valid ollama config without an API key", () => {
    const cfg = UserConfig.parse({
      provider: "ollama",
      ollama: { baseUrl: "http://localhost:11434" },
    });
    expect(cfg.provider).toBe("ollama");
    expect(cfg.ollama?.baseUrl).toBe("http://localhost:11434");
  });

  it("rejects an unknown provider", () => {
    expect(() => UserConfig.parse({ provider: "cohere" })).toThrow();
  });

  it("rejects provider:anthropic when the anthropic block is missing", () => {
    expect(() => UserConfig.parse({ provider: "anthropic" })).toThrow(
      /anthropic block is missing/,
    );
  });

  it("rejects provider:openai when the openai block is missing", () => {
    expect(() => UserConfig.parse({ provider: "openai" })).toThrow(
      /openai block is missing/,
    );
  });

  it("rejects provider:ollama when the ollama block is missing", () => {
    expect(() => UserConfig.parse({ provider: "ollama" })).toThrow(
      /ollama block is missing/,
    );
  });

  it("rejects an empty API key", () => {
    expect(() =>
      UserConfig.parse({
        provider: "anthropic",
        anthropic: { apiKey: "" },
      }),
    ).toThrow();
  });

  it("accepts an anthropic config with an OAuth token instead of an API key", () => {
    const cfg = UserConfig.parse({
      provider: "anthropic",
      anthropic: { oauthToken: "sk-ant-oat01-abc", model: "claude-sonnet-4-6" },
    });
    expect(cfg.anthropic?.oauthToken).toBe("sk-ant-oat01-abc");
    expect(cfg.anthropic?.apiKey).toBeUndefined();
  });

  it("rejects anthropic config with neither apiKey nor oauthToken", () => {
    expect(() =>
      UserConfig.parse({
        provider: "anthropic",
        anthropic: { model: "claude-sonnet-4-6" },
      }),
    ).toThrow(/either 'apiKey' or 'oauthToken'/);
  });

  it("rejects anthropic config with BOTH apiKey and oauthToken set", () => {
    expect(() =>
      UserConfig.parse({
        provider: "anthropic",
        anthropic: { apiKey: "sk-ant-api-x", oauthToken: "sk-ant-oat-y" },
      }),
    ).toThrow(/both 'apiKey' and 'oauthToken'/);
  });

  it("rejects a non-URL ollama baseUrl", () => {
    expect(() =>
      UserConfig.parse({
        provider: "ollama",
        ollama: { baseUrl: "not-a-url" },
      }),
    ).toThrow();
  });
});

describe("Agent schema", () => {
  it("accepts a minimal valid agent", () => {
    const agent = Agent.parse({
      slug: "sql-injection",
      name: "SQL Injection",
      description: "Detects string-concatenated SQL queries",
      prompt: "Look for SQL...",
    });
    expect(agent.slug).toBe("sql-injection");
    expect(agent.noiseTier).toBe("normal");
    expect(agent.filePatterns).toEqual([]);
  });

  it("does not carry a severity field (scoring is per-finding)", () => {
    const agent = Agent.parse({
      slug: "sql-injection",
      name: "x",
      description: "x",
      prompt: "x",
    });
    expect((agent as Record<string, unknown>).severity).toBeUndefined();
  });

  it("rejects slugs that don't match kebab-case", () => {
    expect(() =>
      Agent.parse({
        slug: "SQL Injection",
        name: "x",
        description: "x",
        prompt: "x",
      }),
    ).toThrow();
  });

  it("rejects slugs starting with a hyphen", () => {
    expect(() =>
      Agent.parse({
        slug: "-leading",
        name: "x",
        description: "x",
        prompt: "x",
      }),
    ).toThrow();
  });
});

describe("Finding schema", () => {
  const baseFinding = {
    id: "abc",
    agentSlug: "sql-injection",
    title: "SQLi in login handler",
    vulnSlug: "sql-injection",
    filePath: "src/login.ts",
    summary: "Login handler concatenates request body into SQL, allowing arbitrary DB access.",
    details: "Line 12 in src/login.ts builds a query via string concatenation...",
    poc: "curl -X POST /login -d \"username=admin' OR 1=1--\"",
    impact: "Any unauthenticated user can read or modify the users table.",
  };

  it("accepts a finding without severity (pre-scoring state)", () => {
    const f = Finding.parse(baseFinding);
    expect(f.severity).toBeUndefined();
    expect(f.cvss).toBeUndefined();
  });

  it("requires the four GHSA-style narrative fields", () => {
    expect(() => Finding.parse({ ...baseFinding, summary: undefined })).toThrow();
    expect(() => Finding.parse({ ...baseFinding, details: undefined })).toThrow();
    expect(() => Finding.parse({ ...baseFinding, poc: undefined })).toThrow();
    expect(() => Finding.parse({ ...baseFinding, impact: undefined })).toThrow();
  });

  it("accepts a finding with a CVSS score + derived severity", () => {
    const f = Finding.parse({
      ...baseFinding,
      severity: "CRITICAL",
      cvss: {
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        baseScore: 9.8,
        severity: "CRITICAL",
        metrics: {
          attackVector: "N",
          attackComplexity: "L",
          privilegesRequired: "N",
          userInteraction: "N",
          scope: "U",
          confidentiality: "H",
          integrity: "H",
          availability: "H",
        },
        justification: "Network-reachable, no auth, full read/write/availability impact.",
      },
    });
    expect(f.severity).toBe("CRITICAL");
    expect(f.cvss?.baseScore).toBe(9.8);
  });
});

describe("CvssScore schema", () => {
  it("rejects a baseScore above 10", () => {
    expect(() =>
      CvssScore.parse({
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        baseScore: 12,
        severity: "CRITICAL",
        metrics: {
          attackVector: "N",
          attackComplexity: "L",
          privilegesRequired: "N",
          userInteraction: "N",
          scope: "U",
          confidentiality: "H",
          integrity: "H",
          availability: "H",
        },
        justification: "x",
      }),
    ).toThrow();
  });

  it("rejects an invalid attackVector value", () => {
    expect(() =>
      CvssScore.parse({
        vector: "x",
        baseScore: 5,
        severity: "MEDIUM",
        metrics: {
          attackVector: "X", // not one of N/A/L/P
          attackComplexity: "L",
          privilegesRequired: "N",
          userInteraction: "N",
          scope: "U",
          confidentiality: "L",
          integrity: "L",
          availability: "L",
        },
        justification: "x",
      }),
    ).toThrow();
  });
});

describe("ScopeConfig schema", () => {
  it("accepts an empty config and fills defaults", () => {
    const scope = ScopeConfig.parse({});
    expect(scope.out_of_scope.paths).toEqual([]);
    expect(scope.out_of_scope.vulnerabilities).toEqual([]);
    expect(scope.accepted_risks).toEqual([]);
    expect(scope.agents.disable).toEqual([]);
  });

  it("accepts a fully populated config", () => {
    const scope = ScopeConfig.parse({
      out_of_scope: {
        paths: ["test/**", "docs/**"],
        vulnerabilities: ["csrf"],
      },
      accepted_risks: [
        { id: "legacy-md5", reason: "tracked in #1234", paths: ["src/auth/legacy.ts"] },
      ],
      agents: { disable: ["graphql-introspection"] },
      project_context: "Internal admin tool behind SSO.",
    });
    expect(scope.accepted_risks[0].id).toBe("legacy-md5");
    expect(scope.project_context).toContain("SSO");
  });
});

describe("FileRecord schema", () => {
  it("requires filePath and contentHash; fills the rest", () => {
    const fr = FileRecord.parse({
      filePath: "src/foo.ts",
      contentHash: "abc123",
    });
    expect(fr.candidates).toEqual([]);
    expect(fr.findings).toEqual([]);
    expect(fr.analysisHistory).toEqual([]);
    expect(fr.scope).toEqual({ outOfScope: false });
    expect(fr.status).toBe("pending");
  });

  it("rejects a record without a filePath", () => {
    expect(() =>
      FileRecord.parse({
        contentHash: "abc123",
      }),
    ).toThrow();
  });
});
