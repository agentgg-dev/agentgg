import { parseAgentMarkdown } from "@agentgg/core";
import { describe, expect, it } from "vitest";
import { type AgentSpec, renderAgentSpecMd } from "../src/agent-spec.js";

const BASE_SPEC: AgentSpec = {
  slug: "tenant-leak-on-find",
  name: "Tenant Leak on Find",
  description:
    "Controller returns a tenant-scoped record without first checking the request tenant.",
  noiseTier: "normal",
  references: ["CWE-639", "GHSA-xxxx-yyyy-zzzz"],
  precondition: {
    regex: {
      extensions: ["ts"],
      files: [],
      directories: [],
      patterns: [
        {
          regex: "findUnique|findFirst",
          in: ["src/**/*.ts"],
          notIn: [],
          label: "prisma fetch by id",
        },
      ],
    },
  },
  where: {
    extensions: ["ts", "tsx"],
    filePatterns: ["src/api/**"],
    excludePatterns: ["**/__tests__/**", "**/*.test.ts"],
    preFilter: [
      {
        regex: "findUnique\\s*\\(\\s*\\{",
        label: "prisma findUnique call",
      },
    ],
    maxFilesPerBatch: 5,
    maxTurnsPerBatch: 30,
  },
  prompt: `You are reviewing a batch of API handlers for tenant-leak-on-find.

The anti-pattern: a controller calls \`prisma.thing.findUnique({ where: { id } })\`
and returns the record without first calling \`assertTenantMatchesRequest(record)\`.
This previously caused a cross-tenant data leak.

## True positives
- A handler that fetches a record by id and returns it without a tenant check.

## False positives to skip
- Read-only public endpoints documented as cross-tenant by design.
`,
};

describe("renderAgentSpecMd", () => {
  it("round-trips a full spec through parseAgentMarkdown", () => {
    const md = renderAgentSpecMd(BASE_SPEC);
    const parsed = parseAgentMarkdown(md);
    expect(parsed.slug).toBe(BASE_SPEC.slug);
    expect(parsed.name).toBe(BASE_SPEC.name);
    expect(parsed.description).toBe(BASE_SPEC.description);
    expect(parsed.noiseTier).toBe("normal");
    expect(parsed.references).toEqual(BASE_SPEC.references);
    expect(parsed.where.extensions).toEqual(["ts", "tsx"]);
    expect(parsed.where.filePatterns).toEqual(["src/api/**"]);
    expect(parsed.where.excludePatterns).toContain("**/__tests__/**");
    expect(parsed.where.preFilter).toHaveLength(1);
    expect(parsed.where.preFilter[0]?.regex).toBe("findUnique\\s*\\(\\s*\\{");
    expect(parsed.precondition?.regex?.patterns).toHaveLength(1);
    expect(parsed.precondition?.regex?.patterns[0]?.regex).toBe("findUnique|findFirst");
    expect(parsed.prompt).toContain("tenant-leak-on-find");
  });

  it("omits empty optional sections", () => {
    const minimal: AgentSpec = {
      slug: "minimal-agent",
      name: "Minimal",
      description: "Tiny test agent.",
      noiseTier: "precise",
      references: [],
      where: {
        extensions: ["ts"],
        filePatterns: [],
        excludePatterns: [],
        preFilter: [],
        maxFilesPerBatch: 5,
        maxTurnsPerBatch: 30,
      },
      prompt: "A short prompt body that survives parsing.",
    };
    const md = renderAgentSpecMd(minimal);
    expect(md).not.toContain("references:");
    expect(md).not.toContain("precondition:");
    expect(md).not.toContain("filePatterns:");
    expect(md).not.toContain("preFilter:");
    expect(md).not.toContain("maxFilesPerBatch");
    expect(md).not.toContain("maxTurnsPerBatch");
    const parsed = parseAgentMarkdown(md);
    expect(parsed.slug).toBe("minimal-agent");
    expect(parsed.where.extensions).toEqual(["ts"]);
    expect(parsed.precondition).toBeUndefined();
  });

  it("escapes special characters in YAML scalars", () => {
    const tricky: AgentSpec = {
      slug: "tricky-quotes",
      name: 'Has "quotes" and: colons',
      description: "Multiple\nlines are folded by the renderer.",
      noiseTier: "normal",
      references: [],
      where: {
        extensions: ["go"],
        filePatterns: [],
        excludePatterns: [],
        preFilter: [],
        maxFilesPerBatch: 5,
        maxTurnsPerBatch: 30,
      },
      prompt: "Body.",
    };
    const md = renderAgentSpecMd(tricky);
    const parsed = parseAgentMarkdown(md);
    expect(parsed.name).toBe('Has "quotes" and: colons');
    expect(parsed.description).toContain("Multiple");
  });
});
