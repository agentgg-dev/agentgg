import type { Agent } from "@agentgg/core";
import { describe, expect, it } from "vitest";
import { formatAgentsTable } from "../src/commands/agents.js";

function makeAgent(slug: string, overrides: Partial<Agent> = {}): Agent {
  return {
    slug,
    name: slug,
    description: `description for ${slug}`,
    version: "0.0.1",
    noiseTier: "normal",
    where: {
      extensions: [],
      filePatterns: ["**/*.ts"],
      excludePatterns: [],
      useDefaultExcludes: true,
      preFilter: [],
      maxFilesPerBatch: 5,
      maxTurnsPerBatch: 30,
    },
    references: [],
    prompt: "placeholder prompt body",
    ...overrides,
  };
}

describe("formatAgentsTable", () => {
  it("returns a friendly message when there are no agents", () => {
    expect(formatAgentsTable([])).toBe("No agents installed.");
  });

  it("renders a header row plus one body row per agent", () => {
    const out = formatAgentsTable([makeAgent("foo")]);
    expect(out).toContain("SLUG");
    expect(out).toContain("CATEGORY");
    expect(out).toContain("NOISE");
    expect(out).toContain("DESCRIPTION");
    expect(out).toContain("foo");
  });

  it("does not render SEVERITY or SOURCE columns", () => {
    const out = formatAgentsTable([makeAgent("foo")]);
    expect(out).not.toContain("SEVERITY");
    expect(out).not.toContain("SOURCE");
  });

  it("truncates long descriptions to keep rows readable", () => {
    const a = makeAgent("foo", { description: "x".repeat(200) });
    const out = formatAgentsTable([a]);
    // 60 char truncation + ellipsis — the full 200-char description
    // must not appear verbatim.
    expect(out).not.toContain("x".repeat(200));
    expect(out).toContain("…");
  });

  it("shows the agent count footer", () => {
    expect(formatAgentsTable([makeAgent("a")])).toContain("1 agent");
    expect(formatAgentsTable([makeAgent("a"), makeAgent("b")])).toContain("2 agents");
  });
});
