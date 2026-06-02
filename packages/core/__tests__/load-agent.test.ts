import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AgentParseError,
  loadAgentFile,
  loadAgentsFromDir,
  parseAgentMarkdown,
} from "../src/load-agent.js";

const VALID_MD = `---
slug: sql-injection
name: SQL Injection
description: Detects string-concatenated SQL queries.
version: 0.1.0
noiseTier: normal
where:
  filePatterns:
    - "**/*.ts"
references:
  - CWE-89
---

You are looking for string-concatenated SQL queries. Reject parameterized
versions; flag anything where user input flows into a SQL string via
template interpolation or string concatenation.

(This body is long enough to satisfy the schema's minimum prompt rule.)
`;

describe("parseAgentMarkdown", () => {
  it("parses valid frontmatter + body into an Agent", () => {
    const agent = parseAgentMarkdown(VALID_MD);
    expect(agent.slug).toBe("sql-injection");
    expect(agent.name).toBe("SQL Injection");
    expect(agent.noiseTier).toBe("normal");
    expect(agent.where.filePatterns).toEqual(["**/*.ts"]);
    expect(agent.references).toEqual(["CWE-89"]);
    // Prompt is the markdown body, trimmed.
    expect(agent.prompt).toContain("string-concatenated SQL");
    expect(agent.prompt.startsWith("\n")).toBe(false);
    expect(agent.prompt.endsWith("\n")).toBe(false);
  });

  it("stamps source when provided", () => {
    const agent = parseAgentMarkdown(VALID_MD, {
      kind: "community",
      path: "/x/y/agent.md",
      pack: "@org/security",
    });
    expect(agent.source?.kind).toBe("community");
    expect(agent.source?.path).toBe("/x/y/agent.md");
    expect(agent.source?.pack).toBe("@org/security");
  });

  it("throws AgentParseError with the file path on schema failure", () => {
    const bad = `---
slug: BAD SLUG WITH SPACES
name: x
description: x
---

body
`;
    try {
      parseAgentMarkdown(bad, { kind: "custom", path: "/x.md" });
      expect.fail("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AgentParseError);
      const e = err as AgentParseError;
      expect(e.filePath).toBe("/x.md");
      expect(e.message).toMatch(/schema validation failed/i);
      expect(e.message).toMatch(/slug/);
    }
  });

  it("throws on missing required slug", () => {
    const bad = `---
name: x
description: x
---

body
`;
    expect(() => parseAgentMarkdown(bad)).toThrow(AgentParseError);
  });

  it("throws when the prompt body is empty", () => {
    const bad = `---
slug: foo
name: x
description: x
---
`;
    expect(() => parseAgentMarkdown(bad)).toThrow(/no prompt body/i);
  });

  it("throws on malformed YAML frontmatter", () => {
    const bad = `---
slug: foo
name: [unclosed bracket
---

body
`;
    expect(() => parseAgentMarkdown(bad)).toThrow(AgentParseError);
  });

  it("fills schema defaults (noiseTier -> normal, where defaults, etc.)", () => {
    const minimal = `---
slug: minimal-agent
name: Minimal
description: x
---

This is the prompt body. It's long enough to be useful as a real prompt.
`;
    const agent = parseAgentMarkdown(minimal);
    expect(agent.noiseTier).toBe("normal");
    expect(agent.version).toBe("0.0.1");
    // Omitted `where` resolves to an all-files default scope.
    expect(agent.where.extensions).toEqual([]);
    expect(agent.where.filePatterns).toEqual([]);
    expect(agent.where.maxFilesPerBatch).toBe(5);
    expect(agent.references).toBeUndefined();
  });
});

describe("loadAgentFile + loadAgentsFromDir", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "agentgg-agents-"));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("loadAgentFile reads a file and stamps source.path", () => {
    const file = join(tmp, "x.md");
    writeFileSync(file, VALID_MD, "utf8");
    const agent = loadAgentFile(file, "project");
    expect(agent.source?.kind).toBe("project");
    expect(agent.source?.path).toBe(file);
  });

  it("loadAgentsFromDir returns every valid .md file as an Agent", () => {
    writeFileSync(join(tmp, "a.md"), VALID_MD, "utf8");
    writeFileSync(
      join(tmp, "b.md"),
      VALID_MD.replace("slug: sql-injection", "slug: other-thing"),
      "utf8",
    );
    const { agents, errors } = loadAgentsFromDir(tmp, { kind: "community" });
    expect(errors).toEqual([]);
    expect(agents.map((a) => a.slug).sort()).toEqual(["other-thing", "sql-injection"]);
    expect(agents[0].source?.kind).toBe("community");
  });

  it("ignores non-.md files and reserved doc filenames", () => {
    writeFileSync(join(tmp, "real.md"), VALID_MD, "utf8");
    writeFileSync(join(tmp, "package.json"), "{}", "utf8");
    writeFileSync(join(tmp, "README.md"), "# pack readme\n", "utf8");
    writeFileSync(join(tmp, "LICENSE.md"), "license\n", "utf8");
    const { agents, errors } = loadAgentsFromDir(tmp);
    expect(errors).toEqual([]);
    expect(agents).toHaveLength(1);
    expect(agents[0].slug).toBe("sql-injection");
  });

  it("skips .git, .github, and node_modules directories", () => {
    writeFileSync(join(tmp, "real.md"), VALID_MD, "utf8");
    mkdirSync(join(tmp, ".github"));
    writeFileSync(
      join(tmp, ".github", "PULL_REQUEST_TEMPLATE.md"),
      "### What does this PR do?\n",
      "utf8",
    );
    mkdirSync(join(tmp, ".git"));
    writeFileSync(join(tmp, ".git", "COMMIT_EDITMSG.md"), "junk\n", "utf8");
    mkdirSync(join(tmp, "node_modules"));
    writeFileSync(join(tmp, "node_modules", "HISTORY.md"), "v1.0\n", "utf8");
    const { agents, errors } = loadAgentsFromDir(tmp);
    expect(errors).toEqual([]);
    expect(agents).toHaveLength(1);
    expect(agents[0].slug).toBe("sql-injection");
  });

  it("throws on the first invalid file when collectErrors is false (default)", () => {
    writeFileSync(join(tmp, "a.md"), VALID_MD, "utf8");
    writeFileSync(join(tmp, "b.md"), "not even frontmatter\n", "utf8");
    expect(() => loadAgentsFromDir(tmp)).toThrow(AgentParseError);
  });

  it("collects errors instead of throwing when collectErrors=true", () => {
    writeFileSync(join(tmp, "valid.md"), VALID_MD, "utf8");
    writeFileSync(join(tmp, "broken.md"), "---\nslug:\n---\n", "utf8");
    const { agents, errors } = loadAgentsFromDir(tmp, { collectErrors: true });
    expect(agents).toHaveLength(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(AgentParseError);
    expect(errors[0].filePath).toContain("broken.md");
  });

  it("throws AgentParseError when the directory doesn't exist", () => {
    expect(() => loadAgentsFromDir(join(tmp, "nope"))).toThrow(AgentParseError);
  });
});
