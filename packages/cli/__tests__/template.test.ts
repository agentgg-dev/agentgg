import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Agent } from "@agentgg/core";
import { resolveTemplates } from "../src/template.js";

function makeAgent(slug: string): Agent {
  return {
    slug,
    name: slug,
    description: `description for ${slug}`,
    version: "0.0.1",
    mode: "file",
    noiseTier: "normal",
    filePatterns: ["**/*.ts"],
    languages: [],
    prefilter: [],
    references: [],
    prompt: "placeholder prompt body",
  };
}

const VALID_AGENT_MD = `---
slug: from-file
name: From File
description: Agent loaded from a .md file
version: 0.0.1
mode: file
noiseTier: normal
filePatterns:
  - "**/*.ts"
---

This is the prompt body for the file-based agent. It is long enough
to clear the schema's minimum-length floor without being trivial.
`;

describe("resolveTemplates", () => {
  const catalog: Agent[] = [
    makeAgent("sql-injection"),
    makeAgent("hardcoded-secrets"),
    makeAgent("command-injection"),
  ];

  it("returns empty array when no inputs supplied", () => {
    expect(resolveTemplates([], catalog)).toEqual([]);
  });

  it("looks up a single slug from the catalog", () => {
    const out = resolveTemplates(["sql-injection"], catalog);
    expect(out).toHaveLength(1);
    expect(out[0].slug).toBe("sql-injection");
  });

  it("splits comma-separated inputs (nuclei style)", () => {
    const out = resolveTemplates(["sql-injection,hardcoded-secrets"], catalog);
    expect(out.map((a) => a.slug).sort()).toEqual([
      "hardcoded-secrets",
      "sql-injection",
    ]);
  });

  it("accepts repeated -t flags", () => {
    const out = resolveTemplates(["sql-injection", "command-injection"], catalog);
    expect(out.map((a) => a.slug).sort()).toEqual([
      "command-injection",
      "sql-injection",
    ]);
  });

  it("dedupes when the same slug appears via different inputs", () => {
    const out = resolveTemplates(
      ["sql-injection,sql-injection", "sql-injection"],
      catalog,
    );
    expect(out).toHaveLength(1);
  });

  it("returns every agent matching a slug — official + custom shadow both run", () => {
    // Two distinct agents share a slug (e.g. user copied an official
    // agent into their custom dir and tweaked it). Resolving by slug
    // should produce both, deduped only by source path.
    const officialCopy: Agent = {
      ...makeAgent("sql-injection"),
      source: { kind: "official", path: "/official/sql-injection.md" },
    };
    const customCopy: Agent = {
      ...makeAgent("sql-injection"),
      source: { kind: "custom", path: "/custom/sql-injection.md" },
    };
    const out = resolveTemplates(
      ["sql-injection"],
      [officialCopy, customCopy],
    );
    expect(out).toHaveLength(2);
    expect(out.map((a) => a.source?.kind).sort()).toEqual(["custom", "official"]);
  });

  it("throws with the offending tokens when a slug doesn't match", () => {
    expect(() => resolveTemplates(["nope-no-such-slug"], catalog)).toThrow(
      /no installed agent with that slug/,
    );
  });

  it("throws once with every offending token listed", () => {
    try {
      resolveTemplates(["nope-1,nope-2"], catalog);
      expect.fail("expected throw");
    } catch (err) {
      const msg = (err as Error).message;
      expect(msg).toContain("nope-1");
      expect(msg).toContain("nope-2");
    }
  });

  describe("filesystem loading", () => {
    let tmp: string;
    beforeEach(() => {
      tmp = mkdtempSync(join(tmpdir(), "agentgg-template-"));
    });
    afterEach(() => {
      rmSync(tmp, { recursive: true, force: true });
    });

    it("loads an agent from a .md file path", () => {
      const file = join(tmp, "ext.md");
      writeFileSync(file, VALID_AGENT_MD, "utf8");
      const out = resolveTemplates([file], catalog);
      expect(out).toHaveLength(1);
      expect(out[0].slug).toBe("from-file");
      expect(out[0].source?.kind).toBe("project");
    });

    it("loads every .md from a directory path", () => {
      writeFileSync(join(tmp, "a.md"), VALID_AGENT_MD, "utf8");
      writeFileSync(
        join(tmp, "b.md"),
        VALID_AGENT_MD.replace("slug: from-file", "slug: from-file-two"),
        "utf8",
      );
      const out = resolveTemplates([tmp], catalog);
      expect(out.map((a) => a.slug).sort()).toEqual(["from-file", "from-file-two"]);
    });

    it("mixes builtin slugs with file paths in one invocation", () => {
      const file = join(tmp, "ext.md");
      writeFileSync(file, VALID_AGENT_MD, "utf8");
      const out = resolveTemplates([`sql-injection,${file}`], catalog);
      expect(out.map((a) => a.slug).sort()).toEqual(["from-file", "sql-injection"]);
    });

    it("throws on a path that doesn't exist (and labels it as a path, not a slug)", () => {
      expect(() => resolveTemplates(["./missing-agent.md"], catalog)).toThrow(
        /No such file or directory/,
      );
    });

    it("rejects non-.md / non-.txt files when given as paths", () => {
      const file = join(tmp, "notes.json");
      writeFileSync(file, '{"foo":1}', "utf8");
      expect(() => resolveTemplates([file], catalog)).toThrow(/Not a \.md file/);
    });

    it("rejects directories that contain no valid agents", () => {
      writeFileSync(join(tmp, "readme.md"), "not frontmatter at all", "utf8");
      expect(() => resolveTemplates([tmp], catalog)).toThrow(
        /No valid \.md agents found/,
      );
    });
  });

  describe("whitespace splitting", () => {
    it("splits a single -t value on spaces (nuclei-style quoted list)", () => {
      const out = resolveTemplates(["sql-injection hardcoded-secrets"], catalog);
      expect(out.map((a) => a.slug).sort()).toEqual([
        "hardcoded-secrets",
        "sql-injection",
      ]);
    });

    it("mixes commas and spaces in one value", () => {
      const out = resolveTemplates(
        ["sql-injection, hardcoded-secrets  command-injection"],
        catalog,
      );
      expect(out.map((a) => a.slug).sort()).toEqual([
        "command-injection",
        "hardcoded-secrets",
        "sql-injection",
      ]);
    });

    it("collapses repeated whitespace", () => {
      const out = resolveTemplates(["sql-injection\t\t\nhardcoded-secrets"], catalog);
      expect(out).toHaveLength(2);
    });
  });

  describe(".txt list file expansion", () => {
    let tmp: string;
    beforeEach(() => {
      tmp = mkdtempSync(join(tmpdir(), "agentgg-listfile-"));
    });
    afterEach(() => {
      rmSync(tmp, { recursive: true, force: true });
    });

    it("reads slugs one-per-line from a .txt file", () => {
      const list = join(tmp, "agents.txt");
      writeFileSync(list, "sql-injection\nhardcoded-secrets\n", "utf8");
      const out = resolveTemplates([list], catalog);
      expect(out.map((a) => a.slug).sort()).toEqual([
        "hardcoded-secrets",
        "sql-injection",
      ]);
    });

    it("ignores blank lines and `#` comments inside the list", () => {
      const list = join(tmp, "agents.txt");
      writeFileSync(
        list,
        "# pinned set\nsql-injection\n\n# end-to-end injection group\ncommand-injection\n",
        "utf8",
      );
      const out = resolveTemplates([list], catalog);
      expect(out.map((a) => a.slug).sort()).toEqual([
        "command-injection",
        "sql-injection",
      ]);
    });

    it("supports list files that reference other list files (recursion)", () => {
      const inner = join(tmp, "inner.txt");
      const outer = join(tmp, "outer.txt");
      writeFileSync(inner, "command-injection\n", "utf8");
      writeFileSync(outer, `sql-injection\n${inner}\n`, "utf8");
      const out = resolveTemplates([outer], catalog);
      expect(out.map((a) => a.slug).sort()).toEqual([
        "command-injection",
        "sql-injection",
      ]);
    });

    it("does not re-expand the same list file twice (cycle protection)", () => {
      const a = join(tmp, "a.txt");
      const b = join(tmp, "b.txt");
      writeFileSync(a, `sql-injection\n${b}\n`, "utf8");
      writeFileSync(b, `hardcoded-secrets\n${a}\n`, "utf8");
      const out = resolveTemplates([a], catalog);
      expect(out.map((a) => a.slug).sort()).toEqual([
        "hardcoded-secrets",
        "sql-injection",
      ]);
    });

    it("mixes a list file with other -t values seamlessly", () => {
      const list = join(tmp, "agents.txt");
      writeFileSync(list, "hardcoded-secrets\n", "utf8");
      const out = resolveTemplates(
        [`sql-injection,${list}`, "command-injection"],
        catalog,
      );
      expect(out.map((a) => a.slug).sort()).toEqual([
        "command-injection",
        "hardcoded-secrets",
        "sql-injection",
      ]);
    });

    it("errors clearly when the .txt file doesn't exist", () => {
      expect(() => resolveTemplates(["./does-not-exist.txt"], catalog)).toThrow(
        /list file does not exist/,
      );
    });

    it("a .md slug-like name inside a .txt is resolved as a path, not a slug", () => {
      const list = join(tmp, "agents.txt");
      const agentMd = join(tmp, "ext.md");
      writeFileSync(agentMd, VALID_AGENT_MD, "utf8");
      writeFileSync(list, `sql-injection\n${agentMd}\n`, "utf8");
      const out = resolveTemplates([list], catalog);
      expect(out.map((a) => a.slug).sort()).toEqual(["from-file", "sql-injection"]);
    });
  });
});
