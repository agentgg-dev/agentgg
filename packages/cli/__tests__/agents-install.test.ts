import { describe, expect, it } from "vitest";
import { isAgentFile, isCatalogFile } from "../src/agents-install.js";

describe("isAgentFile", () => {
  it("counts agents in a category subdirectory", () => {
    expect(isAgentFile("agents/auth/missing-access-control.md")).toBe(true);
  });

  it("does not count top-level docs", () => {
    expect(isAgentFile("README.md")).toBe(false);
  });

  it("does not count a stale .github doc left by an older extractor", () => {
    // The reported bug: the extract loop said 160 and the cached-path walk
    // said 161 on any machine that installed before the dot-directory filter.
    // Both now share this predicate, so they cannot disagree.
    expect(isAgentFile(".github/PULL_REQUEST_TEMPLATE.md")).toBe(false);
  });

  it("does not count semgrep rules", () => {
    expect(isAgentFile("semgrep-rules/http-endpoints.yml")).toBe(false);
  });

  it.each([
    "agents/README.md",
    "agents/auth/CHANGELOG.md",
    "agents/SECURITY.md",
    "agents/injection/contributing.md",
  ])("does not count reserved doc %s, which the loader skips at any depth", (p) => {
    expect(isAgentFile(p)).toBe(false);
  });
});

describe("isCatalogFile", () => {
  it("takes agent files at any depth", () => {
    expect(isCatalogFile("agents/auth/missing-access-control.md")).toBe(true);
    expect(isCatalogFile("README.md")).toBe(true);
  });

  it("takes semgrep rules, which are not .md", () => {
    // The regression this exists for: an install that filtered on `.md` alone
    // silently dropped every rule, leaving `semgrepRule` preFilters pointing
    // at files that were never written.
    expect(isCatalogFile("semgrep-rules/http-endpoints.yml")).toBe(true);
    expect(isCatalogFile("semgrep-rules/injection/sql.yaml")).toBe(true);
  });

  it("handles Windows separators", () => {
    expect(isCatalogFile("semgrep-rules\\http-endpoints.yml")).toBe(true);
  });

  it("excludes dot directories", () => {
    // `.github/PULL_REQUEST_TEMPLATE.md` is a .md in a subdirectory, so it
    // used to install and inflate the reported agent count by one.
    expect(isCatalogFile(".github/PULL_REQUEST_TEMPLATE.md")).toBe(false);
    expect(isCatalogFile(".github/ISSUE_TEMPLATE/new_agent.yml")).toBe(false);
    expect(isCatalogFile(".gstack/notes.md")).toBe(false);
  });

  it("leaves everything else in the repo alone", () => {
    expect(isCatalogFile("contributors.json")).toBe(false);
    expect(isCatalogFile("static/logo.png")).toBe(false);
    // A .yml outside semgrep-rules/ is repo config, not catalog content.
    expect(isCatalogFile("agents/auth/notes.yml")).toBe(false);
  });
});
