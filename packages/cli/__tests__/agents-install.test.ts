import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import AdmZip from "adm-zip";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installOfficialAgents, isAgentFile, isCatalogFile } from "../src/agents-install.js";

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

const ZIPBALL = "https://api.github.com/repos/agentgg-dev/agentgg-agents/zipball";

/** A stand-in for the archive GitHub serves, with the same top-level prefix. */
function catalogZip(prefix = "agentgg-dev-agentgg-agents-abc1234"): Buffer {
  const zip = new AdmZip();
  zip.addFile(`${prefix}/`, Buffer.alloc(0));
  zip.addFile(`${prefix}/README.md`, Buffer.from("# catalog"));
  zip.addFile(`${prefix}/agents/auth/sample.md`, Buffer.from("---\nslug: sample\n---\nbody"));
  zip.addFile(`${prefix}/semgrep-rules/http.yml`, Buffer.from("rules: []"));
  return zip.toBuffer();
}

describe("installOfficialAgents at an explicit ref", () => {
  let home: string;
  let env: NodeJS.ProcessEnv;
  let urls: string[];

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "agentgg-install-"));
    env = { AGENTGG_HOME: home };
    urls = [];
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    rmSync(home, { recursive: true, force: true });
  });

  /** Serve the same archive for any URL, and record what was asked for. */
  function stubFetch(): void {
    vi.stubGlobal("fetch", async (url: string | URL) => {
      urls.push(String(url));
      const buf = catalogZip();
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
      } as unknown as Response;
    });
  }

  it("downloads the zipball for the requested ref", async () => {
    stubFetch();

    const res = await installOfficialAgents(env, { ref: "v0.1.20" });

    expect(urls).toContain(`${ZIPBALL}/v0.1.20`);
    expect(res.version).toBe("v0.1.20");
    expect(res.count).toBe(1);
    expect(existsSync(join(home, "agentgg-agents", "agents", "auth", "sample.md"))).toBe(true);
  });

  it("does not ask GitHub for the latest release", async () => {
    stubFetch();

    await installOfficialAgents(env, { ref: "v0.1.20" });

    expect(urls.some((u) => u.includes("releases/latest"))).toBe(false);
  });

  it("re-downloads a ref it already installed, because a branch moves", async () => {
    stubFetch();

    await installOfficialAgents(env, { ref: "main" });
    await installOfficialAgents(env, { ref: "main" });

    expect(urls.filter((u) => u.startsWith(ZIPBALL))).toHaveLength(2);
  });

  it("records the ref in the version marker", async () => {
    stubFetch();

    await installOfficialAgents(env, { ref: "32c92f7fc03b6b40ea408bf2940ea9ca4928a018" });

    const marker = JSON.parse(readFileSync(join(home, "agentgg-agents", ".version.json"), "utf8"));
    expect(marker.version).toBe("32c92f7fc03b6b40ea408bf2940ea9ca4928a018");
  });

  it("names the ref when the download fails", async () => {
    vi.stubGlobal("fetch", async () => {
      return { ok: false, status: 404, statusText: "Not Found" } as unknown as Response;
    });

    await expect(installOfficialAgents(env, { ref: "v9.9.9" })).rejects.toThrow(/v9\.9\.9/);
  });

  it("adds the v prefix to a bare version number, because releases are tagged with one", async () => {
    stubFetch();

    await installOfficialAgents(env, { ref: "0.1.29" });

    expect(urls).toContain(`${ZIPBALL}/v0.1.29`);
  });

  it("records the tag it fetched, not the version number as typed", async () => {
    // The update check compares this marker against the latest release's
    // `tag_name`. Storing "0.1.29" against a tag of "v0.1.29" would report an
    // update on a catalog that is already current.
    stubFetch();

    await installOfficialAgents(env, { ref: "0.1.29" });

    const marker = JSON.parse(readFileSync(join(home, "agentgg-agents", ".version.json"), "utf8"));
    expect(marker.version).toBe("v0.1.29");
  });

  it("leaves a commit SHA alone", async () => {
    stubFetch();

    await installOfficialAgents(env, { ref: "95858d12c2c4db781cea38e4fa7cb208c3a703dc" });

    expect(urls).toContain(`${ZIPBALL}/95858d12c2c4db781cea38e4fa7cb208c3a703dc`);
  });
});
