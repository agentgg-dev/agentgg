import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { getOfficialAgentsDir, getOfficialAgentsVersionPath, isReservedDoc } from "@agentgg/core";
import AdmZip from "adm-zip";

const AGENTS_REPO = "agentgg-dev/agentgg-agents";
const GITHUB_API = "https://api.github.com";

interface VersionInfo {
  version: string;
  installedAt: string;
}

/**
 * What the catalog ships, keyed on the path relative to the catalog root:
 * agent files anywhere, plus semgrep rule files under `semgrep-rules/`.
 * Everything else in the repo (workflows, the logo, contributors.json) is
 * not catalog content.
 *
 * Rules are NOT `.md`, so an install that only took `.md` files left every
 * `semgrepRule` preFilter pointing at a file that was never written — the
 * agent then degraded to regex-only with nothing but a warning to say why.
 */
export function isCatalogFile(relativePath: string): boolean {
  const p = relativePath.replace(/\\/g, "/");
  // Nothing under a dot directory. `.github/PULL_REQUEST_TEMPLATE.md` is a
  // `.md` in a subdirectory, so without this it installs into the user's
  // catalog and inflates the reported agent count by one.
  if (p.split("/").some((seg) => seg.startsWith("."))) return false;
  if (p.endsWith(".md")) return true;
  return p.startsWith("semgrep-rules/") && (p.endsWith(".yml") || p.endsWith(".yaml"));
}

/**
 * Does this path count as an agent? The single rule shared by both places
 * that report a count — the extract loop and the cached-path walk below.
 * They used to carry separate rules and disagreed by one on any machine
 * with a stale `.github/*.md` left by an older extractor.
 *
 * Top-level `.md` files (README.md etc.) ship in the same install but are
 * not agents, hence the subdirectory requirement.
 */
export function isAgentFile(relativePath: string): boolean {
  const p = relativePath.replace(/\\/g, "/");
  if (!isCatalogFile(p) || !p.endsWith(".md") || !p.includes("/")) return false;
  // The loader skips reserved docs at every depth, not just the top level, so
  // a future `agents/README.md` would count here and never load. Shares the
  // loader's list rather than copying it — a second copy would drift.
  return !isReservedDoc(p);
}

/**
 * Broader than `isCatalogFile` on purpose. Removal has to clear anything an
 * *older* CLI installed, not just what this one would write — otherwise a
 * file that is no longer catalog content (a `.github/*.md` from before the
 * dot-directory filter) can never be cleaned up, not even by `--force`.
 */
function isRemovableCatalogFile(relativePath: string): boolean {
  const p = relativePath.replace(/\\/g, "/");
  return p.endsWith(".md") || isCatalogFile(p);
}

/** Count agent files on disk, using the same rule as the extract loop. */
function countAgentFiles(dir: string, rel = ""): number {
  let n = 0;
  for (const f of readdirSync(dir)) {
    const abs = join(dir, f);
    const relPath = rel ? `${rel}/${f}` : f;
    if (statSync(abs).isDirectory()) n += countAgentFiles(abs, relPath);
    else if (isAgentFile(relPath)) n++;
  }
  return n;
}

export function getInstalledVersion(env: NodeJS.ProcessEnv = process.env): VersionInfo | null {
  const versionPath = getOfficialAgentsVersionPath(env);
  if (!existsSync(versionPath)) return null;
  try {
    return JSON.parse(readFileSync(versionPath, "utf8")) as VersionInfo;
  } catch {
    return null;
  }
}

async function fetchLatestRelease(): Promise<{ tag: string; zipUrl: string } | null> {
  try {
    const res = await fetch(`${GITHUB_API}/repos/${AGENTS_REPO}/releases/latest`, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "agentgg-cli" },
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { tag_name: string; zipball_url: string };
    return { tag: data.tag_name, zipUrl: data.zipball_url };
  } catch {
    return null;
  }
}

/**
 * Download and install all official agents from the agentgg-agents GitHub repo
 * into `~/.agentgg/agentgg-agents/`. Mirrors how nuclei auto-downloads templates
 * on first run and how `nuclei -update-templates` refreshes them.
 *
 * On first install or when `force` is true, downloads the latest release zip (or
 * the main branch archive if no releases exist), extracts all `.md` agent files,
 * and writes a `.version.json` marker so subsequent calls are no-ops unless the
 * remote version changed.
 */
export async function installOfficialAgents(
  env: NodeJS.ProcessEnv = process.env,
  opts: { force?: boolean } = {},
): Promise<{ version: string; count: number }> {
  const officialDir = getOfficialAgentsDir(env);

  const release = await fetchLatestRelease();
  const version = release?.tag ?? "main";

  // No-op if already on the current released version. The "main" fallback
  // (used when the repo has no releases yet) is a mutable branch, so it must
  // always re-fetch — comparing the literal string "main" to itself would
  // pin the install forever.
  if (!opts.force && version !== "main") {
    const installed = getInstalledVersion(env);
    if (installed?.version === version && existsSync(officialDir)) {
      return { version, count: countAgentFiles(officialDir) };
    }
  }

  // Fall back to the main branch archive when the repo has no releases yet
  const zipUrl = release?.zipUrl ?? `https://github.com/${AGENTS_REPO}/archive/refs/heads/main.zip`;

  const res = await fetch(zipUrl, { headers: { "User-Agent": "agentgg-cli" } });
  if (!res.ok) {
    throw new Error(`Failed to download agentgg-agents: ${res.status} ${res.statusText}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());

  mkdirSync(officialDir, { recursive: true });

  // Clear the previous catalog before extracting the fresh pack. Tracks the
  // path relative to the catalog root so it removes stale semgrep rules too —
  // otherwise a rule deleted upstream would linger and keep resolving.
  function removeCatalogFiles(dir: string, rel = ""): void {
    for (const f of readdirSync(dir)) {
      const abs = join(dir, f);
      const relPath = rel ? `${rel}/${f}` : f;
      if (statSync(abs).isDirectory()) {
        removeCatalogFiles(abs, relPath);
        // Drop the directory once emptied, so a category deleted upstream
        // doesn't linger. It matters in one case: with `agents/` absent, a
        // stale empty `base/` makes `defaultAgentDirs` return a directory
        // with no agents, and the scan hard-fails instead of falling back.
        if (readdirSync(abs).length === 0) rmSync(abs, { recursive: true });
      } else if (isRemovableCatalogFile(relPath)) {
        rmSync(abs);
      }
    }
  }
  removeCatalogFiles(officialDir);

  // Extract .md files, preserving directory structure but stripping the
  // top-level archive prefix (e.g. "agentgg-agents-main/default/sql-injection.md"
  // → "~/.agentgg/agentgg-agents/default/sql-injection.md")
  const zip = new AdmZip(buf);
  const entries = zip.getEntries();

  // Find the top-level prefix from the first directory entry
  const topPrefix = entries.find((e) => e.isDirectory)?.entryName.split("/")[0] ?? "";

  let count = 0;
  for (const entry of entries) {
    if (entry.isDirectory) continue;

    // Strip "agentgg-agents-main/" prefix, keep the rest of the path
    const relative = topPrefix ? entry.entryName.slice(topPrefix.length + 1) : entry.entryName;
    if (!relative || !isCatalogFile(relative)) continue;

    const destPath = join(officialDir, relative);
    mkdirSync(dirname(destPath), { recursive: true });
    writeFileSync(destPath, entry.getData());
    if (isAgentFile(relative)) count++;
  }

  writeFileSync(
    getOfficialAgentsVersionPath(env),
    JSON.stringify({ version, installedAt: new Date().toISOString() }, null, 2),
  );

  return { version, count };
}
