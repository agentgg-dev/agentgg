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
import AdmZip from "adm-zip";
import { getOfficialAgentsDir, getOfficialAgentsVersionPath } from "@agentgg/core";

const AGENTS_REPO = "agentgg-dev/agentgg-agents";
const GITHUB_API = "https://api.github.com";

interface VersionInfo {
  version: string;
  installedAt: string;
}

export function getInstalledVersion(
  env: NodeJS.ProcessEnv = process.env,
): VersionInfo | null {
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

  // No-op if already on the current version
  if (!opts.force) {
    const installed = getInstalledVersion(env);
    if (installed?.version === version && existsSync(officialDir)) {
      const count = readdirSync(officialDir).filter((f) => f.endsWith(".md")).length;
      return { version, count };
    }
  }

  // Fall back to the main branch archive when the repo has no releases yet
  const zipUrl =
    release?.zipUrl ??
    `https://github.com/${AGENTS_REPO}/archive/refs/heads/main.zip`;

  const res = await fetch(zipUrl, { headers: { "User-Agent": "agentgg-cli" } });
  if (!res.ok) {
    throw new Error(
      `Failed to download agentgg-agents: ${res.status} ${res.statusText}`,
    );
  }
  const buf = Buffer.from(await res.arrayBuffer());

  mkdirSync(officialDir, { recursive: true });

  // Remove all existing .md files (recursively) before extracting the fresh pack
  function removeAgentFiles(dir: string): void {
    for (const f of readdirSync(dir)) {
      const abs = join(dir, f);
      if (statSync(abs).isDirectory()) {
        removeAgentFiles(abs);
      } else if (f.endsWith(".md")) {
        rmSync(abs);
      }
    }
  }
  removeAgentFiles(officialDir);

  // Extract .md files, preserving directory structure but stripping the
  // top-level archive prefix (e.g. "agentgg-agents-main/default/sql-injection.md"
  // → "~/.agentgg/agentgg-agents/default/sql-injection.md")
  const zip = new AdmZip(buf);
  const entries = zip.getEntries();

  // Find the top-level prefix from the first directory entry
  const topPrefix = entries.find((e) => e.isDirectory)?.entryName.split("/")[0] ?? "";

  let count = 0;
  for (const entry of entries) {
    if (entry.isDirectory || !entry.name.endsWith(".md")) continue;

    // Strip "agentgg-agents-main/" prefix, keep the rest of the path
    const relative = topPrefix
      ? entry.entryName.slice(topPrefix.length + 1)
      : entry.entryName;
    if (!relative) continue;

    const destPath = join(officialDir, relative);
    mkdirSync(dirname(destPath), { recursive: true });
    writeFileSync(destPath, entry.getData());
    count++;
  }

  writeFileSync(
    getOfficialAgentsVersionPath(env),
    JSON.stringify({ version, installedAt: new Date().toISOString() }, null, 2),
  );

  return { version, count };
}
