// Copyright 2026 The agentgg Authors. SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { getDataDir, getOfficialAgentsVersionPath } from "@agentgg/core";
import { VERSION as CLI_VERSION } from "./version.js";

/**
 * Background update-availability check for the CLI and the agents catalog.
 *
 * Pattern matches `update-notifier`, `firebase-tools`, etc.: read a 24h
 * cache, print a banner now if the cache says something is stale, kick off
 * a refresh fetch in the background so the *next* invocation sees the
 * latest. Never blocks the current command on the wire.
 *
 * Two version sources:
 *   - CLI:    npm registry's `agentgg/latest` (semver)
 *   - Agents: the `tag_name` of the latest release on the agentgg-agents
 *             repo, written locally to `<dataDir>/agentgg-agents/.version.json`
 *             by `agentgg agents update` (see `agents-install.ts`).
 *
 * Disabled when stdout isn't a TTY, when `--json` is in argv, or when
 * `AGENTGG_NO_UPDATE_CHECK=1` is set — same posture other CLIs take so
 * scripts / CI never get surprised by a banner.
 */

const NPM_REGISTRY = "https://registry.npmjs.org";
const GITHUB_API = "https://api.github.com";
const AGENTS_REPO = "agentgg-dev/agentgg-agents";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 3000;
const CLI_PKG = "agentgg";

interface PkgCache {
  checkedAt: string;
  latest: string;
}

interface UpdateCache {
  cli?: PkgCache;
  agents?: PkgCache;
}

function getCachePath(env: NodeJS.ProcessEnv = process.env): string {
  return join(getDataDir(env), ".update-check.json");
}

function loadCache(): UpdateCache {
  const path = getCachePath();
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, "utf8")) as UpdateCache;
  } catch {
    return {};
  }
}

function saveCache(cache: UpdateCache): void {
  const path = getCachePath();
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(cache, null, 2));
  } catch {
    // Best-effort. A failed cache write must never break the CLI.
  }
}

function isFresh(entry: PkgCache | undefined): boolean {
  if (!entry) return false;
  const checkedAt = Date.parse(entry.checkedAt);
  if (Number.isNaN(checkedAt)) return false;
  return Date.now() - checkedAt < CACHE_TTL_MS;
}

/** Tolerate the `v` prefix that the agents repo uses on its release tags. */
function normalize(version: string): string {
  return version.startsWith("v") ? version.slice(1) : version;
}

/** True iff `latest` is a strictly higher semver than `current` (plain x.y.z). */
function isNewer(current: string, latest: string): boolean {
  const c = normalize(current).split(".").map(Number);
  const l = normalize(latest).split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const a = c[i] ?? 0;
    const b = l[i] ?? 0;
    if (b !== a) return b > a;
  }
  return false;
}

async function fetchWithTimeout(url: string, headers: Record<string, string>): Promise<unknown> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { headers, signal: ctrl.signal });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchLatestNpmVersion(pkg: string): Promise<string | null> {
  const data = (await fetchWithTimeout(`${NPM_REGISTRY}/${pkg}/latest`, {
    Accept: "application/json",
  })) as { version?: string } | null;
  return typeof data?.version === "string" ? data.version : null;
}

async function fetchLatestAgentsTag(): Promise<string | null> {
  const data = (await fetchWithTimeout(`${GITHUB_API}/repos/${AGENTS_REPO}/releases/latest`, {
    Accept: "application/vnd.github+json",
    "User-Agent": "agentgg-cli",
  })) as { tag_name?: string } | null;
  return typeof data?.tag_name === "string" ? data.tag_name : null;
}

function getInstalledAgentsVersion(): string | null {
  try {
    const path = getOfficialAgentsVersionPath();
    if (!existsSync(path)) return null;
    const data = JSON.parse(readFileSync(path, "utf8")) as { version?: string };
    return typeof data.version === "string" ? data.version : null;
  } catch {
    return null;
  }
}

function shouldSkip(argv: string[]): boolean {
  if (process.env.AGENTGG_NO_UPDATE_CHECK === "1") return true;
  if (!process.stdout.isTTY) return true;
  if (argv.includes("--json")) return true;
  return false;
}

function renderBanner(parts: {
  cli?: { current: string; latest: string };
  agents?: { current: string; latest: string };
}): string {
  const LABEL = "Update available";
  const indent = " ".repeat(LABEL.length);
  const CLI_NAME = "agentgg";
  const AGENTS_NAME = "agentgg-agents";
  const nameWidth = Math.max(
    parts.cli ? CLI_NAME.length : 0,
    parts.agents ? AGENTS_NAME.length : 0,
  );

  const updateLines: string[] = [];
  if (parts.cli) {
    updateLines.push(
      `${LABEL}  ${CLI_NAME.padEnd(nameWidth)} ${parts.cli.current} → ${parts.cli.latest}`,
    );
  }
  if (parts.agents) {
    const prefix = updateLines.length === 0 ? LABEL : indent;
    updateLines.push(
      `${prefix}  ${AGENTS_NAME.padEnd(nameWidth)} ${parts.agents.current} → ${parts.agents.latest}`,
    );
  }

  const cmds: string[] = [];
  if (parts.cli) cmds.push("npm i -g agentgg");
  if (parts.agents) cmds.push("agentgg agents update");
  const runLine = `Run: ${cmds.join(" && ")}`;

  const content = [...updateLines, runLine];
  const inner = Math.max(...content.map((l) => l.length));
  const top = `┌${"─".repeat(inner + 4)}┐`;
  const bottom = `└${"─".repeat(inner + 4)}┘`;
  const body = content.map((l) => `│  ${l.padEnd(inner, " ")}  │`).join("\n");
  return [top, body, bottom].join("\n");
}

function reportFromCache(): void {
  const cache = loadCache();
  const cli =
    cache.cli && isNewer(CLI_VERSION, cache.cli.latest)
      ? { current: CLI_VERSION, latest: cache.cli.latest }
      : undefined;

  const installedAgents = getInstalledAgentsVersion();
  const agents =
    installedAgents && cache.agents && isNewer(installedAgents, cache.agents.latest)
      ? { current: installedAgents, latest: cache.agents.latest }
      : undefined;

  if (!cli && !agents) return;
  console.error(renderBanner({ cli, agents }));
}

async function refreshCache(): Promise<void> {
  const cache = loadCache();
  const now = new Date().toISOString();

  const tasks: Promise<void>[] = [];
  if (!isFresh(cache.cli)) {
    tasks.push(
      fetchLatestNpmVersion(CLI_PKG).then((v) => {
        if (v) cache.cli = { checkedAt: now, latest: v };
      }),
    );
  }
  if (!isFresh(cache.agents)) {
    tasks.push(
      fetchLatestAgentsTag().then((v) => {
        if (v) cache.agents = { checkedAt: now, latest: v };
      }),
    );
  }
  if (tasks.length === 0) return;
  await Promise.all(tasks);
  saveCache(cache);
}

/**
 * Print the update banner (if applicable) from cached info, and kick off a
 * background refresh for the next invocation. Safe to call at every CLI
 * startup — no-ops in CI/scripted contexts and when the cache is fresh.
 *
 * Synchronous return; the background refresh is fire-and-forget so we
 * never block the command. Quick commands (`--help`) may see Node wait a
 * moment for the fetch to settle on cache-miss runs; the 3s fetch timeout
 * caps that worst case.
 */
export function checkAndReportUpdates(argv: string[]): void {
  if (shouldSkip(argv)) return;
  reportFromCache();
  void refreshCache().catch(() => {
    // Network failures are expected (offline use, GitHub down, etc.)
    // and must never surface to the user — the banner just won't update.
  });
}
