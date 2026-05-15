import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

/**
 * Strict allowlist for path segments that get joined onto a state dir.
 * Rejects empty/`.`/`..`/null bytes/path separators so a malicious
 * runId can't escape `<outputDir>/state/runs/`.
 */
export function assertSafeSegment(name: string, label = "segment"): void {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error(`Invalid ${label}: must be a non-empty string`);
  }
  if (name === "." || name === "..") {
    throw new Error(`Invalid ${label}: ${JSON.stringify(name)}`);
  }
  if (name.includes("\0")) {
    throw new Error(`Invalid ${label}: contains null byte`);
  }
  if (name.includes("/") || name.includes("\\")) {
    throw new Error(`Invalid ${label}: contains path separator`);
  }
  if (isAbsolute(name)) {
    throw new Error(`Invalid ${label}: must not be absolute`);
  }
}

/**
 * FileRecord paths are repo-relative POSIX-style (forward slashes
 * between segments). Allow `/` separators but reject `..`, absolute
 * paths, null bytes, and backslashes (which would otherwise become
 * path separators on Windows and let a record path escape `files/`).
 */
export function assertSafeFilePath(filePath: string): void {
  if (typeof filePath !== "string" || filePath.length === 0) {
    throw new Error("Invalid filePath: must be a non-empty string");
  }
  if (filePath.includes("\0")) {
    throw new Error("Invalid filePath: contains null byte");
  }
  if (filePath.includes("\\")) {
    throw new Error("Invalid filePath: contains backslash");
  }
  if (isAbsolute(filePath)) {
    throw new Error("Invalid filePath: must not be absolute");
  }
  for (const part of filePath.split("/")) {
    if (part === "" || part === "." || part === "..") {
      throw new Error(`Invalid filePath: contains "${part}" segment`);
    }
  }
}

/**
 * Resolve the agentgg config directory. Honors `AGENTGG_HOME` for tests
 * and power users who want to keep config out of `~`. Defaults to
 * `~/.agentgg/` on every platform — same pattern other Node CLIs
 * follow (gh, claude, codex, etc.).
 *
 * NB: this is purely for **LLM credentials and the user's custom
 * agents catalog**. Scan state does NOT live here; it lives in the
 * `--output` dir of each scan. See `getStateDir` below.
 */
export function getDataDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.AGENTGG_HOME) return env.AGENTGG_HOME;
  return join(homedir(), ".agentgg");
}

/** Path to the user-level config file: `<dataDir>/config.json`. */
export function getConfigPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(getDataDir(env), "config.json");
}

/** Path to the agents subdirectory: `<dataDir>/agents/`. */
export function getAgentsDir(env: NodeJS.ProcessEnv = process.env): string {
  return join(getDataDir(env), "agents");
}

/** Path to the official agents directory: `<dataDir>/agentgg-agents/` — populated by `agentgg agents update`. */
export function getOfficialAgentsDir(env: NodeJS.ProcessEnv = process.env): string {
  return join(getDataDir(env), "agentgg-agents");
}

/** Path to the version marker: `<dataDir>/agentgg-agents/.version.json`. */
export function getOfficialAgentsVersionPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(getOfficialAgentsDir(env), ".version.json");
}

// ---------------------------------------------------------------------------
// Per-scan state — lives inside each scan's --output dir
// ---------------------------------------------------------------------------
//
// One-shot tool, nuclei-style: every scan owns its own state dir, no
// global cache, no `projectId` abstraction. Re-running `scan` with the
// same `--output` resumes from this state; using a different `--output`
// is a fresh scan. `status` and `revalidate` operate on the same dir
// the scan wrote into.
//
// Layout:
//
//   <outputDir>/
//     summary.md
//     findings/...                    human-facing report
//     state/
//       scan.json                     ScanMeta (root path + timestamps)
//       runs/<runId>.json             RunMeta (one per scan / revalidate)
//       files/<relativePath>.json     FileRecord (one per scanned source file)

/** `<outputDir>/state/` — root of everything `status` / `revalidate` read. */
export function getStateDir(outputDir: string): string {
  return join(outputDir, "state");
}

/** `<outputDir>/state/scan.json` — `ScanMeta` sidecar (root + timestamps). */
export function getScanMetaPath(outputDir: string): string {
  return join(getStateDir(outputDir), "scan.json");
}

/** `<outputDir>/state/files/` — mirrors the scan root, one `.json` per file. */
export function getStateFilesDir(outputDir: string): string {
  return join(getStateDir(outputDir), "files");
}

/** `<outputDir>/state/files/<filePath>.json` — one `FileRecord` per source file. */
export function getFileRecordPath(outputDir: string, filePath: string): string {
  assertSafeFilePath(filePath);
  return join(getStateFilesDir(outputDir), `${filePath}.json`);
}

/** `<outputDir>/state/runs/` — one `RunMeta` `.json` per run. */
export function getStateRunsDir(outputDir: string): string {
  return join(getStateDir(outputDir), "runs");
}

/** `<outputDir>/state/runs/<runId>.json` — `RunMeta` for one run. */
export function getRunMetaPath(outputDir: string, runId: string): string {
  assertSafeSegment(runId, "runId");
  return join(getStateRunsDir(outputDir), `${runId}.json`);
}
