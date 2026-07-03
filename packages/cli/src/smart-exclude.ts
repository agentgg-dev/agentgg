import type { Detector, SuggestExcludesResult } from "./detect.js";
import { loadExcludeInstructions } from "./exclude-agent.js";
import { collectAllFiles } from "./walker.js";

/**
 * Smart-exclude orchestration. Opt-in (`--auto-exclude`), run once at the
 * very start of a scan, BEFORE recon. It renders the repo's directory
 * layout, asks the model which folders are not worth security-scanning
 * (tests, fixtures, generated code, vendored deps, docs, sample data),
 * and returns those as globs. scan.ts folds them into `excludePatterns`
 * so they behave exactly like a user-typed `--exclude`: invisible to
 * recon, the precondition census, and every agent.
 *
 * The pass is a single no-tools structured call: the directory tree is in
 * the prompt, so the model classifies folders instead of exploring. That
 * keeps it cheap enough to run ahead of the whole scan.
 */

export interface RunSmartExcludeOptions {
  rootDir: string;
  detector: Detector;
  /** Baseline walk excludes (default set + CLI `--exclude`) already applied. */
  excludePatterns: string[];
  includePatterns: string[];
  maxFileSizeBytes: number;
  signal?: AbortSignal;
}

/**
 * Render the directory layout as a flat, full-path listing: each folder
 * with the recursive count of files under it. This is the only repo view
 * the (no-tools) model gets, so it must stay bounded regardless of repo
 * size. Folders already pruned by the caller's excludes never appear,
 * because they aren't in `files`.
 *
 * There is NO depth cap: a deep vendored/generated/test folder has to be
 * visible to be excludable, and those buried folders are exactly the ones
 * worth dropping. The file count doubles as the ranking signal: it's how
 * many files a scan would spend on that folder, so when the listing is
 * over budget we keep the highest-count folders (which, since a parent's
 * count is always >= any child's, keeps ancestors too) and drop the
 * trivial leaf folders first.
 */
export function renderDirTree(files: string[], opts: { maxDirs?: number } = {}): string {
  const maxDirs = opts.maxDirs ?? 400;

  // dir path (POSIX, no trailing slash) -> recursive file count, all depths.
  const counts = new Map<string, number>();
  let rootFiles = 0;
  for (const f of files) {
    const parts = f.split("/");
    if (parts.length === 1) {
      rootFiles++;
      continue;
    }
    for (let d = 1; d < parts.length; d++) {
      const dir = parts.slice(0, d).join("/");
      counts.set(dir, (counts.get(dir) ?? 0) + 1);
    }
  }

  let dirs = [...counts.keys()];
  let omitted = 0;
  if (dirs.length > maxDirs) {
    // Keep the biggest folders (most expensive to scan, most worth
    // excluding) at any depth, then list by path so the layout reads
    // top-down.
    dirs.sort((a, b) => (counts.get(b) ?? 0) - (counts.get(a) ?? 0));
    omitted = dirs.length - maxDirs;
    dirs = dirs.slice(0, maxDirs);
  }
  dirs.sort();

  const lines: string[] = [];
  if (rootFiles > 0) lines.push(`. (${rootFiles} files at repo root)`);
  for (const d of dirs) lines.push(`${d}/  (${counts.get(d)} files)`);
  if (omitted > 0) lines.push(`... (+${omitted} smaller leaf folders omitted)`);
  return lines.join("\n");
}

/**
 * Run the pass and return the suggested excludes. On an empty tree,
 * returns []. Detector/transport errors propagate; the caller (scan.ts)
 * treats smart-exclude as advisory and continues without it on failure.
 */
export async function runSmartExclude(
  opts: RunSmartExcludeOptions,
): Promise<SuggestExcludesResult["excludes"]> {
  const files = collectAllFiles(opts.rootDir, {
    excludePatterns: opts.excludePatterns,
    includePatterns: opts.includePatterns,
    maxFileSizeBytes: opts.maxFileSizeBytes,
  });
  if (files.length === 0) return [];

  const result = await opts.detector.suggestExcludes({
    instructions: loadExcludeInstructions(),
    dirTree: renderDirTree(files),
    signal: opts.signal,
  });
  return result.excludes;
}
