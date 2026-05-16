import { execFileSync } from "node:child_process";
import { sep } from "node:path";

/**
 * List paths changed *in* a single commit, using
 * `git diff-tree --no-commit-id --name-only -r <commit>`. Paths come
 * back POSIX-style relative to the repo root, matching what the walker
 * emits.
 *
 * This is the commit's own diff (parent → commit), not commit →
 * working tree. Reviewing a specific commit shouldn't be perturbed by
 * the user's local checkout state.
 *
 * Renames are returned as the destination filename (git's default
 * behavior). Deleted files would also appear; we filter them out via
 * the `--diff-filter=ACMRTUB` flag so callers don't try to scan a path
 * that no longer exists.
 *
 * Throws a friendly error when git isn't installed, the commit doesn't
 * exist, or the directory isn't a repo. The CLI surfaces those without
 * dumping a process stack trace.
 *
 * Test seam: callers can swap `runner` to inject a fake for unit tests.
 */
export function listChangedFiles(
  commit: string,
  rootDir: string,
  runner: (commit: string, cwd: string) => string = gitDiffTreeNameOnly,
): string[] {
  const raw = runner(commit, rootDir);
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map(toPosix);
}

function gitDiffTreeNameOnly(commit: string, cwd: string): string {
  try {
    return execFileSync(
      "git",
      [
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        "--diff-filter=ACMRTUB",
        commit,
      ],
      { cwd, encoding: "utf8" },
    );
  } catch (err) {
    const e = err as Error & { code?: string; stderr?: string };
    if (e.code === "ENOENT") {
      throw new Error(
        "git is not installed or not on PATH. --diff requires git to enumerate changed files.",
      );
    }
    const stderr = (e.stderr ?? "").toString().trim();
    const suffix = stderr ? `\n  ${stderr}` : "";
    throw new Error(
      `git diff-tree ${commit} failed.${suffix}\n` +
        `  Check that '${commit}' is a valid commit SHA reachable in this repo.`,
    );
  }
}

/**
 * Load the full `git show <commit>` output — commit metadata, message,
 * and the commit's patch. Used to inject context into hunt-mode prompts
 * so the hunter sees both *what* changed (the diff) and *why* (the
 * commit message).
 *
 * Bounded by the commit itself, not by how far the working tree has
 * drifted, so this stays small for normal commits.
 *
 * Same friendly-error contract as `listChangedFiles`. Test seam: swap
 * `runner` for unit tests.
 */
export function loadCommitPatch(
  commit: string,
  rootDir: string,
  runner: (commit: string, cwd: string) => string = gitShow,
): string {
  return runner(commit, rootDir);
}

function gitShow(commit: string, cwd: string): string {
  try {
    return execFileSync("git", ["show", commit], {
      cwd,
      encoding: "utf8",
      // Single commits are normally small, but the occasional vendored
      // import or generated-file commit can be tens of MB. 64 MB is
      // comfortable headroom without being absurd.
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (err) {
    const e = err as Error & { code?: string; stderr?: string };
    if (e.code === "ENOENT") {
      throw new Error(
        "git is not installed or not on PATH. --diff requires git to read the commit patch.",
      );
    }
    if (e.code === "ENOBUFS") {
      throw new Error(
        `git show ${commit} produced a patch larger than 64 MB — likely a vendored-code or generated-file commit. That's too large to inject into a hunt prompt; review it manually or narrow the scan.`,
      );
    }
    const stderr = (e.stderr ?? "").toString().trim();
    const suffix = stderr ? `\n  ${stderr}` : "";
    throw new Error(
      `git show ${commit} failed.${suffix}\n` +
        `  Check that '${commit}' is a valid commit SHA reachable in this repo.`,
    );
  }
}

function toPosix(p: string): string {
  return sep === "\\" ? p.split(sep).join("/") : p;
}
