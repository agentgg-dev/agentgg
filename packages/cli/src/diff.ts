import { execFileSync } from "node:child_process";
import { sep } from "node:path";

/**
 * List paths changed between a commit and the working tree, using
 * `git diff --name-only <commit>`. Paths come back POSIX-style relative
 * to the repo root, matching what the walker emits.
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
  runner: (commit: string, cwd: string) => string = gitDiffNameOnly,
): string[] {
  const raw = runner(commit, rootDir);
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map(toPosix);
}

function gitDiffNameOnly(commit: string, cwd: string): string {
  try {
    return execFileSync(
      "git",
      ["diff", "--name-only", "--diff-filter=ACMRTUB", commit],
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
      `git diff --name-only ${commit} failed.${suffix}\n` +
        `  Check that '${commit}' is a valid commit SHA reachable in this repo.`,
    );
  }
}

function toPosix(p: string): string {
  return sep === "\\" ? p.split(sep).join("/") : p;
}
