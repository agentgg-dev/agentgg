import { existsSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

// A path from a model or a record is untrusted, and a link can point anywhere,
// so every read of a repository file checks the REAL path against the real root.

function climbsOut(rel: string): boolean {
  return rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel);
}

/** The real path of `path` when it exists inside the real `root`, else undefined. */
export function resolveInsideRoot(root: string, path: string): string | undefined {
  let realRoot: string;
  let real: string;
  try {
    realRoot = realpathSync.native(root);
    real = realpathSync.native(resolve(root, path));
  } catch {
    return undefined;
  }
  return climbsOut(relative(realRoot, real)) ? undefined : real;
}

/**
 * True when `path` names a place outside `root`: an existing path whose real
 * location is outside, or a missing path that climbs out. No path is false.
 */
export function namesOutsideRoot(root: string, path: string | null | undefined): boolean {
  if (path == null || path.trim() === "") return false;
  const abs = resolve(root, path);
  if (existsSync(abs)) return resolveInsideRoot(root, path) === undefined;
  return climbsOut(relative(resolve(root), abs));
}

/** Read a repository file. Throws when it is missing or outside `root`. */
export function readRepoFileSync(root: string, path: string): string {
  const real = resolveInsideRoot(root, path);
  if (real === undefined) throw new Error(`${path} is not a file inside the repository`);
  return readFileSync(real, "utf8");
}
