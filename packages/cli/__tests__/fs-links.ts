import { symlinkSync } from "node:fs";

/** A folder link. On Windows this is a junction, which needs no admin rights. */
export function linkDir(target: string, path: string): void {
  symlinkSync(target, path, "junction");
}

/** A file link, or false when the OS refuses one (Windows without admin rights). */
export function tryLinkFile(target: string, path: string): boolean {
  try {
    symlinkSync(target, path, "file");
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EPERM") return false;
    throw err;
  }
}
