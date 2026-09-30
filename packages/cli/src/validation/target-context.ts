import { readFileSync } from "node:fs";

export function readTargetContext(raw: string | undefined): string | undefined {
  if (raw === undefined || !raw.startsWith("@")) return raw;
  const path = raw.slice(1);
  try {
    return readFileSync(path, "utf8");
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`could not read --target-context file ${path}: ${reason}`);
  }
}
