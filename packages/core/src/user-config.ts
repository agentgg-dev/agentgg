import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { getConfigPath } from "./paths.js";
import { UserConfig } from "./types.js";

/**
 * Load the user-level config from `~/.agentgg/config.json` (or
 * `$AGENTGG_HOME/config.json`).
 *
 * Returns `null` when the file does not exist — callers should treat that
 * as "user has never run init" rather than an error. Throws on malformed
 * JSON or on schema validation failure; both are real problems the user
 * should see.
 */
export function loadUserConfig(env: NodeJS.ProcessEnv = process.env): UserConfig | null {
  const path = getConfigPath(env);
  if (!existsSync(path)) return null;
  const raw = readFileSync(path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse ${path}: ${(err as Error).message}`);
  }
  return UserConfig.parse(parsed);
}

/**
 * Persist a UserConfig to disk. Creates the parent directory if missing
 * and best-effort tightens the file to 0600 (no-op on Windows; correct on
 * Linux/macOS).
 *
 * The schema is validated before writing — better to refuse than to write
 * a file the next `load` will reject.
 */
export function saveUserConfig(config: UserConfig, env: NodeJS.ProcessEnv = process.env): string {
  const validated = UserConfig.parse(config);
  const path = getConfigPath(env);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(validated, null, 2)}\n`, "utf8");
  try {
    chmodSync(path, 0o600);
  } catch {
    // chmod is a no-op on Windows for permission bits — silently skip.
  }
  return path;
}
