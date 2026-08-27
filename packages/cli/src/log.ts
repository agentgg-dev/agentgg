// Copyright 2026 The agentgg Authors. SPDX-License-Identifier: Apache-2.0

/**
 * Level-prefixed diagnostics: `[INFO]`, `[WARN]`, `[ERROR]`.
 *
 * Streams match the call sites these replaced, so piping behavior does not
 * change: INFO defaults to stdout, WARN and ERROR go to stderr. Pass
 * `"err"` for a status line that already lived on stderr.
 *
 * Product output stays bare — reports, tables, JSON, banners and the indented
 * detail lines under a prefixed message. A prefix there would break `--json`
 * and the report layout.
 *
 * A message that already carries a scope tag keeps it after the level:
 * `[WARN] [runAgent:slug] ...`.
 */

export function logInfo(msg: string, stream: "out" | "err" = "out"): void {
  const line = `[INFO] ${msg}`;
  if (stream === "err") console.error(line);
  else console.log(line);
}

export function logWarn(msg: string): void {
  console.warn(`[WARN] ${msg}`);
}

export function logError(msg: string): void {
  console.error(`[ERROR] ${msg}`);
}
