// Copyright 2026 The agentgg Authors. SPDX-License-Identifier: Apache-2.0

// Kept free of node imports and reachable as `@agentgg/core/verdict`, so a
// browser bundle can call it without pulling in the filesystem layer.

import type { Finding } from "./types.js";

/**
 * The one verdict a reader sees: the static verdict and the live result
 * combined. A live result never pushes a verdict below `uncertain`, and a
 * live `reproduced` only reaches `confirmed` when static did not reject it.
 * A live run that found no proof takes a static `confirmed` down to
 * `uncertain`; a broken run or a refusal leaves the static verdict alone.
 */
export function effectiveVerdict(
  f: Finding,
): "confirmed" | "false-positive" | "out-of-scope" | "uncertain" | undefined {
  const staticVerdict = f.validation?.verdict;
  const live = f.live?.result;
  if (staticVerdict === "out-of-scope") return "out-of-scope";
  if (live === undefined || live === "error" || live === "not-reproducible" || f.live?.refused)
    return staticVerdict;
  if (staticVerdict === undefined) {
    if (live === "reproduced") return "confirmed";
    return live === "refuted" ? "uncertain" : undefined;
  }
  if (live === "reproduced") {
    return staticVerdict === "false-positive" ? "uncertain" : "confirmed";
  }
  if (staticVerdict === "confirmed") return "uncertain";
  return staticVerdict;
}
