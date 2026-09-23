// Copyright 2026 The agentgg Authors. SPDX-License-Identifier: Apache-2.0

// What the live-validation pass says about a finding, in the words a reader
// needs. Kept free of node imports and reachable as `@agentgg/core/live`, so
// the viewer and the reporters render the same story from the same rules.

import type { Finding } from "./types.js";
import { effectiveVerdict } from "./verdict.js";

const ALIASES: Record<string, string> = {
  sqli: "sql-injection",
  "sql-inj": "sql-injection",
  xss: "xss",
  "cross-site-scripting": "xss",
  "reflected-xss": "xss",
  "stored-xss": "xss",
  idor: "idor",
  "insecure-direct-object-reference": "idor",
  "broken-access-control": "idor",
  ssrf: "ssrf",
  "open-redirect": "open-redirect",
  csrf: "csrf",
  "path-traversal": "path-traversal",
  "directory-traversal": "path-traversal",
  "auth-bypass": "auth-bypass",
  "authentication-bypass": "auth-bypass",
  "command-injection": "command-injection",
  rce: "command-injection",
};

const WEB_REACHABLE = new Set([
  "sql-injection",
  "xss",
  "idor",
  "ssrf",
  "open-redirect",
  "csrf",
  "path-traversal",
  "auth-bypass",
  "command-injection",
]);

// CWE is a controlled vocabulary, so it is checked first; `vulnSlug` is free
// text and the same class arrives under many spellings.
const WEB_REACHABLE_CWES = new Set([
  22, // path traversal
  77, // command injection
  78, // OS command injection
  79, // XSS
  89, // SQL injection
  284, // improper access control
  285, // improper authorization
  287, // improper authentication
  352, // CSRF
  601, // open redirect
  639, // IDOR: authorization bypass through a user-controlled key
  862, // missing authorization
  863, // incorrect authorization
  918, // SSRF
]);

export function normalizeVulnSlug(slug: string): string {
  const s = slug.trim().toLowerCase();
  return ALIASES[s] ?? s;
}

function cweIds(references: readonly string[]): number[] {
  const ids: number[] = [];
  for (const ref of references) {
    for (const m of ref.matchAll(/\bCWE-(\d+)\b/gi)) ids.push(Number(m[1]));
  }
  return ids;
}

/** Whether a browser can drive this finding at all. A class that fails this
 *  never reaches the live pass, so its missing result is not a failure. */
export function isWebReachable(f: Finding): boolean {
  if (f.dedup) return false;
  if (cweIds(f.references ?? []).some((id) => WEB_REACHABLE_CWES.has(id))) return true;
  return WEB_REACHABLE.has(normalizeVulnSlug(f.vulnSlug));
}

export const TIMEOUT_PREFIX = "reproduction timed out after";

export type LiveStateKind =
  | "reproduced"
  | "refuted"
  | "timed-out"
  | "inconclusive"
  | "error"
  | "refused"
  | "duplicate"
  | "out-of-scope"
  | "not-reachable"
  | "not-run";

export interface LiveState {
  kind: LiveStateKind;
  /** Short label for a chip or a table cell. */
  label: string;
  /** One sentence a reader can act on. */
  detail: string;
  /** False when the state says nothing about the code, only about the run. */
  tellsAboutCode: boolean;
}

const STATES: Record<LiveStateKind, Omit<LiveState, "kind">> = {
  reproduced: {
    label: "reproduced",
    detail: "The live test drove this against a running target and captured the proof.",
    tellsAboutCode: true,
  },
  refuted: {
    label: "refuted",
    detail: "The live test tried this against a running target and could not make it happen.",
    tellsAboutCode: true,
  },
  "timed-out": {
    label: "timed out",
    detail: "The live test ran out of time before it reached an answer. Nothing was ruled out.",
    tellsAboutCode: false,
  },
  inconclusive: {
    label: "inconclusive",
    detail: "The live test finished without proof either way. Nothing was ruled out.",
    tellsAboutCode: false,
  },
  error: {
    label: "run failed",
    detail: "The live test broke before it reached an answer. This says nothing about the code.",
    tellsAboutCode: false,
  },
  refused: {
    label: "refused",
    detail: "The live test declined to run this one. This says nothing about the code.",
    tellsAboutCode: false,
  },
  // Both of these are replaced per finding by `detailFor`. The text here is
  // the fallback for a record that is missing the field it names.
  duplicate: {
    label: "not tested live",
    detail: "This finding repeats another one. Only that one is tested.",
    tellsAboutCode: false,
  },
  "out-of-scope": {
    label: "not tested live",
    detail: "The review judged this out of scope, so nothing tested it.",
    tellsAboutCode: false,
  },
  "not-reachable": {
    label: "not testable live",
    detail: "A browser cannot drive this class of issue, so the live test skipped it.",
    tellsAboutCode: false,
  },
  "not-run": {
    label: "not tested live",
    detail: "No live test ran. Add a target URL to test this one against a running app.",
    tellsAboutCode: false,
  },
};

/** The single live state of a finding, with the empty and failure cases kept
 *  apart: "we could not test it" must never read as "it is not real". */
export function liveState(f: Finding): LiveState {
  const kind = liveStateKind(f);
  return { kind, ...STATES[kind], detail: detailFor(f, kind) };
}

/**
 * Two states can say more than a fixed sentence, and saying less would be
 * wrong. A duplicate knows which finding it repeats. `out-of-scope` comes
 * either from the user's scope file or from the reviewer's own judgement,
 * and only `scopeRef` tells the two apart.
 */
function detailFor(f: Finding, kind: LiveStateKind): string {
  if (kind === "duplicate" && f.dedup) {
    // Never claim the primary holds proof. It may not have been tested either.
    return `This repeats finding ${f.dedup.duplicateOf}. Only that one is tested.`;
  }
  if (kind === "out-of-scope" && f.validation?.scopeRef) {
    return `Your scope file excludes this (${f.validation.scopeRef}), so nothing tested it.`;
  }
  return STATES[kind].detail;
}

function liveStateKind(f: Finding): LiveStateKind {
  const live = f.live;
  if (!live) {
    // Each of these skips is deliberate, and a reader must not read any of
    // them as "the live test tried and failed".
    if (f.dedup) return "duplicate";
    if (f.validation?.verdict === "out-of-scope") return "out-of-scope";
    return isWebReachable(f) ? "not-run" : "not-reachable";
  }
  if (live.refused) return "refused";
  if (live.result === "error") return "error";
  if (live.result === "reproduced") return "reproduced";
  if (live.result === "refuted") return "refuted";
  return live.reasoning.trimStart().startsWith(TIMEOUT_PREFIX) ? "timed-out" : "inconclusive";
}

/**
 * Whether the live test moved the verdict off what static review said. Only
 * then does the combined verdict need explaining: when the two agree, the
 * badge and the two sections already say it.
 */
export function verdictConflict(f: Finding): boolean {
  const staticVerdict = f.validation?.verdict;
  return staticVerdict !== undefined && effectiveVerdict(f) !== staticVerdict;
}

/**
 * Why the combined verdict reads the way it does, in one plain sentence.
 * Derived from the same inputs as `effectiveVerdict`, so the two cannot drift.
 * Returns undefined when nothing has judged the finding yet.
 */
export function verdictStory(f: Finding): string | undefined {
  const combined = effectiveVerdict(f);
  if (!combined) return undefined;
  const staticVerdict = f.validation?.verdict;
  const state = liveState(f);

  if (staticVerdict === "out-of-scope") {
    return f.validation?.scopeRef
      ? `Your scope file excludes this (${f.validation.scopeRef}). The review stopped there.`
      : "The review judged this out of scope and stopped there.";
  }
  if (!staticVerdict) {
    return state.kind === "reproduced"
      ? "Static review reached no verdict. The live test reproduced it."
      : "Static review reached no verdict. The live test could not settle it.";
  }
  if (!state.tellsAboutCode) {
    return `Static review said ${staticVerdict}. ${state.detail} The static verdict stands.`;
  }
  if (state.kind === "reproduced") {
    return staticVerdict === "false-positive"
      ? "Static review called this a false positive, but the live test reproduced it. Read both."
      : `Static review said ${staticVerdict}. The live test reproduced it.`;
  }
  return staticVerdict === "confirmed"
    ? "Static review confirmed it, but the live test could not. Treat it as unsettled."
    : `Static review said ${staticVerdict}. The live test could not reproduce it.`;
}
