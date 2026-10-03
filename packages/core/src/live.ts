// Copyright 2026 The agentgg Authors. SPDX-License-Identifier: Apache-2.0

// What the live-validation pass says about a finding, in the words a reader
// needs. Kept free of node imports and reachable as `@agentgg/core/live`, so
// the viewer and the reporters render the same story from the same rules.

import type { Finding, ValidationVerdict } from "./types.js";
import { effectiveVerdict } from "./verdict.js";

export const TIMEOUT_PREFIX = "reproduction timed out after";

export type LiveStateKind =
  | "reproduced"
  | "refuted"
  | "timed-out"
  | "inconclusive"
  | "error"
  | "not-reproducible"
  | "refused"
  | "duplicate"
  | "out-of-scope"
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
    detail: "The live test reproduced this issue against the running target and captured evidence.",
    tellsAboutCode: true,
  },
  refuted: {
    label: "refuted",
    detail: "The live test could not reproduce this issue against the running target.",
    tellsAboutCode: true,
  },
  "timed-out": {
    label: "timed out",
    detail:
      "The live test reached its time limit before it produced a result. The issue has not been ruled out.",
    tellsAboutCode: false,
  },
  inconclusive: {
    label: "inconclusive",
    detail: "The live test finished without conclusive evidence. The issue has not been ruled out.",
    tellsAboutCode: false,
  },
  error: {
    label: "run failed",
    detail:
      "The live test did not complete because of an error. This does not indicate whether the issue exists.",
    tellsAboutCode: false,
  },
  "not-reproducible": {
    label: "nothing to reproduce",
    detail:
      "This type of finding describes a missing security control, not an exploitable behavior, so a live test cannot demonstrate it.",
    tellsAboutCode: false,
  },
  refused: {
    label: "refused",
    detail:
      "The testing agent declined to run this test. This does not indicate whether the issue exists.",
    tellsAboutCode: false,
  },
  // Both of these are replaced per finding by `detailFor`. The text here is
  // the fallback for a record that is missing the field it names.
  duplicate: {
    label: "not tested live",
    detail: "This finding duplicates another finding. Live tests run only on the original.",
    tellsAboutCode: false,
  },
  "out-of-scope": {
    label: "not tested live",
    detail: "The review marked this finding out of scope, so it was not tested live.",
    tellsAboutCode: false,
  },
  "not-run": {
    label: "not tested live",
    detail: "This finding was not tested live. Add a target URL to test it against a running app.",
    tellsAboutCode: false,
  },
};

const STATIC_VERDICT_SENTENCE: Record<ValidationVerdict, string> = {
  confirmed: "Static review confirmed this finding.",
  "false-positive": "Static review marked this finding as a false positive.",
  uncertain: "Static review marked this finding as uncertain.",
  "out-of-scope": "Static review marked this finding out of scope.",
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
    return `This finding duplicates finding ${f.dedup.duplicateOf}. Live tests run only on the original.`;
  }
  if (kind === "out-of-scope" && f.validation?.scopeRef) {
    return `Your scope file excludes this finding (${f.validation.scopeRef}), so it was not tested live.`;
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
    return "not-run";
  }
  if (live.refused) return "refused";
  if (live.result === "error") return "error";
  if (live.result === "not-reproducible") return "not-reproducible";
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
      ? `Your scope file excludes this finding (${f.validation.scopeRef}), so it was not reviewed further.`
      : "The review marked this finding out of scope, so it was not reviewed further.";
  }
  if (!staticVerdict) {
    return state.kind === "reproduced"
      ? "Static review did not reach a verdict. The live test reproduced the issue."
      : "Static review did not reach a verdict, and the live test was not conclusive.";
  }
  const said = STATIC_VERDICT_SENTENCE[staticVerdict];
  if (!state.tellsAboutCode) {
    return `${said} ${state.detail} The static review verdict still applies.`;
  }
  if (state.kind === "reproduced") {
    return staticVerdict === "false-positive"
      ? "Static review marked this finding as a false positive, but the live test reproduced it. Review both results."
      : `${said} The live test reproduced the issue.`;
  }
  return staticVerdict === "confirmed"
    ? "Static review confirmed this finding, but the live test could not reproduce it. Treat it as unresolved."
    : `${said} The live test could not reproduce the issue.`;
}
