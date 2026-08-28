/**
 * Recovery from a reformat call that threw.
 *
 * `generateObject` parses its own response and throws, so the raw text never
 * reaches `extractJSON` — even though that function handles every corruption
 * Makora produced. The fixtures below are the real strings from the local scan
 * on 2026-08-28 (run 20260828071048) and from the pinned-provider probe that
 * identified Makora: makora 1/8 valid, baseten 8/8, streamlake 8/8, ambient 8/8.
 *
 * No LLM call is involved: the helper reads `err.text`, which is already paid for.
 */

import { describe, expect, it } from "vitest";
import { DetectionResult } from "../src/detect.js";
import { recoverFromError, salvageVerdict } from "../src/detectors/vercel-agent.js";
import { LlmValidation } from "../src/validator.js";

/** The AI SDK attaches the raw completion to the error as `text`. */
function noObjectGenerated(text: string | undefined): Error & { text?: string } {
  return Object.assign(new Error("No object generated: could not parse the response."), { text });
}

/** One well-formed finding, used inside the corrupted wrappers below. */
const FINDING =
  `{"title":"IDOR: getOrderById returns order without ownership check",` +
  `"vulnSlug":"idor","agentSlug":null,"lineRange":[23,26],"filePath":"src/api/orders.ts",` +
  `"summary":"getOrderById fetches an order by ID without verifying ownership.",` +
  `"details":"getOrderById accepts an orderId and returns the row directly.",` +
  `"poc":"Authenticate as user A, request user B's order id.",` +
  `"impact":"Any authenticated user reads any other user's order.",` +
  `"references":["CWE-639"],"confidence":0.85}`;

describe("recoverFromError — findings", () => {
  it("recovers through the stray brace-quote prefix that lost 8 findings", () => {
    // agent:unverified-lookup, gen-1787901080-eempbMZqR3ByPxKklDcx
    const got = recoverFromError(DetectionResult, noObjectGenerated(`{"{"findings":[${FINDING}]}`));
    expect(got?.findings).toHaveLength(1);
    expect(got?.findings[0].filePath).toBe("src/api/orders.ts");
    // The reasoning prose survives, which the verdict-only salvage cannot do.
    expect(got?.findings[0].details).toContain("returns the row directly");
  });

  it("recovers when the object is emitted twice", () => {
    // agent:sql-injection, gen-1787901133-f9wjpBDduZP20hpfYJFo
    const got = recoverFromError(
      DetectionResult,
      noObjectGenerated(`{"findings":[]}{"findings":[]}`),
    );
    expect(got?.findings).toEqual([]);
  });

  it("returns null on text with no recoverable object, so the caller rethrows", () => {
    expect(recoverFromError(DetectionResult, noObjectGenerated(`{"{""  :  ""}`))).toBeNull();
    expect(
      recoverFromError(DetectionResult, noObjectGenerated("I could not complete this.")),
    ).toBeNull();
  });

  it("returns null when the error carries no text at all", () => {
    expect(recoverFromError(DetectionResult, noObjectGenerated(undefined))).toBeNull();
    expect(recoverFromError(DetectionResult, noObjectGenerated(""))).toBeNull();
    expect(recoverFromError(DetectionResult, new Error("network reset"))).toBeNull();
  });

  it("returns null when the JSON parses but does not match the schema", () => {
    expect(
      recoverFromError(DetectionResult, noObjectGenerated(`{"totally":"different"}`)),
    ).toBeNull();
  });
});

describe("recoverFromError — validation verdicts", () => {
  it("recovers the verdict AND the reasoning through the prefix", () => {
    const got = recoverFromError(
      LlmValidation,
      noObjectGenerated(
        `{"{"verdict":"confirmed","reasoning":"The DELETE handler reads id from the body.","confidence":0.95}`,
      ),
    );
    expect(got?.verdict).toBe("confirmed");
    // This is the whole point of fix 7 over the verdict-only salvage.
    expect(got?.reasoning).toBe("The DELETE handler reads id from the body.");
  });

  it("hands a mid-object delimiter break down to salvageVerdict", () => {
    // A break BETWEEN fields is not recoverable this way: the only slice that
    // parses starts after the corruption, so `verdict` is already gone and the
    // schema rejects what is left. This is the staging shape from 2026-08-26,
    // and salvageVerdict is the layer that covers it.
    const text = `{"verdict":"out-of-scope","{"reasoning":"Test fixtures are excluded.","confidence":0.7}`;
    expect(recoverFromError(LlmValidation, noObjectGenerated(text))).toBeNull();
    expect(salvageVerdict(text)).toBe("out-of-scope");
  });
});
