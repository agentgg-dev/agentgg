/**
 * Tests for `resolveMangledToolName` in detectors/vercel-agent.ts — step one of
 * the malformed-tool-call repair.
 *
 * Why this exists: GLM-5 intermittently leaks its raw tool-call markup into the
 * tool NAME rather than the arguments. The Vercel AI SDK can't match the name,
 * throws `AI_NoSuchToolError` out of `generateText`, and the batch dies. A dead
 * batch sets `rt.failed`, which suppresses the agent's resume sidecar, which
 * makes the platform mark the WHOLE agent failed — so one bad turn cost three
 * agents on prod scan 764dbd1d (2026-08-18).
 *
 * Every `mangled` string below is a real tool name copied from that scan's
 * Cloud Logging output. Pure-function tests — no LLM calls.
 */
import { describe, expect, it } from "vitest";
import { resolveMangledToolName } from "../src/detectors/vercel-agent.js";

const TOOLS = ["Read", "Glob", "Grep"];

describe("resolveMangledToolName", () => {
  it("passes a well-formed name straight through", () => {
    expect(resolveMangledToolName("Grep", TOOLS)).toBe("Grep");
    expect(resolveMangledToolName("Read", TOOLS)).toBe("Read");
  });

  it("recovers the tool when arg markup is appended to the name", () => {
    // scan 764dbd1d, slug missing-access-control, 13:03:59Z
    expect(
      resolveMangledToolName(
        "Grep<arg_value>pattern</arg_key><arg_value>get_owned_provider_account_or_404</arg_value>",
        TOOLS,
      ),
    ).toBe("Grep");
    // slug zip-slip, 13:23:52Z
    expect(
      resolveMangledToolName(
        "Grep path</arg_key><arg_value>langflow-1.11.3/src/lfx/src/lfx/cli</arg_value>",
        TOOLS,
      ),
    ).toBe("Grep");
    // slug zip-slip, 09:46:37Z
    expect(resolveMangledToolName("Read  file_path: setup.py</arg_value>", TOOLS)).toBe("Read");
  });

  it("recovers the tool when the name is PREFIXED by leaked markup", () => {
    // slug sql-injection, 14:32:53Z — the name arrived as `…</tool_call>Read`.
    expect(resolveMangledToolName("</tool_call>Read", TOOLS)).toBe("Read");
  });

  it("recovers from a degenerate repetition-loop name", () => {
    // slug sql-injection, 13:20:14Z — the model looped and emitted this as a
    // tool name. The leading `Grep` is still the intent.
    expect(
      resolveMangledToolName(
        'Grep`pattern</arg_key>="def run\\self.0.3/src/lfx=1.11.3/srclfx=111langflow-11113 the3.11.3.',
        TOOLS,
      ),
    ).toBe("Grep");
  });

  it("takes the leftmost name when the garbage mentions several", () => {
    // The intended call leads; anything after it is transcript spill.
    expect(resolveMangledToolName("Glob</arg_value>Read Grep", TOOLS)).toBe("Glob");
  });

  it("returns null when no known tool appears, leaving the call unrepaired", () => {
    expect(resolveMangledToolName("Bash", TOOLS)).toBeNull();
    expect(resolveMangledToolName("", TOOLS)).toBeNull();
  });

  it("does not let a short name shadow a longer one at the same position", () => {
    expect(resolveMangledToolName("ReadMany", [...TOOLS, "ReadMany"])).toBe("ReadMany");
  });
});
