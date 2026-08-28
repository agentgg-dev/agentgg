/**
 * Tests for the per-phase tool-output budget in detectors/vercel-agent.ts.
 *
 * The budget caps bytes returned by Read/Glob/Grep across one tool loop, so the
 * accumulated transcript cannot outgrow the model's context window. Two things
 * are new here:
 *
 *   - it resolves per phase, overridable by env, because the base prompt each
 *     phase carries differs (detection embeds up to 5 full candidate files;
 *     validation embeds one plus the finding and scope), so the room left for
 *     tool output differs too;
 *   - exhausting it now warns. Before, tools silently began returning the
 *     finalize notice, which is why "the budget caused the 2026-08-10 stall"
 *     could never be confirmed or ruled out from the logs.
 *
 * The defaults are deliberately uniform until that warning produces data — see
 * the comment on `toolOutputBudgetBytes`.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  budgetNotice,
  buildTools,
  type ToolLoopPhase,
  toolOutputBudgetBytes,
} from "../src/detectors/vercel-agent.js";

const PHASES: ToolLoopPhase[] = ["detect", "validate", "recon", "create-agent"];
const DEFAULT_BYTES = 400_000;

describe("toolOutputBudgetBytes", () => {
  it("defaults every phase to the shared cap", () => {
    for (const p of PHASES) {
      expect(toolOutputBudgetBytes(p, {})).toBe(DEFAULT_BYTES);
    }
  });

  it("honors a per-phase override in KB", () => {
    const env = { AGENTGG_TOOL_BUDGET_KB_VALIDATE: "250" };
    expect(toolOutputBudgetBytes("validate", env)).toBe(250 * 1024);
    expect(toolOutputBudgetBytes("detect", env)).toBe(DEFAULT_BYTES);
  });

  it("falls back to the global override for phases without their own", () => {
    const env = { AGENTGG_TOOL_BUDGET_KB: "300" };
    for (const p of PHASES) {
      expect(toolOutputBudgetBytes(p, env)).toBe(300 * 1024);
    }
  });

  it("prefers the per-phase override over the global one", () => {
    const env = { AGENTGG_TOOL_BUDGET_KB: "300", AGENTGG_TOOL_BUDGET_KB_RECON: "500" };
    expect(toolOutputBudgetBytes("recon", env)).toBe(500 * 1024);
    expect(toolOutputBudgetBytes("detect", env)).toBe(300 * 1024);
  });

  // A typo'd or hostile env must not silently disable the cap — that is the
  // guard against context-overflow 400s, which are a hard failure.
  it.each([
    ["nonsense"],
    [""],
    ["0"],
    ["-50"],
    ["NaN"],
  ])("ignores the unusable override %j and keeps the default", (raw) => {
    expect(toolOutputBudgetBytes("detect", { AGENTGG_TOOL_BUDGET_KB: raw })).toBe(DEFAULT_BYTES);
  });
});

describe("budgetNotice reports the budget actually in force", () => {
  it("uses the resolved per-phase value, not a hardcoded constant", () => {
    expect(budgetNotice("validate", 250 * 1024)).toContain("~250 KB");
    expect(budgetNotice("detect", DEFAULT_BYTES)).toContain("~391 KB");
  });
});

describe("exhaustion warning", () => {
  let root: string;
  let warn: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "agentgg-budget-"));
    // Comfortably larger than the 1 KB budget the tests below set.
    writeFileSync(join(root, "big.ts"), "x".repeat(4000), "utf8");
    writeFileSync(join(root, "other.ts"), "y".repeat(4000), "utf8");
    warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
    vi.restoreAllMocks();
    process.env.AGENTGG_TOOL_BUDGET_KB = undefined;
    delete process.env.AGENTGG_TOOL_BUDGET_KB;
  });

  function tinyBudgetTools() {
    process.env.AGENTGG_TOOL_BUDGET_KB = "1";
    return buildTools({ cwd: root, verbose: false, label: "test", phase: "detect" });
  }

  // biome-ignore lint/suspicious/noExplicitAny: exercising the SDK's call shape
  const run = (t: any, args: unknown) => t.execute(args, {} as any) as Promise<string>;

  it("warns once when the budget runs out, naming the cap", async () => {
    const t = tinyBudgetTools();
    await run(t.Read, { path: "big.ts" }); // blows the 1 KB budget
    await run(t.Read, { path: "other.ts" }); // first call past the cap

    const lines = warn.mock.calls.map((c) => String(c[0]));
    const exhausted = lines.filter((l) => l.includes("tool output budget exhausted"));
    expect(exhausted).toHaveLength(1);
    expect(exhausted[0]).toContain("cap ~1 KB");
    expect(exhausted[0]).toContain("[test]");
  });

  it("does not repeat the warning on every subsequent call", async () => {
    const t = tinyBudgetTools();
    await run(t.Read, { path: "big.ts" });
    await run(t.Read, { path: "other.ts" });
    await run(t.Glob, { pattern: "*.ts" });
    await run(t.Grep, { pattern: "x", glob: null, path: null });

    const exhausted = warn.mock.calls
      .map((c) => String(c[0]))
      .filter((l) => l.includes("tool output budget exhausted"));
    expect(exhausted).toHaveLength(1);
  });

  it("returns the finalize notice once exhausted", async () => {
    const t = tinyBudgetTools();
    await run(t.Read, { path: "big.ts" });
    expect(await run(t.Read, { path: "other.ts" })).toContain("Tool budget reached");
  });

  it("stays quiet while under the cap", async () => {
    const t = buildTools({ cwd: root, verbose: false, label: "test", phase: "detect" });
    await run(t.Read, { path: "big.ts" });
    const exhausted = warn.mock.calls
      .map((c) => String(c[0]))
      .filter((l) => l.includes("tool output budget exhausted"));
    expect(exhausted).toHaveLength(0);
  });
});
