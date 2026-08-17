import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { installSemgrepCore, wheelForCurrentPlatform } from "../src/semgrep-install.js";

// Pulls ~60 MB from PyPI. Opt in with AGENTGG_TEST_SEMGREP_DOWNLOAD=1 so CI and
// contributors are not forced to pay for it on every run. This is the only
// check that proves the pinned digest is correct for the current platform.
const enabled = process.env.AGENTGG_TEST_SEMGREP_DOWNLOAD === "1";

describe.skipIf(!enabled)("installSemgrepCore against the real PyPI", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "agentgg-sgdl-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("downloads, verifies, and produces a binary that runs", { timeout: 600_000 }, async () => {
    expect(wheelForCurrentPlatform()).not.toBeNull();
    const result = await installSemgrepCore({ AGENTGG_HOME: home });
    expect(result).toMatchObject({ ok: true });
    if (!result.ok) return;

    expect(statSync(result.path).size).toBeGreaterThan(10 * 1024 * 1024);
    const help = execFileSync(result.path, ["--help"], { encoding: "utf8" });
    expect(help).toContain("-rules");
  });
});
