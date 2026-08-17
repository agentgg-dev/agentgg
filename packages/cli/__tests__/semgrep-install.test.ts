import { describe, expect, it } from "vitest";
import { SEMGREP_VERSION, WHEELS, wheelForCurrentPlatform } from "../src/semgrep-install.js";

describe("pinned wheel table", () => {
  it("pins one wheel per supported platform", () => {
    expect(Object.keys(WHEELS).sort()).toEqual([
      "darwin-arm64",
      "linux-arm64",
      "linux-x64",
      "win32-x64",
    ]);
  });

  it("names a wheel matching the pinned version, with a 64-char sha256", () => {
    for (const [key, entry] of Object.entries(WHEELS)) {
      expect(entry.filename, key).toContain(`semgrep-${SEMGREP_VERSION}-`);
      expect(entry.filename, key).toMatch(/\.whl$/);
      expect(entry.sha256, key).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("gives every supported platform a distinct wheel", () => {
    const names = Object.values(WHEELS).map((w) => w.filename);
    expect(new Set(names).size).toBe(names.length);
  });

  it("resolves the current platform to an entry or null, never undefined", () => {
    const entry = wheelForCurrentPlatform();
    expect(entry === null || typeof entry.sha256 === "string").toBe(true);
  });
});
