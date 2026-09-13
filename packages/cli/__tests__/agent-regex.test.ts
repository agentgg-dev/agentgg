import { describe, expect, test } from "vitest";
import { compileAgentRegex } from "../src/agent-regex.js";

describe("compileAgentRegex — PCRE (?i) inline flag", () => {
  test("a leading (?i) becomes the JS i flag instead of throwing", () => {
    const re = compileAgentRegex("(?i)cmd\\.exe");
    expect(re.flags).toContain("i");
    expect(re.test("spawn('CMD.EXE')")).toBe(true);
    expect(re.test("spawn('cmd.exe')")).toBe(true);
  });

  test("matches the lowercase spelling a case-sensitive compile would miss", () => {
    const src = "(?i)(?:snyk|SNYK_TOKEN)\\s*[=:]\\s*['\"]?[a-f0-9]{8}";
    expect(compileAgentRegex(src).test("snyk_token = 'deadbeef'")).toBe(true);
    expect(compileAgentRegex(src).test("SNYK_TOKEN = 'deadbeef'")).toBe(true);
  });

  test("a repeated (?i) inside the pattern is stripped too", () => {
    // agents/secrets/sendgrid-api-key.md carries a second (?i) mid-pattern.
    const re = compileAgentRegex("(?i)\\b(SG\\.(?i)[a-z0-9]{6})\\b");
    expect(re.test(`key = SG.${"a".repeat(6)}`)).toBe(true);
    expect(re.test(`key = sg.${"A".repeat(6)}`)).toBe(true);
  });

  test("a pattern without (?i) stays case-SENSITIVE", () => {
    const re = compileAgentRegex("PLAIN\\d+");
    expect(re.flags).not.toContain("i");
    expect(re.test("PLAIN42")).toBe(true);
    expect(re.test("plain42")).toBe(false);
  });

  test("a genuinely malformed pattern still throws, so the catalog linter reports it", () => {
    expect(() => compileAgentRegex("(unclosed")).toThrow();
    expect(() => compileAgentRegex("(?i)(unclosed")).toThrow();
  });
});
