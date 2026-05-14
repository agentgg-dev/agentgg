import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "@agentgg/core";
import {
  findingFilename,
  renderFindingMd,
  renderSummaryMd,
  writeMarkdownReport,
} from "../src/reporters/md.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "agentgg-report-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "abc123",
    agentSlug: "sql-injection",
    title: "SQLi in login handler",
    vulnSlug: "sql-injection",
    filePath: "src/login.ts",
    lineRange: [12, 14],
    summary:
      "Login handler concatenates request body into SQL, allowing arbitrary DB access.",
    details:
      "Line 12 builds the query via string concatenation:\n```\ndb.query('SELECT * FROM users WHERE id=' + id)\n```",
    poc: "curl -X GET '/users/1%20OR%201%3D1'",
    impact: "Any unauthenticated request can read or modify the users table.",
    references: ["CWE-89"],
    confidence: 0.9,
    notifications: [],
    ...overrides,
  };
}

describe("findingFilename", () => {
  it("includes a zero-padded sequence, slug, and short title", () => {
    expect(findingFilename(makeFinding(), 0)).toMatch(
      /^001-sql-injection-sqli-in-login-handler\.md$/,
    );
  });

  it("zero-pads the sequence", () => {
    expect(findingFilename(makeFinding(), 9)).toMatch(/^010-/);
  });

  it("truncates extremely long titles", () => {
    const f = makeFinding({ title: "a".repeat(200) });
    const name = findingFilename(f, 0);
    // 3 (seq) + 1 (-) + slug + 1 (-) + max 40 char title slug + ".md"
    expect(name.length).toBeLessThan(80);
  });
});

describe("renderFindingMd", () => {
  it("includes title, file, lines, confidence, and pending-severity note", () => {
    const md = renderFindingMd(makeFinding());
    expect(md).toContain("# SQLi in login handler");
    expect(md).toContain("`src/login.ts`");
    expect(md).toContain("12–14");
    expect(md).toContain("90%");
    expect(md).toContain("pending");
  });

  it("renders a real severity when present", () => {
    const md = renderFindingMd(makeFinding({ severity: "CRITICAL" }));
    expect(md).toContain("**Severity:** CRITICAL");
    expect(md).not.toContain("pending");
  });

  it("includes a CVSS block when cvss is set", () => {
    const md = renderFindingMd(
      makeFinding({
        severity: "CRITICAL",
        cvss: {
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          baseScore: 9.8,
          severity: "CRITICAL",
          metrics: {
            attackVector: "N",
            attackComplexity: "L",
            privilegesRequired: "N",
            userInteraction: "N",
            scope: "U",
            confidentiality: "H",
            integrity: "H",
            availability: "H",
          },
          justification: "x",
        },
      }),
    );
    expect(md).toContain("CVSS:3.1");
    expect(md).toContain("9.8");
  });

  it("omits sections that have no content", () => {
    const md = renderFindingMd(
      makeFinding({
        snippet: undefined,
        recommendation: undefined,
        references: [],
      }),
    );
    expect(md).not.toContain("## Code");
    expect(md).not.toContain("## Recommendation");
    expect(md).not.toContain("## References");
  });
});

describe("writeMarkdownReport", () => {
  it("writes summary.md + one .md per finding under findings/", () => {
    const out = writeMarkdownReport({
      outDir: tmp,
      root: "/fake/project",
      startedAt: new Date(2026, 0, 1, 12, 0, 0),
      completedAt: new Date(2026, 0, 1, 12, 1, 30),
      findings: [makeFinding(), makeFinding({ id: "def", title: "Other" })],
      filesScanned: 3,
      byAgent: { "sql-injection": 2 },
    });
    expect(out.summaryPath).toBe(join(tmp, "summary.md"));
    expect(out.findingPaths).toHaveLength(2);

    const findingsDirEntries = readdirSync(join(tmp, "findings"));
    expect(findingsDirEntries).toHaveLength(2);

    const summary = readFileSync(out.summaryPath, "utf8");
    expect(summary).toContain("# Scan summary");
    expect(summary).toContain("Total findings:** 2");
    expect(summary).toContain("`sql-injection`: 2");
    expect(summary).toContain("findings/001-sql-injection-");
  });

  it("writes a summary even when there are zero findings", () => {
    const out = writeMarkdownReport({
      outDir: tmp,
      root: "/fake",
      startedAt: new Date(),
      completedAt: new Date(),
      findings: [],
      filesScanned: 5,
      byAgent: {},
    });
    const summary = readFileSync(out.summaryPath, "utf8");
    expect(summary).toContain("Total findings:** 0");
    expect(summary).toContain("_No findings._");
    expect(out.findingPaths).toEqual([]);
  });
});

describe("renderSummaryMd", () => {
  it("computes duration in seconds", () => {
    const startedAt = new Date("2026-01-01T00:00:00.000Z");
    const completedAt = new Date("2026-01-01T00:00:42.500Z");
    const md = renderSummaryMd(
      {
        outDir: "/x",
        root: "/r",
        startedAt,
        completedAt,
        findings: [],
        filesScanned: 1,
        byAgent: {},
      },
      [],
    );
    expect(md).toContain("Duration:** 42.5s");
  });
});
