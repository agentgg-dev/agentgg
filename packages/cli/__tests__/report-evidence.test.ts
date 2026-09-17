import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Finding, getEvidenceDir } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evidenceDirName, writeMarkdownReport } from "../src/reporters/md.js";

const finding = (): Finding =>
  ({
    id: "abc123",
    agentSlug: "xss-agent",
    title: "Reflected XSS in search",
    vulnSlug: "xss",
    filePath: "src/server.ts",
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    references: [],
    confidence: 0.9,
    notifications: [],
    validation: {
      verdict: "confirmed",
      reasoning: "static",
      dynamic: {
        verdict: "confirmed",
        reasoning: "reproduced in the browser",
        baseUrl: "http://host.docker.internal:3000",
        evidence: {
          trace: "trace.zip",
          video: "session.webm",
          screenshots: ["shot-1.png"],
          script: { path: "repro.spec.ts", executed: true, passed: true },
        },
      },
    },
  }) as Finding;

describe("evidence in the rendered report", () => {
  let outDir: string;

  beforeEach(() => {
    outDir = mkdtempSync(join(tmpdir(), "agentgg-report-"));
  });
  afterEach(() => rmSync(outDir, { recursive: true, force: true }));

  const render = (f: Finding) => {
    const src = getEvidenceDir(outDir, f.agentSlug, f.id);
    mkdirSync(src, { recursive: true });
    for (const n of ["trace.zip", "session.webm", "shot-1.png", "repro.spec.ts"]) {
      writeFileSync(join(src, n), n);
    }
    return writeMarkdownReport({
      outDir,
      root: "/repo",
      startedAt: new Date(0),
      completedAt: new Date(1000),
      findings: [f],
      filesScanned: 1,
      byAgent: { "xss-agent": 1 },
    });
  };

  it("copies the evidence next to the finding markdown", () => {
    const f = finding();
    render(f);
    const dir = join(outDir, "findings", evidenceDirName(f));
    expect(existsSync(join(dir, "trace.zip"))).toBe(true);
    expect(existsSync(join(dir, "session.webm"))).toBe(true);
    expect(existsSync(join(dir, "repro.spec.ts"))).toBe(true);
    expect(existsSync(join(dir, "shot-1.png"))).toBe(true);
  });

  it("keeps the durable copy under state/", () => {
    const f = finding();
    render(f);
    expect(existsSync(join(getEvidenceDir(outDir, f.agentSlug, f.id), "trace.zip"))).toBe(true);
  });

  it("links the evidence relatively from the finding markdown", () => {
    const f = finding();
    const { findingPaths } = render(f);
    const md = readFileSync(findingPaths[0] as string, "utf8");
    const dir = evidenceDirName(f);
    expect(md).toContain(`(${dir}/trace.zip)`);
    expect(md).toContain(`(${dir}/session.webm)`);
    expect(md).toContain(`(${dir}/repro.spec.ts)`);
    expect(md).toContain(`(${dir}/shot-1.png)`);
  });

  it("adds a live validation table to the summary", () => {
    const f = finding();
    render(f);
    const summary = readFileSync(join(outDir, "summary.md"), "utf8");
    expect(summary).toContain("## Live validation");
    expect(summary).toContain("| Finding | Result | Evidence |");
    expect(summary).toContain("Reflected XSS in search");
    expect(summary).toContain("`confirmed`");
  });

  it("omits the live validation table when nothing was live-validated", () => {
    const f = finding();
    f.validation = { verdict: "confirmed", reasoning: "static" };
    render(f);
    const summary = readFileSync(join(outDir, "summary.md"), "utf8");
    expect(summary).not.toContain("## Live validation");
  });

  it("does not link evidence in the summary table when nothing was copied", () => {
    // Metadata survives a rerun that deletes state/files/<agentSlug>/, so the
    // evidence directory never gets created on disk. No render() helper here:
    // it always seeds the source directory, which is exactly what this case
    // must NOT have.
    const f = finding();
    writeMarkdownReport({
      outDir,
      root: "/repo",
      startedAt: new Date(0),
      completedAt: new Date(1000),
      findings: [f],
      filesScanned: 1,
      byAgent: { "xss-agent": 1 },
    });
    const summary = readFileSync(join(outDir, "summary.md"), "utf8");
    expect(summary).toContain("Reflected XSS in search");
    expect(summary).toContain("`confirmed`");
    expect(summary).not.toContain(`findings/${evidenceDirName(f)}/`);
  });
});
