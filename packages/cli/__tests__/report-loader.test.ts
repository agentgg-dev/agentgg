import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadReports } from "../src/report-loader.js";

describe("loadReports", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "agentgg-report-loader-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("loads a single .md file", () => {
    const reportPath = join(dir, "cve-2024-12345.md");
    writeFileSync(reportPath, "# CVE-2024-12345\n\nSQL injection in /login.", "utf8");
    const reports = loadReports(reportPath);
    expect(reports).toHaveLength(1);
    expect(reports[0]?.name).toBe("cve-2024-12345.md");
    expect(reports[0]?.content).toContain("SQL injection");
  });

  it("loads a single .txt file as a report (not a list)", () => {
    const reportPath = join(dir, "incident.txt");
    writeFileSync(reportPath, "Free-form notes describing the incident.\nNot a path.", "utf8");
    const reports = loadReports(reportPath);
    expect(reports).toHaveLength(1);
    expect(reports[0]?.name).toBe("incident.txt");
  });

  it("loads every .md/.txt file in a directory", () => {
    writeFileSync(join(dir, "a.md"), "Report A", "utf8");
    writeFileSync(join(dir, "b.txt"), "Report B", "utf8");
    writeFileSync(join(dir, "README.md"), "Just a readme", "utf8");
    writeFileSync(join(dir, "ignored.json"), "{}", "utf8");
    const reports = loadReports(dir);
    expect(reports.map((r) => r.name).sort()).toEqual(["README.md", "a.md", "b.txt"]);
  });

  it("expands a .txt list file when every line is an existing path", () => {
    const aPath = join(dir, "a.md");
    const bPath = join(dir, "b.md");
    writeFileSync(aPath, "Report A", "utf8");
    writeFileSync(bPath, "Report B", "utf8");
    const listPath = join(dir, "list.txt");
    writeFileSync(listPath, `# header\n${aPath}\n${bPath}\n`, "utf8");
    const reports = loadReports(listPath);
    expect(reports.map((r) => r.name).sort()).toEqual(["a.md", "b.md"]);
  });

  it("treats a .txt with mixed prose as a report, not a list", () => {
    const listPath = join(dir, "mixed.txt");
    writeFileSync(listPath, `${join(dir, "real.md")}\nplain prose line\n`, "utf8");
    writeFileSync(join(dir, "real.md"), "Real report", "utf8");
    const reports = loadReports(listPath);
    expect(reports).toHaveLength(1);
    expect(reports[0]?.name).toBe("mixed.txt");
  });

  it("rejects unsupported file types", () => {
    const pdfPath = join(dir, "report.pdf");
    writeFileSync(pdfPath, "%PDF-1.4 binary", "utf8");
    expect(() => loadReports(pdfPath)).toThrow(/unsupported file type/);
  });

  it("rejects an empty .md file", () => {
    const empty = join(dir, "empty.md");
    writeFileSync(empty, "   \n", "utf8");
    expect(() => loadReports(empty)).toThrow(/is empty/);
  });

  it("rejects an empty directory", () => {
    const sub = join(dir, "empty-sub");
    mkdirSync(sub);
    expect(() => loadReports(sub)).toThrow(/no \.md or \.txt files/);
  });

  it("rejects a missing path", () => {
    expect(() => loadReports(join(dir, "does-not-exist.md"))).toThrow(/no such file or directory/);
  });
});
