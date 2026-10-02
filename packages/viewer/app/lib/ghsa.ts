import type { Finding } from "@agentgg/core";
import { suggestedFixOf } from "@agentgg/core/verdict";

/**
 * Serialize a finding as a GHSA-style advisory: only the fields a GitHub
 * Security Advisory body carries — title, summary, details, PoC, the
 * suggested fix of a confirmed finding, the CVSS score + vector selections
 * (no justification prose), and references. The internal triage metadata
 * (agent, verdict, dedup, confidence, finding ID) is intentionally omitted.
 * The CVSS and the fix come from `holder`, the finding that carries the
 * group's verdict and score.
 */
export function findingToGhsaMarkdown(f: Finding, holder: Finding): string {
  const out: string[] = [];
  out.push(`# ${f.title}`, "");
  out.push("## Summary", "", f.summary, "");
  out.push("## Details", "", f.details, "");
  out.push("## Proof of concept", "", f.poc, "");
  const fix = suggestedFixOf(holder);
  if (fix) out.push("## Suggested fix", "", fix, "");
  const { cvss } = holder;
  if (cvss) {
    // Two-space line breaks keep score + vector as one paragraph.
    out.push(
      "## CVSS",
      "",
      `Base score: ${cvss.baseScore.toFixed(1)}  \nVector: \`${cvss.vector}\``,
      "",
    );
  }
  if (f.references.length > 0) {
    out.push("## References", "");
    for (const ref of f.references) out.push(`- ${ref}`);
    out.push("");
  }
  return out.join("\n").trimEnd();
}
