import type { Finding } from "@agentgg/core";
import { ArrowLeft, ExternalLink, Hash } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import {
  ConfidenceBar,
  DuplicateBadge,
  SeverityBadge,
  VerdictBadge,
} from "@/app/components/Badges";
import CopyMarkdownButton from "@/app/components/CopyMarkdownButton";
import Markdown from "@/app/components/Markdown";
import Nav from "@/app/components/Nav";
import { findFindingById, loadViewerState } from "@/app/lib/state";

export const dynamic = "force-dynamic";

export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const hit = findFindingById(id);
  if (!hit) notFound();

  const { finding, file } = hit;
  const state = loadViewerState();

  return (
    <>
      <Nav rootPath={state.scan?.root} />
      <main className="max-w-4xl mx-auto px-6 pt-8 pb-24">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs text-ink-muted hover:text-amber transition-colors mb-6"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to all findings
        </Link>

        {/* header card */}
        <div className="rounded-xl border border-bg-border bg-bg-panel/40 p-6 md:p-8 mb-6">
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <SeverityBadge severity={finding.severity} />
            <VerdictBadge verdict={finding.validation?.verdict} />
            <DuplicateBadge dedup={finding.dedup} />
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border border-bg-border bg-bg/40 text-amber">
              {finding.agentSlug}
            </span>
            <CopyMarkdownButton markdown={findingToMarkdown(finding)} className="ml-auto" />
          </div>

          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-ink leading-tight">
            {finding.title}
          </h1>

          <p className="mt-4 text-base text-ink-muted leading-relaxed">{finding.summary}</p>

          <div className="mt-6 flex flex-wrap items-center gap-5 text-xs">
            <MetaField label="File">
              <span className="font-mono text-cyan break-all">{finding.filePath}</span>
            </MetaField>
            {finding.lineRange && (
              <MetaField label="Lines">
                <span className="font-mono text-ink">
                  {finding.lineRange[0]}–{finding.lineRange[1]}
                </span>
              </MetaField>
            )}
            <MetaField label="Confidence">
              <ConfidenceBar value={finding.confidence} />
            </MetaField>
            <MetaField label="File status">
              <span className="font-mono text-ink-muted">{file.status}</span>
            </MetaField>
          </div>
        </div>

        {/* sections */}
        <Section title="Details">
          <Markdown source={finding.details} />
        </Section>

        <Section title="Proof of concept">
          <Markdown source={finding.poc} />
        </Section>

        <Section title="Impact">
          <Markdown source={finding.impact} />
        </Section>

        {finding.validation && (
          <Section title="Validation">
            <div className="mb-4 flex items-center gap-2">
              <VerdictBadge verdict={finding.validation.verdict} />
              {finding.validation.scopeRef && (
                <span className="text-xs font-mono text-ink-dim">
                  scope: {finding.validation.scopeRef}
                </span>
              )}
            </div>
            <Markdown source={finding.validation.reasoning} />
          </Section>
        )}

        {finding.dedup && (
          <Section title="Duplicate">
            <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
              <DuplicateBadge dedup={finding.dedup} />
              <span className="text-ink-dim">folded into primary</span>
              <Link
                href={`/finding/${finding.dedup.duplicateOf}`}
                className="inline-flex items-center gap-1 font-mono text-cyan hover:text-cyan-glow transition-colors"
              >
                <Hash className="w-3 h-3" />
                {finding.dedup.duplicateOf}
              </Link>
            </div>
            <Markdown source={finding.dedup.reasoning} />
          </Section>
        )}

        {finding.cvss && (
          <Section title="CVSS 3.1">
            <div className="font-mono text-xs text-cyan break-all mb-3">{finding.cvss.vector}</div>
            <div className="text-sm text-ink mb-3">
              Base score:{" "}
              <span className="text-amber font-semibold">{finding.cvss.baseScore.toFixed(1)}</span>{" "}
              · <SeverityBadge severity={finding.cvss.severity} />
            </div>
            <Markdown source={finding.cvss.justification} />
          </Section>
        )}

        {finding.references.length > 0 && (
          <Section title="References">
            <ul className="space-y-2">
              {finding.references.map((ref) => (
                <li key={ref} className="text-sm">
                  {ref.startsWith("http") ? (
                    <a
                      href={ref}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 text-cyan hover:text-cyan-glow transition-colors"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      {ref}
                    </a>
                  ) : (
                    <span className="font-mono text-ink-muted">{ref}</span>
                  )}
                </li>
              ))}
            </ul>
          </Section>
        )}
      </main>
    </>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-bg-border bg-bg-panel/40 p-6 md:p-8 mb-5">
      <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-amber mb-3">
        {title}
      </div>
      {children}
    </section>
  );
}

function MetaField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1 min-w-0">
      <span className="text-[10px] font-mono uppercase tracking-[0.18em] text-ink-dim">
        {label}
      </span>
      {children}
    </div>
  );
}

/**
 * Serialize a finding to a single self-contained markdown block — what we'd
 * paste into a Slack thread, a Linear ticket, or a PR review. Mirrors the
 * GHSA section order the rest of the viewer reflects (Summary / Details /
 * PoC / Impact / Validation / CVSS / References) so a copied finding reads
 * the same as the page does. `details`/`poc`/`impact`/`validation.reasoning`/
 * `dedup.reasoning`/`cvss.justification` are already markdown bodies; we
 * concatenate without re-escaping.
 */
function findingToMarkdown(f: Finding): string {
  const out: string[] = [];
  out.push(`# ${f.title}`, "");

  const facts: string[] = [];
  facts.push(`**Severity:** ${f.severity ?? "unscored"}`);
  if (f.validation) facts.push(`**Verdict:** ${f.validation.verdict}`);
  facts.push(`**Agent:** \`${f.agentSlug}\``);
  facts.push(`**Class:** \`${f.vulnSlug}\``);
  facts.push(`**Location:** \`${f.filePath}${locationSuffix(f)}\``);
  facts.push(`**Confidence:** ${Math.round(f.confidence * 100)}%`);
  if (f.cvss) {
    facts.push(`**CVSS:** ${f.cvss.baseScore.toFixed(1)} (\`${f.cvss.vector}\`)`);
  }
  // Two-space line breaks render as one paragraph (GitHub, Linear, mrkdwn)
  // instead of collapsing into a single line.
  out.push(facts.join("  \n"), "");

  out.push("## Summary", "", f.summary, "");
  out.push("## Details", "", f.details, "");
  out.push("## Proof of concept", "", f.poc, "");
  out.push("## Impact", "", f.impact, "");

  if (f.validation) {
    out.push("## Validation", "", `**Verdict:** ${f.validation.verdict}`);
    if (f.validation.scopeRef) out.push(`**Scope:** ${f.validation.scopeRef}`);
    out.push("", f.validation.reasoning, "");
  }

  if (f.dedup) {
    out.push(
      "## Duplicate",
      "",
      `Folded into primary \`${f.dedup.duplicateOf}\`.`,
      "",
      f.dedup.reasoning,
      "",
    );
  }

  if (f.cvss) {
    out.push(
      "## CVSS 3.1",
      "",
      `Vector: \`${f.cvss.vector}\`  \nBase score: **${f.cvss.baseScore.toFixed(1)}** (${f.cvss.severity})`,
      "",
      f.cvss.justification,
      "",
    );
  }

  if (f.references.length > 0) {
    out.push("## References", "");
    for (const ref of f.references) out.push(`- ${ref}`);
    out.push("");
  }

  out.push(`*Finding ID: \`${f.id}\`*`);
  return out.join("\n");
}

function locationSuffix(f: Finding): string {
  if (!f.lineRange) return "";
  const [a, b] = f.lineRange;
  if (a === b) return `:${a}`;
  return `:${a}-${b}`;
}
