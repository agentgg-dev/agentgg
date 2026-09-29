import type { Finding } from "@agentgg/core";
import { liveState, verdictConflict, verdictStory } from "@agentgg/core/live";
import { AlertTriangle, Globe, ImageIcon } from "lucide-react";
import { VerdictBadge } from "./Badges";
import { LiveResultBadge } from "./LiveBadges";
import Markdown from "./Markdown";
import Section from "./Section";

/**
 * The triage view: is this real, and do I send it to a developer? The proof
 * is summarized here; the raw artifacts are one tab over.
 */
export default function ValidationPanel({ finding }: { finding: Finding }) {
  const state = liveState(finding);
  const live = finding.live;
  const screenshot = proofScreenshot(live?.evidence?.screenshots);
  const proof = proofLine(finding);

  return (
    <>
      {/* Only when the live test moved the verdict. Otherwise the header badge
          and the two sections below already say it. */}
      {verdictConflict(finding) && (
        <div className="mb-5 flex items-start gap-2.5 rounded-lg border border-terminal-yellow/30 bg-terminal-yellow/5 px-4 py-3">
          <AlertTriangle className="mt-0.5 w-3.5 h-3.5 shrink-0 text-terminal-yellow" />
          <p className="text-sm text-ink leading-relaxed">{verdictStory(finding)}</p>
        </div>
      )}

      <Section title="Static review">
        {finding.validation ? (
          <>
            <div className="mb-3 flex items-center gap-2">
              <VerdictBadge verdict={finding.validation.verdict} />
              {finding.validation.scopeRef && (
                <span className="text-xs font-mono text-ink-dim">
                  scope: {finding.validation.scopeRef}
                </span>
              )}
            </div>
            <Markdown source={finding.validation.reasoning} />
            {finding.validation.confirmedImpact && (
              <p className="mt-3 text-sm text-ink-muted leading-relaxed">
                <strong className="text-ink">Confirmed impact:</strong>{" "}
                {finding.validation.confirmedImpact}
              </p>
            )}
            {finding.validation.unconfirmedImpact && (
              <p className="mt-2 text-sm text-ink-muted leading-relaxed">
                <strong className="text-ink">Claimed, not confirmed:</strong>{" "}
                {finding.validation.unconfirmedImpact}
              </p>
            )}
          </>
        ) : (
          <p className="text-sm text-ink-dim">
            No static review ran. The finding is as the detection agent reported it.
          </p>
        )}
      </Section>

      <Section title="Live test">
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <LiveResultBadge state={state} />
          {live?.baseUrl && (
            <span className="inline-flex items-center gap-1.5 text-xs font-mono text-cyan break-all">
              <Globe className="w-3 h-3 shrink-0" />
              {live.baseUrl}
            </span>
          )}
        </div>
        <p className="text-sm text-ink-muted leading-relaxed mb-3">{state.detail}</p>

        {proof && (
          <p className="mb-4 rounded border border-bg-border bg-bg/60 px-3 py-2 font-mono text-[11px] text-ink-muted break-all">
            {proof}
          </p>
        )}

        {live && <Markdown source={live.reasoning} />}

        {live?.counterevidence.trim() && (
          <div className="mt-4 rounded-lg border border-terminal-yellow/30 bg-terminal-yellow/5 p-4">
            <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-terminal-yellow mb-2">
              Counterevidence
            </div>
            <p className="text-sm text-ink-muted leading-relaxed">{live.counterevidence}</p>
          </div>
        )}

        {screenshot && (
          <a
            href={`/api/evidence/${finding.id}/${encodeURIComponent(screenshot)}`}
            target="_blank"
            rel="noreferrer"
            className="mt-4 block w-[320px] max-w-full group"
          >
            {/* biome-ignore lint/performance/noImgElement: a local evidence file, not a build-time asset */}
            <img
              src={`/api/evidence/${finding.id}/${encodeURIComponent(screenshot)}`}
              alt={`Live test of ${finding.title}`}
              className="w-full rounded border border-bg-border group-hover:border-amber transition-colors"
            />
            <span className="mt-1.5 inline-flex items-center gap-1.5 text-[11px] text-ink-dim group-hover:text-amber transition-colors">
              <ImageIcon className="w-3 h-3" />
              {screenshot}
            </span>
          </a>
        )}
      </Section>
    </>
  );
}

/**
 * The one shot to put beside the result. `screenshots` is newest first, and
 * the newest is not always the proof: a run that ends on a negative control
 * records that last. The agent names its proof shot, so prefer that name and
 * fall back to the newest.
 */
function proofScreenshot(screenshots?: string[]): string | undefined {
  if (!screenshots || screenshots.length === 0) return undefined;
  return (
    screenshots.find((n) => /proof/i.test(n) && !/negative|control/i.test(n)) ?? screenshots[0]
  );
}

/** The single exchange that carries the result: the last one whose status
 *  differs from the run's most common status. A reviewer reads this before
 *  the reasoning. */
function proofLine(finding: Finding): string | undefined {
  const requests = finding.live?.evidence?.requests;
  if (!requests || requests.length === 0) return undefined;

  const counts = new Map<number, number>();
  for (const r of requests) counts.set(r.status, (counts.get(r.status) ?? 0) + 1);
  const common = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];

  const candidates = requests.filter((r) => r.requestBody && r.status !== common);
  const pick = candidates.at(-1) ?? requests.filter((r) => r.requestBody).at(-1);
  if (!pick) return undefined;

  const path = pick.url.replace(/^https?:\/\/[^/]+/, "");
  return `${pick.method} ${path} with ${pick.requestBody} returned ${pick.status}`;
}
