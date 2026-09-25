import type { Finding } from "@agentgg/core";
import { liveState } from "@agentgg/core/live";
import { Download, FileCode, FileText, Film } from "lucide-react";
import RequestsTable from "./RequestsTable";
import Section from "./Section";

/** The raw artifacts, for a reviewer who does not take the summary on trust. */
export default function EvidencePanel({ finding }: { finding: Finding }) {
  const evidence = finding.live?.evidence;
  const href = (name: string) => `/api/evidence/${finding.id}/${encodeURIComponent(name)}`;

  if (!evidence) {
    return (
      <Section title="Evidence">
        <p className="text-sm text-ink-dim">{liveState(finding).detail}</p>
      </Section>
    );
  }

  const screenshots = evidence.screenshots ?? [];
  const requests = evidence.requests ?? [];

  return (
    <>
      {requests.length > 0 && (
        <Section title="Requests">
          <p className="text-sm text-ink-muted mb-4">
            What the live test sent and what came back. Open a row for the full headers and the
            response, or copy it as a curl command.
          </p>
          <RequestsTable
            requests={requests}
            findingId={finding.id}
            requestsFile={evidence.requestsFile}
          />
        </Section>
      )}

      {evidence.video && (
        <Section title="Recording">
          {/* biome-ignore lint/a11y/useMediaCaption: a screen recording with no speech */}
          <video
            src={href(evidence.video)}
            controls
            className="w-full rounded border border-bg-border"
          />
        </Section>
      )}

      {screenshots.length > 0 && (
        <Section title={`Screenshots (${screenshots.length})`}>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {screenshots.map((name) => (
              <a key={name} href={href(name)} target="_blank" rel="noreferrer" className="group">
                {/* biome-ignore lint/performance/noImgElement: a local evidence file, not a build-time asset */}
                <img
                  src={href(name)}
                  alt={name}
                  className="w-full rounded border border-bg-border group-hover:border-amber transition-colors"
                />
                <span className="mt-1 block truncate font-mono text-[10px] text-ink-dim group-hover:text-amber transition-colors">
                  {name}
                </span>
              </a>
            ))}
          </div>
        </Section>
      )}

      <Section title="Files">
        <ul className="space-y-3">
          {evidence.trace && (
            <FileRow
              icon={<Download className="w-3.5 h-3.5" />}
              href={href(evidence.trace)}
              name={evidence.trace}
            >
              Every step, network call and DOM snapshot. Open it with{" "}
              <code className="font-mono text-cyan">npx playwright show-trace trace.zip</code>.
            </FileRow>
          )}
          {evidence.requestsFile && (
            <FileRow
              icon={<FileText className="w-3.5 h-3.5" />}
              href={href(evidence.requestsFile)}
              name={evidence.requestsFile}
            >
              Every exchange with full headers and bodies. Holds the live session cookie, so keep it
              local.
            </FileRow>
          )}
          {evidence.har && (
            <FileRow
              icon={<FileText className="w-3.5 h-3.5" />}
              href={href(evidence.har)}
              name={evidence.har}
            >
              The network log, for a proxy or an HTTP client that reads HAR.
            </FileRow>
          )}
          {evidence.script && (
            <FileRow
              icon={<FileCode className="w-3.5 h-3.5" />}
              href={href(evidence.script.path)}
              name={evidence.script.path}
            >
              {finding.live?.result === "refuted"
                ? "The negative control: a Playwright script that tried the attack and did not get it to fire. Never replayed, because a pass would contradict the verdict."
                : "A Playwright script that repeats the attempt. Replay not verified, so treat it as a starting point and not as a result."}
            </FileRow>
          )}
          {evidence.video && (
            <FileRow
              icon={<Film className="w-3.5 h-3.5" />}
              href={href(evidence.video)}
              name={evidence.video}
            >
              The screen recording of the run.
            </FileRow>
          )}
        </ul>
      </Section>
    </>
  );
}

function FileRow({
  icon,
  href,
  name,
  children,
}: {
  icon: React.ReactNode;
  href: string;
  name: string;
  children: React.ReactNode;
}) {
  return (
    <li className="flex items-start gap-3">
      <span className="mt-0.5 text-ink-dim">{icon}</span>
      <div className="min-w-0">
        <a
          href={href}
          download={name}
          className="font-mono text-xs text-cyan hover:text-cyan-glow transition-colors break-all"
        >
          {name}
        </a>
        <p className="mt-0.5 text-xs text-ink-dim leading-relaxed">{children}</p>
      </div>
    </li>
  );
}
