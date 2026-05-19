import { AlertCircle, Clock, FileText, ShieldCheck } from "lucide-react";
import FindingsTable from "./components/FindingsTable";
import Nav from "./components/Nav";
import StatCard from "./components/StatCard";
import { loadViewerState } from "./lib/state";

export const dynamic = "force-dynamic";

export default function DashboardPage() {
  const state = loadViewerState();

  if (!state.scan) {
    return (
      <>
        <Nav />
        <main className="max-w-3xl mx-auto px-6 pt-20 pb-32">
          <div className="rounded-xl border border-bg-border bg-bg-panel/40 p-8 text-center">
            <AlertCircle className="w-10 h-10 text-amber mx-auto mb-4" />
            <h1 className="text-xl font-semibold text-ink mb-2">No scan state found</h1>
            <p className="text-sm text-ink-muted">
              The viewer is pointed at{" "}
              <code className="font-mono text-amber-glow">{state.outputDir}</code> but no{" "}
              <code className="font-mono">state/scan.json</code> exists there yet.
            </p>
            <p className="mt-4 text-sm text-ink-muted">
              Run{" "}
              <code className="font-mono text-cyan">
                agentgg scan &lt;path&gt; -o {state.outputDir}
              </code>{" "}
              first.
            </p>
          </div>
        </main>
      </>
    );
  }

  const { counts, scan, runs } = state;
  const lastRun = runs[0];
  const durationSeconds = lastRun?.completedAt
    ? (new Date(lastRun.completedAt).getTime() - new Date(lastRun.startedAt).getTime()) / 1000
    : null;

  const confirmed = counts.findingsByVerdict.confirmed ?? 0;
  const falsePositive = counts.findingsByVerdict["false-positive"] ?? 0;
  const outOfScope = counts.findingsByVerdict["out-of-scope"] ?? 0;
  const uncertain = counts.findingsByVerdict.uncertain ?? 0;

  return (
    <>
      <Nav rootPath={scan.root} />
      <main className="max-w-6xl mx-auto px-6 pt-10 pb-24">
        {/* header */}
        <section className="mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan/30 bg-cyan/5 text-xs font-mono text-cyan-glow mb-5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan animate-glow-pulse" />
            Local report · {new Date(scan.updatedAt).toLocaleString()}
          </div>
          <h1 className="text-3xl md:text-4xl font-bold tracking-tight leading-tight">
            <span className="text-ink">Scan results.</span>{" "}
            <span className="text-gradient-amber">{counts.findings}</span>{" "}
            <span className="text-ink">finding{counts.findings === 1 ? "" : "s"} across</span>{" "}
            <span className="text-gradient-cyan">{counts.files}</span>{" "}
            <span className="text-ink">file{counts.files === 1 ? "" : "s"}.</span>
          </h1>
          <p className="mt-3 text-sm text-ink-muted font-mono truncate">{scan.root}</p>
        </section>

        {/* stat grid */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10">
          <StatCard
            label="Findings"
            value={counts.findings}
            hint={`${counts.findingsValidated}/${counts.findings} validated`}
            accent="amber"
          />
          <StatCard
            label="Confirmed"
            value={confirmed}
            hint={uncertain > 0 ? `${uncertain} uncertain` : undefined}
            accent="green"
          />
          <StatCard
            label="False positive"
            value={falsePositive}
            hint={outOfScope > 0 ? `${outOfScope} out of scope` : undefined}
            accent="neutral"
          />
          <StatCard
            label="Files scanned"
            value={counts.files}
            hint={`${counts.analyzed} analyzed · ${counts.pending} pending`}
            accent="cyan"
          />
        </section>

        {/* meta strip */}
        <section className="mb-10 grid md:grid-cols-3 gap-4">
          <div className="rounded-xl border border-bg-border bg-bg-panel/40 p-5">
            <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.18em] text-ink-dim mb-2">
              <Clock className="w-3 h-3" /> Last run
            </div>
            <div className="text-sm text-ink font-mono">{lastRun ? lastRun.runId : "—"}</div>
            <div className="mt-1 text-xs text-ink-muted">
              {lastRun?.phase === "done"
                ? `done${durationSeconds != null ? ` in ${durationSeconds.toFixed(1)}s` : ""}`
                : (lastRun?.phase ?? "no runs")}
            </div>
          </div>
          <div className="rounded-xl border border-bg-border bg-bg-panel/40 p-5">
            <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.18em] text-ink-dim mb-2">
              <ShieldCheck className="w-3 h-3" /> Agents that fired
            </div>
            <div className="flex flex-wrap gap-1.5">
              {counts.findingsByAgent.length === 0 ? (
                <span className="text-xs text-ink-muted">No findings yet.</span>
              ) : (
                counts.findingsByAgent.slice(0, 6).map((a) => (
                  <span
                    key={a.slug}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono border border-bg-border bg-bg/40 text-ink-muted"
                  >
                    <span className="text-amber">{a.slug}</span>
                    <span className="text-ink-dim">×{a.count}</span>
                  </span>
                ))
              )}
              {counts.findingsByAgent.length > 6 && (
                <span className="text-xs text-ink-dim">
                  +{counts.findingsByAgent.length - 6} more
                </span>
              )}
            </div>
          </div>
          <div className="rounded-xl border border-bg-border bg-bg-panel/40 p-5">
            <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.18em] text-ink-dim mb-2">
              <FileText className="w-3 h-3" /> Output directory
            </div>
            <div className="text-xs text-ink-muted font-mono break-all">{state.outputDir}</div>
          </div>
        </section>

        {/* findings table */}
        <section>
          <div className="flex items-end justify-between mb-4">
            <div>
              <div className="text-xs font-mono uppercase tracking-[0.18em] text-amber mb-1">
                Findings
              </div>
              <h2 className="text-xl font-semibold tracking-tight text-ink">
                All findings, filterable
              </h2>
            </div>
            <div className="text-xs text-ink-dim">
              Click any row for the full GHSA-shaped report.
            </div>
          </div>
          <FindingsTable
            findings={state.findings}
            agents={counts.findingsByAgent.map((a) => a.slug)}
          />
        </section>

        {/* empty state */}
        {state.findings.length === 0 && (
          <div className="mt-6 rounded-xl border border-bg-border bg-bg-panel/40 p-8 text-center">
            <ShieldCheck className="w-10 h-10 text-terminal-green mx-auto mb-3" />
            <div className="text-lg font-semibold text-ink">No findings yet.</div>
            <p className="mt-2 text-sm text-ink-muted">
              {counts.files === 0
                ? "Run a scan against this output directory and the findings will appear here."
                : "Every agent ran clean on every file in scope."}
            </p>
          </div>
        )}
      </main>
    </>
  );
}
