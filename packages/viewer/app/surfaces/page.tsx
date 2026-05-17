import { AlertCircle, Compass } from 'lucide-react';
import Nav from '../components/Nav';
import StatCard from '../components/StatCard';
import SurfacesTable from '../components/SurfacesTable';
import { loadViewerState } from '../lib/state';

export const dynamic = 'force-dynamic';

export default function SurfacesPage() {
  const state = loadViewerState();

  if (!state.scan) {
    return (
      <>
        <Nav />
        <main className="max-w-3xl mx-auto px-6 pt-20 pb-32">
          <div className="rounded-xl border border-bg-border bg-bg-panel/40 p-8 text-center">
            <AlertCircle className="w-10 h-10 text-amber mx-auto mb-4" />
            <h1 className="text-xl font-semibold text-ink mb-2">
              No scan state found
            </h1>
            <p className="text-sm text-ink-muted">
              The viewer is pointed at{' '}
              <code className="font-mono text-amber-glow">{state.outputDir}</code>{' '}
              but no <code className="font-mono">state/scan.json</code> exists there yet.
            </p>
          </div>
        </main>
      </>
    );
  }

  const { counts, scan, surfaces } = state;
  const noAuth = surfaces.filter((s) => s.authInScope.length === 0).length;
  const withAuth = counts.surfaces - noAuth;
  const distinctMethods = new Set(
    surfaces.map((s) => s.method).filter((m): m is string => Boolean(m)),
  ).size;

  return (
    <>
      <Nav rootPath={scan.root} />
      <main className="max-w-6xl mx-auto px-6 pt-10 pb-24">
        {/* header */}
        <section className="mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan/30 bg-cyan/5 text-xs font-mono text-cyan-glow mb-5">
            <Compass className="w-3 h-3" />
            Attack surface inventory · {new Date(scan.updatedAt).toLocaleString()}
          </div>
          <h1 className="text-3xl md:text-4xl font-bold tracking-tight leading-tight">
            <span className="text-ink">Surfaces.</span>{' '}
            <span className="text-gradient-cyan">{counts.surfaces}</span>{' '}
            <span className="text-ink">entry point{counts.surfaces === 1 ? '' : 's'} mapped by</span>{' '}
            <span className="text-gradient-amber">{counts.surfacesByAgent.length}</span>{' '}
            <span className="text-ink">recon agent{counts.surfacesByAgent.length === 1 ? '' : 's'}.</span>
          </h1>
          <p className="mt-3 text-sm text-ink-muted">
            Surfaces are an attack-surface inventory — not vulnerabilities. They have
            no severity or verdict; they're the input to downstream auth / validation
            audits.
          </p>
        </section>

        {/* empty state — no surfaces at all */}
        {counts.surfaces === 0 ? (
          <div className="rounded-xl border border-bg-border bg-bg-panel/40 p-8 text-center">
            <Compass className="w-10 h-10 text-cyan mx-auto mb-3" />
            <div className="text-lg font-semibold text-ink">No surfaces yet.</div>
            <p className="mt-2 text-sm text-ink-muted">
              Run a scan with <code className="font-mono text-cyan">-t recon/</code> to map entry points.
            </p>
          </div>
        ) : (
          <>
            {/* stat grid */}
            <section className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10">
              <StatCard
                label="Surfaces"
                value={counts.surfaces}
                hint={`${counts.surfacesByAgent.length} recon agent(s) fired`}
                accent="cyan"
              />
              <StatCard
                label="No auth observed"
                value={noAuth}
                hint={noAuth > 0 ? 'triage these first' : undefined}
                accent="amber"
              />
              <StatCard
                label="Auth in scope"
                value={withAuth}
                hint={withAuth > 0 ? 'still audit downstream' : undefined}
                accent="green"
              />
              <StatCard
                label="HTTP methods"
                value={distinctMethods}
                hint="distinct verbs / triggers"
                accent="neutral"
              />
            </section>

            {/* per-agent strip */}
            <section className="mb-10 rounded-xl border border-bg-border bg-bg-panel/40 p-5">
              <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-ink-dim mb-2">
                Surfaces by recon agent
              </div>
              <div className="flex flex-wrap gap-1.5">
                {counts.surfacesByAgent.map((a) => (
                  <span
                    key={a.slug}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono border border-bg-border bg-bg/40 text-ink-muted"
                  >
                    <span className="text-cyan">{a.slug}</span>
                    <span className="text-ink-dim">×{a.count}</span>
                  </span>
                ))}
              </div>
            </section>

            {/* table */}
            <section>
              <div className="flex items-end justify-between mb-4">
                <div>
                  <div className="text-xs font-mono uppercase tracking-[0.18em] text-cyan mb-1">
                    Surfaces
                  </div>
                  <h2 className="text-xl font-semibold tracking-tight text-ink">
                    All entry points, filterable
                  </h2>
                </div>
                <div className="text-xs text-ink-dim">
                  Default sort: surfaces with no auth observed first.
                </div>
              </div>
              <SurfacesTable
                surfaces={surfaces}
                agents={counts.surfacesByAgent.map((a) => a.slug)}
              />
            </section>
          </>
        )}
      </main>
    </>
  );
}
