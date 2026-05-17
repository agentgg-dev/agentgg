'use client';

import { useMemo, useState } from 'react';
import { Search, ShieldOff, ShieldCheck } from 'lucide-react';
import type { Surface } from '@agentgg/core';

type Props = {
  surfaces: Surface[];
  agents: string[];
};

type AgentFilter = 'all' | string;
// "none" = surface has empty authInScope (the load-bearing triage filter:
// recon's most useful output is "which entry points have no auth wired").
// "any"  = at least one auth helper observed.
type AuthFilter = 'all' | 'none' | 'any';

export default function SurfacesTable({ surfaces, agents }: Props) {
  const [agent, setAgent] = useState<AgentFilter>('all');
  const [auth, setAuth] = useState<AuthFilter>('all');
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return surfaces
      .filter((s) => {
        if (agent !== 'all' && s.agentSlug !== agent) return false;
        if (auth === 'none' && s.authInScope.length > 0) return false;
        if (auth === 'any' && s.authInScope.length === 0) return false;
        if (q) {
          const hay = [
            s.title,
            s.filePath,
            s.summary,
            s.agentSlug,
            s.method ?? '',
            s.path ?? '',
            s.handler ?? '',
            s.surfaceKind ?? '',
            ...s.authInScope,
          ]
            .join(' ')
            .toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      })
      // Sort: auth-empty surfaces first (the triage target), then by file.
      // Inside each bucket the original detection order is preserved so a
      // walker batch's outputs stay together.
      .sort((a, b) => {
        const aEmpty = a.authInScope.length === 0 ? 0 : 1;
        const bEmpty = b.authInScope.length === 0 ? 0 : 1;
        if (aEmpty !== bEmpty) return aEmpty - bEmpty;
        return a.filePath.localeCompare(b.filePath);
      });
  }, [surfaces, agent, auth, query]);

  const noAuthCount = useMemo(
    () => surfaces.filter((s) => s.authInScope.length === 0).length,
    [surfaces],
  );

  return (
    <div className="rounded-xl border border-bg-border bg-bg-panel/30 overflow-hidden">
      {/* filter bar */}
      <div className="flex flex-col md:flex-row md:items-center gap-3 p-4 border-b border-bg-border/60">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-dim" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by method, path, handler, file…"
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-bg/60 border border-bg-border text-sm text-ink placeholder:text-ink-dim focus:outline-none focus:border-cyan/40 transition-colors"
          />
        </div>
        <Selector
          value={agent}
          onChange={setAgent}
          options={[
            { value: 'all', label: 'All recon agents' },
            ...agents.map((a) => ({ value: a, label: a })),
          ]}
        />
        <Selector
          value={auth}
          onChange={(v) => setAuth(v as AuthFilter)}
          options={[
            { value: 'all', label: 'All auth states' },
            { value: 'none', label: `No auth (${noAuthCount})` },
            { value: 'any', label: 'Has auth' },
          ]}
        />
      </div>

      {/* table header */}
      <div className="hidden md:grid grid-cols-[80px_1fr_1fr_180px_1fr] gap-3 px-4 py-2 border-b border-bg-border/60 text-[10px] font-mono uppercase tracking-[0.18em] text-ink-dim">
        <span>Method</span>
        <span>Path</span>
        <span>Handler</span>
        <span>Auth in scope</span>
        <span>File</span>
      </div>

      {/* rows */}
      <ul className="divide-y divide-bg-border/60">
        {filtered.length === 0 && (
          <li className="p-8 text-center text-sm text-ink-muted">
            No surfaces match this filter.
          </li>
        )}
        {filtered.map((s) => (
          <li
            key={s.id}
            className="grid grid-cols-1 md:grid-cols-[80px_1fr_1fr_180px_1fr] gap-3 px-4 py-3 hover:bg-bg-panel/40 transition-colors text-sm"
          >
            <span className="font-mono text-xs text-amber inline-flex items-center">
              {s.method ?? <span className="text-ink-dim">—</span>}
            </span>
            <span className="font-mono text-xs text-ink truncate" title={s.path ?? ''}>
              {s.path ?? <span className="text-ink-dim">—</span>}
            </span>
            <span className="font-mono text-xs text-ink-muted truncate" title={s.handler ?? ''}>
              {s.handler ?? <span className="text-ink-dim">—</span>}
            </span>
            <span className="text-xs">
              {s.authInScope.length === 0 ? (
                <span className="inline-flex items-center gap-1 text-amber-glow">
                  <ShieldOff className="w-3 h-3" />
                  none observed
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-terminal-green">
                  <ShieldCheck className="w-3 h-3" />
                  <span className="font-mono truncate" title={s.authInScope.join(', ')}>
                    {s.authInScope.join(', ')}
                  </span>
                </span>
              )}
            </span>
            <span className="font-mono text-[11px] text-ink-muted truncate" title={s.filePath}>
              {s.filePath}
              {s.lineRange ? `:${s.lineRange[0]}` : ''}
              <span className="block text-[10px] text-ink-dim mt-0.5">
                {s.agentSlug}
              </span>
            </span>
          </li>
        ))}
      </ul>

      {/* footer count */}
      <div className="px-4 py-2.5 border-t border-bg-border/60 bg-bg/30 text-[11px] font-mono text-ink-dim flex items-center justify-between">
        <span>
          Showing <span className="text-ink">{filtered.length}</span> of{' '}
          <span className="text-ink">{surfaces.length}</span>
        </span>
        <span>Sort: no-auth first, then file</span>
      </div>
    </div>
  );
}

type SelectorProps = {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
};

function Selector({ value, onChange, options }: SelectorProps) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="px-3 py-2 rounded-lg bg-bg/60 border border-bg-border text-sm text-ink focus:outline-none focus:border-cyan/40 transition-colors"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value} className="bg-bg-panel">
          {o.label}
        </option>
      ))}
    </select>
  );
}
