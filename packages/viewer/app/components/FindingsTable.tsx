"use client";

import type { Finding, Severity } from "@agentgg/core";
import { ChevronRight, Search } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { ConfidenceBar, DuplicateBadge, SeverityBadge, VerdictBadge } from "./Badges";

type Props = {
  findings: Finding[];
  agents: string[];
};

type AgentFilter = "all" | string;
type VerdictFilter =
  | "all"
  | "confirmed"
  | "false-positive"
  | "out-of-scope"
  | "uncertain"
  | "pending";
type SeverityFilter = "all" | Severity | "unscored";
// Dedup status is orthogonal to the validation verdict (a finding can be
// confirmed AND a duplicate), so it gets its own axis: show both, only the
// duplicates, or only the uniques (primaries + never-duplicated findings).
type DedupFilter = "all" | "duplicate" | "unique";

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
  unscored: 0,
};

export default function FindingsTable({ findings, agents }: Props) {
  const [agent, setAgent] = useState<AgentFilter>("all");
  // Default to the shippable view: confirmed findings, duplicates excluded.
  // Users can widen to "All verdicts" / "Dup & unique" from the dropdowns.
  const [verdict, setVerdict] = useState<VerdictFilter>("confirmed");
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [dedup, setDedup] = useState<DedupFilter>("unique");
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const result = findings
      .map((f, i) => ({ f, i }))
      .filter(({ f }) => {
        if (agent !== "all" && f.agentSlug !== agent) return false;
        if (verdict !== "all") {
          const v = f.validation?.verdict ?? "pending";
          if (v !== verdict) return false;
        }
        if (dedup === "duplicate" && !f.dedup) return false;
        if (dedup === "unique" && f.dedup) return false;
        if (severity !== "all") {
          const s = f.severity ?? "unscored";
          if (s !== severity) return false;
        }
        if (q) {
          const hay = `${f.title} ${f.filePath} ${f.summary} ${f.agentSlug}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

    result.sort((a, b) => {
      const ra = SEVERITY_RANK[a.f.severity ?? "unscored"] ?? 0;
      const rb = SEVERITY_RANK[b.f.severity ?? "unscored"] ?? 0;
      if (ra !== rb) return rb - ra;
      return a.i - b.i;
    });

    return result.map((x) => x.f);
  }, [findings, agent, verdict, severity, dedup, query]);

  const anyDuplicates = useMemo(() => findings.some((f) => f.dedup), [findings]);

  return (
    <div className="rounded-xl border border-bg-border bg-bg-panel/30 overflow-hidden">
      {/* filter bar */}
      <div className="flex flex-col md:flex-row md:items-center gap-3 p-4 border-b border-bg-border/60">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-dim" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by title, file, summary…"
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-bg/60 border border-bg-border text-sm text-ink placeholder:text-ink-dim focus:outline-none focus:border-amber/40 transition-colors"
          />
        </div>
        <Selector
          value={severity}
          onChange={(v) => setSeverity(v as SeverityFilter)}
          options={[
            { value: "all", label: "All severities" },
            { value: "CRITICAL", label: "Critical" },
            { value: "HIGH", label: "High" },
            { value: "MEDIUM", label: "Medium" },
            { value: "LOW", label: "Low" },
            { value: "INFO", label: "Info" },
            { value: "unscored", label: "Unscored" },
          ]}
        />
        <Selector
          value={agent}
          onChange={setAgent}
          options={[
            { value: "all", label: "All agents" },
            ...agents.map((a) => ({ value: a, label: a })),
          ]}
        />
        <Selector
          value={verdict}
          onChange={(v) => setVerdict(v as VerdictFilter)}
          options={[
            { value: "all", label: "All verdicts" },
            { value: "confirmed", label: "Confirmed" },
            { value: "uncertain", label: "Uncertain" },
            { value: "false-positive", label: "False positive" },
            { value: "out-of-scope", label: "Out of scope" },
            { value: "pending", label: "Pending" },
          ]}
        />
        {anyDuplicates && (
          <Selector
            value={dedup}
            onChange={(v) => setDedup(v as DedupFilter)}
            options={[
              { value: "all", label: "Dup & unique" },
              { value: "unique", label: "Unique only" },
              { value: "duplicate", label: "Duplicates only" },
            ]}
          />
        )}
      </div>

      {/* rows */}
      <ul className="divide-y divide-bg-border/60">
        {filtered.length === 0 && (
          <li className="p-8 text-center text-sm text-ink-muted">No findings match this filter.</li>
        )}
        {filtered.map((f) => (
          <li key={f.id}>
            <Link
              href={`/finding/${f.id}`}
              className="group flex items-start gap-4 p-4 md:p-5 hover:bg-bg-panel/40 transition-colors"
            >
              <div className="flex flex-col items-center gap-2 pt-1 min-w-[88px]">
                <SeverityBadge severity={f.severity} />
                <VerdictBadge verdict={f.validation?.verdict} />
                <DuplicateBadge dedup={f.dedup} />
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="font-mono text-[11px] text-amber">{f.agentSlug}</span>
                  <span className="text-ink-dim">·</span>
                  <span
                    className="font-mono text-[11px] text-ink-muted truncate"
                    title={f.filePath}
                  >
                    {f.filePath}
                    {f.lineRange ? `:${f.lineRange[0]}-${f.lineRange[1]}` : ""}
                  </span>
                </div>
                <h3 className="text-sm md:text-[15px] font-semibold text-ink leading-snug group-hover:text-amber-glow transition-colors">
                  {f.title}
                </h3>
                <p className="mt-1.5 text-xs md:text-[13px] text-ink-muted line-clamp-2 leading-relaxed">
                  {f.summary}
                </p>
              </div>

              <div className="flex flex-col items-end gap-2 pt-1 shrink-0">
                <ConfidenceBar value={f.confidence} />
                <ChevronRight className="w-4 h-4 text-ink-dim group-hover:text-amber transition-colors" />
              </div>
            </Link>
          </li>
        ))}
      </ul>

      {/* footer count */}
      <div className="px-4 py-2.5 border-t border-bg-border/60 bg-bg/30 text-[11px] font-mono text-ink-dim flex items-center justify-between">
        <span>
          Showing <span className="text-ink">{filtered.length}</span> of{" "}
          <span className="text-ink">{findings.length}</span>
        </span>
        <span>Sorted by severity</span>
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
      className="px-3 py-2 rounded-lg bg-bg/60 border border-bg-border text-sm text-ink focus:outline-none focus:border-amber/40 transition-colors"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value} className="bg-bg-panel">
          {o.label}
        </option>
      ))}
    </select>
  );
}
