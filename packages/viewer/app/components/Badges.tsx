import type { Severity, ValidationVerdict } from '@agentgg/core';

const SEVERITY_STYLE: Record<Severity, string> = {
  CRITICAL: 'border-severity-critical/40 bg-severity-critical/10 text-severity-critical',
  HIGH: 'border-severity-high/40 bg-severity-high/10 text-severity-high',
  MEDIUM: 'border-severity-medium/40 bg-severity-medium/10 text-severity-medium',
  LOW: 'border-severity-low/40 bg-severity-low/10 text-severity-low',
  INFO: 'border-severity-info/40 bg-severity-info/10 text-severity-info',
};

export function SeverityBadge({ severity }: { severity?: Severity }) {
  if (!severity) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border border-bg-border bg-bg-panel/60 text-ink-dim">
        unscored
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border ${SEVERITY_STYLE[severity]}`}
    >
      {severity}
    </span>
  );
}

const VERDICT_STYLE: Record<ValidationVerdict, string> = {
  confirmed: 'border-terminal-green/40 bg-terminal-green/10 text-terminal-green',
  'false-positive': 'border-bg-border bg-bg-panel/60 text-ink-dim',
  'out-of-scope': 'border-cyan/30 bg-cyan/5 text-cyan',
  uncertain: 'border-terminal-yellow/40 bg-terminal-yellow/10 text-terminal-yellow',
};

export function VerdictBadge({ verdict }: { verdict?: ValidationVerdict }) {
  if (!verdict) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border border-bg-border bg-bg-panel/60 text-ink-dim">
        pending
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border ${VERDICT_STYLE[verdict]}`}
    >
      {verdict}
    </span>
  );
}

export function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? 'bg-terminal-green' : pct >= 50 ? 'bg-terminal-yellow' : 'bg-terminal-red';
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="w-12 h-1.5 rounded-full bg-bg-panel overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[11px] font-mono text-ink-dim">{pct}%</span>
    </div>
  );
}
