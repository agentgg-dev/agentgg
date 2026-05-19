type Props = {
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  accent?: "amber" | "cyan" | "green" | "red" | "neutral";
};

const ACCENT_RING: Record<NonNullable<Props["accent"]>, string> = {
  amber: "hover:border-amber/40",
  cyan: "hover:border-cyan/40",
  green: "hover:border-terminal-green/40",
  red: "hover:border-severity-critical/40",
  neutral: "hover:border-bg-border",
};

const ACCENT_TEXT: Record<NonNullable<Props["accent"]>, string> = {
  amber: "text-amber",
  cyan: "text-cyan",
  green: "text-terminal-green",
  red: "text-severity-critical",
  neutral: "text-ink",
};

export default function StatCard({ label, value, hint, accent = "neutral" }: Props) {
  return (
    <div
      className={`rounded-xl border border-bg-border bg-bg-panel/40 p-5 transition-colors ${ACCENT_RING[accent]}`}
    >
      <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-ink-dim mb-2">
        {label}
      </div>
      <div className={`text-3xl font-semibold tracking-tight ${ACCENT_TEXT[accent]}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-ink-muted">{hint}</div>}
    </div>
  );
}
