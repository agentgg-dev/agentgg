import type { LiveState, LiveStateKind } from "@agentgg/core/live";

const STYLE: Record<LiveStateKind, string> = {
  reproduced: "border-terminal-green/40 bg-terminal-green/10 text-terminal-green",
  refuted: "border-cyan/30 bg-cyan/5 text-cyan",
  "timed-out": "border-terminal-yellow/40 bg-terminal-yellow/10 text-terminal-yellow",
  inconclusive: "border-terminal-yellow/40 bg-terminal-yellow/10 text-terminal-yellow",
  error: "border-terminal-red/40 bg-terminal-red/10 text-terminal-red",
  "not-reproducible": "border-bg-border bg-bg-panel/60 text-ink-dim",
  refused: "border-bg-border bg-bg-panel/60 text-ink-dim",
  duplicate: "border-bg-border bg-bg-panel/60 text-ink-dim",
  "out-of-scope": "border-bg-border bg-bg-panel/60 text-ink-dim",
  "not-run": "border-bg-border bg-bg-panel/60 text-ink-dim",
};

export function LiveResultBadge({ state }: { state: LiveState }) {
  return (
    <span
      title={state.detail}
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border ${STYLE[state.kind]}`}
    >
      live: {state.label}
    </span>
  );
}
