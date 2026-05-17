'use client';

import { useState, type MouseEvent } from 'react';

type Agent = { slug: string; count: number };

type Props = {
  agents: Agent[];
  initialLimit?: number;
  color?: 'cyan' | 'amber';
};

export default function AgentBadgeList({
  agents,
  initialLimit = 6,
  color = 'cyan',
}: Props) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? agents : agents.slice(0, initialLimit);
  const hidden = agents.length - initialLimit;
  const slugClass = color === 'amber' ? 'text-amber' : 'text-cyan';

  const toggle = (e: MouseEvent<HTMLButtonElement>) => {
    // Some callers render this list inside an <a>/<Link>; stop the click
    // from triggering navigation when the user is just expanding the list.
    e.preventDefault();
    e.stopPropagation();
    setExpanded((v) => !v);
  };

  return (
    <>
      {visible.map((a) => (
        <span
          key={a.slug}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono border border-bg-border bg-bg/40 text-ink-muted"
        >
          <span className={slugClass}>{a.slug}</span>
          <span className="text-ink-dim">×{a.count}</span>
        </span>
      ))}
      {hidden > 0 && (
        <button
          type="button"
          onClick={toggle}
          className="text-xs text-ink-dim hover:text-ink underline-offset-2 hover:underline focus:outline-none focus:text-ink"
        >
          {expanded ? 'show less' : `+${hidden} more`}
        </button>
      )}
    </>
  );
}
