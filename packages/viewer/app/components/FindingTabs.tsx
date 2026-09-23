"use client";

import { useState } from "react";

export type TabName = "Details" | "Validation" | "Evidence";

const TABS: TabName[] = ["Details", "Validation", "Evidence"];

/**
 * Tab state only. The panels arrive as already-rendered server children, so
 * the markdown and the finding data never cross into the client bundle.
 */
export default function FindingTabs({
  details,
  validation,
  evidence,
}: {
  details: React.ReactNode;
  validation: React.ReactNode;
  evidence: React.ReactNode;
}) {
  const [tab, setTab] = useState<TabName>("Details");
  const panels: Record<TabName, React.ReactNode> = {
    Details: details,
    Validation: validation,
    Evidence: evidence,
  };

  return (
    <>
      <div className="flex gap-1 mb-5 border-b border-bg-border" role="tablist">
        {TABS.map((name) => (
          <button
            key={name}
            type="button"
            role="tab"
            aria-selected={tab === name}
            onClick={() => setTab(name)}
            className={`px-4 py-2 text-xs font-mono uppercase tracking-wider border-b-2 -mb-px transition-colors ${
              tab === name
                ? "border-amber text-amber"
                : "border-transparent text-ink-dim hover:text-ink-muted"
            }`}
          >
            {name}
          </button>
        ))}
      </div>
      <div role="tabpanel">{panels[tab]}</div>
    </>
  );
}
