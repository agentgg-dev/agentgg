"use client";

import { Check, Copy } from "lucide-react";
import { useCallback, useState } from "react";

export default function CopyMarkdownButton({
  markdown,
  className = "",
}: {
  markdown: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);

  const onClick = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(markdown);
      setFailed(false);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
      setFailed(true);
      window.setTimeout(() => setFailed(false), 2000);
    }
  }, [markdown]);

  return (
    <button
      type="button"
      onClick={onClick}
      title="Copy this finding as markdown"
      className={`inline-flex items-center gap-1.5 rounded border border-bg-border bg-bg/40 px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider text-ink-dim transition-colors hover:border-amber/40 hover:text-amber ${className}`}
    >
      {copied ? (
        <>
          <Check className="w-3 h-3 text-terminal-green" />
          <span className="text-terminal-green">Copied</span>
        </>
      ) : failed ? (
        <>
          <Copy className="w-3 h-3" />
          <span>Failed</span>
        </>
      ) : (
        <>
          <Copy className="w-3 h-3" />
          <span>Copy</span>
        </>
      )}
    </button>
  );
}
