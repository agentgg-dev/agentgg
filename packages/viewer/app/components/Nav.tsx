import Image from 'next/image';
import Link from 'next/link';
import { Compass, FolderOpen, ListChecks } from 'lucide-react';

type Props = {
  rootPath?: string;
};

export default function Nav({ rootPath }: Props) {
  return (
    <header className="sticky top-0 z-50 backdrop-blur-xl bg-bg/70 border-b border-bg-border">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between gap-4">
        <Link href="/" className="flex items-center gap-2.5 group">
          <Image
            src="/logo-mini.png"
            alt="agentgg"
            width={32}
            height={32}
            priority
            className="rounded-md"
          />
          <span className="font-mono text-[15px] tracking-tight">
            <span className="text-cyan">agent</span>
            <span className="text-amber">gg</span>
          </span>
          <span className="hidden sm:inline-block ml-1 text-[10px] font-mono uppercase tracking-widest text-ink-dim border border-bg-border px-1.5 py-0.5 rounded">
            report
          </span>
        </Link>

        <nav className="flex items-center gap-1 text-xs font-mono">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-ink-muted hover:text-amber hover:bg-bg-panel/60 transition-colors"
          >
            <ListChecks className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Findings</span>
          </Link>
          <Link
            href="/surfaces"
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-ink-muted hover:text-cyan hover:bg-bg-panel/60 transition-colors"
          >
            <Compass className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Surfaces</span>
          </Link>
        </nav>

        {rootPath && (
          <div className="hidden md:flex items-center gap-2 text-xs font-mono text-ink-muted max-w-[35%] truncate">
            <FolderOpen className="w-3.5 h-3.5 text-ink-dim shrink-0" />
            <span className="truncate" title={rootPath}>{rootPath}</span>
          </div>
        )}
      </div>
    </header>
  );
}
