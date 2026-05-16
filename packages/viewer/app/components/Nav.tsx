import Link from 'next/link';
import { FileSearch, FolderOpen } from 'lucide-react';

type Props = {
  rootPath?: string;
};

export default function Nav({ rootPath }: Props) {
  return (
    <header className="sticky top-0 z-50 backdrop-blur-xl bg-bg/70 border-b border-bg-border">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 group">
          <span className="inline-flex items-center justify-center w-8 h-8 rounded-md bg-bg-panel border border-bg-border">
            <FileSearch className="w-4 h-4 text-amber" />
          </span>
          <span className="font-mono text-[15px] tracking-tight">
            <span className="text-cyan">agent</span>
            <span className="text-amber">gg</span>
          </span>
          <span className="hidden sm:inline-block ml-1 text-[10px] font-mono uppercase tracking-widest text-ink-dim border border-bg-border px-1.5 py-0.5 rounded">
            report
          </span>
        </Link>

        {rootPath && (
          <div className="hidden md:flex items-center gap-2 text-xs font-mono text-ink-muted max-w-[55%] truncate">
            <FolderOpen className="w-3.5 h-3.5 text-ink-dim shrink-0" />
            <span className="truncate" title={rootPath}>{rootPath}</span>
          </div>
        )}
      </div>
    </header>
  );
}
