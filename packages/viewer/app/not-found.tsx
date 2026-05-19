import { ArrowLeft, FileQuestion } from "lucide-react";
import Link from "next/link";
import Nav from "./components/Nav";

export default function NotFound() {
  return (
    <>
      <Nav />
      <main className="max-w-2xl mx-auto px-6 pt-20 pb-32 text-center">
        <FileQuestion className="w-12 h-12 text-amber mx-auto mb-4" />
        <h1 className="text-2xl font-bold tracking-tight text-ink">Not in this scan</h1>
        <p className="mt-3 text-sm text-ink-muted">
          The finding you asked for is not in the current{" "}
          <code className="font-mono text-cyan">--output</code> directory.
        </p>
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 mt-6 px-4 py-2 rounded-lg bg-amber text-bg font-medium text-sm hover:bg-amber-glow transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to dashboard
        </Link>
      </main>
    </>
  );
}
