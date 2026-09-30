export default function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-bg-border bg-bg-panel/40 p-6 md:p-8 mb-5">
      <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-amber mb-3">
        {title}
      </div>
      {children}
    </section>
  );
}
