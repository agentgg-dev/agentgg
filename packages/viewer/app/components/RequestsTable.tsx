"use client";

import { AlertTriangle, ChevronDown, ChevronRight } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import {
  type CollapsedRequest,
  collapseRequests,
  type HttpExchange,
  isSecretHeader,
  parseHttpBlock,
  shortPath,
  splitHttpBlocks,
  toCurl,
} from "@/app/lib/requests";
import CopyMarkdownButton from "./CopyMarkdownButton";

type Request = { method: string; url: string; status: number; requestBody?: string };

function statusStyle(status: number): string {
  if (status >= 500) return "text-terminal-red";
  if (status >= 400) return "text-terminal-yellow";
  if (status >= 300) return "text-cyan";
  return "text-ink-muted";
}

export default function RequestsTable({
  requests,
  findingId,
  requestsFile,
}: {
  requests: Request[];
  findingId: string;
  requestsFile?: string;
}) {
  const rows = collapseRequests(requests);
  const [open, setOpen] = useState<number | null>(null);
  const [blocks, setBlocks] = useState<string[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);

  // One fetch for the whole file: the record holds no headers and no response
  // body, and both stay local rather than in the mirrored finding.
  useEffect(() => {
    if (open === null || blocks || loadFailed || !requestsFile) return;
    let live = true;
    fetch(`/api/evidence/${findingId}/${encodeURIComponent(requestsFile)}`)
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error(String(r.status)))))
      .then((text) => live && setBlocks(splitHttpBlocks(text)))
      .catch(() => live && setLoadFailed(true));
    return () => {
      live = false;
    };
  }, [open, blocks, loadFailed, requestsFile, findingId]);

  const toggle = useCallback((i: number) => setOpen((cur) => (cur === i ? null : i)), []);

  if (rows.length === 0) return null;

  return (
    <div className="rounded-lg border border-bg-border overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-bg-panel/60 text-ink-dim">
            <th className="w-6" />
            <th className="text-left font-mono font-normal uppercase tracking-wider px-2 py-2">
              Method
            </th>
            <th className="text-left font-mono font-normal uppercase tracking-wider px-2 py-2">
              Path
            </th>
            <th className="text-left font-mono font-normal uppercase tracking-wider px-2 py-2">
              Status
            </th>
            <th className="text-left font-mono font-normal uppercase tracking-wider px-2 py-2">
              Payload
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <Row
              key={row.index}
              row={row}
              open={open === row.index}
              onToggle={() => toggle(row.index)}
              exchange={blocks ? parseHttpBlock(blocks[row.index] ?? "") : null}
              loadFailed={loadFailed || !requestsFile}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Row({
  row,
  open,
  onToggle,
  exchange,
  loadFailed,
}: {
  row: CollapsedRequest;
  open: boolean;
  onToggle: () => void;
  exchange: HttpExchange | null;
  loadFailed: boolean;
}) {
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <>
      <tr
        className="border-t border-bg-border hover:bg-bg-panel/40 cursor-pointer"
        onClick={onToggle}
      >
        <td className="pl-2 text-ink-dim">
          <Chevron className="w-3 h-3" />
        </td>
        <td className="px-2 py-1.5 font-mono text-ink">{row.method}</td>
        <td className="px-2 py-1.5 font-mono text-cyan break-all">{shortPath(row.url)}</td>
        <td className={`px-2 py-1.5 font-mono ${statusStyle(row.status)}`}>{row.status || "—"}</td>
        <td className="px-2 py-1.5 font-mono text-ink-muted break-all max-w-md">
          {row.requestBody ?? ""}
        </td>
      </tr>
      {open && (
        <tr className="border-t border-bg-border bg-bg/40">
          <td colSpan={5} className="px-4 py-3">
            {exchange ? (
              <Exchange exchange={exchange} />
            ) : loadFailed ? (
              <p className="text-ink-dim">
                The full headers are in <span className="font-mono">requests.http</span>, which is
                not available here.
              </p>
            ) : (
              <p className="text-ink-dim">Loading the full exchange…</p>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function Exchange({ exchange }: { exchange: HttpExchange }) {
  const hasSecret = exchange.requestHeaders.some(([n]) => isSecretHeader(n));
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <CopyMarkdownButton
          markdown={toCurl(exchange)}
          label="Copy as curl"
          title="Copy this exchange as a curl command, with its headers and payload"
        />
        {hasSecret && (
          <span className="inline-flex items-center gap-1.5 text-[11px] text-terminal-yellow">
            <AlertTriangle className="w-3 h-3" />
            Carries a live session. Do not paste it into a ticket.
          </span>
        )}
      </div>

      {exchange.decoded.length > 0 && (
        <Pane title="Payload sent">
          {exchange.decoded.map((d) => (
            <div key={d}>{d}</div>
          ))}
        </Pane>
      )}

      <Pane title="Request">
        <div className="text-ink">{`${exchange.method} ${exchange.url}`}</div>
        {exchange.requestHeaders.map(([name, value]) => (
          <div key={name} className={isSecretHeader(name) ? "text-terminal-yellow" : undefined}>
            {name}: {value}
          </div>
        ))}
        {exchange.requestBody && <div className="mt-2 text-ink">{exchange.requestBody}</div>}
      </Pane>

      <Pane title="Response">
        <div className={`${statusStyle(exchange.status)}`}>HTTP {exchange.status}</div>
        {exchange.responseHeaders.map(([name, value]) => (
          <div key={name}>
            {name}: {value}
          </div>
        ))}
        {exchange.responseBody && (
          <pre className="mt-2 whitespace-pre-wrap text-ink max-h-64 overflow-auto">
            {exchange.responseBody}
          </pre>
        )}
      </Pane>
    </div>
  );
}

function Pane({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-ink-dim mb-1">
        {title}
      </div>
      <div className="rounded border border-bg-border bg-bg/60 p-3 font-mono text-[11px] text-ink-muted break-all">
        {children}
      </div>
    </div>
  );
}
