import { createReadStream, statSync } from "node:fs";
import { join } from "node:path";
import { Readable } from "node:stream";
import { getEvidenceDir } from "@agentgg/core";
import { NextResponse } from "next/server";
import { parseRange } from "@/app/lib/range";
import { findFindingById, getResultsDir } from "@/app/lib/state";

export const dynamic = "force-dynamic";

const CONTENT_TYPES: Record<string, string> = {
  webm: "video/webm",
  mp4: "video/mp4",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  zip: "application/zip",
  har: "application/json",
  http: "text/plain; charset=utf-8",
  ts: "text/plain; charset=utf-8",
};

/** Every name `live.evidence` refers to. A request for anything else is
 *  refused, so the route can never be walked into the rest of the disk. */
function allowedNames(evidence: NonNullable<NonNullable<ReturnType<typeof findFindingById>>>) {
  const ev = evidence.finding.live?.evidence;
  if (!ev) return new Set<string>();
  return new Set(
    [
      ev.trace,
      ev.video,
      ev.har,
      ev.requestsFile,
      ev.script?.path,
      ...(ev.screenshots ?? []),
    ].filter((n): n is string => typeof n === "string" && n.length > 0),
  );
}

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string; name: string }> },
) {
  const { id, name: rawName } = await params;
  const name = decodeURIComponent(rawName);

  const hit = findFindingById(id);
  if (!hit) return NextResponse.json({ error: "finding not found" }, { status: 404 });

  if (!allowedNames(hit).has(name)) {
    return NextResponse.json({ error: "not an evidence file for this finding" }, { status: 404 });
  }

  const path = join(getEvidenceDir(getResultsDir(), hit.finding.agentSlug, id), name);
  let size: number;
  try {
    size = statSync(path).size;
  } catch {
    return NextResponse.json({ error: "evidence file is missing on disk" }, { status: 404 });
  }

  const ext = name.split(".").pop()?.toLowerCase() ?? "";
  const headers: Record<string, string> = {
    "Content-Type": CONTENT_TYPES[ext] ?? "application/octet-stream",
    "Accept-Ranges": "bytes",
    // The evidence holds live session cookies. Keep it out of shared caches.
    "Cache-Control": "private, no-store",
  };

  // A <video> can only seek when the server answers byte-range requests.
  const range = parseRange(req.headers.get("range"), size);
  if (range === "unsatisfiable") {
    return new NextResponse(null, {
      status: 416,
      headers: { ...headers, "Content-Range": `bytes */${size}` },
    });
  }
  if (range) {
    const { start, end } = range;
    const stream = Readable.toWeb(createReadStream(path, { start, end })) as ReadableStream;
    return new NextResponse(stream, {
      status: 206,
      headers: {
        ...headers,
        "Content-Range": `bytes ${start}-${end}/${size}`,
        "Content-Length": String(end - start + 1),
      },
    });
  }

  const stream = Readable.toWeb(createReadStream(path)) as ReadableStream;
  return new NextResponse(stream, {
    headers: { ...headers, "Content-Length": String(size) },
  });
}
