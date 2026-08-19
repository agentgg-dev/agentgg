import type { AgentCandidate } from "./detect.js";
import type { PreFilterHit } from "./pre-filter.js";

/**
 * One place in a file the model is asked to look at. Several raw hits can
 * point at the same place — two regexes matching one line, or a regex and a
 * semgrep rule on the same range — so they are one location and the anchor
 * cap charges for them once. Source-agnostic on purpose: regex anchors are
 * unbounded too, and the prompt renders both kinds the same way.
 */
export interface AnchorLocation {
  line: number;
  endLine: number;
  hits: PreFilterHit[];
}

/** `L12` and `L12-18` are different places, so the span is the key. */
function locationKey(h: PreFilterHit): string {
  return `${h.line}:${h.endLine ?? h.line}`;
}

/** Group a file's raw hits into distinct locations, sorted by line. */
export function toLocations(hits: readonly PreFilterHit[]): AnchorLocation[] {
  const byKey = new Map<string, AnchorLocation>();
  for (const h of hits) {
    const key = locationKey(h);
    const existing = byKey.get(key);
    if (existing) existing.hits.push(h);
    else byKey.set(key, { line: h.line, endLine: h.endLine ?? h.line, hits: [h] });
  }
  return [...byKey.values()].sort((a, b) => a.line - b.line || a.endLine - b.endLine);
}

/** Distinct places in this candidate — what the anchor cap charges for. */
export function anchorLoad(c: AgentCandidate): number {
  return toLocations(c.hits).length;
}

/**
 * Identity of one shard within its file, and the key per-shard resume
 * stores. The line span is part of the key, so a changed rule set (new
 * anchors, new boundaries) cannot resume onto a stale cut — the key simply
 * misses and the shard re-runs. Shards of one file hold disjoint line
 * ranges, so two of them never produce the same key.
 */
export function shardKeyOf(c: AgentCandidate): string {
  const locs = toLocations(c.hits);
  if (locs.length === 0) return "0-0:0";
  return `${locs[0].line}-${locs[locs.length - 1].endLine}:${locs.length}`;
}

/**
 * Split one candidate into shards of at most `maxAnchors` locations, each a
 * contiguous line range. A file at or under the cap is returned as the SAME
 * object with its hit order untouched, so a scan that never trips the cap
 * renders byte-identical prompts to a build without it.
 */
export function shardCandidate(c: AgentCandidate, maxAnchors: number): AgentCandidate[] {
  if (!Number.isFinite(maxAnchors) || maxAnchors <= 0) return [c];
  const locs = toLocations(c.hits);
  if (locs.length <= maxAnchors) return [c];
  const shards: AgentCandidate[] = [];
  for (let i = 0; i < locs.length; i += maxAnchors) {
    shards.push({
      filePath: c.filePath,
      content: c.content,
      hits: locs.slice(i, i + maxAnchors).flatMap((l) => l.hits),
    });
  }
  return shards;
}

/**
 * Pack candidates into batches under two ceilings: at most `maxFiles`
 * entries, and at most `maxAnchors` anchor locations. Whichever binds first
 * closes the batch. With `maxAnchors` disabled this is exactly the fixed
 * slice it replaces.
 *
 * A sharded file needs no special case here. It only split because its total
 * exceeded the cap, so any two of its shards also exceed it and the anchor
 * ceiling rejects the pair on its own — one prompt never inlines the same
 * file content twice.
 */
export function packBatches(
  candidates: readonly AgentCandidate[],
  maxFiles: number,
  maxAnchors: number,
): AgentCandidate[][] {
  const batches: AgentCandidate[][] = [];
  let current: AgentCandidate[] = [];
  let load = 0;
  for (const c of candidates) {
    const n = anchorLoad(c);
    const full = current.length >= maxFiles || load + n > maxAnchors;
    if (current.length > 0 && full) {
      batches.push(current);
      current = [];
      load = 0;
    }
    current.push(c);
    load += n;
  }
  if (current.length > 0) batches.push(current);
  return batches;
}
