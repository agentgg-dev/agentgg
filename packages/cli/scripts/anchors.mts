// Anchor-only check: runs the exact pre-filter a scan runs, with no LLM call.
// Usage: tsx packages/cli/scripts/anchors.mts <target-dir> <agent.md> <rules-dir>
import { readFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { loadAgentsFromDir } from "@agentgg/core";
import { renderHit } from "../src/detect.js";
import { evaluatePreFilter } from "../src/pre-filter.js";
import { runSemgrepPreFilter } from "../src/semgrep.js";
import { walkForAgents } from "../src/walker.js";

const [target, agentPath, rulesDir] = process.argv.slice(2);
const { agents, errors } = loadAgentsFromDir(resolve(agentPath, ".."), {
  kind: "official",
  collectErrors: true,
});
for (const e of errors) console.error("load error:", e);
const slug = readFileSync(agentPath, "utf8").match(/^slug:\s*(\S+)/m)?.[1];
const agent = agents.find((a) => a.slug === slug);
if (!agent) throw new Error(`no agent with slug ${slug}`);

const root = resolve(target);
const [work] = walkForAgents(root, [agent], {
  excludePatterns: agent.where.excludePatterns,
  includePatterns: [],
  maxFileSizeBytes: 1024 * 1024,
});
const files = work ? work.files : [];
console.log(`${agent.slug}: ${files.length} file(s) in scope`);

const { hits, degraded } = await runSemgrepPreFilter(
  root,
  agent,
  files,
  [resolve(rulesDir)],
  4,
  (m) => console.warn("warn:", m),
  process.env,
  { onInfo: (m) => console.log("  " + m) },
);
if (degraded) console.error("DEGRADED:", degraded);

for (const rel of files) {
  const content = readFileSync(resolve(root, rel), "utf8");
  const lines = content.split("\n");
  const all = [
    ...evaluatePreFilter(content, agent.where.preFilter),
    ...(hits.get(rel) ?? []).map((h) => ({
      ...h,
      snippet: (lines[h.line - 1] ?? "").trim().slice(0, 200),
    })),
  ].filter((h) => h.label !== "(no preFilter)");
  if (all.length === 0) continue;
  // Print through the prompt's own renderer. A second format here would let
  // this script pass while the bytes the model reads are wrong.
  console.log(`\n${relative(root, resolve(root, rel))}`);
  console.log("**Scanner anchor lines:**\n");
  for (const h of all) console.log(renderHit(h));
}
