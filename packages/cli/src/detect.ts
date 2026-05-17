import { createHash } from "node:crypto";
import { extname } from "node:path";
import type { Agent, Finding, Surface } from "@agentgg/core";
import { z } from "zod";

/**
 * Subset of `Finding` the LLM is asked to produce. id/agentSlug/
 * filePath are stamped on after the fact — the model shouldn't be
 * inventing those.
 *
 * Shared across both backends (Vercel AI SDK and Claude Agent SDK).
 * The Vercel path uses this as the `generateObject` schema directly;
 * the agent-SDK path prompts for JSON matching this shape and validates
 * the parsed result.
 */
export const LlmFinding = z.object({
  title: z
    .string()
    .describe("Short, specific one-line title. No trailing period."),
  vulnSlug: z
    .string()
    .describe(
      "Short kebab-case label for the vulnerability class (e.g. 'sql-injection').",
    ),
  agentSlug: z
    .string()
    .nullable()
    .describe(
      "Slug of the walker agent whose detection brief surfaced this finding. Required when the investigation pooled multiple agents into one session (so we can attribute findings back). Null in single-agent investigations — the runtime stamps the calling agent's slug.",
    ),
  lineRange: z
    .array(z.number().int().min(1))
    .length(2)
    .nullable()
    .describe("[startLine, endLine], 1-indexed, exactly 2 elements. null if not applicable."),
  filePath: z
    .string()
    .nullable()
    .describe(
      "Path of the file the finding lives in, relative to the repo root. Required only in hunt mode where the agent picks files itself; ignored in file mode where the caller already knows the path.",
    ),
  summary: z
    .string()
    .describe(
      "One sentence stating the issue and its impact. Quotable in a PR comment as-is.",
    ),
  details: z
    .string()
    .describe(
      "Markdown body with the full analysis. Point to the affected source code: include the file path, line numbers, and a fenced code block excerpt. Explain why this code is unsafe.",
    ),
  poc: z
    .string()
    .describe(
      "Concrete reproduction steps. An HTTP request with a payload, a sequence of CLI commands, or a code snippet that triggers the issue.",
    ),
  impact: z
    .string()
    .describe(
      "What kind of vulnerability is it, who is affected, what an attacker gets. Cover blast radius and whether authentication is required.",
    ),
  references: z
    .array(z.string())
    .describe("CWE IDs, OWASP categories, or documentation links. Use [] if none."),
  confidence: z
    .preprocess((v) => (typeof v === "number" && v > 1 ? v / 100 : v), z.number().min(0).max(1))
    .describe("Decimal 0.0–1.0. NOT a percentage. Write 0.9 not 90. 0.0 = guess, 1.0 = certain."),
});
export type LlmFinding = z.infer<typeof LlmFinding>;

/**
 * Subset of `Surface` the LLM produces. Mirrors `LlmFinding` for the
 * recon path: id and the runtime-stamped `agentSlug` (when single-agent)
 * are added after parsing. Recon agents emit this; vuln agents emit
 * `LlmFinding`. Walker pooling can mix both in one batched call.
 */
export const LlmSurface = z.object({
  title: z
    .string()
    .describe(
      "Short, specific one-line title. Conventionally 'Entry point: <METHOD> <PATH>'. No trailing period.",
    ),
  agentSlug: z
    .string()
    .nullable()
    .describe(
      "Slug of the recon agent whose brief surfaced this entry. Required in multi-agent batches (so the runtime can attribute). Null in single-agent investigations — the runtime stamps the calling agent's slug.",
    ),
  filePath: z
    .string()
    .nullable()
    .describe(
      "Path of the file the surface lives in, relative to the repo root. Required only when the agent located it via tools; otherwise the runtime fills it from the candidate file.",
    ),
  lineRange: z
    .array(z.number().int().min(1))
    .length(2)
    .nullable()
    .describe("[startLine, endLine], 1-indexed, exactly 2 elements. null if not applicable."),
  summary: z
    .string()
    .describe(
      "One sentence stating what the surface is — handler name + auth posture is the canonical shape.",
    ),
  method: z
    .string()
    .nullable()
    .describe(
      "HTTP verb (GET/POST/PUT/PATCH/DELETE/...), or 'ALL'/'ANY' for catch-all, or a non-HTTP marker like 'RPC' / 'TASK' / 'EVENT' / 'LAMBDA' / 'WORKER'. Null when not applicable (e.g. mobile manifests).",
    ),
  path: z
    .string()
    .nullable()
    .describe(
      "Route pattern, RPC name, queue name — the identifier at the surface boundary. Null when not applicable.",
    ),
  handler: z
    .string()
    .nullable()
    .describe("Handler function or class name plus line number. Null when not derivable."),
  runtime: z
    .string()
    .nullable()
    .describe(
      "Runtime hint: 'nodejs' / 'edge' / 'lambda' / 'worker' / 'bun' / etc. Null when unknown.",
    ),
  authInScope: z
    .array(z.string())
    .describe(
      "Names of auth middleware / guards / decorators / options observed in scope at this surface, verbatim. Empty array = no auth observed.",
    ),
  surfaceKind: z
    .string()
    .nullable()
    .describe(
      "Short label categorising the surface — 'nextjs-route-handler', 'bullmq-worker', 'aws-lambda', 'graphql-resolver', etc.",
    ),
  details: z
    .string()
    .describe(
      "Markdown body with the structured Method / Path / Handler / Runtime / Auth-in-scope bullets that the agent's prompt asks for.",
    ),
  references: z
    .array(z.string())
    .describe("CWE IDs, framework docs links. Use [] if none."),
  confidence: z
    .preprocess((v) => (typeof v === "number" && v > 1 ? v / 100 : v), z.number().min(0).max(1))
    .describe(
      "Decimal 0.0–1.0. NOT a percentage. 1.0 = unambiguously declared surface, 0.7 = inferred from dynamic registration, 0.5 = uncertain.",
    ),
});
export type LlmSurface = z.infer<typeof LlmSurface>;

/**
 * Walker / hunt structured-output envelope. Carries both vuln findings
 * and recon surfaces so a pooled batch (mixed vuln + recon agents on
 * the same files) can emit both shapes in a single LLM call. Vuln-only
 * batches keep `surfaces: []`; recon-only batches keep `findings: []`.
 */
export const DetectionResult = z.object({
  findings: z.array(LlmFinding).default([]),
  surfaces: z.array(LlmSurface).default([]),
});
export type DetectionResult = z.infer<typeof DetectionResult>;

/**
 * Backend-agnostic contract. Each backend (Vercel AI SDK, Claude Agent
 * SDK) implements this. The orchestrator (scan.ts) doesn't care which
 * one it got — just that the contract holds.
 *
 * Two execution shapes, dispatched by `agent.mode`:
 *
 *   - `detectFile` — runs one prompt against one file's content.
 *     Used by `mode: "file"` agents.
 *   - `hunt` — runs one tool-enabled session across the whole repo.
 *     The agent uses Read/Glob/Grep to find its own targets. Used by
 *     `mode: "hunt"` agents.
 */
export interface Detector {
  /** Short label for logs: "anthropic-api", "anthropic-oauth", "openai", "ollama". */
  readonly name: string;

  /** Per-file review. The caller picks files; the agent reads what it's given. */
  detectFile(args: {
    agent: Agent;
    filePath: string;
    content: string;
  }): Promise<Finding[]>;

  /**
   * Whole-repo hunt with tool access. The agent picks its own files via
   * Read/Glob/Grep, respecting the scope hints injected from CLI flags.
   * Backends that can't run hunt mode (currently OpenAI / Ollama) throw
   * a clear error from this method.
   */
  hunt(args: HuntArgs): Promise<Finding[]>;

  /**
   * Walker-mode per-file investigation. The walker has already
   * enumerated this file as a candidate (matches `filePatterns`, has
   * at least one `preFilter` hit). The model gets the file content,
   * the line-level hits, and tool access to follow imports / chase
   * callers. Same enforcement-by-SDK-schema as `detectFile` and
   * `hunt`. Backends without tool support throw.
   *
   * Returns BOTH findings (from vuln agents in the batch) and
   * surfaces (from recon agents). Either array may be empty depending
   * on the agent mix; both are attributed per-agent by the
   * implementation before returning.
   */
  investigate(args: InvestigateArgs): Promise<InvestigateResult>;

  /**
   * Validation phase — second-pass classifier that re-reads the source
   * code for one finding and decides confirmed / false-positive /
   * out-of-scope / uncertain. Same backend as detection by default;
   * the future `--validate-model` flag can swap to a stronger model.
   */
  validateFinding(args: {
    finding: Finding;
    fileContent: string;
    /** Optional scope document; threaded into the validator prompt verbatim. */
    scope?: string;
  }): Promise<{ verdict: "confirmed" | "false-positive" | "out-of-scope" | "uncertain"; reasoning: string }>;

  /**
   * Scope-only validation — cheaper alternative to `validateFinding`
   * that skips re-reading the source file. The model only sees the
   * finding's metadata + the scope document and is constrained (via
   * the prompt) to return `out-of-scope` or `uncertain`. Used by
   * `revalidate --scope-validate` as a cheap pre-filter to dismiss
   * scope-disqualified findings before paying the full validator cost.
   */
  validateFindingByScope(args: {
    finding: Finding;
    scope: string;
  }): Promise<{ verdict: "confirmed" | "false-positive" | "out-of-scope" | "uncertain"; reasoning: string }>;
}

export interface HuntArgs {
  agent: Agent;
  /** Absolute path to the target codebase. */
  rootDir: string;
  /** User-supplied globs to exclude (additive to walker defaults). */
  excludePatterns: string[];
  /** User-supplied globs to restrict scope to. Empty = no restriction. */
  includePatterns: string[];
  /** Files larger than this should be skipped by the agent. */
  maxFileSizeKb: number;
  /** Cap on tool-use turns for the hunt session. */
  maxTurns: number;
  /**
   * When set, the agent is told to focus its review on this commit's
   * patch. Tools stay unrestricted so the agent can chase callers,
   * imports, and related files outside the diff for context.
   */
  diff?: { commit: string; patch: string };
}

/**
 * One scanner hit inside a candidate file — line number + which
 * preFilter pattern matched. Surfaced to the LLM as anchor points so
 * it doesn't have to rediscover what was suspicious.
 */
export interface InvestigateHit {
  line: number;
  label: string;
  snippet: string;
}

/**
 * One agent's hits in a candidate file. When multiple walker agents
 * flag the same file, the runtime pools them into a single
 * investigation so we don't pay N LLM calls on the same file (matches
 * deepsec's file-scoped, matcher-pooled batching).
 */
export interface InvestigateAgentHits {
  agentSlug: string;
  hits: InvestigateHit[];
}

/**
 * One candidate file in a walker batch. Files arrive here only after
 * walker enumeration (`filePatterns`/`excludePatterns`) plus at least
 * one `preFilter` hit from at least one walker agent.
 */
export interface InvestigateCandidate {
  filePath: string;
  content: string;
  /**
   * Hits grouped by agent slug. A single-agent investigation has one
   * entry here; a multi-agent investigation has one per agent whose
   * preFilter hit this file. Order is stable so the prompt and the
   * model both see the same agent ordering.
   */
  hitsByAgent: InvestigateAgentHits[];
}

/**
 * Return shape of `Detector.investigate(...)`. Walker pooling lets a
 * single LLM call serve both vuln-detection and reconnaissance agents
 * on the same files, so the result carries both arrays. Either may be
 * empty for batches that contain only one kind of agent.
 */
export interface InvestigateResult {
  findings: Finding[];
  surfaces: Surface[];
}

export interface InvestigateArgs {
  /**
   * Every agent contributing to this batch (in stable order). For a
   * single-agent investigation this is `[agent]`; for a cross-agent
   * pooled batch this is the union of agents whose preFilter caught
   * any file in `candidates`. The investigator prompt includes each
   * agent's detection brief.
   */
  agents: Agent[];
  /** Absolute path to the target codebase (for tool cwd). */
  rootDir: string;
  /**
   * Batched candidate files. The LLM sees the whole batch in one
   * session and can cross-reference between them. Same shape as
   * deepsec's `batch: FileRecord[]`.
   */
  candidates: InvestigateCandidate[];
  /** Tool-use turn budget for this whole batched session. */
  maxTurns: number;
}

/**
 * Build the prompt for a hunt-mode invocation. Includes the agent's
 * own instructions, the user-supplied scope, a strategy hint, and a
 * required JSON output spec.
 */
export function buildHuntPrompt(
  agent: Agent,
  args: Pick<HuntArgs, "excludePatterns" | "includePatterns" | "maxFileSizeKb" | "diff">,
): string {
  const excludeLines =
    args.excludePatterns.length > 0
      ? args.excludePatterns.map((p) => `  - ${p}`).join("\n")
      : "  (none)";
  const includeLines =
    args.includePatterns.length > 0
      ? args.includePatterns.map((p) => `  - ${p}`).join("\n")
      : "  (no restrictions — scan the whole repo)";

  // When --diff is set, narrow the hunter's attention to the commit
  // under review without restricting its tools. The block goes first
  // so it's the most prominent thing after the agent's own brief.
  // `args.diff.patch` is the full `git show <commit>` output —
  // metadata, author's commit message, and the patch — so the hunter
  // sees both what changed and the author's stated intent.
  const diffBlock = args.diff
    ? `

---

## Review focus: commit \`${args.diff.commit}\`

A specific commit is under review. Below is its full \`git show\`
output — author / date / message / patch. Focus your investigation
on the changes in this commit: that's the surface area we're asking
about. Read the commit message carefully — the author's stated
intent often tells you what threat model to apply.

Your Read / Glob / Grep tools are NOT restricted to the changed
files: use them freely to pull in surrounding context (callers,
imports, related config, related routes) whenever understanding the
change requires it. But don't go hunt unrelated bugs elsewhere in
the repo — only findings that arise from or relate to this commit
are in scope.

\`\`\`
${args.diff.patch}
\`\`\``
    : "";

  return `${agent.prompt}${diffBlock}

---

You have these tools available: Read, Glob, Grep. Your working
directory is the target repository's root. These tools let you
examine files INSIDE the target codebase — they are not subjects
of your investigation, they are how you conduct it.

## Scope rules

Skip files matching any of these patterns:
${excludeLines}

${
  args.includePatterns.length > 0
    ? `Only scan files matching at least one of these patterns:\n${includeLines}\n`
    : ""
}
Skip files larger than ${args.maxFileSizeKb}KB. Skip lockfiles,
minified bundles, binary assets, and anything inside node_modules /
dist / build / .git / vendor / venv.

## Strategy

${
  args.diff
    ? `The diff above is your starting point. Read the changed files in full to see the change in context, then use Grep/Glob to find callers, related logic, and anything else you need to judge whether the change introduces or fixes the vulnerability you hunt.`
    : `Don't read every file. Use Grep to find candidate locations across the codebase; use Glob to enumerate file shapes. Then Read only the candidates and their imports. Trace logic flow across files when the finding requires it (e.g. checking that a middleware is actually applied to a route).`
}

Be efficient with tool calls. If a single Grep gives you the answer,
don't burn turns reading every match.

## Reporting

Write your findings in whatever form your instructions ask for. Be
specific: include file paths, line numbers, the matched code element,
and an explanation of why it's unsafe. If you investigated something
and it turned out to be safe or already patched, say so explicitly —
that signal lets a downstream consumer distinguish real findings from
analyzed-and-cleared items. Do NOT invent findings to satisfy
expectations — false positives erode trust.`;
}

/**
 * Build the prompt for one walker-mode batched investigation. A
 * batch contains N candidate files (each carrying hits from one OR
 * more walker agents) that the LLM sees in a single session, the
 * same shape deepsec sends to its investigator. When multiple agents
 * flagged the same file, this is what merges them: one investigation
 * looks at the file once, applying every agent's brief.
 */
export function buildInvestigatePrompt(
  agents: ReadonlyArray<Agent>,
  candidates: ReadonlyArray<InvestigateCandidate>,
): string {
  const fileBlocks = candidates
    .map((c, i) => renderCandidateBlock(c, i + 1, candidates.length))
    .join("\n\n---\n\n");

  // Annotate each brief with its expected output type so the model
  // knows whether to emit a Finding (vuln agents) or a Surface (recon
  // agents) for that brief's hits. The annotation is the single most
  // important attribution signal in a mixed batch.
  const briefs = agents
    .map((a) => {
      const tag =
        a.outputType === "surface"
          ? "**Emits:** `surface` (entry-point inventory — NOT a vulnerability)"
          : "**Emits:** `finding` (security vulnerability)";
      return `### Brief: \`${a.slug}\`

${tag}

${a.prompt}`;
    })
    .join("\n\n---\n\n");

  const hasVuln = agents.some((a) => a.outputType !== "surface");
  const hasSurface = agents.some((a) => a.outputType === "surface");
  const multi = agents.length > 1;

  // Output-shape instructions vary by what the batch actually contains.
  // A vuln-only batch shouldn't be told to emit surfaces (the array
  // would be empty), and vice versa. Mixed batches get the full menu.
  const outputShape: string[] = [];
  if (hasVuln && hasSurface) {
    outputShape.push(
      "This batch contains BOTH vulnerability-detection agents (emit `findings`) AND reconnaissance agents (emit `surfaces`).",
      "For each vuln-detection brief's hits: emit a `Finding` (the standard shape — title, vulnSlug, summary, details, poc, impact, references, confidence).",
      "For each recon brief's hits: emit a `Surface` (title, summary, method, path, handler, runtime, authInScope, surfaceKind, details, references, confidence). Surfaces are an attack-surface inventory — they have NO severity, NO impact, NO PoC. Do NOT fabricate vuln data for them.",
      "When a single file is flagged by both a vuln brief and a recon brief, emit BOTH artifacts attributed to their respective agents.",
    );
  } else if (hasSurface) {
    outputShape.push(
      "This batch only contains reconnaissance agents. Emit `surfaces` (NOT `findings`).",
      "A Surface has: title, summary, method, path, handler, runtime, authInScope, surfaceKind, details, references, confidence. NO severity, NO PoC, NO impact — surfaces are an attack-surface inventory, not security claims.",
      "Leave the `findings` array empty.",
    );
  } else {
    outputShape.push(
      "This batch only contains vulnerability-detection agents. Emit `findings` only; leave `surfaces` empty.",
    );
  }

  const attributionRule = multi
    ? `Every emitted artifact (finding OR surface) MUST set \`agentSlug\` to the slug of the brief whose criteria it satisfies. Artifacts without a recognised \`agentSlug\` in a multi-agent batch are dropped.`
    : `Set \`agentSlug\` to \`null\` (or omit it) — the runtime stamps the single agent's slug onto whichever array carries the output.`;

  return `${INVESTIGATOR_SCAFFOLDING}

## Detection brief${multi ? "s" : ""}

${briefs}

---

You are investigating a BATCH of ${candidates.length} candidate file${
    candidates.length === 1 ? "" : "s"
  } flagged by ${
    multi ? `${agents.length} scanner agents` : "the agent's scanner"
  }. You have Read / Glob / Grep available — your working directory
is the repository root. Use the tools to chase imports, callers, and
shared helpers across files in the batch (and outside it when
judgment requires it), but do NOT re-discover the candidate set —
the files below are already the targets.

## Target files

${fileBlocks}

## Output shape

${outputShape.map((s) => `- ${s}`).join("\n")}

## Reporting

Investigate each file in the batch. Apply every applicable brief to
its corresponding hits. For vuln briefs: if a flagged candidate turns
out to be safe or already patched, omit it — do NOT emit a
low-confidence finding to "be thorough." For recon briefs: emit one
surface per declared entry point in the candidate file (recon is
inventory work; partial coverage is worse than no coverage). Be
specific: cite exact line ranges and code elements. Do NOT invent
artifacts to satisfy expectations.

${attributionRule}`;
}

/**
 * Shared investigator scaffolding embedded into every walker prompt.
 * Same intent as deepsec's shared investigator prelude: FP guidance,
 * severity calibration, anti-fabrication rules. Per-detection
 * specialization happens in the agents' brief bodies that follow.
 */
const INVESTIGATOR_SCAFFOLDING = `You are a security auditor investigating one or more candidate files
flagged by scanner agents. Each agent below declares its detection
brief — the bug class it cares about and how to recognize it.

General rules:

- Apply each brief to the hits the corresponding agent flagged. A
  hit is a starting point, not a conclusion — confirm by reading the
  code (use Read/Glob/Grep to chase imports/callers/configs).
- A finding is only "confirmed" when you can identify the specific
  unsafe code element AND articulate the attacker action that
  triggers it.
- When the code looks safe / already mitigated / out of scope, emit
  NO finding for that hit. Empty findings array is the correct
  answer for a clean file.
- Set numeric \`confidence\` honestly: ~0.9 for confirmed, ~0.6 for
  probable / chained, ~0.3 for uncertain. Don't anchor on the brief's
  confidence guidance if your investigation contradicts it.`;

function renderCandidateBlock(
  c: InvestigateCandidate,
  idx: number,
  total: number,
): string {
  const lang = languageFromPath(c.filePath);
  const hitsBlock = c.hitsByAgent
    .map((group) => {
      const visibleHits = group.hits.filter(
        (h) => h.label !== "(no preFilter)",
      );
      if (visibleHits.length === 0) {
        return `  - [${group.agentSlug}] (no specific scanner hits — review the whole file)`;
      }
      return visibleHits
        .map(
          (h) =>
            `  - [${group.agentSlug}] L${h.line} [${h.label}]: ${h.snippet || "(line)"}`,
        )
        .join("\n");
    })
    .join("\n");

  return `### Candidate ${idx} / ${total}: \`${c.filePath}\`

\`\`\`${lang}
${c.content}
\`\`\`

**Scanner pre-filter hits:**

${hitsBlock}`;
}

/**
 * Build the user-message both backends see for a (file, agent) pair.
 * The agent's `prompt` carries the detection criteria; we append the
 * file content with a fenced code block and the anti-fabrication rules.
 */
export function buildDetectPrompt(
  agent: Agent,
  filePath: string,
  content: string,
): string {
  const lang = languageFromPath(filePath);
  return `${agent.prompt}

---

You are now analyzing this file.

File path: ${filePath}

\`\`\`${lang}
${content}
\`\`\`

Report ONLY vulnerabilities that match the criteria above. Do NOT
invent findings to satisfy expectations — false positives erode trust.

Respond with ONLY a JSON object in this exact shape — no prose, no markdown fences:

{"findings":[{"title":"Short title","vulnSlug":"vuln-class","lineRange":[1,10],"filePath":null,"summary":"One sentence.","details":"Full analysis.","poc":"Steps to reproduce.","impact":"Who is affected and what they get.","references":[],"confidence":0.9}]}

IMPORTANT: \`filePath\` MUST be \`null\` — the file path is already known to the caller.

If nothing matches, respond with exactly: {"findings":[]}`;
}

/**
 * Turn an `LlmSurface` into a full `Surface`. Same stable-id and
 * filePath-fallback rules as `hydrateFinding` so re-runs of the same
 * recon agent on the same file dedupe instead of producing parallel
 * entries.
 */
export function hydrateSurface(
  raw: LlmSurface,
  agent: Agent,
  fallbackFilePath: string,
): Surface {
  const filePath =
    raw.filePath != null && raw.filePath.trim() !== "" ? raw.filePath : fallbackFilePath;
  const lineKey = raw.lineRange != null ? `${raw.lineRange[0]}-${raw.lineRange[1]}` : "0";
  const id = createHash("sha256")
    .update(`${agent.slug}|${filePath}|${raw.title}|${lineKey}`)
    .digest("hex")
    .slice(0, 12);
  return {
    id,
    agentSlug: agent.slug,
    title: raw.title,
    filePath,
    lineRange: raw.lineRange != null ? (raw.lineRange as [number, number]) : undefined,
    summary: raw.summary,
    method: raw.method ?? undefined,
    path: raw.path ?? undefined,
    handler: raw.handler ?? undefined,
    runtime: raw.runtime ?? undefined,
    authInScope: raw.authInScope ?? [],
    surfaceKind: raw.surfaceKind ?? undefined,
    details: raw.details,
    references: raw.references ?? [],
    confidence: raw.confidence,
  };
}

/**
 * Take a raw walker `DetectionResult` from the LLM, attribute each
 * finding / surface to the right walker agent in the batch, and
 * hydrate them into the runtime types. Shared between detector
 * implementations so attribution rules stay identical:
 *
 *   - Single-agent batch: every artifact stamped with that agent. The
 *     model is told it MAY omit `agentSlug`.
 *   - Multi-agent batch: trust the model's `agentSlug` tag. Drop any
 *     artifact whose tag isn't a recognised agent in this batch.
 *
 *   - A finding attributed to a recon agent (outputType === "surface")
 *     is misattribution by the model; drop it. Same for a surface
 *     attributed to a vuln agent. The output-type tag in the prompt
 *     is unambiguous — the model only emits the wrong shape when it
 *     hallucinates against the brief.
 */
export function attributeInvestigateResult(
  raw: DetectionResult,
  agents: ReadonlyArray<Agent>,
  candidates: ReadonlyArray<InvestigateCandidate>,
): { findings: Finding[]; surfaces: Surface[] } {
  const agentsBySlug = new Map(agents.map((a) => [a.slug, a]));
  const fallbackFilePath = candidates[0]?.filePath ?? "(unknown)";
  const singleAgent = agents.length === 1 ? agents[0] : undefined;

  const findings: Finding[] = [];
  for (const f of raw.findings) {
    const owningAgent = (() => {
      if (singleAgent) return singleAgent;
      if (f.agentSlug && agentsBySlug.has(f.agentSlug)) {
        return agentsBySlug.get(f.agentSlug)!;
      }
      return undefined;
    })();
    if (!owningAgent) continue;
    // Drop findings attributed to a recon agent — recon agents emit
    // surfaces, not findings. The model is told this explicitly in
    // the prompt; cross-attribution is hallucination.
    if (owningAgent.outputType === "surface") continue;
    findings.push(hydrateFinding(f, owningAgent, f.filePath ?? fallbackFilePath));
  }

  const surfaces: Surface[] = [];
  for (const s of raw.surfaces) {
    const owningAgent = (() => {
      if (singleAgent) return singleAgent;
      if (s.agentSlug && agentsBySlug.has(s.agentSlug)) {
        return agentsBySlug.get(s.agentSlug)!;
      }
      return undefined;
    })();
    if (!owningAgent) continue;
    // Mirror of the findings rule: a surface attributed to a vuln agent
    // is misattribution; drop it.
    if (owningAgent.outputType !== "surface") continue;
    surfaces.push(hydrateSurface(s, owningAgent, s.filePath ?? fallbackFilePath));
  }

  return { findings, surfaces };
}

/**
 * Turn an LLM-produced partial into a full `Finding`. id is a stable
 * content hash of (agentSlug, filePath, title, lineRange) so re-runs
 * dedupe naturally instead of producing parallel records for the same
 * issue. agentSlug + filePath come from the caller, not the model.
 */
export function hydrateFinding(
  raw: LlmFinding,
  agent: Agent,
  fallbackFilePath: string,
): Finding {
  // In hunt mode the LLM is responsible for `filePath` (it discovered
  // the file itself); in file mode the caller supplies it. Prefer the
  // LLM's value when present so the id stays stable across runs.
  const filePath = raw.filePath != null && raw.filePath.trim() !== "" ? raw.filePath : fallbackFilePath;
  const lineKey = raw.lineRange != null
    ? `${raw.lineRange[0]}-${raw.lineRange[1]}`
    : "0";
  const id = createHash("sha256")
    .update(`${agent.slug}|${filePath}|${raw.title}|${lineKey}`)
    .digest("hex")
    .slice(0, 12);
  return {
    id,
    agentSlug: agent.slug,
    title: raw.title,
    vulnSlug: raw.vulnSlug,
    filePath,
    lineRange: raw.lineRange != null ? (raw.lineRange as [number, number]) : undefined,
    summary: raw.summary,
    details: raw.details,
    poc: raw.poc,
    impact: raw.impact,
    references: raw.references ?? [],
    confidence: raw.confidence,
    notifications: [],
  };
}

export function languageFromPath(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  switch (ext) {
    case ".ts":
    case ".tsx":
    case ".mts":
    case ".cts":
      return "typescript";
    case ".js":
    case ".jsx":
    case ".mjs":
    case ".cjs":
      return "javascript";
    case ".py":
      return "python";
    case ".rb":
      return "ruby";
    case ".go":
      return "go";
    case ".rs":
      return "rust";
    case ".java":
      return "java";
    case ".kt":
    case ".kts":
      return "kotlin";
    case ".cs":
      return "csharp";
    case ".php":
      return "php";
    case ".sh":
    case ".bash":
      return "bash";
    case ".json":
      return "json";
    case ".yml":
    case ".yaml":
      return "yaml";
    case ".html":
    case ".htm":
      return "html";
    case ".sql":
      return "sql";
    default:
      return "";
  }
}
