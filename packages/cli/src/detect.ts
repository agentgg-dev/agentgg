import { createHash } from "node:crypto";
import { extname } from "node:path";
import type { Agent, CvssScore, Finding } from "@agentgg/core";
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
  title: z.string().describe("Short, specific one-line title. No trailing period."),
  vulnSlug: z
    .string()
    .describe("Short kebab-case label for the vulnerability class (e.g. 'sql-injection')."),
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
    .describe("One sentence stating the issue and its impact. Quotable in a PR comment as-is."),
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

export const DetectionResult = z.object({
  findings: z.array(LlmFinding),
});
export type DetectionResult = z.infer<typeof DetectionResult>;

/**
 * What the recon agent returns — the LLM-produced portion of a
 * `ReconReport`. The orchestrator stamps `reconHash` + `generatedAt`
 * after the fact. Kept deliberately CONCISE: this brief is prepended
 * to precondition prompt checks and to every queued agent's first
 * detection prompt, so it must stay short.
 */
export const ReconResult = z.object({
  purpose: z.string().describe("1–3 sentences: what this project is and does."),
  languages: z
    .array(z.string())
    .describe('Primary languages, lowercase (e.g. "typescript", "go"). [] if unclear.'),
  frameworks: z
    .array(z.string())
    .describe('Frameworks / major libraries (e.g. "next.js", "express"). [] if none.'),
  authModel: z
    .string()
    .nullable()
    .describe("1–2 sentences on how auth/identity works, or null if none / not discernible."),
  integrations: z
    .array(z.string())
    .describe("External services, datastores, third-party integrations. [] if none."),
  notableDirs: z
    .array(z.string())
    .describe("Directories a security reviewer should focus on. [] if nothing stands out."),
  summary: z
    .string()
    .describe(
      "One short paragraph, ~80 words max, orienting a security reviewer: what it is, the stack, the auth model, the highest-risk surface. Orientation, not an audit. Never multiple paragraphs.",
    ),
});
export type ReconResult = z.infer<typeof ReconResult>;

/**
 * The LLM's answer to a `precondition.prompt` gate: is this agent
 * relevant to the project described by the recon brief? Cheap, single
 * call, no tools — the recon brief is already in the prompt.
 */
export const PreconditionCheck = z.object({
  relevant: z
    .boolean()
    .describe("true if the agent should run against this project, false to skip it."),
  reason: z.string().describe("One short sentence justifying the decision."),
});
export type PreconditionCheck = z.infer<typeof PreconditionCheck>;

/**
 * Backend-agnostic contract. Each backend (Vercel AI SDK, Claude Agent
 * SDK) implements this. The orchestrator (scan.ts) doesn't care which
 * one it got — just that the contract holds.
 *
 * The detection surface is one unified `runAgent` (always tool-enabled),
 * preceded by `recon` and `checkPrecondition`, and followed by the
 * `validateFinding` / `validateFindingByScope` / `scoreFinding` passes.
 */
/**
 * Optional abort signal carried by every Detector method. When the
 * orchestrator decides the scan should bail (e.g. a fatal quota
 * diagnostic fired in a sibling worker), it aborts the controller and
 * every in-flight detector HTTP request is cancelled at the SDK layer.
 *
 * Detectors translate `signal` to their underlying SDK's preferred
 * shape: Vercel AI SDK consumes `abortSignal`; Claude Agent SDK wants
 * an `AbortController` (we wrap via a linked controller). Detectors
 * MUST NOT swallow `AbortError` — let it propagate so the per-(file,
 * agent) catch in scan.ts leaves the FileRecord untouched, preserving
 * resume.
 */
export type AbortableArgs = { signal?: AbortSignal };

export interface Detector {
  /** Short label for logs: "anthropic-api", "anthropic-oauth", "openai", "ollama". */
  readonly name: string;

  /**
   * Recon pass — run once at the start of a scan, before any agent.
   * A tool-enabled session (Read/Glob/Grep) that surveys the repo and
   * returns a CONCISE high-level brief. The brief is injected into
   * precondition prompt checks and into each queued agent's first
   * detection prompt so the model starts oriented. Backends without
   * tool support produce a best-effort brief from whatever context
   * they can see.
   */
  recon(args: ReconArgs & AbortableArgs): Promise<ReconResult>;

  /**
   * Precondition `prompt` gate — decide whether an agent is relevant to
   * the current project. The model sees the recon brief + the agent's
   * relevance condition and answers a boolean + reason. Single call, no
   * tools. Only invoked for agents that declare `precondition.prompt`;
   * the cheap `regex` checks are evaluated in `precondition.ts` without
   * an LLM.
   */
  checkPrecondition(args: PreconditionCheckArgs & AbortableArgs): Promise<PreconditionCheck>;

  /**
   * Run one queued agent over a batch of seeded `candidates` — files (with
   * preFilter hit anchors) the agent starts from. Always tool-enabled
   * (Read/Glob/Grep), so the agent reads beyond the batch when needed. The
   * recon brief is prepended for context, and `--diff` narrows attention to
   * a commit. One agent per call — findings are stamped with the agent's
   * slug by the runtime.
   */
  runAgent(args: RunAgentArgs & AbortableArgs): Promise<Finding[]>;

  /**
   * Validation phase — second-pass classifier that re-reads the source
   * code for one finding and decides confirmed / false-positive /
   * out-of-scope / uncertain. Same backend as detection by default;
   * the future `--validate-model` flag can swap to a stronger model.
   */
  validateFinding(
    args: {
      finding: Finding;
      fileContent: string;
      /** Optional scope document; threaded into the validator prompt verbatim. */
      scope?: string;
    } & AbortableArgs,
  ): Promise<{
    verdict: "confirmed" | "false-positive" | "out-of-scope" | "uncertain";
    reasoning: string;
  }>;

  /**
   * Scope-only validation — cheaper alternative to `validateFinding`
   * that skips re-reading the source file. The model only sees the
   * finding's metadata + the scope document and is constrained (via
   * the prompt) to return `out-of-scope` or `uncertain`. Used by
   * `revalidate --scope-validate` as a cheap pre-filter to dismiss
   * scope-disqualified findings before paying the full validator cost.
   */
  validateFindingByScope(args: { finding: Finding; scope: string } & AbortableArgs): Promise<{
    verdict: "confirmed" | "false-positive" | "out-of-scope" | "uncertain";
    reasoning: string;
  }>;

  /**
   * Scoring phase — pick the 8 CVSS 3.1 base metrics for one finding.
   * The LLM only chooses metric values; the vector string, the numeric
   * base score, and the severity bucket are computed deterministically
   * in `scoring.asCvssScore`. Same prompting shape as validation
   * (finding + file content), so the model can ground its metric
   * choices in the actual code rather than the detector's prose.
   */
  scoreFinding(args: { finding: Finding; fileContent: string } & AbortableArgs): Promise<CvssScore>;

  /**
   * De-duplication phase — the final gather pass. Given every finding for
   * ONE source file (unioned across agent shards) and, when readable, the
   * file content, return the equivalence classes of findings that describe
   * the same root cause at the same location. The caller marks the
   * non-primary members with a `dedup` field. Single structured-output
   * call, no tools (the finding metadata + file are already in the prompt).
   * Cannot run distributed: it needs all of a file's findings co-located,
   * so it runs only after scan/validate/score complete.
   */
  dedupeFindings(
    args: { filePath: string; findings: Finding[]; fileContent?: string } & AbortableArgs,
  ): Promise<DedupCluster[]>;
}

/**
 * One equivalence class returned by `dedupeFindings`: a primary finding to
 * keep plus the ids of findings that are duplicates of it. Structurally
 * the `LlmDedup` cluster shape from `deduper.ts`; declared here as a plain
 * type so the Detector contract doesn't import the zod module (which
 * imports back from this file).
 */
export interface DedupCluster {
  primaryId: string;
  duplicateIds: string[];
  reasoning: string;
}

/**
 * One seeded candidate file fed into an agent. Produced from the
 * agent's `where` (filePatterns + preFilter). `hits` are the preFilter
 * anchor lines; empty means "no specific anchors — review the file."
 */
export interface AgentCandidate {
  filePath: string;
  content: string;
  hits: InvestigateHit[];
}

export interface RunAgentArgs {
  agent: Agent;
  /** Absolute path to the target codebase (tool cwd). */
  rootDir: string;
  /** Rendered recon brief, prepended for context. */
  recon?: string;
  /** Seeded candidate files from the agent's `where` (always non-empty). */
  candidates: AgentCandidate[];
  /** Excluded paths, used to bound the agent's tools (Vercel path enforces). */
  excludePatterns: string[];
  maxFileSizeKb: number;
  maxTurns: number;
  /** When set, focus the agent on this commit's patch; tools stay open. */
  diff?: { commit: string; patch: string };
}

export interface PreconditionCheckArgs {
  /** The agent's name (for the model's context). */
  agentName: string;
  /** The agent's description (what it looks for). */
  agentDescription: string;
  /** The `precondition.prompt` body — the relevance condition to judge. */
  conditionPrompt: string;
  /** Rendered recon brief, injected so the model can judge relevance. */
  recon?: string;
}

export interface ReconArgs {
  /** Absolute path to the target codebase (tool cwd). */
  rootDir: string;
  /**
   * The recon agent's instructions (the body of the built-in recon
   * agent file). The engine only appends scope + structured-output
   * mechanics around these — the substance lives in the agent file.
   */
  instructions: string;
  /**
   * Static fingerprint tags (from `fingerprint(root)`) handed to the
   * model as a head start so it doesn't re-derive the stack from
   * scratch. Empty when nothing was detected.
   */
  fingerprintTags?: string[];
  /** Globs to skip while surveying (additive to the walker defaults). */
  excludePatterns: string[];
  /** Globs to restrict the survey to. Empty = no restriction. */
  includePatterns: string[];
  /** Files larger than this should be skipped. */
  maxFileSizeKb: number;
  /** Cap on tool-use turns for the recon session. */
  maxTurns: number;
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
 * Wrap the recon agent's instructions with the runtime scope + structured
 * output mechanics. The substance of the recon pass lives in the agent
 * file (`src/agents/recon.md`); this only appends the fingerprint hint,
 * the scope rules, and the brevity/output reminder so the engine stays
 * thin and the agent stays editable.
 */
export function buildReconPrompt(
  args: Pick<
    ReconArgs,
    "instructions" | "fingerprintTags" | "excludePatterns" | "includePatterns" | "maxFileSizeKb"
  >,
): string {
  const tags =
    args.fingerprintTags && args.fingerprintTags.length > 0
      ? args.fingerprintTags.join(", ")
      : "(none detected)";
  const excludeLines =
    args.excludePatterns.length > 0
      ? args.excludePatterns.map((p) => `  - ${p}`).join("\n")
      : "  (none)";
  const includeBlock =
    args.includePatterns.length > 0
      ? `\nOnly look inside files matching at least one of these patterns:\n${args.includePatterns
          .map((p) => `  - ${p}`)
          .join("\n")}\n`
      : "";

  return `${args.instructions}

---

You have these tools: Read, Glob, Grep. Your working directory is the
repository root.

Static fingerprint (a starting hint, may be incomplete): ${tags}

## Scope
Skip files matching any of these patterns:
${excludeLines}
${includeBlock}Skip files larger than ${args.maxFileSizeKb}KB.`;
}

/**
 * Build the precondition `prompt` gate. The model judges whether the
 * agent is worth running against the project described by the recon
 * brief. Bias toward running when genuinely unsure — a skipped agent
 * finds nothing, so false "skip" is worse than a wasted run.
 */
export function buildPreconditionPrompt(args: PreconditionCheckArgs): string {
  const reconBlock = args.recon ? `${args.recon}\n\n---\n\n` : "";
  return `${reconBlock}You are deciding whether a security review agent is RELEVANT to the
project above, before it runs. You are NOT looking for bugs — only
judging relevance.

## Agent
- Name: ${args.agentName}
- Looks for: ${args.agentDescription}

## Relevance condition
${args.conditionPrompt}

Answer whether this agent should run. If the project clearly doesn't
match the condition (e.g. the agent targets a framework or feature the
project doesn't use), answer false. When genuinely unsure, answer true
— skipping a relevant agent is worse than running an unnecessary one.`;
}

/**
 * Build the unified agent prompt. Combines (in order): the recon brief,
 * the agent's own harness/instructions, an optional `--diff` focus block,
 * the seeded candidate files, and reporting guidance. The strict JSON
 * output shape is NOT included here — the Claude backend enforces it via
 * schema, and the Vercel backend appends `jsonOutputInstruction` itself.
 *
 * `candidates` is always non-empty (the orchestrator skips agents with no
 * matching files) — every agent reviews a concrete file set and uses its
 * tools to read beyond it. There is no file-less "roam" mode.
 */
export function buildAgentPrompt(
  args: Pick<RunAgentArgs, "agent" | "recon" | "candidates" | "diff">,
): string {
  const reconBlock = args.recon ? `${args.recon}\n\n---\n\n` : "";

  const diffBlock = args.diff
    ? `

---

## Review focus: commit \`${args.diff.commit}\`

A specific commit is under review. Below is its full \`git show\`
output. Focus your investigation on these changes; read the commit
message for the author's intent. Your tools are NOT restricted to the
changed files — pull in callers, imports, and related config as
needed — but only report findings that arise from or relate to this
commit.

\`\`\`
${args.diff.patch}
\`\`\``
    : "";

  const toolsBlock = `## Your tools

You have Read, Glob, and Grep. Your working directory is the
repository root. Use them to read the files below, follow imports,
chase callers, and confirm a finding before reporting it.`;

  const targetBlock = `## Candidate files

These files were selected as your starting points (some carry scanner
anchor lines). Investigate each one, and use your tools to pull in
related files when judgment requires it. Do NOT re-discover the
candidate set — the files below are already your targets.

${args.candidates.map((c, i) => renderSeededFile(c, i + 1, args.candidates.length)).join("\n\n---\n\n")}`;

  const reporting = `## Reporting

Report only issues that match your detection criteria. For each, cite
the exact file path, line range, and unsafe code element, and explain
why it is exploitable. If a candidate turns out to be safe or already
mitigated, omit it — an empty result is the correct answer for clean
code. Do NOT invent findings to satisfy expectations; false positives
erode trust.`;

  return `${reconBlock}${args.agent.prompt}${diffBlock}

---

${toolsBlock}

${targetBlock}

${reporting}`;
}

function renderSeededFile(c: AgentCandidate, idx: number, total: number): string {
  const lang = languageFromPath(c.filePath);
  const visible = c.hits.filter((h) => h.label !== "(no preFilter)");
  const hitsBlock =
    visible.length > 0
      ? visible.map((h) => `  - L${h.line} [${h.label}]: ${h.snippet || "(line)"}`).join("\n")
      : "  (no specific anchors — review the whole file)";
  return `### Candidate ${idx} / ${total}: \`${c.filePath}\`

\`\`\`${lang}
${c.content}
\`\`\`

**Scanner anchor lines:**

${hitsBlock}`;
}

/**
 * Turn an LLM-produced partial into a full `Finding`. id is a stable
 * content hash of (agentSlug, filePath, title, lineRange) so re-runs
 * dedupe naturally instead of producing parallel records for the same
 * issue. agentSlug + filePath come from the caller, not the model.
 */
export function hydrateFinding(raw: LlmFinding, agent: Agent, fallbackFilePath: string): Finding {
  // In hunt mode the LLM is responsible for `filePath` (it discovered
  // the file itself); in file mode the caller supplies it. Prefer the
  // LLM's value when present so the id stays stable across runs.
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
