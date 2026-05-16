import { createHash } from "node:crypto";
import { extname } from "node:path";
import type { Agent, Finding } from "@agentgg/core";
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

export const DetectionResult = z.object({
  findings: z.array(LlmFinding),
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
   */
  investigate(args: InvestigateArgs): Promise<Finding[]>;

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
  args: Pick<HuntArgs, "excludePatterns" | "includePatterns" | "maxFileSizeKb">,
): string {
  const excludeLines =
    args.excludePatterns.length > 0
      ? args.excludePatterns.map((p) => `  - ${p}`).join("\n")
      : "  (none)";
  const includeLines =
    args.includePatterns.length > 0
      ? args.includePatterns.map((p) => `  - ${p}`).join("\n")
      : "  (no restrictions — scan the whole repo)";

  return `${agent.prompt}

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

Don't read every file. Use Grep to find candidate locations across
the codebase; use Glob to enumerate file shapes. Then Read only the
candidates and their imports. Trace logic flow across files when the
finding requires it (e.g. checking that a middleware is actually
applied to a route).

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

  const briefs = agents
    .map(
      (a) => `### Brief: \`${a.slug}\`

${a.prompt}`,
    )
    .join("\n\n---\n\n");

  const multi = agents.length > 1;
  const attributionRule = multi
    ? `When multiple agents' briefs are listed above, every finding MUST set \`agentSlug\` to the slug of the brief whose detection criteria the finding satisfies. Findings without \`agentSlug\` in a multi-agent batch are dropped.`
    : `Set \`agentSlug\` to \`null\` (or omit it) — the runtime stamps the single agent's slug.`;

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

## Reporting

Investigate each file in the batch. Apply every applicable detection
brief to its corresponding hits. If a flagged candidate turns out to
be safe or already patched, simply omit it from the findings — do
NOT emit a low-confidence finding to "be thorough." For each real
issue, every finding's \`filePath\` should be the file the bug lives
in (one of the batch members, or a related file you uncovered while
tracing — set \`filePath\` accordingly). Be specific: cite the
exact line range and code element. Do NOT invent findings to satisfy
expectations — false positives erode trust.

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
