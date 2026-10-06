import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { extname, resolve } from "node:path";
import type { Agent, CvssScore, Finding, LiveResult, ReconReport } from "@agentgg/core";
import { z } from "zod";
import type { AgentSpec } from "./agent-spec.js";
import type { FixRetry, LiveScript } from "./fixer.js";
import type { PreFilterHit, TaintStep } from "./pre-filter.js";
import type { UsageMeter } from "./usage-meter.js";
import { proofRules } from "./validation/proof-rules.js";
import { CONTROL_TEST, EXPLOIT_TEST } from "./validation/proof-script.js";

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
      "Slug of the agent whose detection brief surfaced this finding. Required when the investigation pooled multiple agents into one session (so we can attribute findings back). Null in single-agent investigations — the runtime stamps the calling agent's slug.",
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
      "Path of the file the finding lives in, relative to the repo root. Required when the agent has no file scope and finds its own targets; ignored when the caller already knows the path because the agent was seeded with it.",
    ),
  summary: z
    .string()
    .describe("One sentence stating the issue and its impact. Quotable in a PR comment as-is."),
  details: z
    .string()
    .describe(
      "Markdown body with the full analysis. Point to the affected source code: include the file path, line numbers, and a fenced code block excerpt copied verbatim from the file (never reconstructed or paraphrased), tagged with the file's language. Explain why this code is unsafe.",
    ),
  poc: z
    .string()
    .describe(
      "Concrete reproduction steps in Markdown. When the issue is reached over HTTP, write each request the attacker sends as a fenced ```http block in raw HTTP form: the request line, the headers that matter (Host, Cookie or Authorization, Content-Type), a blank line, then the exact body. Use placeholders such as <attacker-token> for values the attacker must obtain. Put one short sentence before each block saying what it does, and after the last block say what the response shows. For a non-HTTP issue, give the CLI commands or code snippet in a fenced block instead.",
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
 * Output of the smart-exclude pass: directory globs the LLM judged not
 * worth security-scanning (tests, fixtures, generated code, vendored
 * deps, docs, sample data). Each is applied exactly like a CLI
 * `--exclude` path, so the pass runs FIRST, before recon, and everything
 * downstream inherits the excludes. `reason` is shown in verbose logs so
 * the user can see (and sanity-check) what got dropped.
 */
export const SuggestExcludesResult = z.object({
  excludes: z
    .array(
      z.object({
        glob: z
          .string()
          .describe(
            "A minimatch directory glob to exclude, e.g. `test`, `**/__tests__`, `docs`, `third_party`.",
          ),
        reason: z
          .string()
          .describe("One short line on why this folder is not worth security-scanning."),
      }),
    )
    .describe(
      "Folders NOT worth scanning. Empty when the whole tree is worth scanning. Be conservative: excluding a folder means its code is never reviewed.",
    ),
});
export type SuggestExcludesResult = z.infer<typeof SuggestExcludesResult>;

/**
 * What the reproduce pass returns — the LLM's result after driving a
 * real browser (via Playwright MCP tools) against a live target to
 * reproduce, refute, or fail to settle one finding. `script` is only
 * meaningful when `result` is `reproduced`; the detector enforces that at
 * the call site, not here, so a model that omits or over-populates the
 * field still validates.
 */
/** The script-first path's only output. One field, so a model that wraps its
 *  answer in prose or fences still yields a usable spec. */
export const GeneratedProofScript = z.object({
  script: z
    .string()
    .describe("Complete Playwright spec source carrying both required tests. No markdown fences."),
});
export type GeneratedProofScript = z.infer<typeof GeneratedProofScript>;

export const ReproduceFindingResult = z.object({
  result: z
    .enum(["reproduced", "refuted", "inconclusive"])
    .describe(
      "'reproduced' = you drove the browser through the PoC, observed the vulnerable behavior, and it meets the class's proof rules. 'refuted' = the attack ran and a named control blocked it. 'inconclusive' = anything else, including a run you could not finish.",
    ),
  reasoning: z
    .string()
    .describe(
      "Short prose explaining what you did in the browser and what you observed, and why that supports the result.",
    ),
  counterevidence: z.string().describe("The strongest case against your own result."),
  negativeControl: z
    .string()
    .optional()
    .describe(
      "The control you ran and what happened: the same steps without your input, or without the session. Required when the result is 'reproduced'; a claim without one is downgraded to 'inconclusive'.",
    ),
  script: z
    .string()
    .optional()
    .describe(
      "Self-contained Playwright test source (a repro.spec.ts) that replays every step you performed, including login. Required when result is 'reproduced'; omit otherwise.",
    ),
});
export type ReproduceFindingResult = z.infer<typeof ReproduceFindingResult>;

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
   * Smart-exclude pass — opt-in (`--auto-exclude`), run once BEFORE recon.
   * Given the directory layout, the model picks folders not worth
   * security-scanning; the orchestrator applies them like CLI `--exclude`
   * paths so recon and every agent inherit them. A single structured
   * call, NO tools: the tree is already in the prompt, so the model just
   * classifies folders rather than exploring the repo.
   */
  suggestExcludes(args: SuggestExcludesArgs & AbortableArgs): Promise<SuggestExcludesResult>;

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
      /**
       * Repository root. When provided, the validator runs tool-enabled
       * (Read/Glob/Grep rooted here) so it can trace the exploit chain
       * ACROSS files — e.g. follow a REST endpoint through a service
       * layer to the sink, catching an intermediate filter/guard that the
       * finding's single file doesn't reveal. When omitted, the validator
       * falls back to a single-shot judgement over `fileContent` alone.
       */
      root?: string;
      /**
       * File-visibility knobs mirrored from the scan walk. Honored only on
       * the tool-enabled path (root set): the validator's Read/Glob/Grep
       * skip excluded paths and oversized files, so it traces the chain over
       * the same file set the agent run saw. Ignored on the single-shot path and
       * by backends whose SDK tools can't filter (Claude Agent SDK).
       */
      excludePatterns?: string[];
      maxFileSizeKb?: number;
      /**
       * The reporting agent's `validationPrompt`, when it declares one.
       * Replaces the validator's default judgement rules for this finding
       * only. The caller resolves it from `finding.agentSlug`; a missing
       * agent just means the default rules apply.
       */
      validationPrompt?: string;
      /** The group's duplicates. The verdict then covers the whole group. */
      members?: Finding[];
    } & AbortableArgs,
  ): Promise<{
    verdict: "confirmed" | "false-positive" | "out-of-scope" | "uncertain";
    reasoning: string;
    /** The impact validation confirmed, from any member of the group. */
    confirmedImpact?: string;
    /** A worse claimed impact that validation could not confirm. */
    unconfirmedImpact?: string;
    /** The member whose claim gives `confirmedImpact`. */
    leadId?: string;
    /** Whether the primary's own claim was confirmed. The caller swaps only on
     *  `confirmed` with this set to false. */
    primaryClaimHolds?: boolean;
    /** True when the model declined to validate (refusal); `verdict` is
     *  `uncertain`. The finding stays unvalidated, but the caller records the
     *  refusal instead of treating it as a genuine uncertain verdict. */
    refused?: boolean;
  }>;

  /**
   * Live-validation reproduce pass — optional. Drives a real browser
   * against `baseUrl` (via the Playwright MCP server the sandbox
   * hosts at `browserEndpoint`, an SSE URL) to reproduce or refute one
   * finding's `poc`, then returns a result and, when reproduced, a
   * generated Playwright test that replays it. The session gets ONLY the
   * Playwright MCP tools — no source-tree access — so it works entirely
   * against the running application. `staticVerdict`/`staticReasoning`
   * carry the static validator's own verdict, when one ran, so the live
   * agent can check its evidence against that reasoning rather than
   * re-deriving it blind. Optional on the interface so a backend without
   * tool-driven browser support can skip live validation entirely;
   * callers invoke it as `detector.reproduceFinding?.(args)`.
   */
  reproduceFinding?(args: {
    finding: Finding;
    /** Root URL of the running target the sandbox can reach. */
    baseUrl: string;
    /** SSE URL of the Playwright MCP server hosted by the sandbox. */
    browserEndpoint: string;
    /** Free-form notes folded into the prompt: scope, and the login to use. */
    context?: string;
    /** Per-call turn cap. Overrides the detector's default when set, so a
     *  complex target can be given more browser steps than a demo needs. */
    maxTurns?: number;
    /** Static validator's verdict for this finding, when it ran. */
    staticVerdict?: string;
    /** Static validator's reasoning, quoted into the prompt verbatim. */
    staticReasoning?: string;
    /** The impact static validation confirmed; the agent tests this one. */
    staticConfirmedImpact?: string;
    /** The reporting agent's `liveProofRule`. Adds to the proof principle;
     *  no agent can replace it. */
    proofRule?: string;
    signal?: AbortSignal;
  }): Promise<{
    result: LiveResult;
    reasoning: string;
    /** The strongest case the live agent could make against its own result. */
    counterevidence: string;
    /** The control the agent ran to separate the effect from its own setup.
     *  A `reproduced` without one is downgraded. */
    negativeControl?: string;
    /** True when the model declined to reproduce (refusal); `result` is
     *  `inconclusive`. Mirrors `validateFinding`'s refusal handling. */
    refused?: boolean;
    /** The generated `repro.spec.ts` source. Only present when reproduced. */
    script?: string;
  }>;

  /**
   * Script-first reproduction: one call, no browser tools, returns a Playwright
   * spec that carries both halves of the proof. Optional, so a backend without
   * it falls straight through to `reproduceFinding`.
   */
  generateReproScript?(args: {
    finding: Finding;
    baseUrl: string;
    context?: string;
    proofRule?: string;
    staticVerdict?: string;
    staticReasoning?: string;
    signal?: AbortSignal;
  }): Promise<string>;

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
   *
   * `recon` is the project brief. It anchors the deployment-dependent
   * metrics (Attack Vector, Privileges Required) that the file alone
   * can't disclose — a local CLI/library target should not be scored as
   * a network-reachable service. Optional so a bare `score` run without
   * a recon.json still works.
   */
  scoreFinding(
    args: { finding: Finding; fileContent: string; recon?: ReconReport } & AbortableArgs,
  ): Promise<CvssScore>;

  /**
   * Fix phase — write the remediation for one confirmed finding, as text
   * with SEARCH/REPLACE blocks. The prompt carries the finding, its file,
   * the recon brief and the live run's script when the scan has them.
   * With `root` the call is tool-enabled (Read/Glob/Grep rooted there, same
   * filters as `validateFinding`): a fix often depends on code the
   * finding's file does not hold, and a block may then edit another file.
   * Without `root` it is a single call over `fileContent`. Throws when the
   * answer was cut off or never came. The caller decides which findings
   * qualify, checks the answer against the repository with `finishFix`,
   * and passes a rejected answer back as `retry`. Optional so a backend
   * can opt out; callers invoke it as `detector.suggestFix?.(args)`.
   */
  suggestFix?(
    args: {
      finding: Finding;
      fileContent: string;
      recon?: ReconReport;
      liveScript?: LiveScript;
      root?: string;
      excludePatterns?: string[];
      maxFileSizeKb?: number;
      retry?: FixRetry;
    } & AbortableArgs,
  ): Promise<string>;

  /**
   * De-duplication phase — the gather pass. Given every finding for ONE
   * source file (unioned across agent shards) and, when readable, the
   * file content, return the equivalence classes of findings that describe
   * the same root cause at the same location. The caller marks the
   * non-primary members with a `dedup` field. Single structured-output
   * call, no tools (the finding metadata + file are already in the prompt).
   * Cannot run distributed: it needs all of a file's findings co-located,
   * so it runs only once detection for that file has finished.
   */
  dedupeFindings(
    args: { filePath: string; findings: Finding[]; fileContent?: string } & AbortableArgs,
  ): Promise<DedupCluster[]>;

  /**
   * `agentgg create` author pass. Tool-enabled session (Read/Glob/Grep)
   * that reads a past security report + explores the codebase it came
   * from, then emits an `AgentSpec` (frontmatter + prompt body) that a
   * future `agentgg scan` can run to catch the same anti-pattern if it
   * recurs. Same shape as `recon`: tool-enabled, schema-constrained
   * output. Optional on the interface so a backend can opt out (back-ends
   * without tool support, e.g. raw multi-provider, can implement a
   * best-effort no-tools fallback). Callers invoke as
   * `detector.createAgent?.(args)`.
   */
  createAgent?(args: CreateAgentArgs & AbortableArgs): Promise<AgentSpec>;

  /**
   * Attach a token-usage meter so the detector records `usage` from every LLM
   * response it makes — for observability (see `state/usage.json`), not billing.
   * Optional on the interface so a backend can opt out, but every shipped
   * detector (Vercel / Claude Agent SDK / multi-provider / the Ollama composite)
   * implements it. Callers invoke it as `detector.attachUsageMeter?.(meter)`.
   */
  attachUsageMeter?(meter: UsageMeter): void;
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
  /**
   * Seeded candidate files from the agent's `where`. Empty when the agent
   * declares no file scope: then the whole repository is its scope and it
   * finds its own targets. See `hasFileScope` in @agentgg/core.
   */
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

export interface CreateAgentArgs {
  /** Absolute path to the codebase the past report belongs to (tool cwd). */
  rootDir: string;
  /**
   * Instructions for the create agent (the body of the built-in
   * `create.md` agent file). The engine wraps these with the past
   * report and the AgentSpec output schema mechanics; the substance
   * lives in the agent file.
   */
  instructions: string;
  /** Filename of the past-incident report (for the model's context only). */
  reportName: string;
  /** Full text of the past-incident report. md/txt. */
  reportContent: string;
  /** Globs to skip while exploring the repo. */
  excludePatterns: string[];
  /** Globs to restrict exploration to. Empty = no restriction. */
  includePatterns: string[];
  /** Files larger than this should be skipped. */
  maxFileSizeKb: number;
  /** Cap on tool-use turns for the create session. */
  maxTurns: number;
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
export type InvestigateHit = PreFilterHit;

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

export interface SuggestExcludesArgs {
  /**
   * The smart-exclude agent's instructions (body of the built-in
   * `exclude.md`). The engine only appends the directory tree and the
   * output reminder around these.
   */
  instructions: string;
  /**
   * A compact, depth-limited rendering of the repository's directory
   * layout (folders with file counts). This is the ONLY view the model
   * gets: the pass is no-tools, so the tree stands in for exploration.
   */
  dirTree: string;
}

/**
 * Wrap the smart-exclude agent's instructions with the directory tree and
 * the output reminder. No scope/tool mechanics: this is a single no-tools
 * structured call that classifies the folders it is shown.
 */
export function buildExcludePrompt(args: SuggestExcludesArgs): string {
  return `${args.instructions}

---

## Directory layout

Below is every directory in the repository, by full path, with the
number of files under it. The count is only the folder's size, shown for
context. It is NOT a reason to exclude: a large folder of application
source must still be scanned, and a tiny vendored or test folder should
still be dropped. Nested folders are shown at any depth. Decide from the
paths and folder names. Folders already pruned by default excludes
(node_modules, .git, build output, binaries) are not shown.

\`\`\`
${args.dirTree}
\`\`\`

Return the folder globs to exclude, each with a one-line reason. Return
an empty list if the whole tree is worth scanning.`;
}

/**
 * Build the create-agent prompt. Wraps the create agent's instructions
 * (from `src/agents/create.md`) with the past report and the scope rules
 * the tool session operates under. The output-schema mechanics are
 * enforced by the backend's structured-output layer, not in this string,
 * so the same prompt works against both Claude (json_schema) and the
 * Vercel SDK (json instruction + Zod parse).
 */
export function buildCreateAgentPrompt(
  args: Pick<
    CreateAgentArgs,
    | "instructions"
    | "reportName"
    | "reportContent"
    | "excludePatterns"
    | "includePatterns"
    | "maxFileSizeKb"
  >,
): string {
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

## Past report under review: \`${args.reportName}\`

This is the report you are distilling. Read it carefully, then use your
tools to find where in the codebase the issue happened (or would have
happened pre-fix), so the agent you produce is grounded in this repo's
actual conventions.

\`\`\`
${args.reportContent}
\`\`\`

---

You have these tools: Read, Glob, Grep. Your working directory is the
repository root.

## Scope
Skip files matching any of these patterns:
${excludeLines}
${includeBlock}Skip files larger than ${args.maxFileSizeKb}KB.

## Output

Return exactly one \`AgentSpec\` JSON object. Every regex must compile
as a JavaScript RegExp. The \`slug\` must match \`^[a-z0-9][a-z0-9-]*$\`.`;
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

/** Recorded as the reasoning when the reproduce loop ends with no verdict.
 *  Says the attempt was cut short rather than impersonating an analysis that
 *  never ran. */
export const REPRODUCE_CUT_SHORT =
  "The live reproduction was cut short: the model stopped before it reported a verdict, so this finding was not tested against the running application.";

/** The target owner's notes say how to reach and use the application. A bug
 *  they mention is not the finding under test. */
function targetNotesBlock(context?: string): string {
  return context
    ? `\n## Notes about the application\n\n${context}\n\nUse these notes to reach and use the application: where things are, which\naccounts to use. They do not change what you test. Prove only the finding below, through the input it names.\nIf the notes describe a different issue, leave it alone.\n`
    : "";
}

/** Text a test adds to the page reads as the application's own output. */
const NO_OVERLAY =
  "Do not add your own banner, overlay or label to the page. The sandbox banner already shows the URL and any script execution it captured, and text you add can be taken for the application's output.";

/**
 * Build the reproduce-finding prompt. The model drives a real browser
 * (via the Playwright MCP tools attached to this session — no Read/Glob/
 * Grep) against a live target, then reports `reproduced`, `refuted` or
 * `inconclusive` with its counterevidence and, when reproduced, a
 * Playwright test that replays it end to end.
 */
export function buildReproducePrompt(
  finding: Finding,
  baseUrl: string,
  context?: string,
  staticReview?: { verdict: string; reasoning: string; confirmedImpact?: string },
  /** The reporting agent's `liveProofRule`, when its catalog entry declares
   *  one. It adds to the principle and can never replace it. */
  agentRule?: string,
): string {
  const lineHint = finding.lineRange
    ? `lines ${finding.lineRange[0]}–${finding.lineRange[1]}`
    : "unspecified lines";

  const contextBlock = targetNotesBlock(context);

  const proofRulesBlock = `\n## What counts as proof\n\n${proofRules(agentRule)}\n`;

  const staticReviewBlock = staticReview
    ? `\n## Source review of this finding\n\nA reviewer with the source code reached the verdict \`${staticReview.verdict}\`:\n\n${staticReview.reasoning}\n\nYour result counts as 'reproduced' ONLY if what you observed answers this\nreview. Say in your reasoning how it does.\n${staticReview.confirmedImpact ? `\nThe impact to reproduce is the one the review confirmed:\n\n${staticReview.confirmedImpact}\n\nTest that impact. The finding text below may claim more.\n` : ""}`
    : "";

  // Only a run given a static review owes it an answer; the majority of
  // reproduce calls have none, and the criterion must stay satisfiable there.
  const reviewCriterion = staticReview ? ", and it answers the source review" : "";

  return `You are live-testing a security finding against a running
application, using only the browser tools attached to this session.
You have no access to the source code — work entirely against the live
application.

## Target
Base URL: ${baseUrl}
${contextBlock}
## The finding to reproduce

**Title:** ${finding.title}
**Vuln class:** ${finding.vulnSlug}
**File:** ${finding.filePath} (${lineHint})

### Summary
${finding.summary}

### PoC
${finding.poc}

### Impact
${finding.impact}
${proofRulesBlock}${staticReviewBlock}
## Your task

1. Navigate to ${baseUrl} and, if credentials were given above, log in.
2. Reproduce the PoC above against the live application. If you cannot find
   an HTTP way to reach it, say what you tried and return 'inconclusive'.
3. At the point the vulnerable behavior would appear, take a screenshot
   as proof, whether or not it reproduces. When the finding is cross-site
   scripting, make the injected code prove itself in a way the recording can
   show: call \`alert(document.domain)\`, or set
   \`window.__agentggXss = document.domain\`. The sandbox captures either and
   draws it on the recording. A payload that only changes the title leaves no
   visible proof. ${NO_OVERLAY}
4. Run the control the proof rules ask for: the same steps without your
   input, or without the session. Report what happened in
   \`negativeControl\`. A 'reproduced' result without it is downgraded.
5. Decide a result:
   - 'reproduced': you observed the vulnerable behavior, it meets the proof
     rules above${reviewCriterion}.
   - 'refuted': the attack ran and a named control blocked it. Name the
     control.
   - 'inconclusive': anything else, including a run you could not finish and
     evidence that does not meet the proof rules.
6. When 'reproduced', also write a self-contained Playwright test (the
   source for a \`repro.spec.ts\` file) that replays every step you just
   performed, including login, so someone else can re-run it and see the
   same result. Omit \`script\` otherwise. The script runs unattended, so
   write it for the test runner rather than for a person watching:
   - Anything that blocks page load must be handled before the navigation
     that triggers it, not awaited after it. A handler registered but never
     answered leaves the navigation waiting until the test times out.
   - Assert on what the browser ended up with, not on an intermediate state
     the navigation already consumed on your behalf.
   - Assert the vulnerable effect itself, not a side effect that a fixed
     application would also produce.

Be honest: a PoC that fails to reproduce is a valid, useful outcome. Do
not report 'reproduced' on a guess; only report what you actually observed
in the browser, and give the strongest case against your own result in
\`counterevidence\`.`;
}

/**
 * One-shot prompt for the script-first path: write the proof as a Playwright
 * spec instead of driving the browser turn by turn. No browser tools are
 * attached, so the model gets no feedback and must go straight at the endpoint
 * the finding names. A spec that fails hands the finding to the agent path.
 */
export function buildProofScriptPrompt(
  finding: Finding,
  baseUrl: string,
  context?: string,
  agentRule?: string,
  staticReview?: { verdict: string; reasoning: string },
): string {
  const contextBlock = targetNotesBlock(context);
  const staticBlock = staticReview
    ? `\n## Source review of this finding\n\nA reviewer with the source code reached the verdict \`${staticReview.verdict}\`:\n\n${staticReview.reasoning}\n\nWrite the assertions so that a pass answers this review.\n`
    : "";

  return `Write a Playwright test that proves one security finding against a
running application. You have no browser and no source code: you get one
attempt, and the test is run unattended.

## Target
Base URL: ${baseUrl}
${contextBlock}
## The finding

**Title:** ${finding.title}
**Vuln class:** ${finding.vulnSlug}
**File:** ${finding.filePath}

### Summary
${finding.summary}

### PoC
${finding.poc}

### Impact
${finding.impact}

## What counts as proof

${proofRules(agentRule)}
${staticBlock}
## The two tests

Output ONE spec file with exactly two tests, titled exactly as shown:

- \`test("${EXPLOIT_TEST}", ...)\` drives the PoC and asserts the vulnerable
  effect happened.
- \`test("${CONTROL_TEST}", ...)\` repeats the same steps with the attacker's
  input replaced by a benign value, or with no session, and asserts the effect
  did NOT happen.

Both tests must pass for the finding to count as proved. The control passing is
what separates the effect from your own setup, so do not skip it and do not
make it a copy of the exploit.

## Match the payload to where the value lands

The finding above says where the attacker input is reflected. The payload MUST
suit that context, because a payload for the wrong context does not fire:

- Reflected in the HTML body (between tags): inject an element with an event
  handler, for example \`<img src=x onerror=...>\`. Prefer this over an injected
  \`<script>\`, which a reflected value often will not run.
- Reflected inside an existing \`<script>\` block: you must first break out with
  \`</script>\`, then inject an element with an event handler.
- Reflected inside an HTML attribute (for example \`href="..."\`): close the
  attribute and the tag first, or add an event-handler attribute such as
  \`" onmouseover=... x="\`.
- Reflected inside a JavaScript string: close the quote and statement, for
  example \`';<your code>;//\`.
If the finding does not state the context, send the payload once and read the
raw response (see below) to see how it lands, then choose the payload.

## What to send it in

The attacker input may not be a query value. Send it where the finding says:

- Query or path: build the URL from the base URL above.
- A form field: open the page that shows the form and submit it there (see
  "Show the attack on the recording" below).
- A request header (for example \`X-Forwarded-Host\`): a browser navigation
  CANNOT set request headers. Use \`page.request.get(url, { headers: { ... } })\`,
  or a request body, exactly as the PoC describes.

## The runner, so you do not have to work it out

These are facts about where your test will run. Take them as given:

- Playwright 1.56 with \`@playwright/test\`. Every option in that version's API
  is available to you, including \`maxRedirects\` on a \`page.request\` call.
- The runner reaches the public internet, not only the target.
- \`https://example.com/\` is a stable origin reserved for examples. Use it as
  the outside site when a test has to show the application handing the browser
  to one. Never a domain somebody owns and may change.
- \`page.goto\` follows redirects and ends on the last page, so the browser's own
  URL after it is what you assert on. To see a 3xx response itself, request it
  with \`page.request.get(url, { maxRedirects: 0 })\` and read its \`location\`
  header.

For anything this prompt does not state, choose the simplest approach that can
work and write the test. You cannot settle it from here and the run will settle
it: a doubt you cannot check costs more than the mistake it would avoid.

## How to prove it

For cross-site scripting the effect is that the injected code runs (2 below).
Reflection alone is not the effect: a response the browser does not render as
HTML, for example XML or JSON, carries the payload as text that never runs, and
a broken document or a parse error is not script execution either. Assert
execution, and add the reflection check where you can:

1. Reflection in the raw response. Fetch the exact attack request with
   \`page.request.get(...)\` (or \`.post\`), read \`await res.text()\`, and assert the
   payload appears UNESCAPED in the executable position (its angle brackets,
   quotes or script are intact, not turned into \`&lt;\` / \`&quot;\`). This is
   deterministic and does not depend on the browser running anything.
2. Execution in the browser. Put this at the very top of the test, BEFORE any
   navigation, so an injected handler that calls it is captured:
       await page.addInitScript(() => {
         (window as any).__xssFired = false;
         for (const fn of ["alert", "prompt", "confirm", "print"]) {
           (window as any)[fn] = () => { (window as any).__xssFired = true; };
         }
       });
   Make your payload call one of those functions (for example
   \`onerror=alert(1)\`), navigate with \`page.goto(...)\`, then assert
   \`await page.evaluate(() => (window as any).__xssFired) === true\`. This is more
   reliable than \`page.waitForEvent("dialog")\` and also catches event handlers.

The \`${CONTROL_TEST}\` test runs the same request with a benign value and asserts
the OPPOSITE: the value is absent or HTML-encoded in the response, and
\`__xssFired\` stayed false.

## Record what happened, so the result has a video and a screenshot

Put this once at the top of the file, so each test records a video and a
screenshot at its end, and runs slowly enough to watch:

    test.use({ video: "on", screenshot: "on", launchOptions: { slowMo: 400 } });

At the start of every test, before any navigation, load the recording banner so
the video and screenshot show the URL, the injected payload and, when the code
runs, an "XSS fired" line:

    await page.addInitScript({ path: "/srv/url-banner.js" });

The banner also captures \`alert()\`; you can assert
\`await page.evaluate(() => (window).__agentggXss?.length > 0)\` as the proof of
execution, instead of the local override above.

${NO_OVERLAY}

A generated test finishes in well under a second, so the video is unwatchable
without pauses. After the vulnerable effect appears, hold on it before the test
ends so the recording and the end-screenshot show the proof:

    await page.waitForTimeout(2000);

If the effect only becomes visible after a reload (for example a session cookie
that a \`page.request\` call set), navigate to the affected page again before
that pause, so the screenshot and video show the result and not the
pre-exploit page:

    await page.goto(BASE_URL);   // now the page renders the signed-in state
    await page.waitForTimeout(2000);

## Show the attack on the recording

The recording must show the attack go in and its effect. A request sent with
\`page.request\` runs outside the page and draws nothing, so a test that starts
with one records a blank page until its first navigation.

- Open a page with \`page.goto(...)\` before any \`page.request\` call, right
  after the init scripts above: the page where a user sends this input, or the
  base URL when no page does.
- When a page of the application sends this input (a form, a search box, a
  link), send the attack through that page. Find each field by the parameter
  name the PoC uses, for example \`page.fill('[name="q"]', payload)\`, and
  submit with \`page.press('[name="q"]', "Enter")\`. The control test does the
  same with its benign value.
- Use \`page.request\` only for what a page cannot send, such as a request
  header or a raw API call, and for the raw-response check above.

## How to write it

- Navigate straight to the endpoint the PoC names. Do not explore or crawl.
- Use absolute URLs built from the base URL above. No config file is loaded.
- Import from \`@playwright/test\`.
- Assert the vulnerable effect itself, not a side effect a fixed application
  would also produce.
- Assert on what the browser ended up with, not on an intermediate state the
  navigation already consumed.
- Do not set a session cookie or other state yourself (for example with
  \`context.addCookies\` or \`localStorage\`). The state the result shows must
  come from the application's answer to the attack; a state the test set
  itself proves nothing.

## Output

Put the spec source in \`script\` and nothing else: no prose, no explanation, no
markdown fences.`;
}

/**
 * Build the unified agent prompt. Combines (in order): the recon brief,
 * the agent's own harness/instructions, an optional `--diff` focus block,
 * the seeded candidate files, and reporting guidance. The strict JSON
 * output shape is NOT included here — the Claude backend enforces it via
 * schema, and the Vercel backend appends `jsonOutputInstruction` itself.
 *
 * `candidates` is empty when the agent declares no file scope: the whole
 * repository is its scope, and it uses its tools to find its own targets
 * rather than read beyond a seeded set. See `hasFileScope`.
 *
 * `excludePatterns` is rendered only in the scope block. A seeded agent is
 * told not to re-discover its candidate set, so it has no traversal to bound
 * and its prompt stays byte-identical.
 */
export function buildAgentPrompt(
  args: Pick<RunAgentArgs, "agent" | "recon" | "candidates" | "diff" | "excludePatterns">,
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

  // With no candidates the agent's scope is the whole repository, so the
  // tools are how it finds its targets, not just how it reads them.
  const seeded = args.candidates.length > 0;

  const toolsBlock = `## Your tools

You have Read, Glob, and Grep. Your working directory is the
repository root. Use them to ${
    seeded ? "read the files below, follow" : "find and read the relevant code, follow"
  } imports,
chase callers, and confirm a finding before reporting it.`;

  // Only prompts that actually carry a path get the legend, so every agent
  // without a taint rule keeps byte-identical output.
  const hasTaint = args.candidates.some((c) => c.hits.some((h) => h.taint && h.taint.length > 0));
  const taintLegend = hasTaint
    ? `

An anchor with a \`taint:\` path shows the dataflow the scanner traced:
the source, then each variable the value passes through, then the sink.
Treat it as a lead to confirm in the code, not as a verdict.`
    : "";

  const seededBlock = `## Candidate files

These files were selected as your starting points (some carry scanner
anchor lines). Investigate each one, and use your tools to pull in
related files when judgment requires it. Do NOT re-discover the
candidate set — the files below are already your targets.${taintLegend}

${args.candidates.map((c, i) => renderSeededFile(c, i + 1, args.candidates.length)).join("\n\n---\n\n")}`;

  // The excludes bound where this agent looks. On the Vercel path the tool
  // implementations enforce the same list; on the Claude Agent SDK path the
  // native Read/Glob/Grep take no filter, so naming the paths here is the only
  // bound there is. Either way it belongs in the scope block only: a seeded
  // agent is not traversing anything.
  const excludeBlock =
    args.excludePatterns.length > 0
      ? `
Skip anything matching these patterns. They are not part of your
scope, and searching or reading them wastes your budget:
${args.excludePatterns.map((p) => `  - ${p}`).join("\n")}
`
      : "";

  // No candidates: the agent selects its own targets. Step 2 is the
  // load-bearing instruction — it turns the detection criteria already in the
  // prompt body above into search terms, which is what replaces the anchors a
  // seeded batch carries.
  const scopeBlock = `## Your scope

Your scope is the whole repository. You must locate your own
targets before you can judge them.

Work in this order:
1. Read the project brief above for the stack, the entry points,
   and the layout.
2. Grep for the concrete syntax your detection criteria name. Search
   for the calls, imports, and identifiers themselves, not for
   descriptions of them. Run several searches with different terms.
3. Glob the directories the brief calls out, to find files your
   searches missed.
4. Read each promising file in full before you judge it. Follow its
   imports and callers when a judgement depends on them.
${excludeBlock}
Search widely first, then read deeply. Do not report an issue from a
search result alone. Read the code and confirm it.`;

  const targetBlock = seeded ? seededBlock : scopeBlock;

  const reporting = `## Reporting

Report only issues that match your detection criteria. For each, cite
the exact file path, line range, and unsafe code element, and explain
why it is exploitable. If a candidate turns out to be safe or already
mitigated, omit it — an empty result is the correct answer for clean
code. Do NOT invent findings to satisfy expectations; false positives
erode trust.

Write the title, summary, details, PoC, and impact in plain, direct
language. Do not use em-dashes (—); use commas, parentheses, or separate
sentences instead.`;

  return `${reconBlock}${args.agent.prompt}${diffBlock}

---

${toolsBlock}

${targetBlock}

${reporting}`;
}

/** `L12`, or `L12-18` when the match spans a range. */
function anchorRange(h: InvestigateHit): string {
  return h.endLine && h.endLine > h.line ? `L${h.line}-${h.endLine}` : `L${h.line}`;
}

/** ` (CWE-79, confidence MEDIUM)`, or empty when the rule declared none. */
function metadataSuffix(h: InvestigateHit): string {
  if (!h.metadata) return "";
  // A bare CWE or OWASP id reads as itself. The rest need their key to mean
  // anything, so "MEDIUM" alone becomes "confidence MEDIUM".
  const parts = Object.entries(h.metadata).map(([k, v]) =>
    k === "cwe" || k === "owasp" ? v : `${k} ${v}`,
  );
  return parts.length > 0 ? ` (${parts.join(", ")})` : "";
}

/**
 * ``L24 `req.query` → (3 steps omitted) → L25 `res.send(...)` ``
 *
 * An elided marker prints with no `L` prefix and no backticks. It is not a
 * location and not code, and dressing it as either misreads.
 */
function taintPath(steps: ReadonlyArray<TaintStep>): string {
  return steps
    .map((s) => (s.kind === "elided" ? `(${s.code})` : `L${s.line} \`${s.code}\``))
    .join(" → ");
}

/**
 * One anchor. The first line is the position; the lines under it are what
 * the engine already knew and the model would otherwise re-derive by reading.
 */
export function renderHit(h: InvestigateHit): string {
  const lines = [
    `  - ${anchorRange(h)} [${h.label}]${metadataSuffix(h)}: ${h.snippet || "(line)"}`,
  ];
  if (h.message) lines.push(`    why: ${h.message}`);
  if (h.taint && h.taint.length > 0) lines.push(`    taint: ${taintPath(h.taint)}`);
  return lines.join("\n");
}

function renderSeededFile(c: AgentCandidate, idx: number, total: number): string {
  const lang = languageFromPath(c.filePath);
  const visible = c.hits.filter((h) => h.label !== "(no preFilter)");
  const hitsBlock =
    visible.length > 0
      ? visible.map(renderHit).join("\n")
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
/**
 * Map a path the model reported onto the batch candidate it actually means, or
 * `undefined` when no single candidate matches.
 *
 * A tool-loop model that read a nested path frequently reports the finding
 * against the bare basename. That resolves to nothing under the scan root, so
 * scan.ts's invented-path filter treated a formatting slip as a hallucination
 * and dropped a real finding. The same file can then yield a finding on one
 * run and nothing on the next, purely on how the model spelled the path.
 *
 * CALLERS MUST TRY THE RAW PATH ON DISK FIRST and only fall back to this. That
 * ordering is what keeps the repair strictly additive: `hydrateFinding` hashes
 * the path into the finding id, and that id carries a person's triage status on
 * the platform, so rewriting a path that already resolves would orphan their
 * decision. A finding this rescues was going to be discarded, so it has no id
 * anywhere yet and nothing can be orphaned.
 *
 * Matching is on segment boundaries so `login.ts` cannot claim
 * `prefix-login.ts`, and a tie is refused rather than guessed.
 */
export function resolveCandidatePath(
  raw: string | undefined,
  candidates: readonly { filePath: string }[],
): string | undefined {
  if (raw == null) return undefined;
  const norm = (p: string) => p.replace(/\\/g, "/").replace(/^\.\//, "").trim();
  const want = norm(raw);
  if (want === "" || want === "(unknown)") return undefined;
  const hits = candidates.filter((c) => {
    const p = norm(c.filePath);
    return p === want || p.endsWith(`/${want}`);
  });
  return hits.length === 1 ? hits[0]?.filePath : undefined;
}

/**
 * Return `raw` with its `filePath` corrected, when the model reported a path
 * that does not exist but unambiguously names one of the batch candidates.
 *
 * The disk check comes FIRST and a path that resolves is returned untouched.
 * That ordering is the whole safety argument: `hydrateFinding` hashes the path
 * into the finding id, and that id carries a person's triage status on the
 * platform, so rewriting a path that already works would orphan their decision.
 * A finding this rescues was headed for scan.ts's invented-path filter, so it
 * has no id anywhere yet and nothing can be orphaned. The change is additive.
 *
 * A genuinely invented path still matches no candidate, so it passes through
 * unchanged and the filter drops it exactly as before.
 */
export function repairFindingPath(
  raw: LlmFinding,
  rootDir: string,
  candidates: readonly { filePath: string }[],
): LlmFinding {
  const reported = raw.filePath;
  if (reported == null || reported.trim() === "") return raw;
  if (existsSync(resolve(rootDir, reported))) return raw;
  const repaired = resolveCandidatePath(reported, candidates);
  return repaired === undefined || repaired === reported ? raw : { ...raw, filePath: repaired };
}

/** Fence tags that name a language by a short alias. */
const FENCE_ALIASES: Record<string, string> = {
  ts: "typescript",
  tsx: "typescript",
  js: "javascript",
  jsx: "javascript",
  py: "python",
  rb: "ruby",
  kt: "kotlin",
  cs: "csharp",
  sh: "bash",
  yml: "yaml",
};

/** Shorter lines match by chance: `private String sql;` flagged a confirmed critical. */
const MIN_EVIDENCE_CHARS = 20;

interface FencedBlock {
  index: number;
  tag: string;
  open: number;
  close: number;
}

function fencedBlocks(lines: readonly string[]): FencedBlock[] {
  const blocks: FencedBlock[] = [];
  let open = -1;
  let tag = "";
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (!t.startsWith("```")) continue;
    if (open < 0) {
      open = i;
      tag = t.slice(3).trim().split(" ")[0].toLowerCase();
    } else {
      blocks.push({ index: blocks.length, tag, open, close: i });
      open = -1;
    }
  }
  return blocks;
}

/** Drops `//` comments and all whitespace: reflowed Java was 44 of 65 exact-match misses. */
export function normalizeCode(text: string): string {
  const code = text
    .split("\n")
    .map((line) => {
      const at = line.indexOf("//");
      return at < 0 ? line : line.slice(0, at);
    })
    .join("");
  return Array.from(code)
    .filter((c) => c.trim() !== "")
    .join("");
}

/** Long enough to prove something, and not shortened with an ellipsis. */
function isEvidence(line: string): boolean {
  // "SELECT ... FROM t" abbreviates real code, so it can never match verbatim.
  if (line.includes("...") || line.includes("…")) return false;
  return normalizeCode(line).length >= MIN_EVIDENCE_CHARS;
}

export interface UnverifiedExcerpt {
  /** Position among all fenced blocks in `details`. */
  index: number;
  body: string;
}

/**
 * Fenced blocks in `details` with a line found in none of `sources`, nor by
 * `existsElsewhere` (the repository) when given. Models quote invented or
 * paraphrased code often enough to need this check. A block tagged with
 * another language is example output, not source, so it is skipped.
 */
export function findUnverifiedExcerpts(
  details: string,
  sources: readonly string[],
  language: string,
  existsElsewhere?: (needle: string) => boolean,
): UnverifiedExcerpt[] {
  const lines = details.split("\n");
  const haystacks = sources.map(normalizeCode);
  const out: UnverifiedExcerpt[] = [];
  for (const block of fencedBlocks(lines)) {
    const tag = FENCE_ALIASES[block.tag] ?? block.tag;
    if (tag !== "" && tag !== language) continue;
    const body = lines.slice(block.open + 1, block.close);
    const invented = body.some((line) => {
      if (!isEvidence(line)) return false;
      const needle = normalizeCode(line);
      if (haystacks.some((h) => h.includes(needle))) return false;
      return !existsElsewhere?.(needle);
    });
    if (invented) out.push({ index: block.index, body: body.join("\n") });
  }
  return out;
}

/** Replaces the bodies of the given blocks; every other character stays. */
export function replaceExcerpts(details: string, bodies: ReadonlyMap<number, string>): string {
  const lines = details.split("\n");
  // Last block first, so earlier line numbers stay valid while splicing.
  for (const block of fencedBlocks(lines).reverse()) {
    const body = bodies.get(block.index);
    if (body !== undefined)
      lines.splice(block.open + 1, block.close - block.open - 1, ...body.split("\n"));
  }
  return lines.join("\n");
}

export const UNVERIFIED_EXCERPT_NOTE =
  "Note: part of the code quoted above could not be found in the scanned source, so it may not match the real code.";

export function markExcerptsUnverified(details: string): string {
  return `${details}\n\n_${UNVERIFIED_EXCERPT_NOTE}_`;
}

/** A re-quote must carry real evidence; an empty or trivial one would pass the check. */
function quotesRealCode(
  body: string,
  sources: readonly string[],
  language: string,
  existsElsewhere?: (needle: string) => boolean,
): boolean {
  const lines = body.split("\n");
  // A model can wrap its answer in fences despite being told not to.
  if (lines[0]?.trim().startsWith("```")) lines.shift();
  if (lines.at(-1)?.trim().startsWith("```")) lines.pop();
  const code = lines.join("\n");
  const hasEvidence = lines.some(isEvidence);
  const block = ["```", code, "```"].join("\n");
  return (
    hasEvidence && findUnverifiedExcerpts(block, sources, language, existsElsewhere).length === 0
  );
}

export type ExcerptOutcome = "verified" | "requoted" | "unverified";

/**
 * Checks a finding's quoted code and asks for at most ONE re-quote of what is
 * invented. Only `details` changes: the id hashes slug, path, title and line
 * range, and carries a person's triage status. A re-quote that still fails
 * keeps the original and marks it, so a real bug is never dropped.
 */
export async function repairFindingExcerpts(
  finding: Finding,
  sources: readonly string[],
  requote?: (flagged: readonly UnverifiedExcerpt[]) => Promise<readonly string[]>,
  existsElsewhere?: (needle: string) => boolean,
): Promise<{ finding: Finding; outcome: ExcerptOutcome }> {
  const language = languageFromPath(finding.filePath);
  const flagged = findUnverifiedExcerpts(finding.details, sources, language, existsElsewhere);
  if (flagged.length === 0) return { finding, outcome: "verified" };
  let replacements: readonly string[] = [];
  if (requote) {
    try {
      replacements = await requote(flagged);
    } catch {
      // A failed call counts as a failed re-quote: keep and mark below.
    }
  }
  const accepted = new Map<number, string>();
  flagged.forEach((block, i) => {
    const body = replacements[i];
    if (body !== undefined && quotesRealCode(body, sources, language, existsElsewhere))
      accepted.set(block.index, body);
  });
  const details = replaceExcerpts(finding.details, accepted);
  if (accepted.size === flagged.length) {
    return { finding: { ...finding, details }, outcome: "requoted" };
  }
  return {
    finding: { ...finding, details: markExcerptsUnverified(details) },
    outcome: "unverified",
  };
}

export function hydrateFinding(raw: LlmFinding, agent: Agent, fallbackFilePath: string): Finding {
  // When the agent has no file scope, the LLM is responsible for
  // `filePath` (it discovered the file itself); when the agent was seeded,
  // the caller already supplies it. Prefer the LLM's value when present so
  // the id stays stable across runs.
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
