import { z } from "zod";

// ---------------------------------------------------------------------------
// Severity, noise, validation verdicts
// ---------------------------------------------------------------------------

export const Severity = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
export type Severity = z.infer<typeof Severity>;

export const NoiseTier = z.enum(["precise", "normal", "noisy"]);
export type NoiseTier = z.infer<typeof NoiseTier>;

/**
 * Unified agent model. Every agent is a tool-enabled investigation
 * (Read/Glob/Grep always available) composed of three parts:
 *
 *   1. `precondition` — a cheap gate deciding whether the agent is even
 *      queued for this repo. A `regex` existence check, an LLM `prompt`
 *      check (which sees the recon brief), both (AND), or neither
 *      (always run). See `Precondition`.
 *   2. `where` — the file scope fed into the agent as starting points:
 *      `extensions` / `filePatterns` + `excludePatterns` narrow the tree,
 *      `preFilter` regexes anchor specific lines. An empty `where` includes
 *      ALL files. Either way the agent gets a concrete file set (reviewed in
 *      batches) and uses its tools to read beyond it. See `Where`.
 *   3. the prompt body (markdown after the frontmatter) — the harness +
 *      detection instructions the model runs with.
 *
 * There is no `mode`: the old file / walker / hunt / rule split collapsed
 * into this one shape.
 */

/**
 * One regex in a walker agent's `preFilter`. Files where any
 * `preFilter` regex matches at least one line become "candidates" the
 * LLM investigates. The optional `label` is shown to the model
 * alongside the line number so it knows *why* the scanner flagged
 * the line.
 */
export const AgentPreFilterPattern = z.object({
  regex: z.string(),
  label: z.string().optional(),
});
export type AgentPreFilterPattern = z.infer<typeof AgentPreFilterPattern>;

export const ValidationVerdict = z.enum([
  "confirmed",
  "false-positive",
  "out-of-scope",
  "uncertain",
]);
export type ValidationVerdict = z.infer<typeof ValidationVerdict>;

// ---------------------------------------------------------------------------
// Agent (parsed markdown file)
// ---------------------------------------------------------------------------
//
// The on-disk representation is a `.md` file with YAML frontmatter. After
// gray-matter parses it, we validate the frontmatter against this schema
// and treat the body as the prompt template.

// ---------------------------------------------------------------------------
// Precondition — the queue/skip gate (part 1 of an agent)
// ---------------------------------------------------------------------------
//
// Evaluated for every selected agent before any detection runs. The
// orchestrator records which agents were queued vs skipped (and why).
//
//   - no prompt, no regex → always queued
//   - regex only          → queued iff the regex check matches anything
//   - prompt only         → queued iff the LLM gate (which sees the recon
//                            brief) answers yes
//   - both                → queued iff the regex matches AND the LLM says yes

/**
 * One content regex in a precondition. "Does `regex` match a line in any
 * file selected by `in` (and not excluded by `notIn`)?" Empty `in` means
 * "any file." Globs use the same minimatch dialect as `where`.
 */
export const PreconditionPattern = z.object({
  regex: z.string(),
  in: z.array(z.string()).default([]),
  notIn: z.array(z.string()).default([]),
  label: z.string().optional(),
});
export type PreconditionPattern = z.infer<typeof PreconditionPattern>;

/**
 * Static existence check. The agent is queued when ANY declared sub-check
 * matches (logical OR across `extensions`, `files`, `directories`,
 * `patterns`). An all-empty block is treated as "no regex constraint."
 */
export const PreconditionRegex = z.object({
  /** Queue if a file with one of these extensions exists (e.g. ".php"). */
  extensions: z.array(z.string()).default([]),
  /**
   * Queue if a file matching one of these path globs exists — e.g.
   * "artisan", "Dockerfile", "routes/web.php", or a recursive glob.
   * Use this for sentinel files that signal a stack or feature;
   * `extensions` is the by-type shorthand, this is the by-path check.
   * Minimatch dialect.
   */
  files: z.array(z.string()).default([]),
  /** Queue if a directory matching one of these globs exists (e.g. "app/**"). */
  directories: z.array(z.string()).default([]),
  /** Queue if one of these content patterns matches within its `in`/`notIn` scope. */
  patterns: z.array(PreconditionPattern).default([]),
});
export type PreconditionRegex = z.infer<typeof PreconditionRegex>;

export const Precondition = z.object({
  /**
   * LLM gate. The model sees the recon brief + this prompt and answers
   * whether the agent is relevant to this repo. Combined with `regex` by
   * AND when both are present.
   */
  prompt: z.string().optional(),
  /** Static existence check. Combined with `prompt` by AND when both present. */
  regex: PreconditionRegex.optional(),
});
export type Precondition = z.infer<typeof Precondition>;

// ---------------------------------------------------------------------------
// Where — the file scope fed into an agent (part 2)
// ---------------------------------------------------------------------------

export const Where = z.object({
  /**
   * File types to include, as plain extensions — `["ts", "php"]` (leading
   * dot optional). The nuclei-style way to scope by file type: a file is
   * included when its name ends with one of these. This is the primary
   * knob; most agents only need `extensions` + `preFilter`.
   */
  extensions: z.array(z.string()).default([]),
  /**
   * Optional include patterns for cases `extensions` can't express — a
   * specific file, a directory, or a glob (e.g. "src/legacy", "**​/*.proto").
   * A bare path/dir matches everything under it. OR'd with `extensions`.
   * When BOTH `extensions` and `filePatterns` are empty, the agent's scope is
   * ALL files (reviewed in batches) — there is no file-less "roam" mode.
   */
  filePatterns: z.array(z.string()).default([]),
  /**
   * Globs the agent never touches. Combined additively with any CLI
   * `--exclude` patterns at runtime. Same minimatch dialect as
   * `filePatterns`.
   */
  excludePatterns: z.array(z.string()).default([]),
  /**
   * Whether to apply the shared default exclude set (node_modules, .git,
   * build dirs, lockfiles, binary/asset files — see `DEFAULT_EXCLUDES`).
   * Defaults to true so templates stay clean. Set to false for an agent
   * that genuinely needs to look inside those paths (e.g. auditing a
   * vendored dependency); CLI `--exclude` paths still apply regardless.
   */
  useDefaultExcludes: z.boolean().default(true),
  /**
   * Regexes that narrow `filePatterns`-matching files down to candidates
   * worth investigating: a file becomes a candidate when at least one
   * regex matches at least one line, and the matching line numbers +
   * labels are passed to the model as anchors. Empty = every matching
   * file is a candidate.
   */
  preFilter: z.array(AgentPreFilterPattern).default([]),
  /** How many candidate files to pack into one investigation session. */
  maxFilesPerBatch: z.number().int().min(1).default(5),
  /** Tool-use turn budget per investigation session. */
  maxTurnsPerBatch: z.number().int().min(1).default(30),
});
export type Where = z.infer<typeof Where>;

// ---------------------------------------------------------------------------
// Agent (parsed markdown file)
// ---------------------------------------------------------------------------
//
// The on-disk representation is a `.md` file with YAML frontmatter. After
// gray-matter parses it, we validate the frontmatter against this schema
// and treat the body as the prompt template.

export const Agent = z.object({
  /** Stable identifier. Used in -t selection, scope.agents.disable, etc. */
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  name: z.string(),
  description: z.string(),
  version: z.string().default("0.0.1"),
  author: z.string().optional(),
  noiseTier: NoiseTier.default("normal"),
  /** Queue/skip gate. Omit entirely = always run. See `Precondition`. */
  precondition: Precondition.optional(),
  /** File scope fed into the agent. Omit = all files (reviewed in batches). */
  where: Where.default({}),
  /**
   * Documentation-only field. CWE / OWASP / GHSA / CVE IDs or URLs this
   * agent was modeled after. NOT injected into the prompt — the prompt
   * body is the only thing the model sees. Surfaced by `agents info`
   * for human readers; otherwise unused at runtime.
   */
  references: z.array(z.string()).optional(),
  /** The prompt body (markdown content after the frontmatter). */
  prompt: z.string(),
  /** Where this agent came from. Set by the loader, not by the author. */
  source: z
    .object({
      kind: z.enum(["builtin", "official", "community", "project", "custom"]),
      path: z.string(),
      pack: z.string().optional(),
    })
    .optional(),
});
export type Agent = z.infer<typeof Agent>;

// ---------------------------------------------------------------------------
// Candidate match (pre-filter regex hit, optional)
// ---------------------------------------------------------------------------

export const CandidateMatch = z.object({
  agentSlug: z.string(),
  lineNumbers: z.array(z.number().int().nonnegative()),
  snippet: z.string(),
  matchedPattern: z.string(),
});
export type CandidateMatch = z.infer<typeof CandidateMatch>;

// ---------------------------------------------------------------------------
// CvssScore — output of the scoring agent (CVSS 3.1)
// ---------------------------------------------------------------------------
//
// Detection agents emit findings WITHOUT a severity. A dedicated scoring
// agent (run after detection, before reporting) reads each finding in
// context, fills out the CVSS 3.1 base metrics, and derives a baseScore +
// severity bucket. This keeps severity grounded in actual code context
// rather than a guess baked into the agent declaration.

export const CvssAttackVector = z.enum(["N", "A", "L", "P"]); // Network / Adjacent / Local / Physical
export const CvssAttackComplexity = z.enum(["L", "H"]);
export const CvssPrivilegesRequired = z.enum(["N", "L", "H"]);
export const CvssUserInteraction = z.enum(["N", "R"]);
export const CvssScope = z.enum(["U", "C"]); // Unchanged / Changed
export const CvssImpact = z.enum(["H", "L", "N"]);

export const CvssScore = z.object({
  /** Canonical CVSS 3.1 vector string, e.g. "CVSS:3.1/AV:N/AC:L/...". */
  vector: z.string(),
  /** Base score 0.0–10.0. The bucket is derived from this. */
  baseScore: z.number().min(0).max(10),
  /** Severity bucket derived from baseScore per the CVSS 3.1 rubric. */
  severity: Severity,
  /** Individual base metrics — kept structured for filtering and rebuilds. */
  metrics: z.object({
    attackVector: CvssAttackVector,
    attackComplexity: CvssAttackComplexity,
    privilegesRequired: CvssPrivilegesRequired,
    userInteraction: CvssUserInteraction,
    scope: CvssScope,
    confidentiality: CvssImpact,
    integrity: CvssImpact,
    availability: CvssImpact,
  }),
  /**
   * Short prose from the scoring agent explaining why each metric was
   * picked — surfaces in the per-finding markdown so reviewers can
   * sanity-check the score.
   */
  justification: z.string(),
});
export type CvssScore = z.infer<typeof CvssScore>;

// ---------------------------------------------------------------------------
// Finding (a single security issue surfaced by an agent)
// ---------------------------------------------------------------------------

export const Finding = z.object({
  /** Unique within a FileRecord. Hash of (agentSlug + title + lineRange). */
  id: z.string(),
  agentSlug: z.string(),
  title: z.string(),
  /**
   * Severity bucket. Filled in by the scoring phase, not by the detection
   * agent. Derived from `cvss.baseScore` when a CVSS score is present;
   * may be set directly for findings the scoring agent couldn't quantify.
   */
  severity: Severity.optional(),
  /** Full CVSS 3.1 breakdown when the scoring agent ran. */
  cvss: CvssScore.optional(),
  /** Free-form short class label, e.g. "sql-injection". */
  vulnSlug: z.string(),
  filePath: z.string(),
  lineRange: z.tuple([z.number().int(), z.number().int()]).optional(),
  /**
   * One-sentence statement of the issue and its impact. Modeled on the
   * GitHub Security Advisory "Summary" field — should be quotable in a
   * Slack ping or PR comment without further editing.
   */
  summary: z.string(),
  /**
   * Markdown body with the full analysis. Points to the affected source
   * code (file path + line numbers + excerpted snippet inside a fenced
   * code block). Maps to GHSA "Details".
   */
  details: z.string(),
  /**
   * Reproduction steps: HTTP request, payload, sequence of CLI commands,
   * or config tweaks needed to trigger the vulnerability. Maps to
   * GHSA "Proof of Concept".
   */
  poc: z.string(),
  /**
   * Who is affected and how. Vulnerability class, blast radius, whether
   * authentication is required, what an attacker gets. Maps to GHSA
   * "Impact".
   */
  impact: z.string(),
  references: z.array(z.string()).default([]),
  confidence: z.number().min(0).max(1).default(0.5),
  /** Filled in after validation phase. */
  validation: z
    .object({
      verdict: ValidationVerdict,
      reasoning: z.string(),
      scopeRef: z.string().optional(),
      adjustedSeverity: Severity.optional(),
    })
    .optional(),
  /** Where the finding has been reported (notifiers). */
  notifications: z
    .array(
      z.object({
        notifierName: z.string(),
        notifiedAt: z.string(),
        externalId: z.string().optional(),
        externalUrl: z.string().optional(),
      }),
    )
    .default([]),
});
export type Finding = z.infer<typeof Finding>;

// ---------------------------------------------------------------------------
// AnalysisRun — one entry per detect/validate pass on a file
// ---------------------------------------------------------------------------

export const AnalysisRun = z.object({
  runId: z.string(),
  phase: z.enum(["detect", "validate"]),
  ranAt: z.string(),
  durationMs: z.number().int().nonnegative().default(0),
  provider: z.string(),
  /**
   * Model identifier used for this analysis. Optional because the
   * resolver picks the model internally and we don't surface it back
   * to the orchestrator at MVP. Token/cost accounting follows the
   * same rule — opt-in when we have the data.
   */
  model: z.string().optional(),
  /** Which agent slugs were applied in this run. */
  agentSlugs: z.array(z.string()),
  findingCount: z.number().int().nonnegative(),
  inputTokens: z.number().int().nonnegative().optional(),
  outputTokens: z.number().int().nonnegative().optional(),
  costUsd: z.number().nonnegative().optional(),
  /** Set if the model refused or errored out. */
  refused: z.boolean().optional(),
  error: z.string().optional(),
});
export type AnalysisRun = z.infer<typeof AnalysisRun>;

// ---------------------------------------------------------------------------
// FileRecord — the per-file source of truth (append-only)
// ---------------------------------------------------------------------------

export const FileRecord = z.object({
  /**
   * The agent this record belongs to. Records are sharded by agent on disk
   * (`state/files/<agentSlug>/<filePath>.json`) so multiple agents — and
   * multiple concurrent `scan` processes — never write the same file. A
   * single source file's full picture is the union of every agent's record
   * for that path, assembled at read time.
   */
  agentSlug: z.string(),
  /** Repo-relative POSIX path (forward slashes). */
  filePath: z.string(),
  contentHash: z.string(),
  /**
   * Hash of the recon brief in effect when this file was last analyzed.
   * Per-file resume skips re-analyzing a file only when BOTH its
   * `contentHash` (file unchanged) AND this `reconHash` (same brief)
   * still match — a changed brief re-runs the file. Absent on records
   * written before per-file resume, or by non-detect paths.
   */
  reconHash: z.string().optional(),
  candidates: z.array(CandidateMatch).default([]),
  findings: z.array(Finding).default([]),
  analysisHistory: z.array(AnalysisRun).default([]),
  scope: z
    .object({
      outOfScope: z.boolean().default(false),
      reason: z.string().optional(),
    })
    .default({ outOfScope: false }),
  /** Atomic processing claim — set by the worker, cleared on completion. */
  lockedByRunId: z.string().optional(),
  status: z.enum(["pending", "analyzed", "validated"]).default("pending"),
});
export type FileRecord = z.infer<typeof FileRecord>;

// ---------------------------------------------------------------------------
// ScopeConfig — parsed YAML block from SECURITY.md
// ---------------------------------------------------------------------------

export const AcceptedRisk = z.object({
  id: z.string(),
  reason: z.string(),
  paths: z.array(z.string()).default([]),
});
export type AcceptedRisk = z.infer<typeof AcceptedRisk>;

export const ScopeConfig = z.object({
  out_of_scope: z
    .object({
      paths: z.array(z.string()).default([]),
      vulnerabilities: z.array(z.string()).default([]),
    })
    .default({ paths: [], vulnerabilities: [] }),
  accepted_risks: z.array(AcceptedRisk).default([]),
  agents: z
    .object({
      disable: z.array(z.string()).default([]),
    })
    .default({ disable: [] }),
  project_context: z.string().optional(),
});
export type ScopeConfig = z.infer<typeof ScopeConfig>;

// ---------------------------------------------------------------------------
// ValidationResult — what the validator returns for one candidate finding
// ---------------------------------------------------------------------------

export const ValidationResult = z.object({
  verdict: ValidationVerdict,
  reasoning: z.string(),
  confidence: z.number().min(0).max(1),
  /** Reference to the scope rule that matched, if verdict === "out-of-scope". */
  scopeRef: z.string().optional(),
  /** If the validator wants to override the original severity. */
  adjustedSeverity: Severity.optional(),
});
export type ValidationResult = z.infer<typeof ValidationResult>;

// ---------------------------------------------------------------------------
// Scan metadata sidecar — `<outputDir>/state/scan.json`
// ---------------------------------------------------------------------------
//
// One per output dir. Records the absolute root path the FileRecords
// were generated from so `revalidate` can resolve repo-relative
// filePaths back to actual source files without the user re-typing the
// path. Updated on each fresh scan; same shape regardless of agent set.

export const ScanMeta = z.object({
  /** Absolute path to the scanned codebase as of the most recent scan. */
  root: z.string(),
  /** ISO timestamp of the first time this output dir was scanned into. */
  createdAt: z.string(),
  /** ISO timestamp of the most recent scan. */
  updatedAt: z.string(),
});
export type ScanMeta = z.infer<typeof ScanMeta>;

// ---------------------------------------------------------------------------
// ReconReport — high-level project brief (`<outputDir>/state/recon.json`)
// ---------------------------------------------------------------------------
//
// Produced once per scan by the recon agent before any detection runs. It
// is fed into (a) precondition `prompt` checks and (b) the first
// bug-finding prompt of every queued agent, so the model starts oriented.
// Deliberately CONCISE — bounded fields, no file dumps — because it is
// prepended to many downstream prompts. `summary` is the short prose brief
// agents actually read; the structured fields support gating and display.

export const ReconReport = z.object({
  /** 1–3 sentences: what this project is and does. */
  purpose: z.string(),
  /** Primary languages (e.g. ["typescript", "go"]). */
  languages: z.array(z.string()).default([]),
  /** Frameworks / major libraries (e.g. ["next.js", "express"]). */
  frameworks: z.array(z.string()).default([]),
  /** 1–2 sentences on how auth/identity works, if discernible. */
  authModel: z.string().optional(),
  /** External services, datastores, and third-party integrations. */
  integrations: z.array(z.string()).default([]),
  /** Notable directories worth a security reviewer's attention. */
  notableDirs: z.array(z.string()).default([]),
  /**
   * The concise prose brief injected into downstream prompts. A few short
   * paragraphs at most — orientation, not an audit.
   */
  summary: z.string(),
  /** Hash of the inputs the brief was derived from (for resume invalidation). */
  reconHash: z.string(),
  /** ISO timestamp the brief was generated. */
  generatedAt: z.string(),
});
export type ReconReport = z.infer<typeof ReconReport>;

// ---------------------------------------------------------------------------
// ScanPlan — the precondition decision set (`<outputDir>/state/plan.json`)
// ---------------------------------------------------------------------------
//
// Written once, after recon and after every agent's precondition has been
// evaluated, but BEFORE any agent runs. It is the durable hand-off between
// the "plan" phase and the "run" phase: a distributed runner can compute the
// plan on one worker and dispatch the queued agents to others. Each decision
// records whether the agent was queued and the human-readable reason.

export const PreconditionDecisionRecord = z.object({
  slug: z.string(),
  queued: z.boolean(),
  reason: z.string(),
});
export type PreconditionDecisionRecord = z.infer<typeof PreconditionDecisionRecord>;

export const ScanPlan = z.object({
  /** Run that produced this plan. */
  runId: z.string(),
  generatedAt: z.string(),
  /** Hash of the recon brief the plan was computed against. */
  reconHash: z.string(),
  /** Absolute scanned root. */
  rootPath: z.string(),
  /** One entry per selected agent, in selection order. */
  decisions: z.array(PreconditionDecisionRecord),
});
export type ScanPlan = z.infer<typeof ScanPlan>;

// ---------------------------------------------------------------------------
// UserConfig — what `agentgg init` writes to ~/.agentgg/config.json
// ---------------------------------------------------------------------------
//
// Holds the user's selected LLM provider + credentials for that provider.
// All three provider blocks are optional so a user can populate more than
// one over time (re-run `init` to add another). `provider` is the active
// default for new scans.

// Provider = where you get billed. The "model family" lives in the per-block
// `model` field (e.g. Bedrock model IDs encode `anthropic.claude-...`),
// so we don't need a separate family axis. To add a new cloud-hosted
// provider: append it here, add a typed block + superRefine branch below,
// register a ProviderModule in packages/cli/src/providers/.
export const Provider = z.enum(["anthropic", "openai", "ollama", "bedrock", "vertex"]);
export type Provider = z.infer<typeof Provider>;

export const UserConfig = z
  .object({
    /** Active default provider used by `agentgg scan` unless --provider is passed. */
    provider: Provider,
    anthropic: z
      .object({
        /**
         * Standard Anthropic API key (`sk-ant-api...`) issued by
         * console.anthropic.com. Pay-per-token against the API.
         */
        apiKey: z.string().min(1).optional(),
        /**
         * Claude Code OAuth token (`sk-ant-oat...`). Authenticates
         * against the user's Claude Pro/Max subscription via the
         * Authorization header. Mutually exclusive with `apiKey` —
         * exactly one of the two must be set.
         */
        oauthToken: z.string().min(1).optional(),
        model: z.string().optional(),
      })
      .optional(),
    openai: z
      .object({
        apiKey: z.string().min(1),
        model: z.string().optional(),
      })
      .optional(),
    ollama: z
      .object({
        baseUrl: z.string().url(),
        model: z.string().optional(),
      })
      .optional(),
    bedrock: z
      .object({
        /**
         * AWS region the Bedrock endpoint lives in. Required because Bedrock
         * inference profiles are region-scoped. May be omitted at config-save
         * time if the user wants to rely on `$AWS_REGION` / `$AWS_DEFAULT_REGION`
         * at scan time — `buildDetector` re-resolves there.
         */
        region: z.string().min(1).optional(),
        /**
         * Bedrock model ID. Anthropic-on-Bedrock IDs look like
         * `anthropic.claude-sonnet-4-5-20250929-v1:0` or an inference profile
         * prefix (`us.anthropic.claude-...`). Optional — falls back to the
         * module's default model.
         */
        model: z.string().optional(),
        /**
         * AWS access key ID. Usually omitted: AWS users typically have
         * credentials in `~/.aws/credentials`, env vars, IAM role, or SSO —
         * the Bedrock SDK reads those via the default credential chain. Only
         * persist these here when the user explicitly opted in via the init
         * wizard (CI / cross-account scenarios).
         */
        accessKeyId: z.string().min(1).optional(),
        secretAccessKey: z.string().min(1).optional(),
        /** Temporary STS session token. Optional, paired with the two above. */
        sessionToken: z.string().min(1).optional(),
      })
      .optional(),
    vertex: z
      .object({
        /**
         * GCP project ID hosting the Vertex AI Model Garden endpoint.
         * Required: the MaaS chat-completions URL bakes the project ID
         * into the path. May be omitted at config-save time if the user
         * relies on `$GOOGLE_CLOUD_PROJECT` / `$GCLOUD_PROJECT` at scan
         * time — `buildDetector` re-resolves there.
         */
        project: z.string().min(1).optional(),
        /**
         * Vertex Model Garden model ID. Defaults to `zai-org/glm-5-maas`
         * (GLM-5 managed, OpenAI-compatible). GLM-5.1 is self-host only
         * today and not addressable through this block.
         */
        model: z.string().optional(),
      })
      .optional(),
    /**
     * Stamped on first write. Helps future migrations notice old configs
     * without having to interrogate the shape.
     */
    schemaVersion: z.literal(1).default(1),
  })
  .superRefine((cfg, ctx) => {
    // The active provider's credential block must exist. Catches
    // "I picked anthropic but never set a key" at load time instead
    // of at first scan.
    if (cfg.provider === "anthropic") {
      if (!cfg.anthropic) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "anthropic provider referenced but the anthropic block is missing",
          path: ["anthropic"],
        });
      } else {
        const hasApiKey = Boolean(cfg.anthropic.apiKey);
        const hasOauth = Boolean(cfg.anthropic.oauthToken);
        if (!hasApiKey && !hasOauth) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "anthropic block must have either 'apiKey' or 'oauthToken'",
            path: ["anthropic"],
          });
        } else if (hasApiKey && hasOauth) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "anthropic block has both 'apiKey' and 'oauthToken' — set exactly one",
            path: ["anthropic"],
          });
        }
      }
    }
    if (cfg.provider === "openai" && !cfg.openai) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "openai provider referenced but the openai block is missing",
        path: ["openai"],
      });
    }
    if (cfg.provider === "ollama" && !cfg.ollama) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "ollama provider referenced but the ollama block is missing",
        path: ["ollama"],
      });
    }
    if (cfg.provider === "bedrock" && !cfg.bedrock) {
      // bedrock block can be empty (env-var-only auth) but it must exist —
      // its presence is the user's signal that they've opted into bedrock.
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "bedrock provider referenced but the bedrock block is missing",
        path: ["bedrock"],
      });
    }
    if (cfg.provider === "vertex" && !cfg.vertex) {
      // vertex block can be empty (env-var GOOGLE_CLOUD_PROJECT, ambient
      // ADC) but it must exist — its presence is the user's signal that
      // they've opted into vertex.
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "vertex provider referenced but the vertex block is missing",
        path: ["vertex"],
      });
    }
    if (cfg.bedrock) {
      const hasAccess = Boolean(cfg.bedrock.accessKeyId);
      const hasSecret = Boolean(cfg.bedrock.secretAccessKey);
      if (hasAccess !== hasSecret) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "bedrock: accessKeyId and secretAccessKey must be set together (or both omitted to use the AWS default credential chain)",
          path: ["bedrock"],
        });
      }
    }
  });
export type UserConfig = z.infer<typeof UserConfig>;

// ---------------------------------------------------------------------------
// AgentRun — per-agent completion sidecar (`<outputDir>/state/agents/<slug>.json`)
// ---------------------------------------------------------------------------
//
// An agent's run doesn't map 1:1 onto a single file, so its resume signal
// can't live on FileRecord alone. This sidecar records "this agent
// completed in this output dir, under this scope." On a re-run with the
// same --output and matching scope, the orchestrator can skip the agent
// (lifting prior findings from disk) unless --rescan is passed.
//
// `scope` is signed so a re-run under a different scope re-runs the agent.
// Beyond the file-selection fields it carries:
//   - `reconHash` — a changed recon brief invalidates prompt-gated agents.
//   - `precondition` — whether the agent was queued or skipped last time,
//     so a flipped gate decision re-runs (or newly skips) the agent.
export const AgentRun = z.object({
  agentSlug: z.string(),
  lastCompletedRunId: z.string(),
  lastCompletedAt: z.string(),
  scope: z.object({
    diff: z.string().optional(),
    excludePatterns: z.array(z.string()).default([]),
    includePatterns: z.array(z.string()).default([]),
    maxFileSizeKb: z.number().int().positive(),
    rootPath: z.string(),
    /** Hash of the recon brief in effect; absent on pre-recon sidecars. */
    reconHash: z.string().optional(),
  }),
  /** Outcome of this agent's precondition on the last run. */
  precondition: z
    .object({
      queued: z.boolean(),
      reason: z.string().optional(),
    })
    .optional(),
  findingCount: z.number().int().nonnegative().default(0),
});
export type AgentRun = z.infer<typeof AgentRun>;

export const RunMeta = z.object({
  runId: z.string(),
  type: z.enum(["scan", "detect", "validate"]),
  phase: z.enum(["running", "done", "error"]),
  startedAt: z.string(),
  completedAt: z.string().optional(),
  /**
   * What was actually invoked, so a run is self-describing: the
   * subcommand plus the raw args as typed (which already carry the
   * `-t` templates and every flag). Optional so run files written
   * before this field still parse. `type` alone (e.g. "scan") doesn't
   * say what was run or with what flags — `argv` fills that gap.
   */
  invocation: z
    .object({
      /** Subcommand: "scan" | "revalidate" | "score" | "recon" | "summary". */
      command: z.string(),
      /** Raw CLI args as typed (process.argv after the node binary + entrypoint). */
      argv: z.string().optional(),
    })
    .optional(),
  stats: z
    .object({
      filesScanned: z.number().int().nonnegative().optional(),
      filesProcessed: z.number().int().nonnegative().optional(),
      candidatesFound: z.number().int().nonnegative().optional(),
      findingsCount: z.number().int().nonnegative().optional(),
      totalCostUsd: z.number().nonnegative().optional(),
      totalDurationMs: z.number().int().nonnegative().optional(),
    })
    .default({}),
});
export type RunMeta = z.infer<typeof RunMeta>;
