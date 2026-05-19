import { z } from "zod";

// ---------------------------------------------------------------------------
// Severity, noise, validation verdicts
// ---------------------------------------------------------------------------

export const Severity = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
export type Severity = z.infer<typeof Severity>;

export const NoiseTier = z.enum(["precise", "normal", "noisy"]);
export type NoiseTier = z.infer<typeof NoiseTier>;

/**
 * Execution shape an agent declares for itself.
 *
 * - `file` — the framework runs the agent once per matching file, passing
 *   the file's content as text. Good for surface-level patterns (hardcoded
 *   secrets, obvious sinks). Cheap, predictable, scales linearly with file
 *   count.
 *
 * - `hunt` — the framework runs the agent once for the entire repo with
 *   Read/Glob/Grep tool access. The agent decides which files to read.
 *   Good for cross-file logic (access-control flow, taint chains,
 *   CVE-style pattern hunts). One call per agent regardless of repo size.
 */
/**
 * How an agent locates and inspects code:
 *   - `file`   — single-turn, no tools, one LLM call per file matching
 *                `filePatterns`. Cheapest. Used for surface-level
 *                pattern detection that fits in one file's context.
 *   - `hunt`   — agentic session with Read/Glob/Grep across the whole
 *                repo. The agent discovers its own files. Most flexible,
 *                most expensive, hardest to make deterministic.
 *   - `walker` — anchored agentic investigation. Walker enumerates files matching
 *                `filePatterns` (cheap, deterministic), the agent's
 *                `preFilter` regexes narrow further to "candidates"
 *                with line hits, then each candidate gets its own
 *                anchored agentic session with tools. Same depth as
 *                hunt without burning turns on file discovery.
 */
export const AgentMode = z.enum(["file", "hunt", "walker"]);
export type AgentMode = z.infer<typeof AgentMode>;

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

export const Agent = z.object({
  /** Stable identifier. Used in --only-agents, scope.agents.disable, etc. */
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  name: z.string(),
  description: z.string(),
  version: z.string().default("0.0.1"),
  author: z.string().optional(),
  /** Per-file review vs whole-repo hunt. See AgentMode docstring. */
  mode: AgentMode.default("file"),
  noiseTier: NoiseTier.default("normal"),
  /** Glob patterns the agent applies to. Empty = all files. */
  filePatterns: z.array(z.string()).default([]),
  /**
   * Glob patterns the agent should never touch. Authors use this to
   * declare a permanent skip list (tests, fixtures, e2e, generated
   * code) so CLI users don't need to remember `--exclude` flags.
   * Combined additively with any CLI patterns at runtime. Minimatch
   * dialect — same as `filePatterns`.
   */
  excludePatterns: z.array(z.string()).default([]),
  /**
   * Walker-mode only: regexes that narrow `filePatterns`-matching
   * files down to "candidates" worth investigating. A file becomes a
   * candidate when at least one regex matches at least one line. The
   * matching line numbers and labels are passed to the LLM as scanner
   * hits. Ignored in
   * `file` and `hunt` modes.
   */
  preFilter: z.array(AgentPreFilterPattern).default([]),
  /**
   * Walker-mode only: tool-use turn budget per batched investigation
   * session. A batch can contain multiple candidate files; the model
   * sees all of them at once and uses tools to chase context across
   * them. Default 30.
   */
  maxTurnsPerBatch: z.number().int().min(1).default(30),
  /**
   * Walker-mode only: how many candidate files to pack into one
   * investigation session. Larger batches give the model more
   * cross-file context per call (and amortize the LLM round-trip
   * cost) but reduce concurrency. Default 5 — sane middle ground
   * for most agents.
   */
  maxFilesPerBatch: z.number().int().min(1).default(5),
  /** Optional language gate (e.g. ["typescript", "javascript"]). */
  languages: z.array(z.string()).default([]),
  /** Optional pre-filter regexes; if any match, the file is sent to the LLM. */
  prefilter: z.array(z.string()).default([]),
  /**
   * Documentation-only field. CWE / OWASP / GHSA / CVE IDs or URLs
   * this agent was modeled after. NOT injected into the LLM prompt —
   * the prompt body is the only thing the model sees. Surfaced by
   * `agents info` for human readers; otherwise unused at runtime.
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
  /** Repo-relative POSIX path (forward slashes). */
  filePath: z.string(),
  contentHash: z.string(),
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
export const Provider = z.enum(["anthropic", "openai", "ollama", "bedrock"]);
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
// Hunt and walker agents don't map 1:1 onto a single file the way file-mode
// agents do, so their resume signal can't live on FileRecord alone. This
// sidecar records "this agent completed in this output dir, under this
// scope." On a re-run with the same --output and matching scope, the
// orchestrator can skip the agent (lifting prior findings from disk) unless
// --rescan is passed. Scope-aware so a re-run with different --diff /
// --exclude / --only invalidates the resume and re-runs the agent.

export const AgentRun = z.object({
  agentSlug: z.string(),
  mode: AgentMode,
  lastCompletedRunId: z.string(),
  lastCompletedAt: z.string(),
  scope: z.object({
    diff: z.string().optional(),
    excludePatterns: z.array(z.string()).default([]),
    includePatterns: z.array(z.string()).default([]),
    maxFileSizeKb: z.number().int().positive(),
    rootPath: z.string(),
  }),
  findingCount: z.number().int().nonnegative().default(0),
});
export type AgentRun = z.infer<typeof AgentRun>;

export const RunMeta = z.object({
  runId: z.string(),
  type: z.enum(["scan", "detect", "validate"]),
  phase: z.enum(["running", "done", "error"]),
  startedAt: z.string(),
  completedAt: z.string().optional(),
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
