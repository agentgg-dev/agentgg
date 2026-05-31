import type { Provider, UserConfig } from "@agentgg/core";
import type { Detector } from "../detect.js";

/**
 * Names of the generic, context-scoped CLI flags accepted by `agentgg
 * scan` / `agentgg revalidate`. Each provider declares which subset is
 * meaningful for it; the orchestrator validates explicit flags against
 * that list and errors on anything irrelevant (silent ignore would
 * mask user-intent mistakes — see provider-module design notes).
 *
 * Env vars are intentionally NOT validated — they're ambient context
 * the cloud SDKs read on their own (AWS_*, GOOGLE_APPLICATION_CREDENTIALS,
 * etc.), not direct user intent.
 */
export type ProviderFlag = "api-key" | "oauth-token" | "base-url" | "region" | "project";

/**
 * One-shot CLI credential overrides. Flat namespace so commander
 * doesn't have to know about provider modules at parse time — the
 * registry's `buildCredentials` reads what it needs.
 */
export interface CredentialOverrides {
  anthropicApiKey?: string;
  anthropicOauthToken?: string;
  openaiApiKey?: string;
  ollamaBaseUrl?: string;
  bedrockRegion?: string;
  bedrockAccessKeyId?: string;
  bedrockSecretAccessKey?: string;
  bedrockSessionToken?: string;
  vertexProject?: string;
}

/**
 * Options surfaced from CLI flags into provider modules. Same shape
 * as the legacy `ResolveOptions` so the public `resolveDetector` API
 * doesn't move.
 */
export interface ResolveOptions {
  provider?: string;
  model?: string;
  credentials?: CredentialOverrides;
  verbose?: boolean;
  validateMaxTurns?: number;
  effort?: "low" | "medium" | "high" | "max";
  thinking?: "off" | "adaptive" | "enabled";
}

/**
 * Init-wizard inputs that map onto a single provider's credential
 * block. Modules pull what they need from this and return a
 * UserConfig fragment (anthropic / openai / ollama / bedrock).
 *
 * The wizard collects every field it can ahead of time and routes
 * via the active provider's module — no per-provider switch
 * statements in init.ts.
 */
export interface InitInputs {
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  awsSessionToken?: string;
  /** GCP project ID for the Vertex provider. */
  project?: string;
  model?: string;
}

export interface CollectCredentialsArgs {
  /** What the user supplied via flags + free-form prompts. */
  inputs: InitInputs;
  /** Process env — provider can fall back to standard vars when nothing was passed. */
  env: NodeJS.ProcessEnv;
  /** True when the wizard is running interactively (allowed to prompt). */
  interactive: boolean;
}

/**
 * A bundled provider definition: every touchpoint that used to be a
 * switch-arm across types.ts / llm.ts / init.ts / config.ts now lives
 * in one place. Adding a new provider = one new module file + an enum
 * + schema-block entry in core.
 */
export interface ProviderModule {
  readonly name: Provider;
  /** Human-readable label for prompts and logs ("AWS Bedrock", "OpenAI / Codex"). */
  readonly label: string;
  /** One-line description for the init wizard menu. */
  readonly description: string;
  /** Fallback model when no `--model` flag and no saved value. */
  readonly defaultModel: string;
  /**
   * Generic CLI flags this provider accepts. Validated at scan/revalidate
   * start: any *other* flag explicitly passed is an error.
   * `--provider` and `--model` are implicit (every provider takes them).
   */
  readonly acceptedFlags: ReadonlyArray<ProviderFlag>;

  /**
   * Construct the Detector for a scan run. Reads credentials from
   * `options.credentials` (CLI overrides), then `config[name]`
   * (saved), then env vars / cloud-default chains as appropriate.
   */
  buildDetector(config: UserConfig, options: ResolveOptions): Detector;

  /**
   * Wizard step: collect any credential info missing from `inputs` and
   * return a UserConfig fragment. Throws if interactive=false and a
   * required field can't be resolved.
   */
  collectCredentials(args: CollectCredentialsArgs): Promise<UserConfig>;

  /**
   * Curated list of common model IDs for the init wizard's picker.
   * Modules can also implement `listModels` to fetch dynamically
   * (Ollama does that against `/api/tags`).
   */
  readonly curatedModels?: ReadonlyArray<string>;
  listModels?(args: { config: Partial<UserConfig>; env: NodeJS.ProcessEnv }): Promise<string[]>;

  /**
   * One-line `agentgg config` summary, or null when this provider
   * isn't configured in `cfg`.
   */
  formatForList(cfg: UserConfig): string | null;

  /** Apply masking to this provider's block. Called by `--json` mode. */
  redact(cfg: UserConfig): UserConfig;
}
