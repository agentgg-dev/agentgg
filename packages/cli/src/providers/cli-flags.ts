import type { Provider } from "@agentgg/core";
import { type CredentialOverrides, getProviderModule, type ProviderFlag } from "./index.js";

/**
 * Shape of the credential-bearing CLI flags passed into `agentgg scan`
 * and `agentgg revalidate`. Every field is context-scoped by
 * `--provider`: `--api-key` means the API key for the active provider,
 * `--region` means the region for the active provider, etc. Each
 * provider declares which flags are meaningful for it via
 * `ProviderModule.acceptedFlags`; anything else is rejected with a
 * helpful error.
 */
export interface ScanFlagOpts {
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  project?: string;
}

/**
 * Map flat CLI flag values onto the per-provider credential namespace
 * in CredentialOverrides. `--api-key` populates both Anthropic and
 * OpenAI slots — the active provider's `buildDetector` picks the
 * right one.
 */
export function buildCredentialsFromOpts(opts: ScanFlagOpts): CredentialOverrides {
  return {
    ...(opts.apiKey ? { anthropicApiKey: opts.apiKey, openaiApiKey: opts.apiKey } : {}),
    ...(opts.oauthToken ? { anthropicOauthToken: opts.oauthToken } : {}),
    ...(opts.baseUrl ? { ollamaBaseUrl: opts.baseUrl } : {}),
    ...(opts.region ? { bedrockRegion: opts.region, vertexRegion: opts.region } : {}),
    ...(opts.project ? { vertexProject: opts.project } : {}),
  };
}

interface FlagBinding {
  optKey: keyof ScanFlagOpts;
  flag: ProviderFlag;
}

const ALL_BINDINGS: readonly FlagBinding[] = [
  { optKey: "apiKey", flag: "api-key" },
  { optKey: "oauthToken", flag: "oauth-token" },
  { optKey: "baseUrl", flag: "base-url" },
  { optKey: "region", flag: "region" },
  { optKey: "project", flag: "project" },
];

/**
 * Hard-error when the user passes a credential flag the active
 * provider doesn't understand. Silent ignore would mask user-intent
 * mistakes (e.g. passing --oauth-token expecting Bedrock OAuth, which
 * doesn't exist — without this check the scan would silently route
 * through whatever ambient AWS auth happens to be configured).
 *
 * Env vars are intentionally not validated — they're ambient context
 * the cloud SDKs read on their own, not direct user intent.
 */
export function validateProviderFlags(providerName: Provider, opts: ScanFlagOpts): void {
  const mod = getProviderModule(providerName);
  const accepted = new Set<ProviderFlag>(mod.acceptedFlags);
  const offending: string[] = [];
  for (const { optKey, flag } of ALL_BINDINGS) {
    if (opts[optKey] !== undefined && !accepted.has(flag)) {
      offending.push(`--${flag}`);
    }
  }
  if (offending.length === 0) return;
  const allowed = mod.acceptedFlags.map((f) => `--${f}`).join(", ");
  const allowedList = allowed.length > 0 ? allowed : "(none)";
  const noun = offending.length === 1 ? "flag is" : "flags are";
  throw new Error(
    `${offending.join(", ")} ${noun} not valid for provider '${providerName}'.\n` +
      `       valid credential flags for ${providerName}: ${allowedList}` +
      (providerName === "bedrock"
        ? `\n       (AWS credentials are read from the standard AWS env vars / profile / IAM role)`
        : ""),
  );
}
