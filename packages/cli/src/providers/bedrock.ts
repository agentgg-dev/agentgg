import type { UserConfig } from "@agentgg/core";
import { createAmazonBedrock } from "@ai-sdk/amazon-bedrock";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import { confirm, input, password } from "@inquirer/prompts";
import type { Detector } from "../detect.js";
import { VercelAgentDetector } from "../detectors/index.js";
import type { CollectCredentialsArgs, ProviderModule, ResolveOptions } from "./types.js";

// Default to the US Anthropic inference profile. Newer Claude models on
// Bedrock REQUIRE invocation through a regional inference profile
// (`us.*` / `eu.*` / `apac.*`); on-demand invocation of the bare
// `anthropic.*` ID returns ValidationException. EU/APAC users override
// at init time. Bedrock model IDs encode the family (`anthropic.*`,
// `amazon.*`, `meta.*`, …) so the "model family" axis doesn't need to
// live in the provider name.
const DEFAULT_MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v1:0";

function buildDetector(config: UserConfig, options: ResolveOptions): Detector {
  // CLI flags > saved config > AWS env vars. Anything we don't pass
  // through gets resolved by the underlying AWS SDK's default credential
  // chain (env, ~/.aws, IAM role, SSO).
  const region =
    options.credentials?.bedrockRegion ??
    config.bedrock?.region ??
    process.env.AWS_REGION ??
    process.env.AWS_DEFAULT_REGION;
  if (!region) {
    throw new Error(
      "Bedrock provider requested but no AWS region available. Pass --region, set $AWS_REGION, or run `agentgg init --provider bedrock`.",
    );
  }

  const accessKeyId = options.credentials?.bedrockAccessKeyId ?? config.bedrock?.accessKeyId;
  const secretAccessKey =
    options.credentials?.bedrockSecretAccessKey ?? config.bedrock?.secretAccessKey;
  const sessionToken = options.credentials?.bedrockSessionToken ?? config.bedrock?.sessionToken;

  if ((accessKeyId && !secretAccessKey) || (!accessKeyId && secretAccessKey)) {
    throw new Error(
      "Bedrock: --access-key-id and --secret-access-key (or their config equivalents) must be set together.",
    );
  }

  const modelName = options.model ?? config.bedrock?.model ?? DEFAULT_MODEL;

  // Credential resolution: if explicit keys came from a flag or saved
  // config, use them directly. Otherwise hand the AWS SDK's full default
  // credential chain to the adapter via `bedrockOptions.credentials` —
  // this resolves env vars → ~/.aws/credentials → SSO → IAM role → EC2
  // metadata on every call, the same chain `aws sts get-caller-identity`
  // uses. The v1.x Vercel adapter does NOT read ~/.aws/credentials on
  // its own (it only honors env vars or values you pass it), so without
  // this we'd silently force users into the env-var dance every shell.
  const explicitKeys = Boolean(accessKeyId && secretAccessKey);
  const bedrock = explicitKeys
    ? createAmazonBedrock({
        region,
        accessKeyId,
        secretAccessKey,
        ...(sessionToken ? { sessionToken } : {}),
      })
    : createAmazonBedrock({
        region,
        bedrockOptions: { region, credentials: fromNodeProviderChain() },
      });

  // Bedrock supports tool-calling + structured output through the Vercel
  // SDK on Anthropic, Cohere, and Meta hosted models. Same detector path
  // as OpenAI; the model ID identifies the family.
  return new VercelAgentDetector("bedrock", bedrock(modelName), {
    effort: options.effort,
    thinking: options.thinking,
    verbose: options.verbose,
  });
}

async function collectCredentials(args: CollectCredentialsArgs): Promise<UserConfig> {
  const { inputs, env, interactive } = args;

  // Region: flag > prompt > env. We don't *require* a region at save
  // time — buildDetector re-resolves from env if the saved block omits
  // it, so CI users with $AWS_REGION don't need to bake region into config.
  let region = inputs.region?.trim();
  if (!region && interactive) {
    region = (
      await input({
        message: "AWS region for Bedrock (e.g. us-east-1):",
        default: env.AWS_REGION ?? env.AWS_DEFAULT_REGION ?? "us-east-1",
      })
    ).trim();
  }
  if (!region) {
    region = env.AWS_REGION ?? env.AWS_DEFAULT_REGION;
  }

  // Credentials. Default to "use the AWS default chain" — the vast
  // majority of users already have SSO / IAM role / ~/.aws/credentials
  // wired up. Only persist explicit keys if the user opts in.
  let accessKeyId = inputs.awsAccessKeyId?.trim();
  let secretAccessKey = inputs.awsSecretAccessKey?.trim();
  let sessionToken = inputs.awsSessionToken?.trim();

  if (!accessKeyId && !secretAccessKey) {
    if (interactive) {
      const explicit = await confirm({
        message:
          "Save explicit AWS access keys to agentgg config? (Default: No — agentgg will use your AWS env vars / SSO / IAM role at scan time)",
        default: false,
      });
      if (explicit) {
        accessKeyId = (await password({ message: "AWS_ACCESS_KEY_ID:", mask: "*" })).trim();
        secretAccessKey = (await password({ message: "AWS_SECRET_ACCESS_KEY:", mask: "*" })).trim();
        const wantSession = await confirm({
          message: "Add a session token (sk only needed for STS temp creds)?",
          default: false,
        });
        if (wantSession) {
          sessionToken = (await password({ message: "AWS_SESSION_TOKEN:", mask: "*" })).trim();
        }
      }
    }
    // Non-interactive with no flags: leave creds unset and rely on the
    // AWS default chain. buildDetector will fail clearly if the chain
    // is empty when a scan runs.
  }

  if ((accessKeyId && !secretAccessKey) || (!accessKeyId && secretAccessKey)) {
    throw new Error("Bedrock: access key ID and secret access key must be set together.");
  }

  const model = inputs.model ?? DEFAULT_MODEL;
  return {
    provider: "bedrock",
    bedrock: {
      ...(region ? { region } : {}),
      ...(accessKeyId ? { accessKeyId } : {}),
      ...(secretAccessKey ? { secretAccessKey } : {}),
      ...(sessionToken ? { sessionToken } : {}),
      model,
    },
    schemaVersion: 1,
  };
}

function maskValue(s: string): string {
  if (s.length <= 10) return "****";
  return `${s.slice(0, 10)}…${"*".repeat(4)}`;
}

export const bedrockModule: ProviderModule = {
  name: "bedrock",
  label: "AWS Bedrock (Claude / Llama / Titan, billed via AWS)",
  description:
    "AWS-billed inference via Bedrock. Auth uses the standard AWS chain (env / SSO / IAM role) unless explicit keys are configured.",
  defaultModel: DEFAULT_MODEL,
  // No --api-key / --oauth-token: AWS credentials come from the AWS chain
  // by default. --region is the one knob most users will actually pass
  // (different from the AWS env-var convention they already have set).
  acceptedFlags: ["region"],
  // US inference profiles first — newer Claude models REQUIRE invocation
  // via an inference profile (e.g. `us.*` for US regions, `eu.*` for EU,
  // `apac.*` for APAC). On-demand invocation of newer Claude models
  // returns a ValidationException. Older Claude 3.5 variants still
  // support on-demand; non-Anthropic models work either way. EU/APAC
  // users can type the regional prefix via "Other (enter manually)".
  curatedModels: [
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "us.anthropic.claude-opus-4-1-20250805-v1:0",
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "anthropic.claude-3-5-haiku-20241022-v1:0",
    "meta.llama3-3-70b-instruct-v1:0",
    "amazon.nova-pro-v1:0",
    "amazon.nova-lite-v1:0",
  ],
  buildDetector,
  collectCredentials,
  formatForList(cfg: UserConfig): string | null {
    if (!cfg.bedrock) return null;
    const region = cfg.bedrock.region ?? "(from $AWS_REGION)";
    const auth = cfg.bedrock.accessKeyId ? "explicit keys" : "AWS default chain";
    const model = cfg.bedrock.model ?? "(default)";
    return `bedrock     region=${region}  auth=${auth}  model=${model}`;
  },
  redact(cfg: UserConfig): UserConfig {
    if (!cfg.bedrock) return cfg;
    return {
      ...cfg,
      bedrock: {
        ...cfg.bedrock,
        ...(cfg.bedrock.accessKeyId ? { accessKeyId: maskValue(cfg.bedrock.accessKeyId) } : {}),
        ...(cfg.bedrock.secretAccessKey
          ? { secretAccessKey: maskValue(cfg.bedrock.secretAccessKey) }
          : {}),
        ...(cfg.bedrock.sessionToken ? { sessionToken: maskValue(cfg.bedrock.sessionToken) } : {}),
      },
    };
  },
};
