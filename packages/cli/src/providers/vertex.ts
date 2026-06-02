import type { UserConfig } from "@agentgg/core";
import { createOpenAI } from "@ai-sdk/openai";
import { input } from "@inquirer/prompts";
import { GoogleAuth } from "google-auth-library";
import type { Detector } from "../detect.js";
import { VercelAgentDetector } from "../detectors/index.js";
import type { CollectCredentialsArgs, ProviderModule, ResolveOptions } from "./types.js";

const DEFAULT_MODEL = "zai-org/glm-5-maas";
const DEFAULT_REGION = "global";

// Curated picker entries for `agentgg init`. Each tuple is (model id,
// the region pool Vertex publishes it to). Region matters because the
// MaaS chat-completions URL bakes both the hostname (`<region>-...` or
// global) AND the path's `locations/<x>` segment from the same value;
// pointing at the wrong pool returns HTTP 404 "Publisher Model … not
// found" even when the model is enabled in your project. The picker
// uses this list as a UX hint — `--model <id> --region <r>` accepts
// any compatible MaaS combination, and "Other (enter manually)" is the
// escape hatch.
const CURATED_MODELS: ReadonlyArray<{ model: string; region: string }> = [
  { model: DEFAULT_MODEL, region: "global" },
  { model: "meta/llama-4-scout-17b-16e-instruct-maas", region: "us-east5" },
  { model: "meta/llama-4-maverick-17b-128e-instruct-maas", region: "us-east5" },
];

/**
 * Vertex AI Model Garden (MaaS), OpenAI-compatible surface. Auth is
 * Google ADC — no API key stored anywhere. URL shape depends on the
 * region the model is published to:
 *   - `global` pool (GLM-5):
 *       https://aiplatform.googleapis.com/v1/projects/<id>/locations/global/...
 *   - regional pool (Llama, Mistral):
 *       https://<region>-aiplatform.googleapis.com/v1/projects/<id>/locations/<region>/...
 *
 * Hostname and `locations/<x>` segment swap together — mixing them
 * returns 404. Each MaaS vendor picks their own publishing pool; that
 * pairing is the actual selector, not just the model ID.
 *
 * GLM-5.1 is self-host only today and not addressable here. When/if
 * Z.ai ships a `glm-5.1-maas` model ID we can flip the default; if
 * they instead require a deploy-yourself endpoint, that's a separate
 * provider module that talks to Vertex's native `{instances,
 * parameters}` prediction surface.
 */
function buildBaseURL(project: string, region: string): string {
  const host =
    region === "global" ? "aiplatform.googleapis.com" : `${region}-aiplatform.googleapis.com`;
  return `https://${host}/v1/projects/${project}/locations/${region}/endpoints/openapi`;
}

function resolveProject(config: UserConfig, options: ResolveOptions): string {
  const fromFlag = options.credentials?.vertexProject?.trim();
  if (fromFlag) return fromFlag;
  const fromConfig = config.vertex?.project?.trim();
  if (fromConfig) return fromConfig;
  const fromEnv = (process.env.GOOGLE_CLOUD_PROJECT ?? process.env.GCLOUD_PROJECT)?.trim();
  if (fromEnv) return fromEnv;
  throw new Error(
    "Vertex provider requested but no GCP project resolved. Pass --project, set it via `agentgg init --provider vertex --project <id>`, or export GOOGLE_CLOUD_PROJECT.",
  );
}

function resolveRegion(config: UserConfig, options: ResolveOptions): string {
  const fromFlag = options.credentials?.vertexRegion?.trim();
  if (fromFlag) return fromFlag;
  const fromConfig = config.vertex?.region?.trim();
  if (fromConfig) return fromConfig;
  return DEFAULT_REGION;
}

function buildDetector(config: UserConfig, options: ResolveOptions): Detector {
  const project = resolveProject(config, options);
  const region = resolveRegion(config, options);
  const modelName = options.model ?? config.vertex?.model ?? DEFAULT_MODEL;

  // ADC: reads GOOGLE_APPLICATION_CREDENTIALS, gcloud
  // application-default credentials, or the GCE/GKE/Cloud Run metadata
  // server. The cloud-platform scope is what Vertex AI requires.
  const auth = new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform"] });

  // Access tokens are ~1hr TTL. Refreshing per call is fine for a
  // spike — google-auth-library caches the live token internally and
  // only re-mints when it's near expiry. If this becomes a hot path
  // we can hoist a cached token with manual expiry tracking.
  const vertexFetch: typeof fetch = async (url, init) => {
    const client = await auth.getClient();
    const { token } = await client.getAccessToken();
    if (!token) {
      throw new Error("Vertex: Google ADC returned an empty access token — check ADC setup.");
    }
    const headers = new Headers(init?.headers);
    headers.set("Authorization", `Bearer ${token}`);
    return fetch(url, { ...init, headers });
  };

  const vertex = createOpenAI({
    apiKey: "unused-adc-auth-via-fetch",
    baseURL: buildBaseURL(project, region),
    fetch: vertexFetch,
  });

  return new VercelAgentDetector("vertex", vertex(modelName), {
    effort: options.effort,
    thinking: options.thinking,
    verbose: options.verbose,
  });
}

// Look up the region we know each curated model is published to. Falls
// back to `global` (GLM-5's home) for anything off the curated list —
// users on a non-curated model should pass --region explicitly.
function regionForCuratedModel(model: string): string {
  return CURATED_MODELS.find((m) => m.model === model)?.region ?? DEFAULT_REGION;
}

async function collectCredentials(args: CollectCredentialsArgs): Promise<UserConfig> {
  const { inputs, env, interactive } = args;
  let project = inputs.project?.trim();
  if (!project) {
    const envProject = (env.GOOGLE_CLOUD_PROJECT ?? env.GCLOUD_PROJECT)?.trim();
    if (envProject) {
      project = envProject;
    } else if (interactive) {
      project = (
        await input({
          message: "GCP project ID hosting Vertex AI Model Garden (e.g. my-proj-dev):",
        })
      ).trim();
    } else {
      throw new Error(
        "No GCP project supplied for Vertex provider (--project or $GOOGLE_CLOUD_PROJECT required).",
      );
    }
  }
  if (!project) {
    throw new Error("vertex provider selected but no GCP project provided");
  }
  const model = inputs.model ?? DEFAULT_MODEL;

  // Region: explicit --region wins; otherwise infer from the selected
  // model's curated pool; otherwise prompt with that inference as
  // default; non-interactive falls back to `global`.
  let region = inputs.region?.trim();
  if (!region) {
    const suggested = regionForCuratedModel(model);
    if (interactive) {
      region = (
        await input({
          message: `Vertex region for ${model} (use 'global' for GLM-5, 'us-east5' for Llama 4):`,
          default: suggested,
        })
      ).trim();
    } else {
      region = suggested;
    }
  }
  return {
    provider: "vertex",
    vertex: { project, region, model },
    schemaVersion: 1,
  };
}

export const vertexModule: ProviderModule = {
  name: "vertex",
  label: "Google Vertex AI (Model Garden)",
  description: "GLM-5, Llama 4 and other Model Garden MaaS models on GCP",
  defaultModel: DEFAULT_MODEL,
  acceptedFlags: ["project", "region"],
  curatedModels: CURATED_MODELS.map((m) => m.model),
  buildDetector,
  collectCredentials,
  formatForList(cfg: UserConfig): string | null {
    if (!cfg.vertex) return null;
    const model = cfg.vertex.model ?? "(default)";
    const project = cfg.vertex.project ?? "(env)";
    const region = cfg.vertex.region ?? DEFAULT_REGION;
    return `vertex      auth=ADC      project=${project}  region=${region}  model=${model}`;
  },
  redact(cfg: UserConfig): UserConfig {
    return cfg;
  },
};
