import type { UserConfig } from "@agentgg/core";
import { createOpenAI } from "@ai-sdk/openai";
import { input } from "@inquirer/prompts";
import { GoogleAuth } from "google-auth-library";
import type { Detector } from "../detect.js";
import { VercelAgentDetector } from "../detectors/index.js";
import type { CollectCredentialsArgs, ProviderModule, ResolveOptions } from "./types.js";

const DEFAULT_MODEL = "zai-org/glm-5-maas";

/**
 * GLM-5 on Vertex AI Model Garden (MaaS). Uses the OpenAI-compatible
 * chat-completions surface Google exposes at
 * `…/locations/global/endpoints/openapi/chat/completions`, with the
 * project ID baked into the path. Auth is Google ADC — no API key
 * stored anywhere.
 *
 * GLM-5.1 is self-host only today and not addressable here. When/if
 * Z.ai ships a `glm-5.1-maas` model ID we can flip the default; if
 * they instead require a deploy-yourself endpoint, that's a separate
 * provider module that talks to Vertex's native `{instances,
 * parameters}` prediction surface.
 */
function buildBaseURL(project: string): string {
  return `https://aiplatform.googleapis.com/v1/projects/${project}/locations/global/endpoints/openapi`;
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

function buildDetector(config: UserConfig, options: ResolveOptions): Detector {
  const project = resolveProject(config, options);
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
    baseURL: buildBaseURL(project),
    fetch: vertexFetch,
  });

  return new VercelAgentDetector("vertex", vertex(modelName), {
    effort: options.effort,
    thinking: options.thinking,
    verbose: options.verbose,
  });
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
  return {
    provider: "vertex",
    vertex: { project, model },
    schemaVersion: 1,
  };
}

export const vertexModule: ProviderModule = {
  name: "vertex",
  label: "Google Vertex AI (Model Garden)",
  description: "GLM-5 and other Model Garden MaaS models on GCP",
  defaultModel: DEFAULT_MODEL,
  acceptedFlags: ["project"],
  curatedModels: [DEFAULT_MODEL],
  buildDetector,
  collectCredentials,
  formatForList(cfg: UserConfig): string | null {
    if (!cfg.vertex) return null;
    const model = cfg.vertex.model ?? "(default)";
    const project = cfg.vertex.project ?? "(env)";
    return `vertex      auth=ADC      project=${project}  model=${model}`;
  },
  redact(cfg: UserConfig): UserConfig {
    return cfg;
  },
};
