import type { Agent, Finding } from "@agentgg/core";
import { query } from "@anthropic-ai/claude-agent-sdk";
import {
  DetectionResult,
  type Detector,
  type HuntArgs,
  buildDetectPrompt,
  buildHuntPrompt,
  hydrateFinding,
} from "../detect.js";
import { LlmValidation, asValidationField, buildValidatePrompt } from "../validator.js";

const ENV_ALLOWLIST = new Set<string>([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "TERM",
  "TZ",
  "LANG",
  "LANGUAGE",
  "LC_ALL",
  "LC_CTYPE",
  "TMPDIR",
  "TMP",
  "TEMP",
  "PWD",
  "NODE_PATH",
  "NODE_OPTIONS",
  // Windows-specific essentials
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMFILES",
  "PROGRAMDATA",
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "PATHEXT",
]);

/**
 * Detector backed by `@anthropic-ai/claude-agent-sdk`. Spawns the
 * `claude` CLI as a child process. The same backend serves three needs:
 *
 *   - Anthropic OAuth (`oauthToken`) — `mode: "file"` and `mode: "hunt"`.
 *   - Anthropic API key (`apiKey`) — `mode: "hunt"` only. (File mode
 *     for API-key users runs through the cheaper VercelDetector path
 *     by default; the resolver picks this detector for hunts instead.)
 *
 * File mode is a one-turn agent with no tools — same behavior as before.
 * Hunt mode opens Read/Glob/Grep and lets the agent decide which files
 * to read, up to `maxTurns: 25`.
 */
export class ClaudeAgentDetector implements Detector {
  readonly name: string;
  private readonly apiKey?: string;
  private readonly oauthToken?: string;
  private readonly model: string;

  constructor(opts: { apiKey?: string; oauthToken?: string; model: string }) {
    if (!opts.apiKey && !opts.oauthToken) {
      throw new Error("ClaudeAgentDetector needs either apiKey or oauthToken");
    }
    this.apiKey = opts.apiKey;
    this.oauthToken = opts.oauthToken;
    this.model = opts.model;
    this.name = opts.oauthToken ? "anthropic-oauth" : "anthropic-api-via-cli";
  }

  async detectFile(args: {
    agent: Agent;
    filePath: string;
    content: string;
  }): Promise<Finding[]> {
    const { agent, filePath, content } = args;
    const prompt = buildJsonOnlyFilePrompt(agent, filePath, content);
    const resultText = await this.run({
      prompt,
      allowedTools: [],
      maxTurns: 1,
    });
    const parsed = parseJsonObject(resultText);
    const validated = DetectionResult.parse(parsed);
    return validated.findings.map((f) => hydrateFinding(f, agent, filePath));
  }

  async hunt(args: HuntArgs): Promise<Finding[]> {
    const { agent, rootDir, excludePatterns, includePatterns, maxFileSizeKb } = args;
    const prompt = buildHuntPrompt(agent, {
      excludePatterns,
      includePatterns,
      maxFileSizeKb,
    });
    const resultText = await this.run({
      prompt,
      allowedTools: ["Read", "Glob", "Grep"],
      maxTurns: 25,
      cwd: rootDir,
    });
    const parsed = parseJsonObject(resultText);
    const validated = DetectionResult.parse(parsed);
    // For hunt findings the LLM owns `filePath`; fallback only used if
    // the model omitted it (which buildHuntPrompt forbids).
    return validated.findings.map((f) =>
      hydrateFinding(f, agent, f.filePath ?? "(unknown)"),
    );
  }

  async validateFinding(args: { finding: Finding; fileContent: string; scope?: string }) {
    const basePrompt = buildValidatePrompt(args);
    // Validators occasionally emit malformed JSON (stray `\` in a
    // reasoning quote, etc.). One retry with a tightened prompt fixes
    // most of them and is far cheaper than failing the whole pass.
    // Two attempts cap the worst case at one extra LLM call.
    let lastError: unknown;
    for (let attempt = 0; attempt < 2; attempt++) {
      const prompt =
        attempt === 0
          ? basePrompt
          : `${basePrompt}\n\n---\nIMPORTANT: your previous response did not parse as JSON (${
              lastError instanceof Error ? lastError.message : String(lastError)
            }). Re-emit ONLY a single JSON object matching the schema above. Escape every backslash inside string values as \\\\. No prose, no code fences.`;
      try {
        const resultText = await this.run({
          prompt,
          allowedTools: [],
          maxTurns: 1,
        });
        const parsed = parseJsonObject(resultText);
        const validated = LlmValidation.parse(parsed);
        return asValidationField(validated);
      } catch (err) {
        lastError = err;
        if (process.env.AGENTGG_DEBUG) {
          console.error(
            `ClaudeAgentDetector.validateFinding attempt ${attempt + 1} failed: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
      }
    }
    throw lastError;
  }

  private async run(opts: {
    prompt: string;
    allowedTools: string[];
    maxTurns: number;
    cwd?: string;
  }): Promise<string> {
    let resultText = "";
    try {
      for await (const message of query({
        prompt: opts.prompt,
        options: {
          ...(opts.cwd ? { cwd: opts.cwd } : {}),
          allowedTools: opts.allowedTools,
          permissionMode: "bypassPermissions",
          maxTurns: opts.maxTurns,
          model: this.model,
          env: this.buildEnv(),
        },
      })) {
        const msg = message as Record<string, unknown>;
        if (msg.type === "result" && msg.subtype === "success") {
          resultText = String(msg.result ?? "");
        }
      }
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- ClaudeAgentDetector raw error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("---------------------------------------");
      }
      throw err;
    }
    if (!resultText) {
      throw new Error(
        "Claude Agent SDK produced no result text. Is the `claude` CLI installed and the credential valid?",
      );
    }
    return resultText;
  }

  private buildEnv(): Record<string, string> {
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (typeof v !== "string") continue;
      if (ENV_ALLOWLIST.has(k) || k.startsWith("LC_") || k === "Path") {
        env[k] = v;
      }
    }
    if (this.oauthToken) env.CLAUDE_CODE_OAUTH_TOKEN = this.oauthToken;
    if (this.apiKey) env.ANTHROPIC_API_KEY = this.apiKey;
    return env;
  }
}

/**
 * For file mode under the agent SDK, we want strict JSON output too.
 * The Vercel path uses Zod structured output; the agent SDK doesn't,
 * so we have to be explicit and parse defensively.
 */
function buildJsonOnlyFilePrompt(
  agent: Agent,
  filePath: string,
  content: string,
): string {
  return `${buildDetectPrompt(agent, filePath, content)}

---

Respond with ONLY a JSON object matching this exact shape:

\`\`\`
{
  "findings": [
    {
      "title": string,
      "vulnSlug": string,
      "lineRange": [number, number] | undefined,
      "summary": string,
      "details": string,
      "poc": string,
      "impact": string,
      "references": string[],
      "confidence": number
    }
  ]
}
\`\`\`

Do not include any prose before or after the JSON. Do not wrap the JSON
in markdown code fences. The response must be a single JSON object that
parses cleanly with \`JSON.parse\`. If no vulnerabilities are found,
return \`{ "findings": [] }\`.`;
}

/**
 * Extract a JSON object from the model's free-form text response.
 * Handles three common shapes:
 *   1. Pure JSON (what we asked for)
 *   2. JSON wrapped in ```json fences (model ignored the instruction)
 *   3. JSON embedded in prose (model added explanation)
 */
export function parseJsonObject(text: string): unknown {
  const trimmed = text.trim();

  // Strip a leading/trailing markdown fence if present.
  const fenceMatch = trimmed.match(/^```(?:json)?\s*\n([\s\S]*?)\n```\s*$/);
  if (fenceMatch) {
    return JSON.parse(fenceMatch[1]);
  }

  // Try direct parse first.
  try {
    return JSON.parse(trimmed);
  } catch {
    // Fall through to the substring extraction below.
  }

  // Last resort: pull the first {...} balanced block we can find.
  const firstBrace = trimmed.indexOf("{");
  const lastBrace = trimmed.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    const candidate = trimmed.slice(firstBrace, lastBrace + 1);
    return JSON.parse(candidate);
  }

  throw new Error(
    `ClaudeAgentDetector: response did not contain parseable JSON. Got: ${trimmed.slice(0, 200)}…`,
  );
}
