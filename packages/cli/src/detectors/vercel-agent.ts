import { readFile, readdir } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import type { Agent, Finding } from "@agentgg/core";
import { type LanguageModelV1, generateObject, generateText, tool } from "ai";
import { minimatch } from "minimatch";
import { z } from "zod";
import {
  DetectionResult,
  type DetectionResult as DetectionResultType,
  type Detector,
  type HuntArgs,
  type InvestigateArgs,
  buildDetectPrompt,
  buildHuntPrompt,
  buildInvestigatePrompt,
  hydrateFinding,
} from "../detect.js";
import { LlmValidation, asValidationField, buildValidatePrompt } from "../validator.js";

export type Effort = "low" | "medium" | "high" | "max";
export type Thinking = "off" | "adaptive" | "enabled";

/**
 * Parse the retry delay from a TPM rate-limit error message.
 * OpenAI embeds "Please try again in Xs" in the 429 body; we extract
 * that value so we can sleep exactly as long as the window needs.
 * Returns milliseconds, or null when the pattern isn't present.
 */
function parseRetryAfterMs(message: string): number | null {
  const match = message.match(/try again in ([\d.]+)s/i);
  if (!match) return null;
  return Math.ceil(parseFloat(match[1]) * 1000) + 200;
}

/**
 * Retry an LLM call on TPM rate-limit errors (HTTP 429 with a tokens-per-minute
 * body). The OpenAI error message includes the exact wait time; we parse and
 * sleep it rather than guessing. Non-TPM errors and non-429s fall through
 * immediately so the Vercel AI SDK's own retry logic can handle them.
 */
async function withTpmRetry<T>(fn: () => Promise<T>, maxAttempts = 4): Promise<T> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const isTpm = /tokens per min/i.test(msg) || /tpm/i.test(msg);
      if (!isTpm || attempt >= maxAttempts) throw err;
      const waitMs = parseRetryAfterMs(msg) ?? 60_000;
      await new Promise<void>((r) => setTimeout(r, waitMs));
    }
  }
  throw new Error("withTpmRetry: exhausted attempts");
}

type ProviderOptionsArg = {
  anthropic?: {
    thinking?: { type: "enabled" | "disabled"; budgetTokens?: number };
  };
  openai?: {
    reasoningEffort?: "low" | "medium" | "high";
  };
};

export interface VercelAgentDetectorOpts {
  providerKey?: "anthropic" | "openai" | "ollama";
  effort?: Effort;
  thinking?: Thinking;
  verbose?: boolean;
  /** Fallback model used only for final JSON extraction when the tool-call model
   *  returns malformed JSON. Useful for Ollama where structuredOutputs conflicts
   *  with tool calling but is needed to get reliable JSON output. */
  structuredModel?: LanguageModelV1;
}

// Directories skipped during recursive traversal
const SKIP_DIRS = new Set([
  "node_modules", "dist", "build", ".git", "vendor",
  "venv", ".venv", "__pycache__", ".next", ".nuxt",
]);

const GLOB_MAX_RESULTS = 500;
const GREP_MAX_MATCHES = 200;

/**
 * Detector backed by the Vercel AI SDK's `generateText` for hunt/walker
 * modes (with Read/Glob/Grep tool implementations) and `generateObject`
 * for file mode and validation. Works with any Vercel AI SDK provider —
 * OpenAI, Ollama, etc. — that supports function/tool calling.
 */
export class VercelAgentDetector implements Detector {
  readonly name: string;
  private readonly model: LanguageModelV1;
  private readonly structuredModel?: LanguageModelV1;
  private readonly providerKey?: "anthropic" | "openai" | "ollama";
  private readonly effort?: Effort;
  private readonly thinking?: Thinking;
  private readonly verbose: boolean;

  constructor(name: string, model: LanguageModelV1, opts: VercelAgentDetectorOpts = {}) {
    this.name = name;
    this.model = model;
    this.structuredModel = opts.structuredModel;
    this.providerKey = opts.providerKey ?? derivedProviderKey(name);
    this.effort = opts.effort;
    this.thinking = opts.thinking;
    this.verbose = opts.verbose ?? false;
  }

  async detectFile(args: { agent: Agent; filePath: string; content: string }): Promise<Finding[]> {
    const { agent, filePath, content } = args;
    try {
      const { object } = await withTpmRetry(() =>
        generateObject({
          model: this.model,
          schema: DetectionResult,
          mode: "json",
          prompt: buildDetectPrompt(agent, filePath, content),
          providerOptions: this.providerOptionsArg(),
        }),
      );
      // In file mode the caller provides the real path — ignore whatever
      // the model put in `filePath` (models often emit placeholders here).
      return object.findings.map((f) => hydrateFinding({ ...f, filePath: null }, agent, filePath));
    } catch (err) {
      debugLog("VercelAgentDetector.detectFile", err);
      throw err;
    }
  }

  async hunt(args: HuntArgs): Promise<Finding[]> {
    const { agent, rootDir, excludePatterns, includePatterns, maxFileSizeKb, maxTurns, diff } = args;
    const basePrompt = buildHuntPrompt(agent, { excludePatterns, includePatterns, maxFileSizeKb, diff });
    const prompt = `${basePrompt}\n\n${jsonOutputInstruction(false)}`;

    try {
      const { text } = await withTpmRetry(() =>
        generateText({
          model: this.model,
          prompt,
          tools: buildTools(resolve(rootDir), maxFileSizeKb, this.verbose),
          maxSteps: maxTurns + 1,
          providerOptions: this.providerOptionsArg(),
        }),
      );
      const result = await this.parseOrReformat(text, false);
      return result.findings.map((f) => hydrateFinding(f, agent, f.filePath ?? "(unknown)"));
    } catch (err) {
      debugLog("VercelAgentDetector.hunt", err);
      throw err;
    }
  }

  async investigate(args: InvestigateArgs): Promise<Finding[]> {
    const { agents, rootDir, candidates, maxTurns } = args;
    const basePrompt = buildInvestigatePrompt(agents, candidates);
    const multi = agents.length > 1;
    const prompt = `${basePrompt}\n\n${jsonOutputInstruction(multi)}`;

    try {
      const { text } = await withTpmRetry(() =>
        generateText({
          model: this.model,
          prompt,
          tools: buildTools(resolve(rootDir), undefined, this.verbose),
          maxSteps: maxTurns + 1,
          providerOptions: this.providerOptionsArg(),
        }),
      );

      const result = await this.parseOrReformat(text, multi);

      const agentsBySlug = new Map(agents.map((a) => [a.slug, a]));
      const fallbackFilePath = candidates[0]?.filePath ?? "(unknown)";
      const findings: Finding[] = [];
      for (const f of result.findings) {
        const owningAgent = (() => {
          if (agents.length === 1) return agents[0];
          if (f.agentSlug && agentsBySlug.has(f.agentSlug)) return agentsBySlug.get(f.agentSlug)!;
          return undefined;
        })();
        if (!owningAgent) continue;
        findings.push(hydrateFinding(f, owningAgent, f.filePath ?? fallbackFilePath));
      }
      return findings;
    } catch (err) {
      debugLog("VercelAgentDetector.investigate", err);
      throw err;
    }
  }

  async validateFinding(args: { finding: Finding; fileContent: string; scope?: string }) {
    try {
      const { object } = await withTpmRetry(() =>
        generateObject({
          model: this.model,
          schema: LlmValidation,
          mode: "json",
          prompt: buildValidatePrompt(args),
          providerOptions: this.providerOptionsArg(),
        }),
      );
      return asValidationField(object);
    } catch (err) {
      debugLog("VercelAgentDetector.validateFinding", err);
      throw err;
    }
  }

  /** Parse findings from the tool-loop's final text. If extraction fails and a
   *  structuredModel is configured, re-asks that model (with JSON mode) to
   *  reformat the raw analysis into the required schema. */
  private async parseOrReformat(text: string, multiAgent: boolean): Promise<DetectionResultType> {
    try {
      return DetectionResult.parse(extractJSON(text));
    } catch (extractErr) {
      if (!this.structuredModel) throw extractErr;
      const { object } = await generateObject({
        model: this.structuredModel,
        schema: DetectionResult,
        mode: "json",
        prompt: `The following is a completed security analysis. Extract all confirmed findings into structured JSON.\n\n${text}\n\n${jsonOutputInstruction(multiAgent)}`,
      });
      return object;
    }
  }

  private providerOptionsArg(): ProviderOptionsArg | undefined {
    if (!this.providerKey) return undefined;

    if (this.providerKey === "anthropic") {
      if (!this.thinking) return undefined;
      const type: "enabled" | "disabled" = this.thinking === "off" ? "disabled" : "enabled";
      return { anthropic: { thinking: { type } } };
    }

    if (this.providerKey === "openai") {
      if (!this.effort) return undefined;
      const reasoningEffort: "low" | "medium" | "high" =
        this.effort === "max" ? "high" : this.effort;
      return { openai: { reasoningEffort } };
    }

    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

function buildTools(cwd: string, maxFileSizeKb: number | undefined, verbose: boolean) {
  const logTool = verbose
    ? (name: string, arg: string) => console.log(`    ${name} ${arg.slice(0, 100)}`)
    : () => undefined;

  return {
    Read: tool({
      description: "Read the contents of a file. Path must be relative to the repository root.",
      parameters: z.object({
        path: z.string().describe("File path relative to the repository root"),
      }),
      execute: async ({ path }) => {
        logTool("Read", path);
        return readToolExecute(path, cwd, maxFileSizeKb);
      },
    }),
    Glob: tool({
      description:
        "Find files matching a glob pattern. Returns paths relative to the repository root.",
      parameters: z.object({
        pattern: z.string().describe("Glob pattern, e.g. '**/*.ts' or 'src/**/*.js'"),
      }),
      execute: async ({ pattern }) => {
        logTool("Glob", pattern);
        return globToolExecute(pattern, cwd);
      },
    }),
    Grep: tool({
      description:
        "Search for a regex pattern across files. Returns matching lines as 'file:line: content'.",
      parameters: z.object({
        pattern: z.string().describe("Regular expression to search for"),
        glob: z
          .string()
          .optional()
          .describe("Optional glob to restrict which files are searched, e.g. '**/*.ts'"),
      }),
      execute: async ({ pattern, glob }) => {
        logTool("Grep", pattern);
        return grepToolExecute(pattern, glob, cwd);
      },
    }),
  };
}

async function readToolExecute(
  path: string,
  cwd: string,
  maxFileSizeKb: number | undefined,
): Promise<string> {
  try {
    const absolutePath = resolve(cwd, path);
    if (!isSafe(absolutePath, cwd)) {
      return "Error: Access denied. Path must be within the repository root.";
    }
    if (maxFileSizeKb !== undefined) {
      const { stat } = await import("node:fs/promises");
      const s = await stat(absolutePath).catch(() => null);
      if (s && s.size > maxFileSizeKb * 1024) {
        return `Error: File exceeds size limit (${Math.round(s.size / 1024)}KB > ${maxFileSizeKb}KB). Skipped.`;
      }
    }
    return await readFile(absolutePath, "utf-8");
  } catch (err) {
    return `Error reading file: ${(err as Error).message}`;
  }
}

async function globToolExecute(pattern: string, cwd: string): Promise<string> {
  try {
    const results = await walkAndMatch(cwd, pattern, GLOB_MAX_RESULTS);
    if (results.length === 0) return "(no matches)";
    const out = results.join("\n");
    return results.length >= GLOB_MAX_RESULTS ? `${out}\n(truncated at ${GLOB_MAX_RESULTS} results)` : out;
  } catch (err) {
    return `Error: ${(err as Error).message}`;
  }
}

async function grepToolExecute(pattern: string, glob: string | undefined, cwd: string): Promise<string> {
  let regex: RegExp;
  try {
    regex = new RegExp(pattern);
  } catch {
    return `Error: Invalid regex pattern: ${pattern}`;
  }

  try {
    const files = await walkAndMatch(cwd, glob ?? "**/*", GLOB_MAX_RESULTS);
    const results: string[] = [];

    for (const file of files) {
      if (results.length >= GREP_MAX_MATCHES) break;
      try {
        const content = await readFile(join(cwd, file), "utf-8");
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (results.length >= GREP_MAX_MATCHES) break;
          if (regex.test(lines[i])) {
            results.push(`${file}:${i + 1}: ${lines[i].trimEnd()}`);
          }
        }
      } catch {
        // skip unreadable files
      }
    }

    if (results.length === 0) return "(no matches)";
    const out = results.join("\n");
    return results.length >= GREP_MAX_MATCHES
      ? `${out}\n(truncated at ${GREP_MAX_MATCHES} matches)`
      : out;
  } catch (err) {
    return `Error: ${(err as Error).message}`;
  }
}

async function walkAndMatch(rootDir: string, pattern: string, maxResults: number): Promise<string[]> {
  const results: string[] = [];

  async function walk(dir: string): Promise<void> {
    if (results.length >= maxResults) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (results.length >= maxResults) break;
      if (entry.name.startsWith(".") || SKIP_DIRS.has(entry.name)) continue;
      const fullPath = join(dir, entry.name);
      const relPath = normalizeSep(relative(rootDir, fullPath));
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else {
        const matchOpts = { dot: true, matchBase: !pattern.includes("/") };
        if (minimatch(relPath, pattern, matchOpts)) {
          results.push(relPath);
        }
      }
    }
  }

  await walk(rootDir);
  return results;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isSafe(absolutePath: string, cwd: string): boolean {
  const a = normalizeSep(absolutePath).toLowerCase();
  const b = normalizeSep(cwd).toLowerCase();
  return a.startsWith(b);
}

function normalizeSep(p: string): string {
  return p.replace(/\\/g, "/");
}

function derivedProviderKey(name: string): "anthropic" | "openai" | "ollama" | undefined {
  if (name.startsWith("anthropic")) return "anthropic";
  if (name.startsWith("openai")) return "openai";
  if (name.startsWith("ollama")) return "ollama";
  return undefined;
}

function jsonOutputInstruction(multiAgent: boolean): string {
  const agentSlugNote = multiAgent
    ? 'Set `agentSlug` to the slug of the detection brief whose criteria the finding satisfies.'
    : 'Set `agentSlug` to `null` — the runtime stamps the calling agent\'s slug.';
  return `## Output format

After your investigation, output ALL findings as a single JSON object matching EXACTLY this shape — no prose, no markdown fences, no trailing text:

{"findings":[{"title":"Short title","vulnSlug":"vuln-class","agentSlug":null,"lineRange":[1,10],"filePath":"src/routes/users.ts","summary":"One sentence.","details":"Markdown analysis with file paths and line numbers.","poc":"Reproduction steps.","impact":"Who is affected and what they get.","references":[],"confidence":0.9}]}

IMPORTANT: Every \`filePath\` must be a real file path you actually read or located with tools during this session. Do NOT copy the example path above — replace it with the actual path from your investigation. If no findings, output exactly: {"findings":[]}

${agentSlugNote}`;
}

function extractJSON(text: string): unknown {
  // 1. Fenced JSON block
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
  if (fenced) {
    try { return JSON.parse(fenced[1]); } catch { /* fall through */ }
  }
  // 2. Last valid JSON object starting from each '{' — go backwards for the final answer
  const positions: number[] = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "{") positions.push(i);
  }
  for (let i = positions.length - 1; i >= 0; i--) {
    try { return JSON.parse(text.slice(positions[i])); } catch { /* fall through */ }
  }
  // 3. Whole text
  try { return JSON.parse(text.trim()); } catch { /* fall through */ }

  throw new Error(
    `VercelAgentDetector: could not extract JSON findings from model response. ` +
      `First 400 chars: ${text.slice(0, 400)}`,
  );
}

async function debugLog(label: string, err: unknown): Promise<void> {
  if (!process.env.AGENTGG_DEBUG) return;
  const util = await import("node:util");
  console.error(`---- ${label} error ----`);
  console.error(util.inspect(err, { depth: 5, colors: false }));
  console.error("------------------------");
}
