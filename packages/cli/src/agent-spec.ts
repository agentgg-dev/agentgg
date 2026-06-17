import { z } from "zod";

/**
 * The structured spec the LLM emits when `agentgg create` distills a past
 * vulnerability report into a new agent. A subset of the full `Agent`
 * shape from `@agentgg/core`, narrowed to what the model gets to choose:
 *
 *   - frontmatter metadata (slug, name, description, noiseTier, references)
 *   - the three agent components: precondition, where, prompt body
 *
 * Everything else (version, author, source) is stamped by the runtime
 * when the spec is rendered to `.md`.
 *
 * Renderer in `renderAgentSpecMd` writes the YAML frontmatter + body
 * exactly how `parseAgentMarkdown` expects to read it back, so a
 * generated agent round-trips cleanly through the loader.
 */

const SpecPreconditionPattern = z.object({
  regex: z.string().describe("Cheap content regex (no LLM, line-by-line filesystem check)."),
  in: z
    .array(z.string())
    .default([])
    .describe(
      "Glob(s) restricting which files the regex runs against. [] means any file in the repo.",
    ),
  notIn: z.array(z.string()).default([]).describe("Glob(s) the regex never runs against."),
  label: z.string().optional().describe("Short human label for what this pattern signals."),
});

const SpecPreconditionRegex = z.object({
  extensions: z
    .array(z.string())
    .default([])
    .describe(
      "Queue this agent if a file with one of these extensions exists. Bare ext, no leading dot (e.g. 'ts', 'php').",
    ),
  files: z
    .array(z.string())
    .default([])
    .describe(
      "Queue if a sentinel file matching one of these globs exists (e.g. 'Dockerfile', 'package.json', 'routes/web.php').",
    ),
  directories: z
    .array(z.string())
    .default([])
    .describe("Queue if a directory matching one of these globs exists."),
  patterns: z
    .array(SpecPreconditionPattern)
    .default([])
    .describe("Queue if a content pattern matches in a file in scope."),
});

const SpecPrecondition = z.object({
  regex: SpecPreconditionRegex.optional().describe(
    "Cheap static existence check. Sub-checks are OR'd together. Prefer this over prompt: it costs no LLM call.",
  ),
  prompt: z
    .string()
    .optional()
    .describe(
      "Optional LLM gate that sees the recon brief. Only use when a regex can not express relevance.",
    ),
});

const SpecPreFilter = z.object({
  regex: z.string().describe("Regex that anchors lines worth investigating."),
  label: z.string().optional().describe("Short human label shown to the model alongside hits."),
});

const SpecWhere = z.object({
  extensions: z
    .array(z.string())
    .default([])
    .describe(
      "Primary file-type scope. Bare extensions, no leading dot (e.g. ['ts', 'tsx', 'js']).",
    ),
  filePatterns: z
    .array(z.string())
    .default([])
    .describe(
      "Optional include globs / directories. OR'd with extensions. Use when extensions can not express the scope (e.g. 'src/api/**' or 'config/*.yaml').",
    ),
  excludePatterns: z
    .array(z.string())
    .default([])
    .describe(
      "Globs the agent never touches. Additive on top of the default excludes (node_modules, dist, tests). Add tests/fixtures here unless the bug class genuinely lives in them.",
    ),
  preFilter: z
    .array(SpecPreFilter)
    .default([])
    .describe(
      "Regexes that narrow matching files to candidates by line: a file becomes a candidate when at least one regex matches at least one line. Hit lines are passed to the LLM as anchors. Empty = every matching file is a candidate (more expensive).",
    ),
  maxFilesPerBatch: z
    .number()
    .int()
    .min(1)
    .default(5)
    .describe("How many candidate files per investigation session. Default 5."),
  maxTurnsPerBatch: z
    .number()
    .int()
    .min(1)
    .default(30)
    .describe("Tool-use turn budget per investigation session. Default 30."),
});

export const AgentSpec = z.object({
  slug: z
    .string()
    .regex(/^[a-z0-9][a-z0-9-]*$/)
    .describe(
      "Stable kebab-case identifier (no spaces, no underscores). Should evoke the bug class, e.g. 'unsafe-jwt-verify' or 'tenant-id-leak'.",
    ),
  name: z.string().describe("Short human-readable name."),
  description: z
    .string()
    .describe(
      "One-line summary shown in `agentgg agents list`. Describe the anti-pattern, not the specific past bug.",
    ),
  noiseTier: z
    .enum(["precise", "normal", "noisy"])
    .default("normal")
    .describe(
      "How many false positives to expect. 'precise' = high confidence, 'normal' = some, 'noisy' = many.",
    ),
  references: z
    .array(z.string())
    .default([])
    .describe(
      "CWE / OWASP / CVE / GHSA IDs or URLs from the source report. Documentation only, not injected into prompts.",
    ),
  precondition: SpecPrecondition.optional().describe(
    "Cheap queue/skip gate. Omit entirely = always run.",
  ),
  where: SpecWhere.describe(
    "File scope fed into the agent as starting points. Required (even if just extensions).",
  ),
  prompt: z
    .string()
    .describe(
      "Markdown body of the agent: the harness + detection instructions. Should explain the anti-pattern, list true-positive criteria, list false-positive exclusions, and include at least one concrete code example from the past incident so the model has a grounded reference.",
    ),
});
export type AgentSpec = z.infer<typeof AgentSpec>;

/**
 * Render an AgentSpec to the agent `.md` shape that
 * `parseAgentMarkdown` reads back. YAML frontmatter is emitted by hand
 * (rather than via a YAML lib) so the layout matches the hand-written
 * agents in the official catalog. Optional fields with empty values are
 * omitted to keep the file small.
 */
export function renderAgentSpecMd(spec: AgentSpec): string {
  const fm: string[] = [];
  fm.push(`slug: ${spec.slug}`);
  fm.push(`name: ${quoteYamlScalar(spec.name)}`);
  fm.push(`description: ${quoteYamlScalar(spec.description)}`);
  fm.push(`version: 0.1.0`);
  fm.push(`noiseTier: ${spec.noiseTier}`);
  if (spec.references.length > 0) {
    fm.push("references:");
    for (const r of spec.references) fm.push(`  - ${quoteYamlScalar(r)}`);
  }
  if (spec.precondition) {
    const pre = renderPrecondition(spec.precondition);
    if (pre) fm.push(pre);
  }
  const where = renderWhere(spec.where);
  if (where) fm.push(where);

  const body = spec.prompt.trim();
  return `---\n${fm.join("\n")}\n---\n\n${body}\n`;
}

function renderPrecondition(p: AgentSpec["precondition"]): string | null {
  if (!p) return null;
  const lines: string[] = ["precondition:"];
  if (p.regex) {
    const inner = renderPreconditionRegex(p.regex);
    if (inner) {
      lines.push("  regex:");
      lines.push(inner);
    }
  }
  if (p.prompt?.trim()) {
    lines.push(`  prompt: ${quoteYamlScalar(p.prompt.trim())}`);
  }
  return lines.length > 1 ? lines.join("\n") : null;
}

function renderPreconditionRegex(
  r: NonNullable<AgentSpec["precondition"]>["regex"],
): string | null {
  if (!r) return null;
  const out: string[] = [];
  if (r.extensions.length > 0) {
    out.push("    extensions:");
    for (const e of r.extensions) out.push(`      - ${quoteYamlScalar(e)}`);
  }
  if (r.files.length > 0) {
    out.push("    files:");
    for (const f of r.files) out.push(`      - ${quoteYamlScalar(f)}`);
  }
  if (r.directories.length > 0) {
    out.push("    directories:");
    for (const d of r.directories) out.push(`      - ${quoteYamlScalar(d)}`);
  }
  if (r.patterns.length > 0) {
    out.push("    patterns:");
    for (const p of r.patterns) {
      out.push(`      - regex: ${quoteYamlScalar(p.regex)}`);
      if (p.label) out.push(`        label: ${quoteYamlScalar(p.label)}`);
      if (p.in.length > 0) {
        out.push("        in:");
        for (const g of p.in) out.push(`          - ${quoteYamlScalar(g)}`);
      }
      if (p.notIn.length > 0) {
        out.push("        notIn:");
        for (const g of p.notIn) out.push(`          - ${quoteYamlScalar(g)}`);
      }
    }
  }
  return out.length > 0 ? out.join("\n") : null;
}

function renderWhere(w: AgentSpec["where"]): string | null {
  const lines: string[] = ["where:"];
  if (w.extensions.length > 0) {
    lines.push("  extensions:");
    for (const e of w.extensions) lines.push(`    - ${quoteYamlScalar(e)}`);
  }
  if (w.filePatterns.length > 0) {
    lines.push("  filePatterns:");
    for (const p of w.filePatterns) lines.push(`    - ${quoteYamlScalar(p)}`);
  }
  if (w.excludePatterns.length > 0) {
    lines.push("  excludePatterns:");
    for (const p of w.excludePatterns) lines.push(`    - ${quoteYamlScalar(p)}`);
  }
  if (w.preFilter.length > 0) {
    lines.push("  preFilter:");
    for (const pf of w.preFilter) {
      lines.push(`    - regex: ${quoteYamlScalar(pf.regex)}`);
      if (pf.label) lines.push(`      label: ${quoteYamlScalar(pf.label)}`);
    }
  }
  if (w.maxFilesPerBatch !== 5) lines.push(`  maxFilesPerBatch: ${w.maxFilesPerBatch}`);
  if (w.maxTurnsPerBatch !== 30) lines.push(`  maxTurnsPerBatch: ${w.maxTurnsPerBatch}`);
  return lines.length > 1 ? lines.join("\n") : null;
}

/**
 * Always emit YAML scalars as double-quoted strings. Safer than trying
 * to guess when a string needs quoting (regexes, globs, colons, special
 * chars all need it). YAML's double-quoted form supports `\\`, `\"`, `\n`,
 * `\t`, `\r`; the renderer never emits literal newlines inside a scalar
 * because the LLM is constrained to single-line metadata fields.
 */
function quoteYamlScalar(s: string): string {
  const escaped = s
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t");
  return `"${escaped}"`;
}
