import matter from "gray-matter";

/**
 * gray-matter's documented `engines` map, which its bundled types omit.
 * Reaching it here avoids a second YAML dependency for one parse.
 */
const yamlEngine = (matter as unknown as { engines: { yaml: { parse(s: string): unknown } } })
  .engines.yaml;

/**
 * Rule-file inspection. The bundled engine is Semgrep CE, which accepts a
 * rule file it cannot actually run: `mode: join` loads, reports no error,
 * scans zero files and returns zero hits. A scan that trusts that reads as
 * "clean" when it had no coverage at all, so every rule is inspected before
 * it runs and an unrunnable one degrades the agent instead.
 */

/** Modes the bundled CE engine runs. Anything else is refused up front. */
const SUPPORTED_MODES: ReadonlySet<string> = new Set(["search", "taint", "extract"]);

/**
 * Supply-chain key. Same silent-failure shape as join mode: the rule loads,
 * `skipped_rules` stays empty, and nothing is scanned.
 */
const SCA_KEY = "r2c-internal-project-depends-on";

export interface RuleInspection {
  /** Non-null when the bundled engine cannot run this file. Names the cause. */
  unsupported: string | null;
  /** Declared languages, or null when the file did not parse. */
  langs: Set<string> | null;
  /** Rules that declare their own `paths:`, which narrows agentgg's file set. */
  pathScoped: string[];
  /** Parsed rules, for the merged rule file. Null when the file did not parse. */
  rules: Array<Record<string, unknown>> | null;
}

/** Rule-file spellings that mean the same language as a `-lang` value. */
const LANG_ALIASES: Readonly<Record<string, string>> = {
  typescript: "ts",
  javascript: "js",
  py: "python",
  python2: "python",
  python3: "python",
  rb: "ruby",
  golang: "go",
  kt: "kotlin",
  "c#": "csharp",
  "c++": "cpp",
  sh: "bash",
  sol: "solidity",
  tf: "terraform",
  ex: "elixir",
};

export function normalizeLang(name: string): string {
  const lower = name.trim().toLowerCase();
  return LANG_ALIASES[lower] ?? lower;
}

/**
 * Parse and vet one rule file.
 *
 * `gray-matter` is already a dependency and exposes its YAML engine, so this
 * is a real parse rather than a text scan. A file that will not parse returns
 * `rules: null`; the caller then reports it rather than running it blind.
 */
export function inspectSemgrepRule(source: string): RuleInspection {
  let doc: unknown;
  try {
    doc = yamlEngine.parse(source);
  } catch {
    return { unsupported: null, langs: null, pathScoped: [], rules: null };
  }
  const rawRules = (doc as { rules?: unknown })?.rules;
  if (!Array.isArray(rawRules)) {
    return { unsupported: null, langs: null, pathScoped: [], rules: null };
  }

  const rules = rawRules.filter(
    (r): r is Record<string, unknown> => typeof r === "object" && r !== null,
  );
  const langs = new Set<string>();
  const pathScoped: string[] = [];
  for (const rule of rules) {
    const id = typeof rule.id === "string" ? rule.id : "(unnamed)";
    if (SCA_KEY in rule) {
      return {
        unsupported: `${id}: ${SCA_KEY} needs Semgrep's supply-chain engine`,
        langs: null,
        pathScoped,
        rules,
      };
    }
    const mode = typeof rule.mode === "string" ? rule.mode : "search";
    if (!SUPPORTED_MODES.has(mode)) {
      return {
        unsupported: `${id}: mode '${mode}' is not available in the bundled engine`,
        langs: null,
        pathScoped,
        rules,
      };
    }
    if (rule.paths !== undefined) pathScoped.push(id);
    const declared = rule.languages;
    if (Array.isArray(declared)) {
      for (const l of declared) {
        if (typeof l === "string" && l.trim()) langs.add(normalizeLang(l));
      }
    }
  }
  return { unsupported: null, langs: langs.size > 0 ? langs : null, pathScoped, rules };
}
