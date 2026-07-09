import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadAllFileRecords, loadUserConfig, readFileRecord, type UserConfig } from "@agentgg/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runScan } from "../src/commands/scan.js";

/**
 * Real-LLM smoke tests. Unlike the rest of the suite, these make ACTUAL model
 * calls — they exist to catch flag→provider wiring regressions that a mocked
 * detector can't (e.g. a flag that stops reaching one provider's detector).
 *
 * They do NOT run automatically:
 *   - the default `vitest run` only globs *.test.ts, so this *.smoke.ts file
 *     is invisible to `pnpm test`.
 *   - they run only via `pnpm test:smoke` (vitest.smoke.config.ts).
 *   - each provider block self-gates on its credentials, so only the providers
 *     you have configured actually make calls.
 *
 * Approach: ONE tiny agent over a 2-file fixture (one blatant SQL-injection
 * file + one benign file), on the cheapest model per provider. Each flag's
 * observable effect is asserted. Where a flag has a structural effect (the
 * caps, --exclude, --diff scoping) the assertion is deterministic — every
 * analyzed candidate file gets a FileRecord stamped even with zero findings
 * (see scan.ts "Stamp an empty record …"), so record counts are exact. Where
 * the effect is model-dependent (--validate verdict, --score CVSS) we assert
 * the field is populated, not its value.
 *
 * Credentials come from your saved `agentgg init` config (~/.agentgg/config.json,
 * or $AGENTGG_HOME): a provider runs if it has a block there. So `agentgg init
 * --provider openai` (etc.) is all the setup you need — configure several and
 * the suite covers each. Env vars override / add a provider without a saved
 * block (handy for CI or ambient cloud creds):
 *   ANTHROPIC_API_KEY                             → anthropic
 *   OPENAI_API_KEY                                → openai
 *   AGENTGG_SMOKE_OLLAMA_URL                       → ollama (e.g. http://localhost:11434)
 *   AGENTGG_SMOKE_BEDROCK=1 + AWS_REGION           → bedrock (creds via AWS chain)
 *   AGENTGG_SMOKE_VERTEX=1 + GOOGLE_CLOUD_PROJECT  → vertex (creds via ADC)
 * The model is always a cheap default (NOT your config's model, which may be
 * pricey); override per provider with AGENTGG_SMOKE_<NAME>_MODEL.
 */

type ScanOpts = Parameters<typeof runScan>[1];

interface ProviderCase {
  name: string;
  enabled: boolean;
  model: string;
  /** Provider selection + credential overlay merged into every runScan call. */
  opts: Partial<ScanOpts>;
}

/** The saved config drives which providers run. Read defensively so a
 *  malformed file falls back to env-var gating instead of breaking the suite. */
function loadConfig(): UserConfig | null {
  try {
    return loadUserConfig(process.env);
  } catch {
    return null;
  }
}

// A provider runs if it has a config block OR an env override is set. Explicit
// credential opts are passed ONLY when they come from env (an override);
// otherwise they're omitted so buildDetector reads them from the config block.
// The model is always the cheap default (or its AGENTGG_SMOKE_* override), never
// the config's saved model.
function providerCases(): ProviderCase[] {
  const cfg = loadConfig();
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  const openaiKey = process.env.OPENAI_API_KEY;
  const ollamaUrl = process.env.AGENTGG_SMOKE_OLLAMA_URL;
  const awsRegion = process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION;
  const gcpProject = process.env.GOOGLE_CLOUD_PROJECT ?? process.env.GCLOUD_PROJECT;
  const model = (envKey: string, fallback: string) => process.env[envKey] ?? fallback;

  return [
    {
      name: "anthropic",
      enabled: Boolean(cfg?.anthropic?.apiKey || cfg?.anthropic?.oauthToken || anthropicKey),
      model: model("AGENTGG_SMOKE_ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
      opts: { provider: "anthropic", ...(anthropicKey ? { apiKey: anthropicKey } : {}) },
    },
    {
      name: "openai",
      enabled: Boolean(cfg?.openai?.apiKey || openaiKey),
      model: model("AGENTGG_SMOKE_OPENAI_MODEL", "gpt-4o"),
      opts: { provider: "openai", ...(openaiKey ? { apiKey: openaiKey } : {}) },
    },
    {
      name: "ollama",
      enabled: Boolean(cfg?.ollama?.baseUrl || ollamaUrl),
      model: model("AGENTGG_SMOKE_OLLAMA_MODEL", "qwen2.5"),
      opts: { provider: "ollama", ...(ollamaUrl ? { baseUrl: ollamaUrl } : {}) },
    },
    {
      // Cloud billing: a saved `bedrock` block is deliberate opt-in; without
      // one, require the explicit env flag so a stray AWS_REGION can't spend.
      name: "bedrock",
      enabled: Boolean(cfg?.bedrock || (process.env.AGENTGG_SMOKE_BEDROCK && awsRegion)),
      // Current Claude on Bedrock: reliably emits schema-clean JSON (so the
      // detection/validate paths never fall back to the json-mode reformat this
      // Bedrock SDK version rejects). Access is account/region-specific —
      // override with AGENTGG_SMOKE_BEDROCK_MODEL (e.g. your configured model).
      model: model("AGENTGG_SMOKE_BEDROCK_MODEL", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
      opts: { provider: "bedrock", ...(!cfg?.bedrock && awsRegion ? { region: awsRegion } : {}) },
    },
    {
      name: "vertex",
      enabled: Boolean(cfg?.vertex || (process.env.AGENTGG_SMOKE_VERTEX && gcpProject)),
      model: model("AGENTGG_SMOKE_VERTEX_MODEL", "zai-org/glm-5-maas"),
      opts: { provider: "vertex", ...(!cfg?.vertex && gcpProject ? { project: gcpProject } : {}) },
    },
  ];
}

const AGENT_SLUG = "smoke-sqli";

// A blatant SQL injection so even a cheap/small model reliably flags it.
const VULN_FILE = `const express = require("express");
const db = require("./db");
const app = express();

app.get("/user", (req, res) => {
  // SQL injection: request input concatenated straight into the query text.
  const q = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(q, (err, rows) => res.json(rows));
});

module.exports = app;
`;

const SAFE_FILE = `// Benign helper — no request input reaches a sink.
module.exports = { add: (a, b) => a + b };
`;

const AGENT_MD = `---
slug: ${AGENT_SLUG}
name: SQL Injection (smoke)
description: Flags SQL queries built from untrusted request input.
where:
  extensions:
    - js
---
Find SQL injection. Report any place a SQL query string is built by
concatenating or interpolating request-derived input (req.query, req.params,
req.body) directly into the query text. Report each as a finding with the file
path and line.
`;

let projectRoot: string;
let agentsDir: string;
let agentPath: string;
let diffSha: string;
const outDirs: string[] = [];

// Real environment (real AGENTGG_HOME) so runScan loads the saved config and
// resolves credentials from it. Providers are enumerated once at load time.
const env: NodeJS.ProcessEnv = { ...process.env };
const CASES = providerCases();

function git(args: string[], opts: { capture?: boolean } = {}): string {
  return execFileSync(
    "git",
    [
      "-c",
      "user.email=smoke@agentgg.test",
      "-c",
      "user.name=smoke",
      "-c",
      "commit.gpgsign=false",
      ...args,
    ],
    {
      cwd: projectRoot,
      encoding: "utf8",
      stdio: opts.capture ? "pipe" : ["ignore", "ignore", "pipe"],
    },
  );
}

beforeAll(() => {
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-smoke-proj-"));
  agentsDir = mkdtempSync(join(tmpdir(), "agentgg-smoke-agents-"));
  agentPath = join(agentsDir, `${AGENT_SLUG}.md`);
  writeFileSync(agentPath, AGENT_MD, "utf8");
  writeFileSync(join(projectRoot, "app.js"), VULN_FILE, "utf8");
  writeFileSync(join(projectRoot, "safe.js"), SAFE_FILE, "utf8");

  // Real git fixture so --diff exercises the actual git plumbing. First commit
  // holds both files; a second commit touches ONLY app.js, so `--diff <sha>`
  // scopes to app.js alone.
  git(["init", "-q"]);
  git(["add", "-A"]);
  git(["commit", "-q", "-m", "init"]);
  writeFileSync(join(projectRoot, "app.js"), `${VULN_FILE}// touch\n`, "utf8");
  git(["add", "app.js"]);
  git(["commit", "-q", "-m", "touch app"]);
  diffSha = git(["rev-parse", "HEAD"], { capture: true }).trim();
});

afterAll(() => {
  for (const dir of [projectRoot, agentsDir, ...outDirs]) {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Run one real scan on a fresh output dir (fresh dir = no resume reuse, so the
 *  model is actually called). Cheap + deterministic defaults; tests override. */
async function runSmoke(pc: ProviderCase, extra: Partial<ScanOpts> = {}): Promise<string> {
  const output = mkdtempSync(join(tmpdir(), "agentgg-smoke-out-"));
  outDirs.push(output);
  const opts: ScanOpts = {
    template: [agentPath],
    output,
    model: pc.model,
    // Skip recon + precondition gating (fewer calls; the agent always runs)
    // and the report/dedup passes we don't assert on. Individual tests turn
    // validate / score back on. NOTE: no blanket `effort` here — it maps to
    // OpenAI's `reasoning_effort`, which non-reasoning models (gpt-4o-mini)
    // reject with a 400; the effort test opts in per provider instead.
    recon: false,
    score: false,
    dedup: false,
    summary: false,
    autoExclude: false,
    ...pc.opts,
    ...extra,
  };
  await runScan(projectRoot, opts, env);
  return output;
}

// One always-on test: confirms the fixture built and prints which providers
// are live, so `pnpm test:smoke` with no credentials is an informative no-op
// rather than an empty run.
it("fixture is ready; reports which providers are enabled", () => {
  const enabled = CASES.filter((p) => p.enabled).map((p) => `${p.name} (${p.model})`);
  console.log(`[smoke] enabled providers: ${enabled.join(", ") || "(none — set credentials)"}`);
  expect(diffSha).toMatch(/^[0-9a-f]{7,40}$/);
});

for (const pc of CASES) {
  describe.runIf(pc.enabled)(`smoke: ${pc.name}`, () => {
    it("detects the SQL injection and writes a FileRecord", async () => {
      const out = await runSmoke(pc);
      const rec = readFileRecord(out, AGENT_SLUG, "app.js");
      expect(rec).not.toBeNull();
      // The only model-dependent assertion — a blatant concat SQLi. A miss here
      // means the chosen model is too weak; bump AGENTGG_SMOKE_<NAME>_MODEL.
      expect(rec?.findings.length ?? 0).toBeGreaterThan(0);
    });

    it("--exclude drops the excluded file from the scan", async () => {
      const out = await runSmoke(pc, { exclude: ["safe.js"] });
      expect(readFileRecord(out, AGENT_SLUG, "safe.js")).toBeNull();
      expect(readFileRecord(out, AGENT_SLUG, "app.js")).not.toBeNull();
    });

    it("--max-files-per-agent caps candidates (2 files → 1)", async () => {
      const out = await runSmoke(pc, { maxFilesPerAgent: 1, maxFilesPerBatch: 1 });
      expect(loadAllFileRecords(out).length).toBe(1);
    });

    it("--max-batches caps total batches (2 batches → 1)", async () => {
      const out = await runSmoke(pc, { maxFilesPerBatch: 1, maxBatches: 1 });
      expect(loadAllFileRecords(out).length).toBe(1);
    });

    it("--diff scopes the scan to the changed file", async () => {
      const out = await runSmoke(pc, { diff: diffSha });
      expect(readFileRecord(out, AGENT_SLUG, "app.js")).not.toBeNull();
      expect(readFileRecord(out, AGENT_SLUG, "safe.js")).toBeNull();
    });

    it("--validate attaches a verdict to findings", async () => {
      const out = await runSmoke(pc, { validate: true });
      const findings = loadAllFileRecords(out).flatMap((r) => r.findings);
      expect(findings.length).toBeGreaterThan(0);
      for (const f of findings) {
        expect(f.validation?.verdict).toBeDefined();
      }
    });

    it("--score attaches a CVSS base score to findings", async () => {
      const out = await runSmoke(pc, { score: true });
      const findings = loadAllFileRecords(out).flatMap((r) => r.findings);
      expect(findings.length).toBeGreaterThan(0);
      for (const f of findings) {
        expect(f.cvss?.baseScore).toBeTypeOf("number");
      }
    });

    it("--effort/--thinking are accepted and the scan completes", async () => {
      // Pass each knob only where the provider maps it, so this stays a
      // "flag doesn't break the scan" smoke rather than a provider 400.
      // `thinking` is Anthropic-only (a no-op elsewhere, never sent). `effort`
      // is safe on Anthropic; on OpenAI it becomes `reasoning_effort`, which
      // ONLY reasoning models accept — so it's opt-in there via a reasoning
      // AGENTGG_SMOKE_OPENAI_MODEL, not forced on the cheap default.
      const extra: Partial<ScanOpts> =
        pc.name === "anthropic" ? { effort: "low", thinking: "off" } : { thinking: "off" };
      const out = await runSmoke(pc, extra);
      expect(readFileRecord(out, AGENT_SLUG, "app.js")).not.toBeNull();
    });
  });
}
