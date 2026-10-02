import { Command } from "commander";
import { describe, expect, it } from "vitest";
import { registerDedupCommand } from "../src/commands/dedup.js";
import { registerFixCommand } from "../src/commands/fix.js";
import { registerLiveValidateCommand } from "../src/commands/live-validate.js";
import { registerReconCommand } from "../src/commands/recon.js";
import { registerRevalidateCommand } from "../src/commands/revalidate.js";
import { registerScoreCommand } from "../src/commands/score.js";

const PROVIDER_OPTIONS = [
  "--provider",
  "--model",
  "--api-key",
  "--oauth-token",
  "--base-url",
  "--project",
  "--region",
  "--openrouter-routing",
];

const COMMANDS = ["score", "live-validate", "revalidate", "recon", "dedup", "fix"];

describe("provider options", () => {
  // A caller hands one provider argument list to any of these commands, and
  // commander exits on an option a command did not register.
  it("score, live-validate, revalidate, recon, dedup and fix all register the same eight provider options", () => {
    const program = new Command();
    registerScoreCommand(program);
    registerLiveValidateCommand(program);
    registerRevalidateCommand(program);
    registerReconCommand(program);
    registerDedupCommand(program);
    registerFixCommand(program);

    const missing: Record<string, string[]> = {};
    for (const name of COMMANDS) {
      const command = program.commands.find((c) => c.name() === name);
      // Only options that take a value: a bare flag would not consume its argument.
      const registered = new Set(command?.options.filter((o) => o.required).map((o) => o.long));
      missing[name] = PROVIDER_OPTIONS.filter((flag) => !registered.has(flag));
    }

    expect(missing).toEqual({
      score: [],
      "live-validate": [],
      revalidate: [],
      recon: [],
      dedup: [],
      fix: [],
    });
  });
});
