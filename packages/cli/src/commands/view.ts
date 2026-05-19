import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { readScanMeta } from "@agentgg/core";
import type { Command } from "commander";
import { DEFAULT_VIEWER_PORT, openBrowser, startViewer } from "../viewer-server.js";

interface ViewOpts {
  /** Run `next dev` instead of `next start`. Useful while iterating on the viewer itself. */
  dev?: boolean;
  /** Forward viewer process output to stdout. Default false. */
  verbose?: boolean;
}

/**
 * Boot the viewer against an existing `--output` directory and print
 * a clickable link. The viewer runs in the foreground; Ctrl+C tears it
 * down cleanly. Port is an optional second positional — `agentgg view
 * ./out 8080`. Omitted = default 3737 (auto-incrementing if busy).
 */
export async function runView(
  outputArg: string,
  portArg: string | undefined,
  opts: ViewOpts,
): Promise<void> {
  const outputDir = resolve(outputArg);
  if (!existsSync(outputDir)) {
    throw new Error(`Output directory does not exist: ${outputDir}`);
  }
  const scanMeta = readScanMeta(outputDir);
  if (!scanMeta) {
    process.stdout.write(
      `Warning: no state/scan.json in ${outputDir} — the viewer will load but the dashboard will be empty.\n` +
        `         Run \`agentgg scan <path> -o ${outputArg}\` first to populate it.\n`,
    );
  }

  const port = parsePort(portArg);

  process.stdout.write(`Starting viewer for ${outputDir}…\n`);
  const handle = await startViewer({
    outputDir,
    port,
    dev: opts.dev,
    verbose: opts.verbose,
  });

  printReady(handle.url, outputDir);
  openBrowser(handle.url);

  // Keep alive until Ctrl+C.
  await new Promise<void>((res) => {
    const shutdown = async () => {
      process.stdout.write("\nStopping viewer…\n");
      await handle.stop();
      res();
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
    handle.child.once("exit", () => res());
  });
}

export function printReady(url: string, outputDir: string): void {
  // Tools like Windows Terminal, iTerm2, and VS Code render an OSC 8
  // hyperlink, falling back to the URL when they don't. The raw URL
  // alone is also detected as a click target by most modern terminals.
  process.stdout.write("\n");
  process.stdout.write(`  ▸ Viewer ready at ${hyperlink(url)}\n`);
  process.stdout.write(`    Showing results from: ${outputDir}\n`);
  process.stdout.write(`    Press Ctrl+C to stop.\n\n`);
}

function hyperlink(url: string): string {
  // OSC 8 hyperlink format: ESC ] 8 ; ; URL BEL TEXT ESC ] 8 ; ; BEL
  // Terminals that don't understand it strip the markers and show the URL.
  const ESC = "\x1b";
  const BEL = "\x07";
  return `${ESC}]8;;${url}${BEL}${url}${ESC}]8;;${BEL}`;
}

function parsePort(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = parseInt(value, 10);
  if (!Number.isFinite(n) || n < 1 || n > 65535) {
    throw new Error(`invalid port "${value}" (expected an integer between 1 and 65535)`);
  }
  return n;
}

export function registerViewCommand(program: Command): void {
  program
    .command("view")
    .description("boot a local web UI to browse findings in a scan's --output directory")
    .argument(
      "[output-dir]",
      "path to the scan's --output directory (defaults to ./scan-results)",
      "./scan-results",
    )
    .argument(
      "[port]",
      `port to serve on (default ${DEFAULT_VIEWER_PORT}; auto-increments if busy)`,
    )
    .option(
      "--dev",
      "run Next.js in development mode (slower start, hot reload) — only useful when hacking on the viewer",
    )
    .option("-v, --verbose", "forward the Next.js server output to stdout")
    .action(async (outputDir: string, port: string | undefined, opts: ViewOpts) => {
      try {
        await runView(outputDir, port, opts);
      } catch (err) {
        console.error(`view failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    });
}
