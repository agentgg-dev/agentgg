/**
 * Shared helper for v0 stub commands. Every subcommand wires up its flags
 * via Commander, then calls `stub()` with the command name so the user
 * sees a consistent "not yet implemented" message and a clean exit.
 */
export function stub(name: string, opts?: Record<string, unknown>): void {
  console.log(`[${name}] not yet implemented`);
  if (opts && Object.keys(opts).length > 0) {
    console.log(`  parsed options: ${JSON.stringify(opts, null, 2)}`);
  }
  process.exit(0);
}
