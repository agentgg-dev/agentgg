import { defineConfig } from "vitest/config";

// Config for Docker/network-gated integration tests (packages/**/__tests__/**/*.integration.test.ts).
// The default `vitest.config.ts` excludes this pattern so `pnpm test` never
// collects them. Run them explicitly with `pnpm test:integration`. Each file
// self-gates (describe.runIf on an env var, describe.skipIf on a flag, a
// dockerAvailable() check, etc.), so running this config with no special
// environment set just reports them collected-and-skipped, not executed.
export default defineConfig({
  test: {
    include: ["packages/**/__tests__/**/*.integration.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    environment: "node",
    // These drive real Docker containers / external downloads; give them room.
    testTimeout: 300_000,
  },
});
