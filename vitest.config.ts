import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/**/__tests__/**/*.test.ts"],
    // Docker- and network-gated e2e tests (live-validation.integration.test.ts):
    // require a running toy app + Docker, so they're excluded here. Run them
    // via `pnpm test:integration` (vitest.integration.config.ts) instead.
    exclude: ["**/node_modules/**", "**/dist/**", "**/*.integration.test.ts"],
    environment: "node",
    // 5s default is too tight on slower CI runners: the first test in a
    // file that triggers the official agent catalog auto-install pays a
    // multi-second cold-start cost, even though the test itself does
    // very little. Real hangs still fail at 30s.
    testTimeout: 30_000,
  },
});
