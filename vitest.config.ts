import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/**/__tests__/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    environment: "node",
    // 5s default is too tight on slower CI runners: the first test in a
    // file that triggers the official agent catalog auto-install pays a
    // multi-second cold-start cost, even though the test itself does
    // very little. Real hangs still fail at 30s.
    testTimeout: 30_000,
  },
});
