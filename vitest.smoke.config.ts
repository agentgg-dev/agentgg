import { defineConfig } from "vitest/config";

// Config for the real-LLM smoke suite (packages/**/__tests__/**/*.smoke.ts).
// These tests make ACTUAL model calls, so they are deliberately NOT part of
// the default `vitest run` (vitest.config.ts globs *.test.ts only). Run them
// explicitly with `pnpm test:smoke`. Each provider block self-gates on its
// credentials, so the suite only exercises the providers you have set up.
export default defineConfig({
  test: {
    include: ["packages/**/__tests__/**/*.smoke.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    environment: "node",
    // Real model calls (agent run, plus validate / score passes) are slow.
    testTimeout: 180_000,
    hookTimeout: 60_000,
    // One scan at a time: keeps provider rate limits and cost predictable and
    // the shared git fixture free of cross-test interference.
    fileParallelism: false,
    sequence: { concurrent: false },
  },
});
