import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    setupFiles: ["./test/setupEnv.ts"],
    testTimeout: 15000,
    hookTimeout: 15000,
    // Tests share one Postgres instance and the audit log is a single global
    // hash chain, so concurrent test files would race and produce flaky
    // failures — run them one at a time instead.
    fileParallelism: false,
  },
});
