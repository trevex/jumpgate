import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  // The suite runs against ONE shared, stateful kind cluster and mutates it
  // (users, folders, sessions). Running spec files in parallel contends on that
  // single backend — the WebSocket in-browser-terminal test in particular starves
  // under load and flakes its 30s wait. Serialize: correctness over wall-clock.
  workers: 1,
  use: {
    baseURL: process.env.UI_E2E_URL ?? "http://localhost:8080",
    launchOptions: {
      executablePath:
        process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined,
    },
  },
  reporter: "line",
});
