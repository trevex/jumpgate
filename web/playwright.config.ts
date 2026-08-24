import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  // Serialize: the suite runs against ONE small kind cluster with a single
  // ssh-proxy + gateway pod. Several specs open live SSH sessions (in-browser
  // terminal, CLI connect); run concurrently, their browser↔gateway↔ssh-proxy
  // pipes contend and a session's connection gets dropped mid-test — the
  // in-browser-terminal test (30s echo budget) then flakes on a "Disconnected".
  // Root-caused as connection-layer contention on the shared test cluster (NOT the
  // live-session-revocation sweeper — no teardown in warden logs — and NOT a warden
  // scaling limit). Serial removes the concurrency; thanks to jit=off the whole
  // suite still runs in ~25s, so this costs no meaningful wall-clock.
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
