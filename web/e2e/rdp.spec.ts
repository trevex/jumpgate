import { test, expect } from "@playwright/test";
import { login } from "./helpers";

// The gateway serves the RDP WSS on its external TLS listener with a self-signed
// (mesh-CA) cert, so the browser must accept it — same as the terminal e2e.
test.use({ ignoreHTTPSErrors: true });

// alice has a concrete `rdp:login:demo` standing binding on rdp-box (via the
// seeded sre group + rdp-demo role — see test/e2e/uiseed_test.go), so her asset
// detail surfaces the "Open RDP" affordance.
const ALICE_EMAIL = process.env.E2E_ALICE_EMAIL ?? "alice@demo.test";
const ALICE_PASSWORD = process.env.E2E_ALICE_PASSWORD ?? "alice-password-1234";

// Drives the full browser → gateway → rdp-proxy → xrdp round-trip: the worker does
// the RDP handshake with the injected password and streams graphics PDUs; the
// browser renders them via the jumpgate-rdp WASM renderer onto a <canvas>. The RDP
// handshake is slower than SSH, so timeouts are generous (like the terminal test).
test("in-browser RDP session connects and renders frames", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, ALICE_EMAIL, ALICE_PASSWORD);

  // Open the Catalog (the landing route is the Overview dashboard) and browse to
  // rdp-box under the demo folder.
  await page.getByRole("link", { name: "Catalog", exact: true }).click();
  await page.getByRole("button", { name: "Expand folder demo" }).click();
  const tree = page.locator('nav[aria-label="Catalog tree"]');
  await tree.getByRole("button", { name: "rdp-box" }).click();

  // Read the "Open RDP" target off the detail pane (gets the real asset id).
  const openRdp = page.getByRole("link", { name: /Open RDP/ }).first();
  await expect(openRdp).toBeVisible();
  const href = await openRdp.getAttribute("href");
  expect(href).toContain("/rdp/");

  await page.goto(href!); // chromeless RDP route, same tab
  await expect(page.locator("canvas")).toBeVisible();
  await expect(page.getByRole("status")).toContainText(/connected/i, { timeout: 90_000 });

  // Prove the graphics stream is actually rendering: the WASM renderer processed at
  // least one PDU into the framebuffer (renderer-agnostic liveness hook installed
  // by web/src/routes/rdp/rdp.tsx).
  await page.waitForFunction(
    () => ((window as unknown as { __jumpgateRdp?: { framesProcessed: number } }).__jumpgateRdp?.framesProcessed ?? 0) > 0,
    undefined,
    { timeout: 90_000 },
  );
});
