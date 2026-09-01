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

type RdpHook = { status: string };
const rdpStatus = () =>
  (window as unknown as { __jumpgateRdp?: RdpHook }).__jumpgateRdp?.status ?? "idle";

// Drives the full browser → gateway → rdp-proxy → xrdp round-trip via the
// Devolutions iron-remote-desktop web component (RDCleanPath; the worker injects
// the vault credential server-side). The RDP handshake is slower than SSH, so
// timeouts are generous (like the terminal test).
test("in-browser RDP session connects and stays connected", async ({ page }) => {
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
  await expect(page.getByRole("status")).toContainText(/connected/i, { timeout: 90_000 });

  // The session must stay INTERACTIVE, not just connect once and freeze. The old
  // freeze surfaced as the session dropping (connect()/run() promise settling to
  // an error/closed state). Regression guard: drive input (mouse/keyboard) on the
  // component for ~9s, then require it is STILL 'connected' — never 'closed'/'error'.
  const box = await page.locator("div.h-full.w-full").boundingBox();
  if (!box) throw new Error("rdp surface has no bounding box");
  const cx = box.x + box.width / 2;
  const cy = box.y + box.height / 2;

  for (let i = 0; i < 9; i++) {
    await page.mouse.move(cx - 40, cy - 30);
    await page.mouse.move(cx + 50, cy + 40);
    await page.mouse.click(cx, cy);
    await page.mouse.click(cx + 20, cy + 20, { button: "right" });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(1_000);
    expect(await page.evaluate(rdpStatus)).toBe("connected");
  }
});
