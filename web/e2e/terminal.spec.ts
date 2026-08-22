import { test, expect, type Page } from "@playwright/test";

// The gateway serves the terminal WSS on its external TLS listener with a
// self-signed (mesh-CA) cert, so the browser must accept it.
test.use({ ignoreHTTPSErrors: true });

// alice has a concrete `ssh:login:demo` standing binding on password-box (via the
// seeded sre group), so her asset detail shows the connect/terminal affordances —
// an admin holding `**` does not (the UI only surfaces concrete login caps).
const ALICE_EMAIL = process.env.E2E_ALICE_EMAIL ?? "alice@demo.test";
const ALICE_PASSWORD = process.env.E2E_ALICE_PASSWORD ?? "alice-password-1234";

async function login(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("email").fill(email);
  await page.getByLabel("password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("link", { name: "Catalog" })).toBeVisible();
}

// Reads the live xterm screen buffer (renderer-agnostic) via the window hook the
// terminal page installs, and checks it contains `needle`.
async function terminalContains(page: Page, needle: string): Promise<void> {
  await page.waitForFunction(
    (m) => {
      const term = (window as unknown as { __jumpgateTerm?: {
        buffer: { active: { length: number; getLine(i: number): { translateToString(): string } | undefined } };
      } }).__jumpgateTerm;
      if (!term) return false;
      const buf = term.buffer.active;
      let s = "";
      for (let i = 0; i < buf.length; i++) s += (buf.getLine(i)?.translateToString() ?? "") + "\n";
      return s.includes(m);
    },
    needle,
    { timeout: 30_000 },
  );
}

// Browses the catalog to `asset` under `folder`, opens its browser terminal, runs
// `echo <marker>`, and asserts the marker comes back — proving the full
// browser → gateway → worker → target round-trip for that asset.
async function openTerminalAndEcho(page: Page, folder: string, asset: string): Promise<void> {
  const marker = "JG_WEBTTY_" + Date.now().toString(36).toUpperCase();

  await page.getByRole("button", { name: `Expand folder ${folder}` }).click();
  const tree = page.locator('nav[aria-label="Catalog tree"]');
  await tree.getByRole("button", { name: asset }).click();

  // Read the "Open terminal" target off the detail pane (gets the real asset id).
  const openTerminal = page.getByRole("link", { name: /Open browser terminal/ }).first();
  await expect(openTerminal).toBeVisible();
  const href = await openTerminal.getAttribute("href");
  expect(href).toContain("/terminal/");

  await page.goto(href!); // chromeless terminal route, same tab
  await expect(page.locator(".xterm")).toBeVisible();
  await expect(page.getByRole("status")).toContainText(/connected/i, { timeout: 30_000 });

  await page.locator(".xterm").click();
  await page.keyboard.type(`echo ${marker}`);
  await page.keyboard.press("Enter"); // xterm sends CR — required to run the command
  await terminalContains(page, marker);
}

// alice reaches password-box via a concrete asset-scoped ssh:login:demo binding.
test("in-browser terminal opens a session and echoes a command", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, ALICE_EMAIL, ALICE_PASSWORD);
  await openTerminalAndEcho(page, "demo", "password-box");
});

// alice reaches cascade-box ONLY via a FOLDER-scoped binding (no asset binding) —
// proving connect authz cascades folder→asset (the merged ConnectCapabilities rule).
test("in-browser terminal connects via a folder-scoped binding (cascade)", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, ALICE_EMAIL, ALICE_PASSWORD);
  await openTerminalAndEcho(page, "cascade", "cascade-box");
});
