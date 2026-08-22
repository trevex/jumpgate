import { test, expect, type Page } from "@playwright/test";

// The gateway serves the terminal WSS on its external TLS listener with a
// self-signed (mesh-CA) cert, so the browser must accept it.
test.use({ ignoreHTTPSErrors: true });

const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "admin-password-1234";

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

test("in-browser terminal opens a session and echoes a command", async ({ page }) => {
  test.setTimeout(120_000);
  const marker = "JG_WEBTTY_" + Date.now().toString(36).toUpperCase();

  await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);

  // Browse to the seeded connectable asset (password-box, demo login) and read the
  // "Open terminal" target off its detail pane (gets the real asset id via the UI).
  await page.getByRole("button", { name: "Expand folder demo" }).click();
  const tree = page.locator('nav[aria-label="Catalog tree"]');
  await tree.getByRole("button", { name: "password-box" }).click();

  const openTerminal = page.getByRole("link", { name: "Open terminal" }).first();
  await expect(openTerminal).toBeVisible();
  const href = await openTerminal.getAttribute("href");
  expect(href).toContain("/terminal/");

  // Navigate straight to the chromeless terminal route (same tab).
  await page.goto(href!);
  await expect(page.locator(".xterm")).toBeVisible();

  // The session connects (status pill), then we drive a command and read it back.
  await expect(page.getByRole("status")).toContainText(/connected/i, { timeout: 30_000 });
  await page.locator(".xterm").click();
  await page.keyboard.type(`echo ${marker}\n`);

  // The echoed marker appears in the terminal — proving browser → gateway → worker
  // → target round-trip.
  await terminalContains(page, marker);
});
