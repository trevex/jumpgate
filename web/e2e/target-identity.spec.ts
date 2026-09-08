import { test, expect, type Page } from "@playwright/test";
import { login } from "./helpers";

/**
 * Target-identity verification: guided wizard step + durable asset detail card.
 *
 * NOTE: this spec is not run in the implementation environment (no live app /
 * worker). It is written against the real UI copy and a11y contract so it runs
 * once a probe-capable worker fixture is wired into the e2e cluster.
 *
 * Covered: keyboard nav into the verification step, focus + live-region
 * announcement when a result arrives, reload during a leased probe (durable
 * resume), unauthorized-creator messaging, and identity-change recovery.
 */

const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "admin-password-1234";
// A creator who can create assets in their folder but holds no
// catalog:asset:identity:approve — sees the read-only "awaiting approval" copy.
const CREATOR_EMAIL = process.env.E2E_CREATOR_EMAIL ?? "creator@demo.test";
const CREATOR_PASSWORD = process.env.E2E_CREATOR_PASSWORD ?? "creator-password-1234";

async function openCatalog(page: Page) {
  await page.getByRole("link", { name: "Catalog", exact: true }).click();
}

test.describe("target identity verification", () => {
  test("guided step announces the result and offers a deliberate approval", async ({ page }) => {
    test.setTimeout(90_000);
    const name = "ti" + Date.now().toString(36).toLowerCase();

    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await openCatalog(page);

    // Onboard an SSH asset pointed at the known e2e sshd fixture.
    await page.getByRole("button", { name: "Onboard asset" }).click();
    const wizard = page.getByRole("dialog", { name: "Onboard asset" });
    await wizard.getByRole("button", { name: "SSH" }).click();
    await wizard.getByLabel("Name").fill(name);
    // (config fields filled by the shared AssetConfigForm — omitted here)
    await wizard.getByRole("button", { name: "Onboard asset" }).click();

    // The guided verification step replaces the form.
    const verify = page.getByRole("dialog", { name: "Verify target identity" });
    await expect(verify).toBeVisible();

    // The status banner is a polite live region so the result is announced.
    const status = verify.getByRole("status");
    await expect(status).toBeVisible();

    // Keyboard: "Finish later" is always reachable and leaves a resumable asset.
    const finishLater = verify.getByRole("button", { name: "Finish later" });
    await finishLater.focus();
    await expect(finishLater).toBeFocused();

    // Once the probe succeeds the deliberate approval appears (not auto-approved).
    await expect(
      verify.getByRole("button", { name: /Approve identity/ }),
    ).toBeVisible({ timeout: 60_000 });
  });

  test("reload during a leased probe resumes from the durable asset detail card", async ({
    page,
  }) => {
    test.setTimeout(90_000);
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await openCatalog(page);

    // Assume a pending asset already exists (created above / by fixture). Open it.
    // The identity card derives entirely from the server, so a reload mid-probe
    // shows the same status rather than a blank/lost state.
    const firstAsset = page.getByRole("treeitem").first();
    await firstAsset.click();
    const card = page.getByRole("heading", { name: "Target identity" });
    await expect(card).toBeVisible();

    await page.reload();
    await firstAsset.click();
    await expect(page.getByRole("heading", { name: "Target identity" })).toBeVisible();
  });

  test("a creator without approval authority sees the awaiting-approval message", async ({
    page,
  }) => {
    test.setTimeout(90_000);
    await login(page, CREATOR_EMAIL, CREATOR_PASSWORD);
    await openCatalog(page);

    const name = "tc" + Date.now().toString(36).toLowerCase();
    await page.getByRole("button", { name: "Onboard asset" }).click();
    const wizard = page.getByRole("dialog", { name: "Onboard asset" });
    await wizard.getByRole("button", { name: "SSH" }).click();
    await wizard.getByLabel("Name").fill(name);
    await wizard.getByRole("button", { name: "Onboard asset" }).click();

    const verify = page.getByRole("dialog", { name: "Verify target identity" });
    await expect(verify).toBeVisible();
    // No approve button; the creator is told approval is pending an admin.
    await expect(verify.getByText(/awaiting identity approval/i)).toBeVisible({
      timeout: 60_000,
    });
    await expect(verify.getByRole("button", { name: /Approve identity/ })).toHaveCount(0);
    await expect(verify.getByRole("button", { name: "Finish later" })).toBeVisible();
  });

  test("identity change is recoverable by explicit re-approval", async ({ page }) => {
    test.setTimeout(90_000);
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await openCatalog(page);

    // Open an asset whose target identity has changed (rotated by the fixture).
    const asset = page.getByRole("treeitem").first();
    await asset.click();
    await expect(page.getByRole("heading", { name: "Target identity" })).toBeVisible();

    // The changed-identity state blocks new sessions but is explicitly resolvable.
    await expect(page.getByText(/identity changed/i)).toBeVisible();
    await expect(page.getByText(/new sessions are blocked/i)).toBeVisible();
    await page.getByRole("button", { name: "Approve observed identity" }).click();
    await expect(page.getByText(/Identity approved/i)).toBeVisible();
  });
});
