import { test, expect, type Page } from "@playwright/test";
import { login } from "./helpers";

/**
 * Target-identity verification: guided wizard step + durable asset detail card.
 *
 * These specs drive the REAL shipped components:
 *   - the guided step is a dialog titled "Verify target identity"
 *     (web/src/routes/catalog/target-verification-step.tsx), reached by onboarding
 *     an asset through Catalog ▸ folder ▸ Create… ▸ New asset (there is no direct
 *     "Onboard asset" toolbar button — assets are always created inside a folder);
 *   - the durable card is a "Target identity" DetailSection on the asset detail
 *     pane (web/src/routes/catalog/detail/target-identity-card.tsx), which is a
 *     MANAGEMENT affordance gated on catalog:asset:identity:read.
 *
 * The status copy (headings/detail) comes verbatim from the pure view-model
 * (web/src/routes/catalog/target-verification-model.ts).
 */

const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "demo-admin-passphrase";
// A creator who can create + probe assets in their folder but holds no
// catalog:asset:identity:approve — sees the read-only "awaiting approval" copy.
const CREATOR_EMAIL = process.env.E2E_CREATOR_EMAIL ?? "creator@demo.test";
const CREATOR_PASSWORD = process.env.E2E_CREATOR_PASSWORD ?? "creator-password-1234";
const CREATOR_FOLDER = process.env.E2E_CREATOR_FOLDER ?? "demo";

// A live SSH target already running in the kind cluster (same one the seed uses),
// so the credential-free identity probe reaches it and succeeds.
const REACHABLE_TARGET =
  process.env.E2E_SSH_TARGET ?? "ssh-target.default.svc.cluster.local:22";

// Fixture for the identity-change recovery case: an asset whose target identity
// has changed (rotated host key, no matching active anchor).
const CHANGED_FOLDER = process.env.E2E_CHANGED_FOLDER ?? "demo";
const CHANGED_ASSET = process.env.E2E_CHANGED_ASSET ?? "changed-box";

// ─── shared locators / helpers (mirror catalog-authoring.spec.ts) ────────────

function tree(page: Page) {
  return page.locator('nav[aria-label="Catalog tree"]');
}

async function openCatalog(page: Page): Promise<void> {
  await page.getByRole("link", { name: "Catalog", exact: true }).click();
  await expect(tree(page)).toBeVisible();
}

// Select a folder in the tree and leave it EXPANDED (so its children are in the
// DOM). The folder toggle's accessible name flips between "Expand folder X" and
// "Collapse folder X"; key off that to reach the expanded+selected state.
async function selectFolder(page: Page, name: string): Promise<void> {
  const expand = tree(page).getByRole("button", {
    name: new RegExp(`Expand folder ${name}$`),
  });
  const collapse = tree(page).getByRole("button", {
    name: new RegExp(`Collapse folder ${name}$`),
  });
  await expect(expand.or(collapse).first()).toBeVisible({ timeout: 30_000 });
  if (await expand.count()) {
    await expand.first().click();
  } else {
    await collapse.first().click();
    await tree(page)
      .getByRole("button", { name: new RegExp(`Expand folder ${name}$`) })
      .first()
      .click();
  }
  await expect(page.getByRole("article", { name: `Folder: ${name}` })).toBeVisible();
}

// Asset leaf buttons carry the name plus an optional kind badge (e.g. "box ssh").
function assetLeaf(page: Page, name: string) {
  return tree(page).getByRole("button", { name: new RegExp(`^${name}( ssh)?$`) });
}

async function selectAsset(page: Page, name: string): Promise<void> {
  await assetLeaf(page, name).first().click();
  await expect(page.getByRole("article", { name: `Asset: ${name}` })).toBeVisible();
}

// Onboard an SSH asset under an already-visible folder via the folder detail's
// Create… ▸ New asset menu. Leaves the guided verification step OPEN (the wizard
// swaps to it rather than closing on submit).
async function onboardSSH(
  page: Page,
  folder: string,
  opts: { name: string; target: string; loginName: string },
): Promise<void> {
  await selectFolder(page, folder);
  await page
    .getByRole("article", { name: `Folder: ${folder}` })
    .getByRole("button", { name: "Create…" })
    .click();
  await page.getByRole("menuitem", { name: "New asset" }).click();

  const wizard = page.getByRole("dialog", { name: "Onboard asset" });
  await expect(wizard).toBeVisible();
  // SSH is the default asset type; fill name, target and the default row's login.
  await wizard.getByPlaceholder("pg-primary").fill(opts.name);
  await wizard.getByPlaceholder("db-primary.internal:22").fill(opts.target);
  await wizard.getByLabel("Login name for row 1").fill(opts.loginName);
  await wizard.getByRole("button", { name: "Onboard asset" }).click();
}

test.describe("target identity verification", () => {
  test("guided step announces the result and offers a deliberate approval", async ({ page }) => {
    test.setTimeout(90_000);
    const name = "ti" + Date.now().toString(36).toLowerCase();

    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await openCatalog(page);

    // Onboard an SSH asset pointed at the reachable e2e sshd fixture; the wizard
    // swaps to the guided verification step.
    await onboardSSH(page, "demo", {
      name,
      target: REACHABLE_TARGET,
      loginName: "deploy",
    });

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
    // The button reads "Approve identity & finish".
    await expect(
      verify.getByRole("button", { name: /Approve identity/ }),
    ).toBeVisible({ timeout: 60_000 });
  });

  test("reload resumes from the durable asset detail card", async ({ page }) => {
    test.setTimeout(90_000);
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await openCatalog(page);

    // demo-box is a seeded, verified asset (test/e2e/uiseed_test.go). Its identity
    // card derives entirely from the server, so opening it, reloading, and
    // reopening shows the same durable "Target identity" section rather than a
    // blank/lost state. Admin holds catalog:asset:identity:read, so the management
    // card renders. Use an exact heading match so the DetailSection <h3> "Target
    // identity" is not confused with a status <h4> like "Probing target identity".
    await selectFolder(page, "demo");
    await selectAsset(page, "demo-box");
    await expect(
      page.getByRole("heading", { name: "Target identity", exact: true }),
    ).toBeVisible();

    await page.reload();
    await openCatalog(page);
    await selectFolder(page, "demo");
    await selectAsset(page, "demo-box");
    await expect(
      page.getByRole("heading", { name: "Target identity", exact: true }),
    ).toBeVisible();
  });

  // FIXME: needs a seeded creator (E2E_CREATOR_EMAIL/PASSWORD, and a folder via
  // E2E_CREATOR_FOLDER) who holds catalog:asset:create + catalog:asset:probe but
  // NOT catalog:asset:identity:approve. No such user/fixture exists in
  // test/e2e/uiseed_test.go yet, so this stays fixme until the seed provisions it.
  // The selectors below already match the shipped non-approver copy (model
  // AWAITING_APPROVAL branch) so it runs as-is once the fixture lands.
  test.fixme(
    "a creator without approval authority sees the awaiting-approval message",
    async ({ page }) => {
      test.setTimeout(90_000);
      const name = "tc" + Date.now().toString(36).toLowerCase();
      await login(page, CREATOR_EMAIL, CREATOR_PASSWORD);
      await openCatalog(page);

      await onboardSSH(page, CREATOR_FOLDER, {
        name,
        target: REACHABLE_TARGET,
        loginName: "deploy",
      });

      const verify = page.getByRole("dialog", { name: "Verify target identity" });
      await expect(verify).toBeVisible();
      // The probe reaches the target, but the creator can't approve, so the step
      // shows the read-only "Awaiting identity approval" heading (assert the
      // status heading, not the longer detail paragraph, to avoid a strict-mode
      // multi-match — both contain the phrase).
      await expect(
        verify.getByRole("heading", { name: "Awaiting identity approval" }),
      ).toBeVisible({ timeout: 60_000 });
      await expect(verify.getByRole("button", { name: /Approve identity/ })).toHaveCount(0);
      await expect(verify.getByRole("button", { name: "Finish later" })).toBeVisible();
    },
  );

  // FIXME: needs a seeded asset whose target identity has CHANGED (a rotated host
  // key with no matching active trust anchor — the IDENTITY_CHANGED state). That
  // can't be produced from the browser and isn't in test/e2e/uiseed_test.go; stays
  // fixme until a fixture rotates an already-probed target (see E2E_CHANGED_*).
  // The selectors match the shipped IDENTITY_CHANGED copy + the re-approval action.
  test.fixme("identity change is recoverable by explicit re-approval", async ({ page }) => {
    test.setTimeout(90_000);
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await openCatalog(page);

    // Open an asset whose target identity has changed (rotated by the fixture).
    await selectFolder(page, CHANGED_FOLDER);
    await selectAsset(page, CHANGED_ASSET);
    await expect(
      page.getByRole("heading", { name: "Target identity", exact: true }),
    ).toBeVisible();

    // The changed-identity state blocks new sessions but is explicitly resolvable.
    await expect(page.getByRole("heading", { name: "Target identity changed" })).toBeVisible();
    await expect(page.getByText(/new sessions are blocked/i)).toBeVisible();
    await page.getByRole("button", { name: "Approve observed identity" }).click();
    // The detail card toasts on success.
    await expect(page.getByText(/Identity approved/i)).toBeVisible();
  });
});
