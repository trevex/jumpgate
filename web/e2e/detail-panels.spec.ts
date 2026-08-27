import { test, expect, type Page } from "@playwright/test";
import { login } from "./helpers";

// Smoke test for the revamped detail panels. Admin holds ** so every panel and
// every disclosure is visible. Creds default to the browser-e2e seed
// (test/e2e/uiseed_test.go), overridable via env for ad-hoc runs.
const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "admin-password-1234";

// Seed anchors the other browser specs already depend on:
//   - folder `demo` holds the asset `demo-box` (a JIT-requestable box, gated by
//     the `approve-deploy` cross-approval policy — access-loop.spec.ts drives it)
//     and the folder-homed role `ssh-deploy` (the requestable role there);
//   - `sre` is a global (folder-less) group, so it renders at the catalog-tree
//     root.
// Keying off these keeps the spec independent of any fixtures it would create.
const FOLDER = "demo";
const ASSET = "demo-box";
const ROLE = "ssh-deploy";
const GROUP = "sre";

// The catalog tree nav — the same locator the other catalog specs use to scope
// name lookups to the tree pane (both the tree and the detail pane render the
// same names).
function tree(page: Page) {
  return page.locator('nav[aria-label="Catalog tree"]');
}

// Copied verbatim from catalog-authoring.spec.ts: expand a folder and leave it
// EXPANDED so its children (assets, roles) are in the DOM. The folder toggle's
// accessible name flips between "Expand folder X" and "Collapse folder X"; we
// key off that to reach the expanded state.
async function selectFolder(page: Page, name: string): Promise<void> {
  const expand = tree(page).getByRole("button", {
    name: new RegExp(`Expand folder ${name}$`),
  });
  const collapse = tree(page).getByRole("button", {
    name: new RegExp(`Collapse folder ${name}$`),
  });
  if (await expand.count()) {
    await expand.click();
  } else {
    await collapse.click();
    await tree(page)
      .getByRole("button", { name: new RegExp(`Expand folder ${name}$`) })
      .click();
  }
  await expect(
    page.getByRole("article", { name: `Folder: ${name}` }),
  ).toBeVisible();
  await expect(collapse).toBeVisible();
}

// The asset leaf button's accessible name is the asset name plus its kind badge
// (e.g. "demo-box ssh"), so match by a start-anchored regex — same helper the
// catalog-authoring spec uses.
function assetLeaf(page: Page, name: string) {
  return tree(page).getByRole("button", { name: new RegExp(`^${name}( ssh)?$`) });
}

async function selectAsset(page: Page, name: string): Promise<void> {
  await assetLeaf(page, name).click();
  await expect(
    page.getByRole("article", { name: `Asset: ${name}` }),
  ).toBeVisible();
}

// Role/group leaves carry just the name as their accessible name (the leading
// icon is aria-hidden), so match exactly. Roles are folder-homed; groups here
// are global, so they sit at the tree root.
async function selectRole(page: Page, folder: string, name: string): Promise<void> {
  await selectFolder(page, folder);
  await tree(page).getByRole("button", { name, exact: true }).click();
  await expect(page.getByRole("article", { name: `Role: ${name}` })).toBeVisible();
}

async function selectGroup(page: Page, name: string): Promise<void> {
  await tree(page).getByRole("button", { name, exact: true }).click();
  await expect(page.getByRole("article", { name: `Group: ${name}` })).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.getByRole("link", { name: "Catalog", exact: true }).click();
});

test("role panel shows capability + request-policy-usage sections", async ({ page }) => {
  await selectRole(page, FOLDER, ROLE);
  // Scope every assertion to the detail article — the role name also appears in
  // the tree, so an unscoped heading query would be ambiguous.
  const pane = page.getByRole("article", { name: `Role: ${ROLE}` });
  await expect(
    pane.getByRole("heading", { name: "Grants these capabilities" }),
  ).toBeVisible();
  await expect(
    pane.getByRole("heading", { name: "Used in request policies" }),
  ).toBeVisible();
});

test("asset panel shows the Requestable via rule cards + roster disclosure", async ({ page }) => {
  await selectFolder(page, FOLDER);
  await selectAsset(page, ASSET);
  const pane = page.getByRole("article", { name: `Asset: ${ASSET}` });
  await expect(
    pane.getByRole("heading", { name: "Requestable via" }),
  ).toBeVisible();

  // demo-box is requestable via the seeded `approve-deploy` policy, so its
  // Requestable-via section renders a rule card with a roster disclosure. Open
  // it and confirm the requester/approver roster expands.
  const disclose = pane.getByRole("button", { name: "Who can request / approve" }).first();
  await expect(disclose).toBeVisible();
  await disclose.click();
  await expect(pane.getByText(/Requesters/)).toBeVisible();
  await expect(pane.getByText(/Approvers/)).toBeVisible();
});

test("group panel uses Policy participation, not Requestable via", async ({ page }) => {
  await selectGroup(page, GROUP);
  const pane = page.getByRole("article", { name: `Group: ${GROUP}` });
  await expect(
    pane.getByRole("heading", { name: "Policy participation" }),
  ).toBeVisible();
  // The revamp renamed the group's section from "Requestable via" (still the
  // asset-panel heading) to "Policy participation" — assert the old heading is
  // gone from the group pane.
  await expect(
    pane.getByRole("heading", { name: "Requestable via" }),
  ).toHaveCount(0);
});
