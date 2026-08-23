import { test, expect, type Page } from "@playwright/test";
import { login } from "./helpers";

// Admin holds ** so every catalog authoring affordance (create/rename/move/
// delete) is available.
const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "admin-password-1234";

// The catalog tree nav — used to scope name lookups to the tree pane (both the
// tree and the detail pane render the same names).
function tree(page: Page) {
  return page.locator('nav[aria-label="Catalog tree"]');
}

// Select a node by clicking its row in the tree. Folder rows are the toggle
// buttons (`Expand/Collapse folder <name>`); asset/other leaves are plain
// buttons carrying the name as text. We wait for the detail pane header to
// reflect the selection before returning so callers can open its action menu.
// Select a folder in the tree and leave it EXPANDED, so its children (assets)
// are in the DOM. The folder toggle button toggles expansion on each click and
// its accessible name flips between "Expand folder X" (collapsed) and "Collapse
// folder X" (expanded); we key off that to reach the expanded state.
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
    // Already expanded — click it to (re)select without collapsing, then
    // re-expand.
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

// The asset leaf button's accessible name is the asset name plus its kind
// badge (e.g. "box2-abc ssh"), so match by a start-anchored regex rather than
// an exact string.
function assetLeaf(page: Page, name: string) {
  return tree(page).getByRole("button", { name: new RegExp(`^${name}( ssh)?$`) });
}

async function selectAsset(page: Page, name: string): Promise<void> {
  await assetLeaf(page, name).click();
  await expect(
    page.getByRole("article", { name: `Asset: ${name}` }),
  ).toBeVisible();
}

test("catalog authoring: create folder, onboard asset, rename, blocked delete, move, delete", async ({
  page,
}) => {
  test.setTimeout(120_000);
  // Unique per run so re-runs on a kept cluster don't collide. Catalog names
  // must match ^[a-z0-9_-]+$, so keep the suffix lowercase-alphanumeric.
  const sfx = Date.now().toString(36).toLowerCase();
  const folder = `auth-${sfx}`;
  const dest = `dest-${sfx}`;
  const asset = `box-${sfx}`;
  const asset2 = `box2-${sfx}`;

  await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.getByRole("link", { name: "Catalog", exact: true }).click();

  // ── 1. Create two root folders: `folder` (holds the asset) and `dest`
  //       (the later move target). Root creation is a capability-gated "Create…"
  //       menu; open it, then choose "New folder". ──
  async function createRootFolder(name: string) {
    await page.getByRole("button", { name: "Create…" }).click();
    await page.getByRole("menuitem", { name: "New folder" }).click();
    const dialog = page.getByRole("dialog", { name: "New folder" });
    await expect(dialog).toBeVisible();
    await dialog.getByPlaceholder("production").fill(name);
    await dialog.getByRole("button", { name: "Create folder" }).click();
    await expect(dialog).toBeHidden();
    // The folder appears at the root of the tree.
    await expect(
      tree(page).getByRole("button", { name: new RegExp(`folder ${name}$`) }),
    ).toBeVisible();
  }
  await createRootFolder(folder);
  await createRootFolder(dest);

  // ── 2. Onboard an SSH asset under `folder` via the wizard, with an inline
  //       password login "app". Secrets are sealed server-side in one tx. ──
  await selectFolder(page, folder);
  // Creation moved out of the "…" menu into a dedicated "Create…" menu in the
  // folder detail header. Scope to the detail article so we don't match the
  // tree-pane "Create…" button.
  await page
    .getByRole("article", { name: `Folder: ${folder}` })
    .getByRole("button", { name: "Create…" })
    .click();
  await page.getByRole("menuitem", { name: "New asset" }).click();

  const wizard = page.getByRole("dialog", { name: "Onboard SSH asset" });
  await expect(wizard).toBeVisible();
  await wizard.getByPlaceholder("pg-primary").fill(asset);
  await wizard.getByPlaceholder("db-primary.internal:22").fill("10.0.0.9:22");

  // The default login row is a CA login (no secret). Switch it to Password and
  // give it a name + secret. The kind is a shadcn Select: click the trigger,
  // then the option.
  await wizard.getByLabel("Login name for row 1").fill("app");
  await wizard.getByLabel("Auth kind for row 1").click();
  await page.getByRole("option", { name: /password/i }).click();
  await wizard.getByLabel("Secret for row 1").fill("hunter2");

  await wizard.getByRole("button", { name: "Onboard asset" }).click();
  await expect(wizard).toBeHidden();

  // The asset now lives under `folder`. `folder` was selected+expanded when we
  // opened its menu, so its children are visible; the new asset appears in the
  // tree (the createAsset success invalidates listFolderContents).
  await expect(assetLeaf(page, asset)).toBeVisible();

  // ── 3. Rename the asset `box-* → box2-*`. ──
  await selectAsset(page, asset);
  await page.getByRole("button", { name: `Actions for asset ${asset}` }).click();
  await page.getByRole("menuitem", { name: "Rename" }).click();

  const renameDialog = page.getByRole("dialog", { name: "Rename asset" });
  await expect(renameDialog).toBeVisible();
  const renameInput = renameDialog.getByLabel("Name");
  await renameInput.fill(asset2);
  await renameDialog.getByRole("button", { name: "Save" }).click();
  await expect(renameDialog).toBeHidden();

  await expect(assetLeaf(page, asset2)).toBeVisible();
  await expect(assetLeaf(page, asset)).toHaveCount(0);

  // ── 4. Attempt to delete the non-empty `folder`: it must be BLOCKED with the
  //       server's FailedPrecondition message ("folder not empty: 1 assets").
  //       The mutation errors and shows a toast.error("Delete failed", …). ──
  await selectFolder(page, folder);
  await page.getByRole("button", { name: `Actions for folder ${folder}` }).click();
  await page.getByRole("menuitem", { name: "Delete" }).click();

  const folderConfirm = page.getByRole("dialog", { name: "Delete this folder?" });
  await expect(folderConfirm).toBeVisible();
  await folderConfirm.getByRole("button", { name: "Delete" }).click();

  // The server rejects: assert the verbatim blocker text surfaces (sonner toast).
  await expect(page.getByText(/not empty/i)).toBeVisible();

  // The delete failed, so the confirm dialog stayed open. Dismiss it before
  // asserting on the tree (the modal overlay makes the tree inert/hidden).
  await page.keyboard.press("Escape");
  await expect(folderConfirm).toBeHidden();

  // The folder is still there.
  await expect(
    tree(page).getByRole("button", { name: new RegExp(`folder ${folder}$`) }),
  ).toBeVisible();

  // ── 5. Move the asset from `folder` to `dest` via the folder-picker. ──
  await selectAsset(page, asset2);
  await page.getByRole("button", { name: `Actions for asset ${asset2}` }).click();
  await page.getByRole("menuitem", { name: "Move" }).click();

  const moveDialog = page.getByRole("dialog", { name: "Move asset" });
  await expect(moveDialog).toBeVisible();
  await moveDialog.getByRole("button", { name: /Choose a folder/ }).click();

  // The FolderPicker is a cmdk CommandDialog searching the visibility-filtered
  // catalog. Type `dest`, pick it.
  const picker = page.getByRole("dialog", { name: "Choose a folder" });
  await expect(picker).toBeVisible();
  await picker.getByPlaceholder("Search folders…").fill(dest);
  await picker.getByRole("option", { name: new RegExp(dest) }).first().click();

  // Back in the move dialog, the destination is chosen — confirm the move.
  await moveDialog.getByRole("button", { name: "Move", exact: true }).click();
  await expect(moveDialog).toBeHidden();

  // The asset now lives under `dest`. Expand `dest` and confirm the asset is
  // there; `folder` no longer contains it.
  await selectFolder(page, dest);
  await expect(assetLeaf(page, asset2)).toBeVisible();

  // ── 6. Delete the asset. ──
  await selectAsset(page, asset2);
  await page.getByRole("button", { name: `Actions for asset ${asset2}` }).click();
  await page.getByRole("menuitem", { name: "Delete" }).click();

  const assetConfirm = page.getByRole("dialog", { name: "Delete this asset?" });
  await expect(assetConfirm).toBeVisible();
  await assetConfirm.getByRole("button", { name: "Delete" }).click();
  await expect(assetConfirm).toBeHidden();

  await expect(assetLeaf(page, asset2)).toHaveCount(0);

  // ── 7. Delete the now-empty `folder`. ──
  await selectFolder(page, folder);
  await page.getByRole("button", { name: `Actions for folder ${folder}` }).click();
  await page.getByRole("menuitem", { name: "Delete" }).click();

  const emptyConfirm = page.getByRole("dialog", { name: "Delete this folder?" });
  await expect(emptyConfirm).toBeVisible();
  await emptyConfirm.getByRole("button", { name: "Delete" }).click();
  await expect(emptyConfirm).toBeHidden();

  await expect(
    tree(page).getByRole("button", { name: new RegExp(`folder ${folder}$`) }),
  ).toHaveCount(0);
});
