import { test, expect, type Page } from "@playwright/test";

// Admin holds ** so every directory affordance is available.
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

test("directory: create a user and a group, then add the user as a member", async ({ page }) => {
  test.setTimeout(90_000);
  // Unique per run so re-runs on a kept cluster don't collide. Group names must
  // match ^[a-z0-9_-]+$, so keep the suffix lowercase-alphanumeric.
  const sfx = Date.now().toString(36).toLowerCase();
  const email = `dir-${sfx}@demo.test`;
  const groupName = `dir-grp-${sfx}`;

  await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);

  // Directory is capability-gated in the nav; admin sees it.
  await page.getByRole("link", { name: "Directory" }).click();
  await expect(page.getByRole("tab", { name: "Users" })).toBeVisible();

  // ── Create a user ──
  await page.getByRole("button", { name: "New user" }).click();
  const userDialog = page.getByRole("dialog", { name: "New user" });
  await userDialog.getByPlaceholder("user@example.com").fill(email);
  await userDialog.getByPlaceholder("Ada Lovelace").fill("Dir E2E");
  await userDialog.getByPlaceholder("At least 8 characters").fill("dir-e2e-password");
  await userDialog.getByRole("button", { name: "Create user" }).click();

  // The new user appears in the list with an Active status.
  const userRow = page.getByRole("row", { name: new RegExp(email) });
  await expect(userRow).toBeVisible();
  await expect(userRow.getByText("Active")).toBeVisible();

  // ── Create a group ──
  await page.getByRole("tab", { name: "Groups" }).click();
  await page.getByRole("button", { name: "New group" }).click();
  const groupDialog = page.getByRole("dialog", { name: "New group" });
  await groupDialog.getByPlaceholder("platform-oncall").fill(groupName);
  await groupDialog.getByRole("button", { name: "Create group" }).click();

  // The group appears; open its detail drawer (the Sheet's title is the group name).
  const groupCell = page.getByRole("cell", { name: groupName, exact: true });
  await expect(groupCell).toBeVisible();
  await groupCell.click();
  const sheet = page.getByRole("dialog", { name: groupName, exact: true });
  await expect(sheet).toBeVisible();

  // ── Add the new user as a member ──
  await sheet.getByRole("button", { name: "Add member" }).click();
  const picker = page.getByRole("dialog", { name: `Add member to ${groupName}` });
  await expect(picker).toBeVisible();
  await picker.getByPlaceholder("Search users…").fill(email);
  await picker.getByRole("option", { name: new RegExp(email) }).first().click();

  // The member shows up in the group detail.
  await expect(sheet.getByText(email)).toBeVisible();
});
