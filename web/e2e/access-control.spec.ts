import { test, expect } from "@playwright/test";
import { login } from "./helpers";

const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "admin-password-1234";

test("access control: create a role with a capability, then cascade-delete it", async ({ page }) => {
  test.setTimeout(90_000);
  // Role names must match ^[a-z0-9_-]+$.
  const role = "acr" + Date.now().toString(36).toLowerCase();

  await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.getByRole("link", { name: "Access control" }).click();
  await expect(page.getByRole("tab", { name: "Roles" })).toBeVisible();

  // ── Create a role (name + one capability, global scope) ──
  await page.getByRole("button", { name: "New role" }).click();
  const dialog = page.getByRole("dialog", { name: "New role" });
  await dialog.getByPlaceholder("db-reader").fill(role);
  const capInput = dialog.getByPlaceholder(/press Enter to add/);
  await capInput.fill("ssh:login:demo");
  await capInput.press("Enter"); // commits the capability chip
  await dialog.getByRole("button", { name: "Create role" }).click();

  const roleCell = page.getByRole("cell", { name: role, exact: true });
  await expect(roleCell).toBeVisible();

  // ── Smoke: the Bindings and Policies tabs render their create affordance ──
  await page.getByRole("tab", { name: "Bindings" }).click();
  await expect(page.getByRole("button", { name: "New binding" })).toBeVisible();
  await page.getByRole("tab", { name: "Policies" }).click();
  await expect(page.getByRole("button", { name: "New policy" })).toBeVisible();

  // ── Open the role detail and cascade-delete it ──
  await page.getByRole("tab", { name: "Roles" }).click();
  await roleCell.click();
  const sheet = page.getByRole("dialog", { name: new RegExp(role) });
  await expect(sheet).toBeVisible();
  await sheet.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("button", { name: `Confirm delete ${role}` }).click();

  // The role is gone from the list (delete succeeded + cascade ran server-side).
  await expect(page.getByRole("cell", { name: role, exact: true })).toHaveCount(0);
});
