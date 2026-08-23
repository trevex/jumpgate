import { test, expect } from "@playwright/test";

const email = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const password = process.env.E2E_ADMIN_PASSWORD ?? "admin-password-1234";

test("login shows capabilities then logout", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);

  await page.getByLabel("email").fill(email);
  await page.getByLabel("password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();

  // The app shell renders: the primary nav and the signed-in footer (the email
  // is carried on a span labelled "Signed in as <email>").
  await expect(page.getByRole("link", { name: "Catalog", exact: true })).toBeVisible();
  await expect(page.getByLabel(`Signed in as ${email}`)).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);
});
