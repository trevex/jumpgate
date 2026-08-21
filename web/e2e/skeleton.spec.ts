import { test, expect } from "@playwright/test";

const email = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const password = process.env.E2E_ADMIN_PASSWORD ?? "admin-password-1234";

test("login shows capabilities then logout", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);

  await page.getByLabel("email").fill(email);
  await page.getByLabel("password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByText(`Signed in as ${email}`)).toBeVisible();
  await expect(
    page.getByLabel("capabilities").getByText("**"),
  ).toBeVisible();

  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/\/login$/);
});
