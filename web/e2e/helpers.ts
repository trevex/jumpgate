import { expect, type Page } from "@playwright/test";

/**
 * Logs an actor into the console: navigate to the app, ride the redirect to
 * /login, submit credentials, and wait for the app shell (the Catalog nav link)
 * to render.
 */
export async function login(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("email").fill(email);
  await page.getByLabel("password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("link", { name: "Catalog", exact: true })).toBeVisible();
}
