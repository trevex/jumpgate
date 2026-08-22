import { test, expect, type Page } from "@playwright/test";

// Actor credentials — defaults match test/e2e/uiseed_test.go (the seed the
// make ui-e2e target runs before this spec). Overridable via env for ad-hoc runs.
const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "admin-password-1234";
const ALICE_EMAIL = process.env.E2E_ALICE_EMAIL ?? "alice@demo.test";
const ALICE_PASSWORD = process.env.E2E_ALICE_PASSWORD ?? "alice-password-1234";
const BOB_EMAIL = process.env.E2E_BOB_EMAIL ?? "bob@demo.test";
const BOB_PASSWORD = process.env.E2E_BOB_PASSWORD ?? "bob-password-1234";

/**
 * Logs an actor into the console: navigate to the app, ride the redirect to
 * /login, submit credentials, and wait for the app shell (the Catalog nav link)
 * to render.
 */
async function login(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("email").fill(email);
  await page.getByLabel("password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("link", { name: "Catalog" })).toBeVisible();
}

test("request → approve → connect-command → audit across four actors", async ({ browser }) => {
  // Four logins plus several server round-trips (JIT grant creation, recording
  // playback) — well beyond the 30s default.
  test.setTimeout(120_000);

  // ── Isolated cookie jars, one per actor ──
  const aliceCtx = await browser.newContext();
  const bobCtx = await browser.newContext();
  const adminCtx = await browser.newContext();
  const alice = await aliceCtx.newPage();
  const bob = await bobCtx.newPage();
  const admin = await adminCtx.newPage();

  try {
    // ─────────────────────────────────────────────────────────────────────────
    // 1. Alice browses the catalog, finds the requestable asset, and requests it
    // ─────────────────────────────────────────────────────────────────────────
    await login(alice, ALICE_EMAIL, ALICE_PASSWORD);

    // Expand the demo folder and select the demo-box asset in the governance tree.
    await alice.getByRole("button", { name: "Expand folder demo" }).click();
    const tree = alice.locator('nav[aria-label="Catalog tree"]');
    await expect(tree.getByRole("button", { name: "demo-box" })).toBeVisible();
    await tree.getByRole("button", { name: "demo-box" }).click();

    // The asset detail pane offers ssh-deploy as a requestable role.
    await expect(alice.getByText("Requestable roles")).toBeVisible();
    await expect(
      alice.getByRole("list", { name: "Requestable roles" }).getByText("ssh-deploy"),
    ).toBeVisible();

    // Open the request sheet, pick the role, give a reason, submit.
    await alice.getByRole("button", { name: "Request access to this asset" }).click();
    const sheet = alice.getByRole("dialog", { name: "Request access" });
    await expect(sheet).toBeVisible();
    await sheet.getByRole("button", { name: "1h" }).click(); // defensive: 1h is pre-selected
    await sheet.getByRole("combobox", { name: "Select a role to request" }).click();
    await alice.getByRole("option", { name: /ssh-deploy/ }).click();
    await sheet.locator("#reason").fill("e2e: need the demo box");
    await sheet.getByRole("button", { name: "Submit request" }).click();

    // On success the sheet closes (the "Access requested" sonner toast fires but
    // auto-dismisses, so the close is the reliable signal). Waiting on the close
    // — rather than the transient toast — avoids a flake.
    await expect(sheet).toBeHidden();

    // The request shows up as Pending in My Access → Requests.
    await alice.getByRole("link", { name: "My Access" }).click();
    await alice.getByRole("tab", { name: "Requests" }).click();
    // Scope to the Pending row for this reason — on a fresh cluster there is
    // exactly one, but filtering on "Pending" keeps it unambiguous even if an
    // earlier granted request with the same reason lingers on a reused cluster.
    const aliceRequestRow = alice
      .getByRole("list", { name: "Access requests" })
      .getByRole("listitem")
      .filter({ hasText: "e2e: need the demo box" })
      .filter({ hasText: "Pending" });
    await expect(aliceRequestRow).toBeVisible();

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Bob (no auditor caps) approves Alice's request from his inbox
    // ─────────────────────────────────────────────────────────────────────────
    await login(bob, BOB_EMAIL, BOB_PASSWORD);

    // Bob is not an auditor: the Recordings nav is gated on recording:read.
    await expect(bob.getByRole("link", { name: "Recordings" })).toHaveCount(0);

    await bob.getByRole("link", { name: "Approvals" }).click();
    // The inbox resolves the requester and asset via the display reads — the
    // requester's name comes from the universal GetUserDisplay, the asset path
    // from GetAssetDisplay authorized because bob is an eligible approver of this
    // pending request. So a plain sre approver (no identity:user:read /
    // catalog:asset:read) sees the real "Alice" / "demo-box.demo", not UUIDs.
    const bobRow = bob
      .getByRole("list", { name: "Pending approval requests" })
      .getByRole("listitem")
      .filter({ hasText: "e2e: need the demo box" });
    await expect(bobRow).toBeVisible();
    // Enriched identity: the row's accessible label carries the resolved names.
    await expect(
      bob.getByRole("listitem", { name: /Access request from Alice for demo-box\.demo/ }),
    ).toBeVisible();
    // Decision context: the requested login's target host is reachable from the
    // GetAssetDisplay payload (expand the row's context panel), proving the
    // secret-free connection detail flows to the approver.
    await bobRow.getByRole("button", { name: /show decision context/i }).click();
    await expect(bobRow.getByText("ssh-target.default.svc.cluster.local:22")).toBeVisible();
    // Approve by the resolved requester name (button label is built from it).
    await bob.getByRole("button", { name: "Approve Alice's request" }).click();
    // Approval invalidates the inbox; the row drops out.
    await expect(bobRow).toHaveCount(0);

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Alice now holds a grant with a runnable connect command
    // ─────────────────────────────────────────────────────────────────────────
    await alice.getByRole("link", { name: "My Access" }).click();
    await alice.getByRole("tab", { name: "Grants" }).click();
    const connectCode = alice.locator("code", {
      hasText: "jumpgate connect deploy@demo-box.demo",
    });
    // Grant creation is server-side; one reload covers the invalidation gap.
    await expect(async () => {
      if (!(await connectCode.first().isVisible())) {
        await alice.reload();
        await alice.getByRole("tab", { name: "Grants" }).click();
      }
      await expect(connectCode.first()).toBeVisible();
    }).toPass({ timeout: 30_000 });

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Admin (auditor) plays back the recorded session in the browser
    // ─────────────────────────────────────────────────────────────────────────
    await login(admin, ADMIN_EMAIL, ADMIN_PASSWORD);
    await expect(admin.getByRole("link", { name: "Recordings" })).toBeVisible();
    await admin.getByRole("link", { name: "Recordings" }).click();

    const firstRecording = admin
      .getByRole("button", { name: /^Recording of / })
      .first();
    await expect(firstRecording).toBeVisible();

    // Arm the response wait BEFORE the click that mounts the player + fetches the cast.
    const castResp = admin.waitForResponse(
      (r) => /\/api\/recordings\/.+\/cast$/.test(r.url()) && r.status() === 200,
    );
    await firstRecording.click();

    await expect(
      admin.getByLabel(/^Terminal recording player for session/),
    ).toBeVisible();
    await castResp;
  } finally {
    await aliceCtx.close();
    await bobCtx.close();
    await adminCtx.close();
  }
});

test("⌘K command palette finds a seeded asset", async ({ browser }) => {
  test.setTimeout(60_000);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  try {
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);

    // Open the palette via the header affordance (the ⌘K key path is equivalent).
    await page.getByRole("button", { name: "Search catalog" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();

    // Typing queries SearchCatalog (debounced); the seeded asset shows up as a hit.
    await page
      .getByPlaceholder("Search folders, assets, roles, groups…")
      .fill("demo-box");
    await expect(
      dialog.getByRole("option", { name: /demo-box/ }).first(),
    ).toBeVisible();
  } finally {
    await ctx.close();
  }
});
