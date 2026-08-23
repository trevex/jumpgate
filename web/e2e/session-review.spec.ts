import { test, expect, type Page } from "@playwright/test";
import { login } from "./helpers";

// Actor credentials — defaults match test/e2e/uiseed_test.go (the seed the
// make ui-e2e target runs before this spec). The seed provisions review-box: a
// JIT asset alice reaches through an approved grant, so its recording is
// attributed to that grant. This spec verifies the three discovery paths onto
// that recording — the subject's grant card, the approver's Reviewable list,
// and the per-asset filter — each ending in in-browser asciinema playback.
const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "admin-password-1234";
const ALICE_EMAIL = process.env.E2E_ALICE_EMAIL ?? "alice@demo.test";
const ALICE_PASSWORD = process.env.E2E_ALICE_PASSWORD ?? "alice-password-1234";
const BOB_EMAIL = process.env.E2E_BOB_EMAIL ?? "bob@demo.test";
const BOB_PASSWORD = process.env.E2E_BOB_PASSWORD ?? "bob-password-1234";

const REVIEW_ASSET = "review-box.demo";

// Given a page already on a (grant- or asset-scoped) recordings list, open the
// first recording and assert the asciinema player mounts and its cast streams
// with 200 — proving the caller can actually PLAY the session, not just list it.
// The cast fetch is authorized independently of the list (server enforces the
// subject/approver rule), so a 200 here is the real end-to-end check.
async function playFirstRecording(page: Page): Promise<void> {
  const firstRecording = page.getByRole("button", { name: /^Recording of / }).first();
  await expect(firstRecording).toBeVisible();

  // Arm the response wait BEFORE the click that mounts the player + fetches the cast.
  const castResp = page.waitForResponse(
    (r) => /\/api\/recordings\/.+\/cast$/.test(r.url()) && r.status() === 200,
  );
  await firstRecording.click();

  await expect(page.getByLabel(/^Terminal recording player for session/)).toBeVisible();
  await castResp;
}

test("session-review discovery: subject, approver, and per-asset playback", async ({ browser }) => {
  // Three logins plus recording playback for each — beyond the 30s default.
  test.setTimeout(120_000);

  const aliceCtx = await browser.newContext();
  const bobCtx = await browser.newContext();
  const adminCtx = await browser.newContext();
  const alice = await aliceCtx.newPage();
  const bob = await bobCtx.newPage();
  const admin = await adminCtx.newPage();

  try {
    // ─────────────────────────────────────────────────────────────────────────
    // ① Subject: alice reaches her review-box grant's recording from her grant
    //    card — she holds NO recording:read, only the grant-scoped review right.
    // ─────────────────────────────────────────────────────────────────────────
    await login(alice, ALICE_EMAIL, ALICE_PASSWORD);
    // Alice is not an auditor: the Recordings nav is gated on recording:read.
    await expect(alice.getByRole("link", { name: "Recordings" })).toHaveCount(0);

    await alice.getByRole("link", { name: "My Access" }).click();
    await alice.getByRole("tab", { name: "Grants" }).click();

    const grantCard = alice.locator(`[aria-label="Grant for asset ${REVIEW_ASSET}"]`);
    await expect(grantCard).toBeVisible();
    await grantCard.getByRole("button", { name: /view session recordings/i }).click();

    // The grant-scoped recordings route opens (the guard admits ?grantId= without
    // recording:read) and alice plays her session.
    await expect(alice).toHaveURL(/\/recordings\?grantId=/);
    await playFirstRecording(alice);

    // ─────────────────────────────────────────────────────────────────────────
    // ② Approver: bob oversees the grant he was eligible to approve — Reviewable
    //    list → the grant → play. Bob also holds NO recording:read.
    // ─────────────────────────────────────────────────────────────────────────
    await login(bob, BOB_EMAIL, BOB_PASSWORD);
    await expect(bob.getByRole("link", { name: "Recordings" })).toHaveCount(0);

    await bob.getByRole("link", { name: "Approvals" }).click();
    await bob.getByRole("tab", { name: "Reviewable" }).click();

    // Scope to the review-box grant row (subject Alice). The RPC self-scopes to
    // grants bob may review; filtering keeps it unambiguous if other grants exist.
    const reviewableRow = bob
      .getByRole("list", { name: "Reviewable grants" })
      .getByRole("listitem")
      .filter({ hasText: REVIEW_ASSET });
    await expect(reviewableRow).toBeVisible();
    await reviewableRow.getByRole("button", { name: /session recordings/i }).click();

    await expect(bob).toHaveURL(/\/recordings\?grantId=/);
    await playFirstRecording(bob);

    // ─────────────────────────────────────────────────────────────────────────
    // ③ Per-asset: admin (auditor) reaches the recording from the asset detail's
    //    "Recordings" jump — the per-asset filter.
    // ─────────────────────────────────────────────────────────────────────────
    await login(admin, ADMIN_EMAIL, ADMIN_PASSWORD);

    await admin.getByRole("link", { name: "Catalog" }).click();
    await admin.getByRole("button", { name: "Expand folder demo" }).click();
    const tree = admin.locator('nav[aria-label="Catalog tree"]');
    await tree.getByRole("button", { name: "review-box" }).click();

    await admin.getByRole("button", { name: "View session recordings for this asset" }).click();
    await expect(admin).toHaveURL(/\/recordings\?assetId=/);
    await playFirstRecording(admin);
  } finally {
    await aliceCtx.close();
    await bobCtx.close();
    await adminCtx.close();
  }
});
