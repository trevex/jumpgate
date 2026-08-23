import { test, expect, type Page, type Browser, type Locator } from "@playwright/test";
import { login } from "./helpers";

// The gateway serves the terminal WSS on its external TLS listener with a
// self-signed (mesh-CA) cert, so the browser must accept it (the live-connect
// acts open in-browser terminals).
test.use({ ignoreHTTPSErrors: true });

// ─────────────────────────────────────────────────────────────────────────────
// A full UI twin of docs/demo/walkthrough-ui.md, driven entirely through the
// browser console: admin governance setup → JIT request/approve loop → live
// browser-terminal connects (CA + password) → recording playback → a delegated
// folder-administration chapter with allow AND deny (absent-affordance) cases.
//
// This spec runs ALONGSIDE the other specs against the ONE seeded cluster, so it
// owns a private `wt-*` namespace (folder `wt`, prefix `wt-`) to avoid colliding
// with the seed (`demo`, `demo-box`, alice/bob, `sre`) and the other specs. The
// prefix is FIXED (not randomised): the cluster is fresh each `make ui-e2e`, and
// the Go seed (test/e2e/uiseed_test.go) provisions the target's CA principal for
// the deterministic path `wt-box.wt` ahead of time, so `wt-box` must onboard to
// exactly that path for the live CA connect to work.
// ─────────────────────────────────────────────────────────────────────────────

const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@demo.test";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "admin-password-1234";

// wt-* actor passwords (we create these users through the UI).
const WT_PASS = "wt-pass-1234";

const WT_ALICE_EMAIL = "wt-alice@demo.test";
const WT_BOB_EMAIL = "wt-bob@demo.test";
const WT_DANA_EMAIL = "wt-dana@demo.test";

// Live SSH targets already running in the kind cluster (same ones the seed uses).
const TARGET_CA = "ssh-target.default.svc.cluster.local:22";
const TARGET_PW = "ssh-target-password.default.svc.cluster.local:22";
const TARGET_KEY = "ssh-target-key.default.svc.cluster.local:22";

// A dummy multi-line PEM — onboard-only (we never connect to wt-key), so its
// content is never exercised. The point is to prove the multi-line key textarea
// accepts a pasted PEM.
const DUMMY_PEM =
  "-----BEGIN OPENSSH PRIVATE KEY-----\nZHVtbXk=\n-----END OPENSSH PRIVATE KEY-----";

// ─── shared locators / helpers ────────────────────────────────────────────────

function tree(page: Page) {
  return page.locator('nav[aria-label="Catalog tree"]');
}

// Open the Catalog page (the landing route is the Overview dashboard).
async function openCatalog(page: Page): Promise<void> {
  await page.getByRole("link", { name: "Catalog", exact: true }).click();
  await expect(tree(page)).toBeVisible();
}

// Select a folder in the tree and leave it EXPANDED (so its children are in the
// DOM). The folder toggle button's accessible name flips between "Expand folder
// X" and "Collapse folder X"; we key off that to reach the expanded+selected
// state, then wait for the folder detail article. Mirrors catalog-authoring's
// selectFolder helper.
async function selectFolder(page: Page, name: string): Promise<void> {
  const expand = tree(page).getByRole("button", {
    name: new RegExp(`Expand folder ${name}$`),
  });
  const collapse = tree(page).getByRole("button", {
    name: new RegExp(`Collapse folder ${name}$`),
  });
  // The tree loads asynchronously: its container appears (openCatalog's gate)
  // before the folder rows stream in — up to several seconds for a low-privilege
  // user. Wait for THIS folder's toggle to exist before branching on expand.count(),
  // which does NOT auto-wait: a premature 0 read would take the else-branch and
  // click a "Collapse folder" button that never exists for a collapsed folder,
  // hanging until the test timeout (Playwright actions have no default timeout).
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
  await expect(
    page.getByRole("article", { name: `Folder: ${name}` }),
  ).toBeVisible();
}

// Select an asset leaf in the tree (its accessible name is the name plus an
// optional kind badge, e.g. "wt-box ssh"), then wait for its detail article.
function assetLeaf(page: Page, name: string) {
  return tree(page).getByRole("button", { name: new RegExp(`^${name}( ssh)?$`) });
}

async function selectAsset(page: Page, name: string): Promise<void> {
  await assetLeaf(page, name).first().click();
  await expect(
    page.getByRole("article", { name: `Asset: ${name}` }),
  ).toBeVisible();
}

// The tree-pane header "Create…" button (root-context creation). Distinct from a
// folder detail article's own "Create…" button, which we scope to the article.
function rootCreateButton(page: Page) {
  return page
    .locator('aside[aria-label="Catalog tree"]')
    .getByRole("button", { name: "Create…" });
}

// Open a folder detail's own "Create…" menu (folder-context creation).
async function folderCreate(page: Page, folder: string, item: string): Promise<void> {
  await page
    .getByRole("article", { name: `Folder: ${folder}` })
    .getByRole("button", { name: "Create…" })
    .click();
  await page.getByRole("menuitem", { name: item }).click();
}

// Create a root-level folder via the tree-pane header create menu.
async function createRootFolder(page: Page, name: string): Promise<void> {
  await rootCreateButton(page).click();
  await page.getByRole("menuitem", { name: "New folder" }).click();
  const dialog = page.getByRole("dialog", { name: "New folder" });
  await expect(dialog).toBeVisible();
  await dialog.getByPlaceholder("production").fill(name);
  await dialog.getByRole("button", { name: "Create folder" }).click();
  await expect(dialog).toBeHidden();
  await expect(
    tree(page).getByRole("button", { name: new RegExp(`folder ${name}$`) }),
  ).toBeVisible();
}

// Onboard an SSH asset under an already-selected+expanded folder via the wizard.
// `loginKind` maps to the shadcn Select option text; `secret` is a password (or,
// for kind "key", the PEM pasted into the multi-line key textarea).
async function onboardAsset(
  page: Page,
  folder: string,
  opts: {
    name: string;
    target: string;
    loginName: string;
    loginKind: "ca" | "password" | "key";
    secret?: string;
  },
): Promise<void> {
  await folderCreate(page, folder, "New asset");
  const wizard = page.getByRole("dialog", { name: "Onboard SSH asset" });
  await expect(wizard).toBeVisible();
  await wizard.getByPlaceholder("pg-primary").fill(opts.name);
  await wizard.getByPlaceholder("db-primary.internal:22").fill(opts.target);
  await wizard.getByLabel("Login name for row 1").fill(opts.loginName);

  if (opts.loginKind !== "ca") {
    await wizard.getByLabel("Auth kind for row 1").click();
    const optionRe = opts.loginKind === "password" ? /password/i : /private key/i;
    await page.getByRole("option", { name: optionRe }).click();
    if (opts.loginKind === "password") {
      await wizard.getByLabel("Secret for row 1").fill(opts.secret ?? "");
    } else {
      // The private-key row is a multi-line textarea — prove a pasted PEM lands.
      await wizard.getByLabel("Private key for row 1").fill(opts.secret ?? "");
    }
  }

  await wizard.getByRole("button", { name: "Onboard asset" }).click();
  await expect(wizard).toBeHidden();
  await expect(assetLeaf(page, opts.name).first()).toBeVisible();
}

// Create a folder-homed role from the folder detail Create… menu. The folder
// context is pre-filled, so the role homes in that folder.
async function createFolderRole(
  page: Page,
  folder: string,
  name: string,
  capability: string,
): Promise<void> {
  await folderCreate(page, folder, "New role");
  const dialog = page.getByRole("dialog", { name: "New role" });
  await expect(dialog).toBeVisible();
  await dialog.getByPlaceholder("db-reader").fill(name);
  const capInput = dialog.getByPlaceholder(/press Enter to add/);
  await capInput.fill(capability);
  await capInput.press("Enter"); // commits the capability chip
  await dialog.getByRole("button", { name: "Create role" }).click();
  await expect(dialog).toBeHidden();
}

// Pick a user by email in an open SubjectPicker cmdk dialog (User | Group toggle).
async function pickSubjectUser(dialog: Locator, email: string) {
  await dialog.getByRole("tab", { name: "User" }).click();
  await dialog.getByPlaceholder("Search users…").fill(email);
  await dialog.getByRole("option", { name: new RegExp(email) }).first().click();
}

// Pick a group by name in an open SubjectPicker cmdk dialog.
async function pickSubjectGroup(dialog: Locator, name: string) {
  await dialog.getByRole("tab", { name: "Group" }).click();
  await dialog.getByPlaceholder("Search groups…").fill(name);
  await dialog.getByRole("option", { name: new RegExp(name) }).first().click();
}

// Reads the live xterm screen buffer via the window hook the terminal page
// installs, and asserts it contains `needle`. Copied from terminal.spec.ts.
async function terminalContains(page: Page, needle: string): Promise<void> {
  await page.waitForFunction(
    (m) => {
      const term = (window as unknown as { __jumpgateTerm?: {
        buffer: { active: { length: number; getLine(i: number): { translateToString(): string } | undefined } };
      } }).__jumpgateTerm;
      if (!term) return false;
      const buf = term.buffer.active;
      let s = "";
      for (let i = 0; i < buf.length; i++) s += (buf.getLine(i)?.translateToString() ?? "") + "\n";
      return s.includes(m);
    },
    needle,
    { timeout: 30_000 },
  );
}

// Follows an "Open terminal" href (grant card / asset detail) to the chromeless
// terminal route, waits for connected, echoes a unique marker, and asserts it.
async function openTerminalHrefAndEcho(page: Page, href: string): Promise<string> {
  const marker = "JG_WT_" + Date.now().toString(36).toUpperCase() + "_" + Math.floor(Math.random() * 1e6).toString(36).toUpperCase();
  // The "Open terminal" affordance is a target="_blank" link: the terminal route
  // is chromeless (no app shell / nav), so in the product it opens in its OWN tab
  // and the caller's page stays on the app. Mirror that with a fresh page — a
  // same-page goto would strand the caller on the navless terminal, hanging the
  // next nav click (e.g. openCatalog).
  const term = await page.context().newPage();
  try {
    await term.goto(href);
    await expect(term.locator(".xterm")).toBeVisible();
    await expect(term.getByRole("status")).toContainText(/connected/i, { timeout: 30_000 });
    await term.locator(".xterm").click();
    await term.keyboard.type(`echo ${marker}`);
    await term.keyboard.press("Enter"); // xterm sends CR — required to run the command
    await terminalContains(term, marker);
  } finally {
    await term.close();
  }
  return marker;
}

// Create a wt-* user via Directory ▸ Users ▸ New user. Shared by the governance
// setup test and the delegation test (which creates dana), so it lives at module
// scope and takes the admin page explicitly.
async function createUser(page: Page, email: string, name: string): Promise<void> {
  await page.getByRole("button", { name: "New user" }).click();
  const dialog = page.getByRole("dialog", { name: "New user" });
  await expect(dialog).toBeVisible();
  await dialog.getByPlaceholder("user@example.com").fill(email);
  await dialog.getByPlaceholder("Ada Lovelace").fill(name);
  await dialog.getByPlaceholder("At least 8 characters").fill(WT_PASS);
  await dialog.getByRole("button", { name: "Create user" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("row", { name: new RegExp(email) })).toBeVisible();
}

// ─────────────────────────────────────────────────────────────────────────────
// The walkthrough is split into three sequential tests that share ONE seeded
// cluster. Playwright runs the tests in this file serially, in declaration order,
// on a single worker (no fullyParallel), so objects created by an earlier test
// persist for later ones. Each test re-logs its actors into fresh browser
// contexts and gets its own timeout budget.
//
//   test 1 (governance setup) creates the `wt` folder + assets/roles/users/group
//   + standing binding + request policy. Tests 2 and 3 DEPEND on those objects.
//   test 2 (request→approve→connect→audit) needs test 1's policy + binding.
//   test 3 (delegated administration) needs test 1's `wt` folder.
// ─────────────────────────────────────────────────────────────────────────────

test("walkthrough 1 — admin governance setup", async ({
  browser,
}: {
  browser: Browser;
}) => {
  test.setTimeout(480_000);

  const adminCtx = await browser.newContext();
  const admin = await adminCtx.newPage();

  try {
    // ═══════════════════════════════════════════════════════════════════════
    // Act 0 — admin governance setup (all via the console UI)
    // ═══════════════════════════════════════════════════════════════════════
    await login(admin, ADMIN_EMAIL, ADMIN_PASSWORD);
    await openCatalog(admin);

    // ── Create the `wt` root folder ──
    await createRootFolder(admin, "wt");

    // ── Onboard the three SSH assets under `wt` ──
    await selectFolder(admin, "wt");
    await onboardAsset(admin, "wt", {
      name: "wt-box",
      target: TARGET_CA,
      loginName: "deploy",
      loginKind: "ca", // path wt-box.wt principal is pre-seeded → connectable
    });
    await onboardAsset(admin, "wt", {
      name: "wt-pw",
      target: TARGET_PW,
      loginName: "demo",
      loginKind: "password",
      secret: "demo-password-123",
    });
    await onboardAsset(admin, "wt", {
      name: "wt-key",
      target: TARGET_KEY,
      loginName: "demo",
      loginKind: "key",
      secret: DUMMY_PEM, // onboard-only: proves multi-line key entry works
    });

    // ── Create the two folder-homed roles under `wt` ──
    await createFolderRole(admin, "wt", "wt-deploy", "ssh:login:deploy");
    await expect(admin.getByText(/wt-deploy was created under wt/i)).toBeVisible();
    await selectFolder(admin, "wt"); // re-select (toast may have consumed focus)
    await createFolderRole(admin, "wt", "wt-demo", "ssh:login:demo");
    await expect(admin.getByText(/wt-demo was created under wt/i)).toBeVisible();

    // ── Create the two wt-* users (Directory ▸ Users ▸ New user) ──
    await admin.getByRole("link", { name: "Directory" }).click();
    await expect(admin.getByRole("tab", { name: "Users" })).toBeVisible();

    await createUser(admin, WT_ALICE_EMAIL, "WT Alice");
    await createUser(admin, WT_BOB_EMAIL, "WT Bob");

    // ── Create the global `wt-sre` group and add both wt users ──
    await admin.getByRole("tab", { name: "Groups" }).click();
    await admin.getByRole("button", { name: "New group" }).click();
    const groupDialog = admin.getByRole("dialog", { name: "New group" });
    await expect(groupDialog).toBeVisible();
    await groupDialog.getByPlaceholder("platform-oncall").fill("wt-sre");
    await groupDialog.getByRole("button", { name: "Create group" }).click();
    await expect(groupDialog).toBeHidden();

    const wtSreCell = admin.getByRole("cell", { name: "wt-sre", exact: true });
    await expect(wtSreCell).toBeVisible();
    await wtSreCell.click();
    const groupSheet = admin.getByRole("dialog", { name: "wt-sre", exact: true });
    await expect(groupSheet).toBeVisible();

    async function addGroupMember(email: string) {
      await groupSheet.getByRole("button", { name: "Add member" }).click();
      const picker = admin.getByRole("dialog", { name: "Add member to wt-sre" });
      await expect(picker).toBeVisible();
      await picker.getByPlaceholder("Search users…").fill(email);
      await picker.getByRole("option", { name: new RegExp(email) }).first().click();
      await expect(groupSheet.getByText(email)).toBeVisible();
    }
    await addGroupMember(WT_ALICE_EMAIL);
    await addGroupMember(WT_BOB_EMAIL);
    // Close the group detail sheet so it doesn't overlay later navigation.
    await admin.keyboard.press("Escape");
    await expect(groupSheet).toBeHidden();

    // ── Standing binding: wt-demo → group wt-sre on wt-pw (scope pinned) ──
    await openCatalog(admin);
    await selectFolder(admin, "wt");
    await selectAsset(admin, "wt-pw");
    const wtPwArticle = admin.getByRole("article", { name: "Asset: wt-pw" });
    await wtPwArticle.getByRole("button", { name: "Bind a role to this asset" }).click();

    const bindDialog = admin.getByRole("dialog", { name: "New binding" });
    await expect(bindDialog).toBeVisible();
    // Role picker.
    await bindDialog.getByRole("button", { name: /Choose a role/ }).click();
    const bindRolePicker = admin.getByRole("dialog", { name: "Choose a role" });
    await expect(bindRolePicker).toBeVisible();
    await bindRolePicker.getByPlaceholder("Search roles…").fill("wt-demo");
    await bindRolePicker.getByRole("option", { name: /wt-demo/ }).first().click();
    // Subject picker → group wt-sre.
    await bindDialog.getByRole("button", { name: /Choose a user or group/ }).click();
    const bindSubjectPicker = admin.getByRole("dialog", { name: "Choose a subject" });
    await expect(bindSubjectPicker).toBeVisible();
    await pickSubjectGroup(bindSubjectPicker, "wt-sre");
    // Scope is pinned to wt-pw (fixedScope) — just submit.
    await bindDialog.getByRole("button", { name: "Create binding" }).click();
    await expect(bindDialog).toBeHidden();
    // The binding appears under this asset's Bindings section.
    await expect(wtPwArticle.getByText(/wt-demo/).first()).toBeVisible();

    // ── Make wt-box requestable (policy) — requester & approver group wt-sre ──
    await selectAsset(admin, "wt-box");
    const wtBoxArticle = admin.getByRole("article", { name: "Asset: wt-box" });
    await wtBoxArticle.getByRole("button", { name: "Make this asset requestable" }).click();

    const policyDialog = admin.getByRole("dialog", { name: "New request policy" });
    await expect(policyDialog).toBeVisible();
    // Requestable role → wt-deploy.
    await policyDialog.getByRole("button", { name: "Choose a role…" }).click();
    const reqRolePicker = admin.getByRole("dialog", { name: "Choose the requestable role" });
    await expect(reqRolePicker).toBeVisible();
    await reqRolePicker.getByPlaceholder("Search roles…").fill("wt-deploy");
    await reqRolePicker.getByRole("option", { name: /wt-deploy/ }).first().click();
    // Required approvals → 1 (default is already "1", set defensively).
    await policyDialog.getByLabel("Required approvals").fill("1");
    // Requester subject → group wt-sre.
    await policyDialog.getByRole("button", { name: "Add requester" }).click();
    const reqSubjectPicker = admin.getByRole("dialog", { name: "Choose a subject" });
    await expect(reqSubjectPicker).toBeVisible();
    await pickSubjectGroup(reqSubjectPicker, "wt-sre");
    // Approver subject → group wt-sre.
    await policyDialog.getByRole("button", { name: "Add approver" }).click();
    const apprSubjectPicker = admin.getByRole("dialog", { name: "Choose a subject" });
    await expect(apprSubjectPicker).toBeVisible();
    await pickSubjectGroup(apprSubjectPicker, "wt-sre");
    await policyDialog.getByRole("button", { name: "Create policy" }).click();
    await expect(policyDialog).toBeHidden();

    // The policy now lists wt-deploy under wt-box's "Requestable via" section.
    // (We check "Requestable via" — the policies scoped to this asset — NOT the
    // caller's own "Requestable roles": admin isn't a wt-sre member, so admin
    // cannot itself request it; wt-sre members can, as walkthrough 2 exercises.)
    // Select once and wait: the role label resolves via getRoleDisplay (async,
    // ~seconds, since it also loads the role's caps). Re-selecting in a retry loop
    // would remount the row and reset that query, so use one long-timeout expect.
    await selectAsset(admin, "wt-box");
    await expect(
      wtBoxArticle.getByText(/wt-deploy/).first(),
    ).toBeVisible({ timeout: 20_000 });
  } finally {
    await adminCtx.close();
  }
});

test("walkthrough 2 — request, approve, connect, audit", async ({
  browser,
}: {
  browser: Browser;
}) => {
  // Two live terminal connects + recording playback dominate this test; give it
  // the full budget. Relies on the `wt` folder, `wt-box`/`wt-pw` assets, the
  // request policy + standing binding, and the wt-sre group/users that
  // "walkthrough 1" created on the shared cluster.
  test.setTimeout(480_000);

  const adminCtx = await browser.newContext();
  const aliceCtx = await browser.newContext();
  const bobCtx = await browser.newContext();
  const admin = await adminCtx.newPage();
  const alice = await aliceCtx.newPage();
  const bob = await bobCtx.newPage();

  try {
    // ═══════════════════════════════════════════════════════════════════════
    // Act 1 — wt-alice requests access to wt-box (JIT)
    // ═══════════════════════════════════════════════════════════════════════
    await login(alice, WT_ALICE_EMAIL, WT_PASS);
    await openCatalog(alice);
    await selectFolder(alice, "wt");
    await selectAsset(alice, "wt-box");

    const aliceReason = "wt: need the wt box";
    await alice.getByRole("button", { name: "Request access to this asset" }).click();
    const requestSheet = alice.getByRole("dialog", { name: "Request access" });
    await expect(requestSheet).toBeVisible();
    await requestSheet.getByRole("combobox", { name: "Select a role to request" }).click();
    await alice.getByRole("option", { name: /wt-deploy/ }).click();
    await requestSheet.getByRole("button", { name: "1h" }).click();
    await requestSheet.locator("#reason").fill(aliceReason);
    await requestSheet.getByRole("button", { name: "Submit request" }).click();
    await expect(requestSheet).toBeHidden();

    // Pending in My Access ▸ Requests.
    await alice.getByRole("link", { name: "My Access" }).click();
    await alice.getByRole("tab", { name: "Requests" }).click();
    const alicePendingRow = alice
      .getByRole("list", { name: "Access requests" })
      .getByRole("listitem")
      .filter({ hasText: aliceReason })
      .filter({ hasText: "Pending" });
    await expect(alicePendingRow).toBeVisible();

    // ═══════════════════════════════════════════════════════════════════════
    // Act 2 — wt-bob approves wt-alice's request
    // ═══════════════════════════════════════════════════════════════════════
    await login(bob, WT_BOB_EMAIL, WT_PASS);
    await bob.getByRole("link", { name: "Approvals" }).click();
    // The inbox resolves requester + asset via the display reads (bob is an
    // eligible approver), so the row carries real names.
    const bobRow = bob
      .getByRole("list", { name: "Pending approval requests" })
      .getByRole("listitem")
      .filter({ hasText: aliceReason });
    await expect(bobRow).toBeVisible();
    await expect(
      bob.getByRole("listitem", { name: /Access request from WT Alice for wt-box\.wt/ }),
    ).toBeVisible();
    await bob.getByRole("button", { name: "Approve WT Alice's request" }).click();
    await expect(bobRow).toHaveCount(0);

    // ═══════════════════════════════════════════════════════════════════════
    // Act 3 — wt-alice connects (CA grant + password standing), live terminals
    // ═══════════════════════════════════════════════════════════════════════
    // The grant on wt-box appears in My Access ▸ Grants; grab its terminal href.
    await alice.getByRole("link", { name: "My Access" }).click();
    await alice.getByRole("tab", { name: "Grants" }).click();

    const wtBoxGrant = alice.getByLabel("Grant for asset wt-box.wt");
    const grantTerminalLink = wtBoxGrant.getByRole("link", {
      name: "Open browser terminal as deploy",
    });
    // Grant creation is server-side; one reload covers the invalidation gap.
    await expect(async () => {
      if (!(await grantTerminalLink.first().isVisible().catch(() => false))) {
        await alice.reload();
        await alice.getByRole("tab", { name: "Grants" }).click();
      }
      await expect(grantTerminalLink.first()).toBeVisible();
    }).toPass({ timeout: 30_000 });

    const caHref = await grantTerminalLink.first().getAttribute("href");
    expect(caHref).toContain("/terminal/");
    // Live CA connect on the UI-onboarded, seed-prepared wt-box.
    await openTerminalHrefAndEcho(alice, caHref!);

    // Password box via standing access — reach it from the catalog detail pane.
    await openCatalog(alice);
    await selectFolder(alice, "wt");
    await selectAsset(alice, "wt-pw");
    const pwOpenTerminal = alice
      .getByRole("article", { name: "Asset: wt-pw" })
      .getByRole("link", { name: /Open browser terminal/ })
      .first();
    await expect(pwOpenTerminal).toBeVisible();
    const pwHref = await pwOpenTerminal.getAttribute("href");
    expect(pwHref).toContain("/terminal/");
    // Live password connect.
    await openTerminalHrefAndEcho(alice, pwHref!);

    // ═══════════════════════════════════════════════════════════════════════
    // Act 4 — admin (auditor) plays back a wt recording
    // ═══════════════════════════════════════════════════════════════════════
    await login(admin, ADMIN_EMAIL, ADMIN_PASSWORD);
    // Scope the recordings list to wt-box via the asset detail's "View session
    // recordings" jump (?assetId=…) so we don't pick up another spec's session.
    await openCatalog(admin);
    await selectFolder(admin, "wt");
    await selectAsset(admin, "wt-box");
    await admin
      .getByRole("article", { name: "Asset: wt-box" })
      .getByRole("button", { name: "View session recordings for this asset" })
      .click();

    const firstRecording = admin.getByRole("button", { name: /^Recording of / }).first();
    await expect(async () => {
      await expect(firstRecording).toBeVisible();
    }).toPass({ timeout: 30_000 });

    // Arm the /cast response wait BEFORE the click that mounts the player.
    const castResp = admin.waitForResponse(
      (r) => /\/api\/recordings\/.+\/cast$/.test(r.url()) && r.status() === 200,
    );
    await firstRecording.click();
    await expect(
      admin.getByLabel(/^Terminal recording player for session/),
    ).toBeVisible();
    await castResp;
  } finally {
    await adminCtx.close();
    await aliceCtx.close();
    await bobCtx.close();
  }
});

test("walkthrough 3 — delegated administration", async ({
  browser,
}: {
  browser: Browser;
}) => {
  // The delegation chapter: admin carves `team` under `wt`, mints a global
  // folder-admin role, binds it to dana, then dana governs `team` (and only
  // `team`). Relies on the `wt` folder that "walkthrough 1" created.
  test.setTimeout(360_000);

  const adminCtx = await browser.newContext();
  const danaCtx = await browser.newContext();
  const admin = await adminCtx.newPage();
  const dana = await danaCtx.newPage();

  try {
    await login(admin, ADMIN_EMAIL, ADMIN_PASSWORD);

    // ═══════════════════════════════════════════════════════════════════════
    // Chapter — delegated folder administration
    // ═══════════════════════════════════════════════════════════════════════
    // admin: carve out `team` under `wt`.
    await openCatalog(admin);
    await selectFolder(admin, "wt");
    await folderCreate(admin, "wt", "New folder");
    const teamFolderDialog = admin.getByRole("dialog", { name: "New folder" });
    await expect(teamFolderDialog).toBeVisible();
    await teamFolderDialog.getByPlaceholder("production").fill("team");
    await teamFolderDialog.getByRole("button", { name: "Create folder" }).click();
    await expect(teamFolderDialog).toBeHidden();
    await expect(
      tree(admin).getByRole("button", { name: new RegExp(`folder team$`) }),
    ).toBeVisible();

    // admin: a GLOBAL folder-admin role wt-fadmin (Access control ▸ Roles).
    await admin.getByRole("link", { name: "Access control" }).click();
    await admin.getByRole("tab", { name: "Roles" }).click();
    await admin.getByRole("button", { name: "New role" }).click();
    const fadminDialog = admin.getByRole("dialog", { name: "New role" });
    await expect(fadminDialog).toBeVisible();
    await fadminDialog.getByPlaceholder("db-reader").fill("wt-fadmin");
    const fadminCaps = [
      "catalog:folder:read",
      "catalog:folder:create",
      "catalog:folder:update",
      "catalog:asset:create",
      "catalog:asset:read",
      "catalog:asset:update",
      "access:role:create",
      "access:binding:create",
      "identity:group:create",
      "identity:group:read",
      "identity:group:add-member",
      "ssh:login:*",
    ];
    const fadminCapInput = fadminDialog.getByPlaceholder(/press Enter to add/);
    for (const cap of fadminCaps) {
      await fadminCapInput.fill(cap);
      await fadminCapInput.press("Enter");
    }
    // No folder scope → global role (the binding is what scopes it).
    await fadminDialog.getByRole("button", { name: "Create role" }).click();
    await expect(fadminDialog).toBeHidden();
    await expect(admin.getByRole("cell", { name: "wt-fadmin", exact: true })).toBeVisible();

    // admin: create dana.
    await admin.getByRole("link", { name: "Directory" }).click();
    await expect(admin.getByRole("tab", { name: "Users" })).toBeVisible();
    await createUser(admin, WT_DANA_EMAIL, "WT Dana");

    // admin: bind wt-fadmin → user WT Dana at `team` (scope pinned to team).
    await openCatalog(admin);
    await selectFolder(admin, "wt");
    await selectFolder(admin, "team");
    const teamArticle = admin.getByRole("article", { name: "Folder: team" });
    await teamArticle.getByRole("button", { name: "Bind a role to this folder" }).click();
    const teamBindDialog = admin.getByRole("dialog", { name: "New binding" });
    await expect(teamBindDialog).toBeVisible();
    await teamBindDialog.getByRole("button", { name: /Choose a role/ }).click();
    const teamRolePicker = admin.getByRole("dialog", { name: "Choose a role" });
    await expect(teamRolePicker).toBeVisible();
    await teamRolePicker.getByPlaceholder("Search roles…").fill("wt-fadmin");
    await teamRolePicker.getByRole("option", { name: /wt-fadmin/ }).first().click();
    await teamBindDialog.getByRole("button", { name: /Choose a user or group/ }).click();
    const teamSubjectPicker = admin.getByRole("dialog", { name: "Choose a subject" });
    await expect(teamSubjectPicker).toBeVisible();
    await pickSubjectUser(teamSubjectPicker, WT_DANA_EMAIL);
    await teamBindDialog.getByRole("button", { name: "Create binding" }).click();
    await expect(teamBindDialog).toBeHidden();

    // ── dana (context 4): governs `team` and only `team` ──
    await login(dana, WT_DANA_EMAIL, WT_PASS);
    await openCatalog(dana);
    // Path-reveal: dana governs `team` (her management caps anchor it), so `team`
    // is visible AND its ancestor `wt` is revealed as a breadcrumb on the path.
    // Expand `wt` to reach `team` (the tree lazy-loads level by level).
    await selectFolder(dana, "wt");
    await selectFolder(dana, "team");
    // Create… is present on the team folder (she has caps there).
    await expect(
      dana.getByRole("article", { name: "Folder: team" }).getByRole("button", { name: "Create…" }),
    ).toBeVisible();

    // dana: onboard a password asset team-box under `team` (no principal needed).
    await onboardAsset(dana, "team", {
      name: "team-box",
      target: TARGET_PW,
      loginName: "demo",
      loginKind: "password",
      secret: "demo-password-123",
    });

    // dana: mint a team-homed role `teamdeploy` (ssh:login:demo).
    await createFolderRole(dana, "team", "teamdeploy", "ssh:login:demo");
    await expect(dana.getByText(/teamdeploy was created under team/i)).toBeVisible();

    // dana: bind teamdeploy → herself on team-box (scope pinned to team-box).
    await selectFolder(dana, "team");
    await selectAsset(dana, "team-box");
    const teamBoxArticle = dana.getByRole("article", { name: "Asset: team-box" });
    await teamBoxArticle.getByRole("button", { name: "Bind a role to this asset" }).click();
    const danaBindDialog = dana.getByRole("dialog", { name: "New binding" });
    await expect(danaBindDialog).toBeVisible();
    await danaBindDialog.getByRole("button", { name: /Choose a role/ }).click();
    const danaRolePicker = dana.getByRole("dialog", { name: "Choose a role" });
    await expect(danaRolePicker).toBeVisible();
    await danaRolePicker.getByPlaceholder("Search roles…").fill("teamdeploy");
    await danaRolePicker.getByRole("option", { name: /teamdeploy/ }).first().click();
    await danaBindDialog.getByRole("button", { name: /Choose a user or group/ }).click();
    const danaSubjectPicker = dana.getByRole("dialog", { name: "Choose a subject" });
    await expect(danaSubjectPicker).toBeVisible();
    await pickSubjectUser(danaSubjectPicker, WT_DANA_EMAIL);
    await danaBindDialog.getByRole("button", { name: "Create binding" }).click();
    await expect(danaBindDialog).toBeHidden();
    // The binding appears on team-box.
    await expect(teamBoxArticle.getByText(/teamdeploy/).first()).toBeVisible();

    // ── Deny / boundary — assert via ABSENT affordances ──
    // Up the tree (denied): dana has no caps at `wt` → no Create… on the wt
    // folder detail pane. Select `wt` (visible as team's ancestor) and assert the
    // create button is absent within its article.
    await selectFolder(dana, "wt");
    const wtArticleDana = dana.getByRole("article", { name: "Folder: wt" });
    await expect(wtArticleDana).toBeVisible();
    await expect(wtArticleDana.getByRole("button", { name: "Create…" })).toHaveCount(0);
    // She also can't bind a role at `wt` (access:binding:create is global; she
    // lacks it) — the Bind affordance is absent.
    await expect(
      wtArticleDana.getByRole("button", { name: "Bind a role to this folder" }),
    ).toHaveCount(0);

    // Global operation (denied): Directory ▸ Users shows no "New user" button.
    await dana.getByRole("link", { name: "Directory" }).click();
    // dana holds identity:group:read (team-scoped) so a Directory tab renders;
    // wait for the page shell, then assert the Users create affordance is absent.
    await expect(
      dana.getByRole("heading", { name: "Directory" }),
    ).toBeVisible();
    // If the Users tab is visible, open it; either way "New user" must be absent
    // (identity:user:create is global-only and dana holds it nowhere).
    const usersTab = dana.getByRole("tab", { name: "Users" });
    if (await usersTab.count()) {
      await usersTab.click();
    }
    await expect(dana.getByRole("button", { name: "New user" })).toHaveCount(0);
  } finally {
    await adminCtx.close();
    await danaCtx.close();
  }
});
