/**
 * capability-glossary.ts — human-readable glosses for capability strings.
 *
 * Capabilities are `scope:action[:qualifier]` globs (e.g. `ssh:login:root`,
 * `catalog:asset:read`, `**`). This module maps the common shapes to a short
 * plain-language phrase for tooltips, so operators don't have to read the raw
 * glob vocabulary. `glossCapability` is a pure function — unknown capabilities
 * fall back to a readable Title-Cased rendering of the raw string.
 */

import { capitalize } from "@/lib/format";

// Readable fallback for unknown capabilities: "foo:bar:baz" → "Foo Bar Baz".
function fallbackGloss(cap: string): string {
  return cap
    .split(":")
    .map((seg) => capitalize(seg))
    .join(" ");
}

// Maps a management verb segment to a human verb.
const VERB: Record<string, string> = {
  read: "View",
  create: "Create",
  update: "Edit",
  delete: "Delete",
};

// scope:noun → plural label used in the "View/Create/… <label>" phrasings.
const NOUN_LABEL: Record<string, string> = {
  "catalog:asset": "assets",
  "catalog:folder": "folders",
  "identity:user": "users",
  "identity:group": "groups",
  "access:role": "roles",
  "access:binding": "bindings",
  "access:policy": "policies",
};

/**
 * Returns a short human gloss for a capability string.
 */
export function glossCapability(cap: string): string {
  const raw = cap.trim();
  if (raw.length === 0) return "";

  // Full / all-scope globs.
  if (raw === "**") return "Full administrative access";
  if (raw === "*") return "All actions in this scope";

  const parts = raw.split(":");
  const [scope, action, qualifier] = parts;

  // ── SSH connect ──────────────────────────────────────────────────────────
  if (scope === "ssh") {
    if (raw === "ssh:**") return "Connect over SSH (any login)";
    if (action === "login") {
      if (qualifier === undefined || qualifier === "*") {
        return "Connect over SSH (any login)";
      }
      return `Connect over SSH as ${qualifier}`;
    }
    if (action === "record") {
      if (qualifier === "exempt") return "Exempt from session recording";
      return "Manage session recording";
    }
    // Unknown ssh:* shape.
    return fallbackGloss(raw);
  }

  // ── Recordings ───────────────────────────────────────────────────────────
  if (scope === "recording") {
    if (action === "read") return "View session recordings";
    if (action === "*" || action === "**" || action === undefined) {
      return "Manage session recordings";
    }
    return fallbackGloss(raw);
  }

  // ── Noun-scoped management caps (catalog/identity/access) ────────────────
  const nounKey = `${scope}:${action}`;
  const label = NOUN_LABEL[nounKey];
  if (label) {
    if (qualifier === undefined) {
      // Bare "scope:noun" — treat as full management of the noun.
      return `Manage ${label}`;
    }
    if (qualifier === "*" || qualifier === "**") {
      return `Manage ${label}`;
    }
    const verb = VERB[qualifier];
    if (verb) return `${verb} ${label}`;
    return fallbackGloss(raw);
  }

  // ── Whole-scope globs like "catalog:*", "identity:**" ────────────────────
  if (action === "*" || action === "**") {
    const scopeLabel: Record<string, string> = {
      catalog: "the catalog",
      identity: "users and groups",
      access: "roles, bindings and policies",
    };
    const s = scopeLabel[scope];
    if (s) return `Manage ${s}`;
  }

  return fallbackGloss(raw);
}
