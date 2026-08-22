/**
 * group-actions.ts — pure gating + validation logic for the Groups tab.
 *
 * Decides which group affordances to offer given the caller's global
 * capabilities, and validates the New-group form. The server is the real gate;
 * this only governs which controls are shown.
 *
 *   - Create: caller holds `identity:group:create`.
 *   - Delete: caller holds `identity:group:delete`.
 *
 * Group names mirror the catalog charset rule `^[a-z0-9_-]+$`.
 */

import { capsCover } from "@/lib/capabilities";

/** True if the caller may open the New-group dialog. */
export function canCreateGroup(caps: string[]): boolean {
  return capsCover(caps, "identity:group:create");
}

/** True if the caller may delete a group. */
export function canDeleteGroup(caps: string[]): boolean {
  return capsCover(caps, "identity:group:delete");
}

// Client-side validation mirroring the server's protovalidate constraints.
const GROUP_NAME_RE = /^[a-z0-9_-]+$/;

export function isValidGroupName(name: string): boolean {
  const n = name.trim();
  return n.length >= 1 && n.length <= 200 && GROUP_NAME_RE.test(n);
}
