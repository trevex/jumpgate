/**
 * user-actions.ts — pure gating logic for the Users tab row actions.
 *
 * Decides which lifecycle affordances (Deactivate / Reactivate / Delete) to
 * offer for a given user, given the caller's global capabilities and whether
 * the row is the caller's own account. The server is the real gate; this only
 * governs which controls are shown, plus a self-lockout guard:
 *
 *   - Deactivate: user is active, caller holds `identity:user:deactivate`,
 *     and the row is NOT the caller (never deactivate yourself).
 *   - Reactivate: user is deactivated and caller holds `identity:user:deactivate`
 *     (same cap — reactivation is server-gated on deactivate, not a separate cap).
 *   - Delete: caller holds `identity:user:delete` and the row is NOT the caller.
 *
 * Validation for the create form lives in `canCreateUser` — mirrors protovalidate.
 */

import { capsCover } from "@/lib/capabilities";

export interface UserRowActions {
  canDeactivate: boolean;
  canReactivate: boolean;
  canDelete: boolean;
}

export function userRowActions(
  caps: string[],
  user: { active: boolean },
  isSelf: boolean,
): UserRowActions {
  const holdsDeactivate = capsCover(caps, "identity:user:deactivate");
  const holdsDelete = capsCover(caps, "identity:user:delete");
  return {
    canDeactivate: user.active && holdsDeactivate && !isSelf,
    canReactivate: !user.active && holdsDeactivate,
    canDelete: holdsDelete && !isSelf,
  };
}

/** True if the caller may open the New-user dialog. */
export function canCreateUser(caps: string[]): boolean {
  return capsCover(caps, "identity:user:create");
}

// Client-side validation mirroring the server's protovalidate constraints.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(email: string): boolean {
  return EMAIL_RE.test(email.trim());
}

export function isValidDisplayName(name: string): boolean {
  const n = name.trim();
  return n.length >= 1 && n.length <= 200;
}

export function isValidPassword(password: string): boolean {
  return password.length >= 8;
}

export function isValidNewUser(input: {
  email: string;
  displayName: string;
  password: string;
}): boolean {
  return (
    isValidEmail(input.email) &&
    isValidDisplayName(input.displayName) &&
    isValidPassword(input.password)
  );
}
