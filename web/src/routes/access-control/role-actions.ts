/**
 * role-actions.ts — pure capability-gating + validation helpers for the Roles
 * tab. These mirror the server's capability vocabulary and the catalog name
 * charset; the server remains the real enforcer. Kept side-effect-free so the
 * affordance gating is unit-testable.
 */

import { capsCover } from "@/lib/capabilities";

/** Role names share the catalog charset: lowercase alnum, dash, underscore. */
const ROLE_NAME_RE = /^[a-z0-9_-]+$/;

export function isValidRoleName(name: string): boolean {
  const trimmed = name.trim();
  return trimmed.length >= 1 && trimmed.length <= 200 && ROLE_NAME_RE.test(trimmed);
}

export function canCreateRole(caps: string[]): boolean {
  return capsCover(caps, "access:role:create");
}

export function canUpdateRole(caps: string[]): boolean {
  return capsCover(caps, "access:role:update");
}

export function canDeleteRole(caps: string[]): boolean {
  return capsCover(caps, "access:role:delete");
}
