/**
 * policy-actions.ts — pure capability-gating + validation helpers for the
 * Policies tab. These mirror the server's capability vocabulary and the catalog
 * name charset; the server remains the real enforcer. Kept side-effect-free so
 * affordance gating and validation stay unit-testable.
 */

import { capsCover } from "@/lib/capabilities";

/**
 * Policy names are optional but, when present, share the catalog-ish charset:
 * letters, digits, dash, underscore. An empty name is allowed (unnamed policy).
 */
const POLICY_NAME_RE = /^[a-zA-Z0-9_-]*$/;

export function isValidPolicyName(name: string): boolean {
  return name.length <= 200 && POLICY_NAME_RE.test(name);
}

/** Approvals accepted by the create/edit forms: 0–20 inclusive. */
export function isValidApprovals(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= 20;
}

export function canCreatePolicy(caps: string[]): boolean {
  return capsCover(caps, "access:policy:create");
}

export function canUpdatePolicy(caps: string[]): boolean {
  return capsCover(caps, "access:policy:update");
}

export function canDeletePolicy(caps: string[]): boolean {
  return capsCover(caps, "access:policy:delete");
}
