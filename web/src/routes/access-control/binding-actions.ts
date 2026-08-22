/**
 * binding-actions.ts — pure capability-gating helpers for the Bindings tab.
 * These mirror the server's capability vocabulary; the server remains the real
 * enforcer. Kept side-effect-free so affordance gating stays unit-testable.
 */

import { capsCover } from "@/lib/capabilities";

export function canCreateBinding(caps: string[]): boolean {
  return capsCover(caps, "access:binding:create");
}

export function canDeleteBinding(caps: string[]): boolean {
  return capsCover(caps, "access:binding:delete");
}
