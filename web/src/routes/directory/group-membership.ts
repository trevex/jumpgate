/**
 * group-membership.ts — pure gating + shaping logic for group membership.
 *
 * Decides which membership affordances to offer given the caller's global
 * capabilities, and shapes a `ListGroupMembers` response into the two member
 * kinds the detail Sheet renders. The server is the real gate; these helpers
 * only govern which controls are shown and how the response is partitioned.
 *
 *   - Add member (user OR group): caller holds `identity:group:add-member`.
 *   - Remove member (user OR group): caller holds `identity:group:remove-member`.
 */

import { capsCover } from "@/lib/capabilities";
import type { User, Group } from "@/gen/jumpgate/identity/v1/identity_pb";

/** True if the caller may add a member (user or nested group) to a group. */
export function canAddMember(caps: string[]): boolean {
  return capsCover(caps, "identity:group:add-member");
}

/** True if the caller may remove a member (user or nested group) from a group. */
export function canRemoveMember(caps: string[]): boolean {
  return capsCover(caps, "identity:group:remove-member");
}

/**
 * The two member kinds a group holds. `ListGroupMembers` populates only member
 * ids for `userMembers` (email/name are enriched at render via getUserDisplay);
 * `groupMembers` already carry name/folderPath.
 */
export interface Members {
  userMembers: User[];
  groupMembers: Group[];
}

/**
 * Shapes a `ListGroupMembers` response into `{ userMembers, groupMembers }`.
 * Tolerates a partial/absent response (undefined `users`/`groups`) so callers
 * can pass `data` straight through while a query is loading.
 */
export function partitionMembers(
  resp: { users?: User[]; groups?: Group[] } | undefined,
): Members {
  return {
    userMembers: resp?.users ?? [],
    groupMembers: resp?.groups ?? [],
  };
}

/** Total member count across both kinds — for the header summary. */
export function memberCount(m: Members): number {
  return m.userMembers.length + m.groupMembers.length;
}
