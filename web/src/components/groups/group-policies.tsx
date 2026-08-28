/**
 * group-policies.tsx — request policies a group is a subject of ("Policy participation").
 *
 * A read-only, keyset-paginated list of the request policies that name one group
 * as a subject (requester or approver) — `listPoliciesForGroup`. Each row shows
 * the requestable role + policy scope + a min-approvals badge, enriched to human
 * labels on render — mirroring `group-bindings.tsx`:
 *   - Role  → `getRoleDisplay` (name), fallback shortId.
 *   - Scope → `resolveFolder` (path) for a folder scope, `getAssetDisplay`
 *     (path) for an asset scope, or a muted "global" role-default when neither
 *     is set.
 *
 * Policy authoring lives on the Access-control surface; this view is read-only.
 * Loading / empty / error use the shared state components and "Load more"
 * appends the next page.
 *
 * The group's role in each policy (requester vs approver) would require a
 * per-policy ListPolicySubjects call to disambiguate, so it is intentionally
 * omitted here — the role + scope + min-approvals answer "what can this group
 * request / approve" at a glance.
 */

import { useInfiniteQuery } from "@connectrpc/connect-query";
import { listPoliciesForGroup } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { RoleLabel, ScopeLabel } from "@/components/detail/labels";
import { connectErrorMessage } from "@/lib/format";
import { Send } from "lucide-react";

const PAGE_SIZE = 50;

// ─── Requestable-via view ─────────────────────────────────────────────────────

/** Read-only list of request policies where `groupId` is a subject. */
export function GroupPolicies({ groupId }: { groupId: string }) {
  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery(
    listPoliciesForGroup,
    { groupId, pageSize: PAGE_SIZE, pageToken: "" },
    {
      pageParamKey: "pageToken",
      getNextPageParam: (last) => last.nextPageToken || undefined,
    },
  );

  const policies = data?.pages.flatMap((p) => p.policies) ?? [];

  if (isLoading) return <LoadingRows count={3} label="Loading policies" />;
  if (isError) {
    return (
      <ErrorState
        size="sm"
        message={connectErrorMessage(error)}
        onRetry={() => void refetch()}
      />
    );
  }
  if (policies.length === 0) {
    return (
      <EmptyState
        icon={Send}
        size="sm"
        message="This group isn't a subject of any request policy."
      />
    );
  }

  return (
    <div className="flex flex-col gap-1">
      <ul className="divide-y divide-border">
        {policies.map((policy) => (
          <li
            key={policy.id}
            className="flex items-center justify-between gap-3 px-1 py-2"
          >
            <RoleLabel roleId={policy.roleId} />
            <div className="flex shrink-0 items-center gap-3">
              <ScopeLabel scope={policy} />
              <Badge
                variant="secondary"
                className="rounded px-1.5 py-0 text-micro font-semibold tabular-nums"
                title="Minimum approvals"
              >
                {policy.requiredApprovals}
              </Badge>
            </div>
          </li>
        ))}
      </ul>

      {hasNextPage && (
        <div className="flex justify-center pt-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void fetchNextPage()}
            disabled={isFetchingNextPage}
            className="h-7 text-compact"
          >
            {isFetchingNextPage ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}
