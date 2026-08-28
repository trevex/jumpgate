/**
 * group-bindings.tsx — role bindings where a group is the subject.
 *
 * A read-only, keyset-paginated list of the standing role bindings that name
 * one group as their subject (`listRoleBindings` filtered by subjectGroupId).
 * Each binding shows its role + scope, enriched to human labels on render —
 * mirroring the Access-control Bindings table:
 *   - Role  → `getRoleDisplay` (name), fallback shortId.
 *   - Scope → `resolveFolder` (path) for a folder scope, `getAssetDisplay`
 *     (path) for an asset scope, or a muted "global" when neither is set.
 *
 * Creating a binding lives on the Access-control surface; this view is
 * read-only. Loading / empty / error use the shared state components and
 * "Load more" appends the next page.
 */

import { useInfiniteQuery } from "@connectrpc/connect-query";
import { listRoleBindings } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { RoleLabel, ScopeLabel } from "@/components/detail/labels";
import { connectErrorMessage } from "@/lib/format";
import { Link2 } from "lucide-react";

const PAGE_SIZE = 50;

// ─── Bound-roles view ─────────────────────────────────────────────────────────

/** Read-only list of role bindings where `groupId` is the subject. */
export function GroupBindings({ groupId }: { groupId: string }) {
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
    listRoleBindings,
    { subjectGroupId: groupId, pageSize: PAGE_SIZE, pageToken: "" },
    {
      pageParamKey: "pageToken",
      getNextPageParam: (last) => last.nextPageToken || undefined,
    },
  );

  const bindings = data?.pages.flatMap((p) => p.bindings) ?? [];

  if (isLoading) return <LoadingRows count={3} label="Loading bound roles" />;
  if (isError) {
    return (
      <ErrorState
        size="sm"
        message={connectErrorMessage(error)}
        onRetry={() => void refetch()}
      />
    );
  }
  if (bindings.length === 0) {
    return (
      <EmptyState icon={Link2} size="sm" message="No roles bound to this group." />
    );
  }

  return (
    <div className="flex flex-col gap-1">
      <ul className="divide-y divide-border">
        {bindings.map((binding) => (
          <li
            key={binding.id}
            className="flex items-center justify-between gap-3 px-1 py-2"
          >
            <RoleLabel roleId={binding.roleId} />
            <ScopeLabel scope={binding} />
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
