/**
 * asset-policies.tsx — request policies scoped to one asset ("Requestable via").
 *
 * A read-only, keyset-paginated list of the request policies whose scope is this
 * asset (`listPoliciesForAsset`). Each row shows the requestable role + a min-
 * approvals badge, enriched to a human label on render — mirroring the
 * Access-control Policies table:
 *   - Role → `getRoleDisplay` (name), fallback shortId.
 *
 * Policy authoring lives on the asset's "Make requestable" affordance; this view
 * is read-only. Loading / empty / error use the shared state components and
 * "Load more" appends the next page.
 */

import { useQuery, useInfiniteQuery } from "@connectrpc/connect-query";
import {
  listPoliciesForAsset,
  getRoleDisplay,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { connectErrorMessage, shortId } from "@/lib/format";
import { ShieldCheck, Send } from "lucide-react";

const PAGE_SIZE = 50;

// ─── Role label (enriched via getRoleDisplay) ─────────────────────────────────

function RoleLabel({ roleId }: { roleId: string }) {
  const { data } = useQuery(
    getRoleDisplay,
    { id: roleId },
    { enabled: Boolean(roleId) },
  );
  const name = data?.role?.name || shortId(roleId);
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5">
      <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="truncate font-medium text-foreground" title={name}>
        {name}
      </span>
    </span>
  );
}

// ─── Requestable-via view ─────────────────────────────────────────────────────

/** Read-only list of request policies scoped to `assetId`. */
export function AssetPolicies({ assetId }: { assetId: string }) {
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
    listPoliciesForAsset,
    { assetId, pageSize: PAGE_SIZE, pageToken: "" },
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
    return <EmptyState icon={Send} size="sm" message="Not requestable yet." />;
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
            <span className="inline-flex shrink-0 items-center gap-1.5 text-compact text-muted-foreground">
              <span className="text-eyebrow uppercase tracking-wide">Min approvals</span>
              <Badge
                variant="secondary"
                className="rounded px-1.5 py-0 text-micro font-semibold tabular-nums"
              >
                {policy.requiredApprovals}
              </Badge>
            </span>
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
