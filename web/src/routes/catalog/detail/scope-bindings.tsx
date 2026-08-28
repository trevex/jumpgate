/**
 * scope-bindings.tsx — read-only role bindings scoped to one catalog node.
 *
 * A keyset-paginated list of the standing role bindings confined to a single
 * folder (`scopeFolderId`) or asset (`scopeAssetId`). Each row shows its role +
 * subject, enriched to human labels on render — mirroring the Access-control
 * Bindings table and `group-bindings.tsx`:
 *   - Role    → `getRoleDisplay` (name), fallback shortId.
 *   - Subject → `getUserDisplay` (email) for a user, or a group name resolved
 *     from a `listGroups` id→name map for a group (there is no group-display RPC).
 *
 * The scope is fixed by the caller, so it isn't repeated per row. Creating a
 * binding elsewhere invalidates `listRoleBindings`, which refetches this
 * infinite query (same schema key), so the pane self-refreshes.
 */

import { useQuery, useInfiniteQuery } from "@connectrpc/connect-query";
import { listRoleBindings } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import {
  getUserDisplay,
  listGroups,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import type { RoleBinding } from "@/gen/jumpgate/access/v1/access_pb";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { RoleLabel } from "@/components/detail/labels";
import { connectErrorMessage, shortId } from "@/lib/format";
import { User, Users, Link2 } from "lucide-react";

const PAGE_SIZE = 50;
const GROUPS_PAGE_SIZE = 100;

// ─── Subject label (user email via getUserDisplay, or group name via map) ─────

function SubjectLabel({
  binding,
  groupNames,
}: {
  binding: RoleBinding;
  groupNames: Map<string, string>;
}) {
  const { data } = useQuery(
    getUserDisplay,
    { id: binding.subjectUserId },
    { enabled: Boolean(binding.subjectUserId) },
  );

  if (binding.subjectUserId) {
    const user = data?.user;
    const label = user?.email || user?.displayName || shortId(binding.subjectUserId);
    return (
      <span className="inline-flex min-w-0 items-center gap-1.5 text-compact text-muted-foreground">
        <User className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span className="truncate" title={label}>
          {label}
        </span>
      </span>
    );
  }

  if (binding.subjectGroupId) {
    const label = groupNames.get(binding.subjectGroupId) || shortId(binding.subjectGroupId);
    return (
      <span className="inline-flex min-w-0 items-center gap-1.5 text-compact text-muted-foreground">
        <Users className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span className="truncate" title={label}>
          {label}
        </span>
      </span>
    );
  }

  return <span className="text-muted-foreground/70">—</span>;
}

// ─── Scoped-bindings view ─────────────────────────────────────────────────────

interface ScopeBindingsProps {
  /** Exactly one of these identifies the scope. */
  folderId?: string;
  assetId?: string;
  /** Empty-state copy, e.g. "No roles bound to this folder." */
  emptyMessage: string;
}

/** Read-only list of role bindings confined to one folder or asset. */
export function ScopeBindings({ folderId, assetId, emptyMessage }: ScopeBindingsProps) {
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
    {
      scopeFolderId: folderId ?? "",
      scopeAssetId: assetId ?? "",
      pageSize: PAGE_SIZE,
      pageToken: "",
    },
    {
      pageParamKey: "pageToken",
      getNextPageParam: (last) => last.nextPageToken || undefined,
    },
  );

  const bindings = data?.pages.flatMap((p) => p.bindings) ?? [];

  // Group id→name map for subject enrichment (no group-display-by-id RPC).
  const { data: groupsData } = useQuery(listGroups, {
    pageSize: GROUPS_PAGE_SIZE,
    pageToken: "",
  });
  const groupNames = new Map<string, string>();
  for (const g of groupsData?.groups ?? []) groupNames.set(g.id, g.name);

  if (isLoading) return <LoadingRows count={3} label="Loading bindings" />;
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
    return <EmptyState icon={Link2} size="sm" message={emptyMessage} />;
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
            <SubjectLabel binding={binding} groupNames={groupNames} />
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
