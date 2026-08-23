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

import { useQuery, useInfiniteQuery } from "@connectrpc/connect-query";
import {
  listRoleBindings,
  getRoleDisplay,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import {
  resolveFolder,
  getAssetDisplay,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import type { RoleBinding } from "@/gen/jumpgate/access/v1/access_pb";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { connectErrorMessage, shortId } from "@/lib/format";
import { ShieldCheck, Folder, Boxes, Globe, Link2 } from "lucide-react";

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

// ─── Scope label (folder path / asset path / global) ──────────────────────────

function FolderScope({ folderId }: { folderId: string }) {
  const { data } = useQuery(resolveFolder, { ref: folderId }, { enabled: true });
  const path = data?.path || shortId(folderId);
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5 font-mono text-compact text-muted-foreground">
      <Folder className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span className="truncate" title={path}>
        {path}
      </span>
    </span>
  );
}

function AssetScope({ assetId }: { assetId: string }) {
  const { data } = useQuery(getAssetDisplay, { assetId }, { enabled: true });
  const path = data?.asset?.path || data?.asset?.name || shortId(assetId);
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5 font-mono text-compact text-muted-foreground">
      <Boxes className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span className="truncate" title={path}>
        {path}
      </span>
    </span>
  );
}

function ScopeLabel({ binding }: { binding: RoleBinding }) {
  if (binding.scopeFolderId) return <FolderScope folderId={binding.scopeFolderId} />;
  if (binding.scopeAssetId) return <AssetScope assetId={binding.scopeAssetId} />;
  return (
    <span className="inline-flex shrink-0 items-center gap-1.5 text-compact text-muted-foreground">
      <Globe className="h-3.5 w-3.5" aria-hidden="true" />
      global
    </span>
  );
}

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
            <ScopeLabel binding={binding} />
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
