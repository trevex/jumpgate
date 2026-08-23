/**
 * group-policies.tsx — request policies a group is a subject of ("Requestable via").
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

import { useQuery, useInfiniteQuery } from "@connectrpc/connect-query";
import {
  listPoliciesForGroup,
  getRoleDisplay,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import {
  resolveFolder,
  getAssetDisplay,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import type { RequestPolicy } from "@/gen/jumpgate/access/v1/access_pb";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { connectErrorMessage, shortId } from "@/lib/format";
import { ShieldCheck, Folder, Boxes, Globe, Send } from "lucide-react";

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

// ─── Scope label (folder path / asset path / role-default) ────────────────────

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

function ScopeLabel({ policy }: { policy: RequestPolicy }) {
  if (policy.scopeFolderId) return <FolderScope folderId={policy.scopeFolderId} />;
  if (policy.scopeAssetId) return <AssetScope assetId={policy.scopeAssetId} />;
  return (
    <span className="inline-flex shrink-0 items-center gap-1.5 text-compact text-muted-foreground">
      <Globe className="h-3.5 w-3.5" aria-hidden="true" />
      global
    </span>
  );
}

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
              <ScopeLabel policy={policy} />
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
