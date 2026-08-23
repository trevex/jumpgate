/**
 * bindings-tab.tsx — Access control ▸ Bindings.
 *
 * A keyset-paginated table of standing role bindings (Role, Subject, Scope).
 * Each id is enriched to a human label on render:
 *   - Role    → `getRoleDisplay` (name).
 *   - Subject → `getUserDisplay` (email) when a user id is set, or the group
 *     name resolved from a `listGroups` id→name map when a group id is set
 *     (there is no group-display-by-id RPC).
 *   - Scope   → `resolveFolder` (path) for a folder scope, `getAssetDisplay`
 *     (path) for an asset scope, or a muted "global" when neither is set.
 * Any enrichment miss falls back to a short id so a row is never blank.
 *
 * Loading / empty / error use the shared state components; "Load more" appends
 * the next page. The list is a `useInfiniteQuery`; creating or deleting a
 * binding invalidates `listRoleBindings`, which refetches the infinite query
 * and TanStack merges the pages, so accumulated pages survive.
 *
 * Mutations are capability-gated and server-enforced.
 */

import { useState } from "react";
import { useQuery, useInfiniteQuery } from "@connectrpc/connect-query";
import {
  listRoleBindings,
  getRoleDisplay,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import {
  getUserDisplay,
  listGroups,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import {
  resolveFolder,
  getAssetDisplay,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import type { RoleBinding } from "@/gen/jumpgate/access/v1/access_pb";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { useCapabilities } from "@/lib/capabilities";
import { connectErrorMessage } from "@/lib/format";
import { NewBindingDialog } from "./new-binding-dialog";
import { DeleteBinding } from "./delete-binding";
import { canCreateBinding, canDeleteBinding } from "./binding-actions";
import {
  Link2,
  Plus,
  ShieldCheck,
  User,
  Users,
  Folder,
  Boxes,
  Globe,
} from "lucide-react";

const PAGE_SIZE = 50;
const GROUPS_PAGE_SIZE = 100;

function shortId(id: string): string {
  return id.split("-")[0] ?? id;
}

// ─── Role cell (enriched via getRoleDisplay) ──────────────────────────────────

function RoleCell({ roleId }: { roleId: string }) {
  const { data } = useQuery(
    getRoleDisplay,
    { id: roleId },
    { enabled: Boolean(roleId) },
  );
  const name = data?.role?.name || shortId(roleId);
  return (
    <span className="inline-flex items-center gap-1.5">
      <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="truncate font-medium text-foreground" title={name}>
        {name}
      </span>
    </span>
  );
}

// ─── Subject cell (user email via getUserDisplay, or group name via map) ──────

function SubjectCell({
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
      <span className="inline-flex items-center gap-1.5">
        <User className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span className="truncate text-foreground" title={label}>
          {label}
        </span>
      </span>
    );
  }

  if (binding.subjectGroupId) {
    const label = groupNames.get(binding.subjectGroupId) || shortId(binding.subjectGroupId);
    return (
      <span className="inline-flex items-center gap-1.5">
        <Users className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span className="truncate text-foreground" title={label}>
          {label}
        </span>
      </span>
    );
  }

  return <span className="text-muted-foreground/70">—</span>;
}

// ─── Scope cell (folder path via resolveFolder, asset path via getAssetDisplay) ─

function FolderScope({ folderId }: { folderId: string }) {
  const { data } = useQuery(resolveFolder, { ref: folderId }, { enabled: true });
  const path = data?.path || shortId(folderId);
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[12px]">
      <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
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
    <span className="inline-flex items-center gap-1.5 font-mono text-[12px]">
      <Boxes className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="truncate" title={path}>
        {path}
      </span>
    </span>
  );
}

function ScopeCell({ binding }: { binding: RoleBinding }) {
  if (binding.scopeFolderId) return <FolderScope folderId={binding.scopeFolderId} />;
  if (binding.scopeAssetId) return <AssetScope assetId={binding.scopeAssetId} />;
  return (
    <span className="inline-flex items-center gap-1.5 text-muted-foreground/70">
      <Globe className="h-3.5 w-3.5" aria-hidden="true" />
      global
    </span>
  );
}

// ─── Bindings tab ─────────────────────────────────────────────────────────────

export function BindingsTab() {
  const caps = useCapabilities();
  const showCreate = canCreateBinding(caps);
  const canDelete = canDeleteBinding(caps);

  const [newBindingOpen, setNewBindingOpen] = useState(false);

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
    { pageSize: PAGE_SIZE, pageToken: "" },
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

  return (
    <div className="flex flex-col">
      {/* Header seam — create affordance */}
      {showCreate && (
        <div className="flex items-center justify-end border-b border-border px-4 py-2.5">
          <Button
            size="sm"
            onClick={() => setNewBindingOpen(true)}
            className="h-7 gap-1 px-3 text-[12px]"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            New binding
          </Button>
        </div>
      )}

      {isLoading ? (
        <LoadingRows />
      ) : isError ? (
        <ErrorState
          size="sm"
          message={connectErrorMessage(error)}
          onRetry={() => refetch()}
        />
      ) : bindings.length === 0 ? (
        <EmptyState icon={Link2} message="No bindings." />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Role
                </TableHead>
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Subject
                </TableHead>
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Scope
                </TableHead>
                <TableHead className="h-9 w-10 px-4" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {bindings.map((binding) => (
                <TableRow key={binding.id} className="hover:bg-muted/40">
                  <TableCell className="px-4 py-2.5 text-foreground">
                    <RoleCell roleId={binding.roleId} />
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-muted-foreground">
                    <SubjectCell binding={binding} groupNames={groupNames} />
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-muted-foreground">
                    <ScopeCell binding={binding} />
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-right">
                    {canDelete && <DeleteBinding binding={binding} />}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {hasNextPage && (
            <div className="flex justify-center border-t border-border px-4 py-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => fetchNextPage()}
                disabled={isFetchingNextPage}
                className="h-7 text-[12px]"
              >
                {isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </>
      )}

      {showCreate && (
        <NewBindingDialog open={newBindingOpen} onOpenChange={setNewBindingOpen} />
      )}
    </div>
  );
}
