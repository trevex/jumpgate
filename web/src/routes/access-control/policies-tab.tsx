/**
 * policies-tab.tsx — Access control ▸ Policies.
 *
 * A keyset-paginated table of request policies (Name, Requestable role, Scope,
 * Min approvals). Each row enriches its ids to human labels on render:
 *   - Requestable role → `getRoleDisplay` (name), short-id fallback.
 *   - Scope            → `resolveFolder` (path) for a folder scope,
 *     `getAssetDisplay` (path) for an asset scope, or a muted "role-default"
 *     when neither is set (the policy applies at the role's own level).
 * A missing name renders as a muted "—".
 *
 * Loading / empty / error use the shared state components; "Load more" appends
 * the next page. Selecting a row opens the policy detail Sheet, which shows the
 * policy's fields, manages its requester/approver subjects, and offers edit and
 * cascade-free delete.
 *
 * The list accumulates pages in local state; a `listRequestPolicies`
 * invalidation (fired by create / update / delete onSuccess) refetches the first
 * query, which re-seeds the accumulated pages so the change shows immediately.
 *
 * Mutations are capability-gated and server-enforced.
 */

import { useState, useEffect, useRef } from "react";
import { useQuery } from "@connectrpc/connect-query";
import {
  listRequestPolicies,
  getRoleDisplay,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import {
  resolveFolder,
  getAssetDisplay,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import type { RequestPolicy } from "@/gen/jumpgate/access/v1/access_pb";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { useCapabilities } from "@/lib/capabilities";
import { connectErrorMessage } from "@/lib/format";
import { NewPolicyDialog } from "./new-policy-dialog";
import { PolicyDetailSheet } from "./policy-detail";
import { canCreatePolicy } from "./policy-actions";
import { ScrollText, Plus, ShieldCheck, Folder, Boxes, Layers } from "lucide-react";

const PAGE_SIZE = 50;

function shortId(id: string): string {
  return id.split("-")[0] ?? id;
}

// ─── Requestable-role cell (enriched via getRoleDisplay) ──────────────────────

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

function ScopeCell({ policy }: { policy: RequestPolicy }) {
  if (policy.scopeFolderId) return <FolderScope folderId={policy.scopeFolderId} />;
  if (policy.scopeAssetId) return <AssetScope assetId={policy.scopeAssetId} />;
  return (
    <span className="inline-flex items-center gap-1.5 text-muted-foreground/70">
      <Layers className="h-3.5 w-3.5" aria-hidden="true" />
      role-default
    </span>
  );
}

// ─── Policies tab ─────────────────────────────────────────────────────────────

export function PoliciesTab() {
  const caps = useCapabilities();
  const showCreate = canCreatePolicy(caps);

  const [newPolicyOpen, setNewPolicyOpen] = useState(false);
  const [selected, setSelected] = useState<RequestPolicy | null>(null);
  const [pages, setPages] = useState<RequestPolicy[]>([]);
  const [nextToken, setNextToken] = useState<string>("");
  const [loadingMore, setLoadingMore] = useState(false);
  const initialised = useRef(false);

  const { data, isLoading, isError, error, refetch } = useQuery(
    listRequestPolicies,
    { roleId: "", pageSize: PAGE_SIZE, pageToken: "" },
  );

  // Seed the first page.
  useEffect(() => {
    if (data && !initialised.current) {
      initialised.current = true;
      setPages(data.policies);
      setNextToken(data.nextPageToken);
    }
  }, [data]);

  // Refresh on query invalidation — re-seed from page one.
  useEffect(() => {
    if (data && initialised.current) {
      setPages(data.policies);
      setNextToken(data.nextPageToken);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.policies]);

  const { refetch: fetchMore } = useQuery(
    listRequestPolicies,
    { roleId: "", pageSize: PAGE_SIZE, pageToken: nextToken },
    { enabled: false },
  );

  async function loadMore() {
    setLoadingMore(true);
    try {
      const result = await fetchMore();
      if (result.data) {
        setPages((prev) => [...prev, ...result.data!.policies]);
        setNextToken(result.data.nextPageToken);
      }
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <div className="flex flex-col">
      {/* Header seam — create affordance */}
      {showCreate && (
        <div className="flex items-center justify-end border-b border-border px-4 py-2.5">
          <Button
            size="sm"
            onClick={() => setNewPolicyOpen(true)}
            className="h-7 gap-1 px-3 text-[12px]"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            New policy
          </Button>
        </div>
      )}

      {isLoading ? (
        <LoadingRows />
      ) : isError ? (
        <ErrorState
          size="sm"
          message={connectErrorMessage(error)}
          onRetry={() => {
            initialised.current = false;
            refetch();
          }}
        />
      ) : pages.length === 0 ? (
        <EmptyState icon={ScrollText} message="No request policies." />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Name
                </TableHead>
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Requestable role
                </TableHead>
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Scope
                </TableHead>
                <TableHead className="h-9 px-4 text-right text-[10px] font-semibold uppercase tracking-widest">
                  Min approvals
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pages.map((policy) => (
                <TableRow
                  key={policy.id}
                  className="cursor-pointer"
                  onClick={() => setSelected(policy)}
                >
                  <TableCell className="px-4 py-2.5 font-medium text-foreground">
                    {policy.name ? (
                      <span className="truncate" title={policy.name}>
                        {policy.name}
                      </span>
                    ) : (
                      <span className="text-muted-foreground/70">—</span>
                    )}
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-foreground">
                    <RoleCell roleId={policy.roleId} />
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-muted-foreground">
                    <ScopeCell policy={policy} />
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-right">
                    <Badge
                      variant="secondary"
                      className="rounded px-1.5 py-0 text-[11px] font-semibold tabular-nums"
                    >
                      {policy.requiredApprovals}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {nextToken && (
            <div className="flex justify-center border-t border-border px-4 py-3">
              <Button
                variant="outline"
                size="sm"
                onClick={loadMore}
                disabled={loadingMore}
                className="h-7 text-[12px]"
              >
                {loadingMore ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </>
      )}

      {showCreate && (
        <NewPolicyDialog open={newPolicyOpen} onOpenChange={setNewPolicyOpen} />
      )}

      <PolicyDetailSheet
        policy={selected}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </div>
  );
}
