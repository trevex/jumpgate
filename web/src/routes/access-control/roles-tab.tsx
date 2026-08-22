/**
 * roles-tab.tsx — Access control ▸ Roles.
 *
 * A keyset-paginated table of roles (Name, Scope, Capabilities). Scope shows
 * the role's folder path, or a muted "global" when the role has no folder.
 * Capabilities is a count badge (the full list lives in the detail Sheet).
 * Loading / empty / error use the shared state components; "Load more" appends
 * the next page.
 *
 * Selecting a row opens the role detail Sheet (`role-detail.tsx`), which shows
 * the role's capabilities as chips and manages its grant edges, and offers the
 * cascade delete.
 *
 * Mutations are capability-gated and server-enforced. The list accumulates
 * pages in local state; a `listRoles` invalidation (fired by create/delete
 * onSuccess) refetches the first query, which re-seeds the accumulated pages so
 * the change is reflected immediately.
 */

import { useState, useEffect, useRef } from "react";
import { useQuery } from "@connectrpc/connect-query";
import { listRoles } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import type { Role } from "@/gen/jumpgate/access/v1/access_pb";
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
import { NewRoleDialog } from "./new-role-dialog";
import { RoleDetailSheet } from "./role-detail";
import { canCreateRole } from "./role-actions";
import { ShieldCheck, Plus, Globe } from "lucide-react";

const PAGE_SIZE = 50;

// ─── Scope cell ───────────────────────────────────────────────────────────────

function RoleScope({ role }: { role: Role }) {
  if (!role.folderPath) {
    return (
      <span className="inline-flex items-center gap-1.5 text-muted-foreground/70">
        <Globe className="h-3.5 w-3.5" aria-hidden="true" />
        global
      </span>
    );
  }
  return <span className="font-mono text-[12px]">{role.folderPath}</span>;
}

// ─── Roles tab ────────────────────────────────────────────────────────────────

export function RolesTab() {
  const caps = useCapabilities();
  const showCreate = canCreateRole(caps);

  const [newRoleOpen, setNewRoleOpen] = useState(false);
  const [selected, setSelected] = useState<Role | null>(null);
  const [pages, setPages] = useState<Role[]>([]);
  const [nextToken, setNextToken] = useState<string>("");
  const [loadingMore, setLoadingMore] = useState(false);
  const initialised = useRef(false);

  const { data, isLoading, isError, error, refetch } = useQuery(listRoles, {
    pageSize: PAGE_SIZE,
    pageToken: "",
  });

  // Seed the first page.
  useEffect(() => {
    if (data && !initialised.current) {
      initialised.current = true;
      setPages(data.roles);
      setNextToken(data.nextPageToken);
    }
  }, [data]);

  // Refresh on query invalidation — a mutation's onSuccess invalidates listRoles,
  // which refetches this query; re-seed the accumulated pages from page one.
  useEffect(() => {
    if (data && initialised.current) {
      setPages(data.roles);
      setNextToken(data.nextPageToken);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.roles]);

  const { refetch: fetchMore } = useQuery(
    listRoles,
    { pageSize: PAGE_SIZE, pageToken: nextToken },
    { enabled: false },
  );

  async function loadMore() {
    setLoadingMore(true);
    try {
      const result = await fetchMore();
      if (result.data) {
        setPages((prev) => [...prev, ...result.data!.roles]);
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
            onClick={() => setNewRoleOpen(true)}
            className="h-7 gap-1 px-3 text-[12px]"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            New role
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
        <EmptyState icon={ShieldCheck} message="No roles." />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Name
                </TableHead>
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Scope
                </TableHead>
                <TableHead className="h-9 px-4 text-right text-[10px] font-semibold uppercase tracking-widest">
                  Capabilities
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pages.map((role) => (
                <TableRow
                  key={role.id}
                  className="cursor-pointer"
                  onClick={() => setSelected(role)}
                >
                  <TableCell className="px-4 py-2.5 font-medium text-foreground">
                    <span className="truncate" title={role.name}>
                      {role.name}
                    </span>
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-muted-foreground">
                    <RoleScope role={role} />
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-right">
                    <Badge
                      variant="secondary"
                      className="rounded px-1.5 py-0 text-[11px] font-semibold tabular-nums"
                    >
                      {role.capabilities.length}
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
        <NewRoleDialog open={newRoleOpen} onOpenChange={setNewRoleOpen} />
      )}

      <RoleDetailSheet
        role={selected}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </div>
  );
}
