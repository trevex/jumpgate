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
 * Mutations are capability-gated and server-enforced. The list is a
 * `useInfiniteQuery`; "Load more" appends the next page. A `listRoles`
 * invalidation (fired by create/delete onSuccess) refetches the infinite query
 * and TanStack merges the pages, so accumulated pages survive.
 */

import { useState } from "react";
import { useInfiniteQuery } from "@connectrpc/connect-query";
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
    listRoles,
    { pageSize: PAGE_SIZE, pageToken: "" },
    {
      pageParamKey: "pageToken",
      getNextPageParam: (last) => last.nextPageToken || undefined,
    },
  );

  const roles = data?.pages.flatMap((p) => p.roles) ?? [];

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
          onRetry={() => refetch()}
        />
      ) : roles.length === 0 ? (
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
              {roles.map((role) => (
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
        <NewRoleDialog open={newRoleOpen} onOpenChange={setNewRoleOpen} />
      )}

      <RoleDetailSheet
        role={selected}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </div>
  );
}
