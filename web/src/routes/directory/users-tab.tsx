/**
 * users-tab.tsx — Directory ▸ Users.
 *
 * A keyset-paginated table of directory users (Email, Display name, Status).
 * Status reflects `User.active` (deactivation state) via a colour-coded badge.
 * Loading / empty / error use the shared state components; "Load more" appends
 * the next page.
 *
 * Mutations (capability-gated, server-enforced):
 *   - "New user" (header, `identity:user:create`) opens a create dialog.
 *   - Per-row menu offers Deactivate / Reactivate / Delete — gated by cap and
 *     row state, with a self-guard (never Deactivate or Delete your own row, to
 *     avoid locking yourself out). Deactivate and Delete confirm via a modal.
 *
 * The list accumulates pages in local state; a `listUsers` invalidation (fired
 * by every mutation's onSuccess) refetches the first query, which re-seeds the
 * accumulated pages so the change is reflected immediately.
 */

import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation } from "@connectrpc/connect-query";
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  listUsers,
  deactivateUser,
  reactivateUser,
  deleteUser,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import type { User } from "@/gen/jumpgate/identity/v1/identity_pb";
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
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { NewUserDialog } from "./new-user-dialog";
import { userRowActions, canCreateUser } from "./user-actions";
import { useCapabilities } from "@/lib/capabilities";
import { useWhoAmI } from "@/auth";
import { cn } from "@/lib/utils";
import { connectErrorMessage } from "@/lib/format";
import { Users, MoreHorizontal, Plus, UserMinus, UserCheck, Trash2 } from "lucide-react";

const PAGE_SIZE = 50;

// ─── Status badge ─────────────────────────────────────────────────────────────

function UserStatusBadge({ active }: { active: boolean }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "rounded px-1.5 py-0 text-[10px] font-semibold uppercase tracking-wide border",
        active
          ? "border-green-300 bg-green-50 text-green-700 dark:border-green-500/30 dark:bg-green-500/10 dark:text-green-300"
          : "border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-500/30 dark:bg-slate-500/10 dark:text-slate-300",
      )}
    >
      {active ? "Active" : "Deactivated"}
    </Badge>
  );
}

// ─── Row actions ──────────────────────────────────────────────────────────────

function useInvalidateUsers() {
  const queryClient = useQueryClient();
  return () =>
    void queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({ schema: listUsers, cardinality: undefined }),
    });
}

interface UserRowActionsProps {
  user: User;
  isSelf: boolean;
}

function UserRowActionsCell({ user, isSelf }: UserRowActionsProps) {
  const caps = useCapabilities();
  const invalidateUsers = useInvalidateUsers();

  const [deactivateOpen, setDeactivateOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const { canDeactivate, canReactivate, canDelete } = userRowActions(
    caps,
    user,
    isSelf,
  );

  const label = user.displayName || user.email;

  const { mutate: doDeactivate, isPending: deactivating } = useMutation(deactivateUser, {
    onSuccess: () => {
      toast.success("User deactivated", {
        description: `${label} can no longer sign in; live sessions terminated.`,
      });
      invalidateUsers();
      setDeactivateOpen(false);
    },
    onError: (err) => toast.error("Deactivate failed", { description: connectErrorMessage(err) }),
  });

  const { mutate: doReactivate, isPending: reactivating } = useMutation(reactivateUser, {
    onSuccess: () => {
      toast.success("User reactivated", { description: `${label} can sign in again.` });
      invalidateUsers();
    },
    onError: (err) => toast.error("Reactivate failed", { description: connectErrorMessage(err) }),
  });

  const { mutate: doDelete, isPending: deleting } = useMutation(deleteUser, {
    onSuccess: () => {
      toast.success("User deleted", { description: `${label} was permanently removed.` });
      invalidateUsers();
      setDeleteOpen(false);
    },
    onError: (err) => toast.error("Delete failed", { description: connectErrorMessage(err) }),
  });

  const hasAnyAction = canDeactivate || canReactivate || canDelete;
  if (!hasAnyAction) {
    // Nothing offered — keep the column aligned with an em-dash placeholder.
    return <span className="text-muted-foreground/40" aria-hidden="true">—</span>;
  }

  const busy = reactivating || deactivating || deleting;

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground hover:text-foreground"
            aria-label={`Actions for ${label}`}
            disabled={busy}
          >
            <MoreHorizontal className="h-4 w-4" aria-hidden="true" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-44">
          {canReactivate && (
            <DropdownMenuItem
              onSelect={() => doReactivate({ userId: user.id })}
              className="text-[13px]"
            >
              <UserCheck className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
              Reactivate
            </DropdownMenuItem>
          )}
          {canDeactivate && (
            <DropdownMenuItem
              onSelect={() => setDeactivateOpen(true)}
              className="text-[13px]"
            >
              <UserMinus className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
              Deactivate
            </DropdownMenuItem>
          )}
          {canDelete && (
            <DropdownMenuItem
              onSelect={() => setDeleteOpen(true)}
              className="text-[13px] text-destructive focus:text-destructive"
            >
              <Trash2 className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
              Delete
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      <ConfirmDialog
        open={deactivateOpen}
        onOpenChange={setDeactivateOpen}
        title="Deactivate user?"
        description={
          <>
            This blocks{" "}
            <span className="font-medium text-foreground">{label}</span> from
            signing in and immediately terminates their live sessions. You can
            reactivate them later.
          </>
        }
        confirmLabel="Deactivate"
        pendingLabel="Deactivating…"
        confirmAriaLabel={`Confirm deactivate ${label}`}
        pending={deactivating}
        onConfirm={() => doDeactivate({ userId: user.id })}
      />

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete user?"
        description={
          <>
            This permanently deletes{" "}
            <span className="font-medium text-foreground">{label}</span> and
            cannot be undone.
          </>
        }
        confirmLabel="Delete"
        pendingLabel="Deleting…"
        variant="destructive"
        confirmAriaLabel={`Confirm delete ${label}`}
        pending={deleting}
        onConfirm={() => doDelete({ userId: user.id })}
      />
    </>
  );
}

// ─── Users tab ────────────────────────────────────────────────────────────────

export function UsersTab() {
  const caps = useCapabilities();
  const selfId = useWhoAmI().data?.userId ?? "";
  const showCreate = canCreateUser(caps);

  const [newUserOpen, setNewUserOpen] = useState(false);
  const [pages, setPages] = useState<User[]>([]);
  const [nextToken, setNextToken] = useState<string>("");
  const [loadingMore, setLoadingMore] = useState(false);
  const initialised = useRef(false);

  const { data, isLoading, isError, error, refetch } = useQuery(listUsers, {
    pageSize: PAGE_SIZE,
    pageToken: "",
  });

  // Seed the first page
  useEffect(() => {
    if (data && !initialised.current) {
      initialised.current = true;
      setPages(data.users);
      setNextToken(data.nextPageToken);
    }
  }, [data]);

  // Refresh on query invalidation — a mutation's onSuccess invalidates listUsers,
  // which refetches this query; re-seed the accumulated pages from page one.
  useEffect(() => {
    if (data && initialised.current) {
      setPages(data.users);
      setNextToken(data.nextPageToken);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.users]);

  const { refetch: fetchMore } = useQuery(
    listUsers,
    { pageSize: PAGE_SIZE, pageToken: nextToken },
    { enabled: false },
  );

  async function loadMore() {
    setLoadingMore(true);
    try {
      const result = await fetchMore();
      if (result.data) {
        setPages((prev) => [...prev, ...result.data!.users]);
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
            onClick={() => setNewUserOpen(true)}
            className="h-7 gap-1 px-3 text-[12px]"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            New user
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
        <EmptyState icon={Users} message="No users." />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Email
                </TableHead>
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Display name
                </TableHead>
                <TableHead className="h-9 px-4 text-right text-[10px] font-semibold uppercase tracking-widest">
                  Status
                </TableHead>
                <TableHead className="h-9 w-12 px-4 text-right text-[10px] font-semibold uppercase tracking-widest">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pages.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="px-4 py-2.5 font-medium text-foreground">
                    <span className="truncate" title={user.email}>
                      {user.email}
                    </span>
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-muted-foreground">
                    {user.displayName || (
                      <span className="text-muted-foreground/50">—</span>
                    )}
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-right">
                    <UserStatusBadge active={user.active} />
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-right">
                    <UserRowActionsCell user={user} isSelf={user.id === selfId} />
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
        <NewUserDialog open={newUserOpen} onOpenChange={setNewUserOpen} />
      )}
    </div>
  );
}
