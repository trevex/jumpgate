/**
 * groups-tab.tsx — Directory ▸ Groups.
 *
 * A keyset-paginated table of directory groups (Name, Home). Home shows the
 * group's folder path, or a muted "global" when the group has no folder home.
 * Loading / empty / error use the shared state components; "Load more" appends
 * the next page.
 *
 * Selecting a row opens a detail Sheet showing the group's name and home.
 * Membership management lands in a later task — the detail reserves that seam.
 *
 * Mutations (capability-gated, server-enforced):
 *   - "New group" (header, `identity:group:create`) opens a create dialog.
 *   - Per-row menu offers Delete — gated by `identity:group:delete`, confirmed
 *     via a modal.
 *
 * The list accumulates pages in local state; a `listGroups` invalidation (fired
 * by every mutation's onSuccess) refetches the first query, which re-seeds the
 * accumulated pages so the change is reflected immediately.
 */

import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation } from "@connectrpc/connect-query";
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  listGroups,
  deleteGroup,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import type { Group } from "@/gen/jumpgate/identity/v1/identity_pb";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { NewGroupDialog } from "./new-group-dialog";
import { canCreateGroup, canDeleteGroup } from "./group-actions";
import { useCapabilities } from "@/lib/capabilities";
import { connectErrorMessage } from "@/lib/format";
import { UsersRound, MoreHorizontal, Plus, Trash2, Globe } from "lucide-react";

const PAGE_SIZE = 50;

// ─── Row actions ──────────────────────────────────────────────────────────────

function useInvalidateGroups() {
  const queryClient = useQueryClient();
  return () =>
    void queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({ schema: listGroups, cardinality: undefined }),
    });
}

interface GroupRowActionsProps {
  group: Group;
}

function GroupRowActionsCell({ group }: GroupRowActionsProps) {
  const caps = useCapabilities();
  const invalidateGroups = useInvalidateGroups();
  const [deleteOpen, setDeleteOpen] = useState(false);

  const canDelete = canDeleteGroup(caps);

  const { mutate: doDelete, isPending: deleting } = useMutation(deleteGroup, {
    onSuccess: () => {
      toast.success("Group deleted", {
        description: `${group.name} was permanently removed.`,
      });
      invalidateGroups();
      setDeleteOpen(false);
    },
    onError: (err) => toast.error("Delete failed", { description: connectErrorMessage(err) }),
  });

  if (!canDelete) {
    // Nothing offered — keep the column aligned with an em-dash placeholder.
    return <span className="text-muted-foreground/40" aria-hidden="true">—</span>;
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground hover:text-foreground"
            aria-label={`Actions for ${group.name}`}
            disabled={deleting}
            // Don't open the detail Sheet when interacting with the menu.
            onClick={(e) => e.stopPropagation()}
          >
            <MoreHorizontal className="h-4 w-4" aria-hidden="true" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          align="end"
          className="w-44"
          onClick={(e) => e.stopPropagation()}
        >
          <DropdownMenuItem
            onSelect={() => setDeleteOpen(true)}
            className="text-[13px] text-destructive focus:text-destructive"
          >
            <Trash2 className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
            Delete
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete group?"
        description={
          <>
            This permanently deletes the group{" "}
            <span className="font-medium text-foreground">{group.name}</span> and
            its bindings and governance. Members are not deleted — only their
            membership in this group is removed. This cannot be undone.
          </>
        }
        confirmLabel="Delete"
        pendingLabel="Deleting…"
        variant="destructive"
        confirmAriaLabel={`Confirm delete ${group.name}`}
        pending={deleting}
        onConfirm={() => doDelete({ groupId: group.id })}
      />
    </>
  );
}

// ─── Home cell ────────────────────────────────────────────────────────────────

function GroupHome({ group }: { group: Group }) {
  if (!group.folderPath) {
    return (
      <span className="inline-flex items-center gap-1.5 text-muted-foreground/70">
        <Globe className="h-3.5 w-3.5" aria-hidden="true" />
        global
      </span>
    );
  }
  return <span className="font-mono text-[12px]">{group.folderPath}</span>;
}

// ─── Detail Sheet (stub — membership lands in a later task) ────────────────────

function GroupDetailSheet({
  group,
  onOpenChange,
}: {
  group: Group | null;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Sheet open={group !== null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-md">
        {group && (
          <>
            <SheetHeader>
              <SheetTitle className="text-[15px]">{group.name}</SheetTitle>
              <SheetDescription className="text-[13px]">
                {group.folderPath ? (
                  <>
                    Governed under{" "}
                    <span className="font-mono text-foreground">
                      {group.folderPath}
                    </span>
                    .
                  </>
                ) : (
                  <>A global group.</>
                )}
              </SheetDescription>
            </SheetHeader>

            <div className="mt-6 rounded-md border border-dashed border-border px-4 py-8 text-center">
              <UsersRound
                className="mx-auto h-8 w-8 text-muted-foreground/25"
                aria-hidden="true"
              />
              <p className="mt-3 text-[13px] font-medium text-foreground">
                Members
              </p>
              <p className="mt-1 text-[12px] text-muted-foreground">
                Membership management is coming soon.
              </p>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

// ─── Groups tab ───────────────────────────────────────────────────────────────

export function GroupsTab() {
  const caps = useCapabilities();
  const showCreate = canCreateGroup(caps);

  const [newGroupOpen, setNewGroupOpen] = useState(false);
  const [selected, setSelected] = useState<Group | null>(null);
  const [pages, setPages] = useState<Group[]>([]);
  const [nextToken, setNextToken] = useState<string>("");
  const [loadingMore, setLoadingMore] = useState(false);
  const initialised = useRef(false);

  const { data, isLoading, isError, error, refetch } = useQuery(listGroups, {
    pageSize: PAGE_SIZE,
    pageToken: "",
  });

  // Seed the first page
  useEffect(() => {
    if (data && !initialised.current) {
      initialised.current = true;
      setPages(data.groups);
      setNextToken(data.nextPageToken);
    }
  }, [data]);

  // Refresh on query invalidation — a mutation's onSuccess invalidates listGroups,
  // which refetches this query; re-seed the accumulated pages from page one.
  useEffect(() => {
    if (data && initialised.current) {
      setPages(data.groups);
      setNextToken(data.nextPageToken);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.groups]);

  const { refetch: fetchMore } = useQuery(
    listGroups,
    { pageSize: PAGE_SIZE, pageToken: nextToken },
    { enabled: false },
  );

  async function loadMore() {
    setLoadingMore(true);
    try {
      const result = await fetchMore();
      if (result.data) {
        setPages((prev) => [...prev, ...result.data!.groups]);
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
            onClick={() => setNewGroupOpen(true)}
            className="h-7 gap-1 px-3 text-[12px]"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            New group
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
        <EmptyState icon={UsersRound} message="No groups." />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Name
                </TableHead>
                <TableHead className="h-9 px-4 text-[10px] font-semibold uppercase tracking-widest">
                  Home
                </TableHead>
                <TableHead className="h-9 w-12 px-4 text-right text-[10px] font-semibold uppercase tracking-widest">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pages.map((group) => (
                <TableRow
                  key={group.id}
                  className="cursor-pointer"
                  onClick={() => setSelected(group)}
                >
                  <TableCell className="px-4 py-2.5 font-medium text-foreground">
                    <span className="truncate" title={group.name}>
                      {group.name}
                    </span>
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-muted-foreground">
                    <GroupHome group={group} />
                  </TableCell>
                  <TableCell className="px-4 py-2.5 text-right">
                    <GroupRowActionsCell group={group} />
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
        <NewGroupDialog open={newGroupOpen} onOpenChange={setNewGroupOpen} />
      )}

      <GroupDetailSheet
        group={selected}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </div>
  );
}
