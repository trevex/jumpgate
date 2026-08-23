/**
 * groups-tab.tsx — Directory ▸ Groups.
 *
 * A keyset-paginated table of directory groups (Name, Home). Home shows the
 * group's folder path, or a muted "global" when the group has no folder home.
 * Loading / empty / error use the shared state components; "Load more" appends
 * the next page.
 *
 * Selecting a row opens the group detail Sheet (`group-detail.tsx`), which shows
 * the group's name/home and manages its membership (users + nested sub-groups).
 *
 * Mutations (capability-gated, server-enforced):
 *   - "New group" (header, `identity:group:create`) opens a create dialog.
 *   - Per-row menu offers Delete — gated by `identity:group:delete`, confirmed
 *     via a modal.
 *
 * The list is a `useInfiniteQuery`; "Load more" appends the next page. A
 * `listGroups` invalidation (fired by every mutation's onSuccess) refetches the
 * infinite query and TanStack merges the pages, so accumulated pages survive.
 */

import { useState } from "react";
import { useInfiniteQuery, useMutation } from "@connectrpc/connect-query";
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
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { NewGroupDialog } from "./new-group-dialog";
import { GroupDetailSheet } from "./group-detail";
import { canCreateGroup, canDeleteGroup } from "./group-actions";
import { useCapabilities } from "@/lib/capabilities";
import { connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";
import { UsersRound, MoreHorizontal, Plus, Trash2, Globe } from "lucide-react";

const PAGE_SIZE = 50;

// ─── Row actions ──────────────────────────────────────────────────────────────

interface GroupRowActionsProps {
  group: Group;
}

function GroupRowActionsCell({ group }: GroupRowActionsProps) {
  const caps = useCapabilities();
  const invalidateList = useInvalidateList();
  const [deleteOpen, setDeleteOpen] = useState(false);

  const canDelete = canDeleteGroup(caps);

  const { mutate: doDelete, isPending: deleting } = useMutation(deleteGroup, {
    onSuccess: () => {
      toast.success("Group deleted", {
        description: `${group.name} was permanently removed.`,
      });
      void invalidateList(listGroups);
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

// ─── Groups tab ───────────────────────────────────────────────────────────────

export function GroupsTab() {
  const caps = useCapabilities();
  const showCreate = canCreateGroup(caps);

  const [newGroupOpen, setNewGroupOpen] = useState(false);
  const [selected, setSelected] = useState<Group | null>(null);

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
    listGroups,
    { pageSize: PAGE_SIZE, pageToken: "" },
    {
      pageParamKey: "pageToken",
      getNextPageParam: (last) => last.nextPageToken || undefined,
    },
  );

  const groups = data?.pages.flatMap((p) => p.groups) ?? [];

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
          onRetry={() => refetch()}
        />
      ) : groups.length === 0 ? (
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
              {groups.map((group) => (
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
        <NewGroupDialog open={newGroupOpen} onOpenChange={setNewGroupOpen} />
      )}

      <GroupDetailSheet
        group={selected}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </div>
  );
}
