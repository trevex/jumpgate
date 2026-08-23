/**
 * add-member-picker.tsx — Directory ▸ Groups ▸ detail ▸ add member.
 *
 * A cmdk command dialog for adding a member to a group, with a User | Group
 * segmented toggle:
 *   - User  → lists directory users (`listUsers`), client-filtered by email or
 *     display name on the typed query → `addUserToGroup({ groupId, userId })`.
 *   - Group → lists directory groups (`listGroups`), client-filtered by name and
 *     excluding the current group itself → `addGroupToGroup({ groupId,
 *     memberGroupId })`.
 *
 * On success: invalidate the group's members query (scoped) + toast + close.
 * On error: `toast.error(connectErrorMessage(err))` — this surfaces the server's
 * cycle / AlreadyExists rejections for nested groups.
 *
 * Both lists fetch a single page (client-side filtering keeps the picker snappy
 * for the common small-directory case; server-side member search is a follow-up
 * if directories grow large).
 */

import { useEffect, useState } from "react";
import { useQuery, useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { User as UserIcon, Users as UsersIcon, Loader2, Globe } from "lucide-react";
import {
  listUsers,
  listGroups,
  addUserToGroup,
  addGroupToGroup,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import type { Group } from "@/gen/jumpgate/identity/v1/identity_pb";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@/components/ui/command";
import { cn } from "@/lib/utils";
import { connectErrorMessage } from "@/lib/format";
import { membersQueryKey } from "./group-detail";

const LIST_PAGE_SIZE = 50;

type Kind = "user" | "group";

interface AddMemberPickerProps {
  /** The group being edited — members are added to this group. */
  group: Group;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function AddMemberPicker({ group, open, onOpenChange }: AddMemberPickerProps) {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<Kind>("user");
  const [query, setQuery] = useState("");

  // Reset to a clean slate each time the dialog opens.
  useEffect(() => {
    if (open) {
      setKind("user");
      setQuery("");
    }
  }, [open]);

  function invalidateMembers() {
    const key = membersQueryKey(group.id);
    void queryClient
      .cancelQueries({ queryKey: key })
      .then(() => queryClient.invalidateQueries({ queryKey: key }));
  }

  const { mutate: doAddUser, isPending: addingUser } = useMutation(addUserToGroup, {
    onSuccess: () => {
      toast.success("Member added", {
        description: `Added a user to ${group.name}.`,
      });
      invalidateMembers();
      onOpenChange(false);
    },
    onError: (err) => toast.error("Add failed", { description: connectErrorMessage(err) }),
  });

  const { mutate: doAddGroup, isPending: addingGroup } = useMutation(addGroupToGroup, {
    onSuccess: () => {
      toast.success("Sub-group added", {
        description: `Added a sub-group to ${group.name}.`,
      });
      invalidateMembers();
      onOpenChange(false);
    },
    onError: (err) => toast.error("Add failed", { description: connectErrorMessage(err) }),
  });

  const busy = addingUser || addingGroup;

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      label={`Add member to ${group.name}`}
      // Client-side filtering is done below; cmdk's own filter is off so the
      // selectable set is exactly what we render.
      commandProps={{ shouldFilter: false }}
    >
      {/* User | Group segmented toggle */}
      <div
        className="flex items-center gap-1 border-b border-border px-3 py-2"
        role="tablist"
        aria-label="Member kind"
      >
        <KindToggle
          active={kind === "user"}
          onClick={() => setKind("user")}
          icon={UserIcon}
          label="User"
        />
        <KindToggle
          active={kind === "group"}
          onClick={() => setKind("group")}
          icon={UsersIcon}
          label="Group"
        />
      </div>

      <CommandInput
        placeholder={kind === "user" ? "Search users…" : "Search groups…"}
        value={query}
        onValueChange={setQuery}
      />

      {kind === "user" ? (
        <UserOptions
          query={query}
          disabled={busy}
          onPick={(userId) => doAddUser({ groupId: group.id, userId })}
        />
      ) : (
        <GroupOptions
          query={query}
          excludeGroupId={group.id}
          disabled={busy}
          onPick={(memberGroupId) => doAddGroup({ groupId: group.id, memberGroupId })}
        />
      )}
    </CommandDialog>
  );
}

// ─── Segmented toggle button ──────────────────────────────────────────────────

function KindToggle({
  active,
  onClick,
  icon: Icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: typeof UserIcon;
  label: string;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[12px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        active
          ? "bg-accent text-accent-foreground"
          : "text-muted-foreground hover:text-foreground",
      )}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {label}
    </button>
  );
}

// ─── User options ─────────────────────────────────────────────────────────────

function UserOptions({
  query,
  disabled,
  onPick,
}: {
  query: string;
  disabled: boolean;
  onPick: (userId: string) => void;
}) {
  const { data, isLoading, isError } = useQuery(listUsers, {
    pageSize: LIST_PAGE_SIZE,
    pageToken: "",
  });

  const q = query.trim().toLowerCase();
  const users = (data?.users ?? []).filter((u) =>
    q.length === 0
      ? true
      : u.email.toLowerCase().includes(q) ||
        u.displayName.toLowerCase().includes(q),
  );

  return (
    <CommandList aria-busy={isLoading}>
      {isLoading && <PickerLoading label="Loading users…" />}
      {isError && <PickerError />}
      {!isLoading && !isError && users.length === 0 && (
        <CommandEmpty>No matching users.</CommandEmpty>
      )}
      {!isLoading && !isError && users.length > 0 && (
        <CommandGroup heading="Users">
          {users.map((u) => (
            <CommandItem
              key={u.id}
              value={`user:${u.id}`}
              disabled={disabled}
              onSelect={() => onPick(u.id)}
            >
              <UserIcon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate text-foreground">
                {u.displayName || u.email}
              </span>
              {u.displayName && u.email && (
                <span className="shrink-0 truncate text-[11px] text-muted-foreground">
                  {u.email}
                </span>
              )}
            </CommandItem>
          ))}
        </CommandGroup>
      )}
    </CommandList>
  );
}

// ─── Group options ────────────────────────────────────────────────────────────

function GroupOptions({
  query,
  excludeGroupId,
  disabled,
  onPick,
}: {
  query: string;
  excludeGroupId: string;
  disabled: boolean;
  onPick: (memberGroupId: string) => void;
}) {
  const { data, isLoading, isError } = useQuery(listGroups, {
    pageSize: LIST_PAGE_SIZE,
    pageToken: "",
  });

  const q = query.trim().toLowerCase();
  const groups = (data?.groups ?? [])
    .filter((g) => g.id !== excludeGroupId) // never add a group to itself
    .filter((g) => (q.length === 0 ? true : g.name.toLowerCase().includes(q)));

  return (
    <CommandList aria-busy={isLoading}>
      {isLoading && <PickerLoading label="Loading groups…" />}
      {isError && <PickerError />}
      {!isLoading && !isError && groups.length === 0 && (
        <CommandEmpty>No matching groups.</CommandEmpty>
      )}
      {!isLoading && !isError && groups.length > 0 && (
        <CommandGroup heading="Groups">
          {groups.map((g) => (
            <CommandItem
              key={g.id}
              value={`group:${g.id}`}
              disabled={disabled}
              onSelect={() => onPick(g.id)}
            >
              <UsersIcon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate text-foreground">{g.name}</span>
              {g.folderPath ? (
                <span className="shrink-0 truncate font-mono text-[11px] text-muted-foreground">
                  {g.folderPath}
                </span>
              ) : (
                <span className="inline-flex shrink-0 items-center gap-1 text-[11px] text-muted-foreground/70">
                  <Globe className="h-3 w-3" aria-hidden="true" />
                  global
                </span>
              )}
            </CommandItem>
          ))}
        </CommandGroup>
      )}
    </CommandList>
  );
}

// ─── Shared list states ───────────────────────────────────────────────────────

function PickerLoading({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
      <Loader2 className="h-4 w-4 shrink-0 animate-spin" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

function PickerError() {
  return (
    <div className="py-8 text-center text-sm text-destructive" role="alert">
      Failed to load. Try again.
    </div>
  );
}
