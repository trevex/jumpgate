/**
 * group-detail.tsx — Directory ▸ Groups ▸ detail Sheet.
 *
 * A right-hand Sheet showing a selected group's identity (name + folder home)
 * and its membership, split into two sections:
 *   - Members (users): each row's email/name is enriched via getUserDisplay —
 *     `ListGroupMembers` returns id-only User stubs, so we look up the display
 *     read per row (falling back to a short UUID). Remove → removeUserFromGroup.
 *   - Sub-groups (nested groups): each row shows the group name + folder home
 *     (both already carried by the members response). Remove → removeGroupFromGroup.
 *
 * The "Add member" control (a User | Group picker) and every Remove are gated on
 * the membership caps (`identity:group:add-member` / `remove-member`); the server
 * is the real gate. Each mutation invalidates this group's members query (scoped
 * via createConnectQueryKey so other groups' member lists are untouched) + toasts;
 * onError surfaces connectErrorMessage (cycle / AlreadyExists show up here).
 */

import { useState } from "react";
import { useQuery, useMutation } from "@connectrpc/connect-query";
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  listGroupMembers,
  getUserDisplay,
  removeUserFromGroup,
  removeGroupFromGroup,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import type { Group, User } from "@/gen/jumpgate/identity/v1/identity_pb";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { useCapabilities } from "@/lib/capabilities";
import { connectErrorMessage, shortId } from "@/lib/format";
import { cn } from "@/lib/utils";
import {
  canAddMember,
  canRemoveMember,
  partitionMembers,
  memberCount,
} from "./group-membership";
import { AddMemberPicker } from "./add-member-picker";
import {
  User as UserIcon,
  Users as UsersIcon,
  UsersRound,
  Globe,
  Plus,
  X,
} from "lucide-react";

/**
 * Members page size. The scoped-invalidation key in the Add/Remove mutations and
 * the picker must match this exact input, so it is exported and shared.
 */
export const MEMBERS_PAGE_SIZE = 100;

// ─── Members query key (shared, scoped to one group) ──────────────────────────

/** The exact connect-query key for a single group's members query. */
export function membersQueryKey(groupId: string) {
  return createConnectQueryKey({
    schema: listGroupMembers,
    input: { groupId, pageSize: MEMBERS_PAGE_SIZE, pageToken: "" },
    cardinality: "finite",
  });
}

function useInvalidateMembers(groupId: string) {
  const queryClient = useQueryClient();
  return () => {
    const key = membersQueryKey(groupId);
    void queryClient
      .cancelQueries({ queryKey: key })
      .then(() => queryClient.invalidateQueries({ queryKey: key }));
  };
}

// ─── User member row (id-only → enriched via getUserDisplay) ──────────────────

function UserMemberRow({
  groupId,
  member,
  canRemove,
}: {
  groupId: string;
  member: User;
  canRemove: boolean;
}) {
  const invalidate = useInvalidateMembers(groupId);
  const { data } = useQuery(
    getUserDisplay,
    { id: member.id },
    { enabled: Boolean(member.id) },
  );
  const display = data?.user;
  const primary = display?.displayName || display?.email || shortId(member.id);
  const secondary =
    display?.displayName && display?.email ? display.email : "";

  const { mutate: doRemove, isPending } = useMutation(removeUserFromGroup, {
    onSuccess: () => {
      toast.success("Member removed", { description: `${primary} was removed.` });
      invalidate();
    },
    onError: (err) => toast.error("Remove failed", { description: connectErrorMessage(err) }),
  });

  return (
    <MemberRow
      icon={UserIcon}
      primary={primary}
      secondary={secondary}
      canRemove={canRemove}
      removing={isPending}
      removeAriaLabel={`Remove ${primary}`}
      onRemove={() => doRemove({ groupId, userId: member.id })}
    />
  );
}

// ─── Sub-group member row ─────────────────────────────────────────────────────

function GroupMemberRow({
  groupId,
  member,
  canRemove,
}: {
  groupId: string;
  member: Group;
  canRemove: boolean;
}) {
  const invalidate = useInvalidateMembers(groupId);

  const { mutate: doRemove, isPending } = useMutation(removeGroupFromGroup, {
    onSuccess: () => {
      toast.success("Sub-group removed", { description: `${member.name} was removed.` });
      invalidate();
    },
    onError: (err) => toast.error("Remove failed", { description: connectErrorMessage(err) }),
  });

  return (
    <MemberRow
      icon={UsersIcon}
      primary={member.name}
      secondary={member.folderPath}
      secondaryMono={Boolean(member.folderPath)}
      secondaryGlobal={!member.folderPath}
      canRemove={canRemove}
      removing={isPending}
      removeAriaLabel={`Remove sub-group ${member.name}`}
      onRemove={() => doRemove({ groupId, memberGroupId: member.id })}
    />
  );
}

// ─── Shared member row ────────────────────────────────────────────────────────

function MemberRow({
  icon: Icon,
  primary,
  secondary,
  secondaryMono = false,
  secondaryGlobal = false,
  canRemove,
  removing,
  removeAriaLabel,
  onRemove,
}: {
  icon: typeof UserIcon;
  primary: string;
  secondary: string;
  secondaryMono?: boolean;
  secondaryGlobal?: boolean;
  canRemove: boolean;
  removing: boolean;
  removeAriaLabel: string;
  onRemove: () => void;
}) {
  return (
    <div className="flex items-center gap-3 px-1 py-2">
      <Icon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <div className="truncate text-body text-foreground" title={primary}>
          {primary}
        </div>
        {secondaryGlobal ? (
          <div className="flex items-center gap-1 text-micro text-muted-foreground">
            <Globe className="h-3 w-3" aria-hidden="true" />
            global
          </div>
        ) : (
          secondary && (
            <div
              className={cn(
                "truncate text-micro text-muted-foreground",
                secondaryMono && "font-mono",
              )}
              title={secondary}
            >
              {secondary}
            </div>
          )
        )}
      </div>
      {canRemove && (
        <Button
          variant="ghost"
          size="icon"
          onClick={onRemove}
          disabled={removing}
          aria-label={removeAriaLabel}
          className="h-7 w-7 shrink-0 text-muted-foreground hover:text-destructive"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      )}
    </div>
  );
}

// ─── Section wrapper ──────────────────────────────────────────────────────────

function Section({
  title,
  count,
  children,
}: {
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-1">
      <h3 className="flex items-center gap-2 px-1 text-eyebrow font-semibold uppercase tracking-widest text-muted-foreground">
        {title}
        <span className="tabular-nums text-muted-foreground/60">{count}</span>
      </h3>
      <div className="divide-y divide-border">{children}</div>
    </section>
  );
}

// ─── Detail body ──────────────────────────────────────────────────────────────

function GroupDetailBody({ group }: { group: Group }) {
  const caps = useCapabilities();
  const showAdd = canAddMember(caps);
  const canRemove = canRemoveMember(caps);
  const [pickerOpen, setPickerOpen] = useState(false);

  const { data, isLoading, isError, error, refetch } = useQuery(listGroupMembers, {
    groupId: group.id,
    pageSize: MEMBERS_PAGE_SIZE,
    pageToken: "",
  });

  const members = partitionMembers(data);
  const total = memberCount(members);

  return (
    <>
      {/* Add-member seam */}
      {showAdd && (
        <div className="mt-4 flex justify-end">
          <Button
            size="sm"
            onClick={() => setPickerOpen(true)}
            className="h-7 gap-1 px-3 text-compact"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            Add member
          </Button>
        </div>
      )}

      <div className="mt-4">
        {isLoading ? (
          <LoadingRows count={3} label="Loading members" />
        ) : isError ? (
          <ErrorState
            size="sm"
            message={connectErrorMessage(error)}
            onRetry={() => void refetch()}
          />
        ) : total === 0 ? (
          <EmptyState icon={UsersRound} size="sm" message="No members yet." />
        ) : (
          <div className="flex flex-col gap-6">
            {members.userMembers.length > 0 && (
              <Section title="Members" count={members.userMembers.length}>
                {members.userMembers.map((u) => (
                  <UserMemberRow
                    key={u.id}
                    groupId={group.id}
                    member={u}
                    canRemove={canRemove}
                  />
                ))}
              </Section>
            )}
            {members.groupMembers.length > 0 && (
              <Section title="Sub-groups" count={members.groupMembers.length}>
                {members.groupMembers.map((g) => (
                  <GroupMemberRow
                    key={g.id}
                    groupId={group.id}
                    member={g}
                    canRemove={canRemove}
                  />
                ))}
              </Section>
            )}
          </div>
        )}
      </div>

      {showAdd && (
        <AddMemberPicker
          group={group}
          open={pickerOpen}
          onOpenChange={setPickerOpen}
        />
      )}
    </>
  );
}

// ─── Detail Sheet ─────────────────────────────────────────────────────────────

export function GroupDetailSheet({
  group,
  onOpenChange,
}: {
  group: Group | null;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Sheet open={group !== null} onOpenChange={onOpenChange}>
      <SheetContent className="flex w-full flex-col overflow-y-auto sm:max-w-md">
        {group && (
          <>
            <SheetHeader>
              <SheetTitle className="text-title">{group.name}</SheetTitle>
              <SheetDescription className="text-body">
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

            <GroupDetailBody group={group} />
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
