/**
 * subject-picker.tsx — shared cmdk subject (User | Group) selector.
 *
 * A CommandDialog with a User | Group segmented toggle:
 *   - User  → lists directory users (`listUsers`), client-filtered by email or
 *     display name.
 *   - Group → lists directory groups (`listGroups`), client-filtered by name.
 *
 * Fires `onSelect` with a `PickedSubject` discriminated by `kind`, then closes.
 * The single subject-result contract shared by Access-control (bindings, policy
 * subjects). Both lists fetch a single page and filter client-side — snappy for
 * the common small-directory case.
 */

import { useEffect, useState } from "react";
import { useQuery } from "@connectrpc/connect-query";
import { User as UserIcon, Users as UsersIcon, Loader2, Globe } from "lucide-react";
import {
  listUsers,
  listGroups,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@/components/ui/command";
import { cn } from "@/lib/utils";

const LIST_PAGE_SIZE = 50;

/** A picked subject — discriminated union over user vs group. */
export type PickedSubject =
  | { kind: "user"; id: string; label: string }
  | { kind: "group"; id: string; label: string };

interface SubjectPickerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Fired with the chosen subject, then the dialog closes. */
  onSelect: (subject: PickedSubject) => void;
}

export function SubjectPicker({ open, onOpenChange, onSelect }: SubjectPickerProps) {
  const [kind, setKind] = useState<"user" | "group">("user");
  const [query, setQuery] = useState("");

  // Reset to a clean slate each time the dialog opens.
  useEffect(() => {
    if (open) {
      setKind("user");
      setQuery("");
    }
  }, [open]);

  function pick(subject: PickedSubject) {
    onSelect(subject);
    onOpenChange(false);
  }

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      label="Choose a subject"
      // Client-side filtering is done below; cmdk's own filter is off.
      commandProps={{ shouldFilter: false }}
    >
      <div
        className="flex items-center gap-1 border-b border-border px-3 py-2"
        role="tablist"
        aria-label="Subject kind"
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
        <UserOptions query={query} onPick={pick} />
      ) : (
        <GroupOptions query={query} onPick={pick} />
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
        "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-compact font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
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
  onPick,
}: {
  query: string;
  onPick: (subject: PickedSubject) => void;
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
              onSelect={() =>
                onPick({ kind: "user", id: u.id, label: u.displayName || u.email })
              }
            >
              <UserIcon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate text-foreground">
                {u.displayName || u.email}
              </span>
              {u.displayName && u.email && (
                <span className="shrink-0 truncate text-micro text-muted-foreground">
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
  onPick,
}: {
  query: string;
  onPick: (subject: PickedSubject) => void;
}) {
  const { data, isLoading, isError } = useQuery(listGroups, {
    pageSize: LIST_PAGE_SIZE,
    pageToken: "",
  });

  const q = query.trim().toLowerCase();
  const groups = (data?.groups ?? []).filter((g) =>
    q.length === 0 ? true : g.name.toLowerCase().includes(q),
  );

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
              onSelect={() => onPick({ kind: "group", id: g.id, label: g.name })}
            >
              <UsersIcon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate text-foreground">{g.name}</span>
              {g.folderPath ? (
                <span className="shrink-0 truncate font-mono text-micro text-muted-foreground">
                  {g.folderPath}
                </span>
              ) : (
                <span className="inline-flex shrink-0 items-center gap-1 text-micro text-muted-foreground">
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
