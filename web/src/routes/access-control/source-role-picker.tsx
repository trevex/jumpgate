/**
 * source-role-picker.tsx — Access control ▸ Roles ▸ detail ▸ Add grant edge.
 *
 * A cmdk command dialog listing roles (via `listRoles`), used to pick the
 * SOURCE role of a grant edge (holding the source confers the target role).
 * The target role itself is excluded (a role can't grant from itself). Unlike
 * the folder picker this lists eagerly rather than server-searching — the role
 * set is small and admin-facing — so cmdk's built-in client filter stays on.
 */

import { useMemo } from "react";
import { useQuery } from "@connectrpc/connect-query";
import { Loader2, AlertCircle, ShieldCheck, Globe } from "lucide-react";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@/components/ui/command";
import { listRoles } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import type { Role } from "@/gen/jumpgate/access/v1/access_pb";

const PAGE_SIZE = 100;

interface SourceRolePickerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Role id to exclude (the edge's target — a role can't source from itself). */
  excludeRoleId: string;
  /** Fired with the chosen source role. */
  onSelect: (role: Role) => void;
}

export function SourceRolePicker({
  open,
  onOpenChange,
  excludeRoleId,
  onSelect,
}: SourceRolePickerProps) {
  const { data, isFetching, isError } = useQuery(
    listRoles,
    { pageSize: PAGE_SIZE, pageToken: "" },
    { enabled: open },
  );

  const roles = useMemo(
    () => (data?.roles ?? []).filter((r) => r.id !== excludeRoleId),
    [data?.roles, excludeRoleId],
  );

  function pick(role: Role) {
    onSelect(role);
    onOpenChange(false);
  }

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      label="Choose a source role"
    >
      <CommandInput placeholder="Search roles…" />
      <CommandList aria-busy={isFetching}>
        {isError ? (
          <div className="flex items-center justify-center gap-2 py-8 text-sm text-destructive">
            <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>Failed to load roles. Try again.</span>
          </div>
        ) : isFetching && !data ? (
          <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 shrink-0 animate-spin" aria-hidden="true" />
            <span>Loading…</span>
          </div>
        ) : roles.length === 0 ? (
          <CommandEmpty>No other roles.</CommandEmpty>
        ) : (
          <CommandGroup heading="Roles">
            {roles.map((role) => (
              <CommandItem
                key={role.id}
                value={`${role.name} ${role.folderPath} ${role.id}`}
                onSelect={() => pick(role)}
              >
                <ShieldCheck className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                <span className="min-w-0 flex-1 truncate text-foreground">{role.name}</span>
                {role.folderPath ? (
                  <span className="shrink-0 truncate font-mono text-[11px] text-muted-foreground">
                    {role.folderPath}
                  </span>
                ) : (
                  <span className="flex shrink-0 items-center gap-1 text-[11px] text-muted-foreground/70">
                    <Globe className="h-3 w-3" aria-hidden="true" />
                    global
                  </span>
                )}
              </CommandItem>
            ))}
          </CommandGroup>
        )}
      </CommandList>
    </CommandDialog>
  );
}
