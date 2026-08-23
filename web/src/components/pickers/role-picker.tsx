/**
 * role-picker.tsx — shared cmdk role selector.
 *
 * A CommandDialog listing roles (via `listRoles`), client-filtered by name /
 * folder path (cmdk's built-in filter). An optional `excludeId` drops one role
 * from the list (e.g. a grant edge can't source from its own target). Fires
 * `onSelect` with a minimal `PickedRole` — the single role-result contract
 * shared across Access-control (grant edges, bindings, policies).
 *
 * The role set is small and admin-facing, so it lists eagerly (one page) rather
 * than server-searching.
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

const PAGE_SIZE = 100;

/** The minimal role result — the shared role-picker contract. */
export interface PickedRole {
  id: string;
  name: string;
  folderPath: string;
}

interface RolePickerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Optional role id to omit from the list. */
  excludeId?: string;
  /** Fired with the chosen role, then the dialog closes. */
  onSelect: (role: PickedRole) => void;
  /** Optional heading override for the dialog's aria label. */
  label?: string;
}

export function RolePicker({
  open,
  onOpenChange,
  excludeId,
  onSelect,
  label = "Choose a role",
}: RolePickerProps) {
  const { data, isFetching, isError } = useQuery(
    listRoles,
    { pageSize: PAGE_SIZE, pageToken: "" },
    { enabled: open },
  );

  const roles = useMemo(
    () => (data?.roles ?? []).filter((r) => r.id !== excludeId),
    [data?.roles, excludeId],
  );

  function pick(role: PickedRole) {
    onSelect(role);
    onOpenChange(false);
  }

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} label={label}>
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
          <CommandEmpty>No roles.</CommandEmpty>
        ) : (
          <CommandGroup heading="Roles">
            {roles.map((role) => (
              <CommandItem
                key={role.id}
                value={`${role.name} ${role.folderPath} ${role.id}`}
                onSelect={() =>
                  pick({
                    id: role.id,
                    name: role.name,
                    folderPath: role.folderPath,
                  })
                }
              >
                <ShieldCheck className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                <span className="min-w-0 flex-1 truncate text-foreground">{role.name}</span>
                {role.folderPath ? (
                  <span className="shrink-0 truncate font-mono text-micro text-muted-foreground">
                    {role.folderPath}
                  </span>
                ) : (
                  <span className="flex shrink-0 items-center gap-1 text-micro text-muted-foreground/70">
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
