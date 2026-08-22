/**
 * role-detail.tsx — Access control ▸ Roles ▸ detail Sheet.
 *
 * A right-hand Sheet showing a selected role's identity (name + folder scope)
 * and its capabilities as chips (enriched via getRoleAccess, which returns the
 * effective capability list; getRoleDisplay backs the header name/folder). A
 * Grant edges section lists the role's userset-rewrite edges (`listRoleGrants`)
 * — each shows the SOURCE role (enriched via getRoleDisplay) and the `via` mode
 * (same_object | parent), with a Remove. An "Add edge" control (a source-role
 * picker + a via select) adds a new edge. All grant mutations are gated on
 * `access:role:update`.
 *
 * A destructive Delete role button (gated `access:role:delete`) opens a
 * ConfirmDialog naming the cascade blast radius, then calls deleteRole and
 * closes the Sheet. Every mutation invalidates the relevant scoped query +
 * toasts; onError surfaces connectErrorMessage.
 */

import { useState } from "react";
import { useQuery, useMutation } from "@connectrpc/connect-query";
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  listRoles,
  listRoleGrants,
  getRoleAccess,
  getRoleDisplay,
  addRoleGrant,
  removeRoleGrant,
  deleteRole,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import type { Role, RoleGrant } from "@/gen/jumpgate/access/v1/access_pb";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { useCapabilities } from "@/lib/capabilities";
import { connectErrorMessage } from "@/lib/format";
import { canUpdateRole, canDeleteRole } from "./role-actions";
import { RolePicker, type PickedRole } from "@/components/pickers/role-picker";
import {
  ShieldCheck,
  GitFork,
  Globe,
  Plus,
  Trash2,
  X,
} from "lucide-react";

const GRANTS_PAGE_SIZE = 100;

/** Human labels for the userset-rewrite `via` mode. */
const VIA_LABEL: Record<string, string> = {
  same_object: "same object",
  parent: "parent",
};

function shortId(id: string): string {
  return id.split("-")[0] ?? id;
}

// ─── Grants query key (shared, scoped to one role) ────────────────────────────

function grantsQueryKey(roleId: string) {
  return createConnectQueryKey({
    schema: listRoleGrants,
    input: { roleId, pageSize: GRANTS_PAGE_SIZE, pageToken: "" },
    cardinality: "finite",
  });
}

function useInvalidateGrants(roleId: string) {
  const queryClient = useQueryClient();
  return () =>
    void queryClient.invalidateQueries({ queryKey: grantsQueryKey(roleId) });
}

function useInvalidateRoles() {
  const queryClient = useQueryClient();
  return () =>
    void queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({ schema: listRoles, cardinality: undefined }),
    });
}

// ─── Capabilities section ─────────────────────────────────────────────────────

function CapabilitiesSection({ roleId }: { roleId: string }) {
  const { data, isLoading, isError, error, refetch } = useQuery(getRoleAccess, {
    roleId,
  });
  const capabilities = data?.capabilities ?? [];

  return (
    <Section title="Capabilities" count={capabilities.length}>
      {isLoading ? (
        <LoadingRows count={2} label="Loading capabilities" />
      ) : isError ? (
        <ErrorState
          size="sm"
          message={connectErrorMessage(error)}
          onRetry={() => void refetch()}
        />
      ) : capabilities.length === 0 ? (
        <p className="px-1 py-2 text-[12px] text-muted-foreground">
          No capabilities.
        </p>
      ) : (
        <div className="flex flex-wrap gap-1.5 px-1 py-2">
          {capabilities.map((cap) => (
            <Badge
              key={cap}
              variant="secondary"
              className="rounded px-1.5 py-0.5 font-mono text-[11px] font-medium"
            >
              {cap}
            </Badge>
          ))}
        </div>
      )}
    </Section>
  );
}

// ─── Grant edge row (source enriched via getRoleDisplay) ──────────────────────

function GrantEdgeRow({
  roleId,
  grant,
  canRemove,
}: {
  roleId: string;
  grant: RoleGrant;
  canRemove: boolean;
}) {
  const invalidate = useInvalidateGrants(roleId);
  const { data } = useQuery(
    getRoleDisplay,
    { id: grant.sourceRoleId },
    { enabled: Boolean(grant.sourceRoleId) },
  );
  const source = data?.role;
  const sourceName = source?.name || shortId(grant.sourceRoleId);
  const via = VIA_LABEL[grant.via] ?? grant.via;

  const { mutate: doRemove, isPending } = useMutation(removeRoleGrant, {
    onSuccess: () => {
      toast.success("Grant edge removed", {
        description: `${sourceName} no longer confers this role.`,
      });
      invalidate();
    },
    onError: (err) => toast.error("Remove failed", { description: connectErrorMessage(err) }),
  });

  return (
    <div className="flex items-center gap-3 px-1 py-2">
      <GitFork className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <div className="truncate text-[13px] text-foreground" title={sourceName}>
          {sourceName}
        </div>
        <div className="text-[11px] text-muted-foreground">
          via <span className="font-medium text-foreground">{via}</span>
          {source?.folderPath && (
            <span className="ml-1 font-mono text-muted-foreground/70">
              · {source.folderPath}
            </span>
          )}
        </div>
      </div>
      {canRemove && (
        <Button
          variant="ghost"
          size="icon"
          onClick={() => doRemove({ id: grant.id })}
          disabled={isPending}
          aria-label={`Remove grant edge from ${sourceName}`}
          className="h-7 w-7 shrink-0 text-muted-foreground hover:text-destructive"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      )}
    </div>
  );
}

// ─── Add grant edge control ───────────────────────────────────────────────────

function AddGrantEdge({ roleId }: { roleId: string }) {
  const invalidate = useInvalidateGrants(roleId);
  const [source, setSource] = useState<PickedRole | null>(null);
  const [via, setVia] = useState<string>("same_object");
  const [pickerOpen, setPickerOpen] = useState(false);

  const { mutate: doAdd, isPending } = useMutation(addRoleGrant, {
    onSuccess: () => {
      toast.success("Grant edge added", {
        description: `${source?.name ?? "source role"} now confers this role.`,
      });
      invalidate();
      setSource(null);
      setVia("same_object");
    },
    onError: (err) => toast.error("Add failed", { description: connectErrorMessage(err) }),
  });

  return (
    <div className="mt-2 flex flex-col gap-2 rounded-md border border-dashed border-border p-2.5">
      <div className="flex items-center gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => setPickerOpen(true)}
          className="h-8 flex-1 justify-start gap-2 text-[12px] font-normal"
        >
          {source ? (
            <>
              <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate text-left">{source.name}</span>
            </>
          ) : (
            <span className="flex-1 text-left text-muted-foreground">
              Choose a source role…
            </span>
          )}
        </Button>

        <Select value={via} onValueChange={setVia}>
          <SelectTrigger className="h-8 w-[130px] text-[12px]" aria-label="Grant via">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="same_object" className="text-[12px]">
              same object
            </SelectItem>
            <SelectItem value="parent" className="text-[12px]">
              parent
            </SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Button
        type="button"
        size="sm"
        onClick={() =>
          source &&
          doAdd({ roleId, sourceRoleId: source.id, via })
        }
        disabled={!source || isPending}
        className="h-7 gap-1 self-end px-3 text-[12px]"
      >
        <Plus className="h-3.5 w-3.5" aria-hidden="true" />
        {isPending ? "Adding…" : "Add edge"}
      </Button>

      <RolePicker
        open={pickerOpen}
        onOpenChange={setPickerOpen}
        excludeId={roleId}
        onSelect={setSource}
        label="Choose a source role"
      />
    </div>
  );
}

// ─── Grant edges section ──────────────────────────────────────────────────────

function GrantEdgesSection({ roleId }: { roleId: string }) {
  const caps = useCapabilities();
  const canUpdate = canUpdateRole(caps);

  const { data, isLoading, isError, error, refetch } = useQuery(listRoleGrants, {
    roleId,
    pageSize: GRANTS_PAGE_SIZE,
    pageToken: "",
  });
  const grants = data?.grants ?? [];

  return (
    <Section title="Grant edges" count={grants.length}>
      {isLoading ? (
        <LoadingRows count={2} label="Loading grant edges" />
      ) : isError ? (
        <ErrorState
          size="sm"
          message={connectErrorMessage(error)}
          onRetry={() => void refetch()}
        />
      ) : grants.length === 0 ? (
        <EmptyState
          icon={GitFork}
          size="sm"
          message="No grant edges. Holding a source role can confer this one."
        />
      ) : (
        <div className="divide-y divide-border">
          {grants.map((grant) => (
            <GrantEdgeRow
              key={grant.id}
              roleId={roleId}
              grant={grant}
              canRemove={canUpdate}
            />
          ))}
        </div>
      )}

      {canUpdate && <AddGrantEdge roleId={roleId} />}
    </Section>
  );
}

// ─── Danger zone (cascade delete) ─────────────────────────────────────────────

function DeleteRole({
  role,
  onDeleted,
}: {
  role: Role;
  onDeleted: () => void;
}) {
  const invalidateRoles = useInvalidateRoles();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const { mutate: doDelete, isPending } = useMutation(deleteRole, {
    onSuccess: () => {
      toast.success("Role deleted", {
        description: `${role.name} and everything that used it was removed.`,
      });
      invalidateRoles();
      setConfirmOpen(false);
      onDeleted();
    },
    onError: (err) => toast.error("Delete failed", { description: connectErrorMessage(err) }),
  });

  return (
    <section className="mt-2 flex items-center justify-between gap-3 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2.5">
      <div className="min-w-0">
        <p className="text-[12px] font-medium text-foreground">Delete role</p>
        <p className="text-[11px] text-muted-foreground">
          Cascades to bindings, policies, and grants.
        </p>
      </div>
      <Button
        variant="destructive"
        size="sm"
        onClick={() => setConfirmOpen(true)}
        disabled={isPending}
        className="h-7 shrink-0 gap-1 px-3 text-[12px]"
      >
        <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
        Delete
      </Button>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Delete this role?"
        description="Delete this role? This removes every binding, request policy, and grant that uses it, ending any live sessions it grants. This cannot be undone."
        confirmLabel="Delete role"
        pendingLabel="Deleting…"
        variant="destructive"
        confirmAriaLabel={`Confirm delete ${role.name}`}
        pending={isPending}
        onConfirm={() => doDelete({ roleId: role.id })}
      />
    </section>
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
      <h3 className="flex items-center gap-2 px-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        {title}
        <span className="tabular-nums text-muted-foreground/60">{count}</span>
      </h3>
      {children}
    </section>
  );
}

// ─── Detail Sheet ─────────────────────────────────────────────────────────────

export function RoleDetailSheet({
  role,
  onOpenChange,
}: {
  role: Role | null;
  onOpenChange: (open: boolean) => void;
}) {
  const caps = useCapabilities();
  const canDelete = canDeleteRole(caps);

  return (
    <Sheet open={role !== null} onOpenChange={onOpenChange}>
      <SheetContent className="flex w-full flex-col gap-6 overflow-y-auto sm:max-w-md">
        {role && (
          <>
            <SheetHeader>
              <SheetTitle className="flex items-center gap-2 text-[15px]">
                <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                {role.name}
              </SheetTitle>
              <SheetDescription className="text-[13px]">
                {role.folderPath ? (
                  <>
                    Scoped to{" "}
                    <span className="font-mono text-foreground">
                      {role.folderPath}
                    </span>
                    .
                  </>
                ) : (
                  <span className="inline-flex items-center gap-1">
                    <Globe className="h-3.5 w-3.5" aria-hidden="true" />A global
                    role.
                  </span>
                )}
              </SheetDescription>
            </SheetHeader>

            <CapabilitiesSection roleId={role.id} />
            <GrantEdgesSection roleId={role.id} />
            {canDelete && (
              <DeleteRole role={role} onDeleted={() => onOpenChange(false)} />
            )}
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
