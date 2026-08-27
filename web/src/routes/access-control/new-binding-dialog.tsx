/**
 * new-binding-dialog.tsx — Access control ▸ Bindings ▸ create.
 *
 * A shadcn Dialog that composes the three shared pickers — RolePicker (the role
 * to grant), SubjectPicker (the user or group who receives it), and ScopePicker
 * (Global | Folder | Asset) — into a standing role binding. All three must be
 * chosen before the submit button enables (scope defaults to Global, which is a
 * valid choice; role and subject are required). On submit only the set fields go
 * to the server: `subjectUserId` XOR `subjectGroupId`, and at most one of
 * `scopeFolderId` / `scopeAssetId` (neither = global).
 *
 * The role and scope can each be pinned by the caller (independently,
 * composably): `fixedRole` (e.g. from a role detail pane) replaces the
 * role-picker with a read-only role row, and `fixedScope` (e.g. from a
 * folder/asset detail pane) replaces the scope-picker with a read-only scope
 * row. Whatever isn't pinned stays an active picker.
 *
 * On success: toast + invalidate `listRoleBindings` so the tab re-seeds, then
 * close and reset. On error: surface `connectErrorMessage(err)` via toast (the
 * server is the real gate — e.g. PermissionDenied, or AlreadyExists for a
 * duplicate binding).
 */

import { useEffect, useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import { ShieldCheck, User, Users, Folder, Boxes, Globe } from "lucide-react";
import {
  createRoleBinding,
  listRoleBindings,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { RolePicker, type PickedRole } from "@/components/pickers/role-picker";
import {
  SubjectPicker,
  type PickedSubject,
} from "@/components/pickers/subject-picker";
import { ScopePicker, type PickedScope } from "@/components/pickers/scope-picker";
import { connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";

/**
 * A scope pinned by the caller (e.g. the catalog folder/asset detail pane).
 * When set, the scope-picker is hidden and this scope is sent verbatim.
 */
export interface FixedScope {
  kind: "folder" | "asset";
  id: string;
  path?: string;
}

/**
 * A role pinned by the caller (e.g. a role detail pane). When set, the
 * role-picker is hidden and `id` is sent verbatim as `roleId`; `name` and the
 * optional `folderPath` back the read-only role row.
 */
export interface FixedRole {
  id: string;
  name: string;
  folderPath?: string;
}

interface NewBindingDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /**
   * When present, the binding is confined to this folder/asset: the scope-picker
   * is replaced by a read-only scope row. Absent = today's behavior (picker).
   */
  fixedScope?: FixedScope;
  /**
   * When present, the binding always grants this role: the role-picker is
   * replaced by a read-only role row. Absent = today's behavior (picker).
   * Independent of and composable with `fixedScope`.
   */
  fixedRole?: FixedRole;
  /**
   * The INITIAL scope shown in the (still editable) scope-picker — e.g. a
   * folder-homed role's home folder, so binding it preselects that folder. The
   * user can change it. Ignored when `fixedScope` is set (that pins/read-only).
   * Absent = today's behavior (starts Global).
   */
  defaultScope?: PickedScope;
}

const FIELD_LABEL =
  "text-micro font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-micro text-muted-foreground";

export function NewBindingDialog({
  open,
  onOpenChange,
  fixedScope,
  fixedRole,
  defaultScope,
}: NewBindingDialogProps) {
  const invalidateList = useInvalidateList();

  const [role, setRole] = useState<PickedRole | null>(null);
  const [subject, setSubject] = useState<PickedSubject | null>(null);
  const [scope, setScope] = useState<PickedScope>(
    defaultScope ?? { kind: "global" },
  );

  // Re-seed the editable scope to the caller's default whenever the dialog
  // opens (and if the default itself changes, e.g. switching between two
  // folder-homed roles that share this mounted dialog). Guarded on `open` so a
  // user's in-dialog scope pick isn't clobbered mid-edit. No-op under
  // `fixedScope`, which pins the scope independently of this state.
  useEffect(() => {
    if (open) setScope(defaultScope ?? { kind: "global" });
  }, [open, defaultScope]);

  const [rolePickerOpen, setRolePickerOpen] = useState(false);
  const [subjectPickerOpen, setSubjectPickerOpen] = useState(false);
  const [scopePickerOpen, setScopePickerOpen] = useState(false);

  // When a scope is fixed by the caller, that scope is sent to the server;
  // otherwise the picker-chosen `scope` is used.
  const effectiveScope: PickedScope = fixedScope
    ? { kind: fixedScope.kind, id: fixedScope.id, path: fixedScope.path ?? "" }
    : scope;

  // When a role is fixed by the caller, that role is sent to the server;
  // otherwise the picker-chosen `role` is used.
  const effectiveRole: PickedRole | null = fixedRole
    ? { id: fixedRole.id, name: fixedRole.name, folderPath: fixedRole.folderPath ?? "" }
    : role;

  function reset() {
    setRole(null);
    setSubject(null);
    setScope(defaultScope ?? { kind: "global" });
  }

  const { mutate: doCreate, isPending } = useMutation(createRoleBinding, {
    onSuccess: () => {
      toast.success("Binding created", {
        description: `${subject?.label ?? "The subject"} now holds ${effectiveRole?.name ?? "the role"}.`,
      });
      void invalidateList(listRoleBindings);
      reset();
      onOpenChange(false);
    },
    onError: (err) => {
      toast.error("Create failed", { description: connectErrorMessage(err) });
    },
  });

  // Role + subject are required; scope always has a value (global by default).
  // The role may be fixed by the caller, so validate against effectiveRole.
  const formValid = effectiveRole !== null && subject !== null;

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    if (!next) reset();
    onOpenChange(next);
  }

  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (!formValid || isPending || !effectiveRole || !subject) return;
    doCreate({
      roleId: effectiveRole.id,
      subjectUserId: subject.kind === "user" ? subject.id : "",
      subjectGroupId: subject.kind === "group" ? subject.id : "",
      scopeFolderId: effectiveScope.kind === "folder" ? effectiveScope.id : "",
      scopeAssetId: effectiveScope.kind === "asset" ? effectiveScope.id : "",
    });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle className="text-title">New binding</DialogTitle>
          <DialogDescription className="text-body">
            A standing binding grants a role to a subject. An optional scope
            confines it to a folder subtree or a single asset; global otherwise.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {/* Role */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Role</span>
            {fixedRole ? (
              <div className="flex h-9 items-center gap-2 rounded-md border border-input bg-muted/40 px-3 text-body">
                <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                <span className="min-w-0 flex-1 truncate text-foreground">
                  {fixedRole.name}
                </span>
                <span className="shrink-0 truncate font-mono text-micro text-muted-foreground">
                  {fixedRole.folderPath || "global"}
                </span>
              </div>
            ) : (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setRolePickerOpen(true)}
                className="h-9 justify-start gap-2 text-body font-normal"
              >
                {role ? (
                  <>
                    <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-left">{role.name}</span>
                    {role.folderPath && (
                      <span className="shrink-0 truncate font-mono text-micro text-muted-foreground">
                        {role.folderPath}
                      </span>
                    )}
                  </>
                ) : (
                  <span className="flex-1 text-left text-muted-foreground">
                    Choose a role…
                  </span>
                )}
              </Button>
            )}
          </div>

          {/* Subject */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Subject</span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setSubjectPickerOpen(true)}
              className="h-9 justify-start gap-2 text-body font-normal"
            >
              {subject ? (
                <>
                  {subject.kind === "user" ? (
                    <User className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  ) : (
                    <Users className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  )}
                  <span className="min-w-0 flex-1 truncate text-left">{subject.label}</span>
                  <span className="shrink-0 text-micro capitalize text-muted-foreground">
                    {subject.kind}
                  </span>
                </>
              ) : (
                <span className="flex-1 text-left text-muted-foreground">
                  Choose a user or group…
                </span>
              )}
            </Button>
          </div>

          {/* Scope */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Scope</span>
            {fixedScope ? (
              <div className="flex h-9 items-center gap-2 rounded-md border border-input bg-muted/40 px-3 text-body">
                {fixedScope.kind === "folder" ? (
                  <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                ) : (
                  <Boxes className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                )}
                <span className="min-w-0 flex-1 truncate font-mono text-compact text-foreground">
                  {fixedScope.path || fixedScope.id}
                </span>
              </div>
            ) : (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setScopePickerOpen(true)}
                className="h-9 justify-start gap-2 text-body font-normal"
              >
                {scope.kind === "folder" ? (
                  <>
                    <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-left font-mono text-compact">
                      {scope.path}
                    </span>
                  </>
                ) : scope.kind === "asset" ? (
                  <>
                    <Boxes className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-left font-mono text-compact">
                      {scope.path}
                    </span>
                  </>
                ) : (
                  <>
                    <Globe className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="flex-1 text-left text-muted-foreground">
                      Global (no scope)
                    </span>
                  </>
                )}
              </Button>
            )}
            <p className={FIELD_HINT}>
              {fixedScope
                ? `Confined to this ${fixedScope.kind}.`
                : "Confine the binding to a folder subtree or a single asset, or leave it global."}
            </p>
          </div>

          <DialogFooter className="mt-1">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => handleOpenChange(false)}
              disabled={isPending}
              className="h-8 text-body"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={!formValid || isPending}
              className="h-8 text-body"
            >
              {isPending ? "Creating…" : "Create binding"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>

      {!fixedRole && (
        <RolePicker
          open={rolePickerOpen}
          onOpenChange={setRolePickerOpen}
          onSelect={setRole}
        />
      )}
      <SubjectPicker
        open={subjectPickerOpen}
        onOpenChange={setSubjectPickerOpen}
        onSelect={setSubject}
      />
      {!fixedScope && (
        <ScopePicker
          open={scopePickerOpen}
          onOpenChange={setScopePickerOpen}
          onSelect={setScope}
        />
      )}
    </Dialog>
  );
}
