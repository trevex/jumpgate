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
 * On success: toast + invalidate `listRoleBindings` so the tab re-seeds, then
 * close and reset. On error: surface `connectErrorMessage(err)` via toast (the
 * server is the real gate — e.g. PermissionDenied, or AlreadyExists for a
 * duplicate binding).
 */

import { useState } from "react";
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

interface NewBindingDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const FIELD_LABEL =
  "text-[11px] font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-[11px] text-muted-foreground";

export function NewBindingDialog({ open, onOpenChange }: NewBindingDialogProps) {
  const invalidateList = useInvalidateList();

  const [role, setRole] = useState<PickedRole | null>(null);
  const [subject, setSubject] = useState<PickedSubject | null>(null);
  const [scope, setScope] = useState<PickedScope>({ kind: "global" });

  const [rolePickerOpen, setRolePickerOpen] = useState(false);
  const [subjectPickerOpen, setSubjectPickerOpen] = useState(false);
  const [scopePickerOpen, setScopePickerOpen] = useState(false);

  function reset() {
    setRole(null);
    setSubject(null);
    setScope({ kind: "global" });
  }

  const { mutate: doCreate, isPending } = useMutation(createRoleBinding, {
    onSuccess: () => {
      toast.success("Binding created", {
        description: `${subject?.label ?? "The subject"} now holds ${role?.name ?? "the role"}.`,
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
  const formValid = role !== null && subject !== null;

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    if (!next) reset();
    onOpenChange(next);
  }

  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (!formValid || isPending || !role || !subject) return;
    doCreate({
      roleId: role.id,
      subjectUserId: subject.kind === "user" ? subject.id : "",
      subjectGroupId: subject.kind === "group" ? subject.id : "",
      scopeFolderId: scope.kind === "folder" ? scope.id : "",
      scopeAssetId: scope.kind === "asset" ? scope.id : "",
    });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle className="text-[15px]">New binding</DialogTitle>
          <DialogDescription className="text-[13px]">
            A standing binding grants a role to a subject. An optional scope
            confines it to a folder subtree or a single asset; global otherwise.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {/* Role */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Role</span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setRolePickerOpen(true)}
              className="h-9 justify-start gap-2 text-[13px] font-normal"
            >
              {role ? (
                <>
                  <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate text-left">{role.name}</span>
                  {role.folderPath && (
                    <span className="shrink-0 truncate font-mono text-[11px] text-muted-foreground">
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
          </div>

          {/* Subject */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Subject</span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setSubjectPickerOpen(true)}
              className="h-9 justify-start gap-2 text-[13px] font-normal"
            >
              {subject ? (
                <>
                  {subject.kind === "user" ? (
                    <User className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  ) : (
                    <Users className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  )}
                  <span className="min-w-0 flex-1 truncate text-left">{subject.label}</span>
                  <span className="shrink-0 text-[11px] capitalize text-muted-foreground">
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
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setScopePickerOpen(true)}
              className="h-9 justify-start gap-2 text-[13px] font-normal"
            >
              {scope.kind === "folder" ? (
                <>
                  <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate text-left font-mono text-[12px]">
                    {scope.path}
                  </span>
                </>
              ) : scope.kind === "asset" ? (
                <>
                  <Boxes className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate text-left font-mono text-[12px]">
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
            <p className={FIELD_HINT}>
              Confine the binding to a folder subtree or a single asset, or leave
              it global.
            </p>
          </div>

          <DialogFooter className="mt-1">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => handleOpenChange(false)}
              disabled={isPending}
              className="h-8 text-[13px]"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={!formValid || isPending}
              className="h-8 text-[13px]"
            >
              {isPending ? "Creating…" : "Create binding"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>

      <RolePicker
        open={rolePickerOpen}
        onOpenChange={setRolePickerOpen}
        onSelect={setRole}
      />
      <SubjectPicker
        open={subjectPickerOpen}
        onOpenChange={setSubjectPickerOpen}
        onSelect={setSubject}
      />
      <ScopePicker
        open={scopePickerOpen}
        onOpenChange={setScopePickerOpen}
        onSelect={setScope}
      />
    </Dialog>
  );
}
