/**
 * new-role-dialog.tsx — Access control ▸ Roles ▸ create.
 *
 * A shadcn Dialog with a Name input, a CapabilityInput (≥1 capability), and an
 * optional folder scope picker. Client validation mirrors the server's charset
 * (`^[a-z0-9_-]+$`, 1–200 chars) and the glob grammar (per chip); the submit
 * button stays disabled until the name is valid and at least one capability is
 * present. The folder scope is optional — an empty selection means the role is
 * global. On success: toast + invalidate `listRoles` (scoped) so the tab
 * re-seeds with the new role, then close and reset. On error: surface
 * `connectErrorMessage(err)` via toast (the server is the real gate — e.g.
 * AlreadyExists for a duplicate name, or InvalidArgument for a bad capability).
 */

import { useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import { Folder, Globe, X } from "lucide-react";
import {
  createRole,
  listRoles,
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
import { Input } from "@/components/ui/input";
import { CapabilityInput } from "@/components/capability-input";
import { connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";
import { isValidRoleName } from "./role-actions";
import {
  FolderHomePicker,
  type FolderHome,
} from "@/routes/directory/folder-home-picker";

interface NewRoleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /**
   * Pre-set folder scope. When provided the scope picker is replaced by a
   * read-only context row and the role is created homed in this folder. When
   * omitted the caller-driven picker behavior (global or pick a scope) is kept.
   */
  folderId?: string;
  folderPath?: string;
}

const FIELD_LABEL =
  "text-micro font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-micro text-muted-foreground";
const FIELD_ERROR = "text-micro text-destructive";

export function NewRoleDialog({
  open,
  onOpenChange,
  folderId,
  folderPath,
}: NewRoleDialogProps) {
  const invalidateList = useInvalidateList();

  // When a folder scope is pre-set by the caller, the role is created there and
  // the scope picker is not shown.
  const pinnedScope = folderId !== undefined;

  const [name, setName] = useState("");
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [scope, setScope] = useState<FolderHome | null>(null);
  const [nameTouched, setNameTouched] = useState(false);
  const [pickerOpen, setPickerOpen] = useState(false);

  // The effective folder id/path: pinned (from props) or picker-chosen.
  const effectiveFolderId = pinnedScope ? (folderId ?? "") : (scope?.id ?? "");
  const effectiveFolderPath = pinnedScope ? folderPath : scope?.path;

  function reset() {
    setName("");
    setCapabilities([]);
    setScope(null);
    setNameTouched(false);
  }

  const { mutate: doCreate, isPending } = useMutation(createRole, {
    onSuccess: () => {
      toast.success("Role created", {
        description: effectiveFolderPath
          ? `${name.trim()} was created under ${effectiveFolderPath}.`
          : `${name.trim()} was created as a global role.`,
      });
      void invalidateList(listRoles);
      reset();
      onOpenChange(false);
    },
    onError: (err) => {
      toast.error("Create failed", { description: connectErrorMessage(err) });
    },
  });

  const nameValid = isValidRoleName(name);
  const capsValid = capabilities.length >= 1;
  const formValid = nameValid && capsValid;

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    if (!next) reset();
    onOpenChange(next);
  }

  // Event type inferred from the JSX onSubmit prop — React 19's types deprecate
  // the named FormEvent alias.
  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (!formValid || isPending) return;
    doCreate({
      name: name.trim(),
      capabilities,
      folderId: effectiveFolderId,
    });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle className="text-title">New role</DialogTitle>
          <DialogDescription className="text-body">
            A role bundles capabilities. Grant it to subjects via a binding, or
            make it requestable via a policy. Capabilities are immutable after
            creation.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {/* Name */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-role-name" className={FIELD_LABEL}>
              Name
            </label>
            <Input
              id="new-role-name"
              type="text"
              autoComplete="off"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setNameTouched(true)}
              placeholder="db-reader"
              className="h-9 text-body"
              aria-invalid={nameTouched && !nameValid}
              aria-describedby="new-role-name-error"
            />
            {nameTouched && !nameValid ? (
              <p id="new-role-name-error" role="alert" className={FIELD_ERROR}>
                Use lowercase letters, digits, dashes or underscores (1–200
                characters).
              </p>
            ) : (
              <p id="new-role-name-error" className={FIELD_HINT}>
                Lowercase letters, digits, - and _.
              </p>
            )}
          </div>

          {/* Capabilities */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-role-caps" className={FIELD_LABEL}>
              Capabilities
            </label>
            <CapabilityInput
              id="new-role-caps"
              value={capabilities}
              onChange={setCapabilities}
            />
          </div>

          {/* Folder scope */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Folder scope</span>
            {pinnedScope ? (
              <>
                <div className="flex h-9 items-center gap-2 rounded-md border border-input bg-muted/40 px-3 text-body">
                  {effectiveFolderPath ? (
                    <>
                      <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                      <span className="min-w-0 flex-1 truncate text-left font-mono text-compact">
                        {effectiveFolderPath}
                      </span>
                    </>
                  ) : (
                    <>
                      <Globe className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                      <span className="flex-1 text-left text-muted-foreground">
                        Global (no folder scope)
                      </span>
                    </>
                  )}
                </div>
                <p className={FIELD_HINT}>
                  This role is scoped to the selected folder.
                </p>
              </>
            ) : (
              <>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setPickerOpen(true)}
                className="h-9 flex-1 justify-start gap-2 text-body font-normal"
              >
                {scope ? (
                  <>
                    <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-left font-mono text-compact">
                      {scope.path}
                    </span>
                  </>
                ) : (
                  <>
                    <Globe className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="flex-1 text-left text-muted-foreground">
                      Global (no folder scope)
                    </span>
                  </>
                )}
              </Button>
              {scope && (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={() => setScope(null)}
                  className="h-9 w-9 shrink-0 text-muted-foreground hover:text-foreground"
                  aria-label="Clear folder scope"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </Button>
              )}
            </div>
            <p className={FIELD_HINT}>
              Optional. A folder scope makes the role addressable and governed
              within that subtree.
            </p>
              </>
            )}
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
              {isPending ? "Creating…" : "Create role"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>

      {!pinnedScope && (
        <FolderHomePicker
          open={pickerOpen}
          onOpenChange={setPickerOpen}
          onSelect={setScope}
        />
      )}
    </Dialog>
  );
}
