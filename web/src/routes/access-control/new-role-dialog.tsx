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
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
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
import { isValidRoleName } from "./role-actions";
import {
  FolderHomePicker,
  type FolderHome,
} from "@/routes/directory/folder-home-picker";

interface NewRoleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const FIELD_LABEL =
  "text-[11px] font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-[11px] text-muted-foreground";
const FIELD_ERROR = "text-[11px] text-destructive";

export function NewRoleDialog({ open, onOpenChange }: NewRoleDialogProps) {
  const queryClient = useQueryClient();

  const [name, setName] = useState("");
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [scope, setScope] = useState<FolderHome | null>(null);
  const [nameTouched, setNameTouched] = useState(false);
  const [pickerOpen, setPickerOpen] = useState(false);

  function reset() {
    setName("");
    setCapabilities([]);
    setScope(null);
    setNameTouched(false);
  }

  const { mutate: doCreate, isPending } = useMutation(createRole, {
    onSuccess: () => {
      toast.success("Role created", {
        description: scope
          ? `${name.trim()} was created under ${scope.path}.`
          : `${name.trim()} was created as a global role.`,
      });
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({ schema: listRoles, cardinality: undefined }),
      });
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
      folderId: scope?.id ?? "",
    });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle className="text-[15px]">New role</DialogTitle>
          <DialogDescription className="text-[13px]">
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
              className="h-9 text-[13px]"
              aria-invalid={nameTouched && !nameValid}
            />
            {nameTouched && !nameValid ? (
              <p className={FIELD_ERROR}>
                Use lowercase letters, digits, dashes or underscores (1–200
                characters).
              </p>
            ) : (
              <p className={FIELD_HINT}>Lowercase letters, digits, - and _.</p>
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
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setPickerOpen(true)}
                className="h-9 flex-1 justify-start gap-2 text-[13px] font-normal"
              >
                {scope ? (
                  <>
                    <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-left font-mono text-[12px]">
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
              {isPending ? "Creating…" : "Create role"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>

      <FolderHomePicker
        open={pickerOpen}
        onOpenChange={setPickerOpen}
        onSelect={setScope}
      />
    </Dialog>
  );
}
