/**
 * new-group-dialog.tsx — Directory ▸ Groups ▸ create.
 *
 * A shadcn Dialog with a Name input and an optional folder-home picker. Client
 * validation mirrors the server's charset rule (`^[a-z0-9_-]+$`, 1–200 chars);
 * the submit button stays disabled until the name is valid. The folder home is
 * optional — an empty selection means the group is global. On success: toast +
 * invalidate `listGroups` (scoped) so the tab re-seeds with the new group, then
 * close and reset. On error: surface `connectErrorMessage(err)` via toast (the
 * server is the real gate — e.g. AlreadyExists for a duplicate name).
 */

import { useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Folder, Globe, X } from "lucide-react";
import {
  createGroup,
  listGroups,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
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
import { connectErrorMessage } from "@/lib/format";
import { isValidGroupName } from "./group-actions";
import { FolderHomePicker, type FolderHome } from "./folder-home-picker";

interface NewGroupDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const FIELD_LABEL =
  "text-[11px] font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-[11px] text-muted-foreground";
const FIELD_ERROR = "text-[11px] text-destructive";

export function NewGroupDialog({ open, onOpenChange }: NewGroupDialogProps) {
  const queryClient = useQueryClient();

  const [name, setName] = useState("");
  const [home, setHome] = useState<FolderHome | null>(null);
  const [nameTouched, setNameTouched] = useState(false);
  const [pickerOpen, setPickerOpen] = useState(false);

  function reset() {
    setName("");
    setHome(null);
    setNameTouched(false);
  }

  const { mutate: doCreate, isPending } = useMutation(createGroup, {
    onSuccess: () => {
      toast.success("Group created", {
        description: home
          ? `${name.trim()} was added under ${home.path}.`
          : `${name.trim()} was added as a global group.`,
      });
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({ schema: listGroups, cardinality: undefined }),
      });
      reset();
      onOpenChange(false);
    },
    onError: (err) => {
      toast.error("Create failed", { description: connectErrorMessage(err) });
    },
  });

  const nameValid = isValidGroupName(name);

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    if (!next) reset();
    onOpenChange(next);
  }

  // Event type inferred from the JSX onSubmit prop — React 19's types deprecate
  // the named FormEvent alias.
  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (!nameValid || isPending) return;
    doCreate({ name: name.trim(), folderId: home?.id ?? "" });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[440px]">
        <DialogHeader>
          <DialogTitle className="text-[15px]">New group</DialogTitle>
          <DialogDescription className="text-[13px]">
            Create a group. Optionally give it a folder home to delegate its
            governance to that part of the catalog; leave it global otherwise.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {/* Name */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-group-name" className={FIELD_LABEL}>
              Name
            </label>
            <Input
              id="new-group-name"
              type="text"
              autoComplete="off"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setNameTouched(true)}
              placeholder="platform-oncall"
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

          {/* Folder home */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Folder home</span>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setPickerOpen(true)}
                className="h-9 flex-1 justify-start gap-2 text-[13px] font-normal"
              >
                {home ? (
                  <>
                    <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-left font-mono text-[12px]">
                      {home.path}
                    </span>
                  </>
                ) : (
                  <>
                    <Globe className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="flex-1 text-left text-muted-foreground">
                      Global (no folder home)
                    </span>
                  </>
                )}
              </Button>
              {home && (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={() => setHome(null)}
                  className="h-9 w-9 shrink-0 text-muted-foreground hover:text-foreground"
                  aria-label="Clear folder home"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </Button>
              )}
            </div>
            <p className={FIELD_HINT}>
              Optional. A folder home delegates this group's governance to that
              subtree.
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
              disabled={!nameValid || isPending}
              className="h-8 text-[13px]"
            >
              {isPending ? "Creating…" : "Create group"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>

      <FolderHomePicker
        open={pickerOpen}
        onOpenChange={setPickerOpen}
        onSelect={setHome}
      />
    </Dialog>
  );
}
