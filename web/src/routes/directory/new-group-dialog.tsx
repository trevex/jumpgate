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
import { toast } from "sonner";
import { Folder, Globe, X } from "lucide-react";
import {
  createGroup,
  listGroups,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import { listFolderContents } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
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
import { useInvalidateList } from "@/lib/query";
import { isValidGroupName } from "./group-actions";
import { FolderHomePicker, type FolderHome } from "./folder-home-picker";

interface NewGroupDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /**
   * Pre-set folder home. When provided the picker is replaced by a read-only
   * context row and the group is created homed in this folder. When omitted the
   * caller-driven picker behavior (global or pick a home) is kept.
   */
  folderId?: string;
  folderPath?: string;
}

const FIELD_LABEL =
  "text-micro font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-micro text-muted-foreground";
const FIELD_ERROR = "text-micro text-destructive";

export function NewGroupDialog({
  open,
  onOpenChange,
  folderId,
  folderPath,
}: NewGroupDialogProps) {
  const invalidateList = useInvalidateList();

  // When a folder home is pre-set by the caller, the group is created there and
  // the picker is not shown.
  const pinnedHome = folderId !== undefined;

  const [name, setName] = useState("");
  const [home, setHome] = useState<FolderHome | null>(null);
  const [nameTouched, setNameTouched] = useState(false);
  const [pickerOpen, setPickerOpen] = useState(false);

  // The effective folder id/path: pinned (from props) or picker-chosen.
  const effectiveFolderId = pinnedHome ? (folderId ?? "") : (home?.id ?? "");
  const effectiveFolderPath = pinnedHome ? folderPath : home?.path;

  function reset() {
    setName("");
    setHome(null);
    setNameTouched(false);
  }

  const { mutate: doCreate, isPending } = useMutation(createGroup, {
    onSuccess: () => {
      toast.success("Group created", {
        description: effectiveFolderPath
          ? `${name.trim()} was added under ${effectiveFolderPath}.`
          : `${name.trim()} was added as a global group.`,
      });
      void invalidateList([listGroups, listFolderContents]);
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
    doCreate({ name: name.trim(), folderId: effectiveFolderId });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[440px]">
        <DialogHeader>
          <DialogTitle className="text-title">New group</DialogTitle>
          <DialogDescription className="text-body">
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
              className="h-9 text-body"
              aria-invalid={nameTouched && !nameValid}
              aria-describedby="new-group-name-error"
            />
            {nameTouched && !nameValid ? (
              <p id="new-group-name-error" role="alert" className={FIELD_ERROR}>
                Use lowercase letters, digits, dashes or underscores (1–200
                characters).
              </p>
            ) : (
              <p id="new-group-name-error" className={FIELD_HINT}>
                Lowercase letters, digits, - and _.
              </p>
            )}
          </div>

          {/* Folder home */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Folder home</span>
            {pinnedHome ? (
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
                        Global (no folder home)
                      </span>
                    </>
                  )}
                </div>
                <p className={FIELD_HINT}>
                  This group is homed in the selected folder.
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
                {home ? (
                  <>
                    <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-left font-mono text-compact">
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
              disabled={!nameValid || isPending}
              className="h-8 text-body"
            >
              {isPending ? "Creating…" : "Create group"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>

      {!pinnedHome && (
        <FolderHomePicker
          open={pickerOpen}
          onOpenChange={setPickerOpen}
          onSelect={setHome}
        />
      )}
    </Dialog>
  );
}
