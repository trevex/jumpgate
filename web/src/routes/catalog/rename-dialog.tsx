/**
 * rename-dialog.tsx — Catalog ▸ rename a folder or asset.
 *
 * A shadcn Dialog with a Name input pre-filled with the current name. Client
 * validation mirrors the sibling-uniqueness charset (`^[a-z0-9_-]+$`, 1–200).
 * Renames via UpdateFolder/UpdateAsset, setting ONLY `name` — the move field
 * (parent_id/folder_id) is left `undefined` so the node stays put. On success:
 * toast + race-safe invalidate of `listFolderContents`, then close. On error:
 * surface the server message via toast (e.g. AlreadyExists on a sibling clash).
 *
 * Both mutation hooks are called unconditionally (React rules-of-hooks); which
 * `.mutate` fires is chosen at submit time from `kind`.
 */

import { useEffect, useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import {
  updateFolder,
  updateAsset,
  listFolderContents,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
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
import { isValidCatalogName } from "./catalog-actions";

interface RenameDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  kind: "folder" | "asset";
  id: string;
  currentName: string;
}

const FIELD_LABEL =
  "text-micro font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-micro text-muted-foreground";
const FIELD_ERROR = "text-micro text-destructive";

export function RenameDialog({
  open,
  onOpenChange,
  kind,
  id,
  currentName,
}: RenameDialogProps) {
  const invalidateList = useInvalidateList();

  const [name, setName] = useState(currentName);
  const [nameTouched, setNameTouched] = useState(false);

  // Re-seed the input whenever the dialog (re)opens for a new node.
  useEffect(() => {
    if (open) {
      setName(currentName);
      setNameTouched(false);
    }
  }, [open, currentName]);

  function onSuccess() {
    toast.success(kind === "folder" ? "Folder renamed" : "Asset renamed");
    void invalidateList(listFolderContents);
    onOpenChange(false);
  }

  function onError(err: unknown) {
    toast.error("Rename failed", { description: connectErrorMessage(err) });
  }

  const folderMut = useMutation(updateFolder, { onSuccess, onError });
  const assetMut = useMutation(updateAsset, { onSuccess, onError });

  const isPending = folderMut.isPending || assetMut.isPending;
  const nameValid = isValidCatalogName(name);
  const unchanged = name.trim() === currentName.trim();

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    onOpenChange(next);
  }

  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (!nameValid || isPending) return;
    const newName = name.trim();
    if (kind === "folder") {
      // Set only `name`; leave `parentId` undefined so the folder stays put.
      folderMut.mutate({ folderId: id, name: newName });
    } else {
      // Set only `name`; leave `folderId` undefined so the asset stays put.
      assetMut.mutate({ assetId: id, name: newName });
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[440px]">
        <DialogHeader>
          <DialogTitle className="text-title">
            Rename {kind}
          </DialogTitle>
          <DialogDescription className="text-body">
            Give this {kind} a new name. Must be unique among its siblings.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="rename-name" className={FIELD_LABEL}>
              Name
            </label>
            <Input
              id="rename-name"
              type="text"
              autoComplete="off"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setNameTouched(true)}
              className="h-9 text-body"
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
              disabled={!nameValid || unchanged || isPending}
              className="h-8 text-body"
            >
              {isPending ? "Saving…" : "Save"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
