/**
 * move-dialog.tsx — Catalog ▸ move a folder or asset.
 *
 * A shadcn Dialog that picks a destination folder (via the reusable
 * FolderPicker) and moves the node there. Folders may additionally be moved to
 * the catalog root; assets always live in a folder, so they have no root
 * option. Moves via UpdateFolder/UpdateAsset:
 *
 *   - asset  → updateAsset  { assetId, folderId: destId }
 *   - folder → updateFolder { folderId, parentId: destId }   (into a folder)
 *   - folder → updateFolder { folderId, parentId: "" }        (to root)
 *
 * protobuf-es v2 presence: `parent_id`/`folder_id` are proto3 `optional`, so an
 * explicit "" in the init object is PRESENT-and-empty (→ root move) while an
 * omitted key is absent. We always assign the field here, so presence is set.
 *
 * On success: toast + race-safe invalidate of `listFolderContents`, then close.
 * On error: surface the server message VERBATIM — a containment/cycle violation
 * returns FailedPrecondition with a specific message the admin needs to read.
 *
 * Both mutation hooks are called unconditionally (React rules-of-hooks); which
 * `.mutate` fires is chosen at submit time from `kind`.
 */

import { useEffect, useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import { Folder, FolderTree } from "lucide-react";
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
import { connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";
import { FolderPicker, type PickedFolder } from "@/components/pickers/folder-picker";

interface MoveDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  kind: "folder" | "asset";
  id: string;
}

const FIELD_LABEL =
  "text-micro font-semibold uppercase tracking-wide text-muted-foreground";

// A discriminated destination: a real folder, or (folders only) the root.
type Destination =
  | { to: "folder"; folder: PickedFolder }
  | { to: "root" };

export function MoveDialog({ open, onOpenChange, kind, id }: MoveDialogProps) {
  const invalidateList = useInvalidateList();

  const [dest, setDest] = useState<Destination | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  // Reset the chosen destination each time the dialog (re)opens.
  useEffect(() => {
    if (open) setDest(null);
  }, [open]);

  function onSuccess() {
    toast.success(kind === "folder" ? "Folder moved" : "Asset moved");
    void invalidateList(listFolderContents);
    onOpenChange(false);
  }

  function onError(err: unknown) {
    // Verbatim: containment/cycle → FailedPrecondition with a specific message.
    toast.error("Move failed", { description: connectErrorMessage(err) });
  }

  const folderMut = useMutation(updateFolder, { onSuccess, onError });
  const assetMut = useMutation(updateAsset, { onSuccess, onError });

  const isPending = folderMut.isPending || assetMut.isPending;

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    onOpenChange(next);
  }

  function handleSubmit() {
    if (!dest || isPending) return;
    if (kind === "asset") {
      // Assets always live in a folder — no root option here.
      if (dest.to !== "folder") return;
      assetMut.mutate({ assetId: id, folderId: dest.folder.id });
    } else {
      // parent_id present-and-empty ("") = move to root; else the folder id.
      const parentId = dest.to === "root" ? "" : dest.folder.id;
      folderMut.mutate({ folderId: id, parentId });
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[440px]">
        <DialogHeader>
          <DialogTitle className="text-title">Move {kind}</DialogTitle>
          <DialogDescription className="text-body">
            Choose a destination folder for this {kind}
            {kind === "folder" ? ", or move it to the catalog root." : "."}
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Destination</span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setPickerOpen(true)}
              className="h-9 justify-start gap-2 text-body font-normal"
            >
              <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
              {dest?.to === "folder" ? (
                <span className="min-w-0 flex-1 truncate text-left font-mono text-compact">
                  {dest.folder.path}
                </span>
              ) : (
                <span className="flex-1 text-left text-muted-foreground">
                  Choose a folder…
                </span>
              )}
            </Button>

            {kind === "folder" && (
              <Button
                type="button"
                variant={dest?.to === "root" ? "secondary" : "ghost"}
                size="sm"
                onClick={() => setDest({ to: "root" })}
                className="h-8 justify-start gap-2 text-body font-normal"
              >
                <FolderTree className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                <span className="flex-1 text-left">Move to catalog root</span>
              </Button>
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
              type="button"
              size="sm"
              onClick={handleSubmit}
              disabled={!dest || isPending}
              className="h-8 text-body"
            >
              {isPending ? "Moving…" : "Move"}
            </Button>
          </DialogFooter>
        </div>
      </DialogContent>

      <FolderPicker
        open={pickerOpen}
        onOpenChange={setPickerOpen}
        onSelect={(folder) => setDest({ to: "folder", folder })}
      />
    </Dialog>
  );
}
