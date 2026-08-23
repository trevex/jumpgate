/**
 * delete-node.tsx — Catalog ▸ delete a folder or asset.
 *
 * Wraps the shared ConfirmDialog with a destructive confirm. Deletes via
 * DeleteFolder/DeleteAsset. On success: toast + race-safe invalidate of
 * `listFolderContents`, an optional `onDeleted` callback (so a caller viewing
 * the deleted node can navigate away), then close. On error: surface the
 * server message VERBATIM — a non-empty folder returns FailedPrecondition with
 * the blocker list, which the admin needs to read.
 *
 * Both mutation hooks are called unconditionally (React rules-of-hooks); which
 * `.mutate` fires is chosen at confirm time from `kind`.
 */

import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import {
  deleteFolder,
  deleteAsset,
  listFolderContents,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";

interface DeleteNodeProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  kind: "folder" | "asset";
  id: string;
  name: string;
  /** Fired after a successful delete (e.g. to navigate away from the node). */
  onDeleted?: () => void;
}

export function DeleteNode({
  open,
  onOpenChange,
  kind,
  id,
  name,
  onDeleted,
}: DeleteNodeProps) {
  const invalidateList = useInvalidateList();

  function onSuccess() {
    toast.success(kind === "folder" ? "Folder deleted" : "Asset deleted");
    void invalidateList(listFolderContents);
    onDeleted?.();
    onOpenChange(false);
  }

  function onError(err: unknown) {
    // Verbatim: a non-empty folder → FailedPrecondition with the blocker list.
    toast.error("Delete failed", { description: connectErrorMessage(err) });
  }

  const folderMut = useMutation(deleteFolder, { onSuccess, onError });
  const assetMut = useMutation(deleteAsset, { onSuccess, onError });

  const isPending = folderMut.isPending || assetMut.isPending;

  function handleConfirm() {
    if (isPending) return;
    if (kind === "folder") {
      folderMut.mutate({ folderId: id });
    } else {
      assetMut.mutate({ assetId: id });
    }
  }

  const description =
    kind === "folder" ? (
      <>
        Delete <span className="font-mono text-compact">{name}</span>? Only an
        empty folder can be deleted.
      </>
    ) : (
      <>
        Delete <span className="font-mono text-compact">{name}</span>? This
        permanently removes the asset, its credentials, and any access to it.
      </>
    );

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Delete this ${kind}?`}
      description={description}
      confirmLabel="Delete"
      pendingLabel="Deleting…"
      variant="destructive"
      pending={isPending}
      onConfirm={handleConfirm}
    />
  );
}
