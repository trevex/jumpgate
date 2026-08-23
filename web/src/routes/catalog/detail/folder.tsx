/**
 * folder.tsx — folder detail pane.
 *
 * Shows the caller's management capabilities on one folder, plus (gated on
 * those same per-folder capabilities) an authoring action menu: create a child
 * folder/asset, rename, move, or delete this folder. Deleting fires
 * `onCleared` so the two-pane shell can drop the `?sel=` selection and reset
 * the detail view.
 */

import { useState } from "react";
import { useQuery } from "@connectrpc/connect-query";
import { Folder, MoreHorizontal, Pencil, FolderInput, Trash2 } from "lucide-react";
import { getFolderAccess } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import { CapList, DetailSection, DetailSkeleton, DetailError } from "./shared";
import { canUpdateFolder, canDeleteFolder } from "../catalog-actions";
import { CreateMenu } from "../create-menu";
import { RenameDialog } from "../rename-dialog";
import { MoveDialog } from "../move-dialog";
import { DeleteNode } from "../delete-node";

export interface FolderDetailProps {
  id: string;
  name: string;
  path?: string;
  /** Fired after this folder is deleted, so the shell can clear the selection. */
  onCleared?: () => void;
}

export function FolderDetail({ id, name, path, onCleared }: FolderDetailProps) {
  const { data, isLoading, isError, error } = useQuery(
    getFolderAccess,
    { folderId: id },
  );

  const [renameOpen, setRenameOpen] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  if (isLoading) return <DetailSkeleton />;
  if (isError) return <DetailError error={error} />;
  if (!data) return null;

  const caps = data.capabilities;
  const mayUpdate = canUpdateFolder(caps);
  const mayDelete = canDeleteFolder(caps);
  // The "…" menu holds only rename/move/delete now; creation lives in CreateMenu.
  const hasActions = mayUpdate || mayDelete;

  return (
    <article className="flex flex-col gap-5 p-5" aria-label={`Folder: ${name}`}>
      {/* Header */}
      <header className="flex flex-col gap-1">
        <div className="flex items-start gap-2">
          <Folder className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <h2 className="min-w-0 flex-1 text-title font-semibold leading-tight text-foreground">
            {name}
          </h2>
          {/* Create menu owns child creation (folder/asset/role/group). */}
          <CreateMenu
            folderId={id}
            folderPath={path}
            caps={caps}
            trigger="button"
          />
          {hasActions && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  className="h-7 w-7 shrink-0 text-muted-foreground hover:text-foreground"
                  aria-label={`Actions for folder ${name}`}
                >
                  <MoreHorizontal className="h-4 w-4" aria-hidden="true" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                {mayUpdate && (
                  <>
                    <DropdownMenuItem
                      onSelect={() => setRenameOpen(true)}
                      className="text-body"
                    >
                      <Pencil className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                      Rename
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onSelect={() => setMoveOpen(true)}
                      className="text-body"
                    >
                      <FolderInput className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                      Move
                    </DropdownMenuItem>
                  </>
                )}
                {mayDelete && (
                  <DropdownMenuItem
                    onSelect={() => setDeleteOpen(true)}
                    className="text-body text-destructive focus:text-destructive"
                  >
                    <Trash2 className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                    Delete
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
        {path && (
          <p className="pl-6 font-mono text-micro text-muted-foreground" aria-label="Folder path">
            {path}
          </p>
        )}
      </header>

      <div className="h-px bg-border" role="separator" />

      {/* Management capabilities */}
      <DetailSection title="Your management capabilities on this folder">
        <CapList caps={caps} />
      </DetailSection>

      {/* ── Authoring dialogs (rename/move/delete; creation is in CreateMenu) ── */}
      {mayUpdate && (
        <>
          <RenameDialog
            open={renameOpen}
            onOpenChange={setRenameOpen}
            kind="folder"
            id={id}
            currentName={name}
          />
          <MoveDialog
            open={moveOpen}
            onOpenChange={setMoveOpen}
            kind="folder"
            id={id}
          />
        </>
      )}
      {mayDelete && (
        <DeleteNode
          open={deleteOpen}
          onOpenChange={setDeleteOpen}
          kind="folder"
          id={id}
          name={name}
          onDeleted={onCleared}
        />
      )}
    </article>
  );
}
