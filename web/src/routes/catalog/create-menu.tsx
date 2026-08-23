/**
 * create-menu.tsx — unified "create" affordance for the Catalog.
 *
 * A single capability-gated DropdownMenu that offers, in one place, the four
 * catalog-authoring create actions: New folder, New asset, New role, New group.
 * The menu owns the dialog open-state and renders only the dialogs the caller
 * may create; each is threaded the current folder context (`folderId`/
 * `folderPath`) so creation lands in the right place:
 *
 *   - At a folder (folderId set): New folder / New asset / New role / New group
 *     all create under that folder.
 *   - At the root (folderId undefined): New folder → root; New role / New group
 *     → global; New asset is hidden (assets always live in a folder).
 *
 * Everything here is capability-gated — the server remains the real gate. If the
 * caller holds none of the four create capabilities, the component renders null.
 */

import { useState } from "react";
import {
  FolderPlus,
  Server,
  Shield,
  UsersRound,
  Plus,
  ChevronDown,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { canCreateFolder, canCreateAsset } from "./catalog-actions";
import { canCreateRole } from "@/routes/access-control/role-actions";
import { canCreateGroup } from "@/routes/directory/group-actions";
import { NewFolderDialog } from "./new-folder-dialog";
import { NewAssetWizard } from "./new-asset-wizard";
import { NewRoleDialog } from "@/routes/access-control/new-role-dialog";
import { NewGroupDialog } from "@/routes/directory/new-group-dialog";

export interface CreateMenuProps {
  /** Current folder context; undefined = catalog root. */
  folderId?: string;
  /** Current folder path, shown for context in the create dialogs. */
  folderPath?: string;
  /** The caller's capabilities on this scope (drives per-item gating). */
  caps: string[];
  /**
   * Trigger style. "plus" → a ghost icon button (aria-label "Create…"); "button"
   * → a small labelled "New" button with a chevron. Defaults to "plus".
   */
  trigger?: "plus" | "button";
}

/**
 * A unified create menu. Cap-gated per item; the whole thing hides when the
 * caller can create nothing. Owns its own dialog state so callers only need to
 * mount one component.
 */
export function CreateMenu({
  folderId,
  folderPath,
  caps,
  trigger = "plus",
}: CreateMenuProps) {
  const [folderOpen, setFolderOpen] = useState(false);
  const [assetOpen, setAssetOpen] = useState(false);
  const [roleOpen, setRoleOpen] = useState(false);
  const [groupOpen, setGroupOpen] = useState(false);

  const mayFolder = canCreateFolder(caps);
  // Assets need a folder home — only offered inside a folder.
  const mayAsset = folderId !== undefined && canCreateAsset(caps);
  const mayRole = canCreateRole(caps);
  const mayGroup = canCreateGroup(caps);

  if (!mayFolder && !mayAsset && !mayRole && !mayGroup) return null;

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          {trigger === "button" ? (
            <Button
              variant="outline"
              size="sm"
              className="h-7 shrink-0 gap-1 text-compact"
              aria-label="Create…"
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              New
              <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
            </Button>
          ) : (
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 text-muted-foreground hover:text-foreground"
              aria-label="Create…"
              title="Create…"
            >
              <Plus className="h-4 w-4" aria-hidden="true" />
            </Button>
          )}
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-44">
          {mayFolder && (
            <DropdownMenuItem
              onSelect={() => setFolderOpen(true)}
              className="text-body"
            >
              <FolderPlus className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
              New folder
            </DropdownMenuItem>
          )}
          {mayAsset && (
            <DropdownMenuItem
              onSelect={() => setAssetOpen(true)}
              className="text-body"
            >
              <Server className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
              New asset
            </DropdownMenuItem>
          )}
          {(mayRole || mayGroup) && (mayFolder || mayAsset) && (
            <DropdownMenuSeparator />
          )}
          {mayRole && (
            <DropdownMenuItem
              onSelect={() => setRoleOpen(true)}
              className="text-body"
            >
              <Shield className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
              New role
            </DropdownMenuItem>
          )}
          {mayGroup && (
            <DropdownMenuItem
              onSelect={() => setGroupOpen(true)}
              className="text-body"
            >
              <UsersRound className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
              New group
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Dialogs — only mounted for actions the caller may take. */}
      {mayFolder && (
        <NewFolderDialog
          open={folderOpen}
          onOpenChange={setFolderOpen}
          parentId={folderId}
          parentPath={folderPath}
        />
      )}
      {mayAsset && folderId !== undefined && (
        <NewAssetWizard
          open={assetOpen}
          onOpenChange={setAssetOpen}
          folderId={folderId}
          folderPath={folderPath}
        />
      )}
      {mayRole && (
        <NewRoleDialog
          open={roleOpen}
          onOpenChange={setRoleOpen}
          folderId={folderId}
          folderPath={folderPath}
        />
      )}
      {mayGroup && (
        <NewGroupDialog
          open={groupOpen}
          onOpenChange={setGroupOpen}
          folderId={folderId}
          folderPath={folderPath}
        />
      )}
    </>
  );
}
