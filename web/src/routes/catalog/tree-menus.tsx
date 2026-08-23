/**
 * tree-menus.tsx — right-click context menus for catalog tree nodes, plus the
 * single set of dialogs they drive.
 *
 * Design — avoiding per-node dialog duplication:
 *   Rendering the create/rename/move/delete dialogs inside every tree node would
 *   mount hundreds of dialog instances. Instead a small **pending action** state
 *   is lifted to the Tree (via <TreeMenuProvider>) and the dialogs are rendered
 *   ONCE, at the tree root, driven by that state. A node's context menu merely
 *   calls a provider callback (`startCreate` / `startFolderAction` /
 *   `startAssetAction`) which sets the pending state; <TreeMenuDialogs> reads it
 *   and opens the matching dialog. This reuses the exact same dialogs as the
 *   detail-pane menus — no logic is duplicated.
 *
 * Cap-gating:
 *   The root create ("+") and detail menus gate on the caller's caps for the
 *   scope. For folder nodes we lazily fetch `getFolderAccess` when the menu opens
 *   so create/rename/move/delete gate on the folder-scoped capabilities; for
 *   asset nodes we lazily fetch `getAssetAccess` for its management caps. Until a
 *   fetch resolves the menu shows a compact loading row (the server is always the
 *   real gate). Role/group leaves currently get an "Open" action only — the
 *   catalog has no rename/move/delete dialogs for them.
 */

import {
  createContext,
  useContext,
  useState,
  type ReactNode,
} from "react";
import { useQuery } from "@connectrpc/connect-query";
import {
  FolderPlus,
  Server,
  Shield,
  UsersRound,
  Pencil,
  FolderInput,
  Trash2,
  SquareArrowOutUpRight,
  Loader2,
} from "lucide-react";
import {
  getFolderAccess,
  getAssetAccess,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import {
  ContextMenu,
  ContextMenuTrigger,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuLabel,
  ContextMenuSeparator,
} from "@/components/ui/context-menu";
import {
  canCreateFolder,
  canCreateAsset,
  canUpdateFolder,
  canDeleteFolder,
  canUpdateAsset,
  canDeleteAsset,
} from "./catalog-actions";
import { canCreateRole } from "@/routes/access-control/role-actions";
import { canCreateGroup } from "@/routes/directory/group-actions";
import { NewFolderDialog } from "./new-folder-dialog";
import { NewAssetWizard } from "./new-asset-wizard";
import { NewRoleDialog } from "@/routes/access-control/new-role-dialog";
import { NewGroupDialog } from "@/routes/directory/new-group-dialog";
import { RenameDialog } from "./rename-dialog";
import { MoveDialog } from "./move-dialog";
import { DeleteNode } from "./delete-node";
import type { SelectedNode } from "./tree";

// ─── Pending-action model (lifted to the Tree) ────────────────────────────────

type CreateKind = "folder" | "asset" | "role" | "group";

interface PendingCreate {
  kind: CreateKind;
  /** Parent folder id; undefined = catalog root. */
  parentId?: string;
  parentPath?: string;
}

type NodeAction = "rename" | "move" | "delete";

interface PendingAction {
  action: NodeAction;
  kind: "folder" | "asset";
  id: string;
  name: string;
}

interface TreeMenuCtx {
  startCreate: (c: PendingCreate) => void;
  startAction: (a: PendingAction) => void;
  /** Clears the current tree selection (used after a delete). */
  clearSelection: () => void;
}

const TreeMenuContext = createContext<TreeMenuCtx | null>(null);

function useTreeMenu(): TreeMenuCtx {
  const ctx = useContext(TreeMenuContext);
  if (!ctx) throw new Error("useTreeMenu must be used within a TreeMenuProvider");
  return ctx;
}

// ─── Provider + single dialog host ────────────────────────────────────────────

interface TreeMenuProviderProps {
  /** Fired after a node is deleted, so the shell can drop the `?sel=` selection. */
  onCleared?: () => void;
  children: ReactNode;
}

/**
 * Wraps the tree and renders the create/rename/move/delete dialogs ONCE, driven
 * by pending state. Context-menu items call `startCreate` / `startAction`.
 */
export function TreeMenuProvider({ onCleared, children }: TreeMenuProviderProps) {
  const [pendingCreate, setPendingCreate] = useState<PendingCreate | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);

  const ctx: TreeMenuCtx = {
    startCreate: setPendingCreate,
    startAction: setPendingAction,
    clearSelection: () => onCleared?.(),
  };

  return (
    <TreeMenuContext.Provider value={ctx}>
      {children}

      {/* ── Create dialogs (one instance each, keyed to re-mount per target) ── */}
      {pendingCreate?.kind === "folder" && (
        <NewFolderDialog
          key={`nf-${pendingCreate.parentId ?? "root"}`}
          open
          onOpenChange={(o) => !o && setPendingCreate(null)}
          parentId={pendingCreate.parentId}
          parentPath={pendingCreate.parentPath}
        />
      )}
      {pendingCreate?.kind === "asset" && pendingCreate.parentId !== undefined && (
        <NewAssetWizard
          key={`na-${pendingCreate.parentId}`}
          open
          onOpenChange={(o) => !o && setPendingCreate(null)}
          folderId={pendingCreate.parentId}
          folderPath={pendingCreate.parentPath}
        />
      )}
      {pendingCreate?.kind === "role" && (
        <NewRoleDialog
          key={`nr-${pendingCreate.parentId ?? "global"}`}
          open
          onOpenChange={(o) => !o && setPendingCreate(null)}
          folderId={pendingCreate.parentId}
          folderPath={pendingCreate.parentPath}
        />
      )}
      {pendingCreate?.kind === "group" && (
        <NewGroupDialog
          key={`ng-${pendingCreate.parentId ?? "global"}`}
          open
          onOpenChange={(o) => !o && setPendingCreate(null)}
          folderId={pendingCreate.parentId}
          folderPath={pendingCreate.parentPath}
        />
      )}

      {/* ── Node action dialogs (rename / move / delete) ── */}
      {pendingAction?.action === "rename" && (
        <RenameDialog
          key={`rn-${pendingAction.id}`}
          open
          onOpenChange={(o) => !o && setPendingAction(null)}
          kind={pendingAction.kind}
          id={pendingAction.id}
          currentName={pendingAction.name}
        />
      )}
      {pendingAction?.action === "move" && (
        <MoveDialog
          key={`mv-${pendingAction.id}`}
          open
          onOpenChange={(o) => !o && setPendingAction(null)}
          kind={pendingAction.kind}
          id={pendingAction.id}
        />
      )}
      {pendingAction?.action === "delete" && (
        <DeleteNode
          key={`del-${pendingAction.id}`}
          open
          onOpenChange={(o) => !o && setPendingAction(null)}
          kind={pendingAction.kind}
          id={pendingAction.id}
          name={pendingAction.name}
          onDeleted={() => onCleared?.()}
        />
      )}
    </TreeMenuContext.Provider>
  );
}

// ─── Loading row (menu still fetching caps) ───────────────────────────────────

function MenuLoadingRow() {
  return (
    <div className="flex items-center gap-2 px-2 py-1.5 text-sm text-muted-foreground">
      <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
      Loading…
    </div>
  );
}

// ─── Folder context menu ──────────────────────────────────────────────────────

interface FolderContextMenuProps {
  folder: { id: string; name: string; path: string };
  children: ReactNode;
}

/**
 * Right-click menu for a folder node: create child folder/asset/role/group +
 * rename/move/delete. Gated on the folder-scoped capabilities, fetched lazily
 * when the menu first opens.
 */
export function FolderContextMenu({ folder, children }: FolderContextMenuProps) {
  const { startCreate, startAction } = useTreeMenu();
  const [opened, setOpened] = useState(false);

  // Fetch folder-scoped caps only once the menu has been opened at least once.
  const { data, isLoading } = useQuery(
    getFolderAccess,
    { folderId: folder.id },
    { enabled: opened },
  );
  const caps = data?.capabilities ?? [];

  const mayFolder = canCreateFolder(caps);
  const mayAsset = canCreateAsset(caps);
  const mayRole = canCreateRole(caps);
  const mayGroup = canCreateGroup(caps);
  const mayUpdate = canUpdateFolder(caps);
  const mayDelete = canDeleteFolder(caps);
  const anyCreate = mayFolder || mayAsset || mayRole || mayGroup;
  const anyAction = anyCreate || mayUpdate || mayDelete;

  return (
    <ContextMenu onOpenChange={(o) => o && setOpened(true)}>
      <ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
      <ContextMenuContent className="w-48">
        <ContextMenuLabel className="truncate text-xs text-muted-foreground">
          {folder.name}
        </ContextMenuLabel>
        <ContextMenuSeparator />
        {isLoading && !data ? (
          <MenuLoadingRow />
        ) : !anyAction ? (
          <ContextMenuItem disabled>No actions available</ContextMenuItem>
        ) : (
          <>
            {mayFolder && (
              <ContextMenuItem
                onSelect={() =>
                  startCreate({ kind: "folder", parentId: folder.id, parentPath: folder.path })
                }
              >
                <FolderPlus className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                New folder
              </ContextMenuItem>
            )}
            {mayAsset && (
              <ContextMenuItem
                onSelect={() =>
                  startCreate({ kind: "asset", parentId: folder.id, parentPath: folder.path })
                }
              >
                <Server className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                New asset
              </ContextMenuItem>
            )}
            {mayRole && (
              <ContextMenuItem
                onSelect={() =>
                  startCreate({ kind: "role", parentId: folder.id, parentPath: folder.path })
                }
              >
                <Shield className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                New role
              </ContextMenuItem>
            )}
            {mayGroup && (
              <ContextMenuItem
                onSelect={() =>
                  startCreate({ kind: "group", parentId: folder.id, parentPath: folder.path })
                }
              >
                <UsersRound className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                New group
              </ContextMenuItem>
            )}
            {(mayUpdate || mayDelete) && anyCreate && <ContextMenuSeparator />}
            {mayUpdate && (
              <>
                <ContextMenuItem
                  onSelect={() =>
                    startAction({ action: "rename", kind: "folder", id: folder.id, name: folder.name })
                  }
                >
                  <Pencil className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                  Rename
                </ContextMenuItem>
                <ContextMenuItem
                  onSelect={() =>
                    startAction({ action: "move", kind: "folder", id: folder.id, name: folder.name })
                  }
                >
                  <FolderInput className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                  Move
                </ContextMenuItem>
              </>
            )}
            {mayDelete && (
              <ContextMenuItem
                className="text-destructive focus:text-destructive"
                onSelect={() =>
                  startAction({ action: "delete", kind: "folder", id: folder.id, name: folder.name })
                }
              >
                <Trash2 className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                Delete
              </ContextMenuItem>
            )}
          </>
        )}
      </ContextMenuContent>
    </ContextMenu>
  );
}

// ─── Asset context menu ───────────────────────────────────────────────────────

interface AssetContextMenuProps {
  asset: { id: string; name: string };
  /** Selects the node in the tree (opens the detail pane). */
  onOpen: () => void;
  children: ReactNode;
}

/**
 * Right-click menu for an asset node: Open + rename/move/delete. Gated on the
 * asset's management capabilities, fetched lazily when the menu first opens.
 */
export function AssetContextMenu({ asset, onOpen, children }: AssetContextMenuProps) {
  const { startAction } = useTreeMenu();
  const [opened, setOpened] = useState(false);

  const { data, isLoading } = useQuery(
    getAssetAccess,
    { assetId: asset.id },
    { enabled: opened },
  );
  const mgmt = data?.managementCapabilities ?? [];
  const mayUpdate = canUpdateAsset(mgmt);
  const mayDelete = canDeleteAsset(mgmt);

  return (
    <ContextMenu onOpenChange={(o) => o && setOpened(true)}>
      <ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
      <ContextMenuContent className="w-48">
        <ContextMenuLabel className="truncate text-xs text-muted-foreground">
          {asset.name}
        </ContextMenuLabel>
        <ContextMenuSeparator />
        <ContextMenuItem onSelect={onOpen}>
          <SquareArrowOutUpRight className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
          Open
        </ContextMenuItem>
        {isLoading && !data ? (
          <MenuLoadingRow />
        ) : (
          (mayUpdate || mayDelete) && (
            <>
              <ContextMenuSeparator />
              {mayUpdate && (
                <>
                  <ContextMenuItem
                    onSelect={() =>
                      startAction({ action: "rename", kind: "asset", id: asset.id, name: asset.name })
                    }
                  >
                    <Pencil className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                    Rename
                  </ContextMenuItem>
                  <ContextMenuItem
                    onSelect={() =>
                      startAction({ action: "move", kind: "asset", id: asset.id, name: asset.name })
                    }
                  >
                    <FolderInput className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                    Move
                  </ContextMenuItem>
                </>
              )}
              {mayDelete && (
                <ContextMenuItem
                  className="text-destructive focus:text-destructive"
                  onSelect={() =>
                    startAction({ action: "delete", kind: "asset", id: asset.id, name: asset.name })
                  }
                >
                  <Trash2 className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                  Delete
                </ContextMenuItem>
              )}
            </>
          )
        )}
      </ContextMenuContent>
    </ContextMenu>
  );
}

// ─── Leaf (role / group) context menu ─────────────────────────────────────────

interface LeafContextMenuProps {
  node: Pick<SelectedNode, "name">;
  onOpen: () => void;
  children: ReactNode;
}

/**
 * Right-click menu for role/group leaves. The catalog has no rename/move/delete
 * dialogs for these, so the first version offers "Open" (select) only.
 */
export function LeafContextMenu({ node, onOpen, children }: LeafContextMenuProps) {
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
      <ContextMenuContent className="w-44">
        <ContextMenuLabel className="truncate text-xs text-muted-foreground">
          {node.name}
        </ContextMenuLabel>
        <ContextMenuSeparator />
        <ContextMenuItem onSelect={onOpen}>
          <SquareArrowOutUpRight className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
          Open
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}
