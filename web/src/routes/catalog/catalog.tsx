/**
 * catalog.tsx — two-pane governance-tree browser.
 *
 * Left pane: lazy expandable folder tree with kind filters.
 * Right pane: kind-adaptive detail view driven by selection.
 * Selection is persisted in the URL search param `?sel=<kind>:<id>` so it
 * survives page reload.
 */

import { useCallback, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { LayoutGrid, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { useCapabilities } from "@/lib/capabilities";
import { Tree } from "./tree";
import type { SelectedNode } from "./tree";
import { AssetDetail } from "./detail/asset";
import { RoleDetail } from "./detail/role";
import { GroupDetail } from "./detail/group";
import { FolderDetail } from "./detail/folder";
import { encodeSelection, decodeSelection } from "./selection";
import { canCreateFolder } from "./catalog-actions";
import { NewFolderDialog } from "./new-folder-dialog";

// ─── Detail pane switcher ─────────────────────────────────────────────────────

interface DetailProps {
  selected: SelectedNode | null;
  /** Clears the `?sel=` selection (e.g. after the selected node is deleted). */
  onCleared: () => void;
}

function Detail({ selected, onCleared }: DetailProps) {
  if (!selected) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-center">
        <LayoutGrid className="h-10 w-10 text-muted-foreground/30" aria-hidden="true" />
        <div>
          <p className="text-[13px] font-medium text-foreground">Select an item</p>
          <p className="mt-0.5 text-[12px] text-muted-foreground">
            Choose a folder, asset, role, or group from the tree to view details.
          </p>
        </div>
      </div>
    );
  }

  switch (selected.kind) {
    case "asset":
      return (
        <AssetDetail
          id={selected.id}
          name={selected.name}
          path={selected.path}
          assetKind={selected.assetKind}
          onCleared={onCleared}
        />
      );
    case "role":
      return <RoleDetail id={selected.id} name={selected.name} />;
    case "group":
      return <GroupDetail id={selected.id} name={selected.name} />;
    case "folder":
      return (
        <FolderDetail
          id={selected.id}
          name={selected.name}
          path={selected.path}
          onCleared={onCleared}
        />
      );
  }
}

// ─── Catalog page ─────────────────────────────────────────────────────────────

export function CatalogPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const caps = useCapabilities();
  const showRootCreate = canCreateFolder(caps);
  const [newFolderOpen, setNewFolderOpen] = useState(false);

  const rawSel = searchParams.get("sel");
  const selected = rawSel ? decodeSelection(rawSel) : null;

  const handleSelect = useCallback(
    (node: SelectedNode) => {
      setSearchParams({ sel: encodeSelection(node) }, { replace: true });
    },
    [setSearchParams],
  );

  // Drop the `?sel=` param so the detail pane resets (e.g. after a delete).
  const clearSelection = useCallback(() => {
    setSearchParams({}, { replace: true });
  }, [setSearchParams]);

  return (
    <div className="flex h-full">
      {/* ── Left: tree pane ── */}
      <aside
        className={cn(
          "flex w-64 shrink-0 flex-col border-r border-border bg-sidebar",
          "overflow-hidden",
        )}
        aria-label="Catalog tree"
      >
        {/* Pane header */}
        <div className="flex h-10 shrink-0 items-center justify-between border-b border-border px-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground select-none">
            Catalog
          </h2>
          {showRootCreate && (
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setNewFolderOpen(true)}
              className="h-6 w-6 text-muted-foreground hover:text-foreground"
              aria-label="New root folder"
              title="New folder"
            >
              <Plus className="h-4 w-4" aria-hidden="true" />
            </Button>
          )}
        </div>
        <div className="min-h-0 flex-1">
          <Tree selected={selected} onSelect={handleSelect} />
        </div>
      </aside>

      {/* ── Right: detail pane ── */}
      <main
        className="flex min-w-0 flex-1 flex-col overflow-hidden"
        aria-label="Item detail"
        id="catalog-detail"
      >
        <ScrollArea className="h-full">
          <Detail selected={selected} onCleared={clearSelection} />
        </ScrollArea>
      </main>

      {showRootCreate && (
        <NewFolderDialog open={newFolderOpen} onOpenChange={setNewFolderOpen} />
      )}
    </div>
  );
}
