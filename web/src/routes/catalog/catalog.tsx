/**
 * catalog.tsx — two-pane governance-tree browser.
 *
 * Left pane: lazy expandable folder tree with kind filters.
 * Right pane: kind-adaptive detail view driven by selection.
 * Selection is persisted in the URL search param `?sel=<kind>:<id>` so it
 * survives page reload.
 */

import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { LayoutGrid } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { Tree } from "./tree";
import type { SelectedNode, NodeKind } from "./tree";
import { AssetDetail } from "./detail/asset";
import { RoleDetail } from "./detail/role";
import { GroupDetail } from "./detail/group";
import { FolderDetail } from "./detail/folder";

// ─── URL-param selection persistence ─────────────────────────────────────────

function encodeSelection(node: SelectedNode): string {
  // kind:id[:name[:path[:assetKind]]] — name/path are URL-encoded
  const parts = [
    node.kind,
    node.id,
    encodeURIComponent(node.name),
    encodeURIComponent(node.path ?? ""),
    encodeURIComponent(node.assetKind ?? ""),
  ];
  return parts.join(":");
}

function decodeSelection(raw: string): SelectedNode | null {
  const parts = raw.split(":");
  if (parts.length < 3) return null;
  const kind = parts[0] as NodeKind;
  if (!["folder", "asset", "role", "group"].includes(kind)) return null;
  return {
    kind,
    id: parts[1],
    name: decodeURIComponent(parts[2] ?? ""),
    path: decodeURIComponent(parts[3] ?? "") || undefined,
    assetKind: decodeURIComponent(parts[4] ?? "") || undefined,
  };
}

// ─── Detail pane switcher ─────────────────────────────────────────────────────

interface DetailProps {
  selected: SelectedNode | null;
}

function Detail({ selected }: DetailProps) {
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
        />
      );
  }
}

// ─── Catalog page ─────────────────────────────────────────────────────────────

export function CatalogPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  const rawSel = searchParams.get("sel");
  const selected = rawSel ? decodeSelection(rawSel) : null;

  const handleSelect = useCallback(
    (node: SelectedNode) => {
      setSearchParams({ sel: encodeSelection(node) }, { replace: true });
    },
    [setSearchParams],
  );

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
        <div className="flex h-10 shrink-0 items-center border-b border-border px-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground select-none">
            Catalog
          </h2>
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
          <Detail selected={selected} />
        </ScrollArea>
      </main>
    </div>
  );
}
