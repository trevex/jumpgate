/**
 * tree.tsx — lazy governance-tree browser for the Catalog page.
 *
 * Renders a two-level lazy tree: root folders load on mount; child folders
 * expand on first click. Each folder node groups its children by kind
 * (sub-folders → Assets → Roles → Groups). When a kind's has_more flag is
 * set the initial 50-item slice is replaced by a fully-paginated "load more"
 * list via the typed per-kind List RPC.
 */

import { useState, useCallback } from "react";
import { useQuery, useInfiniteQuery } from "@connectrpc/connect-query";
import {
  ChevronRight,
  Folder,
  FolderOpen,
  Server,
  KeyRound,
  Users,
  Loader2,
  AlertCircle,
} from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ErrorState } from "@/components/states/states";
import { cn } from "@/lib/utils";
import { listFolderContents, listAssets, listFolders } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { listRoles } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import { listGroups } from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import { folderContentsToNodes } from "./tree-model";
import type { FolderNode, AssetNode, RoleNode, GroupNode } from "./tree-model";

// ─── Selection ───────────────────────────────────────────────────────────────

export type NodeKind = "folder" | "asset" | "role" | "group";

export interface SelectedNode {
  kind: NodeKind;
  id: string;
  name: string;
  /** Extra metadata forwarded to the detail pane */
  path?: string;
  assetKind?: string;
}

// ─── Kind filter chips ────────────────────────────────────────────────────────

const KIND_LABELS: { kind: NodeKind; label: string }[] = [
  { kind: "folder", label: "Folders" },
  { kind: "asset", label: "Assets" },
  { kind: "role", label: "Roles" },
  { kind: "group", label: "Groups" },
];

interface KindFilterProps {
  active: Set<NodeKind>;
  onChange: (next: Set<NodeKind>) => void;
}

function KindFilter({ active, onChange }: KindFilterProps) {
  const toggle = (kind: NodeKind) => {
    const next = new Set(active);
    if (next.has(kind)) {
      // Keep at least one kind visible
      if (next.size > 1) next.delete(kind);
    } else {
      next.add(kind);
    }
    onChange(next);
  };

  return (
    <div className="flex flex-wrap gap-1 px-3 py-2 border-b border-border" role="group" aria-label="Filter by kind">
      {KIND_LABELS.map(({ kind, label }) => (
        <button
          key={kind}
          onClick={() => toggle(kind)}
          aria-pressed={active.has(kind)}
          className={cn(
            "inline-flex items-center rounded px-2 py-0.5 text-eyebrow font-medium transition-colors duration-150",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
            active.has(kind)
              ? "bg-primary/10 text-primary"
              : "text-muted-foreground hover:bg-accent hover:text-foreground",
          )}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

// ─── Paginated "show all" lists ───────────────────────────────────────────────

interface ShowAllAssetsProps {
  folderId: string;
  onSelect: (node: SelectedNode) => void;
  selected: SelectedNode | null;
}

function ShowAllAssets({ folderId, onSelect, selected }: ShowAllAssetsProps) {
  const { data, fetchNextPage, hasNextPage, isFetchingNextPage, isLoading } =
    useInfiniteQuery(
      listAssets,
      { parent: folderId, cascade: false, pageSize: 50, pageToken: "" },
      {
        pageParamKey: "pageToken",
        getNextPageParam: (last) => last.nextPageToken || undefined,
      },
    );

  if (isLoading) return <TreeSkeleton rows={3} />;

  const assets = data?.pages.flatMap((p) => p.assets) ?? [];

  return (
    <>
      {assets.map((a) => (
        <AssetLeaf
          key={a.id}
          asset={{ id: a.id, name: a.name, path: a.path, kind: a.kind }}
          depth={2}
          selected={selected}
          onSelect={onSelect}
        />
      ))}
      {hasNextPage && (
        <button
          onClick={() => fetchNextPage()}
          disabled={isFetchingNextPage}
          className="flex items-center gap-1.5 pl-10 pr-3 py-1 text-micro text-primary hover:underline disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label="Load more assets"
        >
          {isFetchingNextPage ? (
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
          ) : null}
          Load more
        </button>
      )}
    </>
  );
}

interface ShowAllRolesProps {
  folderId: string;
  onSelect: (node: SelectedNode) => void;
  selected: SelectedNode | null;
}

function ShowAllRoles({ folderId, onSelect, selected }: ShowAllRolesProps) {
  const { data, fetchNextPage, hasNextPage, isFetchingNextPage, isLoading } =
    useInfiniteQuery(
      listRoles,
      { parent: folderId, cascade: false, pageSize: 50, pageToken: "" },
      {
        pageParamKey: "pageToken",
        getNextPageParam: (last) => last.nextPageToken || undefined,
      },
    );

  if (isLoading) return <TreeSkeleton rows={3} />;

  const roles = data?.pages.flatMap((p) => p.roles) ?? [];

  return (
    <>
      {roles.map((r) => (
        <RoleLeaf
          key={r.id}
          role={{ id: r.id, name: r.name, folderPath: r.folderPath }}
          depth={2}
          selected={selected}
          onSelect={onSelect}
        />
      ))}
      {hasNextPage && (
        <button
          onClick={() => fetchNextPage()}
          disabled={isFetchingNextPage}
          className="flex items-center gap-1.5 pl-10 pr-3 py-1 text-micro text-primary hover:underline disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label="Load more roles"
        >
          {isFetchingNextPage ? (
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
          ) : null}
          Load more
        </button>
      )}
    </>
  );
}

interface ShowAllGroupsProps {
  folderId: string;
  onSelect: (node: SelectedNode) => void;
  selected: SelectedNode | null;
}

function ShowAllGroups({ folderId, onSelect, selected }: ShowAllGroupsProps) {
  const { data, fetchNextPage, hasNextPage, isFetchingNextPage, isLoading } =
    useInfiniteQuery(
      listGroups,
      { parent: folderId, cascade: false, pageSize: 50, pageToken: "" },
      {
        pageParamKey: "pageToken",
        getNextPageParam: (last) => last.nextPageToken || undefined,
      },
    );

  if (isLoading) return <TreeSkeleton rows={3} />;

  const groups = data?.pages.flatMap((p) => p.groups) ?? [];

  return (
    <>
      {groups.map((g) => (
        <GroupLeaf
          key={g.id}
          group={{ id: g.id, name: g.name, folderPath: g.folderPath }}
          depth={2}
          selected={selected}
          onSelect={onSelect}
        />
      ))}
      {hasNextPage && (
        <button
          onClick={() => fetchNextPage()}
          disabled={isFetchingNextPage}
          className="flex items-center gap-1.5 pl-10 pr-3 py-1 text-micro text-primary hover:underline disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label="Load more groups"
        >
          {isFetchingNextPage ? (
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
          ) : null}
          Load more
        </button>
      )}
    </>
  );
}

interface ShowAllFoldersProps {
  folderId: string;
  onSelect: (node: SelectedNode) => void;
  selected: SelectedNode | null;
  filter: Set<NodeKind>;
}

function ShowAllFolders({ folderId, onSelect, selected, filter }: ShowAllFoldersProps) {
  const { data, fetchNextPage, hasNextPage, isFetchingNextPage, isLoading } =
    useInfiniteQuery(
      listFolders,
      { parent: folderId, cascade: false, pageSize: 50, pageToken: "" },
      {
        pageParamKey: "pageToken",
        getNextPageParam: (last) => last.nextPageToken || undefined,
      },
    );

  if (isLoading) return <TreeSkeleton rows={3} />;

  const folders = data?.pages.flatMap((p) => p.folders) ?? [];

  return (
    <>
      {folders.map((f) => (
        <FolderNode_
          key={f.id}
          folder={{ id: f.id, name: f.name, path: f.path, parentId: f.parentId }}
          depth={1}
          selected={selected}
          onSelect={onSelect}
          filter={filter}
        />
      ))}
      {hasNextPage && (
        <button
          onClick={() => fetchNextPage()}
          disabled={isFetchingNextPage}
          className="flex items-center gap-1.5 pl-6 pr-3 py-1 text-micro text-primary hover:underline disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label="Load more folders"
        >
          {isFetchingNextPage ? (
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
          ) : null}
          Load more
        </button>
      )}
    </>
  );
}

// ─── Leaf nodes ───────────────────────────────────────────────────────────────

function leafIndent(depth: number) {
  return { paddingLeft: `${depth * 16 + 8}px` };
}

interface AssetLeafProps {
  asset: AssetNode;
  depth: number;
  selected: SelectedNode | null;
  onSelect: (node: SelectedNode) => void;
}

function AssetLeaf({ asset, depth, selected, onSelect }: AssetLeafProps) {
  const isSelected = selected?.kind === "asset" && selected.id === asset.id;
  return (
    <button
      style={leafIndent(depth)}
      onClick={() =>
        onSelect({ kind: "asset", id: asset.id, name: asset.name, path: asset.path, assetKind: asset.kind })
      }
      aria-current={isSelected ? "true" : undefined}
      className={cn(
        "group flex w-full items-center gap-2 py-1 pr-3 text-left text-compact transition-colors duration-100",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset",
        isSelected
          ? "bg-primary/10 text-primary font-medium"
          : "text-foreground hover:bg-accent hover:text-foreground",
      )}
    >
      <Server
        className={cn(
          "h-3.5 w-3.5 shrink-0 transition-colors",
          isSelected ? "text-primary" : "text-muted-foreground group-hover:text-foreground",
        )}
        aria-hidden="true"
      />
      <span className="flex-1 truncate">{asset.name}</span>
      {asset.kind && (
        <span className="shrink-0 rounded px-1 py-0 text-eyebrow font-mono uppercase tracking-wide bg-muted text-muted-foreground">
          {asset.kind}
        </span>
      )}
    </button>
  );
}

interface RoleLeafProps {
  role: RoleNode;
  depth: number;
  selected: SelectedNode | null;
  onSelect: (node: SelectedNode) => void;
}

function RoleLeaf({ role, depth, selected, onSelect }: RoleLeafProps) {
  const isSelected = selected?.kind === "role" && selected.id === role.id;
  return (
    <button
      style={leafIndent(depth)}
      onClick={() => onSelect({ kind: "role", id: role.id, name: role.name })}
      aria-current={isSelected ? "true" : undefined}
      className={cn(
        "group flex w-full items-center gap-2 py-1 pr-3 text-left text-compact transition-colors duration-100",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset",
        isSelected
          ? "bg-primary/10 text-primary font-medium"
          : "text-foreground hover:bg-accent hover:text-foreground",
      )}
    >
      <KeyRound
        className={cn(
          "h-3.5 w-3.5 shrink-0 transition-colors",
          isSelected ? "text-primary" : "text-muted-foreground group-hover:text-foreground",
        )}
        aria-hidden="true"
      />
      <span className="flex-1 truncate">{role.name}</span>
    </button>
  );
}

interface GroupLeafProps {
  group: GroupNode;
  depth: number;
  selected: SelectedNode | null;
  onSelect: (node: SelectedNode) => void;
}

function GroupLeaf({ group, depth, selected, onSelect }: GroupLeafProps) {
  const isSelected = selected?.kind === "group" && selected.id === group.id;
  return (
    <button
      style={leafIndent(depth)}
      onClick={() => onSelect({ kind: "group", id: group.id, name: group.name })}
      aria-current={isSelected ? "true" : undefined}
      className={cn(
        "group flex w-full items-center gap-2 py-1 pr-3 text-left text-compact transition-colors duration-100",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset",
        isSelected
          ? "bg-primary/10 text-primary font-medium"
          : "text-foreground hover:bg-accent hover:text-foreground",
      )}
    >
      <Users
        className={cn(
          "h-3.5 w-3.5 shrink-0 transition-colors",
          isSelected ? "text-primary" : "text-muted-foreground group-hover:text-foreground",
        )}
        aria-hidden="true"
      />
      <span className="flex-1 truncate">{group.name}</span>
    </button>
  );
}

// ─── Kind section header (Assets / Roles / Groups mini-label) ─────────────────

interface SectionHeaderProps {
  label: string;
  depth: number;
}

function SectionHeader({ label, depth }: SectionHeaderProps) {
  return (
    <div
      style={{ paddingLeft: `${depth * 16 + 8}px` }}
      className="pb-0.5 pt-1.5 pr-3 text-eyebrow font-semibold uppercase tracking-widest text-muted-foreground select-none"
      aria-hidden="true"
    >
      {label}
    </div>
  );
}

// ─── "Show all N" affordance row ─────────────────────────────────────────────

interface ShowAllRowProps {
  label: string;
  depth: number;
  onExpand: () => void;
}

function ShowAllRow({ label, depth, onExpand }: ShowAllRowProps) {
  return (
    <button
      style={leafIndent(depth)}
      onClick={onExpand}
      className="flex w-full items-center gap-1.5 py-1 pr-3 text-left text-micro text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
      aria-label={`Show all ${label}`}
    >
      <span>Show all {label}</span>
    </button>
  );
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function TreeSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-1 px-3 py-2">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-5 w-full rounded" />
      ))}
    </div>
  );
}

// ─── FolderNode (recursive, expandable) ──────────────────────────────────────

// Track which kind is "expanded to show-all" per folder
type ExpandedKinds = Set<"assets" | "roles" | "groups" | "folders">;

interface FolderNodeProps {
  folder: FolderNode;
  depth: number;
  selected: SelectedNode | null;
  onSelect: (node: SelectedNode) => void;
  filter: Set<NodeKind>;
}

function FolderNode_({ folder, depth, selected, onSelect, filter }: FolderNodeProps) {
  const [expanded, setExpanded] = useState(false);
  const [expandedKinds, setExpandedKinds] = useState<ExpandedKinds>(new Set());

  // Fetch children only when expanded for the first time
  const { data, isLoading, isError } = useQuery(
    listFolderContents,
    { parent: folder.id },
    { enabled: expanded },
  );

  const isSelf = selected?.kind === "folder" && selected.id === folder.id;

  const handleFolderClick = useCallback(() => {
    if (!expanded) setExpanded(true);
    else setExpanded((v) => !v);
    onSelect({ kind: "folder", id: folder.id, name: folder.name, path: folder.path });
  }, [expanded, folder, onSelect]);

  const contents = data ? folderContentsToNodes(data) : null;

  const showKind = (kind: NodeKind) => filter.has(kind);

  const expandKind = (kind: "assets" | "roles" | "groups" | "folders") => {
    setExpandedKinds((prev) => {
      const next = new Set(prev);
      next.add(kind);
      return next;
    });
  };

  return (
    <li aria-current={isSelf ? "true" : undefined}>
      {/* Folder toggle row */}
      <button
        style={{ paddingLeft: `${depth * 16}px` }}
        onClick={handleFolderClick}
        aria-expanded={expanded}
        className={cn(
          "group flex w-full items-center gap-1.5 py-1 pr-3 text-left text-compact font-medium transition-colors duration-100",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset",
          isSelf
            ? "bg-primary/10 text-primary"
            : "text-foreground hover:bg-accent hover:text-foreground",
        )}
        aria-label={`${expanded ? "Collapse" : "Expand"} folder ${folder.name}`}
      >
        <ChevronRight
          className={cn(
            "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform duration-150",
            expanded && "rotate-90",
          )}
          aria-hidden="true"
        />
        {expanded ? (
          <FolderOpen className="h-3.5 w-3.5 shrink-0 text-primary/70" aria-hidden="true" />
        ) : (
          <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground group-hover:text-foreground" aria-hidden="true" />
        )}
        <span className="flex-1 truncate">{folder.name}</span>
      </button>

      {/* Children */}
      {expanded && (
        <ul className="relative">
          {/* Left indent guide */}
          <span
            className="absolute top-0 bottom-0 border-l border-border"
            style={{ left: `${depth * 16 + 11}px` }}
            aria-hidden="true"
          />

          {isLoading && <TreeSkeleton rows={3} />}

          {isError && (
            <li className="flex items-center gap-1.5 py-1 pl-8 pr-3 text-micro text-destructive">
              <AlertCircle className="h-3 w-3 shrink-0" aria-hidden="true" />
              <span>Failed to load</span>
            </li>
          )}

          {contents && (
            <>
              {/* Sub-folders first */}
              {showKind("folder") && (
                <>
                  {expandedKinds.has("folders") ? (
                    <ShowAllFolders
                      folderId={folder.id}
                      onSelect={onSelect}
                      selected={selected}
                      filter={filter}
                    />
                  ) : (
                    <>
                      {contents.folders.map((child) => (
                        <FolderNode_
                          key={child.id}
                          folder={child}
                          depth={depth + 1}
                          selected={selected}
                          onSelect={onSelect}
                          filter={filter}
                        />
                      ))}
                      {contents.hasMore.folders && (
                        <ShowAllRow label="folders" depth={depth + 1} onExpand={() => expandKind("folders")} />
                      )}
                    </>
                  )}
                </>
              )}

              {/* Assets */}
              {showKind("asset") && contents.assets.length > 0 && (
                <>
                  <SectionHeader label="Assets" depth={depth + 1} />
                  {expandedKinds.has("assets") ? (
                    <ShowAllAssets folderId={folder.id} onSelect={onSelect} selected={selected} />
                  ) : (
                    <>
                      {contents.assets.map((a) => (
                        <AssetLeaf
                          key={a.id}
                          asset={a}
                          depth={depth + 1}
                          selected={selected}
                          onSelect={onSelect}
                        />
                      ))}
                      {contents.hasMore.assets && (
                        <ShowAllRow label="assets" depth={depth + 1} onExpand={() => expandKind("assets")} />
                      )}
                    </>
                  )}
                </>
              )}

              {/* Roles */}
              {showKind("role") && contents.roles.length > 0 && (
                <>
                  <SectionHeader label="Roles" depth={depth + 1} />
                  {expandedKinds.has("roles") ? (
                    <ShowAllRoles folderId={folder.id} onSelect={onSelect} selected={selected} />
                  ) : (
                    <>
                      {contents.roles.map((r) => (
                        <RoleLeaf
                          key={r.id}
                          role={r}
                          depth={depth + 1}
                          selected={selected}
                          onSelect={onSelect}
                        />
                      ))}
                      {contents.hasMore.roles && (
                        <ShowAllRow label="roles" depth={depth + 1} onExpand={() => expandKind("roles")} />
                      )}
                    </>
                  )}
                </>
              )}

              {/* Groups */}
              {showKind("group") && contents.groups.length > 0 && (
                <>
                  <SectionHeader label="Groups" depth={depth + 1} />
                  {expandedKinds.has("groups") ? (
                    <ShowAllGroups folderId={folder.id} onSelect={onSelect} selected={selected} />
                  ) : (
                    <>
                      {contents.groups.map((g) => (
                        <GroupLeaf
                          key={g.id}
                          group={g}
                          depth={depth + 1}
                          selected={selected}
                          onSelect={onSelect}
                        />
                      ))}
                      {contents.hasMore.groups && (
                        <ShowAllRow label="groups" depth={depth + 1} onExpand={() => expandKind("groups")} />
                      )}
                    </>
                  )}
                </>
              )}

              {/* Empty folder */}
              {contents.folders.length === 0 &&
                contents.assets.length === 0 &&
                contents.roles.length === 0 &&
                contents.groups.length === 0 && (
                  <li className="py-1.5 pl-8 pr-3 text-micro text-muted-foreground italic select-none">
                    Empty folder
                  </li>
                )}
            </>
          )}
        </ul>
      )}
    </li>
  );
}

// ─── Root tree ────────────────────────────────────────────────────────────────

interface TreeProps {
  selected: SelectedNode | null;
  onSelect: (node: SelectedNode) => void;
}

export function Tree({ selected, onSelect }: TreeProps) {
  const [filter, setFilter] = useState<Set<NodeKind>>(
    new Set(["folder", "asset", "role", "group"] as NodeKind[]),
  );
  // Track which root-level kinds have been expanded to their paginated show-all view.
  const [expandedKinds, setExpandedKinds] = useState<ExpandedKinds>(new Set());

  const { data, isLoading, isError, refetch } = useQuery(
    listFolderContents,
    { parent: "" },
  );

  const contents = data ? folderContentsToNodes(data) : null;

  const expandKind = (kind: "assets" | "roles" | "groups" | "folders") => {
    setExpandedKinds((prev) => {
      const next = new Set(prev);
      next.add(kind);
      return next;
    });
  };

  return (
    <div className="flex h-full flex-col">
      {/* Kind filter chips */}
      <KindFilter active={filter} onChange={setFilter} />

      {/* Tree body */}
      <ScrollArea className="flex-1 min-h-0">
        <nav aria-label="Catalog tree" className="py-1">
          {isLoading && <TreeSkeleton rows={6} />}

          {isError && (
            <ErrorState
              icon={AlertCircle}
              size="sm"
              message="Failed to load catalog"
              onRetry={() => refetch()}
            />
          )}

          {contents && (
            <ul aria-label="Catalog" className="flex flex-col">
              {/* Root-level folders */}
              {filter.has("folder") && (
                <>
                  {expandedKinds.has("folders") ? (
                    <ShowAllFolders
                      folderId=""
                      onSelect={onSelect}
                      selected={selected}
                      filter={filter}
                    />
                  ) : (
                    <>
                      {contents.folders.map((f) => (
                        <FolderNode_
                          key={f.id}
                          folder={f}
                          depth={1}
                          selected={selected}
                          onSelect={onSelect}
                          filter={filter}
                        />
                      ))}
                      {contents.hasMore.folders && (
                        <ShowAllRow label="folders" depth={1} onExpand={() => expandKind("folders")} />
                      )}
                    </>
                  )}
                </>
              )}

              {/* Root-level assets (rare but possible) */}
              {filter.has("asset") && contents.assets.length > 0 && (
                <>
                  <SectionHeader label="Assets" depth={1} />
                  {expandedKinds.has("assets") ? (
                    <ShowAllAssets folderId="" onSelect={onSelect} selected={selected} />
                  ) : (
                    <>
                      {contents.assets.map((a) => (
                        <AssetLeaf
                          key={a.id}
                          asset={a}
                          depth={1}
                          selected={selected}
                          onSelect={onSelect}
                        />
                      ))}
                      {contents.hasMore.assets && (
                        <ShowAllRow label="assets" depth={1} onExpand={() => expandKind("assets")} />
                      )}
                    </>
                  )}
                </>
              )}

              {/* Root-level roles */}
              {filter.has("role") && contents.roles.length > 0 && (
                <>
                  <SectionHeader label="Roles" depth={1} />
                  {expandedKinds.has("roles") ? (
                    <ShowAllRoles folderId="" onSelect={onSelect} selected={selected} />
                  ) : (
                    <>
                      {contents.roles.map((r) => (
                        <RoleLeaf
                          key={r.id}
                          role={r}
                          depth={1}
                          selected={selected}
                          onSelect={onSelect}
                        />
                      ))}
                      {contents.hasMore.roles && (
                        <ShowAllRow label="roles" depth={1} onExpand={() => expandKind("roles")} />
                      )}
                    </>
                  )}
                </>
              )}

              {/* Root-level groups */}
              {filter.has("group") && contents.groups.length > 0 && (
                <>
                  <SectionHeader label="Groups" depth={1} />
                  {expandedKinds.has("groups") ? (
                    <ShowAllGroups folderId="" onSelect={onSelect} selected={selected} />
                  ) : (
                    <>
                      {contents.groups.map((g) => (
                        <GroupLeaf
                          key={g.id}
                          group={g}
                          depth={1}
                          selected={selected}
                          onSelect={onSelect}
                        />
                      ))}
                      {contents.hasMore.groups && (
                        <ShowAllRow label="groups" depth={1} onExpand={() => expandKind("groups")} />
                      )}
                    </>
                  )}
                </>
              )}

              {/* Empty root */}
              {contents.folders.length === 0 &&
                contents.assets.length === 0 &&
                contents.roles.length === 0 &&
                contents.groups.length === 0 && (
                  <li className="py-12 text-center text-compact text-muted-foreground">
                    No items visible
                  </li>
                )}
            </ul>
          )}
        </nav>
      </ScrollArea>
    </div>
  );
}
