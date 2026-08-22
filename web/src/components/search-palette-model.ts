/**
 * search-palette-model.ts — pure mapping helpers for the ⌘K command palette.
 *
 * Kept separate from the React component so the grouping/selection mapping can
 * be unit-tested without a DOM.
 */

import type { SearchHit } from "@/gen/jumpgate/catalog/v1/catalog_pb";
import type { NodeKind, SelectedNode } from "@/routes/catalog/tree";

export interface GroupedHits {
  folders: SearchHit[];
  assets: SearchHit[];
  roles: SearchHit[];
  groups: SearchHit[];
}

/**
 * Partition catalog search hits into the four catalog kinds, preserving the
 * server's ordering within each group. Unknown/unexpected kinds are dropped.
 */
export function groupHitsByKind(hits: SearchHit[]): GroupedHits {
  const grouped: GroupedHits = { folders: [], assets: [], roles: [], groups: [] };
  for (const hit of hits) {
    switch (hit.kind) {
      case "folder":
        grouped.folders.push(hit);
        break;
      case "asset":
        grouped.assets.push(hit);
        break;
      case "role":
        grouped.roles.push(hit);
        break;
      case "group":
        grouped.groups.push(hit);
        break;
      // Unknown kinds are ignored — the palette only renders known groups.
    }
  }
  return grouped;
}

/** True when the hits contain at least one entry of a known kind. */
export function hasAnyHits(g: GroupedHits): boolean {
  return (
    g.folders.length > 0 ||
    g.assets.length > 0 ||
    g.roles.length > 0 ||
    g.groups.length > 0
  );
}

const KNOWN_KINDS: NodeKind[] = ["folder", "asset", "role", "group"];

/**
 * Map a search hit onto the catalog's SelectedNode shape. Returns null for a
 * hit whose kind is not a known catalog kind. `path` is forwarded (the detail
 * panes fetch by id; path is a display hint), asset kind is unknown from search.
 */
export function hitToSelectedNode(hit: SearchHit): SelectedNode | null {
  if (!KNOWN_KINDS.includes(hit.kind as NodeKind)) return null;
  return {
    kind: hit.kind as NodeKind,
    id: hit.id,
    name: hit.name,
    path: hit.path || undefined,
  };
}
