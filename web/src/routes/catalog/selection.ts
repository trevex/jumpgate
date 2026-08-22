/**
 * selection.ts — URL-param codec for the Catalog page's selected node.
 *
 * Selection is carried in the `?sel=<kind>:<id>:<name>:<path>:<assetKind>` search
 * param so it survives reload and can be produced by other surfaces (the ⌘K
 * command palette) to deep-link into a specific node's detail pane.
 */

import type { NodeKind, SelectedNode } from "./tree";

export function encodeSelection(node: SelectedNode): string {
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

export function decodeSelection(raw: string): SelectedNode | null {
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
