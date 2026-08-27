/**
 * selection.ts — URL-param codec for the Catalog page's selected node.
 *
 * Selection is carried in the
 * `?sel=<kind>:<id>:<name>:<path>:<assetKind>:<folderId>:<folderPath>` search
 * param so it survives reload and can be produced by other surfaces (the ⌘K
 * command palette) to deep-link into a specific node's detail pane. The trailing
 * folder fields are role-only (its home folder) and empty for other kinds.
 */

import type { NodeKind, SelectedNode } from "./tree";

export function encodeSelection(node: SelectedNode): string {
  // kind:id[:name[:path[:assetKind[:folderId[:folderPath]]]]] — name/path/folderPath
  // are URL-encoded (ids are colon-free UUIDs).
  const parts = [
    node.kind,
    node.id,
    encodeURIComponent(node.name),
    encodeURIComponent(node.path ?? ""),
    encodeURIComponent(node.assetKind ?? ""),
    node.folderId ?? "",
    encodeURIComponent(node.folderPath ?? ""),
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
    folderId: (parts[5] ?? "") || undefined,
    folderPath: decodeURIComponent(parts[6] ?? "") || undefined,
  };
}
