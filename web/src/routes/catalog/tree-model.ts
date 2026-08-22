/**
 * tree-model.ts — pure mapping helper for ListFolderContents responses.
 *
 * Converts a ListFolderContentsResponse (from CatalogService) into a clean,
 * framework-agnostic node shape that the tree view can consume without touching
 * protobuf message internals.
 */

import type { ListFolderContentsResponse } from "@/gen/jumpgate/catalog/v1/catalog_pb";

export interface FolderNode {
  id: string;
  name: string;
  path: string;
  parentId: string;
}

export interface AssetNode {
  id: string;
  name: string;
  path: string;
  kind: string;
}

export interface RoleNode {
  id: string;
  name: string;
  folderPath: string;
}

export interface GroupNode {
  id: string;
  name: string;
  folderPath: string;
}

export interface HasMore {
  folders: boolean;
  assets: boolean;
  roles: boolean;
  groups: boolean;
}

export interface FolderContents {
  folders: FolderNode[];
  assets: AssetNode[];
  roles: RoleNode[];
  groups: GroupNode[];
  hasMore: HasMore;
}

/**
 * foldersContentsToNodes maps a ListFolderContentsResponse to typed node arrays
 * plus hasMore flags per kind. Pure function — no side effects.
 */
export function folderContentsToNodes(
  res: ListFolderContentsResponse,
): FolderContents {
  return {
    folders: res.folders.map((f) => ({
      id: f.id,
      name: f.name,
      path: f.path,
      parentId: f.parentId,
    })),
    assets: res.assets.map((a) => ({
      id: a.id,
      name: a.name,
      path: a.path,
      kind: a.kind,
    })),
    roles: res.roles.map((r) => ({
      id: r.id,
      name: r.name,
      folderPath: r.folderPath,
    })),
    groups: res.groups.map((g) => ({
      id: g.id,
      name: g.name,
      folderPath: g.folderPath,
    })),
    hasMore: {
      folders: res.foldersHasMore,
      assets: res.assetsHasMore,
      roles: res.rolesHasMore,
      groups: res.groupsHasMore,
    },
  };
}
