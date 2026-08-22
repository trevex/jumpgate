import { describe, it, expect } from "vitest";
import { folderContentsToNodes } from "./tree-model";
import type { ListFolderContentsResponse } from "@/gen/jumpgate/catalog/v1/catalog_pb";

// Minimal stub that satisfies the ListFolderContentsResponse shape.
// We only set the fields folderContentsToNodes actually reads.
function makeResponse(
  overrides: Partial<ListFolderContentsResponse>,
): ListFolderContentsResponse {
  return {
    folders: [],
    foldersHasMore: false,
    assets: [],
    assetsHasMore: false,
    roles: [],
    rolesHasMore: false,
    groups: [],
    groupsHasMore: false,
    ...overrides,
  } as unknown as ListFolderContentsResponse;
}

describe("folderContentsToNodes", () => {
  it("maps folders to FolderNode array", () => {
    const res = makeResponse({
      folders: [
        { id: "f1", name: "prod", path: "prod", parentId: "" } as never,
        { id: "f2", name: "staging", path: "staging", parentId: "" } as never,
      ],
      foldersHasMore: false,
    });
    const { folders, hasMore } = folderContentsToNodes(res);
    expect(folders).toHaveLength(2);
    expect(folders[0]).toEqual({ id: "f1", name: "prod", path: "prod", parentId: "" });
    expect(folders[1]).toEqual({ id: "f2", name: "staging", path: "staging", parentId: "" });
    expect(hasMore.folders).toBe(false);
  });

  it("maps assets to AssetNode array", () => {
    const res = makeResponse({
      assets: [
        { id: "a1", name: "pg-primary", path: "pg-primary.db.prod", kind: "ssh", folderId: "f1", config: { case: undefined } } as never,
      ],
      assetsHasMore: true,
    });
    const { assets, hasMore } = folderContentsToNodes(res);
    expect(assets).toHaveLength(1);
    expect(assets[0]).toEqual({ id: "a1", name: "pg-primary", path: "pg-primary.db.prod", kind: "ssh" });
    expect(hasMore.assets).toBe(true);
  });

  it("maps roles to RoleNode array", () => {
    const res = makeResponse({
      roles: [
        { id: "r1", name: "db-admin", capabilities: [], folderId: "", folderPath: "db.prod" } as never,
      ],
      rolesHasMore: true,
    });
    const { roles, hasMore } = folderContentsToNodes(res);
    expect(roles).toHaveLength(1);
    expect(roles[0]).toEqual({ id: "r1", name: "db-admin", folderPath: "db.prod" });
    expect(hasMore.roles).toBe(true);
  });

  it("maps groups to GroupNode array", () => {
    const res = makeResponse({
      groups: [
        { id: "g1", name: "sre-team", folderId: "", folderPath: "infra" } as never,
      ],
      groupsHasMore: false,
    });
    const { groups, hasMore } = folderContentsToNodes(res);
    expect(groups).toHaveLength(1);
    expect(groups[0]).toEqual({ id: "g1", name: "sre-team", folderPath: "infra" });
    expect(hasMore.groups).toBe(false);
  });

  it("all hasMore flags true when all set", () => {
    const res = makeResponse({
      foldersHasMore: true,
      assetsHasMore: true,
      rolesHasMore: true,
      groupsHasMore: true,
    });
    const { hasMore } = folderContentsToNodes(res);
    expect(hasMore.folders).toBe(true);
    expect(hasMore.assets).toBe(true);
    expect(hasMore.roles).toBe(true);
    expect(hasMore.groups).toBe(true);
  });

  it("returns empty arrays when response is empty", () => {
    const res = makeResponse({});
    const result = folderContentsToNodes(res);
    expect(result.folders).toHaveLength(0);
    expect(result.assets).toHaveLength(0);
    expect(result.roles).toHaveLength(0);
    expect(result.groups).toHaveLength(0);
    expect(result.hasMore).toEqual({ folders: false, assets: false, roles: false, groups: false });
  });
});
