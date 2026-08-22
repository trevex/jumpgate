import { describe, it, expect } from "vitest";
import {
  groupHitsByKind,
  hasAnyHits,
  hitToSelectedNode,
} from "./search-palette-model";
import type { SearchHit } from "@/gen/jumpgate/catalog/v1/catalog_pb";

function hit(kind: string, id: string, name: string, path = ""): SearchHit {
  return { kind, id, name, path } as unknown as SearchHit;
}

describe("groupHitsByKind", () => {
  it("partitions hits into the four catalog kinds", () => {
    const g = groupHitsByKind([
      hit("asset", "a1", "pg-primary", "pg-primary.db.prod"),
      hit("folder", "f1", "prod", "prod"),
      hit("role", "r1", "db-admin", "db-admin.db.prod"),
      hit("group", "g1", "sre-team", "sre-team@infra"),
      hit("asset", "a2", "pg-replica", "pg-replica.db.prod"),
    ]);
    expect(g.folders.map((h) => h.id)).toEqual(["f1"]);
    expect(g.assets.map((h) => h.id)).toEqual(["a1", "a2"]);
    expect(g.roles.map((h) => h.id)).toEqual(["r1"]);
    expect(g.groups.map((h) => h.id)).toEqual(["g1"]);
  });

  it("preserves server ordering within a group", () => {
    const g = groupHitsByKind([
      hit("asset", "a2", "z"),
      hit("asset", "a1", "a"),
    ]);
    expect(g.assets.map((h) => h.id)).toEqual(["a2", "a1"]);
  });

  it("drops unknown kinds", () => {
    const g = groupHitsByKind([
      hit("user", "u1", "alice"),
      hit("folder", "f1", "prod"),
    ]);
    expect(g.folders).toHaveLength(1);
    expect(g.assets).toHaveLength(0);
    expect(g.roles).toHaveLength(0);
    expect(g.groups).toHaveLength(0);
  });

  it("returns empty groups for no hits", () => {
    const g = groupHitsByKind([]);
    expect(hasAnyHits(g)).toBe(false);
    expect(g).toEqual({ folders: [], assets: [], roles: [], groups: [] });
  });
});

describe("hasAnyHits", () => {
  it("is true when any group is non-empty", () => {
    expect(hasAnyHits(groupHitsByKind([hit("role", "r1", "x")]))).toBe(true);
  });
  it("is false when all groups are empty", () => {
    expect(hasAnyHits(groupHitsByKind([hit("user", "u1", "x")]))).toBe(false);
  });
});

describe("hitToSelectedNode", () => {
  it("maps a known-kind hit to a SelectedNode with forwarded path", () => {
    const node = hitToSelectedNode(
      hit("asset", "a1", "pg-primary", "pg-primary.db.prod"),
    );
    expect(node).toEqual({
      kind: "asset",
      id: "a1",
      name: "pg-primary",
      path: "pg-primary.db.prod",
    });
  });

  it("drops an empty path to undefined", () => {
    const node = hitToSelectedNode(hit("role", "r1", "db-admin", ""));
    expect(node).toEqual({ kind: "role", id: "r1", name: "db-admin", path: undefined });
  });

  it("returns null for an unknown kind", () => {
    expect(hitToSelectedNode(hit("user", "u1", "alice"))).toBeNull();
  });
});
