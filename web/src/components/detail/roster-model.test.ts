import { describe, it, expect } from "vitest";
import type { RosterNode } from "@/gen/jumpgate/access/v1/access_pb";
import { rosterNodeLabel } from "./roster-model";

function node(p: Partial<RosterNode>): RosterNode {
  return {
    subjectKind: "user", subjectId: "u1", displayName: "", folderPath: "",
    groupMemberCount: 0, active: true, source: "explicit", viaRoleId: "", viaRoleName: "",
    ...p,
  } as unknown as RosterNode;
}

describe("rosterNodeLabel", () => {
  it("labels an explicit user", () => {
    const l = rosterNodeLabel(node({ displayName: "Alice" }));
    expect(l).toMatchObject({ name: "Alice", kind: "user", detail: "explicit", inactive: false });
  });
  it("labels a group via role with member count", () => {
    const l = rosterNodeLabel(node({
      subjectKind: "group", displayName: "eng-oncall", groupMemberCount: 7,
      source: "via_role", viaRoleName: "oncall",
    }));
    expect(l.detail).toBe("7 members · via oncall");
  });
  it("flags an inactive user", () => {
    expect(rosterNodeLabel(node({ active: false })).inactive).toBe(true);
  });
  it("falls back to a short id when unnamed", () => {
    expect(rosterNodeLabel(node({ subjectId: "abcdef123456" })).name).toBe("abcdef12");
  });
});
