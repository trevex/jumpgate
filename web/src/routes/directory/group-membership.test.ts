import { describe, it, expect } from "vitest";
import type { User, Group } from "@/gen/jumpgate/identity/v1/identity_pb";
import {
  canAddMember,
  canRemoveMember,
  partitionMembers,
  memberCount,
} from "./group-membership";

const ADMIN = ["**"];
const ADD_ONLY = ["identity:group:add-member"];
const REMOVE_ONLY = ["identity:group:remove-member"];
const NONE: string[] = [];

// Minimal fixtures — only the fields the helpers touch. Cast through unknown so
// we don't have to spell out every generated field.
function user(id: string): User {
  return { id } as unknown as User;
}
function group(id: string, name: string): Group {
  return { id, name } as unknown as Group;
}

describe("canAddMember", () => {
  it("gated on identity:group:add-member", () => {
    expect(canAddMember(ADD_ONLY)).toBe(true);
    expect(canAddMember(ADMIN)).toBe(true);
    expect(canAddMember(REMOVE_ONLY)).toBe(false);
    expect(canAddMember(NONE)).toBe(false);
  });
});

describe("canRemoveMember", () => {
  it("gated on identity:group:remove-member", () => {
    expect(canRemoveMember(REMOVE_ONLY)).toBe(true);
    expect(canRemoveMember(ADMIN)).toBe(true);
    expect(canRemoveMember(ADD_ONLY)).toBe(false);
    expect(canRemoveMember(NONE)).toBe(false);
  });

  it("add cap does not confer remove (glob does not over-match)", () => {
    expect(canRemoveMember(ADD_ONLY)).toBe(false);
  });
});

describe("partitionMembers", () => {
  it("splits users and groups from a full response", () => {
    const m = partitionMembers({
      users: [user("u1"), user("u2")],
      groups: [group("g1", "eng")],
    });
    expect(m.userMembers.map((u) => u.id)).toEqual(["u1", "u2"]);
    expect(m.groupMembers.map((g) => g.id)).toEqual(["g1"]);
  });

  it("tolerates undefined response and missing fields", () => {
    expect(partitionMembers(undefined)).toEqual({
      userMembers: [],
      groupMembers: [],
    });
    expect(partitionMembers({ users: [user("u1")] })).toEqual({
      userMembers: [user("u1")],
      groupMembers: [],
    });
    expect(partitionMembers({ groups: [group("g1", "eng")] })).toEqual({
      userMembers: [],
      groupMembers: [group("g1", "eng")],
    });
  });
});

describe("memberCount", () => {
  it("sums both kinds", () => {
    expect(
      memberCount({
        userMembers: [user("u1"), user("u2")],
        groupMembers: [group("g1", "eng")],
      }),
    ).toBe(3);
    expect(memberCount({ userMembers: [], groupMembers: [] })).toBe(0);
  });
});
