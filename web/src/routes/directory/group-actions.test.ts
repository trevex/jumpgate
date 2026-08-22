import { describe, it, expect } from "vitest";
import {
  canCreateGroup,
  canDeleteGroup,
  isValidGroupName,
} from "./group-actions";

const ADMIN = ["**"];
const CREATE_ONLY = ["identity:group:create"];
const DELETE_ONLY = ["identity:group:delete"];
const NONE: string[] = [];

describe("canCreateGroup", () => {
  it("gated on identity:group:create", () => {
    expect(canCreateGroup(CREATE_ONLY)).toBe(true);
    expect(canCreateGroup(ADMIN)).toBe(true);
    expect(canCreateGroup(DELETE_ONLY)).toBe(false);
    expect(canCreateGroup(NONE)).toBe(false);
  });
});

describe("canDeleteGroup", () => {
  it("gated on identity:group:delete", () => {
    expect(canDeleteGroup(DELETE_ONLY)).toBe(true);
    expect(canDeleteGroup(ADMIN)).toBe(true);
    expect(canDeleteGroup(CREATE_ONLY)).toBe(false);
    expect(canDeleteGroup(NONE)).toBe(false);
  });

  it("create cap does not confer delete (glob does not over-match)", () => {
    expect(canDeleteGroup(CREATE_ONLY)).toBe(false);
  });
});

describe("group-name validation (mirrors catalog charset ^[a-z0-9_-]+$)", () => {
  it("accepts lowercase, digits, dashes, underscores", () => {
    expect(isValidGroupName("platform-oncall")).toBe(true);
    expect(isValidGroupName("db_admins")).toBe(true);
    expect(isValidGroupName("team1")).toBe(true);
    expect(isValidGroupName("  trimmed  ")).toBe(true);
  });

  it("rejects empty, uppercase, spaces, dots, and other punctuation", () => {
    expect(isValidGroupName("")).toBe(false);
    expect(isValidGroupName("   ")).toBe(false);
    expect(isValidGroupName("Platform")).toBe(false);
    expect(isValidGroupName("has space")).toBe(false);
    expect(isValidGroupName("dotted.name")).toBe(false);
    expect(isValidGroupName("emoji😀")).toBe(false);
  });

  it("enforces the 1–200 length bound", () => {
    expect(isValidGroupName("a")).toBe(true);
    expect(isValidGroupName("a".repeat(200))).toBe(true);
    expect(isValidGroupName("a".repeat(201))).toBe(false);
  });
});
