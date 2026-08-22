import { describe, it, expect } from "vitest";
import {
  userRowActions,
  canCreateUser,
  isValidEmail,
  isValidDisplayName,
  isValidPassword,
  isValidNewUser,
} from "./user-actions";

const ADMIN = ["**"];
const DEACTIVATE_ONLY = ["identity:user:deactivate"];
const DELETE_ONLY = ["identity:user:delete"];
const NONE: string[] = [];

describe("userRowActions", () => {
  it("admin gets Deactivate + Delete on an active OTHER user", () => {
    const a = userRowActions(ADMIN, { active: true }, false);
    expect(a).toEqual({ canDeactivate: true, canReactivate: false, canDelete: true });
  });

  it("self-guard: never Deactivate or Delete your own active row", () => {
    const a = userRowActions(ADMIN, { active: true }, true);
    expect(a.canDeactivate).toBe(false);
    expect(a.canDelete).toBe(false);
    expect(a.canReactivate).toBe(false);
  });

  it("Reactivate shows for a deactivated user with the deactivate cap (same cap)", () => {
    const a = userRowActions(DEACTIVATE_ONLY, { active: false }, false);
    expect(a.canReactivate).toBe(true);
    expect(a.canDeactivate).toBe(false); // not active
    expect(a.canDelete).toBe(false); // no delete cap
  });

  it("Reactivate is allowed even for your own deactivated row (no self-lockout risk)", () => {
    const a = userRowActions(DEACTIVATE_ONLY, { active: false }, true);
    expect(a.canReactivate).toBe(true);
  });

  it("delete cap alone: Delete only, and never on self", () => {
    expect(userRowActions(DELETE_ONLY, { active: true }, false)).toEqual({
      canDeactivate: false,
      canReactivate: false,
      canDelete: true,
    });
    expect(userRowActions(DELETE_ONLY, { active: true }, true).canDelete).toBe(false);
  });

  it("no caps: no actions", () => {
    expect(userRowActions(NONE, { active: true }, false)).toEqual({
      canDeactivate: false,
      canReactivate: false,
      canDelete: false,
    });
  });

  it("deactivate cap does not confer delete (glob does not over-match)", () => {
    const a = userRowActions(DEACTIVATE_ONLY, { active: true }, false);
    expect(a.canDeactivate).toBe(true);
    expect(a.canDelete).toBe(false);
  });
});

describe("canCreateUser", () => {
  it("gated on identity:user:create", () => {
    expect(canCreateUser(["identity:user:create"])).toBe(true);
    expect(canCreateUser(ADMIN)).toBe(true);
    expect(canCreateUser(DEACTIVATE_ONLY)).toBe(false);
    expect(canCreateUser(NONE)).toBe(false);
  });
});

describe("create-form validation (mirrors protovalidate)", () => {
  it("email", () => {
    expect(isValidEmail("a@b.co")).toBe(true);
    expect(isValidEmail("  a@b.co  ")).toBe(true);
    expect(isValidEmail("nope")).toBe(false);
    expect(isValidEmail("a@b")).toBe(false);
    expect(isValidEmail("")).toBe(false);
  });

  it("display name 1–200", () => {
    expect(isValidDisplayName("A")).toBe(true);
    expect(isValidDisplayName("a".repeat(200))).toBe(true);
    expect(isValidDisplayName("")).toBe(false);
    expect(isValidDisplayName("   ")).toBe(false);
    expect(isValidDisplayName("a".repeat(201))).toBe(false);
  });

  it("password ≥ 8", () => {
    expect(isValidPassword("12345678")).toBe(true);
    expect(isValidPassword("1234567")).toBe(false);
  });

  it("combined", () => {
    expect(
      isValidNewUser({ email: "a@b.co", displayName: "Ada", password: "hunter22" }),
    ).toBe(true);
    expect(
      isValidNewUser({ email: "bad", displayName: "Ada", password: "hunter22" }),
    ).toBe(false);
    expect(
      isValidNewUser({ email: "a@b.co", displayName: "", password: "hunter22" }),
    ).toBe(false);
    expect(
      isValidNewUser({ email: "a@b.co", displayName: "Ada", password: "short" }),
    ).toBe(false);
  });
});
