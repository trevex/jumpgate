import { describe, it, expect } from "vitest";
import { isValidCapability } from "./capability-input";

describe("isValidCapability (mirrors the server glob grammar)", () => {
  it("accepts well-formed scoped capabilities", () => {
    expect(isValidCapability("ssh:login:deploy")).toBe(true);
    expect(isValidCapability("catalog:asset:read")).toBe(true);
    expect(isValidCapability("access:role:*")).toBe(true);
    expect(isValidCapability("**")).toBe(true);
  });

  it("accepts glob forms allowed by the grammar", () => {
    expect(isValidCapability("*:connect")).toBe(true);
    expect(isValidCapability("recording:read")).toBe(true);
    expect(isValidCapability("ssh:login:**")).toBe(true);
    expect(isValidCapability("multi-part:action-name")).toBe(true);
  });

  it("trims surrounding whitespace before validating", () => {
    expect(isValidCapability("  ssh:login:deploy  ")).toBe(true);
  });

  it("rejects unscoped, empty-segment, non-final '**', uppercase, and junk", () => {
    expect(isValidCapability("admin")).toBe(false);
    expect(isValidCapability("k8s:")).toBe(false);
    expect(isValidCapability("SSH:login:deploy")).toBe(false);
    expect(isValidCapability("k8s:**:x")).toBe(false);
    expect(isValidCapability("")).toBe(false);
    expect(isValidCapability("   ")).toBe(false);
    expect(isValidCapability(":leading")).toBe(false);
    expect(isValidCapability("has space:x")).toBe(false);
  });
});
