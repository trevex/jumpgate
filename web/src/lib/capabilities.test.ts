import { describe, expect, it } from "vitest";
import { capsCover } from "./capabilities";

describe("capsCover", () => {
  it("** covers everything", () => {
    expect(capsCover(["**"], "recording:read")).toBe(true);
  });

  it("exact match covers itself", () => {
    expect(capsCover(["recording:read"], "recording:read")).toBe(true);
  });

  it("single-level glob covers a matching action", () => {
    expect(capsCover(["catalog:asset:*"], "catalog:asset:read")).toBe(true);
  });

  it("unrelated cap does not cover", () => {
    expect(capsCover(["access:role:read"], "recording:read")).toBe(false);
  });

  it("recursive glob covers nested scopes", () => {
    expect(capsCover(["catalog:**"], "catalog:asset:read")).toBe(true);
  });

  it("single-level glob does not over-match across scopes", () => {
    expect(capsCover(["catalog:*"], "recording:read")).toBe(false);
  });

  it("empty held caps covers nothing", () => {
    expect(capsCover([], "recording:read")).toBe(false);
  });
});
