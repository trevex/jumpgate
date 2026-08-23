import { describe, expect, it } from "vitest";
import { glossCapability } from "./capability-glossary";

describe("glossCapability", () => {
  it("glosses a concrete ssh login", () => {
    expect(glossCapability("ssh:login:root")).toBe("Connect over SSH as root");
  });

  it("glosses the any-login ssh globs", () => {
    expect(glossCapability("ssh:login:*")).toBe("Connect over SSH (any login)");
    expect(glossCapability("ssh:**")).toBe("Connect over SSH (any login)");
  });

  it("glosses catalog asset read", () => {
    expect(glossCapability("catalog:asset:read")).toBe("View assets");
  });

  it("glosses catalog asset write verbs", () => {
    expect(glossCapability("catalog:asset:create")).toBe("Create assets");
    expect(glossCapability("catalog:asset:update")).toBe("Edit assets");
    expect(glossCapability("catalog:asset:delete")).toBe("Delete assets");
  });

  it("glosses identity/access management caps", () => {
    expect(glossCapability("identity:user:read")).toBe("View users");
    expect(glossCapability("identity:group:*")).toBe("Manage groups");
    expect(glossCapability("access:role:read")).toBe("View roles");
    expect(glossCapability("access:policy:*")).toBe("Manage policies");
  });

  it("glosses recordings", () => {
    expect(glossCapability("recording:read")).toBe("View session recordings");
    expect(glossCapability("recording:*")).toBe("Manage session recordings");
  });

  it("glosses the root globs", () => {
    expect(glossCapability("**")).toBe("Full administrative access");
    expect(glossCapability("*")).toBe("All actions in this scope");
  });

  it("falls back to a readable title-cased string for unknown caps", () => {
    expect(glossCapability("widget:frobnicate:hard")).toBe(
      "Widget Frobnicate Hard",
    );
  });
});
