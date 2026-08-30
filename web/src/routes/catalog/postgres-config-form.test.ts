import { describe, it, expect } from "vitest";
import { buildPostgresConfigInput, emptyPgDraft, type PgConfigDraft } from "./postgres-config-form";

describe("buildPostgresConfigInput", () => {
  it("emits mtls (no secret) and password (newValue) arms", () => {
    const draft: PgConfigDraft = {
      targetAddress: "db:5432", defaultDatabase: "appdb", targetServerCa: "",
      logins: [
        { role: "mtlsuser", kind: "mtls", secret: "" },
        { role: "app", kind: "password", secret: "pw" },
      ],
    };
    const { config, error } = buildPostgresConfigInput(draft, "create");
    expect(error).toBeUndefined();
    expect(config.targetAddress).toBe("db:5432");
    expect(config.defaultDatabase).toBe("appdb");
    expect(config.logins).toHaveLength(2);
    expect(config.logins?.[0]).toMatchObject({ role: "mtlsuser", auth: { case: "mtls" } });
    const pw = config.logins?.[1] as any;
    expect(pw.role).toBe("app");
    expect(pw.auth.case).toBe("password");
    expect(pw.auth.value.source.case).toBe("newValue");
  });
  it("errors on a password login with no secret (create)", () => {
    const draft: PgConfigDraft = {
      targetAddress: "db:5432", defaultDatabase: "appdb", targetServerCa: "",
      logins: [{ role: "app", kind: "password", secret: "" }],
    };
    expect(buildPostgresConfigInput(draft, "create").error).toMatch(/password is required/);
  });
  it("keeps an existing secret on edit when the field is blank", () => {
    const draft: PgConfigDraft = {
      targetAddress: "db:5432", defaultDatabase: "appdb", targetServerCa: "",
      logins: [{ role: "app", kind: "password", secret: "", existingSecretId: "sid-1" }],
    };
    const { config } = buildPostgresConfigInput(draft, "edit");
    const pw = config.logins?.[0] as any;
    expect(pw.auth.value.source).toMatchObject({ case: "existingSecretId", value: "sid-1" });
  });
  it("errors on an empty role", () => {
    expect(buildPostgresConfigInput(emptyPgDraft(), "create").error).toMatch(/role/);
  });
});
