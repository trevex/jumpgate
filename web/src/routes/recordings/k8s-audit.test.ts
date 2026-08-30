import { describe, it, expect } from "vitest";
import { parseK8sAudit } from "./k8s-audit";

describe("parseK8sAudit", () => {
  it("parses header + events and skips malformed/blank lines", () => {
    const ndjson = [
      `{"v":1,"kind":"k8s","session_id":"s1","started_at_unix_ms":1000}`,
      `{"ts":"2026-08-30T20:36:06.9Z","verb":"list","path":"/api/v1/namespaces/kube-system/pods","resource":"pods","namespace":"kube-system","name":"","user":"u1","groups":["developers"],"code":200}`,
      `not json`,
      ``,
      `{"ts":"2026-08-30T20:36:07.1Z","verb":"delete","path":"/api/v1/namespaces/kube-system/secrets/foo","resource":"secrets","namespace":"kube-system","name":"foo","user":"u1","groups":["developers"],"code":403}`,
    ].join("\n");
    const audit = parseK8sAudit(ndjson);
    expect(audit.header?.kind).toBe("k8s");
    expect(audit.header?.sessionId).toBe("s1");
    expect(audit.events).toHaveLength(2);
    expect(audit.events[0]).toMatchObject({ verb: "list", resource: "pods", code: 200 });
    expect(audit.events[1]).toMatchObject({ verb: "delete", name: "foo", code: 403 });
  });

  it("empty input yields no header, no events", () => {
    expect(parseK8sAudit("")).toEqual({ header: null, events: [] });
  });
});
