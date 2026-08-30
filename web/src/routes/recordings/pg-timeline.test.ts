import { describe, it, expect } from "vitest";
import { parsePgTimeline } from "./pg-timeline";

describe("parsePgTimeline", () => {
  it("parses header + events and skips malformed/blank lines", () => {
    const ndjson = [
      `{"v":1,"kind":"pg","session_id":"s1","role":"app","database":"appdb","started_at_unix_ms":1000}`,
      `{"t":12,"type":"query","sql":"SELECT 1"}`,
      `not json`,
      `{"t":18,"type":"parse","name":"s1","sql":"SELECT $1","param_oids":[25]}`,
      `{"t":19,"type":"bind","params":1}`,
      `{"t":25,"type":"command_complete","tag":"SELECT 1"}`,
      `{"t":40,"type":"error","code":"42P01","severity":"ERROR","message":"boom"}`,
      ``,
    ].join("\n");
    const tl = parsePgTimeline(ndjson);
    expect(tl.header?.role).toBe("app");
    expect(tl.header?.database).toBe("appdb");
    expect(tl.events).toHaveLength(5);
    expect(tl.events[0]).toMatchObject({ type: "query", sql: "SELECT 1" });
    expect(tl.events[4]).toMatchObject({ type: "error", code: "42P01" });
  });

  it("empty input yields no header, no events", () => {
    expect(parsePgTimeline("")).toEqual({ header: null, events: [] });
  });
});
