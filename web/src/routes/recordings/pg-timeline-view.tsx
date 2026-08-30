import { useEffect, useState } from "react";
import { parsePgTimeline, type PgEvent, type PgTimeline } from "./pg-timeline";

// PgTimelineViewer plays back a pgwire-timeline-v1 recording as a single-column
// statement timeline. It fetches the same /cast streaming route the asciinema
// player uses (format-agnostic bytes, cookie auth) and parses the NDJSON.
export function PgTimelineViewer({ sessionId }: { sessionId: string }) {
  const [tl, setTl] = useState<PgTimeline | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setTl(null);
    setError(null);
    fetch(`/api/recordings/${sessionId}/cast`, { credentials: "include" })
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.text();
      })
      .then((text) => {
        if (!cancelled) setTl(parsePgTimeline(text));
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "load failed");
      });
    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  if (error) {
    return <div className="p-4 text-body text-red-400 font-mono">Statement log unavailable ({error}).</div>;
  }
  if (!tl) {
    return <div className="p-4 text-body text-white/40 font-mono">Loading statement log…</div>;
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="px-4 py-2 border-b border-white/10 text-eyebrow text-white/50 font-mono shrink-0">
        {tl.header?.role}@{tl.header?.database} · {tl.events.length} events · statements &amp; outcomes only
        (result data is never recorded)
      </div>
      <div className="flex-1 overflow-auto font-mono text-compact">
        {tl.events.map((ev, i) => (
          <TimelineRow key={i} ev={ev} />
        ))}
      </div>
    </div>
  );
}

function TimelineRow({ ev }: { ev: PgEvent }) {
  const isErr = ev.type === "error";
  return (
    <div className={`flex gap-3 px-4 py-1 border-b border-white/5 ${isErr ? "bg-red-500/10" : ""}`}>
      <span className="text-white/30 tabular-nums shrink-0 w-16 text-right">{ev.t}ms</span>
      <span className={`min-w-0 flex-1 whitespace-pre-wrap break-words ${isErr ? "text-red-300" : "text-white/80"}`}>
        {renderEvent(ev)}
      </span>
    </div>
  );
}

function renderEvent(ev: PgEvent): string {
  const s = (k: string) => (ev[k] == null ? "" : String(ev[k]));
  switch (ev.type) {
    case "query":
      return `▶ query    ${s("sql")}`;
    case "parse":
      return `▶ parse ${s("name")}  ${s("sql")}`;
    case "bind":
      return `▶ bind     (${ev.params ?? 0} param(s), redacted)`;
    case "execute":
      return `▶ execute  ${ev.portal ? `portal=${s("portal")}` : ""}`;
    case "function_call":
      return `▶ function_call oid=${s("function")} (${ev.args ?? 0} arg(s), redacted)`;
    case "command_complete":
      return `✓ ${s("tag")}`;
    case "error":
      return `✗ ${s("code")} ${s("severity")}  ${s("message")}`;
    case "record_gap":
      return `⚠ recording gap (structured capture degraded)`;
    default:
      return `${ev.type}  ${JSON.stringify(ev)}`;
  }
}
