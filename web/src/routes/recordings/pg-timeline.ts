export interface PgHeader {
  v: number;
  kind: string;
  sessionId?: string;
  role?: string;
  database?: string;
  startedAtUnixMs?: number;
}

export interface PgEvent {
  t: number;
  type: string;
  [k: string]: unknown;
}

export interface PgTimeline {
  header: PgHeader | null;
  events: PgEvent[];
}

// parsePgTimeline parses a pgwire-timeline-v1 NDJSON recording: the first object
// (carrying `v` + `kind`, no `type`) is the header; the rest are events. Malformed
// or blank lines are skipped so a truncated/failed recording still renders.
export function parsePgTimeline(text: string): PgTimeline {
  let header: PgHeader | null = null;
  const events: PgEvent[] = [];
  for (const line of text.split("\n")) {
    const s = line.trim();
    if (!s) continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(s) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (typeof obj.type === "string") {
      events.push({ ...obj, t: Number(obj.t ?? 0), type: obj.type } as PgEvent);
    } else if (header === null && obj.v !== undefined && obj.kind !== undefined) {
      header = {
        v: Number(obj.v),
        kind: String(obj.kind),
        sessionId: obj.session_id as string | undefined,
        role: obj.role as string | undefined,
        database: obj.database as string | undefined,
        startedAtUnixMs: obj.started_at_unix_ms as number | undefined,
      };
    }
  }
  return { header, events };
}
