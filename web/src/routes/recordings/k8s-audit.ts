export interface K8sHeader {
  v: number;
  kind: string;
  sessionId?: string;
  startedAtUnixMs?: number;
}

export interface K8sAuditEvent {
  ts: string;
  verb: string;
  path: string;
  resource: string;
  namespace: string;
  name: string;
  user: string;
  groups: string[];
  code: number;
}

export interface K8sAudit {
  header: K8sHeader | null;
  events: K8sAuditEvent[];
}

// parseK8sAudit parses a k8s-audit-v1 NDJSON recording: the first object
// (carrying `v` + `kind`, no `verb`) is the header; the rest are API-request
// events. Malformed or blank lines are skipped so a truncated/failed
// recording still renders.
export function parseK8sAudit(text: string): K8sAudit {
  let header: K8sHeader | null = null;
  const events: K8sAuditEvent[] = [];
  for (const line of text.split("\n")) {
    const s = line.trim();
    if (!s) continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(s) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (header === null && obj.v !== undefined && obj.kind !== undefined && obj.verb === undefined) {
      header = {
        v: Number(obj.v),
        kind: String(obj.kind),
        sessionId: obj.session_id as string | undefined,
        startedAtUnixMs: obj.started_at_unix_ms as number | undefined,
      };
    } else if (typeof obj.verb === "string") {
      events.push({
        ts: String(obj.ts ?? ""),
        verb: obj.verb,
        path: String(obj.path ?? ""),
        resource: String(obj.resource ?? ""),
        namespace: String(obj.namespace ?? ""),
        name: String(obj.name ?? ""),
        user: String(obj.user ?? ""),
        groups: Array.isArray(obj.groups) ? (obj.groups as string[]) : [],
        code: Number(obj.code ?? 0),
      });
    }
  }
  return { header, events };
}
