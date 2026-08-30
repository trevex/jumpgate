import { useEffect, useState } from "react";
import { parseK8sAudit, type K8sAudit, type K8sAuditEvent } from "./k8s-audit";
import {
  Table,
  TableHeader,
  TableRow,
  TableHead,
  TableBody,
  TableCell,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { shortId } from "@/lib/format";

// K8sAuditViewer plays back a k8s-audit-v1 recording as a table of API-server
// requests. It fetches the same /cast streaming route the asciinema player
// uses (format-agnostic bytes, cookie auth) and parses the NDJSON.
export function K8sAuditViewer({ sessionId }: { sessionId: string }) {
  const [audit, setAudit] = useState<K8sAudit | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setAudit(null);
    setError(null);
    fetch(`/api/recordings/${sessionId}/cast`, { credentials: "include" })
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.text();
      })
      .then((text) => {
        if (!cancelled) setAudit(parseK8sAudit(text));
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "load failed");
      });
    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  if (error) {
    return <div className="p-4 text-body text-red-400 font-mono">Audit log unavailable ({error}).</div>;
  }
  if (!audit) {
    return <div className="p-4 text-body text-white/40 font-mono">Loading audit log…</div>;
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="px-4 py-2 border-b border-white/10 text-eyebrow text-white/50 font-mono shrink-0">
        {audit.events.length} request{audit.events.length !== 1 ? "s" : ""} · session {shortId(audit.header?.sessionId ?? sessionId)}
      </div>
      <div className="flex-1 overflow-auto">
        <Table>
          <TableHeader>
            <TableRow className="border-white/10 hover:bg-transparent">
              <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-white/50 font-mono">Time</TableHead>
              <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-white/50 font-mono">Verb</TableHead>
              <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-white/50 font-mono">Resource</TableHead>
              <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-white/50 font-mono">Namespace</TableHead>
              <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-white/50 font-mono">Name</TableHead>
              <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-white/50 font-mono">Groups</TableHead>
              <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-white/50 font-mono">Code</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {audit.events.map((ev, i) => (
              <AuditRow key={i} ev={ev} />
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

function AuditRow({ ev }: { ev: K8sAuditEvent }) {
  return (
    <TableRow className="border-white/5 hover:bg-white/5">
      <TableCell className="py-1.5 font-mono text-compact text-white/50 whitespace-nowrap tabular-nums">
        {ev.ts.slice(11, 19) || "—"}
      </TableCell>
      <TableCell className="py-1.5 font-mono text-compact text-white/80">{ev.verb}</TableCell>
      <TableCell className="py-1.5 font-mono text-compact text-white/80">{ev.resource}</TableCell>
      <TableCell className="py-1.5 font-mono text-compact text-white/60">{ev.namespace || "—"}</TableCell>
      <TableCell className="py-1.5 font-mono text-compact text-white/60 truncate max-w-[160px]">{ev.name || "—"}</TableCell>
      <TableCell className="py-1.5 font-mono text-compact text-white/60">{ev.groups.join(", ") || "—"}</TableCell>
      <TableCell className="py-1.5">
        <CodeBadge code={ev.code} />
      </TableCell>
    </TableRow>
  );
}

function CodeBadge({ code }: { code: number }) {
  const variant = code >= 200 && code < 300 ? "success" : code >= 400 ? "danger" : "neutral";
  return (
    <Badge variant={variant} className="px-1.5 py-0 text-eyebrow font-mono font-semibold tabular-nums">
      {code || "—"}
    </Badge>
  );
}
