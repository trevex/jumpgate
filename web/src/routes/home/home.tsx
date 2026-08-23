/**
 * home.tsx — Overview dashboard (the landing route).
 *
 * Replaces the old "land straight in the governance tree" behaviour with a
 * persona-appropriate summary: the caller's active grants and pending requests
 * (everyone), approvals awaiting them (approvers), and recent recordings
 * (auditors — cap-gated). Each card links through to the full view. Cards whose
 * underlying query the caller can't populate simply show an empty state, and the
 * recordings card is hidden without `recording:read`. The catalog moved to
 * `/catalog`; a prominent "Browse the catalog" action points there so a
 * requester's primary task (find an asset → request access) stays one click away.
 */

import { Link } from "react-router-dom";
import { useQuery } from "@connectrpc/connect-query";
import {
  ArrowRight,
  KeyRound,
  Clock3,
  ClipboardCheck,
  Film,
  LayoutGrid,
  Server,
} from "lucide-react";
import {
  listMyGrants,
  listMyRequests,
  listPendingApprovals,
} from "@/gen/jumpgate/accessrequest/v1/accessrequest-AccessRequestService_connectquery";
import { listRecordings } from "@/gen/jumpgate/recording/v1/recording-RecordingService_connectquery";
import { getAssetDisplay } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { useWhoAmI } from "@/auth";
import { capsCover, useCapabilities } from "@/lib/capabilities";
import { relativeTime, timeRemaining, shortId } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

// Resolve an asset's display path (cached; falls back to short id).
function useAssetPath(assetId: string): string {
  const { data } = useQuery(getAssetDisplay, { assetId }, { enabled: Boolean(assetId) });
  const a = data?.asset;
  return a ? a.path || a.name || shortId(assetId) : shortId(assetId);
}

// ─── Card shell ───────────────────────────────────────────────────────────────

interface OverviewCardProps {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  count?: number;
  to: string;
  linkLabel: string;
  children: React.ReactNode;
}

function OverviewCard({ title, icon: Icon, count, to, linkLabel, children }: OverviewCardProps) {
  return (
    <section className="flex flex-col rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-4 py-3">
        <div className="flex items-center gap-2 min-w-0">
          <Icon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <h2 className="text-body font-semibold text-card-foreground truncate">{title}</h2>
          {count != null && count > 0 && (
            <Badge variant="neutral" className="ml-1 tabular-nums">
              {count}
            </Badge>
          )}
        </div>
        <Link
          to={to}
          className="inline-flex items-center gap-1 text-micro font-medium text-primary transition-colors hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 rounded"
        >
          {linkLabel}
          <ArrowRight className="h-3 w-3" aria-hidden="true" />
        </Link>
      </header>
      <div className="flex-1 p-2">{children}</div>
    </section>
  );
}

function CardEmpty({ message }: { message: string }) {
  return (
    <p className="px-2 py-6 text-center text-compact text-muted-foreground">{message}</p>
  );
}

function RowShell({
  to,
  icon: Icon,
  primary,
  secondary,
  trailing,
}: {
  to: string;
  icon: React.ComponentType<{ className?: string }>;
  primary: React.ReactNode;
  secondary?: React.ReactNode;
  trailing?: React.ReactNode;
}) {
  return (
    <Link
      to={to}
      className={cn(
        "flex items-center gap-3 rounded-md px-2 py-2 transition-colors hover:bg-muted/50",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
      )}
    >
      <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <div className="flex-1 min-w-0">
        <div className="truncate font-mono text-compact text-foreground">{primary}</div>
        {secondary != null && (
          <div className="truncate text-micro text-muted-foreground">{secondary}</div>
        )}
      </div>
      {trailing}
    </Link>
  );
}

// ─── Rows (own their per-item display resolution) ─────────────────────────────

function GrantRow({ assetId, assetPath, expiresAt }: { assetId: string; assetPath: string; expiresAt?: string }) {
  const resolved = useAssetPath(assetId);
  const label = assetPath || resolved;
  return (
    <RowShell
      to="/access"
      icon={Server}
      primary={label}
      trailing={
        expiresAt ? (
          <Badge variant="success" className="shrink-0 tabular-nums">
            {timeRemaining(expiresAt)}
          </Badge>
        ) : undefined
      }
    />
  );
}

function RequestRow({ assetId, createdAt }: { assetId: string; createdAt: string }) {
  const label = useAssetPath(assetId);
  return (
    <RowShell
      to="/access"
      icon={Clock3}
      primary={label}
      secondary={`requested ${relativeTime(createdAt)}`}
      trailing={<Badge variant="warning" className="shrink-0">Pending</Badge>}
    />
  );
}

function ApprovalRow({ assetId, createdAt }: { assetId: string; createdAt: string }) {
  const label = useAssetPath(assetId);
  return (
    <RowShell
      to="/approvals"
      icon={ClipboardCheck}
      primary={label}
      secondary={`requested ${relativeTime(createdAt)}`}
    />
  );
}

function RecordingRow({ assetId, sessionId, startedAtUnixMs }: { assetId: string; sessionId: string; startedAtUnixMs: bigint }) {
  const label = useAssetPath(assetId);
  const when = startedAtUnixMs ? relativeTime(new Date(Number(startedAtUnixMs)).toISOString()) : undefined;
  return (
    <RowShell to={`/recordings/${sessionId}`} icon={Film} primary={label} secondary={when} />
  );
}

// ─── Cards ────────────────────────────────────────────────────────────────────

function MyAccessCard() {
  const { data } = useQuery(listMyGrants, { pageSize: 25, pageToken: "" });
  const active = (data?.grants ?? []).filter((g) => g.active);
  return (
    <OverviewCard title="My active access" icon={KeyRound} count={active.length} to="/access" linkLabel="My Access">
      {active.length === 0 ? (
        <CardEmpty message="No active grants. Browse the catalog to request access." />
      ) : (
        active.slice(0, 4).map((g) => (
          <GrantRow key={g.id} assetId={g.assetId} assetPath={g.assetPath} expiresAt={g.expiresAt} />
        ))
      )}
    </OverviewCard>
  );
}

function MyRequestsCard() {
  const { data } = useQuery(listMyRequests, { pageSize: 25, pageToken: "" });
  const pending = (data?.requests ?? []).filter((r) => r.status === "pending");
  return (
    <OverviewCard title="My pending requests" icon={Clock3} count={pending.length} to="/access" linkLabel="My Access">
      {pending.length === 0 ? (
        <CardEmpty message="No requests awaiting a decision." />
      ) : (
        pending.slice(0, 4).map((r) => (
          <RequestRow key={r.id} assetId={r.assetId} createdAt={r.createdAt} />
        ))
      )}
    </OverviewCard>
  );
}

function ApprovalsCard() {
  const { data } = useQuery(listPendingApprovals, { pageSize: 100 });
  const requests = data?.requests ?? [];
  if (requests.length === 0) return null; // only surfaces for actual approvers with a queue
  return (
    <OverviewCard title="Approvals awaiting you" icon={ClipboardCheck} count={requests.length} to="/approvals" linkLabel="Review">
      {requests.slice(0, 4).map((r) => (
        <ApprovalRow key={r.id} assetId={r.assetId} createdAt={r.createdAt} />
      ))}
    </OverviewCard>
  );
}

function RecordingsCard() {
  const { data } = useQuery(listRecordings, { pageSize: 5 });
  const recs = data?.recordings ?? [];
  return (
    <OverviewCard title="Recent recordings" icon={Film} to="/recordings" linkLabel="Recordings">
      {recs.length === 0 ? (
        <CardEmpty message="No session recordings yet." />
      ) : (
        recs.slice(0, 4).map((r) => (
          <RecordingRow key={r.sessionId} assetId={r.assetId} sessionId={r.sessionId} startedAtUnixMs={r.startedAtUnixMs} />
        ))
      )}
    </OverviewCard>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export function OverviewPage() {
  const { data: whoAmI } = useWhoAmI();
  const caps = useCapabilities();
  const canReadRecordings = capsCover(caps, "recording:read");
  const email = whoAmI?.email ?? "";

  return (
    <div className="flex flex-col h-full">
      <header className="border-b border-border px-6 py-5">
        <h1 className="text-title font-semibold text-foreground">Overview</h1>
        <p className="mt-0.5 text-compact text-muted-foreground">
          {email ? `Signed in as ${email}.` : "Welcome."} Your access at a glance.
        </p>
      </header>

      <div className="flex-1 overflow-y-auto p-6">
        {/* Primary action — browse & request */}
        <Link
          to="/catalog"
          className={cn(
            "mb-6 flex items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3 transition-colors hover:bg-muted/50",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
          )}
        >
          <span className="flex items-center gap-3 min-w-0">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary">
              <LayoutGrid className="h-4 w-4" aria-hidden="true" />
            </span>
            <span className="flex flex-col min-w-0">
              <span className="text-body font-medium text-foreground">Browse the catalog</span>
              <span className="truncate text-micro text-muted-foreground">
                Find an asset and request time-boxed access.
              </span>
            </span>
          </span>
          <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        </Link>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          <MyAccessCard />
          <MyRequestsCard />
          <ApprovalsCard />
          {canReadRecordings && <RecordingsCard />}
        </div>
      </div>
    </div>
  );
}
