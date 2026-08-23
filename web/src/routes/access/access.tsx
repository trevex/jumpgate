/**
 * access.tsx — "My Access" page.
 *
 * Two tabs:
 *   Requests — the caller's own JIT requests, paginated, with colour-coded
 *              status badges and a "Load more" button.
 *   Grants   — the caller's access grants (active + past), with a live
 *              expiry countdown and copy-able connect command(s).
 *
 * Grant.assetPath and Grant.logins are populated by the server so the UI
 * can emit valid `jumpgate connect <login>@<asset_path>` commands without
 * any extra lookups.
 */

import { useState, useCallback, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useInfiniteQuery, useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import {
  listMyRequests,
  listMyGrants,
  revokeGrant,
} from "@/gen/jumpgate/accessrequest/v1/accessrequest-AccessRequestService_connectquery";
import { getAssetDisplay } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { getRoleDisplay } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import type {
  AccessRequest,
  Grant,
} from "@/gen/jumpgate/accessrequest/v1/accessrequest_pb";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { cn } from "@/lib/utils";
import { relativeTime, timeRemaining, isExpired, connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";
import {
  Copy,
  Check,
  Terminal,
  ClipboardList,
  KeyRound,
  AlertTriangle,
  SquareArrowOutUpRight,
  Film,
} from "lucide-react";

// ─── Status badge ─────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<string, string> = {
  pending:   "border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300",
  granted:   "border-green-300 bg-green-50 text-green-700 dark:border-green-500/30 dark:bg-green-500/10 dark:text-green-300",
  denied:    "border-red-300 bg-red-50 text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300",
  cancelled: "border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-500/30 dark:bg-slate-500/10 dark:text-slate-300",
};

function StatusBadge({ status }: { status: string }) {
  const style = STATUS_STYLES[status] ?? "border-border bg-muted text-muted-foreground";
  const label = status.charAt(0).toUpperCase() + status.slice(1);
  return (
    <Badge
      variant="outline"
      className={cn("rounded px-1.5 py-0 text-[10px] font-semibold uppercase tracking-wide border", style)}
    >
      {label}
    </Badge>
  );
}

// ─── Copy button (inline) ─────────────────────────────────────────────────────

function InlineCopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard not available — silently ignore
    }
  }, [text]);

  return (
    <button
      onClick={copy}
      className={cn(
        "flex h-6 w-6 shrink-0 items-center justify-center rounded transition-colors duration-150",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
        copied
          ? "text-green-600 dark:text-green-400"
          : "text-muted-foreground hover:text-foreground",
      )}
      aria-label={copied ? "Copied" : (label ?? "Copy")}
    >
      {copied ? (
        <Check className="h-3 w-3" aria-hidden="true" />
      ) : (
        <Copy className="h-3 w-3" aria-hidden="true" />
      )}
    </button>
  );
}

// ─── Expiry countdown (ticking) ───────────────────────────────────────────────

function ExpiryBadge({ expiresAt }: { expiresAt: string }) {
  const [tick, setTick] = useState(0);

  useEffect(() => {
    // Update every 30 s — recompute expired + remaining on each tick
    const id = setInterval(() => setTick((n) => n + 1), 30_000);
    return () => clearInterval(id);
  }, [expiresAt]);

  // Recompute on every tick so the badge flips when a grant lapses while open
  const expired = isExpired(expiresAt);
  const remaining = timeRemaining(expiresAt);
  void tick; // consumed via the setter above; included to keep the dep honest

  return (
    <span
      className={cn(
        "font-mono text-[11px] tabular-nums",
        expired ? "text-muted-foreground line-through" : "text-foreground",
      )}
      title={expiresAt}
      aria-label={expired ? "Expired" : `Expires in ${remaining}`}
    >
      {expired ? "expired" : remaining}
    </span>
  );
}

// ─── Requests table ───────────────────────────────────────────────────────────

// Truncates a UUID to its first segment for display (e.g. "a3f2b1c0-…")
function shortId(id: string): string {
  return id.split("-")[0] ?? id;
}

// ─── Per-row enrichment hooks ─────────────────────────────────────────────────
// The caller is party to their own requests, so the request-scoped display
// reads resolve for them; fall back to the short UUID on error/missing.

function useAssetDisplay(assetId: string): string {
  const { data } = useQuery(getAssetDisplay, { assetId }, { enabled: Boolean(assetId) });
  if (!data?.asset) return shortId(assetId);
  return data.asset.path || data.asset.name || shortId(assetId);
}

function useRoleDisplay(roleId: string): string {
  const { data } = useQuery(getRoleDisplay, { id: roleId }, { enabled: Boolean(roleId) });
  if (!data?.role) return shortId(roleId);
  const r = data.role;
  return r.folderPath ? `${r.name}.${r.folderPath}` : r.name;
}

function RequestRow({ req }: { req: AccessRequest }) {
  const assetDisplay = useAssetDisplay(req.assetId);
  const roleDisplay = useRoleDisplay(req.roleId);

  return (
    <div className="grid grid-cols-[1fr_auto_auto] items-start gap-x-3 gap-y-0.5 px-4 py-3 hover:bg-muted/40 transition-colors">
      {/* Asset / Role */}
      <div className="flex flex-col gap-0.5 min-w-0">
        <span
          className="font-mono text-[11px] text-muted-foreground truncate"
          title={req.assetId}
          aria-label={`Asset ${assetDisplay}`}
        >
          {assetDisplay}
        </span>
        <span
          className="text-[11px] text-muted-foreground truncate"
          title={req.roleId}
          aria-label={`Role ${roleDisplay}`}
        >
          role: {roleDisplay}
        </span>
        {req.reason && (
          <span
            className="text-[12px] text-foreground line-clamp-2"
            title={req.reason}
          >
            {req.reason}
          </span>
        )}
      </div>

      {/* Status */}
      <div className="pt-0.5">
        <StatusBadge status={req.status} />
      </div>

      {/* Time */}
      <div className="flex flex-col items-end gap-0.5 pt-0.5 shrink-0">
        <span
          className="text-[11px] text-muted-foreground whitespace-nowrap"
          title={req.createdAt}
        >
          {relativeTime(req.createdAt)}
        </span>
        {req.resolvedAt && (
          <span
            className="text-[10px] text-muted-foreground/70 whitespace-nowrap"
            title={req.resolvedAt}
          >
            resolved {relativeTime(req.resolvedAt)}
          </span>
        )}
      </div>
    </div>
  );
}

function RequestsTab() {
  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery(
    listMyRequests,
    { pageSize: 25, pageToken: "" },
    {
      pageParamKey: "pageToken",
      getNextPageParam: (last) => last.nextPageToken || undefined,
    },
  );

  const requests = data?.pages.flatMap((p) => p.requests) ?? [];

  if (isLoading) return <LoadingRows />;

  if (isError) {
    return (
      <ErrorState
        size="sm"
        message={connectErrorMessage(error)}
        onRetry={() => refetch()}
      />
    );
  }

  if (requests.length === 0) {
    return (
      <EmptyState
        icon={ClipboardList}
        message="You have no access requests."
      />
    );
  }

  return (
    <div className="flex flex-col">
      {/* Column header */}
      <div className="grid grid-cols-[1fr_auto_auto] gap-x-3 border-b border-border px-4 py-2">
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Asset / Role / Reason
        </span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Status
        </span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground text-right">
          Time
        </span>
      </div>

      <div className="divide-y divide-border" role="list" aria-label="Access requests">
        {requests.map((req) => (
          <div key={req.id} role="listitem">
            <RequestRow req={req} />
          </div>
        ))}
      </div>

      {hasNextPage && (
        <div className="flex justify-center border-t border-border px-4 py-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
            className="h-7 text-[12px]"
          >
            {isFetchingNextPage ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Grants tab ───────────────────────────────────────────────────────────────

/**
 * Build connect commands from the enriched grant.
 * - If the role has ssh:login caps, return one `jumpgate connect <login>@<path>` per login.
 * - If assetPath is set but no logins (e.g. password/key asset), return one bare-path command.
 * - If neither, return an empty array (connect block is omitted).
 */
function grantConnectCmds(grant: Grant): string[] {
  const path = grant.assetPath;
  if (grant.logins.length > 0 && path) {
    return grant.logins.map((login) => `jumpgate connect ${login}@${path}`);
  }
  if (path) {
    return [`jumpgate connect ${path}`];
  }
  return [];
}

// ─── Two-step revoke button ───────────────────────────────────────────────────

const REVOKE_CONFIRM_MS = 4_000;

function RevokeButton({
  onConfirmed,
  isRevoking,
}: {
  onConfirmed: () => void;
  isRevoking: boolean;
}) {
  const [confirming, setConfirming] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Cancel confirm-state if the component unmounts or revoking starts
  useEffect(() => {
    if (isRevoking) setConfirming(false);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [isRevoking]);

  function handleClick() {
    if (!confirming) {
      setConfirming(true);
      timerRef.current = setTimeout(() => setConfirming(false), REVOKE_CONFIRM_MS);
    } else {
      if (timerRef.current) clearTimeout(timerRef.current);
      setConfirming(false);
      onConfirmed();
    }
  }

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={handleClick}
      disabled={isRevoking}
      className={cn(
        "h-6 text-[11px] transition-colors",
        confirming
          ? "border-red-400 bg-red-50 text-red-700 hover:bg-red-100 dark:border-red-500/50 dark:bg-red-500/15 dark:text-red-300 dark:hover:bg-red-500/25"
          : "border-red-200 text-red-600 hover:bg-red-50 hover:text-red-700 dark:border-red-500/30 dark:text-red-400 dark:hover:bg-red-500/10 dark:hover:text-red-300",
      )}
      aria-label={confirming ? "Click again to confirm revoke" : "Revoke this grant"}
    >
      {isRevoking ? (
        "Revoking…"
      ) : confirming ? (
        <span className="flex items-center gap-1">
          <AlertTriangle className="h-3 w-3" aria-hidden="true" />
          Confirm revoke?
        </span>
      ) : (
        "Revoke"
      )}
    </Button>
  );
}

// ─── Grant card ───────────────────────────────────────────────────────────────

function GrantCard({ grant }: { grant: Grant }) {
  const navigate = useNavigate();
  const invalidateList = useInvalidateList();
  const revoked = Boolean(grant.revokedAt);
  const active = grant.active;

  const { mutate: doRevoke, isPending: isRevoking } = useMutation(revokeGrant, {
    onSuccess: () => {
      toast.success("Grant revoked");
      void invalidateList([listMyGrants, listMyRequests]);
    },
    onError: (err) => {
      toast.error("Failed to revoke", { description: connectErrorMessage(err) });
    },
  });

  const connectCmds = grantConnectCmds(grant);

  return (
    <div
      className={cn(
        "flex flex-col gap-2 rounded-lg border border-border bg-background p-4 transition-colors",
        !active && "opacity-60",
      )}
      aria-label={`Grant for asset ${grant.assetPath || shortId(grant.assetId)}`}
    >
      {/* Top row: asset / role + expiry status */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex flex-col gap-0.5 min-w-0">
          <span
            className="font-mono text-[11px] text-foreground truncate"
            title={grant.assetId}
          >
            {grant.assetPath || shortId(grant.assetId)}
          </span>
          <span
            className="text-[11px] text-muted-foreground truncate"
            title={grant.roleId}
          >
            role: {shortId(grant.roleId)}
          </span>
        </div>

        <div className="flex flex-col items-end gap-1 shrink-0">
          {revoked ? (
            <Badge
              variant="outline"
              className="rounded border-red-200 bg-red-50 px-1.5 py-0 text-[10px] font-semibold uppercase text-red-600 tracking-wide dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300"
            >
              Revoked
            </Badge>
          ) : grant.active ? (
            <Badge
              variant="outline"
              className="rounded border-green-300 bg-green-50 px-1.5 py-0 text-[10px] font-semibold uppercase text-green-700 tracking-wide dark:border-green-500/30 dark:bg-green-500/10 dark:text-green-300"
            >
              Active
            </Badge>
          ) : (
            <Badge
              variant="outline"
              className="rounded border-slate-200 bg-slate-50 px-1.5 py-0 text-[10px] font-semibold uppercase text-slate-500 tracking-wide dark:border-slate-500/30 dark:bg-slate-500/10 dark:text-slate-300"
            >
              Expired
            </Badge>
          )}
          {grant.expiresAt && (
            <ExpiryBadge expiresAt={grant.expiresAt} />
          )}
        </div>
      </div>

      {/* Connect command(s) — one row per login */}
      {active && connectCmds.length > 0 && (
        <div className="flex flex-col gap-1">
          {connectCmds.map((cmd) => (
            <div
              key={cmd}
              className="flex items-center gap-2 rounded border border-border bg-muted px-3 py-2"
            >
              <Terminal
                className="h-3.5 w-3.5 shrink-0 text-muted-foreground"
                aria-hidden="true"
              />
              <code className="flex-1 overflow-x-auto font-mono text-[11px] text-foreground whitespace-nowrap">
                {cmd}
              </code>
              <InlineCopyButton text={cmd} label="Copy connect command" />
            </div>
          ))}
        </div>
      )}

      {/* Open in-browser terminal — one link per concrete SSH login */}
      {active && grant.logins.length > 0 && (
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {grant.logins.map((login) => (
            <a
              key={login}
              href={`/terminal/${grant.assetId}?login=${encodeURIComponent(login)}`}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                "inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[11px] font-medium text-primary transition-colors hover:underline",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
              )}
              aria-label={`Open browser terminal as ${login}`}
            >
              <SquareArrowOutUpRight className="h-3 w-3" aria-hidden="true" />
              Open terminal ({login})
            </a>
          ))}
        </div>
      )}

      {/* Footer — session recordings (always, subjects may review their own
          sessions) + revoke (two-step confirm, active grants only) */}
      <div className="flex items-center justify-between gap-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate(`/recordings?grantId=${grant.id}`)}
          className="h-7 gap-1.5 px-2 text-[12px] text-muted-foreground hover:text-foreground"
          aria-label="View session recordings for this grant"
        >
          <Film className="h-3.5 w-3.5" aria-hidden="true" />
          Session recordings
        </Button>

        {active && (
          <RevokeButton
            isRevoking={isRevoking}
            onConfirmed={() => doRevoke({ grantId: grant.id, reason: "Self-revoked" })}
          />
        )}
      </div>

      {/* Revoked reason */}
      {revoked && grant.revokedReason && (
        <p className="text-[11px] text-muted-foreground italic">
          Reason: {grant.revokedReason}
        </p>
      )}
    </div>
  );
}

function GrantsTab() {
  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery(
    listMyGrants,
    { pageSize: 25, pageToken: "" },
    {
      pageParamKey: "pageToken",
      getNextPageParam: (last) => last.nextPageToken || undefined,
    },
  );

  const grants = data?.pages.flatMap((p) => p.grants) ?? [];

  if (isLoading) return <LoadingRows />;

  if (isError) {
    return (
      <ErrorState
        size="sm"
        message={connectErrorMessage(error)}
        onRetry={() => refetch()}
      />
    );
  }

  if (grants.length === 0) {
    return <EmptyState icon={KeyRound} message="You have no active grants." />;
  }

  return (
    <div className="flex flex-col gap-3">
      <div
        className="grid grid-cols-1 gap-3 sm:grid-cols-2"
        role="list"
        aria-label="Access grants"
      >
        {grants.map((g) => (
          <div key={g.id} role="listitem">
            <GrantCard grant={g} />
          </div>
        ))}
      </div>

      {hasNextPage && (
        <div className="flex justify-center pt-1">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
            className="h-7 text-[12px]"
          >
            {isFetchingNextPage ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── My Access page ───────────────────────────────────────────────────────────

export function MyAccessPage() {
  return (
    <div className="flex flex-col gap-0 h-full">
      {/* Page header */}
      <header className="border-b border-border px-6 py-5">
        <h1 className="text-[15px] font-semibold text-foreground">My Access</h1>
        <p className="mt-0.5 text-[12px] text-muted-foreground">
          Your pending requests and active access grants.
        </p>
      </header>

      {/* Tabs */}
      <Tabs defaultValue="requests" className="flex flex-1 flex-col overflow-hidden">
        <div className="border-b border-border px-6 pt-4">
          <TabsList className="h-8 gap-0 rounded-none border-b-0 bg-transparent p-0">
            <TabsTrigger
              value="requests"
              className={cn(
                "relative h-8 rounded-none border-b-2 border-transparent bg-transparent px-4 pb-2 pt-0 text-[13px] font-medium text-muted-foreground shadow-none transition-colors",
                "data-[state=active]:border-primary data-[state=active]:text-foreground data-[state=active]:shadow-none",
              )}
            >
              Requests
            </TabsTrigger>
            <TabsTrigger
              value="grants"
              className={cn(
                "relative h-8 rounded-none border-b-2 border-transparent bg-transparent px-4 pb-2 pt-0 text-[13px] font-medium text-muted-foreground shadow-none transition-colors",
                "data-[state=active]:border-primary data-[state=active]:text-foreground data-[state=active]:shadow-none",
              )}
            >
              Grants
            </TabsTrigger>
          </TabsList>
        </div>

        <TabsContent
          value="requests"
          className="flex-1 overflow-y-auto mt-0 data-[state=inactive]:hidden"
        >
          <RequestsTab />
        </TabsContent>

        <TabsContent
          value="grants"
          className="flex-1 overflow-y-auto mt-0 data-[state=inactive]:hidden p-4"
        >
          <GrantsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
