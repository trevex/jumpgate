/**
 * recordings.tsx — Session recordings list + in-browser asciinema player.
 *
 * Layout: full-height split when a recording is selected.
 *   Left panel  — scrollable list with keyset "Load more"
 *   Right panel — asciinema terminal player fetching from same-origin
 *                 /api/recordings/{sessionId}/cast (cookie rides along)
 *
 * Route guards (RequireCap recording:read) are applied in main.tsx so this
 * component can assume the caller holds the capability.
 */

import { useState, useEffect, useRef, useCallback } from "react";
import type { ReactNode } from "react";
import { useParams, useNavigate, useSearchParams } from "react-router-dom";
import { useQuery, useInfiniteQuery } from "@connectrpc/connect-query";
import { create as createPlayer } from "asciinema-player";
import "asciinema-player/dist/bundle/asciinema-player.css";
import type { Player } from "asciinema-player";
import {
  listRecordings,
  getRecording,
} from "@/gen/jumpgate/recording/v1/recording-RecordingService_connectquery";
import { getAssetDisplay } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { getUserDisplay } from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import type { Recording } from "@/gen/jumpgate/recording/v1/recording_pb";
import { PgTimelineViewer } from "./pg-timeline-view";
import { K8sAuditViewer } from "./k8s-audit-view";
import { RdpView } from "./rdp-view";
import {
  Table,
  TableHeader,
  TableRow,
  TableHead,
  TableBody,
  TableCell,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EmptyState, ErrorState } from "@/components/states/states";
import { cn } from "@/lib/utils";
import { connectErrorMessage, relativeTime, shortId } from "@/lib/format";
import {
  Film,
  RefreshCw,
  Terminal,
  AlertTriangle,
  ChevronRight,
  Clock,
  User,
  Server,
  X,
} from "lucide-react";

// ─── helpers ──────────────────────────────────────────────────────────────────

/** Format duration between two unix-ms timestamps as m:ss or h:mm:ss */
function formatDuration(startMs: bigint, endMs: bigint): string {
  if (!startMs || !endMs || endMs <= startMs) return "—";
  const secs = Number((endMs - startMs) / 1000n);
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  return `${m}:${String(s).padStart(2, "0")}`;
}

/** Relative time from a unix-ms timestamp. */
function relativeTimeMs(unixMs: bigint): string {
  if (!unixMs) return "—";
  return relativeTime(new Date(Number(unixMs)).toISOString());
}

// ─── Recording status badge ───────────────────────────────────────────────────

const STATUS_VARIANTS: Record<string, "success" | "info" | "danger" | "neutral"> = {
  completed: "success",
  recording: "info",
  failed: "danger",
};

function StatusBadge({ status }: { status: string }) {
  const variant = STATUS_VARIANTS[status] ?? "neutral";
  return (
    <Badge
      variant={variant}
      className="px-1.5 py-0 text-eyebrow font-semibold capitalize tabular-nums"
    >
      {status}
    </Badge>
  );
}

// ─── Per-row enrichment hooks ─────────────────────────────────────────────────

function useAssetDisplay(assetId: string): string {
  const { data } = useQuery(getAssetDisplay, { assetId }, { enabled: Boolean(assetId) });
  if (!data?.asset) return shortId(assetId);
  return data.asset.path || data.asset.name || shortId(assetId);
}

function useUserDisplay(userId: string): string {
  const { data } = useQuery(getUserDisplay, { id: userId }, { enabled: Boolean(userId) });
  if (!data?.user) return shortId(userId);
  return data.user.displayName || data.user.email || shortId(userId);
}

// ─── Skeleton rows ────────────────────────────────────────────────────────────

function RowSkeleton() {
  return (
    <TableRow aria-hidden="true">
      <TableCell><Skeleton className="h-3 w-32 rounded" /></TableCell>
      <TableCell><Skeleton className="h-3 w-24 rounded" /></TableCell>
      <TableCell><Skeleton className="h-4 w-14 rounded" /></TableCell>
      <TableCell><Skeleton className="h-3 w-20 rounded" /></TableCell>
      <TableCell><Skeleton className="h-3 w-12 rounded" /></TableCell>
      <TableCell />
    </TableRow>
  );
}

// ─── Recording row ────────────────────────────────────────────────────────────

interface RecordingRowProps {
  rec: Recording;
  isSelected: boolean;
  onSelect: (id: string) => void;
}

function RecordingRow({ rec, isSelected, onSelect }: RecordingRowProps) {
  const assetDisplay = useAssetDisplay(rec.assetId);
  const userDisplay = useUserDisplay(rec.userId);

  return (
    <TableRow
      className={cn(
        "cursor-pointer transition-colors",
        isSelected ? "bg-primary/8 border-l-2 border-l-primary" : "hover:bg-muted/40",
      )}
      onClick={() => onSelect(rec.sessionId)}
      role="button"
      tabIndex={0}
      aria-selected={isSelected}
      aria-label={`Recording of ${assetDisplay} by ${userDisplay}`}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(rec.sessionId);
        }
      }}
    >
      {/* Asset */}
      <TableCell className="py-2.5">
        <span className="flex items-center gap-1.5 font-mono text-compact text-foreground">
          <Server className="h-3 w-3 shrink-0 text-muted-foreground" aria-hidden="true" />
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="truncate max-w-[160px] cursor-default">{assetDisplay}</span>
            </TooltipTrigger>
            <TooltipContent side="top" className="text-xs font-mono">{rec.assetId}</TooltipContent>
          </Tooltip>
        </span>
      </TableCell>

      {/* User */}
      <TableCell className="py-2.5">
        <span className="flex items-center gap-1.5 text-compact text-muted-foreground">
          <User className="h-3 w-3 shrink-0" aria-hidden="true" />
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="truncate max-w-[140px] cursor-default">{userDisplay}</span>
            </TooltipTrigger>
            <TooltipContent side="top" className="text-xs font-mono">{rec.userId}</TooltipContent>
          </Tooltip>
        </span>
      </TableCell>

      {/* Status */}
      <TableCell className="py-2.5">
        <StatusBadge status={rec.status} />
      </TableCell>

      {/* Started */}
      <TableCell className="py-2.5">
        <span
          className="flex items-center gap-1 text-compact text-muted-foreground whitespace-nowrap"
          title={rec.startedAtUnixMs ? new Date(Number(rec.startedAtUnixMs)).toISOString() : ""}
        >
          <Clock className="h-3 w-3 shrink-0" aria-hidden="true" />
          {rec.startedAtUnixMs ? relativeTimeMs(rec.startedAtUnixMs) : "—"}
        </span>
      </TableCell>

      {/* Duration */}
      <TableCell className="py-2.5 tabular-nums text-compact text-muted-foreground">
        {formatDuration(rec.startedAtUnixMs, rec.endedAtUnixMs)}
      </TableCell>

      {/* Chevron */}
      <TableCell className="py-2.5 pr-3">
        <ChevronRight
          className={cn(
            "h-3.5 w-3.5 text-muted-foreground/50 transition-colors",
            isSelected && "text-primary",
          )}
          aria-hidden="true"
        />
      </TableCell>
    </TableRow>
  );
}

// ─── Asciinema player panel ───────────────────────────────────────────────────

interface PlayerPanelProps {
  sessionId: string;
  onClose: () => void;
}

function PlayerPanel({ sessionId, onClose }: PlayerPanelProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const playerRef = useRef<Player | null>(null);
  const [playerError, setPlayerError] = useState<string | null>(null);

  // Fetch recording metadata for display (title, asset).
  const { data: recData } = useQuery(getRecording, { sessionId });
  const assetDisplay = useAssetDisplay(recData?.assetId ?? "");

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    // Postgres, Kubernetes, and RDP recordings use their own structured
    // viewers, not the terminal player.
    if (
      recData?.format === "pgwire-timeline-v1" ||
      recData?.format === "k8s-audit-v1" ||
      recData?.format === "rdp-graphics-v1"
    )
      return;
    setPlayerError(null);

    // Dispose previous instance before creating a new one.
    if (playerRef.current) {
      playerRef.current.dispose();
      playerRef.current = null;
    }

    // Clear the container so asciinema-player gets a fresh mount.
    container.innerHTML = "";

    const src = `/api/recordings/${sessionId}/cast`;

    let raf = 0;
    let ro: ResizeObserver | null = null;

    try {
      const p = createPlayer(
        { url: src, fetchOpts: { credentials: "include" } },
        container,
        {
          autoPlay: true,
          // Fit within the panel in BOTH axes. Unlike fit:"width", this mode
          // reacts to the container's own size settling after mount (the
          // ResizeObserver path), so the terminal renders reliably in the side
          // panel instead of staying blank until a window resize (opening
          // devtools) nudges it. A large recording (e.g. 188x99) scales to fit.
          fit: "both",
          theme: "monokai",
          terminalFontFamily: "'JetBrains Mono', 'Fira Mono', monospace",
          terminalFontSize: "small",
          controls: true,
        },
      );
      playerRef.current = p;

      // asciinema-player measures the container once at create() and afterwards
      // only refits on a window 'resize' — it does not observe the container. In a
      // side panel the container's final size and the web-font metrics settle a
      // frame later, so the terminal mounts blank/mis-sized until some resize
      // (notably: opening devtools) nudges it. Force a refit once layout and fonts
      // settle, and whenever the panel itself resizes. rAF-coalesced so a refit
      // (which does not change the container box) can't feed back into a loop.
      let scheduled = false;
      const refit = () => {
        if (scheduled) return;
        scheduled = true;
        raf = requestAnimationFrame(() => {
          scheduled = false;
          window.dispatchEvent(new Event("resize"));
        });
      };
      refit();
      void document.fonts?.ready.then(refit).catch(() => {});
      ro = new ResizeObserver(refit);
      ro.observe(container);

      // The player emits no explicit "error" event on a 404/403 fetch, but the
      // browser will log it. We detect load failure by observing the fetch response.
      fetch(src, { credentials: "include", method: "HEAD" }).then((r) => {
        if (!r.ok) setPlayerError("Recording unavailable (HTTP " + r.status + ")");
      }).catch(() => {
        setPlayerError("Recording unavailable — could not reach the server.");
      });
    } catch (err) {
      setPlayerError(err instanceof Error ? err.message : "Player failed to initialize.");
    }

    return () => {
      if (ro) ro.disconnect();
      if (raf) cancelAnimationFrame(raf);
      if (playerRef.current) {
        playerRef.current.dispose();
        playerRef.current = null;
      }
    };
  // Re-mount only when the sessionId changes.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, recData?.format]);

  return (
    <div className="flex flex-col h-full bg-[#1a1a1a] border-l border-border">
      {/* Panel header */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-white/10 shrink-0">
        <Terminal className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
        <span className="flex-1 min-w-0 text-compact font-medium text-white/80 truncate font-mono">
          {assetDisplay || shortId(sessionId)}
        </span>
        <span className="text-eyebrow text-white/40 font-mono shrink-0">{shortId(sessionId)}</span>
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 shrink-0 text-white/40 hover:text-white hover:bg-white/10"
          onClick={onClose}
          aria-label="Close player"
        >
          <X className="h-3.5 w-3.5" aria-hidden="true" />
        </Button>
      </div>

      {/* Player / viewer area */}
      {recData === undefined ? (
        <div className="flex-1 flex items-center justify-center text-body text-white/40 font-mono">
          Loading…
        </div>
      ) : recData.format === "pgwire-timeline-v1" ? (
        <div className="flex-1 overflow-hidden">
          <PgTimelineViewer sessionId={sessionId} />
        </div>
      ) : recData.format === "k8s-audit-v1" ? (
        <div className="flex-1 overflow-hidden">
          <K8sAuditViewer sessionId={sessionId} />
        </div>
      ) : recData.format === "rdp-graphics-v1" ? (
        <div className="flex-1 overflow-hidden">
          <RdpView sessionId={sessionId} />
        </div>
      ) : (
        <div className="flex-1 overflow-hidden flex items-center justify-center p-2">
          {playerError ? (
            <div className="flex flex-col items-center gap-3 text-center">
              <AlertTriangle className="h-8 w-8 text-warning-fg" aria-hidden="true" />
              <p className="text-body text-white/60 max-w-xs">{playerError}</p>
            </div>
          ) : (
            <div
              ref={containerRef}
              className="w-full h-full"
              aria-label={`Terminal recording player for session ${sessionId}`}
            />
          )}
        </div>
      )}
    </div>
  );
}

// ─── Active-filter chips ──────────────────────────────────────────────────────

/** Chip label for an asset filter — resolves the asset path/name via display RPC. */
function AssetFilterChip({ assetId }: { assetId: string }) {
  const label = useAssetDisplay(assetId);
  return (
    <FilterChipShell icon={Server} prefix="Asset">
      {label}
    </FilterChipShell>
  );
}

/** Chip label for a user filter — resolves the display name/email via display RPC. */
function UserFilterChip({ userId }: { userId: string }) {
  const label = useUserDisplay(userId);
  return (
    <FilterChipShell icon={User} prefix="User">
      {label}
    </FilterChipShell>
  );
}

function FilterChipShell({
  icon: Icon,
  prefix,
  children,
}: {
  icon: typeof Server;
  prefix: string;
  children: ReactNode;
}) {
  return (
    <Badge
      variant="secondary"
      className="gap-1 rounded-full px-2 py-0.5 text-micro font-normal"
    >
      <Icon className="h-3 w-3 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="text-muted-foreground">{prefix}:</span>
      <span className="max-w-[160px] truncate font-mono text-foreground">{children}</span>
    </Badge>
  );
}

interface FilterChipsProps {
  assetId: string;
  userId: string;
  grantId: string;
  onClear: () => void;
}

function FilterChips({ assetId, userId, grantId, onClear }: FilterChipsProps) {
  return (
    <div className="flex flex-wrap items-center gap-2 px-6 py-2.5 border-b border-border shrink-0 bg-muted/20">
      <span className="text-micro font-medium uppercase tracking-wider text-muted-foreground">
        Filtered by
      </span>
      {assetId && <AssetFilterChip assetId={assetId} />}
      {userId && <UserFilterChip userId={userId} />}
      {grantId && (
        <FilterChipShell icon={Film} prefix="Grant">
          {shortId(grantId)}
        </FilterChipShell>
      )}
      <Button
        variant="ghost"
        size="sm"
        onClick={onClear}
        className="h-6 gap-1 px-2 text-micro text-muted-foreground hover:text-foreground"
        aria-label="Clear all recording filters"
      >
        <X className="h-3 w-3" aria-hidden="true" />
        Clear
      </Button>
    </div>
  );
}

// ─── Recordings list ──────────────────────────────────────────────────────────

const PAGE_SIZE = 50;

interface RecordingsListProps {
  selectedId: string | null;
  onSelect: (id: string) => void;
}

function RecordingsList({ selectedId, onSelect }: RecordingsListProps) {
  const [sp, setSearchParams] = useSearchParams();
  const assetId = sp.get("assetId") ?? "";
  const userId = sp.get("userId") ?? "";
  const grantId = sp.get("grantId") ?? "";
  const hasFilter = Boolean(assetId || userId || grantId);

  // The filter inputs are part of the query input (and thus the query key), so
  // changing a filter automatically resets pagination to the first page — no
  // manual reset needed.
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
    listRecordings,
    {
      pageSize: PAGE_SIZE,
      pageToken: "",
      userId,
      assetId,
      grantId,
    },
    {
      pageParamKey: "pageToken",
      getNextPageParam: (last) => last.nextPageToken || undefined,
    },
  );

  const allRecordings = data?.pages.flatMap((p) => p.recordings) ?? [];

  // Clear all active filters by dropping the query params.
  const clearFilters = useCallback(() => {
    setSearchParams({}, { replace: true });
  }, [setSearchParams]);

  // Show initial loading skeletons only on first fetch.
  const isInitialLoading = isLoading && allRecordings.length === 0;

  return (
    <div className="flex flex-col h-full">
      {/* Section header */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-border shrink-0">
        <div className="flex items-center gap-2">
          <Film className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <span className="text-body font-medium text-foreground">
            {allRecordings.length > 0 ? `${allRecordings.length} recording${allRecordings.length !== 1 ? "s" : ""}` : "Recordings"}
          </span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void refetch()}
          className="h-7 gap-1 text-compact text-muted-foreground"
          aria-label="Refresh recordings list"
        >
          <RefreshCw className="h-3 w-3" aria-hidden="true" />
        </Button>
      </div>

      {/* Active-filter chips */}
      {hasFilter && (
        <FilterChips
          assetId={assetId}
          userId={userId}
          grantId={grantId}
          onClear={clearFilters}
        />
      )}

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {isInitialLoading ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9">Asset</TableHead>
                <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9">User</TableHead>
                <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9">Status</TableHead>
                <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9">Started</TableHead>
                <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9">Duration</TableHead>
                <TableHead className="w-6" />
              </TableRow>
            </TableHeader>
            <TableBody aria-busy="true" aria-label="Loading recordings">
              {Array.from({ length: 5 }).map((_, i) => <RowSkeleton key={i} />)}
            </TableBody>
          </Table>
        ) : isError ? (
          <ErrorState
            icon={AlertTriangle}
            message={connectErrorMessage(error)}
            onRetry={() => void refetch()}
          />
        ) : allRecordings.length === 0 ? (
          <EmptyState
            icon={Film}
            size="lg"
            title={hasFilter ? "No recordings for this filter" : "No recordings yet"}
            message={
              hasFilter
                ? "No recordings match the active filter. Clear it to see all recordings."
                : "Session recordings will appear here once sessions have been recorded."
            }
          />
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-muted-foreground font-semibold">Asset</TableHead>
                  <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-muted-foreground font-semibold">User</TableHead>
                  <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-muted-foreground font-semibold">Status</TableHead>
                  <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-muted-foreground font-semibold">Started</TableHead>
                  <TableHead className="text-eyebrow uppercase tracking-wider py-2 h-9 text-muted-foreground font-semibold">Duration</TableHead>
                  <TableHead className="w-6" />
                </TableRow>
              </TableHeader>
              <TableBody role="list" aria-label="Session recordings">
                {allRecordings.map((rec) => (
                  <RecordingRow
                    key={rec.sessionId}
                    rec={rec}
                    isSelected={rec.sessionId === selectedId}
                    onSelect={onSelect}
                  />
                ))}
              </TableBody>
            </Table>

            {/* Load more */}
            {hasNextPage && (
              <div className="flex justify-center py-4 border-t border-border">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => fetchNextPage()}
                  disabled={isFetchingNextPage}
                  className="h-7 gap-1.5 text-compact"
                >
                  {isFetchingNextPage ? (
                    <>
                      <RefreshCw className="h-3 w-3 animate-spin" aria-hidden="true" />
                      Loading…
                    </>
                  ) : (
                    "Load more"
                  )}
                </Button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ─── RecordingsPage ───────────────────────────────────────────────────────────

export function RecordingsPage() {
  const { sessionId } = useParams<{ sessionId?: string }>();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const selectedId = sessionId ?? null;

  // Preserve the active filter (?grantId=/?assetId=/?userId=) across selecting
  // and closing a recording. This keeps the list scoped, and — critically for
  // the grant-scoped review path — keeps ?grantId= on the URL so a subject or
  // approver without recording:read stays inside the route guard when they open
  // a recording (the guard admits grant-scoped entry).
  const query = searchParams.toString();
  const suffix = query ? `?${query}` : "";

  const handleSelect = useCallback((id: string) => {
    navigate(`/recordings/${id}${suffix}`, { replace: true });
  }, [navigate, suffix]);

  const handleClose = useCallback(() => {
    navigate(`/recordings${suffix}`, { replace: true });
  }, [navigate, suffix]);

  return (
    <div className="flex flex-col h-full">
      {/* Page header */}
      <header className="border-b border-border px-6 py-5 shrink-0">
        <h1 className="text-title font-semibold text-foreground">Recordings</h1>
        <p className="mt-0.5 text-compact text-muted-foreground">
          Session recordings for audit and review.
        </p>
      </header>

      {/* Split: list | player — stacks below md, side-by-side at md+ */}
      <div
        className={cn(
          "flex flex-1 min-h-0 flex-col overflow-hidden md:flex-row",
        )}
      >
        {/* Recordings list — narrows when a recording is selected (md+ only) */}
        <div
          className={cn(
            "flex flex-col transition-all duration-200 min-w-0",
            selectedId
              ? "min-h-0 flex-1 border-b border-border md:h-auto md:w-[45%] md:flex-none md:border-b-0 md:border-r"
              : "flex-1",
          )}
        >
          <RecordingsList selectedId={selectedId} onSelect={handleSelect} />
        </div>

        {/* Player panel — only shown when a recording is selected */}
        {selectedId && (
          <div className="min-h-0 flex-1 min-w-0">
            <PlayerPanel sessionId={selectedId} onClose={handleClose} />
          </div>
        )}
      </div>
    </div>
  );
}
