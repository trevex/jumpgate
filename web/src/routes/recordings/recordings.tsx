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
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@connectrpc/connect-query";
import { create as createPlayer } from "asciinema-player";
import "asciinema-player/dist/bundle/asciinema-player.css";
import type { Player } from "asciinema-player";
import {
  listRecordings,
  getRecording,
} from "@/gen/jumpgate/recording/v1/recording-RecordingService_connectquery";
import { getAsset } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { getUser } from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import type { Recording } from "@/gen/jumpgate/recording/v1/recording_pb";
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
import { cn } from "@/lib/utils";
import { connectErrorMessage } from "@/lib/format";
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

function shortId(id: string): string {
  return id.split("-")[0] ?? id;
}

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
  const diffMs = Number(unixMs) - Date.now();
  const absMs = Math.abs(diffMs);
  const past = diffMs < 0;
  if (absMs < 60_000) return "just now";
  let value: number;
  let unit: string;
  if (absMs < 3_600_000) {
    value = Math.floor(absMs / 60_000);
    unit = value === 1 ? "minute" : "minutes";
  } else if (absMs < 86_400_000) {
    value = Math.floor(absMs / 3_600_000);
    unit = value === 1 ? "hour" : "hours";
  } else {
    value = Math.floor(absMs / 86_400_000);
    unit = value === 1 ? "day" : "days";
  }
  return past ? `${value} ${unit} ago` : `in ${value} ${unit}`;
}

// ─── Recording status badge ───────────────────────────────────────────────────

const STATUS_STYLES: Record<string, string> = {
  completed: "border-green-200 bg-green-50 text-green-700",
  recording: "border-blue-200 bg-blue-50 text-blue-700",
  failed:    "border-red-200 bg-red-50 text-red-700",
};

function StatusBadge({ status }: { status: string }) {
  const style = STATUS_STYLES[status] ?? "border-muted bg-muted/50 text-muted-foreground";
  return (
    <Badge
      variant="outline"
      className={cn("rounded px-1.5 py-0 text-[10px] font-semibold capitalize tabular-nums", style)}
    >
      {status}
    </Badge>
  );
}

// ─── Per-row enrichment hooks ─────────────────────────────────────────────────

function useAssetDisplay(assetId: string): string {
  const { data } = useQuery(getAsset, { assetId }, { enabled: Boolean(assetId) });
  if (!data?.asset) return shortId(assetId);
  return data.asset.path || data.asset.name || shortId(assetId);
}

function useUserDisplay(userId: string): string {
  const { data } = useQuery(getUser, { id: userId }, { enabled: Boolean(userId) });
  if (!data?.user) return shortId(userId);
  return data.user.email || shortId(userId);
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
        <span className="flex items-center gap-1.5 font-mono text-[12px] text-foreground">
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
        <span className="flex items-center gap-1.5 text-[12px] text-muted-foreground">
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
          className="flex items-center gap-1 text-[12px] text-muted-foreground whitespace-nowrap"
          title={rec.startedAtUnixMs ? new Date(Number(rec.startedAtUnixMs)).toISOString() : ""}
        >
          <Clock className="h-3 w-3 shrink-0" aria-hidden="true" />
          {rec.startedAtUnixMs ? relativeTimeMs(rec.startedAtUnixMs) : "—"}
        </span>
      </TableCell>

      {/* Duration */}
      <TableCell className="py-2.5 tabular-nums text-[12px] text-muted-foreground">
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

// ─── Empty / error states ─────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-20 text-center">
      <Film className="h-12 w-12 text-muted-foreground/20" aria-hidden="true" />
      <p className="text-[14px] font-medium text-foreground">No recordings yet</p>
      <p className="text-[12px] text-muted-foreground max-w-xs">
        Session recordings will appear here once SSH sessions have been recorded.
      </p>
    </div>
  );
}

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center">
      <AlertTriangle className="h-8 w-8 text-destructive/60" aria-hidden="true" />
      <p className="text-[13px] text-muted-foreground max-w-sm">{message}</p>
      <Button variant="outline" size="sm" onClick={onRetry} className="h-7 gap-1.5 text-[12px]">
        <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
        Retry
      </Button>
    </div>
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
    if (!containerRef.current) return;
    setPlayerError(null);

    // Dispose previous instance before creating a new one.
    if (playerRef.current) {
      playerRef.current.dispose();
      playerRef.current = null;
    }

    // Clear the container so asciinema-player gets a fresh mount.
    containerRef.current.innerHTML = "";

    const src = `/api/recordings/${sessionId}/cast`;

    try {
      const p = createPlayer(
        { url: src, fetchOpts: { credentials: "include" } },
        containerRef.current,
        {
          autoPlay: true,
          fit: "width",
          theme: "monokai",
          terminalFontFamily: "'JetBrains Mono', 'Fira Mono', monospace",
          terminalFontSize: "small",
          controls: true,
        },
      );
      playerRef.current = p;

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
      if (playerRef.current) {
        playerRef.current.dispose();
        playerRef.current = null;
      }
    };
  // Re-mount only when the sessionId changes.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  return (
    <div className="flex flex-col h-full bg-[#1a1a1a] border-l border-border">
      {/* Panel header */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-white/10 shrink-0">
        <Terminal className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
        <span className="flex-1 min-w-0 text-[12px] font-medium text-white/80 truncate font-mono">
          {assetDisplay || shortId(sessionId)}
        </span>
        <span className="text-[10px] text-white/40 font-mono shrink-0">{shortId(sessionId)}</span>
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

      {/* Player area */}
      <div className="flex-1 overflow-hidden flex items-center justify-center p-4">
        {playerError ? (
          <div className="flex flex-col items-center gap-3 text-center">
            <AlertTriangle className="h-8 w-8 text-amber-400/80" aria-hidden="true" />
            <p className="text-[13px] text-white/60 max-w-xs">{playerError}</p>
          </div>
        ) : (
          <div
            ref={containerRef}
            className="w-full max-w-full"
            aria-label={`Terminal recording player for session ${sessionId}`}
          />
        )}
      </div>
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
  const [pageToken, setPageToken] = useState("");
  const [allRecordings, setAllRecordings] = useState<Recording[]>([]);
  const [nextToken, setNextToken] = useState<string | null>(null);
  const [isLoadingMore, setIsLoadingMore] = useState(false);

  const { data, isLoading, isError, error, refetch } = useQuery(listRecordings, {
    pageSize: PAGE_SIZE,
    pageToken,
  });

  // Accumulate pages.
  useEffect(() => {
    if (!data) return;
    if (pageToken === "") {
      // First page: replace.
      setAllRecordings(data.recordings ?? []);
    } else {
      // Subsequent page: append.
      setAllRecordings((prev) => [...prev, ...(data.recordings ?? [])]);
      setIsLoadingMore(false);
    }
    setNextToken(data.nextPageToken || null);
  }, [data, pageToken]);

  const handleLoadMore = useCallback(() => {
    if (nextToken) {
      setIsLoadingMore(true);
      setPageToken(nextToken);
    }
  }, [nextToken]);

  // Show initial loading skeletons only on first fetch.
  const isInitialLoading = isLoading && pageToken === "" && allRecordings.length === 0;

  return (
    <div className="flex flex-col h-full">
      {/* Section header */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-border shrink-0">
        <div className="flex items-center gap-2">
          <Film className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <span className="text-[13px] font-medium text-foreground">
            {allRecordings.length > 0 ? `${allRecordings.length} recording${allRecordings.length !== 1 ? "s" : ""}` : "Recordings"}
          </span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => { setPageToken(""); void refetch(); }}
          className="h-7 gap-1 text-[12px] text-muted-foreground"
          aria-label="Refresh recordings list"
        >
          <RefreshCw className="h-3 w-3" aria-hidden="true" />
        </Button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {isInitialLoading ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-[10px] uppercase tracking-wider py-2 h-9">Asset</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider py-2 h-9">User</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider py-2 h-9">Status</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider py-2 h-9">Started</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider py-2 h-9">Duration</TableHead>
                <TableHead className="w-6" />
              </TableRow>
            </TableHeader>
            <TableBody aria-busy="true" aria-label="Loading recordings">
              {Array.from({ length: 5 }).map((_, i) => <RowSkeleton key={i} />)}
            </TableBody>
          </Table>
        ) : isError ? (
          <ErrorState message={connectErrorMessage(error)} onRetry={() => void refetch()} />
        ) : allRecordings.length === 0 ? (
          <EmptyState />
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase tracking-wider py-2 h-9 text-muted-foreground font-semibold">Asset</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider py-2 h-9 text-muted-foreground font-semibold">User</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider py-2 h-9 text-muted-foreground font-semibold">Status</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider py-2 h-9 text-muted-foreground font-semibold">Started</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider py-2 h-9 text-muted-foreground font-semibold">Duration</TableHead>
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
            {nextToken && (
              <div className="flex justify-center py-4 border-t border-border">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleLoadMore}
                  disabled={isLoadingMore}
                  className="h-7 gap-1.5 text-[12px]"
                >
                  {isLoadingMore ? (
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

  const selectedId = sessionId ?? null;

  const handleSelect = useCallback((id: string) => {
    navigate(`/recordings/${id}`, { replace: true });
  }, [navigate]);

  const handleClose = useCallback(() => {
    navigate("/recordings", { replace: true });
  }, [navigate]);

  return (
    <div className="flex flex-col h-full">
      {/* Page header */}
      <header className="border-b border-border px-6 py-5 shrink-0">
        <h1 className="text-[15px] font-semibold text-foreground">Recordings</h1>
        <p className="mt-0.5 text-[12px] text-muted-foreground">
          SSH session recordings for audit and review.
        </p>
      </header>

      {/* Split: list | player */}
      <div
        className={cn(
          "flex flex-1 min-h-0 overflow-hidden",
        )}
      >
        {/* Recordings list — narrows when a recording is selected */}
        <div
          className={cn(
            "flex flex-col transition-all duration-200 min-w-0",
            selectedId ? "w-[45%] border-r border-border" : "flex-1",
          )}
        >
          <RecordingsList selectedId={selectedId} onSelect={handleSelect} />
        </div>

        {/* Player panel — only shown when a recording is selected */}
        {selectedId && (
          <div className="flex-1 min-w-0">
            <PlayerPanel sessionId={selectedId} onClose={handleClose} />
          </div>
        )}
      </div>
    </div>
  );
}
