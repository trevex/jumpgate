/**
 * approvals.tsx — Approver inbox.
 *
 * Lists pending access requests the caller is eligible to approve, with
 * per-row enrichment (requester name, asset path, role name) fetched via the
 * request-scoped display reads getUserDisplay / getAssetDisplay / getRoleDisplay.
 * Each pending row also surfaces the decision context — the SSH target address
 * and the capabilities the requested role grants — behind a compact toggle so
 * the request can be judged in place.  Approve fires immediately; Deny opens a
 * small confirm dialog with an optional reason textarea (reason is UI-only —
 * DenyRequestRequest only carries request_id on the wire).
 *
 * Invalidation on success: listPendingApprovals + listMyRequests + listMyGrants,
 * routed through the race-safe useInvalidateList helper (cancel-then-invalidate,
 * scoped to those lists so unrelated catalog queries are untouched).
 */

import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useInfiniteQuery, useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import {
  listPendingApprovals,
  listReviewableGrants,
  approveRequest,
  denyRequest,
  listMyRequests,
  listMyGrants,
} from "@/gen/jumpgate/accessrequest/v1/accessrequest-AccessRequestService_connectquery";
import { getAssetDisplay } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { getRoleDisplay } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import { getUserDisplay } from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import type { AccessRequest, Grant } from "@/gen/jumpgate/accessrequest/v1/accessrequest_pb";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { cn } from "@/lib/utils";
import { relativeTime, connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";
import {
  ClipboardCheck,
  RefreshCw,
  Check,
  X,
  User,
  Server,
  Shield,
  Clock,
  ChevronDown,
  ChevronRight,
  Target,
  KeyRound,
  Film,
} from "lucide-react";

// ─── Short-UUID fallback ──────────────────────────────────────────────────────

function shortId(id: string): string {
  return id.split("-")[0] ?? id;
}

// ─── Per-row enrichment hooks ─────────────────────────────────────────────────

/**
 * Fetches display name for a user id via the universal directory read.
 * Returns displayName or email if available; falls back to short UUID.
 */
function useRequesterDisplay(requesterId: string): string {
  const { data } = useQuery(getUserDisplay, { id: requesterId }, { enabled: Boolean(requesterId) });
  if (!data?.user) return shortId(requesterId);
  const u = data.user;
  return u.displayName || u.email || shortId(requesterId);
}

/**
 * Fetches an asset's decision context via the request-scoped display read.
 * `label` is the DNS-style path (falling back to name/short UUID); `target`
 * is the SSH target address when the asset is SSH (empty otherwise).
 */
function useAssetContext(assetId: string): { label: string; target: string } {
  const { data } = useQuery(getAssetDisplay, { assetId }, { enabled: Boolean(assetId) });
  const asset = data?.asset;
  const label = asset ? asset.path || asset.name || shortId(assetId) : shortId(assetId);
  const target = asset?.config.case === "ssh" ? asset.config.value.targetAddress : "";
  return { label, target };
}

/**
 * Fetches a role's decision context via the request-scoped display read.
 * `label` is "name.folderPath" when folder-scoped (else the bare name);
 * `capabilities` are the capabilities the role grants.
 */
function useRoleContext(roleId: string): { label: string; capabilities: string[] } {
  const { data } = useQuery(getRoleDisplay, { id: roleId }, { enabled: Boolean(roleId) });
  const role = data?.role;
  const label = role
    ? role.folderPath
      ? `${role.name}.${role.folderPath}`
      : role.name
    : shortId(roleId);
  return { label, capabilities: role?.capabilities ?? [] };
}

// ─── Loading skeleton rows ────────────────────────────────────────────────────

function RowSkeleton() {
  return (
    <div className="flex items-start gap-4 px-6 py-4 border-b border-border last:border-0">
      <div className="flex flex-1 flex-col gap-2 min-w-0">
        <div className="flex items-center gap-2">
          <Skeleton className="h-3.5 w-28 rounded" />
          <Skeleton className="h-3.5 w-20 rounded" />
        </div>
        <Skeleton className="h-3 w-48 rounded" />
        <Skeleton className="h-3 w-64 rounded" />
      </div>
      <div className="flex items-center gap-2 shrink-0 pt-0.5">
        <Skeleton className="h-7 w-16 rounded-md" />
        <Skeleton className="h-7 w-12 rounded-md" />
      </div>
    </div>
  );
}

function TableSkeletons() {
  return (
    <div aria-busy="true" aria-label="Loading pending approvals">
      {Array.from({ length: 3 }).map((_, i) => (
        <RowSkeleton key={i} />
      ))}
    </div>
  );
}

// ─── Approvals badge (N/M) ────────────────────────────────────────────────────

function ApprovalProgress({
  approvalsSoFar,
  requiredApprovals,
}: {
  approvalsSoFar: number;
  requiredApprovals: number;
}) {
  if (requiredApprovals <= 0) return null;
  return (
    <Badge
      variant="outline"
      className="rounded border-amber-200 bg-amber-50 px-1.5 py-0 text-eyebrow font-semibold tabular-nums text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300"
      aria-label={`${approvalsSoFar} of ${requiredApprovals} approvals received`}
    >
      {approvalsSoFar}/{requiredApprovals}
    </Badge>
  );
}

// ─── Deny dialog ──────────────────────────────────────────────────────────────

interface DenyDialogProps {
  request: AccessRequest;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDenied: () => void;
}

/**
 * Confirm-only dialog for denying a request. DenyRequestRequest carries only
 * `requestId` on the wire — there is no reason field yet, so we don't collect
 * one (a discarded textarea would mislead the approver). Persisting a denial
 * rationale is a follow-up: add `reason` to DenyRequestRequest + surface it on
 * the requester's ListMyRequests view.
 */
function DenyDialog({ request, open, onOpenChange, onDenied }: DenyDialogProps) {
  const invalidateList = useInvalidateList();

  const requesterDisplay = useRequesterDisplay(request.requesterId);
  const { label: assetDisplay } = useAssetContext(request.assetId);

  const { mutate: doDeny, isPending } = useMutation(denyRequest, {
    onSuccess: () => {
      toast.success("Request denied", {
        description: `Denied ${requesterDisplay}'s request for ${assetDisplay}.`,
      });
      void invalidateList([listPendingApprovals, listMyRequests, listMyGrants]);
      onOpenChange(false);
      onDenied();
    },
    onError: (err) => {
      toast.error("Deny failed", { description: connectErrorMessage(err) });
    },
  });

  function handleDeny() {
    doDeny({ requestId: request.id });
  }

  function handleOpenChange(next: boolean) {
    onOpenChange(next);
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[400px]">
        <DialogHeader>
          <DialogTitle className="text-title">Deny request?</DialogTitle>
          <DialogDescription className="text-body">
            This will immediately deny{" "}
            <span className="font-medium text-foreground">{requesterDisplay}</span>
            's request for{" "}
            <span className="font-mono font-medium text-foreground">{assetDisplay}</span>.
            This action cannot be undone.
          </DialogDescription>
        </DialogHeader>

        <DialogFooter>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleOpenChange(false)}
            disabled={isPending}
            className="h-8 text-body"
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={handleDeny}
            disabled={isPending}
            className="h-8 text-body"
            aria-label="Confirm deny request"
          >
            {isPending ? "Denying…" : "Deny request"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Single request row ───────────────────────────────────────────────────────

interface RequestRowProps {
  req: AccessRequest;
}

function RequestRow({ req }: RequestRowProps) {
  const [denyOpen, setDenyOpen] = useState(false);
  const [contextOpen, setContextOpen] = useState(false);
  const invalidateList = useInvalidateList();

  // Enrichment — three parallel per-row queries (cheap: cached after first fetch)
  const requesterDisplay = useRequesterDisplay(req.requesterId);
  const { label: assetDisplay, target: assetTarget } = useAssetContext(req.assetId);
  const { label: roleDisplay, capabilities } = useRoleContext(req.roleId);

  const hasContext = Boolean(assetTarget) || capabilities.length > 0;

  const { mutate: doApprove, isPending: isApproving } = useMutation(approveRequest, {
    onSuccess: () => {
      toast.success("Request approved", {
        description: `Approved ${requesterDisplay}'s request for ${assetDisplay}.`,
      });
      void invalidateList([listPendingApprovals, listMyRequests, listMyGrants]);
    },
    onError: (err) => {
      toast.error("Approval failed", { description: connectErrorMessage(err) });
    },
  });

  return (
    <>
      <div
        className="group flex items-start gap-4 px-6 py-4 border-b border-border last:border-0 transition-colors hover:bg-muted/30"
        role="listitem"
        aria-label={`Access request from ${requesterDisplay} for ${assetDisplay}`}
      >
        {/* ── Request metadata ── */}
        <div className="flex flex-1 flex-col gap-1.5 min-w-0">

          {/* Row 1: Requester + asset + role */}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            {/* Requester */}
            <span className="flex items-center gap-1 text-body font-medium text-foreground">
              <User className="h-3 w-3 shrink-0 text-muted-foreground" aria-hidden="true" />
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="truncate max-w-[160px] cursor-default">
                    {requesterDisplay}
                  </span>
                </TooltipTrigger>
                <TooltipContent side="top" className="text-xs font-mono">
                  {req.requesterId}
                </TooltipContent>
              </Tooltip>
            </span>

            <span className="text-micro text-muted-foreground" aria-hidden="true">→</span>

            {/* Asset */}
            <span className="flex items-center gap-1 text-compact text-foreground">
              <Server className="h-3 w-3 shrink-0 text-muted-foreground" aria-hidden="true" />
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="font-mono truncate max-w-[180px] cursor-default">
                    {assetDisplay}
                  </span>
                </TooltipTrigger>
                <TooltipContent side="top" className="text-xs font-mono">
                  {req.assetId}
                </TooltipContent>
              </Tooltip>
            </span>

            <span className="text-micro text-muted-foreground" aria-hidden="true">·</span>

            {/* Role */}
            <span className="flex items-center gap-1 text-compact text-muted-foreground">
              <Shield className="h-3 w-3 shrink-0" aria-hidden="true" />
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="truncate max-w-[120px] cursor-default">
                    {roleDisplay}
                  </span>
                </TooltipTrigger>
                <TooltipContent side="top" className="text-xs font-mono">
                  {req.roleId}
                </TooltipContent>
              </Tooltip>
            </span>
          </div>

          {/* Row 2: Reason */}
          {req.reason && (
            <p
              className="text-compact text-muted-foreground line-clamp-2 leading-relaxed"
              title={req.reason}
            >
              "{req.reason}"
            </p>
          )}

          {/* Row 3: Meta — time + approvals + decision-context toggle */}
          <div className="flex items-center gap-3 flex-wrap">
            <span
              className="flex items-center gap-1 text-micro text-muted-foreground whitespace-nowrap"
              title={req.createdAt}
            >
              <Clock className="h-3 w-3 shrink-0" aria-hidden="true" />
              {relativeTime(req.createdAt)}
            </span>

            {req.requiredApprovals > 0 && (
              <ApprovalProgress
                approvalsSoFar={req.approvalsSoFar}
                requiredApprovals={req.requiredApprovals}
              />
            )}

            {hasContext && (
              <button
                type="button"
                onClick={() => setContextOpen((o) => !o)}
                aria-expanded={contextOpen}
                aria-label={
                  contextOpen
                    ? "Hide decision context"
                    : "Show decision context"
                }
                className="flex items-center gap-0.5 rounded text-micro font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1"
              >
                {contextOpen ? (
                  <ChevronDown className="h-3 w-3 shrink-0" aria-hidden="true" />
                ) : (
                  <ChevronRight className="h-3 w-3 shrink-0" aria-hidden="true" />
                )}
                Context
              </button>
            )}
          </div>

          {/* Row 4: Decision context — SSH target + granted capabilities */}
          {hasContext && contextOpen && (
            <div className="mt-1 flex flex-col gap-2 rounded-md border border-border bg-muted/30 px-3 py-2.5">
              {assetTarget && (
                <div className="flex items-center gap-1.5 min-w-0">
                  <Target
                    className="h-3 w-3 shrink-0 text-muted-foreground"
                    aria-hidden="true"
                  />
                  <span className="text-eyebrow font-semibold uppercase tracking-wide text-muted-foreground shrink-0">
                    Target
                  </span>
                  <code className="truncate font-mono text-micro text-foreground" title={assetTarget}>
                    {assetTarget}
                  </code>
                </div>
              )}

              {capabilities.length > 0 && (
                <div className="flex flex-col gap-1">
                  <span className="flex items-center gap-1.5 text-eyebrow font-semibold uppercase tracking-wide text-muted-foreground">
                    <KeyRound className="h-3 w-3 shrink-0" aria-hidden="true" />
                    Grants {capabilities.length} capabilit{capabilities.length === 1 ? "y" : "ies"}
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {capabilities.map((cap) => (
                      <Badge
                        key={cap}
                        variant="outline"
                        className="rounded border-border bg-background px-1.5 py-0 font-mono text-eyebrow font-normal text-foreground"
                      >
                        {cap}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── Actions ── */}
        <div className="flex items-center gap-2 shrink-0 pt-0.5">
          {/* Approve */}
          <Button
            size="sm"
            onClick={() => doApprove({ requestId: req.id })}
            disabled={isApproving}
            aria-label={`Approve ${requesterDisplay}'s request`}
            className="h-7 gap-1 px-3 text-compact bg-green-600 text-white hover:bg-green-700 focus-visible:ring-green-600"
          >
            {isApproving ? (
              <span className="flex items-center gap-1">
                <RefreshCw className="h-3 w-3 animate-spin" aria-hidden="true" />
                Approving…
              </span>
            ) : (
              <span className="flex items-center gap-1">
                <Check className="h-3 w-3" aria-hidden="true" />
                Approve
              </span>
            )}
          </Button>

          {/* Deny */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setDenyOpen(true)}
            disabled={isApproving}
            aria-label={`Deny ${requesterDisplay}'s request`}
            className="h-7 gap-1 px-3 text-compact border-red-200 text-red-600 hover:bg-red-50 hover:text-red-700 hover:border-red-300 dark:border-red-500/30 dark:text-red-400 dark:hover:bg-red-500/10 dark:hover:text-red-300 dark:hover:border-red-500/50"
          >
            <X className="h-3 w-3" aria-hidden="true" />
            Deny
          </Button>
        </div>
      </div>

      {/* Deny confirmation dialog */}
      <DenyDialog
        request={req}
        open={denyOpen}
        onOpenChange={setDenyOpen}
        onDenied={() => setDenyOpen(false)}
      />
    </>
  );
}

// ─── Table header ─────────────────────────────────────────────────────────────

function TableHeader() {
  return (
    <div
      className="grid grid-cols-[1fr_auto] gap-x-4 border-b border-border bg-muted/30 px-6 py-2.5"
      aria-hidden="true"
    >
      <span className="text-eyebrow font-semibold uppercase tracking-widest text-muted-foreground">
        Requester · Asset · Role · Reason
      </span>
      <span className="text-eyebrow font-semibold uppercase tracking-widest text-muted-foreground text-right">
        Actions
      </span>
    </div>
  );
}

// ─── Pending tab ──────────────────────────────────────────────────────────────

/**
 * The pending-approvals list: requests the caller is eligible to approve,
 * each with a decision (approve/deny) and per-row enrichment. `onCount`
 * lifts the pending count so the tab trigger can badge it.
 */
function PendingTab({ onCount }: { onCount?: (n: number) => void }) {
  const { data, isLoading, isError, error, refetch } = useQuery(
    listPendingApprovals,
    { pageSize: 100 },
  );

  const requests = data?.requests ?? [];

  const ready = !isLoading && !isError;
  useEffect(() => {
    if (ready) onCount?.(requests.length);
  }, [ready, requests.length, onCount]);

  if (isLoading) return <TableSkeletons />;

  if (isError) {
    return (
      <ErrorState
        message={connectErrorMessage(error)}
        onRetry={() => void refetch()}
      />
    );
  }

  if (requests.length === 0) {
    return (
      <EmptyState
        icon={ClipboardCheck}
        size="lg"
        title="All clear"
        message="Nothing awaiting your approval."
      />
    );
  }

  return (
    <div role="list" aria-label="Pending approval requests">
      <TableHeader />
      {requests.map((req) => (
        <RequestRow key={req.id} req={req} />
      ))}
    </div>
  );
}

// ─── Reviewable tab ───────────────────────────────────────────────────────────

/**
 * One reviewable-grant row — a grant whose originating request the caller was
 * eligible to approve. Surfaces the subject, asset, role and grant time, plus a
 * jump to the grant-scoped session recordings (server enforces the real authz).
 */
function ReviewableRow({ grant }: { grant: Grant }) {
  const navigate = useNavigate();
  const subjectDisplay = useRequesterDisplay(grant.subjectUserId);
  const assetLabel = grant.assetPath || shortId(grant.assetId);

  return (
    <div
      className="group flex items-center gap-4 px-6 py-4 border-b border-border last:border-0 transition-colors hover:bg-muted/30"
      role="listitem"
      aria-label={`Grant for ${subjectDisplay} on ${assetLabel}`}
    >
      <div className="flex flex-1 flex-col gap-1.5 min-w-0">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          {/* Subject */}
          <span className="flex items-center gap-1 text-body font-medium text-foreground">
            <User className="h-3 w-3 shrink-0 text-muted-foreground" aria-hidden="true" />
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="truncate max-w-[160px] cursor-default">{subjectDisplay}</span>
              </TooltipTrigger>
              <TooltipContent side="top" className="text-xs font-mono">
                {grant.subjectUserId}
              </TooltipContent>
            </Tooltip>
          </span>

          <span className="text-micro text-muted-foreground" aria-hidden="true">→</span>

          {/* Asset */}
          <span className="flex items-center gap-1 text-compact text-foreground">
            <Server className="h-3 w-3 shrink-0 text-muted-foreground" aria-hidden="true" />
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="font-mono truncate max-w-[180px] cursor-default">{assetLabel}</span>
              </TooltipTrigger>
              <TooltipContent side="top" className="text-xs font-mono">
                {grant.assetId}
              </TooltipContent>
            </Tooltip>
          </span>

          <span className="text-micro text-muted-foreground" aria-hidden="true">·</span>

          {/* Role */}
          <span className="flex items-center gap-1 text-compact text-muted-foreground">
            <Shield className="h-3 w-3 shrink-0" aria-hidden="true" />
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="truncate max-w-[120px] cursor-default font-mono">
                  {shortId(grant.roleId)}
                </span>
              </TooltipTrigger>
              <TooltipContent side="top" className="text-xs font-mono">
                {grant.roleId}
              </TooltipContent>
            </Tooltip>
          </span>
        </div>

        {/* Meta — granted time */}
        <span
          className="flex items-center gap-1 text-micro text-muted-foreground whitespace-nowrap"
          title={grant.grantedAt}
        >
          <Clock className="h-3 w-3 shrink-0" aria-hidden="true" />
          {relativeTime(grant.grantedAt)}
        </span>
      </div>

      {/* Action — jump to grant-scoped recordings */}
      <div className="flex items-center gap-2 shrink-0">
        <Button
          variant="outline"
          size="sm"
          onClick={() => navigate(`/recordings?grantId=${grant.id}`)}
          className="h-7 gap-1.5 px-3 text-compact"
          aria-label={`View session recordings for ${subjectDisplay}'s grant`}
        >
          <Film className="h-3.5 w-3.5" aria-hidden="true" />
          Session recordings
        </Button>
      </div>
    </div>
  );
}

/**
 * The reviewable-grants list — grants whose originating request the caller was
 * eligible to approve (oversight). The RPC self-scopes, so an empty list is the
 * normal state for a caller with no approval reach.
 */
function ReviewableTab() {
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
    listReviewableGrants,
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
        message={connectErrorMessage(error)}
        onRetry={() => void refetch()}
      />
    );
  }

  if (grants.length === 0) {
    return (
      <EmptyState
        icon={Film}
        size="lg"
        title="Nothing to review"
        message="Grants you were eligible to approve will appear here."
      />
    );
  }

  return (
    <div className="flex flex-col">
      <div role="list" aria-label="Reviewable grants">
        {grants.map((g) => (
          <ReviewableRow key={g.id} grant={g} />
        ))}
      </div>

      {hasNextPage && (
        <div className="flex justify-center py-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
            className="h-7 text-compact"
          >
            {isFetchingNextPage ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Approvals page ───────────────────────────────────────────────────────────

const TAB_TRIGGER = cn(
  "relative h-8 rounded-none border-b-2 border-transparent bg-transparent px-4 pb-2 pt-0 text-body font-medium text-muted-foreground shadow-none transition-colors",
  "data-[state=active]:border-primary data-[state=active]:text-foreground data-[state=active]:shadow-none",
);

export function ApprovalsPage() {
  const [pendingCount, setPendingCount] = useState(0);

  return (
    <div className="flex flex-col h-full">
      {/* Page header */}
      <header className="border-b border-border px-6 py-5">
        <h1 className="text-title font-semibold text-foreground">Approvals</h1>
        <p className="mt-0.5 text-compact text-muted-foreground">
          Requests awaiting your decision, and grants you may review.
        </p>
      </header>

      {/* Tabs */}
      <Tabs defaultValue="pending" className="flex flex-1 flex-col overflow-hidden">
        <div className="border-b border-border px-6 pt-4">
          <TabsList className="h-8 gap-0 rounded-none border-b-0 bg-transparent p-0">
            <TabsTrigger value="pending" className={TAB_TRIGGER}>
              <span className="flex items-center gap-1.5">
                Pending
                {pendingCount > 0 && (
                  <Badge
                    variant="default"
                    className="h-4 min-w-4 rounded-full px-1 text-eyebrow font-semibold tabular-nums"
                    aria-label={`${pendingCount} pending approval${pendingCount !== 1 ? "s" : ""}`}
                  >
                    {pendingCount > 99 ? "99+" : pendingCount}
                  </Badge>
                )}
              </span>
            </TabsTrigger>
            <TabsTrigger value="reviewable" className={TAB_TRIGGER}>
              Reviewable
            </TabsTrigger>
          </TabsList>
        </div>

        <TabsContent
          value="pending"
          className="mt-0 flex-1 overflow-y-auto data-[state=inactive]:hidden"
        >
          <PendingTab onCount={setPendingCount} />
        </TabsContent>

        <TabsContent
          value="reviewable"
          className="mt-0 flex-1 overflow-y-auto data-[state=inactive]:hidden"
        >
          <ReviewableTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
