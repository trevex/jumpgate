/**
 * approvals.tsx — Approver inbox.
 *
 * Lists pending access requests the caller is eligible to approve, with
 * per-row enrichment (requester email, asset path, role name) fetched via
 * getUser / getAsset / getRole.  Approve fires immediately; Deny opens a
 * small confirm dialog with an optional reason textarea (reason is UI-only —
 * DenyRequestRequest only carries request_id on the wire).
 *
 * Invalidation on success: listPendingApprovals + listMyRequests + listMyGrants
 * (scoped via createConnectQueryKey so unrelated catalog queries are untouched).
 */

import { useState } from "react";
import { useQuery, useMutation } from "@connectrpc/connect-query";
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  listPendingApprovals,
  approveRequest,
  denyRequest,
  listMyRequests,
  listMyGrants,
} from "@/gen/jumpgate/accessrequest/v1/accessrequest-AccessRequestService_connectquery";
import { getAsset } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { getRole } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import { getUser } from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import type { AccessRequest } from "@/gen/jumpgate/accessrequest/v1/accessrequest_pb";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { relativeTime, connectErrorMessage } from "@/lib/format";
import {
  ClipboardCheck,
  RefreshCw,
  Check,
  X,
  User,
  Server,
  Shield,
  Clock,
} from "lucide-react";

// ─── Short-UUID fallback ──────────────────────────────────────────────────────

function shortId(id: string): string {
  return id.split("-")[0] ?? id;
}

// ─── Per-row enrichment hooks ─────────────────────────────────────────────────

/**
 * Fetches display name for a user id.
 * Returns email or displayName if available; falls back to short UUID.
 */
function useRequesterDisplay(requesterId: string): string {
  const { data } = useQuery(getUser, { id: requesterId }, { enabled: Boolean(requesterId) });
  if (!data?.user) return shortId(requesterId);
  const u = data.user;
  return u.displayName || u.email || shortId(requesterId);
}

/**
 * Fetches asset path/name for an asset id.
 * Returns DNS-style path if available; falls back to short UUID.
 */
function useAssetDisplay(assetId: string): string {
  const { data } = useQuery(getAsset, { assetId }, { enabled: Boolean(assetId) });
  if (!data?.asset) return shortId(assetId);
  const a = data.asset;
  return a.path || a.name || shortId(assetId);
}

/**
 * Fetches role name for a role id.
 * Returns "name.folder" if folder-scoped; otherwise just the name.
 */
function useRoleDisplay(roleId: string): string {
  const { data } = useQuery(getRole, { id: roleId }, { enabled: Boolean(roleId) });
  if (!data?.role) return shortId(roleId);
  const r = data.role;
  return r.folderPath ? `${r.name}.${r.folderPath}` : r.name;
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
      className="rounded border-amber-200 bg-amber-50 px-1.5 py-0 text-[10px] font-semibold tabular-nums text-amber-700"
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
  const queryClient = useQueryClient();

  const requesterDisplay = useRequesterDisplay(request.requesterId);
  const assetDisplay = useAssetDisplay(request.assetId);

  const { mutate: doDeny, isPending } = useMutation(denyRequest, {
    onSuccess: () => {
      toast.success("Request denied", {
        description: `Denied ${requesterDisplay}'s request for ${assetDisplay}.`,
      });
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({ schema: listPendingApprovals, cardinality: undefined }),
      });
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({ schema: listMyRequests, cardinality: undefined }),
      });
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({ schema: listMyGrants, cardinality: undefined }),
      });
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
          <DialogTitle className="text-[15px]">Deny request?</DialogTitle>
          <DialogDescription className="text-[13px]">
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
            className="h-8 text-[13px]"
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={handleDeny}
            disabled={isPending}
            className="h-8 text-[13px]"
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
  const queryClient = useQueryClient();

  // Enrichment — three parallel per-row queries (cheap: cached after first fetch)
  const requesterDisplay = useRequesterDisplay(req.requesterId);
  const assetDisplay = useAssetDisplay(req.assetId);
  const roleDisplay = useRoleDisplay(req.roleId);

  const { mutate: doApprove, isPending: isApproving } = useMutation(approveRequest, {
    onSuccess: () => {
      toast.success("Request approved", {
        description: `Approved ${requesterDisplay}'s request for ${assetDisplay}.`,
      });
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({ schema: listPendingApprovals, cardinality: undefined }),
      });
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({ schema: listMyRequests, cardinality: undefined }),
      });
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({ schema: listMyGrants, cardinality: undefined }),
      });
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
            <span className="flex items-center gap-1 text-[13px] font-medium text-foreground">
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

            <span className="text-[11px] text-muted-foreground" aria-hidden="true">→</span>

            {/* Asset */}
            <span className="flex items-center gap-1 text-[12px] text-foreground">
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

            <span className="text-[11px] text-muted-foreground" aria-hidden="true">·</span>

            {/* Role */}
            <span className="flex items-center gap-1 text-[12px] text-muted-foreground">
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
              className="text-[12px] text-muted-foreground line-clamp-2 leading-relaxed"
              title={req.reason}
            >
              "{req.reason}"
            </p>
          )}

          {/* Row 3: Meta — time + approvals */}
          <div className="flex items-center gap-3 flex-wrap">
            <span
              className="flex items-center gap-1 text-[11px] text-muted-foreground whitespace-nowrap"
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
          </div>
        </div>

        {/* ── Actions ── */}
        <div className="flex items-center gap-2 shrink-0 pt-0.5">
          {/* Approve */}
          <Button
            size="sm"
            onClick={() => doApprove({ requestId: req.id })}
            disabled={isApproving}
            aria-label={`Approve ${requesterDisplay}'s request`}
            className="h-7 gap-1 px-3 text-[12px] bg-green-600 text-white hover:bg-green-700 focus-visible:ring-green-600"
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
            className="h-7 gap-1 px-3 text-[12px] border-red-200 text-red-600 hover:bg-red-50 hover:text-red-700 hover:border-red-300"
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

// ─── Empty state ──────────────────────────────────────────────────────────────

function EmptyInbox() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-20 text-center">
      <ClipboardCheck
        className="h-12 w-12 text-muted-foreground/25"
        aria-hidden="true"
      />
      <p className="text-[14px] font-medium text-foreground">All clear</p>
      <p className="text-[13px] text-muted-foreground max-w-xs">
        Nothing awaiting your approval.
      </p>
    </div>
  );
}

// ─── Error state ──────────────────────────────────────────────────────────────

function InboxError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center">
      <p className="text-[13px] text-muted-foreground max-w-sm">{message}</p>
      <Button
        variant="outline"
        size="sm"
        onClick={onRetry}
        className="h-7 gap-1.5 text-[12px]"
      >
        <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
        Retry
      </Button>
    </div>
  );
}

// ─── Table header ─────────────────────────────────────────────────────────────

function TableHeader() {
  return (
    <div
      className="grid grid-cols-[1fr_auto] gap-x-4 border-b border-border bg-muted/30 px-6 py-2.5"
      aria-hidden="true"
    >
      <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        Requester · Asset · Role · Reason
      </span>
      <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground text-right">
        Actions
      </span>
    </div>
  );
}

// ─── Approvals page ───────────────────────────────────────────────────────────

export function ApprovalsPage() {
  const { data, isLoading, isError, error, refetch } = useQuery(
    listPendingApprovals,
    { pageSize: 100 },
  );

  const requests = data?.requests ?? [];

  return (
    <div className="flex flex-col h-full">
      {/* Page header */}
      <header className="border-b border-border px-6 py-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-[15px] font-semibold text-foreground">Approvals</h1>
            <p className="mt-0.5 text-[12px] text-muted-foreground">
              Pending access requests awaiting your decision.
            </p>
          </div>

          {/* Pending count badge */}
          {!isLoading && !isError && requests.length > 0 && (
            <Badge
              variant="default"
              className="h-6 min-w-6 rounded-full px-2 text-[11px] font-semibold"
              aria-label={`${requests.length} pending approval${requests.length !== 1 ? "s" : ""}`}
            >
              {requests.length > 99 ? "99+" : requests.length}
            </Badge>
          )}
        </div>
      </header>

      {/* Content area */}
      <div className="flex-1 overflow-y-auto">
        {isLoading ? (
          <TableSkeletons />
        ) : isError ? (
          <InboxError
            message={connectErrorMessage(error)}
            onRetry={() => void refetch()}
          />
        ) : requests.length === 0 ? (
          <EmptyInbox />
        ) : (
          <div role="list" aria-label="Pending approval requests">
            <TableHeader />
            {requests.map((req) => (
              <RequestRow key={req.id} req={req} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
