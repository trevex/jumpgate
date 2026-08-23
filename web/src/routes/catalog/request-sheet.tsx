/**
 * request-sheet.tsx — JIT access request slide-over.
 *
 * Props: the target asset, the roles the caller can request, and
 * sheet open/close control.  Builds a RequestAccessRequest and calls
 * RequestAccess on submit, then toasts and closes.
 *
 * duration_seconds: int64 on the wire (bigint in TS) — we convert the
 * user's chip/custom selection to seconds before sending.
 */

import { useState, useCallback } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import type { RoleRef } from "@/gen/jumpgate/catalog/v1/catalog_pb";
import {
  requestAccess,
  listMyRequests,
  listMyGrants,
  listPendingApprovals,
} from "@/gen/jumpgate/accessrequest/v1/accessrequest-AccessRequestService_connectquery";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
} from "@/components/ui/sheet";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";
import { Server, Clock } from "lucide-react";

// ─── Duration presets ────────────────────────────────────────────────────────

interface DurationPreset {
  label: string;
  seconds: number;
}

const DURATION_PRESETS: DurationPreset[] = [
  { label: "1h", seconds: 3_600 },
  { label: "4h", seconds: 14_400 },
  { label: "8h", seconds: 28_800 },
  { label: "24h", seconds: 86_400 },
];

// ─── Duration chip group ──────────────────────────────────────────────────────

interface DurationChipsProps {
  value: number | null;
  onChange: (seconds: number | null) => void;
  customSeconds: string;
  onCustomChange: (v: string) => void;
}

function DurationChips({
  value,
  onChange,
  customSeconds,
  onCustomChange,
}: DurationChipsProps) {
  const [showCustom, setShowCustom] = useState(false);

  function selectPreset(seconds: number) {
    setShowCustom(false);
    onCustomChange("");
    onChange(seconds);
  }

  function toggleCustom() {
    const next = !showCustom;
    setShowCustom(next);
    if (next) {
      onChange(null);
    } else {
      onCustomChange("");
    }
  }

  // Parse custom hours into seconds when the input changes
  function handleCustomInput(raw: string) {
    onCustomChange(raw);
    const hours = parseFloat(raw);
    if (!isNaN(hours) && hours > 0) {
      onChange(Math.round(hours * 3600));
    } else {
      onChange(null);
    }
  }

  return (
    <div className="flex flex-col gap-2">
      <div
        className="flex flex-wrap gap-1.5"
        role="group"
        aria-label="Duration presets"
      >
        {DURATION_PRESETS.map((p) => {
          const active = !showCustom && value === p.seconds;
          return (
            <button
              key={p.label}
              type="button"
              onClick={() => selectPreset(p.seconds)}
              aria-pressed={active}
              className={cn(
                "rounded-md border px-3 py-1.5 text-compact font-medium transition-colors duration-100",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                active
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border bg-background text-muted-foreground hover:border-primary/40 hover:text-foreground",
              )}
            >
              {p.label}
            </button>
          );
        })}
        <button
          type="button"
          onClick={toggleCustom}
          aria-pressed={showCustom}
          className={cn(
            "rounded-md border px-3 py-1.5 text-compact font-medium transition-colors duration-100",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
            showCustom
              ? "border-primary bg-primary/10 text-primary"
              : "border-border bg-background text-muted-foreground hover:border-primary/40 hover:text-foreground",
          )}
        >
          Custom
        </button>
      </div>

      {showCustom && (
        <div className="flex items-center gap-2">
          <input
            type="number"
            min="0.25"
            step="0.25"
            placeholder="Hours (e.g. 2.5)"
            value={customSeconds}
            onChange={(e) => handleCustomInput(e.target.value)}
            aria-label="Custom duration in hours"
            className={cn(
              "h-9 w-36 rounded-md border border-input bg-background px-3 text-sm",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
              "placeholder:text-muted-foreground",
            )}
          />
          <span className="text-compact text-muted-foreground">hours</span>
        </div>
      )}
    </div>
  );
}

// ─── Field label ──────────────────────────────────────────────────────────────

function FieldLabel({
  htmlFor,
  children,
  required,
}: {
  htmlFor?: string;
  children: React.ReactNode;
  required?: boolean;
}) {
  return (
    <label
      htmlFor={htmlFor}
      className="block text-micro font-semibold uppercase tracking-widest text-muted-foreground"
    >
      {children}
      {required && (
        <span className="ml-1 text-destructive" aria-hidden="true">
          *
        </span>
      )}
    </label>
  );
}

// ─── Request sheet ────────────────────────────────────────────────────────────

export interface RequestSheetProps {
  asset: { id: string; path?: string; name: string };
  requestableRoles: RoleRef[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function RequestSheet({
  asset,
  requestableRoles,
  open,
  onOpenChange,
}: RequestSheetProps) {
  const invalidate = useInvalidateList();

  // ── Form state
  const [roleId, setRoleId] = useState<string>("");
  const [durationSeconds, setDurationSeconds] = useState<number | null>(
    DURATION_PRESETS[0].seconds,
  );
  const [customHours, setCustomHours] = useState("");
  const [reason, setReason] = useState("");

  // ── Reset on open/close
  const handleOpenChange = useCallback(
    (next: boolean) => {
      if (!next) {
        setRoleId("");
        setDurationSeconds(DURATION_PRESETS[0].seconds);
        setCustomHours("");
        setReason("");
      }
      onOpenChange(next);
    },
    [onOpenChange],
  );

  // ── Mutation
  const { mutate, isPending } = useMutation(requestAccess, {
    onSuccess: () => {
      toast.success("Access requested", {
        description: "Your request has been submitted.",
      });
      // Scope invalidation to the access-request queries only — avoid
      // flushing catalog/vault queries which are unaffected by a new request.
      void invalidate([listMyRequests, listMyGrants, listPendingApprovals]);
      handleOpenChange(false);
    },
    onError: (err) => {
      toast.error("Request failed", { description: connectErrorMessage(err) });
    },
  });

  // ── Validation
  const canSubmit =
    roleId !== "" &&
    durationSeconds !== null &&
    durationSeconds > 0 &&
    reason.trim().length > 0 &&
    !isPending;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    mutate({
      roleId,
      assetId: asset.id,
      durationSeconds: BigInt(durationSeconds!),
      reason: reason.trim(),
    });
  }

  const selectedRole = requestableRoles.find((r) => r.id === roleId);

  return (
    <Sheet open={open} onOpenChange={handleOpenChange}>
      <SheetContent
        side="right"
        className="flex w-full flex-col gap-0 p-0 sm:max-w-[440px]"
        aria-label="Request access"
      >
        <SheetHeader className="border-b border-border px-6 py-5">
          <SheetTitle className="text-title">Request access</SheetTitle>
          <SheetDescription className="flex items-center gap-1.5 text-compact">
            <Server className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span className="font-mono">{asset.path ?? asset.name}</span>
          </SheetDescription>
        </SheetHeader>

        <form
          id="request-access-form"
          onSubmit={handleSubmit}
          className="flex flex-1 flex-col gap-5 overflow-y-auto px-6 py-6"
        >
          {/* ── Role ── */}
          <div className="flex flex-col gap-2">
            <FieldLabel required>Role</FieldLabel>
            <Select
              value={roleId}
              onValueChange={setRoleId}
              required
            >
              <SelectTrigger
                id="role-select"
                aria-label="Select a role to request"
                className="h-9 text-sm"
              >
                <SelectValue placeholder="Select a role…" />
              </SelectTrigger>
              <SelectContent>
                {requestableRoles.map((r) => {
                  const label = r.folderPath
                    ? `${r.name}.${r.folderPath}`
                    : r.name;
                  return (
                    <SelectItem key={r.id} value={r.id}>
                      {label}
                    </SelectItem>
                  );
                })}
              </SelectContent>
            </Select>
            {selectedRole && (
              <p className="text-micro text-muted-foreground">
                {selectedRole.folderPath
                  ? `Scoped to folder: ${selectedRole.folderPath}`
                  : "Global role"}
              </p>
            )}
          </div>

          {/* ── Duration ── */}
          <div className="flex flex-col gap-2">
            <FieldLabel required>
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" aria-hidden="true" />
                Duration
              </span>
            </FieldLabel>
            <DurationChips
              value={durationSeconds}
              onChange={setDurationSeconds}
              customSeconds={customHours}
              onCustomChange={setCustomHours}
            />
          </div>

          {/* ── Reason ── */}
          <div className="flex flex-col gap-2">
            <FieldLabel htmlFor="reason" required>
              Reason
            </FieldLabel>
            <textarea
              id="reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Briefly explain why you need this access…"
              required
              rows={4}
              aria-required="true"
              aria-describedby="reason-hint"
              className={cn(
                "w-full resize-none rounded-md border border-input bg-background px-3 py-2 text-sm",
                "placeholder:text-muted-foreground",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
              )}
            />
            <p
              id="reason-hint"
              className="text-micro text-muted-foreground"
            >
              Required. This will be visible to approvers.
            </p>
          </div>
        </form>

        <SheetFooter className="border-t border-border px-6 py-4">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => handleOpenChange(false)}
            disabled={isPending}
            className="h-8 text-body"
          >
            Cancel
          </Button>
          <Button
            type="submit"
            form="request-access-form"
            size="sm"
            disabled={!canSubmit}
            className="h-8 text-body"
            aria-disabled={!canSubmit}
          >
            {isPending ? "Submitting…" : "Submit request"}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
