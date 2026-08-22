/**
 * new-policy-dialog.tsx — Access control ▸ Policies ▸ create.
 *
 * A shadcn Dialog composing the requestable-role RolePicker (required), an
 * optional ScopePicker (Global | Folder | Asset), a required-approvals number
 * input (0–20), optional requester-role and approver-role RolePickers, and an
 * optional max-duration in hours. It builds a `CreateRequestPolicyRequest`:
 *   - `roleId` from the requestable role (submit disabled until chosen).
 *   - `scopeFolderId` XOR `scopeAssetId` from the scope (neither = role-default).
 *   - `requiredApprovals` (int32).
 *   - `requesterRoleId` / `approverRoleId` from the optional pickers ("" = none).
 *   - `maxDurationSeconds` as `BigInt(hours * 3600)` — 0n when the hours field is
 *     empty (int64 field, so bigint in TS; 0 means "no per-scope cap").
 *   - `name` — optional; validated against `^[a-zA-Z0-9_-]*$` when present.
 *
 * On success: toast + invalidate `listRequestPolicies` so the tab re-seeds, then
 * close and reset. On error: surface `connectErrorMessage(err)` via toast (the
 * server is the real gate — e.g. PermissionDenied, or a duplicate policy).
 */

import { useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import { ShieldCheck, Folder, Boxes, Layers } from "lucide-react";
import {
  createRequestPolicy,
  listRequestPolicies,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { RolePicker, type PickedRole } from "@/components/pickers/role-picker";
import { ScopePicker, type PickedScope } from "@/components/pickers/scope-picker";
import { connectErrorMessage } from "@/lib/format";
import { isValidPolicyName, isValidApprovals } from "./policy-actions";
import { useInvalidateList } from "@/lib/query";

interface NewPolicyDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const FIELD_LABEL =
  "text-[11px] font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-[11px] text-muted-foreground";
const FIELD_ERROR = "text-[11px] text-destructive";

/** A trigger button that shows the chosen role or a placeholder. */
function RoleField({
  role,
  placeholder,
  onOpen,
}: {
  role: PickedRole | null;
  placeholder: string;
  onOpen: () => void;
}) {
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={onOpen}
      className="h-9 justify-start gap-2 text-[13px] font-normal"
    >
      {role ? (
        <>
          <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
          <span className="min-w-0 flex-1 truncate text-left">{role.name}</span>
          {role.folderPath && (
            <span className="shrink-0 truncate font-mono text-[11px] text-muted-foreground">
              {role.folderPath}
            </span>
          )}
        </>
      ) : (
        <span className="flex-1 text-left text-muted-foreground">{placeholder}</span>
      )}
    </Button>
  );
}

export function NewPolicyDialog({ open, onOpenChange }: NewPolicyDialogProps) {
  const invalidateList = useInvalidateList();

  const [name, setName] = useState("");
  const [role, setRole] = useState<PickedRole | null>(null);
  const [scope, setScope] = useState<PickedScope>({ kind: "global" });
  const [approvals, setApprovals] = useState("1");
  const [requesterRole, setRequesterRole] = useState<PickedRole | null>(null);
  const [approverRole, setApproverRole] = useState<PickedRole | null>(null);
  const [hours, setHours] = useState("");

  const [rolePickerOpen, setRolePickerOpen] = useState(false);
  const [scopePickerOpen, setScopePickerOpen] = useState(false);
  const [requesterPickerOpen, setRequesterPickerOpen] = useState(false);
  const [approverPickerOpen, setApproverPickerOpen] = useState(false);

  function reset() {
    setName("");
    setRole(null);
    setScope({ kind: "global" });
    setApprovals("1");
    setRequesterRole(null);
    setApproverRole(null);
    setHours("");
  }

  const { mutate: doCreate, isPending } = useMutation(createRequestPolicy, {
    onSuccess: () => {
      toast.success("Policy created", {
        description: `${role?.name ?? "The role"} is now requestable.`,
      });
      void invalidateList(listRequestPolicies);
      reset();
      onOpenChange(false);
    },
    onError: (err) => {
      toast.error("Create failed", { description: connectErrorMessage(err) });
    },
  });

  const approvalsNum = Number(approvals);
  const approvalsValid = approvals.trim() !== "" && isValidApprovals(approvalsNum);
  const nameValid = isValidPolicyName(name);
  const hoursNum = Number(hours);
  const hoursValid =
    hours.trim() === "" || (Number.isFinite(hoursNum) && hoursNum >= 0);
  // Only the requestable role is required.
  const formValid = role !== null && approvalsValid && nameValid && hoursValid;

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    if (!next) reset();
    onOpenChange(next);
  }

  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (!formValid || isPending || !role) return;
    const durationSeconds =
      hours.trim() === "" ? 0n : BigInt(Math.round(hoursNum * 3600));
    doCreate({
      roleId: role.id,
      name: name.trim(),
      scopeFolderId: scope.kind === "folder" ? scope.id : "",
      scopeAssetId: scope.kind === "asset" ? scope.id : "",
      requiredApprovals: approvalsNum,
      requesterRoleId: requesterRole?.id ?? "",
      approverRoleId: approverRole?.id ?? "",
      maxDurationSeconds: durationSeconds,
    });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle className="text-[15px]">New request policy</DialogTitle>
          <DialogDescription className="text-[13px]">
            A policy makes a role requestable at a scope. An approval count and
            optional requester / approver roles govern who may request and grant
            it; an optional duration caps each grant.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {/* Name */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-policy-name" className={FIELD_LABEL}>
              Name
            </label>
            <Input
              id="new-policy-name"
              type="text"
              autoComplete="off"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Optional"
              className="h-9 text-[13px]"
              aria-invalid={!nameValid}
            />
            {!nameValid ? (
              <p className={FIELD_ERROR}>
                Use letters, digits, dashes or underscores.
              </p>
            ) : (
              <p className={FIELD_HINT}>Optional. Letters, digits, - and _.</p>
            )}
          </div>

          {/* Requestable role (required) */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Requestable role</span>
            <RoleField
              role={role}
              placeholder="Choose a role…"
              onOpen={() => setRolePickerOpen(true)}
            />
          </div>

          {/* Scope (optional) */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Scope</span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setScopePickerOpen(true)}
              className="h-9 justify-start gap-2 text-[13px] font-normal"
            >
              {scope.kind === "folder" ? (
                <>
                  <Folder className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate text-left font-mono text-[12px]">
                    {scope.path}
                  </span>
                </>
              ) : scope.kind === "asset" ? (
                <>
                  <Boxes className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate text-left font-mono text-[12px]">
                    {scope.path}
                  </span>
                </>
              ) : (
                <>
                  <Layers className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <span className="flex-1 text-left text-muted-foreground">
                    Role-default (no scope)
                  </span>
                </>
              )}
            </Button>
            <p className={FIELD_HINT}>
              Confine the policy to a folder subtree or a single asset, or leave
              it at the role's own level.
            </p>
          </div>

          {/* Required approvals */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-policy-approvals" className={FIELD_LABEL}>
              Required approvals
            </label>
            <Input
              id="new-policy-approvals"
              type="number"
              inputMode="numeric"
              min={0}
              max={20}
              value={approvals}
              onChange={(e) => setApprovals(e.target.value)}
              className="h-9 w-28 text-[13px]"
              aria-invalid={!approvalsValid}
            />
            {!approvalsValid ? (
              <p className={FIELD_ERROR}>Enter a whole number from 0 to 20.</p>
            ) : (
              <p className={FIELD_HINT}>
                Approvals needed before a request is granted (0–20).
              </p>
            )}
          </div>

          {/* Requester role (optional) */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Requester role</span>
            <div className="flex items-center gap-2">
              <div className="min-w-0 flex-1">
                <RoleField
                  role={requesterRole}
                  placeholder="Anyone (no requester role)…"
                  onOpen={() => setRequesterPickerOpen(true)}
                />
              </div>
              {requesterRole && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setRequesterRole(null)}
                  className="h-9 shrink-0 px-2 text-[12px] text-muted-foreground hover:text-foreground"
                >
                  Clear
                </Button>
              )}
            </div>
            <p className={FIELD_HINT}>
              Optional. Restrict requesting to holders of this role.
            </p>
          </div>

          {/* Approver role (optional) */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Approver role</span>
            <div className="flex items-center gap-2">
              <div className="min-w-0 flex-1">
                <RoleField
                  role={approverRole}
                  placeholder="No approver role…"
                  onOpen={() => setApproverPickerOpen(true)}
                />
              </div>
              {approverRole && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setApproverRole(null)}
                  className="h-9 shrink-0 px-2 text-[12px] text-muted-foreground hover:text-foreground"
                >
                  Clear
                </Button>
              )}
            </div>
            <p className={FIELD_HINT}>
              Optional. Let holders of this role approve requests.
            </p>
          </div>

          {/* Max duration (optional) */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-policy-hours" className={FIELD_LABEL}>
              Max duration (hours)
            </label>
            <Input
              id="new-policy-hours"
              type="number"
              inputMode="numeric"
              min={0}
              value={hours}
              onChange={(e) => setHours(e.target.value)}
              placeholder="No cap"
              className="h-9 w-28 text-[13px]"
              aria-invalid={!hoursValid}
            />
            {!hoursValid ? (
              <p className={FIELD_ERROR}>Enter a non-negative number of hours.</p>
            ) : (
              <p className={FIELD_HINT}>
                Optional. Caps each grant's lifetime; empty means no cap.
              </p>
            )}
          </div>

          <DialogFooter className="mt-1">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => handleOpenChange(false)}
              disabled={isPending}
              className="h-8 text-[13px]"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={!formValid || isPending}
              className="h-8 text-[13px]"
            >
              {isPending ? "Creating…" : "Create policy"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>

      <RolePicker
        open={rolePickerOpen}
        onOpenChange={setRolePickerOpen}
        onSelect={setRole}
        label="Choose the requestable role"
      />
      <ScopePicker
        open={scopePickerOpen}
        onOpenChange={setScopePickerOpen}
        onSelect={setScope}
      />
      <RolePicker
        open={requesterPickerOpen}
        onOpenChange={setRequesterPickerOpen}
        onSelect={setRequesterRole}
        label="Choose a requester role"
      />
      <RolePicker
        open={approverPickerOpen}
        onOpenChange={setApproverPickerOpen}
        onSelect={setApproverRole}
        label="Choose an approver role"
      />
    </Dialog>
  );
}
