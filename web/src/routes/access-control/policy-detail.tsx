/**
 * policy-detail.tsx — Access control ▸ Policies ▸ detail Sheet.
 *
 * A right-hand Sheet for a selected request policy. The header shows the policy
 * name (or a muted "Unnamed policy") and its scope (folder / asset path via
 * resolveFolder / getAssetDisplay, or "role-default"). A Configuration section
 * lists the requestable role, required approvals, max duration, and the optional
 * requester / approver source roles (all enriched via getRoleDisplay).
 *
 * A Subjects section (`listPolicySubjects`) is split into Requesters and
 * Approvers groups. Each subject row shows the user (email via getUserDisplay)
 * or group (name via a listGroups id→name map, mirroring the Bindings tab) with
 * a Remove (gated `access:policy:update`). Each group has an Add control — a
 * SubjectPicker → addPolicySubject({ policyId, kind, subjectUserId|Group }).
 *
 * Edit (gated `access:policy:update`) opens a small dialog updating the mutable
 * fields (approvals, duration, requester / approver roles) via updateRequestPolicy.
 * Delete (gated `access:policy:delete`) opens a ConfirmDialog then deleteRequestPolicy.
 * Mutations invalidate the relevant scoped query + toast; onError surfaces
 * connectErrorMessage. This is the single source of truth for a policy's edits,
 * so the selected policy is tracked in local state and updated in place after an edit.
 */

import { useEffect, useState } from "react";
import { useQuery, useMutation } from "@connectrpc/connect-query";
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  listRequestPolicies,
  listPolicySubjects,
  addPolicySubject,
  removePolicySubject,
  updateRequestPolicy,
  deleteRequestPolicy,
  getRoleDisplay,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import {
  getUserDisplay,
  listGroups,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import {
  resolveFolder,
  getAssetDisplay,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import type {
  RequestPolicy,
  PolicySubject,
} from "@/gen/jumpgate/access/v1/access_pb";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
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
import { Badge } from "@/components/ui/badge";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states/states";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { useCapabilities } from "@/lib/capabilities";
import { connectErrorMessage } from "@/lib/format";
import { canUpdatePolicy, canDeletePolicy, isValidApprovals } from "./policy-actions";
import { RolePicker, type PickedRole } from "@/components/pickers/role-picker";
import {
  SubjectPicker,
  type PickedSubject,
} from "@/components/pickers/subject-picker";
import {
  ScrollText,
  ShieldCheck,
  Folder,
  Boxes,
  Layers,
  User,
  Users,
  Plus,
  Pencil,
  Trash2,
  X,
  Clock,
} from "lucide-react";

const SUBJECTS_PAGE_SIZE = 100;
const GROUPS_PAGE_SIZE = 100;

type SubjectKind = "requester" | "approver";

function shortId(id: string): string {
  return id.split("-")[0] ?? id;
}

/** Render a duration in seconds (bigint) as a compact human string. */
function formatDuration(seconds: bigint): string {
  if (seconds <= 0n) return "No cap";
  const total = Number(seconds);
  const hours = Math.floor(total / 3600);
  const days = Math.floor(hours / 24);
  if (days >= 1 && hours % 24 === 0) return `${days}d`;
  if (hours >= 1) return `${hours}h`;
  const minutes = Math.floor(total / 60);
  if (minutes >= 1) return `${minutes}m`;
  return `${total}s`;
}

// ─── Subjects query key (shared, scoped to one policy) ────────────────────────

function subjectsQueryKey(policyId: string) {
  return createConnectQueryKey({
    schema: listPolicySubjects,
    input: { policyId, pageSize: SUBJECTS_PAGE_SIZE, pageToken: "" },
    cardinality: "finite",
  });
}

function useInvalidateSubjects(policyId: string) {
  const queryClient = useQueryClient();
  return () =>
    void queryClient.invalidateQueries({ queryKey: subjectsQueryKey(policyId) });
}

function useInvalidatePolicies() {
  const queryClient = useQueryClient();
  return () =>
    void queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({
        schema: listRequestPolicies,
        cardinality: undefined,
      }),
    });
}

// ─── Enriched role name (inline) ──────────────────────────────────────────────

function RoleName({ roleId }: { roleId: string }) {
  const { data } = useQuery(getRoleDisplay, { id: roleId }, { enabled: Boolean(roleId) });
  const name = data?.role?.name || shortId(roleId);
  return (
    <span className="inline-flex items-center gap-1.5">
      <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="truncate text-foreground" title={name}>
        {name}
      </span>
    </span>
  );
}

// ─── Section wrapper ──────────────────────────────────────────────────────────

function Section({
  title,
  count,
  children,
}: {
  title: string;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-1">
      <h3 className="flex items-center gap-2 px-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        {title}
        {count !== undefined && (
          <span className="tabular-nums text-muted-foreground/60">{count}</span>
        )}
      </h3>
      {children}
    </section>
  );
}

function FieldRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-3 px-1 py-1.5">
      <span className="shrink-0 text-[12px] text-muted-foreground">{label}</span>
      <span className="min-w-0 text-right text-[13px] text-foreground">{children}</span>
    </div>
  );
}

// ─── Configuration section ────────────────────────────────────────────────────

function ConfigurationSection({ policy }: { policy: RequestPolicy }) {
  return (
    <Section title="Configuration">
      <div className="divide-y divide-border rounded-md border border-border">
        <FieldRow label="Requestable role">
          <RoleName roleId={policy.roleId} />
        </FieldRow>
        <FieldRow label="Required approvals">
          <Badge
            variant="secondary"
            className="rounded px-1.5 py-0 text-[11px] font-semibold tabular-nums"
          >
            {policy.requiredApprovals}
          </Badge>
        </FieldRow>
        <FieldRow label="Max duration">
          <span className="inline-flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
            {formatDuration(policy.maxDurationSeconds)}
          </span>
        </FieldRow>
        <FieldRow label="Requester role">
          {policy.requesterRoleId ? (
            <RoleName roleId={policy.requesterRoleId} />
          ) : (
            <span className="text-muted-foreground/70">Anyone</span>
          )}
        </FieldRow>
        <FieldRow label="Approver role">
          {policy.approverRoleId ? (
            <RoleName roleId={policy.approverRoleId} />
          ) : (
            <span className="text-muted-foreground/70">None</span>
          )}
        </FieldRow>
      </div>
    </Section>
  );
}

// ─── Subject row (user email / group name) ────────────────────────────────────

function SubjectRow({
  policyId,
  subject,
  groupNames,
  canRemove,
}: {
  policyId: string;
  subject: PolicySubject;
  groupNames: Map<string, string>;
  canRemove: boolean;
}) {
  const invalidate = useInvalidateSubjects(policyId);
  const { data } = useQuery(
    getUserDisplay,
    { id: subject.subjectUserId },
    { enabled: Boolean(subject.subjectUserId) },
  );

  const isUser = Boolean(subject.subjectUserId);
  const label = isUser
    ? data?.user?.email || data?.user?.displayName || shortId(subject.subjectUserId)
    : groupNames.get(subject.subjectGroupId) || shortId(subject.subjectGroupId);

  const { mutate: doRemove, isPending } = useMutation(removePolicySubject, {
    onSuccess: () => {
      toast.success("Subject removed", {
        description: `${label} was removed from this policy.`,
      });
      invalidate();
    },
    onError: (err) => toast.error("Remove failed", { description: connectErrorMessage(err) }),
  });

  return (
    <div className="flex items-center gap-2.5 px-1 py-1.5">
      {isUser ? (
        <User className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      ) : (
        <Users className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      )}
      <span className="min-w-0 flex-1 truncate text-[13px] text-foreground" title={label}>
        {label}
      </span>
      {canRemove && (
        <Button
          variant="ghost"
          size="icon"
          onClick={() => doRemove({ id: subject.id })}
          disabled={isPending}
          aria-label={`Remove ${label}`}
          className="h-7 w-7 shrink-0 text-muted-foreground hover:text-destructive"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      )}
    </div>
  );
}

// ─── Add-subject control ──────────────────────────────────────────────────────

function AddSubject({ policyId, kind }: { policyId: string; kind: SubjectKind }) {
  const invalidate = useInvalidateSubjects(policyId);
  const [pickerOpen, setPickerOpen] = useState(false);

  const { mutate: doAdd } = useMutation(addPolicySubject, {
    onSuccess: () => {
      toast.success("Subject added");
      invalidate();
    },
    onError: (err) => toast.error("Add failed", { description: connectErrorMessage(err) }),
  });

  function onSelect(subject: PickedSubject) {
    doAdd({
      policyId,
      kind,
      subjectUserId: subject.kind === "user" ? subject.id : "",
      subjectGroupId: subject.kind === "group" ? subject.id : "",
    });
  }

  return (
    <>
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => setPickerOpen(true)}
        className="mt-1 h-7 gap-1 self-start px-2.5 text-[12px]"
      >
        <Plus className="h-3.5 w-3.5" aria-hidden="true" />
        Add {kind}
      </Button>
      <SubjectPicker open={pickerOpen} onOpenChange={setPickerOpen} onSelect={onSelect} />
    </>
  );
}

// ─── One subject group (Requesters | Approvers) ───────────────────────────────

function SubjectGroup({
  policyId,
  kind,
  subjects,
  groupNames,
  canUpdate,
}: {
  policyId: string;
  kind: SubjectKind;
  subjects: PolicySubject[];
  groupNames: Map<string, string>;
  canUpdate: boolean;
}) {
  const heading = kind === "requester" ? "Requesters" : "Approvers";
  return (
    <div className="flex flex-col gap-0.5">
      <h4 className="px-1 text-[11px] font-medium text-foreground">{heading}</h4>
      {subjects.length === 0 ? (
        <p className="px-1 py-1.5 text-[12px] text-muted-foreground/70">
          {kind === "requester"
            ? "No requester subjects."
            : "No approver subjects."}
        </p>
      ) : (
        <div className="divide-y divide-border">
          {subjects.map((s) => (
            <SubjectRow
              key={s.id}
              policyId={policyId}
              subject={s}
              groupNames={groupNames}
              canRemove={canUpdate}
            />
          ))}
        </div>
      )}
      {canUpdate && <AddSubject policyId={policyId} kind={kind} />}
    </div>
  );
}

// ─── Subjects section ─────────────────────────────────────────────────────────

function SubjectsSection({
  policyId,
  canUpdate,
}: {
  policyId: string;
  canUpdate: boolean;
}) {
  const { data, isLoading, isError, error, refetch } = useQuery(listPolicySubjects, {
    policyId,
    pageSize: SUBJECTS_PAGE_SIZE,
    pageToken: "",
  });

  // Group id→name map (no group-display-by-id RPC — mirrors the Bindings tab).
  const { data: groupsData } = useQuery(listGroups, {
    pageSize: GROUPS_PAGE_SIZE,
    pageToken: "",
  });
  const groupNames = new Map<string, string>();
  for (const g of groupsData?.groups ?? []) groupNames.set(g.id, g.name);

  const subjects = data?.subjects ?? [];
  const requesters = subjects.filter((s) => s.kind === "requester");
  const approvers = subjects.filter((s) => s.kind === "approver");

  return (
    <Section title="Subjects" count={subjects.length}>
      {isLoading ? (
        <LoadingRows count={2} label="Loading subjects" />
      ) : isError ? (
        <ErrorState
          size="sm"
          message={connectErrorMessage(error)}
          onRetry={() => void refetch()}
        />
      ) : (
        <div className="flex flex-col gap-4 py-1">
          <SubjectGroup
            policyId={policyId}
            kind="requester"
            subjects={requesters}
            groupNames={groupNames}
            canUpdate={canUpdate}
          />
          <SubjectGroup
            policyId={policyId}
            kind="approver"
            subjects={approvers}
            groupNames={groupNames}
            canUpdate={canUpdate}
          />
        </div>
      )}
    </Section>
  );
}

// ─── Edit dialog ──────────────────────────────────────────────────────────────

function EditPolicyDialog({
  policy,
  open,
  onOpenChange,
  onUpdated,
}: {
  policy: RequestPolicy;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUpdated: (next: RequestPolicy) => void;
}) {
  const invalidatePolicies = useInvalidatePolicies();

  const [approvals, setApprovals] = useState(String(policy.requiredApprovals));
  const [hours, setHours] = useState(
    policy.maxDurationSeconds > 0n
      ? String(Number(policy.maxDurationSeconds) / 3600)
      : "",
  );
  const [requesterRole, setRequesterRole] = useState<PickedRole | null>(null);
  const [approverRole, setApproverRole] = useState<PickedRole | null>(null);
  // Track whether the pickers have been touched, so an untouched dialog keeps
  // the policy's existing requester / approver role ids.
  const [requesterTouched, setRequesterTouched] = useState(false);
  const [approverTouched, setApproverTouched] = useState(false);
  const [requesterPickerOpen, setRequesterPickerOpen] = useState(false);
  const [approverPickerOpen, setApproverPickerOpen] = useState(false);

  // Reset local state each time the dialog opens for this policy.
  useEffect(() => {
    if (open) {
      setApprovals(String(policy.requiredApprovals));
      setHours(
        policy.maxDurationSeconds > 0n
          ? String(Number(policy.maxDurationSeconds) / 3600)
          : "",
      );
      setRequesterRole(null);
      setApproverRole(null);
      setRequesterTouched(false);
      setApproverTouched(false);
    }
  }, [open, policy]);

  const { mutate: doUpdate, isPending } = useMutation(updateRequestPolicy, {
    onSuccess: (res) => {
      toast.success("Policy updated");
      invalidatePolicies();
      if (res.policy) onUpdated(res.policy);
      onOpenChange(false);
    },
    onError: (err) => toast.error("Update failed", { description: connectErrorMessage(err) }),
  });

  const approvalsNum = Number(approvals);
  const approvalsValid = approvals.trim() !== "" && isValidApprovals(approvalsNum);
  const hoursNum = Number(hours);
  const hoursValid =
    hours.trim() === "" || (Number.isFinite(hoursNum) && hoursNum >= 0);
  const formValid = approvalsValid && hoursValid;

  // Requester / approver: keep existing unless the picker was touched (then use
  // the picked id, or "" if the picker was cleared).
  const requesterRoleId = requesterTouched
    ? (requesterRole?.id ?? "")
    : policy.requesterRoleId;
  const approverRoleId = approverTouched
    ? (approverRole?.id ?? "")
    : policy.approverRoleId;

  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (!formValid || isPending) return;
    const durationSeconds =
      hours.trim() === "" ? 0n : BigInt(Math.round(hoursNum * 3600));
    doUpdate({
      id: policy.id,
      requiredApprovals: approvalsNum,
      requesterRoleId,
      approverRoleId,
      maxDurationSeconds: durationSeconds,
    });
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !isPending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-[440px]">
        <DialogHeader>
          <DialogTitle className="text-[15px]">Edit policy</DialogTitle>
          <DialogDescription className="text-[13px]">
            Adjust the approval count, duration cap, and requester / approver
            source roles. The requestable role and scope are fixed.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {/* Required approvals */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="edit-policy-approvals" className={FIELD_LABEL}>
              Required approvals
            </label>
            <Input
              id="edit-policy-approvals"
              type="number"
              inputMode="numeric"
              min={0}
              max={20}
              value={approvals}
              onChange={(e) => setApprovals(e.target.value)}
              className="h-9 w-28 text-[13px]"
              aria-invalid={!approvalsValid}
            />
            {!approvalsValid && (
              <p className={FIELD_ERROR}>Enter a whole number from 0 to 20.</p>
            )}
          </div>

          {/* Requester role */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Requester role</span>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setRequesterPickerOpen(true)}
                className="h-9 min-w-0 flex-1 justify-start gap-2 text-[13px] font-normal"
              >
                {requesterTouched ? (
                  requesterRole ? (
                    <RolePreview role={requesterRole} />
                  ) : (
                    <span className="flex-1 text-left text-muted-foreground">
                      Anyone (cleared)
                    </span>
                  )
                ) : policy.requesterRoleId ? (
                  <ExistingRolePreview roleId={policy.requesterRoleId} />
                ) : (
                  <span className="flex-1 text-left text-muted-foreground">
                    Anyone (no requester role)
                  </span>
                )}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => {
                  setRequesterTouched(true);
                  setRequesterRole(null);
                }}
                className="h-9 shrink-0 px-2 text-[12px] text-muted-foreground hover:text-foreground"
              >
                Clear
              </Button>
            </div>
          </div>

          {/* Approver role */}
          <div className="flex flex-col gap-1.5">
            <span className={FIELD_LABEL}>Approver role</span>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setApproverPickerOpen(true)}
                className="h-9 min-w-0 flex-1 justify-start gap-2 text-[13px] font-normal"
              >
                {approverTouched ? (
                  approverRole ? (
                    <RolePreview role={approverRole} />
                  ) : (
                    <span className="flex-1 text-left text-muted-foreground">
                      None (cleared)
                    </span>
                  )
                ) : policy.approverRoleId ? (
                  <ExistingRolePreview roleId={policy.approverRoleId} />
                ) : (
                  <span className="flex-1 text-left text-muted-foreground">
                    No approver role
                  </span>
                )}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => {
                  setApproverTouched(true);
                  setApproverRole(null);
                }}
                className="h-9 shrink-0 px-2 text-[12px] text-muted-foreground hover:text-foreground"
              >
                Clear
              </Button>
            </div>
          </div>

          {/* Max duration */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="edit-policy-hours" className={FIELD_LABEL}>
              Max duration (hours)
            </label>
            <Input
              id="edit-policy-hours"
              type="number"
              inputMode="numeric"
              min={0}
              value={hours}
              onChange={(e) => setHours(e.target.value)}
              placeholder="No cap"
              className="h-9 w-28 text-[13px]"
              aria-invalid={!hoursValid}
            />
            {!hoursValid && (
              <p className={FIELD_ERROR}>Enter a non-negative number of hours.</p>
            )}
          </div>

          <DialogFooter className="mt-1">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onOpenChange(false)}
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
              {isPending ? "Saving…" : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>

      <RolePicker
        open={requesterPickerOpen}
        onOpenChange={setRequesterPickerOpen}
        onSelect={(r) => {
          setRequesterTouched(true);
          setRequesterRole(r);
        }}
        label="Choose a requester role"
      />
      <RolePicker
        open={approverPickerOpen}
        onOpenChange={setApproverPickerOpen}
        onSelect={(r) => {
          setApproverTouched(true);
          setApproverRole(r);
        }}
        label="Choose an approver role"
      />
    </Dialog>
  );
}

function RolePreview({ role }: { role: PickedRole }) {
  return (
    <>
      <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="min-w-0 flex-1 truncate text-left">{role.name}</span>
    </>
  );
}

function ExistingRolePreview({ roleId }: { roleId: string }) {
  const { data } = useQuery(getRoleDisplay, { id: roleId }, { enabled: Boolean(roleId) });
  const name = data?.role?.name || shortId(roleId);
  return (
    <>
      <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="min-w-0 flex-1 truncate text-left">{name}</span>
    </>
  );
}

// ─── Danger zone (delete) ─────────────────────────────────────────────────────

function DeletePolicy({
  policy,
  onDeleted,
}: {
  policy: RequestPolicy;
  onDeleted: () => void;
}) {
  const invalidatePolicies = useInvalidatePolicies();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const { mutate: doDelete, isPending } = useMutation(deleteRequestPolicy, {
    onSuccess: () => {
      toast.success("Policy deleted");
      invalidatePolicies();
      setConfirmOpen(false);
      onDeleted();
    },
    onError: (err) => toast.error("Delete failed", { description: connectErrorMessage(err) }),
  });

  return (
    <section className="mt-2 flex items-center justify-between gap-3 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2.5">
      <div className="min-w-0">
        <p className="text-[12px] font-medium text-foreground">Delete policy</p>
        <p className="text-[11px] text-muted-foreground">
          Its role stops being requestable at this scope.
        </p>
      </div>
      <Button
        variant="destructive"
        size="sm"
        onClick={() => setConfirmOpen(true)}
        disabled={isPending}
        className="h-7 shrink-0 gap-1 px-3 text-[12px]"
      >
        <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
        Delete
      </Button>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Delete this request policy?"
        description="Delete this request policy? Its role stops being requestable at this scope."
        confirmLabel="Delete policy"
        pendingLabel="Deleting…"
        variant="destructive"
        confirmAriaLabel="Confirm delete policy"
        pending={isPending}
        onConfirm={() => doDelete({ id: policy.id })}
      />
    </section>
  );
}

// ─── Header scope description ──────────────────────────────────────────────────

function ScopeDescription({ policy }: { policy: RequestPolicy }) {
  const folder = useQuery(
    resolveFolder,
    { ref: policy.scopeFolderId },
    { enabled: Boolean(policy.scopeFolderId) },
  );
  const asset = useQuery(
    getAssetDisplay,
    { assetId: policy.scopeAssetId },
    { enabled: Boolean(policy.scopeAssetId) },
  );

  if (policy.scopeFolderId) {
    const path = folder.data?.path || shortId(policy.scopeFolderId);
    return (
      <span className="inline-flex items-center gap-1.5">
        <Folder className="h-3.5 w-3.5" aria-hidden="true" />
        Scoped to <span className="font-mono text-foreground">{path}</span>.
      </span>
    );
  }
  if (policy.scopeAssetId) {
    const path =
      asset.data?.asset?.path || asset.data?.asset?.name || shortId(policy.scopeAssetId);
    return (
      <span className="inline-flex items-center gap-1.5">
        <Boxes className="h-3.5 w-3.5" aria-hidden="true" />
        Scoped to <span className="font-mono text-foreground">{path}</span>.
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <Layers className="h-3.5 w-3.5" aria-hidden="true" />
      Applies at the role's own level.
    </span>
  );
}

const FIELD_LABEL =
  "text-[11px] font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_ERROR = "text-[11px] text-destructive";

// ─── Detail Sheet ─────────────────────────────────────────────────────────────

export function PolicyDetailSheet({
  policy,
  onOpenChange,
}: {
  policy: RequestPolicy | null;
  onOpenChange: (open: boolean) => void;
}) {
  const caps = useCapabilities();
  const canUpdate = canUpdatePolicy(caps);
  const canDelete = canDeletePolicy(caps);

  // Track the policy locally so an edit reflects immediately in this Sheet.
  const [current, setCurrent] = useState<RequestPolicy | null>(policy);
  const [editOpen, setEditOpen] = useState(false);

  useEffect(() => {
    setCurrent(policy);
  }, [policy]);

  const shown = current ?? policy;

  return (
    <Sheet open={policy !== null} onOpenChange={onOpenChange}>
      <SheetContent className="flex w-full flex-col gap-6 overflow-y-auto sm:max-w-md">
        {shown && (
          <>
            <SheetHeader>
              <SheetTitle className="flex items-center gap-2 text-[15px]">
                <ScrollText className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                {shown.name || (
                  <span className="text-muted-foreground">Unnamed policy</span>
                )}
              </SheetTitle>
              <SheetDescription className="text-[13px]">
                <ScopeDescription policy={shown} />
              </SheetDescription>
            </SheetHeader>

            {canUpdate && (
              <div className="flex justify-end">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setEditOpen(true)}
                  className="h-7 gap-1 px-3 text-[12px]"
                >
                  <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                  Edit
                </Button>
              </div>
            )}

            <ConfigurationSection policy={shown} />
            <SubjectsSection policyId={shown.id} canUpdate={canUpdate} />
            {canDelete && (
              <DeletePolicy policy={shown} onDeleted={() => onOpenChange(false)} />
            )}

            {canUpdate && (
              <EditPolicyDialog
                policy={shown}
                open={editOpen}
                onOpenChange={setEditOpen}
                onUpdated={setCurrent}
              />
            )}
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
