import { useState } from "react";
import { useQuery } from "@connectrpc/connect-query";
import { ShieldCheck, ChevronRight, ChevronDown } from "lucide-react";
import {
  getPolicyRoster,
  getRoleDisplay,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import type { RequestPolicy, RosterNode } from "@/gen/jumpgate/access/v1/access_pb";
import { Badge } from "@/components/ui/badge";
import { LoadingRows, ErrorState } from "@/components/states/states";
import { connectErrorMessage } from "@/lib/format";
import { cn } from "@/lib/utils";
import { SubjectRow } from "./subject-row";
import { rosterNodeLabel, emptyRosterMessage } from "./roster-model";
import { policyRuleSummary } from "./policy-usage-model";

function roleName(roleId: string, fallback = ""): string {
  return fallback || roleId.slice(0, 8);
}

/** Fetches a role's display name (best-effort) for the rule summary. */
function useRoleName(roleId: string): string {
  const { data } = useQuery(getRoleDisplay, { id: roleId }, { enabled: Boolean(roleId) });
  return data?.role?.name ?? "";
}

export function PolicyRuleCard({ policy }: { policy: RequestPolicy }) {
  const grantName = useRoleName(policy.roleId);
  const requesterName = useRoleName(policy.requesterRoleId);
  const approverName = useRoleName(policy.approverRoleId);

  return (
    <div className="rounded-lg border border-border p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="inline-flex min-w-0 items-center gap-1.5">
          <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
          <span className="truncate text-body font-medium text-foreground">{grantName || roleName(policy.roleId)}</span>
        </span>
        <Badge variant="secondary" className="shrink-0 rounded px-1.5 py-0 text-micro font-semibold tabular-nums">
          {policy.requiredApprovals} approval{policy.requiredApprovals === 1 ? "" : "s"}
        </Badge>
      </div>
      <p className="mt-2 text-micro text-muted-foreground">
        {policyRuleSummary(policy, requesterName, approverName)}
      </p>
      <RosterDisclosure policyId={policy.id} />
    </div>
  );
}

function RosterDisclosure({ policyId }: { policyId: string }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading, isError, error } = useQuery(
    getPolicyRoster,
    { policyId },
    { enabled: open },
  );

  return (
    <div className="mt-2 border-t border-dashed border-border pt-2">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1 text-micro font-medium text-primary hover:underline"
        aria-expanded={open}
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        Who can request / approve
      </button>
      {open && (
        <div className="mt-2 grid gap-3 sm:grid-cols-2">
          <RosterColumn title="Requesters" empty={emptyRosterMessage("request")}
            isLoading={isLoading} isError={isError} error={error} nodes={data?.requesters ?? []} />
          <RosterColumn title="Approvers" empty={emptyRosterMessage("approve")}
            isLoading={isLoading} isError={isError} error={error} nodes={data?.approvers ?? []} />
        </div>
      )}
    </div>
  );
}

function RosterColumn({
  title, empty, isLoading, isError, error, nodes,
}: {
  title: string; empty: string; isLoading: boolean; isError: boolean; error: unknown; nodes: RosterNode[];
}) {
  return (
    <div>
      <div className="mb-1 text-eyebrow font-semibold uppercase tracking-widest text-muted-foreground">
        {title} · {nodes.length}
      </div>
      {isLoading ? (
        <LoadingRows count={2} label={`Loading ${title}`} />
      ) : isError ? (
        <ErrorState size="sm" message={connectErrorMessage(error)} />
      ) : nodes.length === 0 ? (
        <p className="px-1 text-micro italic text-muted-foreground">{empty}</p>
      ) : (
        <div className={cn("divide-y divide-border")}>
          {nodes.map((n) => {
            const l = rosterNodeLabel(n);
            return <SubjectRow key={n.subjectId} name={l.name} kind={l.kind} detail={l.detail} inactive={l.inactive} />;
          })}
        </div>
      )}
    </div>
  );
}
