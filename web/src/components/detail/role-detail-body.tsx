import { useQuery, useInfiniteQuery } from "@connectrpc/connect-query";
import { Inbox } from "lucide-react";
import {
  getRoleDisplay,
  listRoleBindings,
  listPoliciesUsingRole,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import { CapList, DetailSection } from "@/routes/catalog/detail/shared";
import { EmptyState, LoadingRows } from "@/components/states/states";
import { Badge } from "@/components/ui/badge";
import { SubjectRow } from "./subject-row";
import { usageLabel } from "./policy-usage-model";

export interface RoleDetailBodyProps {
  roleId: string;
}

/** Canonical role detail body: capabilities, held-by (standing bindings), and
 *  policy usage. Rendered in both the catalog pane and the access-control Sheet. */
export function RoleDetailBody({ roleId }: RoleDetailBodyProps) {
  // The role's OWN granted capabilities (from role_capabilities). getRoleAccess
  // returns the *caller's* management caps on the role's folder — for an admin
  // that's `**` for every role, which is what this section used to (wrongly) show.
  const display = useQuery(getRoleDisplay, { id: roleId });

  return (
    <div className="flex flex-col gap-5">
      <DetailSection title="Grants these capabilities">
        {display.isLoading ? <LoadingRows count={1} /> : <CapList caps={display.data?.role?.capabilities ?? []} />}
      </DetailSection>

      <DetailSection title="Held by (standing bindings)">
        <HeldBy roleId={roleId} />
      </DetailSection>

      <DetailSection title="Used in request policies">
        <RolePolicyUsage roleId={roleId} />
      </DetailSection>
    </div>
  );
}

function HeldBy({ roleId }: { roleId: string }) {
  const { data, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteQuery(
    listRoleBindings,
    { roleId, pageSize: 50, pageToken: "" },
    { pageParamKey: "pageToken", getNextPageParam: (last) => last.nextPageToken || undefined },
  );
  const bindings = data?.pages.flatMap((p) => p.bindings) ?? [];
  if (isLoading) return <LoadingRows count={2} label="Loading bindings" />;
  if (bindings.length === 0) return <EmptyState icon={Inbox} size="sm" message="Not held by anyone." />;
  return (
    <div className="divide-y divide-border">
      {bindings.map((b) => (
        <SubjectRow
          key={b.id}
          name={b.subjectDisplayName || (b.subjectGroupId || b.subjectUserId).slice(0, 8)}
          kind={b.subjectKind}
          detail={b.scopePath}
        />
      ))}
      {hasNextPage && (
        <button type="button" onClick={() => void fetchNextPage()} disabled={isFetchingNextPage}
          className="px-1 pt-2 text-micro text-primary hover:underline">
          {isFetchingNextPage ? "Loading…" : "Load more"}
        </button>
      )}
    </div>
  );
}

function RolePolicyUsage({ roleId }: { roleId: string }) {
  const { data, isLoading } = useQuery(listPoliciesUsingRole, { roleId });
  const usages = data?.usages ?? [];
  if (isLoading) return <LoadingRows count={2} label="Loading policy usage" />;
  if (usages.length === 0) return <EmptyState icon={Inbox} size="sm" message="Not used in any policy." />;
  return (
    <ul className="divide-y divide-border">
      {usages.map((u, i) => (
        <li key={`${u.policy?.id}-${u.usage}-${i}`} className="flex items-center justify-between gap-3 px-1 py-1.5">
          <span className="truncate text-compact text-foreground" title={u.policy?.name}>
            {u.policy?.name || u.policy?.id.slice(0, 8)}
          </span>
          <Badge variant="outline" className="shrink-0 rounded px-1.5 py-0 text-micro">{usageLabel(u.usage)}</Badge>
        </li>
      ))}
    </ul>
  );
}
