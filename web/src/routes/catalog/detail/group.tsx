/**
 * group.tsx — catalog group detail pane.
 *
 * A full group detail: identity (name), the caller's management capabilities on
 * the group, its Members (users + sub-groups, with add/remove — the shared
 * membership body), and the roles bound to it as a subject.
 *
 * GetGroupAccess returns NotFound (existence-hiding) when the caller has no
 * relationship — handled by the shared DetailError component.
 *
 * The catalog tree only carries id + name for a group (there is no id-keyed
 * group-display RPC that returns a folder home), so the folder-home line is
 * omitted here; the shared membership body is driven off id + name.
 */

import { useQuery } from "@connectrpc/connect-query";
import { Users } from "lucide-react";
import { getGroupAccess } from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import { GroupDetailBody } from "@/components/detail/group-detail-body";
import { DetailSkeleton, DetailError } from "./shared";

export interface GroupDetailProps {
  id: string;
  name: string;
}

export function GroupDetail({ id, name }: GroupDetailProps) {
  const { data, isLoading, isError, error } = useQuery(
    getGroupAccess,
    { groupId: id },
  );

  if (isLoading) return <DetailSkeleton />;
  if (isError) return <DetailError error={error} />;
  if (!data) return null;

  return (
    <article className="flex flex-col gap-5 p-5" aria-label={`Group: ${name}`}>
      {/* Header */}
      <header className="flex items-start gap-2">
        <Users className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <h2 className="text-title font-semibold leading-tight text-foreground">
          {name}
        </h2>
      </header>

      <div className="h-px bg-border" role="separator" />

      <GroupDetailBody groupId={id} groupName={name} />

      <div className="h-px bg-border" role="separator" />

      {/* Management capabilities — demoted footer */}
      <p className="text-micro text-muted-foreground">
        Your management capabilities on this group:{" "}
        <span className="font-mono">{(data.capabilities ?? []).join(" ") || "none"}</span>
      </p>
    </article>
  );
}
