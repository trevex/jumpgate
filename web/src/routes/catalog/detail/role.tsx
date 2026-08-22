/**
 * role.tsx — role detail pane.
 *
 * Shows the caller's management capabilities on one role.
 * GetRoleAccess returns PermissionDenied (not NotFound) when the caller has
 * no relationship — handled by the shared DetailError component.
 */

import { useQuery } from "@connectrpc/connect-query";
import { KeyRound } from "lucide-react";
import { getRoleAccess } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import { CapList, DetailSection, DetailSkeleton, DetailError } from "./shared";

export interface RoleDetailProps {
  id: string;
  name: string;
}

export function RoleDetail({ id, name }: RoleDetailProps) {
  const { data, isLoading, isError, error } = useQuery(
    getRoleAccess,
    { roleId: id },
  );

  if (isLoading) return <DetailSkeleton />;
  if (isError) return <DetailError error={error} />;
  if (!data) return null;

  return (
    <article className="flex flex-col gap-5 p-5" aria-label={`Role: ${name}`}>
      {/* Header */}
      <header className="flex items-start gap-2">
        <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <h2 className="text-[15px] font-semibold leading-tight text-foreground">
          {name}
        </h2>
      </header>

      <div className="h-px bg-border" role="separator" />

      {/* Management capabilities */}
      <DetailSection title="Your management capabilities on this role">
        <CapList caps={data.capabilities} />
      </DetailSection>
    </article>
  );
}
