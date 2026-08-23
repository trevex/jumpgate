/**
 * role.tsx — role detail pane.
 *
 * Shows the caller's management capabilities on one role, plus (gated on the
 * caller's GLOBAL `access:binding:create`) a "Bind this role" action that opens
 * the shared NewBindingDialog with this role pinned — the user picks the scope
 * and subject in the modal. GetRoleAccess returns PermissionDenied (not
 * NotFound) when the caller has no relationship — handled by the shared
 * DetailError component.
 */

import { useState } from "react";
import { useQuery } from "@connectrpc/connect-query";
import { KeyRound, Link2 } from "lucide-react";
import { getRoleAccess } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import { Button } from "@/components/ui/button";
import { useCapabilities } from "@/lib/capabilities";
import { CapList, DetailSection, DetailSkeleton, DetailError } from "./shared";
import { canCreateBinding } from "../../access-control/binding-actions";
import { NewBindingDialog } from "../../access-control/new-binding-dialog";

export interface RoleDetailProps {
  id: string;
  name: string;
}

export function RoleDetail({ id, name }: RoleDetailProps) {
  // Binding creation is a GLOBAL `access:*` action, so it's gated on the
  // caller's own global capabilities (as the folder/asset panes do). The
  // server re-checks — including folder-scope containment for scoped roles.
  const globalCaps = useCapabilities();
  const mayBind = canCreateBinding(globalCaps);

  const [bindOpen, setBindOpen] = useState(false);

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
        <h2 className="min-w-0 flex-1 text-title font-semibold leading-tight text-foreground">
          {name}
        </h2>
        {mayBind && (
          <Button
            size="sm"
            variant="outline"
            onClick={() => setBindOpen(true)}
            className="h-7 shrink-0 gap-1.5 text-compact"
            aria-label={`Bind role ${name}`}
          >
            <Link2 className="h-3.5 w-3.5" aria-hidden="true" />
            Bind this role
          </Button>
        )}
      </header>

      <div className="h-px bg-border" role="separator" />

      {/* Management capabilities */}
      <DetailSection title="Your management capabilities on this role">
        <CapList caps={data.capabilities} />
      </DetailSection>

      {/* GetRoleAccess doesn't carry the role's folder path, so omit it — the
          read-only role row then shows the name + "global". */}
      {mayBind && (
        <NewBindingDialog
          open={bindOpen}
          onOpenChange={setBindOpen}
          fixedRole={{ id, name }}
        />
      )}
    </article>
  );
}
