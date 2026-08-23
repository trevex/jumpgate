/**
 * access-control.tsx — Access control console.
 *
 * Manages the authorization configuration — roles (+ capabilities, folder
 * scope, grant edges), standing bindings, and request policies — all
 * capability-gated. A tab shell (Roles / Bindings / Policies) mirrors the
 * Directory tab styling. Each tab trigger is cap-gated so a caller only sees the
 * sections they can read.
 */

import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { capsCover, useCapabilities } from "@/lib/capabilities";
import { RolesTab } from "./roles-tab";
import { BindingsTab } from "./bindings-tab";
import { PoliciesTab } from "./policies-tab";

export function AccessControlPage() {
  const caps = useCapabilities();
  const canReadRoles = capsCover(caps, "access:role:read");
  const canReadBindings = capsCover(caps, "access:binding:read");
  const canReadPolicies = capsCover(caps, "access:policy:read");

  // Default to whichever tab the caller can actually see.
  const defaultTab = canReadRoles
    ? "roles"
    : canReadBindings
      ? "bindings"
      : "policies";

  return (
    <div className="flex h-full flex-col gap-0">
      {/* Page header */}
      <header className="border-b border-border px-6 py-5">
        <h1 className="text-title font-semibold text-foreground">Access control</h1>
        <p className="mt-0.5 text-compact text-muted-foreground">
          Manage roles, standing bindings, and request policies.
        </p>
      </header>

      {/* Tabs */}
      <Tabs
        defaultValue={defaultTab}
        className="flex flex-1 flex-col overflow-hidden"
      >
        <div className="border-b border-border px-6 pt-4">
          <TabsList className="h-8 gap-0 rounded-none border-b-0 bg-transparent p-0">
            {canReadRoles && (
              <TabsTrigger value="roles" variant="underline">
                Roles
              </TabsTrigger>
            )}
            {canReadBindings && (
              <TabsTrigger value="bindings" variant="underline">
                Bindings
              </TabsTrigger>
            )}
            {canReadPolicies && (
              <TabsTrigger value="policies" variant="underline">
                Policies
              </TabsTrigger>
            )}
          </TabsList>
        </div>

        {canReadRoles && (
          <TabsContent
            value="roles"
            className="mt-0 flex-1 overflow-y-auto data-[state=inactive]:hidden"
          >
            <RolesTab />
          </TabsContent>
        )}

        {canReadBindings && (
          <TabsContent
            value="bindings"
            className="mt-0 flex-1 overflow-y-auto data-[state=inactive]:hidden"
          >
            <BindingsTab />
          </TabsContent>
        )}

        {canReadPolicies && (
          <TabsContent
            value="policies"
            className="mt-0 flex-1 overflow-y-auto data-[state=inactive]:hidden"
          >
            <PoliciesTab />
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}
