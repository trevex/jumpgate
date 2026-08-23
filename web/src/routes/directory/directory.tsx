/**
 * directory.tsx — Directory console.
 *
 * Manages users and groups, capability-gated. A tab shell (Users / Groups)
 * mirrors the My-Access tab styling. The Users tab lists directory users with
 * a deactivation-state badge; the Groups tab lists groups with their folder
 * home. Each tab reserves a right-aligned header seam for its create affordance.
 */

import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { capsCover, useCapabilities } from "@/lib/capabilities";
import { UsersTab } from "./users-tab";
import { GroupsTab } from "./groups-tab";

export function DirectoryPage() {
  const caps = useCapabilities();
  const canReadUsers = capsCover(caps, "identity:user:read");
  const canReadGroups = capsCover(caps, "identity:group:read");

  // Default to whichever tab the caller can actually see.
  const defaultTab = canReadUsers ? "users" : "groups";

  return (
    <div className="flex h-full flex-col gap-0">
      {/* Page header */}
      <header className="border-b border-border px-6 py-5">
        <h1 className="text-title font-semibold text-foreground">Directory</h1>
        <p className="mt-0.5 text-compact text-muted-foreground">
          Manage users and groups across the organization.
        </p>
      </header>

      {/* Tabs */}
      <Tabs
        defaultValue={defaultTab}
        className="flex flex-1 flex-col overflow-hidden"
      >
        <div className="border-b border-border px-6 pt-4">
          <TabsList className="h-8 gap-0 rounded-none border-b-0 bg-transparent p-0">
            {canReadUsers && (
              <TabsTrigger value="users" variant="underline">
                Users
              </TabsTrigger>
            )}
            {canReadGroups && (
              <TabsTrigger value="groups" variant="underline">
                Groups
              </TabsTrigger>
            )}
          </TabsList>
        </div>

        {canReadUsers && (
          <TabsContent
            value="users"
            className="mt-0 flex-1 overflow-y-auto data-[state=inactive]:hidden"
          >
            {/* Header action seam — "New user" lands here in a later task. */}
            <UsersTab />
          </TabsContent>
        )}

        {canReadGroups && (
          <TabsContent
            value="groups"
            className="mt-0 flex-1 overflow-y-auto data-[state=inactive]:hidden"
          >
            <GroupsTab />
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}
