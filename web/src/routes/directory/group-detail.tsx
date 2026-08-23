/**
 * group-detail.tsx — Directory ▸ Groups ▸ detail Sheet.
 *
 * A right-hand Sheet showing a selected group's identity (name + folder home)
 * and its membership. The membership body (Members + Sub-groups + Add-member
 * picker, all cap-gated with scoped invalidation) is the shared
 * `GroupMembers` component; this file supplies only the Sheet chrome.
 */

import type { Group } from "@/gen/jumpgate/identity/v1/identity_pb";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { GroupMembers } from "@/components/groups/group-members";

// ─── Detail Sheet ─────────────────────────────────────────────────────────────

export function GroupDetailSheet({
  group,
  onOpenChange,
}: {
  group: Group | null;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Sheet open={group !== null} onOpenChange={onOpenChange}>
      <SheetContent className="flex w-full flex-col overflow-y-auto sm:max-w-md">
        {group && (
          <>
            <SheetHeader>
              <SheetTitle className="text-title">{group.name}</SheetTitle>
              <SheetDescription className="text-body">
                {group.folderPath ? (
                  <>
                    Governed under{" "}
                    <span className="font-mono text-foreground">
                      {group.folderPath}
                    </span>
                    .
                  </>
                ) : (
                  <>A global group.</>
                )}
              </SheetDescription>
            </SheetHeader>

            <GroupMembers
              group={{
                groupId: group.id,
                groupName: group.name,
                folderPath: group.folderPath,
              }}
            />
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
