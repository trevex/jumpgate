import { DetailSection } from "@/routes/catalog/detail/shared";
import { GroupMembers } from "@/components/groups/group-members";
import { GroupBindings } from "@/components/groups/group-bindings";
import { GroupPolicies } from "@/components/groups/group-policies";

export interface GroupDetailBodyProps {
  groupId: string;
  groupName: string;
  folderPath?: string;
}

/** Canonical group detail body: members, bound roles, policy participation.
 *  Rendered in both the catalog pane and the directory Sheet. */
export function GroupDetailBody({ groupId, groupName, folderPath }: GroupDetailBodyProps) {
  return (
    <div className="flex flex-col gap-5">
      <DetailSection title="Members">
        <GroupMembers group={{ groupId, groupName, folderPath }} />
      </DetailSection>
      <DetailSection title="Bound roles (what this group can do)">
        <GroupBindings groupId={groupId} />
      </DetailSection>
      <DetailSection title="Policy participation">
        <GroupPolicies groupId={groupId} />
      </DetailSection>
    </div>
  );
}
