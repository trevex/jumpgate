import { DetailSection } from "@/routes/catalog/detail/shared";
import { GroupMembers } from "@/components/groups/group-members";
import { GroupBindings } from "@/components/groups/group-bindings";
import { GroupPolicies } from "@/components/groups/group-policies";
import { GroupExternalKey } from "@/components/groups/group-external-key";
import { canSetGroupExternalKey } from "@/routes/directory/group-actions";
import { useCapabilities } from "@/lib/capabilities";

export interface GroupDetailBodyProps {
  groupId: string;
  groupName: string;
  folderPath?: string;
  /**
   * The group's current external key (IdP group-claim mapping for OIDC group
   * sync). Only known where the caller has the full `Group` message — the
   * directory Sheet. The catalog pane's tree only carries id + name (see the
   * folder-home omission above), so this section is left out there too when
   * `externalKey` is undefined.
   */
  externalKey?: string;
}

/** Canonical group detail body: members, bound roles, policy participation.
 *  Rendered in both the catalog pane and the directory Sheet. */
export function GroupDetailBody({ groupId, groupName, folderPath, externalKey }: GroupDetailBodyProps) {
  const caps = useCapabilities();
  return (
    <div className="flex flex-col gap-5">
      {externalKey !== undefined && (
        <DetailSection title="External key (SSO group mapping)">
          <GroupExternalKey
            groupId={groupId}
            externalKey={externalKey}
            canEdit={canSetGroupExternalKey(caps)}
          />
        </DetailSection>
      )}
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
