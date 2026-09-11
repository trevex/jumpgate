/**
 * group-external-key.tsx — group's IdP group-claim mapping (SSO group sync).
 *
 * Shows the group's `external_key` — the IdP group-claim value mapped to this
 * group for OIDC group sync. Read-only unless the caller holds
 * `identity:group:set-external-key` (gated by the caller via
 * `canSetGroupExternalKey`); editable inline via SetGroupExternalKey (an empty
 * value clears the mapping). The server is the real gate — this only governs
 * whether the editor is offered.
 */

import { useEffect, useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import { Pencil } from "lucide-react";
import {
  setGroupExternalKey,
  listGroups,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";

export function GroupExternalKey({
  groupId,
  externalKey,
  canEdit,
}: {
  groupId: string;
  externalKey: string;
  canEdit: boolean;
}) {
  const invalidateList = useInvalidateList();
  const [editing, setEditing] = useState(false);
  const [current, setCurrent] = useState(externalKey);
  const [value, setValue] = useState(externalKey);

  // Re-seed whenever a different group is shown (or its key changes server-side).
  useEffect(() => {
    setCurrent(externalKey);
    setValue(externalKey);
    setEditing(false);
  }, [groupId, externalKey]);

  const { mutate: doSet, isPending } = useMutation(setGroupExternalKey, {
    onSuccess: () => {
      toast.success(value.trim() ? "External key set" : "External key cleared");
      void invalidateList(listGroups);
      setCurrent(value.trim());
      setEditing(false);
    },
    onError: (err) => {
      toast.error("Update failed", { description: connectErrorMessage(err) });
    },
  });

  if (!canEdit) {
    return (
      <p className="text-body text-foreground">
        {current || <span className="text-muted-foreground">Not mapped</span>}
      </p>
    );
  }

  if (!editing) {
    return (
      <div className="flex items-center gap-2">
        <span className="flex-1 text-body text-foreground">
          {current || <span className="text-muted-foreground">Not mapped</span>}
        </span>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setEditing(true)}
          className="h-7 gap-1.5 text-compact text-muted-foreground hover:text-foreground"
          aria-label="Edit external key"
        >
          <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
          Edit
        </Button>
      </div>
    );
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (isPending) return;
        doSet({ groupId, externalKey: value.trim() });
      }}
      className="flex items-center gap-2"
    >
      <Input
        autoComplete="off"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="idp-group-claim-value"
        aria-label="External key"
        className="h-8 flex-1 text-body"
      />
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => {
          setValue(current);
          setEditing(false);
        }}
        disabled={isPending}
        className="h-8 text-compact"
      >
        Cancel
      </Button>
      <Button
        type="submit"
        size="sm"
        disabled={isPending || value.trim() === current}
        className="h-8 text-compact"
      >
        {isPending ? "Saving…" : "Save"}
      </Button>
    </form>
  );
}
