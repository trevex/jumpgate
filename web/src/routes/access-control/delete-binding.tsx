/**
 * delete-binding.tsx — Access control ▸ Bindings ▸ per-row delete.
 *
 * A trash icon button that opens a ConfirmDialog naming the consequence, then
 * calls `deleteRoleBinding({ id })`. On success: toast + invalidate
 * `listRoleBindings` so the tab re-seeds without the removed row. On error:
 * surface `connectErrorMessage(err)` via toast (the server is the real gate).
 *
 * The caller (bindings tab) already gates rendering on `access:binding:delete`;
 * the server remains the enforcer.
 */

import { useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Trash2 } from "lucide-react";
import {
  deleteRoleBinding,
  listRoleBindings,
} from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import type { RoleBinding } from "@/gen/jumpgate/access/v1/access_pb";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { connectErrorMessage } from "@/lib/format";

export function DeleteBinding({ binding }: { binding: RoleBinding }) {
  const queryClient = useQueryClient();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const { mutate: doDelete, isPending } = useMutation(deleteRoleBinding, {
    onSuccess: () => {
      toast.success("Binding deleted", {
        description: "The subject no longer holds this role at this scope.",
      });
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({
          schema: listRoleBindings,
          cardinality: undefined,
        }),
      });
      setConfirmOpen(false);
    },
    onError: (err) =>
      toast.error("Delete failed", { description: connectErrorMessage(err) }),
  });

  return (
    <>
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setConfirmOpen(true)}
        disabled={isPending}
        aria-label="Delete binding"
        className="h-7 w-7 text-muted-foreground hover:text-destructive"
      >
        <Trash2 className="h-4 w-4" aria-hidden="true" />
      </Button>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Delete this binding?"
        description="Delete this binding? The subject loses the access it grants."
        confirmLabel="Delete binding"
        pendingLabel="Deleting…"
        variant="destructive"
        pending={isPending}
        onConfirm={() => doDelete({ id: binding.id })}
      />
    </>
  );
}
