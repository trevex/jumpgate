/**
 * new-folder-dialog.tsx — Catalog ▸ create folder.
 *
 * A shadcn Dialog with a single Name input. Client validation mirrors the
 * server's sibling-uniqueness charset (`^[a-z0-9_-]+$`, 1–200 chars); the
 * submit button stays disabled until the name is valid. Creates the folder
 * under `parentId` (empty → root). On success: toast + race-safe invalidate of
 * `listFolderContents`, then reset + close. On error: surface the server
 * message via toast (the server is the real gate — e.g. AlreadyExists).
 */

import { useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import {
  createFolder,
  listFolderContents,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";
import { isValidCatalogName } from "./catalog-actions";

interface NewFolderDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Parent folder id; empty/undefined creates the folder at the root. */
  parentId?: string;
  /** Parent folder path, shown for context. */
  parentPath?: string;
}

const FIELD_LABEL =
  "text-[11px] font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-[11px] text-muted-foreground";
const FIELD_ERROR = "text-[11px] text-destructive";

export function NewFolderDialog({
  open,
  onOpenChange,
  parentId,
  parentPath,
}: NewFolderDialogProps) {
  const invalidateList = useInvalidateList();

  const [name, setName] = useState("");
  const [nameTouched, setNameTouched] = useState(false);

  function reset() {
    setName("");
    setNameTouched(false);
  }

  const { mutate: doCreate, isPending } = useMutation(createFolder, {
    onSuccess: () => {
      toast.success("Folder created");
      void invalidateList(listFolderContents);
      reset();
      onOpenChange(false);
    },
    onError: (err) => {
      toast.error("Create failed", { description: connectErrorMessage(err) });
    },
  });

  const nameValid = isValidCatalogName(name);

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    if (!next) reset();
    onOpenChange(next);
  }

  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (!nameValid || isPending) return;
    doCreate({ name: name.trim(), parentId: parentId ?? "" });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[440px]">
        <DialogHeader>
          <DialogTitle className="text-[15px]">New folder</DialogTitle>
          <DialogDescription className="text-[13px]">
            {parentPath ? (
              <>
                Create a folder under{" "}
                <span className="font-mono text-[12px]">{parentPath}</span>.
              </>
            ) : (
              "Create a folder at the catalog root."
            )}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-folder-name" className={FIELD_LABEL}>
              Name
            </label>
            <Input
              id="new-folder-name"
              type="text"
              autoComplete="off"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setNameTouched(true)}
              placeholder="production"
              className="h-9 text-[13px]"
              aria-invalid={nameTouched && !nameValid}
            />
            {nameTouched && !nameValid ? (
              <p className={FIELD_ERROR}>
                Use lowercase letters, digits, dashes or underscores (1–200
                characters).
              </p>
            ) : (
              <p className={FIELD_HINT}>Lowercase letters, digits, - and _.</p>
            )}
          </div>

          <DialogFooter className="mt-1">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => handleOpenChange(false)}
              disabled={isPending}
              className="h-8 text-[13px]"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={!nameValid || isPending}
              className="h-8 text-[13px]"
            >
              {isPending ? "Creating…" : "Create folder"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
