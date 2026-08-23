/**
 * new-asset-wizard.tsx — Catalog ▸ onboard an SSH asset.
 *
 * A shadcn Dialog that onboards an asset in a single atomic call: a name
 * (validated against the sibling-uniqueness charset), the destination folder,
 * and an SSHConfigInput built by the shared AssetConfigForm. Onboarding is
 * atomic — `createAsset` seals any inline secrets server-side in one tx.
 *
 * Submit gathers the draft via `buildSSHConfigInput(draft, "create")`; a
 * validation error (missing login name, or a password/key login with no
 * secret) is surfaced inline and blocks the call. On success: toast + race-safe
 * invalidate of `listFolderContents`, then reset + close. On error: surface the
 * server message (the server is the real gate — e.g. AlreadyExists).
 */

import { useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import {
  createAsset,
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
import {
  AssetConfigForm,
  buildSSHConfigInput,
  emptyDraft,
  type ConfigDraft,
} from "./asset-config-form";

interface NewAssetWizardProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Destination folder id. */
  folderId: string;
  /** Destination folder path, shown for context. */
  folderPath?: string;
}

const FIELD_LABEL =
  "text-micro font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-micro text-muted-foreground";
const FIELD_ERROR = "text-micro text-destructive";

export function NewAssetWizard({
  open,
  onOpenChange,
  folderId,
  folderPath,
}: NewAssetWizardProps) {
  const invalidateList = useInvalidateList();

  const [name, setName] = useState("");
  const [nameTouched, setNameTouched] = useState(false);
  const [draft, setDraft] = useState<ConfigDraft>(emptyDraft);
  const [configError, setConfigError] = useState<string | null>(null);

  function reset() {
    setName("");
    setNameTouched(false);
    setDraft(emptyDraft());
    setConfigError(null);
  }

  const { mutate: doCreate, isPending } = useMutation(createAsset, {
    onSuccess: () => {
      toast.success("Asset onboarded", {
        description: `${name.trim()} is ready.`,
      });
      void invalidateList(listFolderContents);
      reset();
      onOpenChange(false);
    },
    onError: (err) => {
      toast.error("Onboard failed", { description: connectErrorMessage(err) });
    },
  });

  const nameValid = isValidCatalogName(name);
  const hasLogin = draft.logins.length >= 1;
  const formValid = nameValid && hasLogin;

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    if (!next) reset();
    onOpenChange(next);
  }

  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (!formValid || isPending) return;
    const { config, error } = buildSSHConfigInput(draft, "create");
    if (error) {
      setConfigError(error);
      return;
    }
    setConfigError(null);
    doCreate({
      folderId,
      name: name.trim(),
      config: { case: "ssh", value: config },
    });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle className="text-title">Onboard SSH asset</DialogTitle>
          <DialogDescription className="text-body">
            {folderPath ? (
              <>
                Onboard an asset under{" "}
                <span className="font-mono text-compact">{folderPath}</span>.
                Secrets are sealed server-side.
              </>
            ) : (
              "Onboard an asset. Secrets are sealed server-side."
            )}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {/* Name */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-asset-name" className={FIELD_LABEL}>
              Name
            </label>
            <Input
              id="new-asset-name"
              type="text"
              autoComplete="off"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setNameTouched(true)}
              placeholder="pg-primary"
              className="h-9 text-body"
              aria-invalid={nameTouched && !nameValid}
              aria-describedby="new-asset-name-error"
            />
            {nameTouched && !nameValid ? (
              <p id="new-asset-name-error" role="alert" className={FIELD_ERROR}>
                Use lowercase letters, digits, dashes or underscores (1–200
                characters).
              </p>
            ) : (
              <p id="new-asset-name-error" className={FIELD_HINT}>
                Lowercase letters, digits, - and _.
              </p>
            )}
          </div>

          <div className="h-px bg-border" role="separator" />

          <AssetConfigForm
            mode="create"
            value={draft}
            onChange={(next) => {
              setDraft(next);
              if (configError) setConfigError(null);
            }}
          />

          {configError && (
            <p role="alert" className={FIELD_ERROR}>
              {configError}
            </p>
          )}

          <DialogFooter className="mt-1">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => handleOpenChange(false)}
              disabled={isPending}
              className="h-8 text-body"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={!formValid || isPending}
              className="h-8 text-body"
            >
              {isPending ? "Onboarding…" : "Onboard asset"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
