/**
 * asset.tsx — asset detail pane.
 *
 * Shows the caller's effective access on a single asset: capabilities,
 * active roles, requestable roles, and (when ssh:login:* caps are present)
 * a Connect command block with a copy button.
 *
 * The "Request access" button opens RequestSheet (Task 3).
 */

import { useQuery, useMutation } from "@connectrpc/connect-query";
import { Server, Terminal, SquareArrowOutUpRight, Pencil, MoreHorizontal, FolderInput, Trash2, Film, Plus, Send } from "lucide-react";
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import {
  getAssetAccess,
  getAsset,
  updateAssetConfig,
  listFolderContents,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import { capsCover, useCapabilities } from "@/lib/capabilities";
import { connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";
import { CopyButton } from "@/components/copy-button";
import { RequestSheet } from "../request-sheet";
import { canUpdateAsset, canDeleteAsset } from "../catalog-actions";
import { canCreateBinding } from "../../access-control/binding-actions";
import { canCreatePolicy } from "../../access-control/policy-actions";
import { NewBindingDialog } from "../../access-control/new-binding-dialog";
import { NewPolicyDialog } from "../../access-control/new-policy-dialog";
import { ScopeBindings } from "./scope-bindings";
import { RenameDialog } from "../rename-dialog";
import { MoveDialog } from "../move-dialog";
import { DeleteNode } from "../delete-node";
import {
  AssetConfigForm,
  buildSSHConfigInput,
  draftFromAsset,
  emptyDraft,
  type ConfigDraft,
} from "../asset-config-form";
import {
  CapList,
  DetailSection,
  DetailSkeleton,
  DetailError,
  RolePill,
} from "./shared";

// ─── SSH connect command derivation ──────────────────────────────────────────

/**
 * Extracts concrete login names from ssh:login:<login> capabilities. The
 * capability format is "ssh:login:<login>" (exactly 3 segments). Glob logins
 * ("*", "**") are intentionally excluded: a wildcard means "any login" and
 * is not a runnable command — the CLI/grant flow covers that case.
 * Returns [] when no concrete SSH connect capabilities are present.
 */
function sshLoginsCoveredByCaps(caps: string[]): string[] {
  return caps
    .filter((c) => c.startsWith("ssh:login:") && c.split(":").length === 3)
    .map((c) => c.split(":")[2])
    .filter((login) => login !== "*" && login !== "**");
}

// ─── SSH connect block ────────────────────────────────────────────────────────

interface ConnectBlockProps {
  assetId: string;
  logins: string[];
  assetPath: string;
}

function ConnectBlock({ assetId, logins, assetPath }: ConnectBlockProps) {
  if (logins.length === 0 || !assetPath) return null;

  return (
    <DetailSection title="Connect">
      <div className="flex flex-col gap-1.5" role="list" aria-label="Connect commands">
        {logins.map((login) => {
          const cmd = `jumpgate connect ${login}@${assetPath}`;
          const terminalHref = `/terminal/${assetId}?login=${encodeURIComponent(login)}`;
          return (
            <div key={login} className="flex flex-col gap-1.5" role="listitem">
              <div className="flex items-center gap-2 rounded border border-border bg-muted px-3 py-2">
                <Terminal className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                <code className="flex-1 overflow-x-auto font-mono text-micro text-foreground whitespace-nowrap">
                  {cmd}
                </code>
                <CopyButton text={cmd} label="Copy command" size="md" />
              </div>
              <a
                href={terminalHref}
                target="_blank"
                rel="noopener noreferrer"
                className={cn(
                  "inline-flex w-fit items-center gap-1.5 rounded px-1.5 py-0.5 text-micro font-medium text-primary transition-colors hover:underline",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                )}
                aria-label={`Open browser terminal as ${login}`}
              >
                <SquareArrowOutUpRight className="h-3 w-3" aria-hidden="true" />
                Open terminal
              </a>
            </div>
          );
        })}
      </div>
    </DetailSection>
  );
}

// ─── Edit config dialog ───────────────────────────────────────────────────────

interface EditConfigDialogProps {
  assetId: string;
  assetName: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * Loads the asset's current SSH config (lazily — only while open) and edits it
 * through the shared AssetConfigForm. An empty secret on a pre-existing
 * password/key login keeps the sealed value; a typed one rotates it. On success
 * we invalidate the asset's own getAsset/getAssetAccess queries plus the folder
 * listing so the pane and tree re-seed.
 */
function EditConfigDialog({
  assetId,
  assetName,
  open,
  onOpenChange,
}: EditConfigDialogProps) {
  const invalidateList = useInvalidateList();

  const { data, isLoading, isError, error } = useQuery(
    getAsset,
    { assetId },
    { enabled: open },
  );

  const [draft, setDraft] = useState<ConfigDraft>(emptyDraft);
  const [configError, setConfigError] = useState<string | null>(null);

  const ssh =
    data?.asset?.config.case === "ssh" ? data.asset.config.value : undefined;

  // Seed the draft once the config loads (or when re-opening a fresh asset).
  useEffect(() => {
    if (ssh) setDraft(draftFromAsset(ssh));
  }, [ssh]);

  const { mutate: doUpdate, isPending } = useMutation(updateAssetConfig, {
    onSuccess: () => {
      toast.success("Config updated");
      void invalidateList([getAsset, getAssetAccess, listFolderContents]);
      setConfigError(null);
      onOpenChange(false);
    },
    onError: (err) => {
      toast.error("Update failed", { description: connectErrorMessage(err) });
    },
  });

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    if (!next) setConfigError(null);
    onOpenChange(next);
  }

  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (isPending) return;
    const { config, error: buildError } = buildSSHConfigInput(draft, "edit");
    if (buildError) {
      setConfigError(buildError);
      return;
    }
    setConfigError(null);
    doUpdate({ assetId, config: { case: "ssh", value: config } });
  }

  const hasLogin = draft.logins.length >= 1;

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle className="text-title">Edit config</DialogTitle>
          <DialogDescription className="text-body">
            Update the SSH connection and per-login auth for{" "}
            <span className="font-mono text-compact">{assetName}</span>. Leave a
            secret blank to keep the current one.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <p className="py-6 text-center text-body text-muted-foreground">
            Loading config…
          </p>
        ) : isError ? (
          <p className="py-6 text-center text-body text-destructive">
            {connectErrorMessage(error)}
          </p>
        ) : ssh ? (
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <AssetConfigForm
              mode="edit"
              value={draft}
              onChange={(next) => {
                setDraft(next);
                if (configError) setConfigError(null);
              }}
            />

            {configError && (
              <p className="text-micro text-destructive">{configError}</p>
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
                disabled={isPending || !hasLogin}
                className="h-8 text-body"
              >
                {isPending ? "Saving…" : "Save config"}
              </Button>
            </DialogFooter>
          </form>
        ) : (
          <p className="py-6 text-center text-body text-muted-foreground">
            This asset has no editable SSH config.
          </p>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ─── Asset detail pane ────────────────────────────────────────────────────────

export interface AssetDetailProps {
  id: string;
  name: string;
  path?: string;
  assetKind?: string;
  /** Fired after this asset is deleted, so the shell can clear the selection. */
  onCleared?: () => void;
}

export function AssetDetail({ id, name, path, assetKind, onCleared }: AssetDetailProps) {
  const navigate = useNavigate();
  const [sheetOpen, setSheetOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [renameOpen, setRenameOpen] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [bindOpen, setBindOpen] = useState(false);
  const [policyOpen, setPolicyOpen] = useState(false);

  // Binding/policy creation are GLOBAL `access:*` actions, gated on the caller's
  // own global capabilities (as the Access-control tabs do). The server re-checks.
  const globalCaps = useCapabilities();
  const mayBind = canCreateBinding(globalCaps);
  const mayMakeRequestable = canCreatePolicy(globalCaps);

  const { data, isLoading, isError, error } = useQuery(
    getAssetAccess,
    { assetId: id },
  );

  if (isLoading) return <DetailSkeleton />;
  if (isError) return <DetailError error={error} />;
  if (!data) return null;

  const sshLogins = sshLoginsCoveredByCaps(data.capabilities);
  const hasRequestable = data.requestableRoles.length > 0;
  // Authoring is a MANAGEMENT action, gated on the management capability set
  // (which includes `**`) — not the connect set in `capabilities`, which strips
  // `**` and so would hide these controls from an admin.
  const canEdit = canUpdateAsset(data.managementCapabilities);
  const canDelete = canDeleteAsset(data.managementCapabilities);
  // Session-review discovery: surface a jump to this asset's recordings for
  // anyone who can read them. `recording:read` cascades on the connect arm
  // (ConnectCapabilities), but a bare-`**` admin/auditor holds it only via the
  // management set (which retains `**`), so check both.
  const canViewRecordings =
    capsCover(data.capabilities, "recording:read") ||
    capsCover(data.managementCapabilities, "recording:read");

  return (
    <article className="flex flex-col gap-5 p-5" aria-label={`Asset: ${name}`}>
      {/* Header */}
      <header className="flex flex-col gap-1">
        <div className="flex items-start gap-2">
          <Server className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <h2 className="min-w-0 flex-1 text-title font-semibold leading-tight text-foreground">
            {name}
          </h2>
          {canEdit && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEditOpen(true)}
              className="h-7 shrink-0 gap-1.5 text-compact"
              aria-label="Edit asset config"
            >
              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
              Edit config
            </Button>
          )}
          {(canEdit || canDelete) && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  className="h-7 w-7 shrink-0 text-muted-foreground hover:text-foreground"
                  aria-label={`Actions for asset ${name}`}
                >
                  <MoreHorizontal className="h-4 w-4" aria-hidden="true" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                {canEdit && (
                  <>
                    <DropdownMenuItem
                      onSelect={() => setRenameOpen(true)}
                      className="text-body"
                    >
                      <Pencil className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                      Rename
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onSelect={() => setMoveOpen(true)}
                      className="text-body"
                    >
                      <FolderInput className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                      Move
                    </DropdownMenuItem>
                  </>
                )}
                {canDelete && (
                  <>
                    {canEdit && <DropdownMenuSeparator />}
                    <DropdownMenuItem
                      onSelect={() => setDeleteOpen(true)}
                      className="text-body text-destructive focus:text-destructive"
                    >
                      <Trash2 className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                      Delete
                    </DropdownMenuItem>
                  </>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
        {path && (
          <p className="pl-6 font-mono text-micro text-muted-foreground" aria-label="Asset path">
            {path}
          </p>
        )}
        {assetKind && (
          <div className="pl-6">
            <Badge
              variant="secondary"
              className="rounded px-1.5 py-0 text-eyebrow font-mono uppercase tracking-wide"
            >
              {assetKind}
            </Badge>
          </div>
        )}
      </header>

      <div className="h-px bg-border" role="separator" />

      {/* SSH connect block (only when connect caps present) */}
      {sshLogins.length > 0 && (
        <>
          <ConnectBlock assetId={id} logins={sshLogins} assetPath={path ?? ""} />
          <div className="h-px bg-border" role="separator" />
        </>
      )}

      {/* Session recordings (only when the caller can read this asset's recordings) */}
      {canViewRecordings && (
        <>
          <DetailSection title="Recordings">
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate(`/recordings?assetId=${id}`)}
              className="h-7 gap-1.5 text-compact"
              aria-label="View session recordings for this asset"
            >
              <Film className="h-3.5 w-3.5" aria-hidden="true" />
              View session recordings
            </Button>
          </DetailSection>
          <div className="h-px bg-border" role="separator" />
        </>
      )}

      {/* Capabilities */}
      <DetailSection title="Your capabilities on this asset">
        <CapList caps={data.capabilities} />
      </DetailSection>

      {/* Bindings scoped directly to this asset (+ governance affordances) */}
      <DetailSection title="Bindings">
        {(mayBind || mayMakeRequestable) && (
          <div className="flex flex-wrap justify-end gap-1.5">
            {mayBind && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => setBindOpen(true)}
                className="h-7 gap-1.5 text-compact"
                aria-label="Bind a role to this asset"
              >
                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                Bind a role
              </Button>
            )}
            {mayMakeRequestable && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => setPolicyOpen(true)}
                className="h-7 gap-1.5 text-compact"
                aria-label="Make this asset requestable"
              >
                <Send className="h-3.5 w-3.5" aria-hidden="true" />
                Make requestable
              </Button>
            )}
          </div>
        )}
        <ScopeBindings
          assetId={id}
          emptyMessage="No roles bound directly to this asset."
        />
      </DetailSection>

      {mayBind && (
        <NewBindingDialog
          open={bindOpen}
          onOpenChange={setBindOpen}
          fixedScope={{ kind: "asset", id, path }}
        />
      )}
      {mayMakeRequestable && (
        <NewPolicyDialog
          open={policyOpen}
          onOpenChange={setPolicyOpen}
          fixedScope={{ kind: "asset", id, path }}
          // Also re-seed this asset's access so "Requestable roles" updates.
          extraInvalidate={getAssetAccess}
        />
      )}

      {/* Active roles */}
      {data.activeRoles.length > 0 && (
        <DetailSection title="Active roles">
          <ul className="flex flex-wrap gap-1.5" aria-label="Active roles">
            {data.activeRoles.map((r) => (
              <li key={r.id}>
                <RolePill name={r.name} folderPath={r.folderPath} />
              </li>
            ))}
          </ul>
        </DetailSection>
      )}

      {/* Requestable roles */}
      {hasRequestable && (
        <>
          <DetailSection title="Requestable roles">
            <ul className="flex flex-wrap gap-1.5" aria-label="Requestable roles">
              {data.requestableRoles.map((r) => (
                <li key={r.id}>
                  <RolePill name={r.name} folderPath={r.folderPath} />
                </li>
              ))}
            </ul>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSheetOpen(true)}
              className="mt-1 h-7 text-compact"
              aria-label="Request access to this asset"
            >
              Request access
            </Button>
          </DetailSection>

          <RequestSheet
            asset={{ id, name, path }}
            requestableRoles={data.requestableRoles}
            open={sheetOpen}
            onOpenChange={setSheetOpen}
          />
        </>
      )}

      {/* No access state */}
      {data.capabilities.length === 0 &&
        data.activeRoles.length === 0 &&
        !hasRequestable && (
          <p className="text-compact text-muted-foreground italic">
            You have no access or pending requestable roles for this asset.
          </p>
        )}

      {canEdit && (
        <EditConfigDialog
          assetId={id}
          assetName={name}
          open={editOpen}
          onOpenChange={setEditOpen}
        />
      )}
      {canEdit && (
        <>
          <RenameDialog
            open={renameOpen}
            onOpenChange={setRenameOpen}
            kind="asset"
            id={id}
            currentName={name}
          />
          <MoveDialog
            open={moveOpen}
            onOpenChange={setMoveOpen}
            kind="asset"
            id={id}
          />
        </>
      )}
      {canDelete && (
        <DeleteNode
          open={deleteOpen}
          onOpenChange={setDeleteOpen}
          kind="asset"
          id={id}
          name={name}
          onDeleted={onCleared}
        />
      )}
    </article>
  );
}
