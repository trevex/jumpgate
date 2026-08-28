/**
 * labels.tsx — shared enriched labels for role bindings & request policies.
 *
 * RoleLabel resolves a role id to its display name (getRoleDisplay) with a
 * short-id fallback. ScopeLabel renders a binding/policy scope as a folder path
 * (resolveFolder), an asset path (getAssetDisplay), or a muted "global" when
 * neither is set. Extracted from group-bindings / group-policies / scope-bindings
 * so the enrichment + markup live in one place.
 */

import { useQuery } from "@connectrpc/connect-query";
import { getRoleDisplay } from "@/gen/jumpgate/access/v1/access-AccessService_connectquery";
import {
  resolveFolder,
  getAssetDisplay,
} from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { shortId } from "@/lib/format";
import { ShieldCheck, Folder, Boxes, Globe } from "lucide-react";

// ─── Role label (enriched via getRoleDisplay) ─────────────────────────────────

/** Role id → display name (getRoleDisplay), short-id fallback. */
export function RoleLabel({ roleId }: { roleId: string }) {
  const { data } = useQuery(
    getRoleDisplay,
    { id: roleId },
    { enabled: Boolean(roleId) },
  );
  const name = data?.role?.name || shortId(roleId);
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5">
      <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="truncate font-medium text-foreground" title={name}>
        {name}
      </span>
    </span>
  );
}

// ─── Scope label (folder path / asset path / global) ──────────────────────────

function FolderScope({ folderId }: { folderId: string }) {
  const { data } = useQuery(resolveFolder, { ref: folderId }, { enabled: true });
  const path = data?.path || shortId(folderId);
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5 font-mono text-compact text-muted-foreground">
      <Folder className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span className="truncate" title={path}>
        {path}
      </span>
    </span>
  );
}

function AssetScope({ assetId }: { assetId: string }) {
  const { data } = useQuery(getAssetDisplay, { assetId }, { enabled: true });
  const path = data?.asset?.path || data?.asset?.name || shortId(assetId);
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5 font-mono text-compact text-muted-foreground">
      <Boxes className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span className="truncate" title={path}>
        {path}
      </span>
    </span>
  );
}

/**
 * Scope as folder path / asset path / muted "global". Accepts any object
 * carrying the two scope id fields (RoleBinding or RequestPolicy).
 */
export function ScopeLabel({
  scope,
}: {
  scope: { scopeFolderId: string; scopeAssetId: string };
}) {
  if (scope.scopeFolderId) return <FolderScope folderId={scope.scopeFolderId} />;
  if (scope.scopeAssetId) return <AssetScope assetId={scope.scopeAssetId} />;
  return (
    <span className="inline-flex shrink-0 items-center gap-1.5 text-compact text-muted-foreground">
      <Globe className="h-3.5 w-3.5" aria-hidden="true" />
      global
    </span>
  );
}
