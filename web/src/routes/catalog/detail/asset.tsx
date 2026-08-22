/**
 * asset.tsx — asset detail pane.
 *
 * Shows the caller's effective access on a single asset: capabilities,
 * active roles, requestable roles, and (when ssh:login:* caps are present)
 * a Connect command block with a copy button.
 *
 * The "Request access" button opens RequestSheet (Task 3).
 */

import { useQuery } from "@connectrpc/connect-query";
import { Server, Copy, Check, Terminal } from "lucide-react";
import { useState, useCallback } from "react";
import { getAssetAccess } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { RequestSheet } from "../request-sheet";
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

// ─── Copy-to-clipboard button ─────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard not available — silently ignore
    }
  }, [text]);

  return (
    <button
      onClick={copy}
      className={cn(
        "flex h-7 w-7 shrink-0 items-center justify-center rounded transition-colors duration-150",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
        copied
          ? "text-green-600 dark:text-green-400"
          : "text-muted-foreground hover:text-foreground",
      )}
      aria-label={copied ? "Copied" : "Copy command"}
    >
      {copied ? (
        <Check className="h-3.5 w-3.5" aria-hidden="true" />
      ) : (
        <Copy className="h-3.5 w-3.5" aria-hidden="true" />
      )}
    </button>
  );
}

// ─── SSH connect block ────────────────────────────────────────────────────────

interface ConnectBlockProps {
  logins: string[];
  assetPath: string;
}

function ConnectBlock({ logins, assetPath }: ConnectBlockProps) {
  if (logins.length === 0 || !assetPath) return null;

  return (
    <DetailSection title="Connect">
      <div className="flex flex-col gap-1.5" role="list" aria-label="Connect commands">
        {logins.map((login) => {
          const cmd = `jumpgate connect ${login}@${assetPath}`;
          return (
            <div
              key={login}
              className="flex items-center gap-2 rounded border border-border bg-muted px-3 py-2"
              role="listitem"
            >
              <Terminal className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
              <code className="flex-1 overflow-x-auto font-mono text-[11px] text-foreground whitespace-nowrap">
                {cmd}
              </code>
              <CopyButton text={cmd} />
            </div>
          );
        })}
      </div>
    </DetailSection>
  );
}

// ─── Asset detail pane ────────────────────────────────────────────────────────

export interface AssetDetailProps {
  id: string;
  name: string;
  path?: string;
  assetKind?: string;
}

export function AssetDetail({ id, name, path, assetKind }: AssetDetailProps) {
  const [sheetOpen, setSheetOpen] = useState(false);

  const { data, isLoading, isError, error } = useQuery(
    getAssetAccess,
    { assetId: id },
  );

  if (isLoading) return <DetailSkeleton />;
  if (isError) return <DetailError error={error} />;
  if (!data) return null;

  const sshLogins = sshLoginsCoveredByCaps(data.capabilities);
  const hasRequestable = data.requestableRoles.length > 0;

  return (
    <article className="flex flex-col gap-5 p-5" aria-label={`Asset: ${name}`}>
      {/* Header */}
      <header className="flex flex-col gap-1">
        <div className="flex items-start gap-2">
          <Server className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <h2 className="text-[15px] font-semibold leading-tight text-foreground">
            {name}
          </h2>
        </div>
        {path && (
          <p className="pl-6 font-mono text-[11px] text-muted-foreground" aria-label="Asset path">
            {path}
          </p>
        )}
        {assetKind && (
          <div className="pl-6">
            <Badge
              variant="secondary"
              className="rounded px-1.5 py-0 text-[10px] font-mono uppercase tracking-wide"
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
          <ConnectBlock logins={sshLogins} assetPath={path ?? ""} />
          <div className="h-px bg-border" role="separator" />
        </>
      )}

      {/* Capabilities */}
      <DetailSection title="Your capabilities on this asset">
        <CapList caps={data.capabilities} />
      </DetailSection>

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
              className="mt-1 h-7 text-[12px]"
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
          <p className="text-[12px] text-muted-foreground italic">
            You have no access or pending requestable roles for this asset.
          </p>
        )}
    </article>
  );
}
