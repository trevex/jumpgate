/**
 * folder.tsx — folder detail pane.
 *
 * Shows the caller's management capabilities on one folder.
 */

import { useQuery } from "@connectrpc/connect-query";
import { Folder } from "lucide-react";
import { getFolderAccess } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { CapList, DetailSection, DetailSkeleton, DetailError } from "./shared";

export interface FolderDetailProps {
  id: string;
  name: string;
  path?: string;
}

export function FolderDetail({ id, name, path }: FolderDetailProps) {
  const { data, isLoading, isError, error } = useQuery(
    getFolderAccess,
    { folderId: id },
  );

  if (isLoading) return <DetailSkeleton />;
  if (isError) return <DetailError error={error} />;
  if (!data) return null;

  return (
    <article className="flex flex-col gap-5 p-5" aria-label={`Folder: ${name}`}>
      {/* Header */}
      <header className="flex flex-col gap-1">
        <div className="flex items-start gap-2">
          <Folder className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <h2 className="text-[15px] font-semibold leading-tight text-foreground">
            {name}
          </h2>
        </div>
        {path && (
          <p className="pl-6 font-mono text-[11px] text-muted-foreground" aria-label="Folder path">
            {path}
          </p>
        )}
      </header>

      <div className="h-px bg-border" role="separator" />

      {/* Management capabilities */}
      <DetailSection title="Your management capabilities on this folder">
        <CapList caps={data.capabilities} />
      </DetailSection>
    </article>
  );
}
