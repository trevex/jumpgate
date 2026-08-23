/**
 * folder-picker.tsx — a reusable folder chooser.
 *
 * A cmdk command dialog that searches the catalog via the visibility-filtered
 * `SearchCatalog` RPC (debounced), filtered to folders, and fires `onSelect`
 * with the chosen folder's `{ id, path }`. Unlike the directory's folder-home
 * picker there is NO "Global"/clear option — this always picks a real folder
 * (e.g. a move destination); any "move to root" affordance is the caller's job.
 */

import { useEffect, useState } from "react";
import { useQuery } from "@connectrpc/connect-query";
import { Folder, Loader2, AlertCircle } from "lucide-react";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@/components/ui/command";
import { searchCatalog } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";

const SEARCH_LIMIT = 20;
const DEBOUNCE_MS = 200;

/** A picked folder — the id is sent to the server, the path is displayed. */
export interface PickedFolder {
  id: string;
  path: string;
}

function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

interface FolderPickerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Fired with the chosen folder. */
  onSelect: (folder: PickedFolder) => void;
}

export function FolderPicker({ open, onOpenChange, onSelect }: FolderPickerProps) {
  const [query, setQuery] = useState("");
  const debounced = useDebounced(query, DEBOUNCE_MS);
  const enabled = debounced.trim().length >= 1;

  // Reset the query each time the dialog opens for a clean slate.
  useEffect(() => {
    if (open) setQuery("");
  }, [open]);

  const { data, isFetching, isError } = useQuery(
    searchCatalog,
    { query: debounced, limit: SEARCH_LIMIT },
    { enabled },
  );

  const folders = (data?.hits ?? []).filter((h) => h.kind === "folder");

  function pick(folder: PickedFolder) {
    onSelect(folder);
    onOpenChange(false);
  }

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      label="Choose a folder"
      // cmdk's built-in fuzzy filter is off — the server already matched.
      commandProps={{ shouldFilter: false }}
    >
      <CommandInput
        placeholder="Search folders…"
        value={query}
        onValueChange={setQuery}
      />
      <CommandList aria-busy={isFetching}>
        {!enabled && <CommandEmpty>Type to search folders.</CommandEmpty>}

        {enabled && isError && (
          <div className="flex items-center justify-center gap-2 py-8 text-sm text-destructive">
            <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>Search failed. Try again.</span>
          </div>
        )}

        {enabled && !isError && isFetching && !data && (
          <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 shrink-0 animate-spin" aria-hidden="true" />
            <span>Searching…</span>
          </div>
        )}

        {enabled && !isError && data && folders.length === 0 && (
          <CommandEmpty>No folders</CommandEmpty>
        )}

        {enabled && !isError && folders.length > 0 && (
          <CommandGroup heading="Folders">
            {folders.map((hit) => (
              <CommandItem
                key={hit.id}
                value={`folder:${hit.id}`}
                onSelect={() => pick({ id: hit.id, path: hit.path || hit.name })}
              >
                <Folder className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                <span className="min-w-0 flex-1 truncate text-foreground">{hit.name}</span>
                {hit.path && (
                  <span className="shrink-0 truncate font-mono text-micro text-muted-foreground">
                    {hit.path}
                  </span>
                )}
              </CommandItem>
            ))}
          </CommandGroup>
        )}
      </CommandList>
    </CommandDialog>
  );
}
