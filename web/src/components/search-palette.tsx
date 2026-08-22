/**
 * search-palette.tsx — ⌘K / Ctrl+K global command palette.
 *
 * Searches the catalog via the visibility-filtered `SearchCatalog` RPC and
 * groups hits by kind (Folders / Assets / Roles / Groups). Selecting a hit
 * closes the palette and deep-links into the Catalog page's detail pane for
 * that node (via the `?sel=` selection param the catalog already consumes).
 *
 * Open-state is controlled by the shell so the header affordance and the global
 * keyboard shortcut share one source of truth.
 */

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@connectrpc/connect-query";
import {
  Folder,
  Server,
  KeyRound,
  Users,
  Loader2,
  AlertCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@/components/ui/command";
import { searchCatalog } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import type { SearchHit } from "@/gen/jumpgate/catalog/v1/catalog_pb";
import { encodeSelection } from "@/routes/catalog/selection";
import {
  groupHitsByKind,
  hasAnyHits,
  hitToSelectedNode,
} from "./search-palette-model";

const SEARCH_LIMIT = 20;
const DEBOUNCE_MS = 200;

// ─── Global ⌘K / Ctrl+K shortcut ─────────────────────────────────────────────

/** Attach a document keydown listener that fires `onOpen` on ⌘K / Ctrl+K. */
export function useCommandK(onOpen: () => void) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpen();
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [onOpen]);
}

// ─── Debounce ────────────────────────────────────────────────────────────────

function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

// ─── Hit row ─────────────────────────────────────────────────────────────────

interface HitRowProps {
  hit: SearchHit;
  icon: LucideIcon;
  onSelect: (hit: SearchHit) => void;
}

function HitRow({ hit, icon: Icon, onSelect }: HitRowProps) {
  return (
    <CommandItem
      // cmdk filters by `value`; disable client filtering (server already
      // matched) by using a stable unique value per hit.
      value={`${hit.kind}:${hit.id}`}
      onSelect={() => onSelect(hit)}
    >
      <Icon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="min-w-0 flex-1 truncate text-foreground">{hit.name}</span>
      {hit.path && (
        <span className="shrink-0 truncate font-mono text-[11px] text-muted-foreground">
          {hit.path}
        </span>
      )}
    </CommandItem>
  );
}

// ─── Palette ─────────────────────────────────────────────────────────────────

interface SearchPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function SearchPalette({ open, onOpenChange }: SearchPaletteProps) {
  const navigate = useNavigate();
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

  const grouped = groupHitsByKind(data?.hits ?? []);

  const handleSelect = (hit: SearchHit) => {
    const node = hitToSelectedNode(hit);
    onOpenChange(false);
    if (node) {
      navigate(`/?sel=${encodeSelection(node)}`);
    }
  };

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      label="Search catalog"
      // cmdk's built-in fuzzy filter is off — the server already matched.
      commandProps={{ shouldFilter: false }}
    >
      <CommandInput
        placeholder="Search folders, assets, roles, groups…"
        value={query}
        onValueChange={setQuery}
      />
      <CommandList aria-busy={isFetching}>
        {!enabled && (
          <CommandEmpty>Type to search the catalog.</CommandEmpty>
        )}

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

        {enabled && !isError && data && !hasAnyHits(grouped) && (
          <CommandEmpty>No matches</CommandEmpty>
        )}

        {enabled && !isError && (
          <>
            {grouped.folders.length > 0 && (
              <CommandGroup heading="Folders">
                {grouped.folders.map((hit) => (
                  <HitRow key={hit.id} hit={hit} icon={Folder} onSelect={handleSelect} />
                ))}
              </CommandGroup>
            )}
            {grouped.assets.length > 0 && (
              <CommandGroup heading="Assets">
                {grouped.assets.map((hit) => (
                  <HitRow key={hit.id} hit={hit} icon={Server} onSelect={handleSelect} />
                ))}
              </CommandGroup>
            )}
            {grouped.roles.length > 0 && (
              <CommandGroup heading="Roles">
                {grouped.roles.map((hit) => (
                  <HitRow key={hit.id} hit={hit} icon={KeyRound} onSelect={handleSelect} />
                ))}
              </CommandGroup>
            )}
            {grouped.groups.length > 0 && (
              <CommandGroup heading="Groups">
                {grouped.groups.map((hit) => (
                  <HitRow key={hit.id} hit={hit} icon={Users} onSelect={handleSelect} />
                ))}
              </CommandGroup>
            )}
          </>
        )}
      </CommandList>
    </CommandDialog>
  );
}
