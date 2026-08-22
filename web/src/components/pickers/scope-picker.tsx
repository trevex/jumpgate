/**
 * scope-picker.tsx — shared cmdk scope (Global | Folder | Asset) selector.
 *
 * A CommandDialog with a Global | Folder | Asset segmented toggle:
 *   - Global → one always-available item; picks the unscoped (global) scope.
 *   - Folder → debounced `searchCatalog` filtered to folders.
 *   - Asset  → debounced `searchCatalog` filtered to assets.
 *
 * Fires `onSelect` with a `PickedScope` discriminated by `kind`, then closes.
 * The single scope-result contract shared by Access-control (bindings, policy
 * scope). The server already matched, so cmdk's client filter is off.
 */

import { useEffect, useState } from "react";
import { useQuery } from "@connectrpc/connect-query";
import {
  Globe,
  Folder,
  Boxes,
  Loader2,
  AlertCircle,
} from "lucide-react";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@/components/ui/command";
import { searchCatalog } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { cn } from "@/lib/utils";

const SEARCH_LIMIT = 20;
const DEBOUNCE_MS = 200;

/** A picked scope — global, or a folder / asset identified by id + display path. */
export type PickedScope =
  | { kind: "global" }
  | { kind: "folder"; id: string; path: string }
  | { kind: "asset"; id: string; path: string };

type CatalogKind = "folder" | "asset";

interface ScopePickerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Fired with the chosen scope, then the dialog closes. */
  onSelect: (scope: PickedScope) => void;
}

function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

export function ScopePicker({ open, onOpenChange, onSelect }: ScopePickerProps) {
  const [kind, setKind] = useState<CatalogKind>("folder");
  const [query, setQuery] = useState("");

  // Reset each time the dialog opens for a clean slate.
  useEffect(() => {
    if (open) {
      setKind("folder");
      setQuery("");
    }
  }, [open]);

  function pick(scope: PickedScope) {
    onSelect(scope);
    onOpenChange(false);
  }

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      label="Choose a scope"
      // cmdk's built-in fuzzy filter is off — the server already matched.
      commandProps={{ shouldFilter: false }}
    >
      <div
        className="flex items-center gap-1 border-b border-border px-3 py-2"
        role="tablist"
        aria-label="Scope kind"
      >
        <KindToggle
          active={kind === "folder"}
          onClick={() => setKind("folder")}
          icon={Folder}
          label="Folder"
        />
        <KindToggle
          active={kind === "asset"}
          onClick={() => setKind("asset")}
          icon={Boxes}
          label="Asset"
        />
      </div>

      <CommandInput
        placeholder={kind === "folder" ? "Search folders…" : "Search assets…"}
        value={query}
        onValueChange={setQuery}
      />

      <CatalogOptions kind={kind} query={query} onPick={pick} />
    </CommandDialog>
  );
}

// ─── Segmented toggle button ──────────────────────────────────────────────────

function KindToggle({
  active,
  onClick,
  icon: Icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: typeof Folder;
  label: string;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[12px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        active
          ? "bg-accent text-accent-foreground"
          : "text-muted-foreground hover:text-foreground",
      )}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {label}
    </button>
  );
}

// ─── Catalog options (debounced searchCatalog, filtered to kind) ──────────────

function CatalogOptions({
  kind,
  query,
  onPick,
}: {
  kind: CatalogKind;
  query: string;
  onPick: (scope: PickedScope) => void;
}) {
  const debounced = useDebounced(query, DEBOUNCE_MS);
  const enabled = debounced.trim().length >= 1;

  const { data, isFetching, isError } = useQuery(
    searchCatalog,
    { query: debounced, limit: SEARCH_LIMIT },
    { enabled },
  );

  const hits = (data?.hits ?? []).filter((h) => h.kind === kind);
  const Icon = kind === "folder" ? Folder : Boxes;
  const noun = kind === "folder" ? "folders" : "assets";

  return (
    <CommandList aria-busy={isFetching}>
      {/* Always-available Global option — clears the scope. */}
      <CommandGroup heading="Scope">
        <CommandItem value="__global__" onSelect={() => onPick({ kind: "global" })}>
          <Globe className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <span className="min-w-0 flex-1 truncate text-foreground">
            Global (no scope)
          </span>
        </CommandItem>
      </CommandGroup>

      {!enabled && <CommandEmpty>Type to search {noun}.</CommandEmpty>}

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

      {enabled && !isError && data && hits.length === 0 && (
        <CommandEmpty>No {noun}.</CommandEmpty>
      )}

      {enabled && !isError && hits.length > 0 && (
        <CommandGroup heading={kind === "folder" ? "Folders" : "Assets"}>
          {hits.map((hit) => (
            <CommandItem
              key={hit.id}
              value={`${kind}:${hit.id}`}
              onSelect={() =>
                onPick({ kind, id: hit.id, path: hit.path || hit.name })
              }
            >
              <Icon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate text-foreground">{hit.name}</span>
              {hit.path && (
                <span className="shrink-0 truncate font-mono text-[11px] text-muted-foreground">
                  {hit.path}
                </span>
              )}
            </CommandItem>
          ))}
        </CommandGroup>
      )}
    </CommandList>
  );
}
