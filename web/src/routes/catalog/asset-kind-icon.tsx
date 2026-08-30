import { Database, Server } from "lucide-react";
import type { LucideIcon } from "lucide-react";

/** The lucide icon for an asset kind: database for postgres, server otherwise. */
export function assetKindIcon(kind: string | undefined): LucideIcon {
  return kind === "postgres" ? Database : Server;
}
