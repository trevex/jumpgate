import { Boxes, Database, Server } from "lucide-react";
import type { LucideIcon } from "lucide-react";

/**
 * The lucide icon for an asset kind: database for postgres, a cluster of boxes
 * for kubernetes (kind "k8s"), server otherwise.
 */
export function assetKindIcon(kind: string | undefined): LucideIcon {
  if (kind === "postgres") return Database;
  if (kind === "k8s") return Boxes;
  return Server;
}
