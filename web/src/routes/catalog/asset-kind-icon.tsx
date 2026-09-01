import { Boxes, Database, Monitor, Server } from "lucide-react";
import type { LucideIcon } from "lucide-react";

/**
 * The lucide icon for an asset kind: database for postgres, a cluster of boxes
 * for kubernetes (kind "k8s"), a monitor for rdp, server otherwise.
 */
export function assetKindIcon(kind: string | undefined): LucideIcon {
  if (kind === "postgres") return Database;
  if (kind === "k8s") return Boxes;
  if (kind === "rdp") return Monitor;
  return Server;
}
