/**
 * shared.tsx — shared primitives for all detail panes.
 *
 * Keeps CapList, error/loading helpers, and section containers in one place
 * so each detail pane stays thin.
 */

import { Skeleton } from "@/components/ui/skeleton";
import { AlertCircle, Lock } from "lucide-react";
import { Code, ConnectError } from "@connectrpc/connect";
import { cn } from "@/lib/utils";

// ─── Capability badge list ────────────────────────────────────────────────────

interface CapListProps {
  caps: string[];
  className?: string;
}

export function CapList({ caps, className }: CapListProps) {
  if (caps.length === 0) {
    return (
      <p className="text-[12px] text-muted-foreground italic">None</p>
    );
  }
  return (
    <ul className={cn("flex flex-wrap gap-1.5", className)} aria-label="Capabilities">
      {caps.map((cap) => (
        <li key={cap}>
          <span className="inline-flex items-center rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] text-foreground">
            {cap}
          </span>
        </li>
      ))}
    </ul>
  );
}

// ─── Section wrapper ──────────────────────────────────────────────────────────

interface DetailSectionProps {
  title: string;
  children: React.ReactNode;
  className?: string;
}

export function DetailSection({ title, children, className }: DetailSectionProps) {
  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <h3 className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        {title}
      </h3>
      {children}
    </div>
  );
}

// ─── Loading skeleton ─────────────────────────────────────────────────────────

export function DetailSkeleton() {
  return (
    <div className="flex flex-col gap-5 p-5" aria-busy="true" aria-label="Loading">
      <div className="flex flex-col gap-2">
        <Skeleton className="h-6 w-48 rounded" />
        <Skeleton className="h-4 w-64 rounded" />
      </div>
      <div className="flex flex-col gap-2">
        <Skeleton className="h-3 w-24 rounded" />
        <div className="flex flex-wrap gap-1.5">
          <Skeleton className="h-5 w-20 rounded" />
          <Skeleton className="h-5 w-28 rounded" />
          <Skeleton className="h-5 w-16 rounded" />
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <Skeleton className="h-3 w-20 rounded" />
        <Skeleton className="h-5 w-32 rounded" />
        <Skeleton className="h-5 w-24 rounded" />
      </div>
    </div>
  );
}

// ─── Error states ─────────────────────────────────────────────────────────────

interface DetailErrorProps {
  error: unknown;
}

export function DetailError({ error }: DetailErrorProps) {
  const ce = ConnectError.from(error);

  if (ce.code === Code.NotFound || ce.code === Code.PermissionDenied) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 p-10 text-center">
        <Lock className="h-10 w-10 text-muted-foreground/40" aria-hidden="true" />
        <div>
          <p className="text-[13px] font-medium text-foreground">
            Access restricted
          </p>
          <p className="mt-1 text-[12px] text-muted-foreground">
            You don't have access to view this item.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center gap-3 p-10 text-center">
      <AlertCircle className="h-10 w-10 text-destructive/60" aria-hidden="true" />
      <div>
        <p className="text-[13px] font-medium text-foreground">Something went wrong</p>
        <p className="mt-1 text-[11px] font-mono text-muted-foreground">{ce.message}</p>
      </div>
    </div>
  );
}

// ─── Role name pill ───────────────────────────────────────────────────────────

interface RoleNameProps {
  name: string;
  folderPath?: string;
}

export function RolePill({ name, folderPath }: RoleNameProps) {
  const label = folderPath ? `${name}.${folderPath}` : name;
  return (
    <span className="inline-flex items-center rounded border border-border bg-muted px-2 py-0.5 text-[11px] font-medium text-foreground">
      {label}
    </span>
  );
}
