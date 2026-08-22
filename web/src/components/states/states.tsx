/**
 * states.tsx — shared presentational empty / error / loading states.
 *
 * These consolidate the empty/error/skeleton patterns that were hand-rolled
 * per route (access, approvals, recordings, catalog tree). They are purely
 * presentational: callers pass their own copy and icon, and wire retry to
 * their own refetch. Token-styled so they render correctly in light and dark.
 */

import type { ComponentType } from "react";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

type IconType = ComponentType<{ className?: string }>;

// ─── EmptyState ───────────────────────────────────────────────────────────────

export interface EmptyStateProps {
  /** Illustrative icon (rendered muted, decorative). */
  icon: IconType;
  /** Primary line — a short, bold headline. Optional. */
  title?: string;
  /** Supporting message. */
  message: string;
  /** Vertical padding tier; matches the varying densities across routes. */
  size?: "sm" | "md" | "lg";
  className?: string;
}

const EMPTY_PADDING: Record<NonNullable<EmptyStateProps["size"]>, string> = {
  sm: "py-12",
  md: "py-16",
  lg: "py-20",
};

const EMPTY_ICON: Record<NonNullable<EmptyStateProps["size"]>, string> = {
  sm: "h-10 w-10",
  md: "h-10 w-10",
  lg: "h-12 w-12",
};

export function EmptyState({
  icon: Icon,
  title,
  message,
  size = "md",
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 text-center",
        EMPTY_PADDING[size],
        className,
      )}
    >
      <Icon className={cn(EMPTY_ICON[size], "text-muted-foreground/25")} aria-hidden="true" />
      {title && <p className="text-[14px] font-medium text-foreground">{title}</p>}
      <p className="max-w-xs text-[13px] text-muted-foreground">{message}</p>
    </div>
  );
}

// ─── ErrorState ───────────────────────────────────────────────────────────────

export interface ErrorStateProps {
  /** Human-readable error message. */
  message: string;
  /** Optional retry handler; when set, a Retry button is shown. */
  onRetry?: () => void;
  /** Optional icon (rendered in the destructive tint) above the message. */
  icon?: IconType;
  size?: "sm" | "md" | "lg";
  className?: string;
}

const ERROR_PADDING: Record<NonNullable<ErrorStateProps["size"]>, string> = {
  sm: "py-12",
  md: "py-16",
  lg: "py-20",
};

export function ErrorState({
  message,
  onRetry,
  icon: Icon,
  size = "md",
  className,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center gap-3 text-center",
        ERROR_PADDING[size],
        className,
      )}
    >
      {Icon && <Icon className="h-8 w-8 text-destructive/60" aria-hidden="true" />}
      <p className="max-w-sm text-[13px] text-muted-foreground">{message}</p>
      {onRetry && (
        <Button
          variant="outline"
          size="sm"
          onClick={onRetry}
          className="h-7 gap-1.5 text-[12px]"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
          Retry
        </Button>
      )}
    </div>
  );
}

// ─── LoadingRows ──────────────────────────────────────────────────────────────

export interface LoadingRowsProps {
  /** Number of skeleton rows. */
  count?: number;
  /** Accessible name for the busy region. */
  label?: string;
  className?: string;
}

/**
 * A stack of skeleton rows for list/table loading. Carries aria-busy + a label
 * so assistive tech announces the region as loading.
 */
export function LoadingRows({
  count = 4,
  label = "Loading",
  className,
}: LoadingRowsProps) {
  return (
    <div
      className={cn("flex flex-col divide-y divide-border", className)}
      aria-busy="true"
      aria-label={label}
    >
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="flex items-center gap-3 px-4 py-3">
          <Skeleton className="h-4 w-28 rounded" />
          <Skeleton className="h-4 w-20 rounded" />
          <Skeleton className="h-4 w-12 rounded" />
          <Skeleton className="h-4 flex-1 rounded" />
        </div>
      ))}
    </div>
  );
}
