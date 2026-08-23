import { cn } from "@/lib/utils";

/**
 * The jumpgate mark — a portal ring with a jump chevron passing through it
 * (gate + jump + terminal prompt). Drawn in `currentColor` so it inherits the
 * surrounding text/brand color and themes automatically (light/dark). Reads
 * cleanly from 16px (favicon) up. Decorative by default (`aria-hidden`); the
 * accessible name comes from the adjacent wordmark or the caller's label.
 */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("h-6 w-6", className)}
      aria-hidden="true"
      focusable="false"
    >
      {/* Portal ring */}
      <circle
        cx="16"
        cy="16"
        r="12.5"
        stroke="currentColor"
        strokeWidth="2.5"
        opacity="0.9"
      />
      {/* Jump chevron — the prompt breaking through the gate */}
      <path
        d="M12.5 10.5 L18.5 16 L12.5 21.5"
        stroke="currentColor"
        strokeWidth="2.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/**
 * Full brand lockup — mark + "jumpgate" wordmark. Sized via `className` on the
 * wrapper; the mark scales with the font size. Renders as a labelled group so
 * screen readers announce "jumpgate" once (the mark is aria-hidden).
 */
export function Logo({
  className,
  markClassName,
  wordmarkClassName,
}: {
  className?: string;
  markClassName?: string;
  wordmarkClassName?: string;
}) {
  return (
    <span
      className={cn("inline-flex items-center gap-2 text-primary", className)}
      role="img"
      aria-label="jumpgate"
    >
      <LogoMark className={markClassName} />
      <span
        className={cn(
          "font-semibold tracking-tight text-foreground",
          wordmarkClassName,
        )}
      >
        jumpgate
      </span>
    </span>
  );
}
