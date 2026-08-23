/**
 * info-hint.tsx — a small inline "?" affordance for in-context vocabulary help.
 *
 * Renders a muted info icon that reveals a one-line plain-language gloss on
 * hover/focus. Place it next to a section or tab header that introduces a
 * domain concept (Role, Binding, Policy, Grant, …).
 */

import { Info } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

interface InfoHintProps {
  /** The explanatory text shown in the tooltip. */
  children: string;
  /** Short accessible label for the trigger; defaults to "More information". */
  label?: string;
}

export function InfoHint({ children, label = "More information" }: InfoHintProps) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={label}
          className="inline-flex items-center justify-center rounded-full text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1"
        >
          <Info className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-[260px] text-xs">
        {children}
      </TooltipContent>
    </Tooltip>
  );
}
