/**
 * copy-button.tsx — a small copy-to-clipboard button.
 *
 * Writes `text` to the clipboard on click and briefly swaps its icon to a
 * check mark for confirmation. Renders in two sizes: "sm" (compact inline use)
 * and "md" (slightly larger, e.g. next to a command block).
 */

import { useState, useCallback } from "react";
import { Copy, Check } from "lucide-react";
import { cn } from "@/lib/utils";

interface CopyButtonProps {
  /** The text copied to the clipboard on click. */
  text: string;
  /** Accessible label shown before copying; defaults to "Copy". */
  label?: string;
  /** Visual size — "sm" (default) or "md". */
  size?: "sm" | "md";
}

export function CopyButton({ text, label = "Copy", size = "sm" }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard not available — silently ignore
    }
  }, [text]);

  const Icon = copied ? Check : Copy;

  return (
    <button
      onClick={copy}
      className={cn(
        "flex shrink-0 items-center justify-center rounded transition-colors duration-150",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
        size === "sm" ? "h-6 w-6" : "h-7 w-7",
        copied
          ? size === "sm"
            ? "text-success-fg"
            : "text-green-600 dark:text-green-400"
          : "text-muted-foreground hover:text-foreground",
      )}
      aria-label={copied ? "Copied" : label}
    >
      <Icon
        className={cn(size === "sm" ? "h-3 w-3" : "h-3.5 w-3.5")}
        aria-hidden="true"
      />
    </button>
  );
}
