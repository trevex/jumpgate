/**
 * confirm-dialog.tsx — reusable confirmation modal.
 *
 * A shadcn Dialog with a title, description, a confirm button (with an
 * optional destructive variant), and a Cancel. The caller owns the mutation:
 * pass `onConfirm` (fires on the confirm click) and `pending` (disables both
 * buttons + swaps the confirm label to a busy state while the mutation runs).
 * Used across the Directory for Deactivate / Delete confirmations.
 */

import { type ReactNode } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  /** Label shown on the confirm button while `pending` is true. */
  pendingLabel?: string;
  variant?: "default" | "destructive";
  pending?: boolean;
  onConfirm: () => void;
  /** Accessible label for the confirm button (defaults to `confirmLabel`). */
  confirmAriaLabel?: string;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  pendingLabel,
  variant = "default",
  pending = false,
  onConfirm,
  confirmAriaLabel,
}: ConfirmDialogProps) {
  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-[420px]">
        <DialogHeader>
          <DialogTitle className="text-title">{title}</DialogTitle>
          <DialogDescription className="text-body leading-relaxed">
            {description}
          </DialogDescription>
        </DialogHeader>

        <DialogFooter>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onOpenChange(false)}
            disabled={pending}
            className="h-8 text-body"
          >
            Cancel
          </Button>
          <Button
            variant={variant}
            size="sm"
            onClick={onConfirm}
            disabled={pending}
            aria-label={confirmAriaLabel ?? confirmLabel}
            className="h-8 text-body"
          >
            {pending ? (pendingLabel ?? "Working…") : confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
