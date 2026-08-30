/**
 * enrollment-token-dialog.tsx — mint + reveal a k8s agent enrollment token.
 *
 * A self-minting reveal keyed on `assetId`: while `open`, it calls
 * `createEnrollmentToken` once and walks {minting → reveal | error}. The token
 * is a single-use credential shown ONCE — it's copyable and warns it won't
 * reappear. Reused by the new-asset wizard (post-create) and the asset detail
 * page (re-enroll). We deliberately don't auto-close on outside click while the
 * token is visible so it can't be dismissed before the user copies it.
 */

import { useEffect } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { KeyRound, TriangleAlert } from "lucide-react";
import { createEnrollmentToken } from "@/gen/jumpgate/enrollment/v1/enrollment-EnrollmentService_connectquery";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/copy-button";
import { connectErrorMessage, timeRemaining } from "@/lib/format";

interface EnrollmentTokenRevealProps {
  assetId: string;
  assetName: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function EnrollmentTokenReveal({
  assetId,
  assetName,
  open,
  onOpenChange,
}: EnrollmentTokenRevealProps) {
  const { mutate, data, isPending, isError, error, reset } = useMutation(
    createEnrollmentToken,
  );

  // Mint once per open. Reset on close so re-opening yields a fresh token
  // (each is single-use) rather than re-showing a stale one.
  useEffect(() => {
    if (open && !data && !isPending && !isError) {
      mutate({ assetId });
    }
    if (!open) reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, assetId]);

  const showingToken = Boolean(data);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="sm:max-w-[520px]"
        // While the one-time token is on screen, block every accidental dismissal
        // — outside click, Escape, and the built-in ✕ — so the user must copy it
        // and close deliberately via the Done button.
        hideClose={showingToken}
        onInteractOutside={(e) => {
          if (showingToken) e.preventDefault();
        }}
        onEscapeKeyDown={(e) => {
          if (showingToken) e.preventDefault();
        }}
      >
        <DialogHeader>
          <DialogTitle className="text-title">Enrollment token</DialogTitle>
          <DialogDescription className="text-body">
            One-time token for the in-cluster agent of{" "}
            <span className="font-mono text-compact">{assetName}</span>. The
            agent presents it once to obtain its mesh identity.
          </DialogDescription>
        </DialogHeader>

        {isPending && (
          <p className="py-6 text-center text-body text-muted-foreground">
            Minting token…
          </p>
        )}

        {isError && (
          <div className="flex flex-col gap-2">
            <p role="alert" className="text-body text-destructive">
              {connectErrorMessage(error)}
            </p>
            <p className="text-micro text-muted-foreground">
              The asset was created — you can generate a token later from this
              asset&rsquo;s page or with{" "}
              <span className="font-mono text-compact">
                jumpgate assets k8s enroll &lt;path&gt;
              </span>
              .
            </p>
          </div>
        )}

        {data && (
          <div className="flex flex-col gap-3">
            <div className="flex items-start gap-2 rounded border border-warning-border bg-warning-bg px-3 py-2 text-warning-fg">
              <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span className="text-micro">
                Copy this now — it won&rsquo;t be shown again.
              </span>
            </div>

            <div className="flex items-center gap-2 rounded border border-border bg-muted px-3 py-2">
              <KeyRound className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
              <code className="flex-1 overflow-x-auto font-mono text-micro text-foreground">
                {data.token}
              </code>
              <CopyButton text={data.token} label="Copy token" size="md" />
            </div>

            {data.expiresAt && (
              <p className="text-micro text-muted-foreground">
                Expires in {timeRemaining(data.expiresAt)}.
              </p>
            )}
          </div>
        )}

        <DialogFooter className="mt-1">
          <Button
            type="button"
            size="sm"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
            className="h-8 text-body"
          >
            Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
