/**
 * new-user-dialog.tsx — Directory ▸ Users ▸ create.
 *
 * A shadcn Dialog with Email / Display name / Password inputs. Client
 * validation mirrors the server's protovalidate constraints (valid email;
 * display name 1–200 chars; password ≥ 8) and the submit button stays
 * disabled until the form is valid. On success: toast + invalidate `listUsers`
 * (scoped) so the tab re-seeds with the new user, then close and reset. On
 * error: surface `connectErrorMessage(err)` via toast (the server is the real
 * gate — e.g. AlreadyExists for a duplicate email).
 */

import { useState } from "react";
import { useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import {
  createUser,
  listUsers,
} from "@/gen/jumpgate/identity/v1/identity-IdentityService_connectquery";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { connectErrorMessage } from "@/lib/format";
import { useInvalidateList } from "@/lib/query";
import {
  isValidEmail,
  isValidDisplayName,
  isValidPassword,
  isValidNewUser,
} from "./user-actions";

interface NewUserDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const FIELD_LABEL =
  "text-micro font-semibold uppercase tracking-wide text-muted-foreground";
const FIELD_HINT = "text-micro text-muted-foreground";
const FIELD_ERROR = "text-micro text-destructive";

export function NewUserDialog({ open, onOpenChange }: NewUserDialogProps) {
  const invalidateList = useInvalidateList();

  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  // Track which fields have been blurred so errors only show after interaction.
  const [touched, setTouched] = useState({
    email: false,
    displayName: false,
    password: false,
  });

  function reset() {
    setEmail("");
    setDisplayName("");
    setPassword("");
    setTouched({ email: false, displayName: false, password: false });
  }

  const { mutate: doCreate, isPending } = useMutation(createUser, {
    onSuccess: () => {
      toast.success("User created", {
        description: `${email.trim()} was added to the directory.`,
      });
      void invalidateList(listUsers);
      reset();
      onOpenChange(false);
    },
    onError: (err) => {
      toast.error("Create failed", { description: connectErrorMessage(err) });
    },
  });

  const emailValid = isValidEmail(email);
  const nameValid = isValidDisplayName(displayName);
  const passwordValid = isValidPassword(password);
  const formValid = isValidNewUser({ email, displayName, password });

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    if (!next) reset();
    onOpenChange(next);
  }

  // Event type inferred from the JSX onSubmit prop — React 19's types deprecate
  // the named FormEvent alias.
  function handleSubmit(e: { preventDefault: () => void }) {
    e.preventDefault();
    if (!formValid || isPending) return;
    doCreate({
      email: email.trim(),
      displayName: displayName.trim(),
      password,
    });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[440px]">
        <DialogHeader>
          <DialogTitle className="text-title">New user</DialogTitle>
          <DialogDescription className="text-body">
            Create a directory account. The user signs in with the email and
            password you set here.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {/* Email */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-user-email" className={FIELD_LABEL}>
              Email
            </label>
            <Input
              id="new-user-email"
              type="email"
              autoComplete="off"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, email: true }))}
              placeholder="user@example.com"
              className="h-9 text-body"
              aria-invalid={touched.email && !emailValid}
              aria-describedby="new-user-email-error"
            />
            {touched.email && !emailValid && (
              <p id="new-user-email-error" role="alert" className={FIELD_ERROR}>
                Enter a valid email address.
              </p>
            )}
          </div>

          {/* Display name */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-user-name" className={FIELD_LABEL}>
              Display name
            </label>
            <Input
              id="new-user-name"
              type="text"
              autoComplete="off"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, displayName: true }))}
              placeholder="Ada Lovelace"
              className="h-9 text-body"
              aria-invalid={touched.displayName && !nameValid}
              aria-describedby="new-user-name-error"
            />
            {touched.displayName && !nameValid && (
              <p id="new-user-name-error" role="alert" className={FIELD_ERROR}>
                Display name must be 1–200 characters.
              </p>
            )}
          </div>

          {/* Password */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="new-user-password" className={FIELD_LABEL}>
              Password
            </label>
            <Input
              id="new-user-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, password: true }))}
              placeholder="At least 8 characters"
              className="h-9 text-body"
              aria-invalid={touched.password && !passwordValid}
              aria-describedby="new-user-password-error"
            />
            {touched.password && !passwordValid ? (
              <p id="new-user-password-error" role="alert" className={FIELD_ERROR}>
                Password must be at least 8 characters.
              </p>
            ) : (
              <p id="new-user-password-error" className={FIELD_HINT}>
                Minimum 8 characters.
              </p>
            )}
          </div>

          <DialogFooter className="mt-1">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => handleOpenChange(false)}
              disabled={isPending}
              className="h-8 text-body"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={!formValid || isPending}
              className="h-8 text-body"
            >
              {isPending ? "Creating…" : "Create user"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
