import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { AlertCircle, Loader2 } from "lucide-react";
import { login } from "../gen/jumpgate/auth/v1/auth-AuthService_connectquery";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Logo } from "@/components/brand/logo";
import { connectErrorMessage } from "@/lib/format";
import { useAuthMethods } from "@/authMethods";

export function LoginPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const { data: authMethods } = useAuthMethods();
  const oidcEnabled = authMethods?.oidc === true;

  const { mutate, isPending, error } = useMutation(login, {
    onSuccess: () => {
      queryClient.invalidateQueries();
      navigate("/");
    },
  });


  return (
    <div className="flex min-h-dvh items-center justify-center bg-background px-4 py-10">
      <div className="w-full max-w-[400px]">
        {/* Brand lockup */}
        <div className="mb-6 flex justify-center">
          <Logo markClassName="h-7 w-7" wordmarkClassName="text-xl" />
        </div>

        {/* Auth card */}
        <div className="rounded-lg border border-border bg-card p-6 shadow-sm sm:p-8">
          <div className="mb-6 space-y-1">
            <h1 className="text-lg font-semibold tracking-tight text-card-foreground">
              Sign in
            </h1>
            <p className="text-sm text-muted-foreground">
              Access the jumpgate console
            </p>
          </div>

          {error != null && (
            <div
              role="alert"
              className="mb-5 flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive"
            >
              <AlertCircle
                className="mt-0.5 h-4 w-4 shrink-0"
                aria-hidden="true"
              />
              <span>{connectErrorMessage(error)}</span>
            </div>
          )}

          {oidcEnabled && (
            <Button asChild className="w-full">
              <a href="/auth/oidc/login">Sign in with SSO</a>
            </Button>
          )}

          <PasswordForm
            email={email}
            password={password}
            isPending={isPending}
            onEmailChange={setEmail}
            onPasswordChange={setPassword}
            onSubmit={() => mutate({ email, password, cookieOnly: true })}
            demoted={oidcEnabled}
          />
        </div>
      </div>
    </div>
  );
}

interface PasswordFormProps {
  email: string;
  password: string;
  isPending: boolean;
  onEmailChange: (v: string) => void;
  onPasswordChange: (v: string) => void;
  onSubmit: () => void;
  /** Render inside a disclosure, below a primary SSO action. */
  demoted: boolean;
}

function PasswordForm({
  email,
  password,
  isPending,
  onEmailChange,
  onPasswordChange,
  onSubmit,
  demoted,
}: PasswordFormProps) {
  const form = (
    <form
      onSubmit={(e) => {
        // Event type inferred from the prop — React 19's types deprecate the
        // named FormEvent/FormEventHandler aliases.
        e.preventDefault();
        onSubmit();
      }}
      className="space-y-4"
    >
      <div className="space-y-1.5">
        <label
          htmlFor="login-email"
          className="text-sm font-medium text-foreground"
        >
          Email
        </label>
        <Input
          id="login-email"
          aria-label="email"
          type="email"
          autoComplete="email"
          autoFocus={!demoted}
          required
          value={email}
          onChange={(e) => onEmailChange(e.target.value)}
        />
      </div>

      <div className="space-y-1.5">
        <label
          htmlFor="login-password"
          className="text-sm font-medium text-foreground"
        >
          Password
        </label>
        <Input
          id="login-password"
          aria-label="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => onPasswordChange(e.target.value)}
        />
      </div>

      <Button
        type="submit"
        className="w-full"
        disabled={isPending}
        aria-busy={isPending}
      >
        {isPending && (
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
        )}
        Sign in
      </Button>
    </form>
  );

  if (!demoted) {
    return form;
  }

  return (
    <details className="mt-6 border-t border-border pt-4">
      <summary className="cursor-pointer select-none text-sm font-medium text-muted-foreground hover:text-foreground">
        Break-glass sign-in
      </summary>
      <div className="mt-4">{form}</div>
    </details>
  );
}
