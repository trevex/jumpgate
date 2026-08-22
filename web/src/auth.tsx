import { type ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useQuery } from "@connectrpc/connect-query";
import { Loader2, ShieldCheck } from "lucide-react";
import { whoAmI } from "./gen/jumpgate/auth/v1/auth-AuthService_connectquery";

export function useWhoAmI() {
  return useQuery(whoAmI, {});
}

/**
 * Branded full-screen loader shown while the initial WhoAmI resolves, so the
 * first paint is the jumpgate lockup rather than a blank frame. Token-styled
 * for light + dark.
 */
function AuthLoading() {
  return (
    <div
      className="flex min-h-dvh flex-col items-center justify-center gap-4 bg-background"
      aria-busy="true"
      aria-label="Loading"
    >
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-7 w-7 text-primary" aria-hidden="true" />
        <span className="text-xl font-semibold tracking-tight text-foreground">
          jumpgate
        </span>
      </div>
      <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" aria-hidden="true" />
    </div>
  );
}

interface RequireAuthProps {
  children: ReactNode;
}

export function RequireAuth({ children }: RequireAuthProps) {
  const { data, error, isPending } = useWhoAmI();

  if (isPending) {
    return <AuthLoading />;
  }

  if (error != null || data == null) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}
