import { type ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useQuery } from "@connectrpc/connect-query";
import { whoAmI } from "./gen/jumpgate/auth/v1/auth-AuthService_connectquery";

export function useWhoAmI() {
  return useQuery(whoAmI, {});
}

interface RequireAuthProps {
  children: ReactNode;
}

export function RequireAuth({ children }: RequireAuthProps) {
  const { data, error, isPending } = useWhoAmI();

  if (isPending) {
    return null;
  }

  if (error != null || data == null) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}
