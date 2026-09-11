import { useQuery } from "@tanstack/react-query";

export interface AuthMethods {
  local: boolean;
  oidc: boolean;
}

export function useAuthMethods() {
  return useQuery<AuthMethods>({
    queryKey: ["auth-methods"],
    queryFn: async () => {
      const r = await fetch("/auth/methods", { credentials: "include" });
      if (!r.ok) throw new Error("auth methods");
      return r.json();
    },
    staleTime: 5 * 60 * 1000,
  });
}
