import { type ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useWhoAmI } from "../auth";

/**
 * capMatch mirrors the server's CapMatch segment semantics (warden authz):
 * split on ":"; "**" matches the entire remainder; "*" matches EXACTLY one
 * segment; any other segment must match exactly; and with no "**" the segment
 * counts must be equal. So "recording:*" does NOT cover "recording:read:exempt"
 * (2 vs 3 segments), matching the server — a plain startsWith would over-match.
 */
function capMatch(pat: string[], want: string[]): boolean {
  for (let i = 0; i < pat.length; i++) {
    if (pat[i] === "**") return true;
    if (i >= want.length) return false;
    if (pat[i] === "*") continue;
    if (pat[i] !== want[i]) return false;
  }
  return pat.length === want.length;
}

/**
 * capsCover returns true if any held capability pattern covers the wanted
 * (concrete) capability, using the same glob semantics as the server.
 */
export function capsCover(held: string[], want: string): boolean {
  const w = want.split(":");
  return held.some((p) => capMatch(p.split(":"), w));
}

export function useCapabilities(): string[] {
  return useWhoAmI().data?.capabilities ?? [];
}

/**
 * RequireCap guards a route: if the caller lacks `cap`, redirect home. Nav items
 * are hidden by capability too, but routes must be guarded so a hidden section
 * can't be reached by typing its URL.
 */
export function RequireCap({ cap, children }: { cap: string; children: ReactNode }) {
  if (!capsCover(useCapabilities(), cap)) return <Navigate to="/" replace />;
  return <>{children}</>;
}

/**
 * RequireAnyCap guards a route that is reachable by holders of ANY of several
 * caps (OR). Used where a section aggregates multiple resources — e.g. the
 * Directory needs either `identity:user:read` or `identity:group:read`.
 */
export function RequireAnyCap({ caps, children }: { caps: string[]; children: ReactNode }) {
  const held = useCapabilities();
  if (!caps.some((cap) => capsCover(held, cap))) return <Navigate to="/" replace />;
  return <>{children}</>;
}
