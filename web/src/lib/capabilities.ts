import { useWhoAmI } from "../auth";

/**
 * capsCover returns true if any held capability pattern covers the wanted
 * capability. Pattern rules (mirrors server-side CapMatch):
 *   "**"           — wildcard: covers everything
 *   exact match    — e.g. "recording:read"
 *   "scope:*"      — single-level glob: covers any "scope:<action>"
 *   "scope:**"     — recursive glob: covers any "scope:<action>[:qualifier]"
 */
export function capsCover(held: string[], want: string): boolean {
  return held.some(
    (p) =>
      p === "**" ||
      p === want ||
      (p.endsWith(":*") && want.startsWith(p.slice(0, -1))) ||
      (p.endsWith(":**") && want.startsWith(p.slice(0, -2))),
  );
}

export function useCapabilities(): string[] {
  return useWhoAmI().data?.capabilities ?? [];
}
