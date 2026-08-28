import type { RosterNode } from "@/gen/jumpgate/access/v1/access_pb";

export interface RosterNodeLabel {
  /** Primary label: display name or a short id fallback. */
  name: string;
  /** "user" | "group". */
  kind: string;
  /** Secondary line, e.g. "3 members · via eng-oncall" or "explicit". */
  detail: string;
  /** Whether to visually flag an inactive user. */
  inactive: boolean;
}

/** Human label for one roster node. Pure; unit-tested. */
export function rosterNodeLabel(node: RosterNode): RosterNodeLabel {
  const name = node.displayName || node.subjectId.slice(0, 8);
  const bits: string[] = [];
  if (node.subjectKind === "group") {
    bits.push(`${node.groupMemberCount} member${node.groupMemberCount === 1 ? "" : "s"}`);
  }
  bits.push(node.source === "via_role" ? `via ${node.viaRoleName || "role"}` : "explicit");
  return {
    name,
    kind: node.subjectKind,
    detail: bits.join(" · "),
    inactive: node.subjectKind === "user" && !node.active,
  };
}
