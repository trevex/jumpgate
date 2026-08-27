import type { RequestPolicy } from "@/gen/jumpgate/access/v1/access_pb";

/** Human summary of a policy's rule line (requester/approver/duration). */
export function policyRuleSummary(p: RequestPolicy, requesterRoleName: string, approverRoleName: string): string {
  const bits: string[] = [];
  bits.push(requesterRoleName ? `Requesters: ${requesterRoleName}` : "Requesters: explicit only");
  bits.push(approverRoleName ? `Approvers: ${approverRoleName}` : "Approvers: explicit only");
  const secs = Number(p.maxDurationSeconds ?? 0n);
  if (secs > 0) bits.push(`Max ${formatDuration(secs)}`);
  return bits.join(" · ");
}

/** Compact H/M duration, e.g. 28800 → "8h". */
export function formatDuration(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

/** Label for a role→policy usage tag. */
export function usageLabel(usage: string): string {
  switch (usage) {
    case "requestable": return "Requestable";
    case "requester_source": return "Requester source";
    case "approver_source": return "Approver source";
    default: return usage;
  }
}
