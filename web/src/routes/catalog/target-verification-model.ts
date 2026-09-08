/**
 * target-verification-model.ts — pure view-model for target-identity approval.
 *
 * Maps the durable server facts (VerificationStatus, ProbeJob state/failure,
 * TrustAnchor rows) onto the copy, severity, and permitted actions the wizard
 * step and the asset detail card render. It is deliberately PURE — no React, no
 * network, `now` is passed in — so every state is unit-testable and no state
 * can fall through to a blank/unsafe default (see the exhaustive tests).
 *
 * Safety: it only ever renders public, non-secret material (fingerprints,
 * algorithms, principals, sanitized failure categories). Raw error detail from
 * the server is never surfaced here.
 */

import {
  VerificationStatus,
  ProbeState,
  FailureCategory,
  TrustAnchorKind,
  TrustSource,
  EvidenceKind,
} from "@/gen/jumpgate/targetidentity/v1/targetidentity_pb";

// ─── View shape ─────────────────────────────────────────────────────────────

export type Severity = "pending" | "info" | "success" | "warning" | "error";

export type VerificationAction =
  | "approve"
  | "reject"
  | "retry"
  | "inspect"
  | "finish-later";

export interface VerificationView {
  heading: string;
  severity: Severity;
  /** Safe, public-facing explanation. Never raw error detail or secrets. */
  detail: string;
  /** What the operator should do next, when there is a concrete next step. */
  remediation?: string;
  /** Affordances to offer, already filtered by the caller's capabilities. */
  actions: VerificationAction[];
}

export interface VerificationInput {
  status: VerificationStatus;
  /** Latest relevant probe — drives failure copy and progress. */
  probe?: { state: ProbeState; failureCategory: FailureCategory } | null;
  /** Caller holds catalog:asset:identity:approve on this asset. */
  canApprove: boolean;
  /** Caller holds catalog:asset:probe on this asset. */
  canProbe: boolean;
}

// "Finish later" is always offered so no verification step is a dead end; the
// pending asset stays durable and resumable from the detail page.
const FINISH_LATER: VerificationAction[] = ["finish-later"];

export function verificationView(input: VerificationInput): VerificationView {
  const { status, probe, canApprove, canProbe } = input;

  switch (status) {
    case VerificationStatus.PENDING_VERIFICATION:
      return {
        heading: "Probing target identity",
        severity: "pending",
        detail:
          "Jumpgate is connecting to the endpoint from a worker to observe its identity. This runs durably — you can leave and come back.",
        actions: [...FINISH_LATER],
      };

    case VerificationStatus.PROBE_FAILED: {
      const f = failureText(probe?.failureCategory ?? FailureCategory.UNSPECIFIED);
      return {
        heading: "Couldn't verify the target",
        severity: "error",
        detail: f.summary,
        remediation: f.remediation,
        actions: [...(canProbe ? (["retry"] as const) : []), ...FINISH_LATER],
      };
    }

    case VerificationStatus.AWAITING_APPROVAL:
      if (!canApprove) {
        // A creator without approval authority: the asset exists and its
        // observation is queued for an authorized administrator to approve.
        return {
          heading: "Awaiting identity approval",
          severity: "info",
          detail:
            "Asset created; awaiting identity approval. An administrator with approval authority must compare the observed identity with a trusted source before this asset can be used.",
          actions: ["inspect", ...FINISH_LATER],
        };
      }
      return {
        heading: "Compare and approve the observed identity",
        severity: "warning",
        detail:
          "Jumpgate reached this endpoint. Compare the observed identity with a trusted source before approving it — reachability alone does not prove identity.",
        actions: ["approve", "reject", "inspect", ...FINISH_LATER],
      };

    case VerificationStatus.VERIFIED:
      return {
        heading: "Identity verified",
        severity: "success",
        detail:
          "The target's observed identity matches an approved trust anchor. Sessions to this asset can authenticate the target.",
        actions: ["inspect", ...FINISH_LATER],
      };

    case VerificationStatus.IDENTITY_CHANGED:
      return {
        heading: "Target identity changed",
        severity: "error",
        detail:
          "The endpoint is presenting an identity that no active trust anchor matches. New sessions are blocked; already-established sessions keep running.",
        remediation:
          "Compare the new observation with a trusted source, then explicitly approve or reject it. A later matching probe does not clear this automatically.",
        actions: [
          ...(canApprove ? (["approve", "reject"] as const) : []),
          "inspect",
          ...FINISH_LATER,
        ],
      };

    case VerificationStatus.VERIFICATION_EXPIRED:
      return {
        heading: "Verification expired",
        severity: "warning",
        detail:
          "No recent probe satisfies the configured freshness policy for this asset. Trust anchors are unchanged.",
        remediation: "Re-probe the target to refresh its verification.",
        actions: [...(canProbe ? (["retry"] as const) : []), ...FINISH_LATER],
      };

    case VerificationStatus.UNSPECIFIED:
    default:
      // Never blank: an unknown/absent status is a safe, actionable info state.
      return {
        heading: "Verification status unavailable",
        severity: "info",
        detail:
          "Jumpgate has not reported a verification status for this asset yet.",
        remediation: canProbe ? "Start a probe to observe the target." : undefined,
        actions: [...(canProbe ? (["retry"] as const) : []), ...FINISH_LATER],
      };
  }
}

// ─── Failure categories ───────────────────────────────────────────────────────

export interface FailureText {
  summary: string;
  remediation: string;
}

/**
 * Maps a sanitized FailureCategory to safe, actionable copy. Exhaustive over
 * the enum; the default is still a defined, non-blank fallback.
 */
export function failureText(cat: FailureCategory): FailureText {
  switch (cat) {
    case FailureCategory.NO_COMPATIBLE_WORKER:
      return {
        summary: "No compatible worker is available to probe this protocol.",
        remediation: "Ensure a worker for this asset's protocol is registered, then retry.",
      };
    case FailureCategory.DNS_RESOLUTION_FAILED:
      return {
        summary: "DNS resolution for the target hostname failed.",
        remediation: "Check the target hostname and the worker's DNS, then retry.",
      };
    case FailureCategory.CONNECTION_REFUSED:
      return {
        summary: "The target refused the connection.",
        remediation: "Confirm the host and port are correct and the service is listening, then retry.",
      };
    case FailureCategory.CONNECTION_TIMEOUT:
      return {
        summary: "The connection to the target timed out.",
        remediation: "Check reachability and firewall rules from the worker's network, then retry.",
      };
    case FailureCategory.PROTOCOL_MISMATCH:
      return {
        summary: "The endpoint did not speak the expected protocol.",
        remediation: "Confirm the asset's protocol and port match the target, then retry.",
      };
    case FailureCategory.INSECURE_DOWNGRADE:
      return {
        summary: "The target did not offer a secure connection; a plaintext downgrade was rejected.",
        remediation: "Enable TLS on the target and retry. Plaintext is never accepted.",
      };
    case FailureCategory.UNSUPPORTED_IDENTITY_ALGORITHM:
      return {
        summary: "The target presented an identity using an unsupported or deprecated algorithm.",
        remediation: "Reconfigure the target to use a supported algorithm, then retry.",
      };
    case FailureCategory.MALFORMED_IDENTITY:
      return {
        summary: "The identity material the target presented was malformed.",
        remediation: "Inspect the target's certificate or host key configuration, then retry.",
      };
    case FailureCategory.IDENTITY_TOO_LARGE:
      return {
        summary: "The identity material the target presented exceeded the allowed size.",
        remediation: "Review the target's certificate chain, then retry.",
      };
    case FailureCategory.CERTIFICATE_EXPIRED:
      return {
        summary: "The target's certificate has expired.",
        remediation: "Renew the target's certificate, then retry.",
      };
    case FailureCategory.CERTIFICATE_NOT_YET_VALID:
      return {
        summary: "The target's certificate is not yet valid.",
        remediation: "Check the target's clock and certificate validity window, then retry.",
      };
    case FailureCategory.NAME_MISMATCH:
      return {
        summary: "The target's certificate does not match the required name.",
        remediation: "Confirm the configured DNS/SNI name matches the certificate, then retry.",
      };
    case FailureCategory.EXPECTATION_MISMATCH:
      return {
        summary: "The observed identity did not match the supplied expectation.",
        remediation: "Verify the expected fingerprint or CA is correct, then retry.",
      };
    case FailureCategory.WORKER_LOST:
      return {
        summary: "The worker running the probe was lost before it completed.",
        remediation: "Retry — the probe will be re-leased to an available worker.",
      };
    case FailureCategory.LEASE_EXPIRED:
      return {
        summary: "The probe lease expired before a result was reported.",
        remediation: "Retry — the probe will be re-queued.",
      };
    case FailureCategory.TARGET_IDENTITY_CHANGED:
      return {
        summary: "The target is presenting a different identity than the approved one.",
        remediation: "Review the new observation and explicitly approve or reject it.",
      };
    case FailureCategory.UNSPECIFIED:
    default:
      return {
        summary: "The probe did not complete successfully.",
        remediation: "Retry the probe. If it keeps failing, check the target and worker.",
      };
  }
}

// ─── Probe progress ─────────────────────────────────────────────────────────

export type StageState = "done" | "active" | "pending" | "failed";

export interface ProbeStage {
  key: string;
  label: string;
  state: StageState;
}

/**
 * The progress stages the server data actually distinguishes — queued, worker
 * assigned (leased), and result. Finer steps (DNS/connect/negotiate) are not
 * reported by the worker, so we don't fabricate them (design spec: "without
 * fabricating precision unavailable from the worker").
 */
export function probeStages(state: ProbeState): ProbeStage[] {
  const stage = (key: string, label: string, s: StageState): ProbeStage => ({
    key,
    label,
    state: s,
  });
  switch (state) {
    case ProbeState.QUEUED:
      return [
        stage("queued", "Queued", "active"),
        stage("leased", "Worker assigned", "pending"),
        stage("result", "Result", "pending"),
      ];
    case ProbeState.LEASED:
      return [
        stage("queued", "Queued", "done"),
        stage("leased", "Worker assigned", "active"),
        stage("result", "Result", "pending"),
      ];
    case ProbeState.SUCCEEDED:
      return [
        stage("queued", "Queued", "done"),
        stage("leased", "Worker assigned", "done"),
        stage("result", "Result", "done"),
      ];
    case ProbeState.FAILED:
      return [
        stage("queued", "Queued", "done"),
        stage("leased", "Worker assigned", "done"),
        stage("result", "Result", "failed"),
      ];
    default:
      // SUPERSEDED / CANCELLED / UNSPECIFIED — terminal or unknown; no live
      // progress to show.
      return [
        stage("queued", "Queued", "pending"),
        stage("leased", "Worker assigned", "pending"),
        stage("result", "Result", "pending"),
      ];
  }
}

// ─── Trust anchors ─────────────────────────────────────────────────────────

/** The subset of TrustAnchor fields the pure model reads. */
export interface TrustAnchorLike {
  kind: TrustAnchorKind;
  source: TrustSource;
  notBeforeUnixMs: bigint;
  expiresAtUnixMs: bigint;
  revokedAtUnixMs: bigint;
}

export type AnchorState = "active" | "scheduled" | "expired" | "revoked";

export function anchorState(a: TrustAnchorLike, nowMs: number): AnchorState {
  if (a.revokedAtUnixMs > 0n) return "revoked";
  if (a.notBeforeUnixMs > 0n && Number(a.notBeforeUnixMs) > nowMs) return "scheduled";
  if (a.expiresAtUnixMs > 0n && Number(a.expiresAtUnixMs) <= nowMs) return "expired";
  return "active";
}

/** A CA anchor trusts everything it signs — broader than a single leaf/key. */
export function isCA(kind: TrustAnchorKind): boolean {
  return kind === TrustAnchorKind.TLS_CA || kind === TrustAnchorKind.SSH_HOST_CA;
}

export type AnchorWarningKind =
  | "ca-breadth"
  | "leaf-expiring"
  | "leaf-expired"
  | "tofu";

export interface AnchorWarning {
  kind: AnchorWarningKind;
  severity: Severity;
  text: string;
}

const EXPIRING_WINDOW_MS = 30 * 86_400_000; // 30 days

/**
 * Warnings a trust anchor should carry: CA breadth, leaf expiry (upcoming or
 * past), and TOFU (reachability is not identity proof). Revoked anchors carry
 * none (they're inert).
 */
export function anchorWarnings(
  a: TrustAnchorLike,
  nowMs: number,
  expiringWindowMs: number = EXPIRING_WINDOW_MS,
): AnchorWarning[] {
  const out: AnchorWarning[] = [];
  if (a.revokedAtUnixMs > 0n) return out;

  if (isCA(a.kind)) {
    out.push({
      kind: "ca-breadth",
      severity: "warning",
      text: "Approving a CA trusts every current and future certificate it signs — broader than pinning a single identity.",
    });
  }

  if (a.expiresAtUnixMs > 0n) {
    const expires = Number(a.expiresAtUnixMs);
    if (expires <= nowMs) {
      out.push({
        kind: "leaf-expired",
        severity: "error",
        text: "This certificate has expired; new sessions can no longer match it.",
      });
    } else if (expires - nowMs <= expiringWindowMs) {
      out.push({
        kind: "leaf-expiring",
        severity: "warning",
        text: "This certificate expires soon — plan a rotation before it lapses.",
      });
    }
  }

  if (a.source === TrustSource.TOFU) {
    out.push({
      kind: "tofu",
      severity: "warning",
      text: "Trust on first use — reachability did not independently prove this identity.",
    });
  }

  return out;
}

/**
 * More than one currently-active anchor is planned rotation overlap, not an
 * error — the UI presents it as such.
 */
export function rotationActive(anchors: TrustAnchorLike[], nowMs: number): boolean {
  return anchors.filter((a) => anchorState(a, nowMs) === "active").length > 1;
}

/** The subset of Evidence fields the evidence-warning model reads. */
export interface EvidenceLike {
  kind: EvidenceKind;
  validUntilUnixMs: bigint;
}

/**
 * Warnings a piece of observed evidence should carry BEFORE it is approved,
 * mirroring {@link anchorWarnings} but driven off the raw observation (used in
 * the verification wizard/detail flow for TLS assets — postgres and rdp alike):
 * a CA-level certificate (intermediate / presented root) means approving it as a
 * CA anchor trusts broadly; a leaf with a validity window flags upcoming or past
 * expiry. Evidence with neither is unremarkable and yields nothing.
 */
export function evidenceWarnings(
  e: EvidenceLike,
  nowMs: number,
  expiringWindowMs: number = EXPIRING_WINDOW_MS,
): AnchorWarning[] {
  const out: AnchorWarning[] = [];

  if (e.kind === EvidenceKind.TLS_INTERMEDIATE || e.kind === EvidenceKind.TLS_PRESENTED_ROOT) {
    out.push({
      kind: "ca-breadth",
      severity: "warning",
      text: "Approving this as a CA trusts every current and future certificate it signs — broader than pinning a single identity.",
    });
  }

  if (e.validUntilUnixMs > 0n) {
    const expires = Number(e.validUntilUnixMs);
    if (expires <= nowMs) {
      out.push({
        kind: "leaf-expired",
        severity: "error",
        text: "This certificate has expired; approving it will not verify the target.",
      });
    } else if (expires - nowMs <= expiringWindowMs) {
      out.push({
        kind: "leaf-expiring",
        severity: "warning",
        text: "This certificate expires soon — plan a rotation before it lapses.",
      });
    }
  }

  return out;
}
