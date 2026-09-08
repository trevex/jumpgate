/**
 * target-identity-card.tsx — durable target-identity panel for an asset.
 *
 * The source of truth for a single asset's identity verification: current
 * derived status, active trust anchors (with rotation / CA-breadth / expiry
 * warnings), observation + probe history, and the trust-changing actions
 * (retry probe, approve observed identity, reject, revoke anchor).
 *
 * Everything derives from server data (GetVerificationStatus, ListTrustAnchors,
 * ListObservations, ListProbes) — the card holds no correctness state of its
 * own, so a reload mid-probe simply re-fetches and resumes. Affordances are
 * capability-gated for UX only; the server re-checks every mutation.
 *
 * Only public identity material is rendered (fingerprints, algorithms,
 * principals, subject/issuer/SAN, sanitized failure categories). Raw secrets
 * and internal error detail are never shown.
 */

import { useMemo, useState } from "react";
import { useQuery, useMutation } from "@connectrpc/connect-query";
import {
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  Ban,
  ChevronDown,
  ChevronRight,
  Download,
} from "lucide-react";
import { toast } from "sonner";
import {
  getVerificationStatus,
  listTrustAnchors,
  listObservations,
  listProbes,
  startProbe,
  approveEvidence,
  rejectObservation,
  revokeTrustAnchor,
} from "@/gen/jumpgate/targetidentity/v1/targetidentity-TargetIdentityService_connectquery";
import {
  VerificationStatus,
  ProbeState,
  EvidenceKind,
  TrustAnchorKind,
  TrustSource,
  ObservationOutcome,
  ObservationSource,
  type Observation,
  type Evidence,
  type TrustAnchor,
  type ProbeJob,
} from "@/gen/jumpgate/targetidentity/v1/targetidentity_pb";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { capsCover } from "@/lib/capabilities";
import { connectErrorMessage } from "@/lib/format";
import { CopyButton } from "@/components/copy-button";
import { DetailSection } from "./shared";
import {
  verificationView,
  probeStages,
  anchorState,
  anchorWarnings,
  isCA,
  rotationActive,
  type Severity,
  type VerificationView,
} from "../target-verification-model";

// Management capabilities (see warden/internal/authz/caps.go).
const IDENTITY_READ = "catalog:asset:identity:read";
const IDENTITY_APPROVE = "catalog:asset:identity:approve";
const ASSET_PROBE = "catalog:asset:probe";

// ─── Severity styling ─────────────────────────────────────────────────────────

const SEVERITY_RING: Record<Severity, string> = {
  pending: "border-border bg-muted",
  info: "border-border bg-muted",
  success: "border-emerald-500/30 bg-emerald-500/5",
  warning: "border-amber-500/30 bg-amber-500/5",
  error: "border-destructive/30 bg-destructive/5",
};

const SEVERITY_TEXT: Record<Severity, string> = {
  pending: "text-muted-foreground",
  info: "text-muted-foreground",
  success: "text-emerald-600 dark:text-emerald-400",
  warning: "text-amber-600 dark:text-amber-400",
  error: "text-destructive",
};

function SeverityIcon({ severity }: { severity: Severity }) {
  const cls = cn("h-4 w-4 shrink-0", SEVERITY_TEXT[severity]);
  if (severity === "success") return <ShieldCheck className={cls} aria-hidden="true" />;
  if (severity === "error") return <ShieldAlert className={cls} aria-hidden="true" />;
  if (severity === "warning") return <ShieldAlert className={cls} aria-hidden="true" />;
  return <ShieldQuestion className={cls} aria-hidden="true" />;
}

// ─── Time helper ────────────────────────────────────────────────────────────

function fmtUnixMs(ms: bigint): string {
  if (ms <= 0n) return "—";
  return new Date(Number(ms)).toLocaleString();
}

// ─── Enum labels (display-only) ───────────────────────────────────────────────

function evidenceKindLabel(k: EvidenceKind): string {
  switch (k) {
    case EvidenceKind.SSH_HOST_KEY:
      return "SSH host key";
    case EvidenceKind.SSH_HOST_CERTIFICATE:
      return "SSH host certificate";
    case EvidenceKind.TLS_LEAF:
      return "TLS leaf certificate";
    case EvidenceKind.TLS_INTERMEDIATE:
      return "TLS intermediate";
    case EvidenceKind.TLS_PRESENTED_ROOT:
      return "TLS presented root";
    default:
      return "Identity material";
  }
}

function anchorKindLabel(k: TrustAnchorKind): string {
  switch (k) {
    case TrustAnchorKind.SSH_HOST_KEY:
      return "SSH host key";
    case TrustAnchorKind.SSH_HOST_CA:
      return "SSH host CA";
    case TrustAnchorKind.TLS_CA:
      return "TLS CA";
    case TrustAnchorKind.TLS_LEAF:
      return "TLS leaf";
    default:
      return "Trust anchor";
  }
}

function trustSourceLabel(s: TrustSource): string {
  switch (s) {
    case TrustSource.MANUAL:
      return "manual";
    case TrustSource.EXPECTED:
      return "expected";
    case TrustSource.TOFU:
      return "TOFU";
    case TrustSource.MIGRATION:
      return "migration";
    default:
      return "";
  }
}

// ─── Public evidence display (fingerprint / algorithm / cert facts) ────────────

export function EvidenceView({ evidence }: { evidence: Evidence }) {
  const [showRaw, setShowRaw] = useState(false);
  const hasCert = evidence.certificateSubject || evidence.certificateIssuer;

  function download() {
    const blob = new Blob([evidence.publicMaterial], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${evidence.sha256Fingerprint.replace(/[^a-zA-Z0-9]+/g, "_") || "evidence"}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col gap-1.5 rounded border border-border bg-muted/40 p-2.5">
      <div className="flex items-center gap-2">
        <Badge
          variant="secondary"
          className="rounded px-1.5 py-0 text-eyebrow uppercase tracking-wide"
        >
          {evidenceKindLabel(evidence.kind)}
        </Badge>
        {evidence.algorithm && (
          <span className="font-mono text-eyebrow text-muted-foreground">
            {evidence.algorithm}
            {evidence.keyBits > 0 ? ` ${evidence.keyBits}` : ""}
          </span>
        )}
      </div>

      {evidence.sha256Fingerprint && (
        <div className="flex items-center gap-2">
          <code className="flex-1 overflow-x-auto font-mono text-micro text-foreground whitespace-nowrap">
            {evidence.sha256Fingerprint}
          </code>
          <CopyButton text={evidence.sha256Fingerprint} label="Copy fingerprint" size="sm" />
        </div>
      )}

      {hasCert && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-micro">
          {evidence.certificateSubject && (
            <>
              <dt className="text-muted-foreground">Subject</dt>
              <dd className="font-mono text-foreground">{evidence.certificateSubject}</dd>
            </>
          )}
          {evidence.certificateIssuer && (
            <>
              <dt className="text-muted-foreground">Issuer</dt>
              <dd className="font-mono text-foreground">{evidence.certificateIssuer}</dd>
            </>
          )}
          {evidence.dnsNames.length > 0 && (
            <>
              <dt className="text-muted-foreground">DNS</dt>
              <dd className="font-mono text-foreground">{evidence.dnsNames.join(", ")}</dd>
            </>
          )}
          {evidence.ipAddresses.length > 0 && (
            <>
              <dt className="text-muted-foreground">IP</dt>
              <dd className="font-mono text-foreground">{evidence.ipAddresses.join(", ")}</dd>
            </>
          )}
          {evidence.sshPrincipals.length > 0 && (
            <>
              <dt className="text-muted-foreground">Principals</dt>
              <dd className="font-mono text-foreground">{evidence.sshPrincipals.join(", ")}</dd>
            </>
          )}
          {evidence.validUntilUnixMs > 0n && (
            <>
              <dt className="text-muted-foreground">Valid until</dt>
              <dd className="font-mono text-foreground">{fmtUnixMs(evidence.validUntilUnixMs)}</dd>
            </>
          )}
        </dl>
      )}

      {evidence.publicMaterial && (
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowRaw((v) => !v)}
              className="inline-flex items-center gap-1 text-eyebrow font-medium text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1"
              aria-expanded={showRaw}
            >
              {showRaw ? (
                <ChevronDown className="h-3 w-3" aria-hidden="true" />
              ) : (
                <ChevronRight className="h-3 w-3" aria-hidden="true" />
              )}
              Inspect public material
            </button>
            <CopyButton text={evidence.publicMaterial} label="Copy public material" size="sm" />
            <button
              type="button"
              onClick={download}
              className="inline-flex items-center gap-1 text-eyebrow font-medium text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1"
              aria-label="Download public material"
            >
              <Download className="h-3 w-3" aria-hidden="true" />
              Download
            </button>
          </div>
          {showRaw && (
            <pre className="max-h-40 overflow-auto rounded border border-border bg-background p-2 font-mono text-micro text-foreground">
              {evidence.publicMaterial}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Status banner (shared with the wizard step) ──────────────────────────────

export function StatusBanner({
  view,
  probe,
}: {
  view: VerificationView;
  probe?: ProbeJob | null;
}) {
  const showStages =
    view.severity === "pending" &&
    probe != null &&
    (probe.state === ProbeState.QUEUED || probe.state === ProbeState.LEASED);
  const stages = probe ? probeStages(probe.state) : [];

  return (
    <div
      className={cn("flex flex-col gap-2 rounded-md border p-3", SEVERITY_RING[view.severity])}
      role="status"
      aria-live="polite"
    >
      <div className="flex items-center gap-2">
        <SeverityIcon severity={view.severity} />
        <h4 className={cn("text-body font-semibold", SEVERITY_TEXT[view.severity])}>
          {view.heading}
        </h4>
      </div>
      <p className="text-compact text-muted-foreground">{view.detail}</p>
      {view.remediation && (
        <p className="text-compact text-foreground">{view.remediation}</p>
      )}
      {showStages && (
        <ol className="mt-1 flex flex-wrap gap-3" aria-label="Probe progress">
          {stages.map((s) => (
            <li key={s.key} className="flex items-center gap-1.5 text-micro">
              <span
                className={cn(
                  "inline-block h-1.5 w-1.5 rounded-full",
                  s.state === "done"
                    ? "bg-emerald-500"
                    : s.state === "active"
                      ? "animate-pulse bg-primary"
                      : s.state === "failed"
                        ? "bg-destructive"
                        : "bg-muted-foreground/30",
                )}
                aria-hidden="true"
              />
              <span
                className={
                  s.state === "pending" ? "text-muted-foreground/60" : "text-foreground"
                }
              >
                {s.label}
              </span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

// ─── Trust anchor row ──────────────────────────────────────────────────────────

const ANCHOR_STATE_LABEL = {
  active: "Active",
  scheduled: "Scheduled",
  expired: "Expired",
  revoked: "Revoked",
} as const;

function AnchorRow({
  anchor,
  now,
  onRevoke,
  canRevoke,
  revoking,
}: {
  anchor: TrustAnchor;
  now: number;
  onRevoke: (a: TrustAnchor) => void;
  canRevoke: boolean;
  revoking: boolean;
}) {
  const state = anchorState(anchor, now);
  const warnings = anchorWarnings(anchor, now);
  return (
    <div className="flex flex-col gap-1 rounded border border-border p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="secondary" className="rounded px-1.5 py-0 text-eyebrow uppercase tracking-wide">
          {anchorKindLabel(anchor.kind)}
        </Badge>
        <Badge
          variant={state === "active" ? "default" : "outline"}
          className={cn(
            "rounded px-1.5 py-0 text-eyebrow",
            state === "revoked" || state === "expired" ? "text-muted-foreground" : "",
          )}
        >
          {ANCHOR_STATE_LABEL[state]}
        </Badge>
        {isCA(anchor.kind) && (
          <Badge variant="outline" className="rounded px-1.5 py-0 text-eyebrow text-amber-600 dark:text-amber-400">
            CA — broad trust
          </Badge>
        )}
        {trustSourceLabel(anchor.source) && (
          <span className="text-eyebrow text-muted-foreground">
            via {trustSourceLabel(anchor.source)}
          </span>
        )}
        {canRevoke && state !== "revoked" && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onRevoke(anchor)}
            disabled={revoking}
            className="ml-auto h-6 gap-1 text-eyebrow text-destructive hover:text-destructive"
            aria-label={`Revoke ${anchorKindLabel(anchor.kind)} anchor`}
          >
            <Ban className="h-3 w-3" aria-hidden="true" />
            Revoke
          </Button>
        )}
      </div>

      {anchor.sha256Fingerprint && (
        <div className="flex items-center gap-2">
          <code className="flex-1 overflow-x-auto font-mono text-micro text-foreground whitespace-nowrap">
            {anchor.sha256Fingerprint}
          </code>
          <CopyButton text={anchor.sha256Fingerprint} label="Copy fingerprint" size="sm" />
        </div>
      )}

      <dl className="grid grid-cols-[auto_1fr] gap-x-3 text-micro text-muted-foreground">
        {anchor.notBeforeUnixMs > 0n && (
          <>
            <dt>Active from</dt>
            <dd className="font-mono text-foreground">{fmtUnixMs(anchor.notBeforeUnixMs)}</dd>
          </>
        )}
        {anchor.expiresAtUnixMs > 0n && (
          <>
            <dt>Expires</dt>
            <dd className="font-mono text-foreground">{fmtUnixMs(anchor.expiresAtUnixMs)}</dd>
          </>
        )}
      </dl>

      {warnings.map((w) => (
        <p
          key={w.kind}
          className={cn(
            "text-eyebrow",
            w.severity === "error" ? "text-destructive" : "text-amber-600 dark:text-amber-400",
          )}
        >
          {w.text}
        </p>
      ))}
    </div>
  );
}

// ─── Observation history row ───────────────────────────────────────────────────

function observationApprovableEvidence(obs: Observation): Evidence[] {
  // Pin the observed leaf/host-key material (the exact identity), not the CA —
  // CA approval is a deliberate, broader action handled separately.
  const exact = obs.evidence.filter(
    (e) =>
      e.kind === EvidenceKind.SSH_HOST_KEY ||
      e.kind === EvidenceKind.SSH_HOST_CERTIFICATE ||
      e.kind === EvidenceKind.TLS_LEAF,
  );
  return exact.length > 0 ? exact : obs.evidence;
}

// ─── Card ──────────────────────────────────────────────────────────────────────

export function TargetIdentityCard({
  assetId,
  managementCaps,
}: {
  assetId: string;
  managementCaps: string[];
}) {
  const canRead = capsCover(managementCaps, IDENTITY_READ);
  const canApprove = capsCover(managementCaps, IDENTITY_APPROVE);
  const canProbe = capsCover(managementCaps, ASSET_PROBE);

  const statusQ = useQuery(
    getVerificationStatus,
    { assetId },
    {
      enabled: canRead,
      // Poll while a probe is in flight so progress advances without a reload.
      refetchInterval: (q) =>
        q.state.data?.status === VerificationStatus.PENDING_VERIFICATION ? 3000 : false,
    },
  );
  const anchorsQ = useQuery(listTrustAnchors, { assetId }, { enabled: canRead });
  const obsQ = useQuery(listObservations, { assetId }, { enabled: canRead });
  const probesQ = useQuery(
    listProbes,
    { assetId },
    {
      enabled: canRead,
      refetchInterval: () =>
        statusQ.data?.status === VerificationStatus.PENDING_VERIFICATION ? 3000 : false,
    },
  );

  const status = statusQ.data?.status ?? VerificationStatus.UNSPECIFIED;
  const anchors = useMemo(() => anchorsQ.data?.trustAnchors ?? [], [anchorsQ.data]);
  const observations = obsQ.data?.observations ?? [];
  const probes = probesQ.data?.probes ?? [];
  // Latest probe drives failure/progress copy. Sort by creation time rather than
  // trusting server array order — picking a stale probe would mislead the banner.
  const latestProbe = useMemo(() => {
    if (probes.length === 0) return null;
    return [...probes].sort((a, b) => Number(b.createdAtUnixMs - a.createdAtUnixMs))[0];
  }, [probes]);
  // Current endpoint revision: the highest revision any durable row references.
  const currentRevision = useMemo(() => {
    let rev = 1n;
    for (const p of probes) if (p.endpointRevision > rev) rev = p.endpointRevision;
    for (const a of anchors) if (a.endpointRevision > rev) rev = a.endpointRevision;
    return rev;
  }, [probes, anchors]);

  const now = Date.now();
  const view = verificationView({
    status,
    probe: latestProbe
      ? { state: latestProbe.state, failureCategory: latestProbe.failureCategory }
      : null,
    canApprove,
    canProbe,
  });

  const refetchAll = () => {
    void statusQ.refetch();
    void anchorsQ.refetch();
    void obsQ.refetch();
    void probesQ.refetch();
  };

  const retryM = useMutation(startProbe, {
    onSuccess: () => {
      toast.success("Probe started");
      refetchAll();
    },
    onError: (err) => toast.error("Probe failed to start", { description: connectErrorMessage(err) }),
  });
  const approveM = useMutation(approveEvidence, {
    onSuccess: () => {
      toast.success("Identity approved");
      refetchAll();
    },
    onError: (err) => toast.error("Approval failed", { description: connectErrorMessage(err) }),
  });
  const rejectM = useMutation(rejectObservation, {
    onSuccess: () => {
      toast.success("Observation rejected");
      refetchAll();
    },
    onError: (err) => toast.error("Reject failed", { description: connectErrorMessage(err) }),
  });
  const revokeM = useMutation(revokeTrustAnchor, {
    onSuccess: () => {
      toast.success("Trust anchor revoked");
      refetchAll();
    },
    onError: (err) => toast.error("Revoke failed", { description: connectErrorMessage(err) }),
  });

  if (!canRead) return null;

  const busy =
    retryM.isPending || approveM.isPending || rejectM.isPending || revokeM.isPending;

  function retry() {
    // Fresh key per click: reusing one would collapse a repeat retry onto the
    // prior job (StartProbe is idempotent on requestId). Double-click is guarded
    // by disabled={busy}.
    retryM.mutate({
      requestId: crypto.randomUUID(),
      assetId,
      expectedEndpointRevision: currentRevision,
    });
  }
  function approve(obs: Observation) {
    const evidence = observationApprovableEvidence(obs);
    approveM.mutate({
      requestId: crypto.randomUUID(),
      assetId,
      expectedEndpointRevision: obs.endpointRevision > 0n ? obs.endpointRevision : currentRevision,
      observationId: obs.id,
      evidenceIds: evidence.map((e) => e.id),
      source: TrustSource.MANUAL,
    });
  }
  function reject(obs: Observation) {
    rejectM.mutate({
      requestId: crypto.randomUUID(),
      assetId,
      expectedEndpointRevision: obs.endpointRevision > 0n ? obs.endpointRevision : currentRevision,
      observationId: obs.id,
      reason: "",
    });
  }
  function revoke(a: TrustAnchor) {
    revokeM.mutate({
      requestId: crypto.randomUUID(),
      assetId,
      expectedEndpointRevision: a.endpointRevision > 0n ? a.endpointRevision : currentRevision,
      trustAnchorId: a.id,
      reason: "",
    });
  }

  // The most recent successful observation is the one an approver acts on.
  // Sort by observation time rather than trusting array order — approving a
  // stale observation could pin an outdated identity.
  const pendingObs = observations
    .filter((o) => o.outcome === ObservationOutcome.SUCCEEDED)
    .sort((a, b) => Number(b.observedAtUnixMs - a.observedAtUnixMs))[0];

  const activeAnchors = anchors.filter((a) => anchorState(a, now) !== "revoked");
  const showRotation = rotationActive(anchors, now);

  return (
    <DetailSection title="Target identity">
      <div className="flex flex-col gap-3">
        <StatusBanner view={view} probe={latestProbe} />

        {/* Actions */}
        <div className="flex flex-wrap gap-1.5">
          {view.actions.includes("approve") && pendingObs && (
            <Button
              size="sm"
              onClick={() => approve(pendingObs)}
              disabled={busy}
              className="h-7 gap-1.5 text-compact"
            >
              <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
              Approve observed identity
            </Button>
          )}
          {view.actions.includes("reject") && pendingObs && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => reject(pendingObs)}
              disabled={busy}
              className="h-7 gap-1.5 text-compact"
            >
              Reject
            </Button>
          )}
          {view.actions.includes("retry") && canProbe && (
            <Button
              size="sm"
              variant="outline"
              onClick={retry}
              disabled={busy}
              className="h-7 gap-1.5 text-compact"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              Retry probe
            </Button>
          )}
        </div>

        {/* Active trust anchors */}
        {activeAnchors.length > 0 && (
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <h5 className="text-eyebrow font-semibold uppercase tracking-widest text-muted-foreground">
                Active trust anchors
              </h5>
              {showRotation && (
                <Badge variant="outline" className="rounded px-1.5 py-0 text-eyebrow">
                  Rotation — multiple identities active
                </Badge>
              )}
            </div>
            {anchors.map((a) => (
              <AnchorRow
                key={a.id}
                anchor={a}
                now={now}
                onRevoke={revoke}
                canRevoke={canApprove}
                revoking={revokeM.isPending}
              />
            ))}
          </div>
        )}

        {/* Observation / probe history */}
        {observations.length > 0 && (
          <div className="flex flex-col gap-2">
            <h5 className="text-eyebrow font-semibold uppercase tracking-widest text-muted-foreground">
              Observations
            </h5>
            {observations.map((o) => (
              <div key={o.id} className="flex flex-col gap-1.5 rounded border border-border p-2.5">
                <div className="flex items-center gap-2 text-micro text-muted-foreground">
                  <span className="font-mono text-foreground">{fmtUnixMs(o.observedAtUnixMs)}</span>
                  {o.source === ObservationSource.SESSION_MISMATCH && (
                    <Badge variant="outline" className="rounded px-1.5 py-0 text-eyebrow text-amber-600 dark:text-amber-400">
                      session mismatch
                    </Badge>
                  )}
                  {o.resolvedAddresses.length > 0 && (
                    <span className="font-mono">{o.resolvedAddresses.join(", ")}</span>
                  )}
                </div>
                {o.evidence.map((e) => (
                  <EvidenceView key={e.id} evidence={e} />
                ))}
              </div>
            ))}
          </div>
        )}
      </div>
    </DetailSection>
  );
}
