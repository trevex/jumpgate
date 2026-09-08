/**
 * target-verification-step.tsx — guided final step of asset creation.
 *
 * After the asset is created (non-connectable), this step queues a
 * credential-free identity probe and streams its durable progress. It never
 * holds correctness state of its own: it keys off the created asset id + the
 * started probe id and re-fetches from the server (GetProbe /
 * GetVerificationStatus / ListObservations), so closing or reloading leaves a
 * resumable pending asset — the asset detail page's identity card is the
 * durable source of truth.
 *
 * Approval is a deliberate action offered only to authorized users; "Finish
 * later" is always available. The server re-checks every mutation.
 */

import { useEffect, useState } from "react";
import { useQuery, useMutation } from "@connectrpc/connect-query";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  startProbe,
  getProbe,
  getVerificationStatus,
  listObservations,
  approveEvidence,
  rejectObservation,
} from "@/gen/jumpgate/targetidentity/v1/targetidentity-TargetIdentityService_connectquery";
import {
  VerificationStatus,
  ProbeState,
  EvidenceKind,
  TrustSource,
  ObservationOutcome,
  type Observation,
} from "@/gen/jumpgate/targetidentity/v1/targetidentity_pb";
import { ShieldCheck } from "lucide-react";
import { capsCover, useCapabilities } from "@/lib/capabilities";
import { connectErrorMessage } from "@/lib/format";
import { verificationView } from "./target-verification-model";
import { StatusBanner, EvidenceView } from "./detail/target-identity-card";

const IDENTITY_APPROVE = "catalog:asset:identity:approve";
const ASSET_PROBE = "catalog:asset:probe";

interface TargetVerificationStepProps {
  assetId: string;
  assetName: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function approvableEvidence(obs: Observation) {
  const exact = obs.evidence.filter(
    (e) =>
      e.kind === EvidenceKind.SSH_HOST_KEY ||
      e.kind === EvidenceKind.SSH_HOST_CERTIFICATE ||
      e.kind === EvidenceKind.TLS_LEAF,
  );
  return exact.length > 0 ? exact : obs.evidence;
}

export function TargetVerificationStep({
  assetId,
  assetName,
  open,
  onOpenChange,
}: TargetVerificationStepProps) {
  const caps = useCapabilities();
  const canApprove = capsCover(caps, IDENTITY_APPROVE);
  const canProbe = capsCover(caps, ASSET_PROBE);

  // Stable idempotency key: re-invoking StartProbe with the same request id
  // returns the same durable job rather than queuing a duplicate.
  const [probeReqId] = useState(() => crypto.randomUUID());
  const [probeId, setProbeId] = useState<string | null>(null);

  // Queue the onboarding probe once, when the step opens. New assets are at
  // endpoint revision 1.
  const startM = useMutation(startProbe, {
    onSuccess: (res) => {
      if (res.probe?.id) setProbeId(res.probe.id);
    },
    onError: (err) =>
      toast.error("Couldn't start verification", { description: connectErrorMessage(err) }),
  });
  useEffect(() => {
    if (open && !probeId && !startM.isPending) {
      startM.mutate({ requestId: probeReqId, assetId, expectedEndpointRevision: 1n });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const probeQ = useQuery(
    getProbe,
    { assetId, probeId: probeId ?? "" },
    {
      enabled: open && !!probeId,
      refetchInterval: (q) => {
        const s = q.state.data?.probe?.state;
        return s === ProbeState.QUEUED || s === ProbeState.LEASED ? 2000 : false;
      },
    },
  );
  const statusQ = useQuery(
    getVerificationStatus,
    { assetId },
    {
      enabled: open,
      refetchInterval: (q) =>
        q.state.data?.status === VerificationStatus.PENDING_VERIFICATION ? 2000 : false,
    },
  );
  const obsQ = useQuery(
    listObservations,
    { assetId },
    { enabled: open && statusQ.data?.status === VerificationStatus.AWAITING_APPROVAL },
  );

  const probe = probeQ.data?.probe ?? null;
  const status = statusQ.data?.status ?? VerificationStatus.PENDING_VERIFICATION;
  const observations = obsQ.data?.observations ?? [];
  // Newest successful observation (sort, don't trust array order — a stale one
  // could pin an outdated identity).
  const pendingObs = observations
    .filter((o) => o.outcome === ObservationOutcome.SUCCEEDED)
    .sort((a, b) => Number(b.observedAtUnixMs - a.observedAtUnixMs))[0];

  const view = verificationView({
    status,
    probe: probe ? { state: probe.state, failureCategory: probe.failureCategory } : null,
    canApprove,
    canProbe,
  });

  const approveM = useMutation(approveEvidence, {
    onSuccess: () => {
      toast.success("Identity approved", { description: `${assetName} is verified.` });
      onOpenChange(false);
    },
    onError: (err) => toast.error("Approval failed", { description: connectErrorMessage(err) }),
  });
  const rejectM = useMutation(rejectObservation, {
    onSuccess: () => {
      toast.success("Observation rejected");
      void statusQ.refetch();
      void obsQ.refetch();
    },
    onError: (err) => toast.error("Reject failed", { description: connectErrorMessage(err) }),
  });
  const retryM = useMutation(startProbe, {
    onSuccess: (res) => {
      if (res.probe?.id) setProbeId(res.probe.id);
      void statusQ.refetch();
    },
    onError: (err) => toast.error("Probe failed to start", { description: connectErrorMessage(err) }),
  });

  const busy = approveM.isPending || rejectM.isPending || retryM.isPending;

  function approve() {
    if (!pendingObs) return;
    approveM.mutate({
      requestId: crypto.randomUUID(),
      assetId,
      expectedEndpointRevision: pendingObs.endpointRevision > 0n ? pendingObs.endpointRevision : 1n,
      observationId: pendingObs.id,
      evidenceIds: approvableEvidence(pendingObs).map((e) => e.id),
      source: TrustSource.MANUAL,
    });
  }
  function reject() {
    if (!pendingObs) return;
    rejectM.mutate({
      requestId: crypto.randomUUID(),
      assetId,
      expectedEndpointRevision: pendingObs.endpointRevision > 0n ? pendingObs.endpointRevision : 1n,
      observationId: pendingObs.id,
      reason: "",
    });
  }
  function retry() {
    retryM.mutate({ requestId: crypto.randomUUID(), assetId, expectedEndpointRevision: 1n });
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle className="text-title">Verify target identity</DialogTitle>
          <DialogDescription className="text-body">
            <span className="font-mono text-compact">{assetName}</span> was created but is not
            connectable yet. Jumpgate is authenticating the target before any credential can be
            released.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3">
          <StatusBanner view={view} probe={probe} />

          {observations.map((o) => (
            <div key={o.id} className="flex flex-col gap-1.5">
              {o.evidence.map((e) => (
                <EvidenceView key={e.id} evidence={e} />
              ))}
            </div>
          ))}
        </div>

        <DialogFooter className="mt-1 flex-wrap gap-1.5">
          {view.actions.includes("retry") && canProbe && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={retry}
              disabled={busy}
              className="h-8 text-body"
            >
              Retry probe
            </Button>
          )}
          {view.actions.includes("reject") && pendingObs && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={reject}
              disabled={busy}
              className="h-8 text-body"
            >
              Reject
            </Button>
          )}
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => onOpenChange(false)}
            disabled={busy}
            className="h-8 text-body"
          >
            Finish later
          </Button>
          {view.actions.includes("approve") && pendingObs && (
            <Button
              type="button"
              size="sm"
              onClick={approve}
              disabled={busy}
              className="h-8 gap-1.5 text-body"
            >
              <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
              Approve identity &amp; finish
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
