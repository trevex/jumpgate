import { describe, it, expect } from "vitest";
import {
  VerificationStatus,
  ProbeState,
  FailureCategory,
  TrustAnchorKind,
  TrustSource,
  EvidenceKind,
} from "@/gen/jumpgate/targetidentity/v1/targetidentity_pb";
import {
  verificationView,
  failureText,
  probeStages,
  anchorState,
  anchorWarnings,
  evidenceWarnings,
  isCA,
  rotationActive,
  type TrustAnchorLike,
} from "./target-verification-model";

// A minimal TrustAnchor-shaped object; only the fields the model reads.
function anchor(over: Partial<TrustAnchorLike> = {}): TrustAnchorLike {
  return {
    kind: TrustAnchorKind.TLS_LEAF,
    source: TrustSource.MANUAL,
    notBeforeUnixMs: 0n,
    expiresAtUnixMs: 0n,
    revokedAtUnixMs: 0n,
    ...over,
  };
}

const NOW = 1_700_000_000_000; // fixed clock
const DAY = 86_400_000;

describe("verificationView — exhaustive status mapping", () => {
  const allStatuses = Object.values(VerificationStatus).filter(
    (v): v is VerificationStatus => typeof v === "number",
  );

  it("maps every status to a defined, non-blank view (no unsafe fall-through)", () => {
    for (const status of allStatuses) {
      const view = verificationView({ status, canApprove: true, canProbe: true });
      expect(view.heading, `heading for status ${status}`).toBeTruthy();
      expect(view.detail, `detail for status ${status}`).toBeTruthy();
      expect(view.severity).toBeTruthy();
      expect(Array.isArray(view.actions)).toBe(true);
      // "Finish later" is always available so a step is never a dead end.
      expect(view.actions).toContain("finish-later");
    }
  });

  it("awaiting-approval offers approve+reject to an authorized approver", () => {
    const view = verificationView({
      status: VerificationStatus.AWAITING_APPROVAL,
      canApprove: true,
      canProbe: true,
    });
    expect(view.actions).toContain("approve");
    expect(view.actions).toContain("reject");
    expect(view.actions).toContain("inspect");
    // Approved copy: compare with a trusted source before approving.
    expect(view.detail.toLowerCase()).toContain("compare");
  });

  it("awaiting-approval WITHOUT approval authority is read-only / finish-later", () => {
    const view = verificationView({
      status: VerificationStatus.AWAITING_APPROVAL,
      canApprove: false,
      canProbe: false,
    });
    expect(view.actions).not.toContain("approve");
    expect(view.actions).not.toContain("reject");
    expect(view.actions).toContain("finish-later");
    // The creator sees the awaiting-approval message, not a broken/empty state.
    expect(view.detail.toLowerCase()).toContain("awaiting identity approval");
    expect(view.severity).toBe("info");
  });

  it("probe-failed surfaces the failure category and gates retry on probe cap", () => {
    const withCap = verificationView({
      status: VerificationStatus.PROBE_FAILED,
      probe: {
        state: ProbeState.FAILED,
        failureCategory: FailureCategory.CONNECTION_REFUSED,
      },
      canApprove: false,
      canProbe: true,
    });
    expect(withCap.severity).toBe("error");
    expect(withCap.actions).toContain("retry");
    expect(withCap.remediation).toBeTruthy();
    // Safe detail, not a raw error string.
    expect(withCap.detail.toLowerCase()).toContain("refused");

    const noCap = verificationView({
      status: VerificationStatus.PROBE_FAILED,
      probe: {
        state: ProbeState.FAILED,
        failureCategory: FailureCategory.CONNECTION_REFUSED,
      },
      canApprove: false,
      canProbe: false,
    });
    expect(noCap.actions).not.toContain("retry");
  });

  it("identity-changed is an error that blocks new sessions but keeps existing ones", () => {
    const view = verificationView({
      status: VerificationStatus.IDENTITY_CHANGED,
      canApprove: true,
      canProbe: true,
    });
    expect(view.severity).toBe("error");
    expect(view.detail.toLowerCase()).toContain("new sessions");
    // An approver can resolve it explicitly.
    expect(view.actions).toContain("approve");
    expect(view.actions).toContain("reject");
  });

  it("verified is a success terminal state with nothing to approve", () => {
    const view = verificationView({
      status: VerificationStatus.VERIFIED,
      canApprove: true,
      canProbe: true,
    });
    expect(view.severity).toBe("success");
    expect(view.actions).not.toContain("approve");
  });

  it("pending shows progress and never offers approve", () => {
    const view = verificationView({
      status: VerificationStatus.PENDING_VERIFICATION,
      probe: { state: ProbeState.LEASED, failureCategory: FailureCategory.UNSPECIFIED },
      canApprove: true,
      canProbe: true,
    });
    expect(view.severity).toBe("pending");
    expect(view.actions).not.toContain("approve");
  });
});

describe("failureText — exhaustive category mapping", () => {
  const allCategories = Object.values(FailureCategory).filter(
    (v): v is FailureCategory => typeof v === "number",
  );

  it("maps every failure category to a non-blank summary + remediation", () => {
    for (const cat of allCategories) {
      const t = failureText(cat);
      expect(t.summary, `summary for category ${cat}`).toBeTruthy();
      expect(t.remediation, `remediation for category ${cat}`).toBeTruthy();
    }
  });

  it("gives a specific message for a known category", () => {
    expect(failureText(FailureCategory.DNS_RESOLUTION_FAILED).summary.toLowerCase()).toContain(
      "dns",
    );
    expect(failureText(FailureCategory.NO_COMPATIBLE_WORKER).summary.toLowerCase()).toContain(
      "worker",
    );
  });
});

describe("probeStages — only server-supported stages", () => {
  it("queued shows the first stage active, rest pending", () => {
    const stages = probeStages(ProbeState.QUEUED);
    expect(stages.map((s) => s.state)).toEqual(["active", "pending", "pending"]);
  });
  it("leased advances to worker-assigned", () => {
    const stages = probeStages(ProbeState.LEASED);
    expect(stages[0].state).toBe("done");
    expect(stages[1].state).toBe("active");
  });
  it("succeeded marks every stage done", () => {
    const stages = probeStages(ProbeState.SUCCEEDED);
    expect(stages.every((s) => s.state === "done")).toBe(true);
  });
  it("failed marks the result stage failed", () => {
    const stages = probeStages(ProbeState.FAILED);
    expect(stages[stages.length - 1].state).toBe("failed");
  });
});

describe("anchorState", () => {
  it("revoked wins over everything", () => {
    expect(anchorState(anchor({ revokedAtUnixMs: BigInt(NOW - DAY) }), NOW)).toBe("revoked");
  });
  it("future not-before is scheduled", () => {
    expect(anchorState(anchor({ notBeforeUnixMs: BigInt(NOW + DAY) }), NOW)).toBe("scheduled");
  });
  it("past expiry is expired", () => {
    expect(anchorState(anchor({ expiresAtUnixMs: BigInt(NOW - DAY) }), NOW)).toBe("expired");
  });
  it("otherwise active", () => {
    expect(anchorState(anchor({ expiresAtUnixMs: BigInt(NOW + 90 * DAY) }), NOW)).toBe("active");
  });
});

describe("anchorWarnings", () => {
  it("CA anchors surface a breadth warning", () => {
    const w = anchorWarnings(anchor({ kind: TrustAnchorKind.TLS_CA }), NOW);
    expect(w.some((x) => x.kind === "ca-breadth")).toBe(true);
    expect(isCA(TrustAnchorKind.TLS_CA)).toBe(true);
    expect(isCA(TrustAnchorKind.SSH_HOST_CA)).toBe(true);
    expect(isCA(TrustAnchorKind.TLS_LEAF)).toBe(false);
  });
  it("near-expiry leaf surfaces an expiry warning", () => {
    const w = anchorWarnings(
      anchor({ kind: TrustAnchorKind.TLS_LEAF, expiresAtUnixMs: BigInt(NOW + 5 * DAY) }),
      NOW,
    );
    expect(w.some((x) => x.kind === "leaf-expiring")).toBe(true);
  });
  it("already-expired leaf surfaces an expired warning", () => {
    const w = anchorWarnings(
      anchor({ kind: TrustAnchorKind.TLS_LEAF, expiresAtUnixMs: BigInt(NOW - DAY) }),
      NOW,
    );
    expect(w.some((x) => x.kind === "leaf-expired")).toBe(true);
  });
  it("a leaf comfortably in-date has no expiry warning", () => {
    const w = anchorWarnings(
      anchor({ kind: TrustAnchorKind.TLS_LEAF, expiresAtUnixMs: BigInt(NOW + 200 * DAY) }),
      NOW,
    );
    expect(w.some((x) => x.kind.startsWith("leaf-"))).toBe(false);
  });
  it("TOFU anchors warn that reachability is not proof of identity", () => {
    const w = anchorWarnings(anchor({ source: TrustSource.TOFU }), NOW);
    expect(w.some((x) => x.kind === "tofu")).toBe(true);
  });
});

describe("evidenceWarnings — pre-approval, evidence-driven (postgres + rdp TLS)", () => {
  it("a CA-level cert (presented root / intermediate) surfaces a breadth warning", () => {
    expect(
      evidenceWarnings({ kind: EvidenceKind.TLS_PRESENTED_ROOT, validUntilUnixMs: 0n }, NOW).some(
        (w) => w.kind === "ca-breadth",
      ),
    ).toBe(true);
    expect(
      evidenceWarnings({ kind: EvidenceKind.TLS_INTERMEDIATE, validUntilUnixMs: 0n }, NOW).some(
        (w) => w.kind === "ca-breadth",
      ),
    ).toBe(true);
  });
  it("a leaf surfaces no CA-breadth warning", () => {
    expect(
      evidenceWarnings({ kind: EvidenceKind.TLS_LEAF, validUntilUnixMs: 0n }, NOW).some(
        (w) => w.kind === "ca-breadth",
      ),
    ).toBe(false);
  });
  it("a near-expiry leaf surfaces an expiry warning", () => {
    const w = evidenceWarnings(
      { kind: EvidenceKind.TLS_LEAF, validUntilUnixMs: BigInt(NOW + 5 * DAY) },
      NOW,
    );
    expect(w.some((x) => x.kind === "leaf-expiring")).toBe(true);
  });
  it("an already-expired leaf surfaces an expired (error) warning", () => {
    const w = evidenceWarnings(
      { kind: EvidenceKind.TLS_LEAF, validUntilUnixMs: BigInt(NOW - DAY) },
      NOW,
    );
    expect(w.some((x) => x.kind === "leaf-expired" && x.severity === "error")).toBe(true);
  });
  it("a leaf comfortably in-date is unremarkable", () => {
    expect(
      evidenceWarnings(
        { kind: EvidenceKind.TLS_LEAF, validUntilUnixMs: BigInt(NOW + 200 * DAY) },
        NOW,
      ),
    ).toHaveLength(0);
  });
});

describe("rotationActive", () => {
  it("multiple active anchors are rotation, not an error", () => {
    const anchors = [
      anchor({ expiresAtUnixMs: BigInt(NOW + 90 * DAY) }),
      anchor({ expiresAtUnixMs: BigInt(NOW + 120 * DAY) }),
    ];
    expect(rotationActive(anchors, NOW)).toBe(true);
  });
  it("a single active anchor is not rotation", () => {
    expect(rotationActive([anchor()], NOW)).toBe(false);
  });
  it("revoked/expired anchors don't count toward rotation", () => {
    const anchors = [
      anchor(),
      anchor({ revokedAtUnixMs: BigInt(NOW - DAY) }),
      anchor({ expiresAtUnixMs: BigInt(NOW - DAY) }),
    ];
    expect(rotationActive(anchors, NOW)).toBe(false);
  });
});
