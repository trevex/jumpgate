package targetidentity_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

// seedAnchor inserts a trust anchor directly for the env asset at revision 1 and
// returns its id. It bypasses the approval flow so a session-verify test can pin an
// exact kind/fingerprint/revocation state without threading a full probe→approve.
func (e *targetIdentityEnv) seedAnchor(t *testing.T, kind, fp string, dnsNames []string, revoked bool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(e.ctx, `
		INSERT INTO target_trust_anchors
			(asset_id, endpoint_revision, kind, algorithm, sha256_fingerprint, public_material, source,
			 required_dns_names, revoked_at)
		VALUES ($1, 1, $2, 'ecdsa', $3, 'public', 'manual', $4, CASE WHEN $5 THEN now() ELSE NULL END)
		RETURNING id`, e.asset, kind, fp, emptyStrings(dnsNames), revoked).Scan(&id); err != nil {
		t.Fatalf("seed %s anchor: %v", kind, err)
	}
	return id
}

func emptyStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// TestVerifySessionTargetTLSCAAccepted proves a tls_ca anchor that is current and
// active is accepted on the session-verify path: warden re-confirms the anchor is
// current/active (the ListCurrentActiveTrustAnchors gate) and trusts the mesh-
// authenticated worker's chain attestation, since warden holds only the observed
// leaf fingerprint, not the chain. The observed leaf fingerprint need not equal the
// CA anchor's own fingerprint (it is not a pin).
func TestVerifySessionTargetTLSCAAccepted(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	anchorID := env.seedAnchor(t, "tls_ca", fingerprint("pg-ca"), []string{"db.test"}, false)

	got, err := env.svc.VerifySessionTarget(env.ctx, targetidentity.VerifySessionTargetRequest{
		AssetID:             env.asset,
		ReportedRevision:    1,
		AnchorID:            anchorID,
		ObservedFingerprint: fingerprint("some-leaf-under-the-ca"), // a leaf, not the CA fp
	})
	if err != nil {
		t.Fatalf("VerifySessionTarget(tls_ca current) = %v; want accept", err)
	}
	if got != anchorID {
		t.Fatalf("matched anchor = %s; want %s", got, anchorID)
	}
}

// TestVerifySessionTargetTLSCARevokedFailsClosed proves a revoked tls_ca anchor is
// refused: it is absent from the current-active set, so the claimed anchor id is not
// found and no credential may be released.
func TestVerifySessionTargetTLSCARevokedFailsClosed(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	anchorID := env.seedAnchor(t, "tls_ca", fingerprint("pg-ca-revoked"), []string{"db.test"}, true)

	_, err := env.svc.VerifySessionTarget(env.ctx, targetidentity.VerifySessionTargetRequest{
		AssetID:             env.asset,
		ReportedRevision:    1,
		AnchorID:            anchorID,
		ObservedFingerprint: fingerprint("leaf"),
	})
	if err == nil {
		t.Fatal("VerifySessionTarget(tls_ca revoked) = nil; want fail-closed refusal")
	}
}

// TestVerifySessionTargetTLSCAStaleRevisionFailsClosed proves a tls_ca anchor bound
// to an old endpoint revision is refused once the endpoint moved: the reported
// revision no longer matches the asset's current revision.
func TestVerifySessionTargetTLSCAStaleRevisionFailsClosed(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	anchorID := env.seedAnchor(t, "tls_ca", fingerprint("pg-ca-stale"), []string{"db.test"}, false)
	if _, err := testPool.Exec(env.ctx, `UPDATE assets SET endpoint_revision = 2 WHERE id = $1`, env.asset); err != nil {
		t.Fatalf("bump endpoint revision: %v", err)
	}

	_, err := env.svc.VerifySessionTarget(env.ctx, targetidentity.VerifySessionTargetRequest{
		AssetID:             env.asset,
		ReportedRevision:    1, // worker prepared against the now-stale revision 1
		AnchorID:            anchorID,
		ObservedFingerprint: fingerprint("leaf"),
	})
	if !errors.Is(err, targetidentity.ErrStaleRevision) {
		t.Fatalf("VerifySessionTarget(stale revision) = %v; want ErrStaleRevision", err)
	}
}

// TestVerifySessionTargetTLSLeafExactMatch is a regression guard: tls_leaf anchors
// stay proven by exact leaf-fingerprint equality, and a mismatch is the MITM signal.
func TestVerifySessionTargetTLSLeafExactMatch(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	leafFP := fingerprint("pg-leaf-pin")
	anchorID := env.seedAnchor(t, "tls_leaf", leafFP, []string{"db.test"}, false)

	got, err := env.svc.VerifySessionTarget(env.ctx, targetidentity.VerifySessionTargetRequest{
		AssetID: env.asset, ReportedRevision: 1, AnchorID: anchorID, ObservedFingerprint: leafFP,
	})
	if err != nil || got != anchorID {
		t.Fatalf("VerifySessionTarget(tls_leaf exact) = %s,%v; want %s,nil", got, err, anchorID)
	}

	if _, err := env.svc.VerifySessionTarget(env.ctx, targetidentity.VerifySessionTargetRequest{
		AssetID: env.asset, ReportedRevision: 1, AnchorID: anchorID, ObservedFingerprint: fingerprint("other"),
	}); !errors.Is(err, targetidentity.ErrIdentityMismatch) {
		t.Fatalf("VerifySessionTarget(tls_leaf mismatch) = %v; want ErrIdentityMismatch", err)
	}
}

// TestVerifySessionTargetSSHHostCAStillUnsupported pins that ssh_host_ca session
// verification remains unsupported — the SSH worker does not yet do the local chain
// validation the tls_ca acceptance relies on, so it must stay fail-closed.
func TestVerifySessionTargetSSHHostCAStillUnsupported(t *testing.T) {
	env := newTargetIdentityEnv(t) // ssh asset
	anchorID := env.seedAnchor(t, "ssh_host_ca", fingerprint("ssh-ca"), nil, false)

	_, err := env.svc.VerifySessionTarget(env.ctx, targetidentity.VerifySessionTargetRequest{
		AssetID: env.asset, ReportedRevision: 1, AnchorID: anchorID, ObservedFingerprint: fingerprint("leaf"),
	})
	if !errors.Is(err, targetidentity.ErrCAAnchorSessionUnsupported) {
		t.Fatalf("VerifySessionTarget(ssh_host_ca) = %v; want ErrCAAnchorSessionUnsupported", err)
	}
}
