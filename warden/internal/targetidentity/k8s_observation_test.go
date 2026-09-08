package targetidentity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

// apiServerLeaf mints a self-signed API-server-style TLS leaf carrying dnsName, as
// raw DER — the shape an agent captures from a real API-server handshake.
func apiServerLeaf(t *testing.T, dnsName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestRecordAgentObservationLeafToVerified proves the agent-driven k8s evidence
// path: recording API-server TLS evidence creates an awaiting-approval observation,
// approving the observed leaf makes the asset verified, and a later observation of a
// DIFFERENT API-server identity is recorded as an unresolved mismatch (identity
// changed) — which is exactly what the session gate keys on to block new sessions.
func TestRecordAgentObservationLeafToVerified(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolKubernetes)
	const apiName = "kubernetes.default.svc"

	leaf := apiServerLeaf(t, apiName)
	status, err := env.svc.RecordAgentObservation(env.ctx, targetidentity.AgentObservationRequest{
		AssetID: env.asset, WorkerID: env.worker, APIServerName: apiName, ChainDER: [][]byte{leaf},
	})
	if err != nil {
		t.Fatalf("RecordAgentObservation: %v", err)
	}
	if status != targetidentity.StatusAwaitingApproval {
		t.Fatalf("post-observation status = %q, want awaiting_approval", status)
	}

	obsID, leafFP := mustLeafObservation(t, env)
	env.approve(t, obsID, leafFP, time.Time{})
	if got := env.status(t); got != targetidentity.StatusVerified {
		t.Fatalf("post-approval status = %q, want verified", got)
	}

	// A different API-server identity → mismatch → identity_changed (blocks new sessions).
	other := apiServerLeaf(t, apiName)
	status, err = env.svc.RecordAgentObservation(env.ctx, targetidentity.AgentObservationRequest{
		AssetID: env.asset, WorkerID: env.worker, APIServerName: apiName, ChainDER: [][]byte{other},
	})
	if err != nil {
		t.Fatalf("RecordAgentObservation (rotated): %v", err)
	}
	if status != targetidentity.StatusIdentityChanged {
		t.Fatalf("post-rotation status = %q, want identity_changed", status)
	}
}

// TestRecordAgentObservationRejectsNonK8sAndEmpty proves fail-closed input handling.
func TestRecordAgentObservationRejectsNonK8sAndEmpty(t *testing.T) {
	k8s := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolKubernetes)
	if _, err := k8s.svc.RecordAgentObservation(k8s.ctx, targetidentity.AgentObservationRequest{
		AssetID: k8s.asset, WorkerID: k8s.worker, APIServerName: "x", ChainDER: nil,
	}); err == nil {
		t.Fatal("expected error for empty chain")
	}

	ssh := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolSSH)
	if _, err := ssh.svc.RecordAgentObservation(ssh.ctx, targetidentity.AgentObservationRequest{
		AssetID: ssh.asset, WorkerID: ssh.worker, APIServerName: "x", ChainDER: [][]byte{apiServerLeaf(t, "x")},
	}); err == nil {
		t.Fatal("expected error recording a k8s observation against a non-k8s asset")
	}
}

// mustLeafObservation returns the observation id + fingerprint of the tls_leaf evidence.
func mustLeafObservation(t *testing.T, env *targetIdentityEnv) (uuid.UUID, string) {
	t.Helper()
	for _, ev := range env.evidence(t) {
		if ev.Kind == targetidentity.EvidenceTLSLeaf {
			return ev.ObservationID, ev.Fingerprint
		}
	}
	t.Fatal("no tls_leaf evidence recorded")
	return uuid.Nil, ""
}
