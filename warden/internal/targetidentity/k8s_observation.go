package targetidentity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// AgentObservationRequest carries the API-server TLS evidence an in-cluster k8s
// agent observed for its bound asset. Unlike a worker-run probe it is not leased:
// the agent self-probes and relays the chain over its authenticated tunnel, and
// warden has already re-derived AssetID from the agent's verified mesh cert SAN, so
// this request is trusted only for the asset it is called with.
type AgentObservationRequest struct {
	AssetID       uuid.UUID
	WorkerID      string
	APIServerName string
	ChainDER      [][]byte // presented certificate chain, leaf-first (DER)
}

// RecordAgentObservation persists an agent's API-server identity evidence as an
// immutable k8s probe observation at the asset's current endpoint revision, and
// returns the derived verification status. It mirrors Complete's mismatch handling
// (a succeeded observation that matches no current active anchor is recorded as a
// mismatch), but without a lease/job since the observation is agent-driven.
func (s *Service) RecordAgentObservation(ctx context.Context, req AgentObservationRequest) (VerificationStatus, error) {
	now := s.now()
	if req.AssetID == uuid.Nil || req.WorkerID == "" || len(req.ChainDER) == 0 {
		return "", ErrInvalidRequest
	}
	evidence, err := tlsChainEvidence(req.ChainDER)
	if err != nil {
		return "", ErrInvalidResult
	}
	result := ProbeResult{
		Outcome:    ProbeSucceeded,
		ObservedAt: now,
		Kubernetes: &KubernetesMetadata{APIServerName: req.APIServerName},
		Evidence:   evidence,
	}
	if err := validateResult(result, now); err != nil {
		return "", err
	}
	if err := validateProtocolResult(ProtocolKubernetes, result); err != nil {
		return "", err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin agent observation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	asset, err := q.GetAsset(ctx, req.AssetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrAssetNotFound
		}
		return "", fmt.Errorf("read asset revision: %w", err)
	}
	if asset.Kind != string(ProtocolKubernetes) {
		return "", ErrInvalidRequest
	}
	revision := asset.EndpointRevision

	anchors, err := q.ListCurrentActiveTrustAnchors(ctx, sqlc.ListCurrentActiveTrustAnchorsParams{AssetID: req.AssetID, AtTime: now})
	if err != nil {
		return "", fmt.Errorf("list anchors for observation: %w", err)
	}
	outcome := string(ProbeSucceeded)
	var failureCategory FailureCategory
	if len(anchors) > 0 && !resultMatchesAnchors(result, anchors, now) {
		outcome = "mismatch"
		failureCategory = FailureTargetIdentityChanged
	}

	observationID, err := s.insertObservation(ctx, tx, observationInsert{
		AssetID: req.AssetID, EndpointRevision: revision, WorkerID: req.WorkerID,
		Source: ObservationProbe, Outcome: outcome, ObservedAt: now,
		Kubernetes: result.Kubernetes, Evidence: result.Evidence, FailureCategory: failureCategory,
	})
	if err != nil {
		return "", err
	}
	if err := s.enqueue(ctx, q, eventProbeSucceeded, uuid.Nil, req.AssetID, map[string]any{
		"observation_id": observationID.String(), "worker_id": req.WorkerID, "source": "agent",
	}); err != nil {
		return "", err
	}
	if err := s.enqueue(ctx, q, eventObservationAccepted, uuid.Nil, req.AssetID, map[string]any{
		"observation_id": observationID.String(), "outcome": outcome,
	}); err != nil {
		return "", err
	}
	if outcome == "mismatch" {
		if err := s.enqueue(ctx, q, eventRuntimeMismatch, uuid.Nil, req.AssetID, map[string]any{
			"observation_id": observationID.String(), "source": ObservationProbe,
		}); err != nil {
			return "", err
		}
	}
	status, err := s.statusAt(ctx, tx, StatusRequest{AssetID: req.AssetID}, now)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit agent observation: %w", err)
	}
	return status, nil
}

// tlsChainEvidence normalizes a leaf-first DER chain into typed identity evidence:
// the first cert is the tls_leaf, the rest are tls_intermediate. Roots absent from
// the presented chain are not fabricated.
func tlsChainEvidence(chainDER [][]byte) ([]Evidence, error) {
	out := make([]Evidence, 0, len(chainDER))
	for i, der := range chainDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse chain cert %d: %w", i, err)
		}
		kind := EvidenceTLSIntermediate
		if i == 0 {
			kind = EvidenceTLSLeaf
		}
		sum := sha256.Sum256(cert.Raw)
		out = append(out, Evidence{
			Kind:               kind,
			Algorithm:          cert.PublicKeyAlgorithm.String(),
			Fingerprint:        "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
			PublicMaterial:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
			CertificateSubject: cert.Subject.String(),
			CertificateIssuer:  cert.Issuer.String(),
			DNSNames:           cert.DNSNames,
			IPAddresses:        ipStrings(cert.IPAddresses),
			SerialNumber:       cert.SerialNumber.String(),
			ValidFrom:          cert.NotBefore,
			ValidUntil:         cert.NotAfter,
		})
	}
	return out, nil
}

func ipStrings(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
