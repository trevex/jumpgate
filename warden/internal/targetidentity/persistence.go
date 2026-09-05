package targetidentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

type observationInsert struct {
	JobID             pgtype.UUID
	AssetID           uuid.UUID
	EndpointRevision  int64
	WorkerID          string
	Source            ObservationSource
	Outcome           string
	ObservedAt        time.Time
	ResolvedAddresses []string
	SSH               *SSHMetadata
	TLS               *TLSMetadata
	Kubernetes        *KubernetesMetadata
	Evidence          []Evidence
	ValidationFacts   []ValidationFact
	FailureCategory   FailureCategory
	FailureDetail     string
}

type protocolMetadata struct {
	SSH        *SSHMetadata        `json:"ssh,omitempty"`
	TLS        *TLSMetadata        `json:"tls,omitempty"`
	Kubernetes *KubernetesMetadata `json:"kubernetes,omitempty"`
}

func (s *Service) insertObservation(ctx context.Context, tx pgx.Tx, in observationInsert) (uuid.UUID, error) {
	addresses, err := json.Marshal(cloneStrings(in.ResolvedAddresses))
	if err != nil {
		return uuid.Nil, ErrInvalidResult
	}
	metadata, err := json.Marshal(protocolMetadata{SSH: in.SSH, TLS: in.TLS, Kubernetes: in.Kubernetes})
	if err != nil {
		return uuid.Nil, ErrInvalidResult
	}
	validationState := "unvalidated"
	if len(in.ValidationFacts) > 0 {
		validationState = "validated"
	}
	q := sqlc.New(tx)
	observation, err := q.InsertIdentityObservation(ctx, sqlc.InsertIdentityObservationParams{
		JobID: in.JobID, AssetID: in.AssetID, EndpointRevision: in.EndpointRevision,
		WorkerID: in.WorkerID, Source: string(in.Source), ResolvedAddresses: addresses, ProtocolMetadata: metadata,
		ObservedAt: pgtype.Timestamptz{Time: in.ObservedAt, Valid: true}, Outcome: in.Outcome, ValidationState: validationState,
		FailureCategory: nullableText(string(in.FailureCategory)), FailureDetail: nullableText(in.FailureDetail),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert identity observation: %w", err)
	}
	type evidenceKey struct {
		kind        EvidenceKind
		fingerprint string
	}
	evidenceByKey := make(map[evidenceKey]uuid.UUID, len(in.Evidence))
	for _, item := range in.Evidence {
		keyMetadata, _ := json.Marshal(item.Key)
		extensions := make(map[string]string, len(item.DisplayExtensions))
		for _, extension := range item.DisplayExtensions {
			extensions[extension.Name] = extension.Value
		}
		displayExtensions, _ := json.Marshal(extensions)
		row, err := q.InsertIdentityEvidence(ctx, sqlc.InsertIdentityEvidenceParams{
			ObservationID: observation.ID, Kind: string(item.Kind), Algorithm: item.Algorithm,
			Sha256Fingerprint: item.Fingerprint, PublicMaterial: item.PublicMaterial,
			CertificateSubject: nullableText(item.CertificateSubject), CertificateIssuer: nullableText(item.CertificateIssuer),
			IssuerSha256Fingerprint: nullableText(item.IssuerFingerprint), DnsNames: cloneStrings(item.DNSNames),
			IpAddresses: cloneStrings(item.IPAddresses), SshPrincipals: cloneStrings(item.SSHPrincipals),
			SerialNumber: nullableText(item.SerialNumber), ValidFrom: nullableTime(item.ValidFrom), ValidUntil: nullableTime(item.ValidUntil),
			KeyMetadata: keyMetadata, DisplayExtensions: displayExtensions,
		})
		if err != nil {
			return uuid.Nil, fmt.Errorf("insert identity evidence: %w", err)
		}
		evidenceByKey[evidenceKey{kind: item.Kind, fingerprint: item.Fingerprint}] = row.ID
	}
	for _, fact := range in.ValidationFacts {
		evidenceID, ok := evidenceByKey[evidenceKey{kind: fact.EvidenceKind, fingerprint: fact.EvidenceFingerprint}]
		if !ok {
			return uuid.Nil, ErrInvalidResult
		}
		if err := q.InsertIdentityValidationFact(ctx, sqlc.InsertIdentityValidationFactParams{ObservationID: observation.ID, AssetID: in.AssetID, EndpointRevision: in.EndpointRevision, AnchorID: fact.AnchorID, EvidenceID: evidenceID}); err != nil {
			return uuid.Nil, fmt.Errorf("insert identity validation fact: %w", err)
		}
	}
	return observation.ID, nil
}

func listEvidence(ctx context.Context, db sqlc.DBTX, assetID uuid.UUID, revision int64) ([]Evidence, error) {
	rows, err := sqlc.New(db).ListIdentityEvidence(ctx, sqlc.ListIdentityEvidenceParams{AssetID: assetID, EndpointRevision: revision})
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	out := make([]Evidence, 0, len(rows))
	for _, row := range rows {
		out = append(out, evidenceFromRow(row))
	}
	return out, nil
}

func getEvidenceForApproval(ctx context.Context, db sqlc.DBTX, observationID, evidenceID uuid.UUID) (Evidence, error) {
	row, err := sqlc.New(db).GetIdentityEvidenceForApproval(ctx, sqlc.GetIdentityEvidenceForApprovalParams{ObservationID: observationID, EvidenceID: evidenceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Evidence{}, ErrEvidenceNotFound
	}
	if err != nil {
		return Evidence{}, fmt.Errorf("select approval evidence: %w", err)
	}
	return evidenceFromRow(row), nil
}

func (s *Service) enqueue(ctx context.Context, q *sqlc.Queries, eventType string, actorID, assetID uuid.UUID, details map[string]any) error {
	if s.audit == nil {
		return ErrAuditUnavailable
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}
	if err := s.audit.Enqueue(ctx, q, audit.Event{Type: eventType, ActorID: actorID, Subject: "asset:" + assetID.String(), Details: raw}); err != nil {
		return fmt.Errorf("enqueue %s audit: %w", eventType, err)
	}
	return nil
}

func lockExpectedRevision(ctx context.Context, q *sqlc.Queries, assetID uuid.UUID, expected int64) error {
	asset, err := q.LockTargetIdentityAsset(ctx, assetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAssetNotFound
		}
		return fmt.Errorf("lock asset: %w", err)
	}
	if asset.EndpointRevision != expected {
		return ErrStaleRevision
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
