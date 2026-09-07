package targetidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

type approvalMutationResponse struct {
	Anchor TrustAnchor
	Status VerificationStatus
}

type batchApprovalMutationResponse struct {
	Anchors []TrustAnchor
	Status  VerificationStatus
}

type statusMutationResponse struct {
	Status VerificationStatus
}

func claimMutation[T any](ctx context.Context, q *sqlc.Queries, requestID uuid.UUID, operation string, assetID, actorID uuid.UUID, payload any, replay *T) (bool, error) {
	if requestID == uuid.Nil {
		return false, nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("marshal idempotency payload: %w", err)
	}
	hash := sha256.Sum256(raw)
	row, err := q.ClaimTargetIdentityMutation(ctx, sqlc.ClaimTargetIdentityMutationParams{
		RequestID: requestID, Operation: operation, AssetID: assetID,
		ActorID: nullableUUID(actorID), RequestHash: hash[:],
	})
	if err != nil {
		return false, fmt.Errorf("claim idempotency key: %w", err)
	}
	if row.Operation != operation || row.AssetID != assetID || !bytes.Equal(row.RequestHash, hash[:]) {
		return false, ErrIdempotencyConflict
	}
	if len(row.Response) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(row.Response, replay); err != nil {
		return false, fmt.Errorf("decode idempotency response: %w", err)
	}
	return true, nil
}

func completeMutation(ctx context.Context, q *sqlc.Queries, requestID uuid.UUID, response any) error {
	if requestID == uuid.Nil {
		return nil
	}
	raw, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("marshal idempotency response: %w", err)
	}
	if _, err := q.CompleteTargetIdentityMutation(ctx, sqlc.CompleteTargetIdentityMutationParams{Response: raw, RequestID: requestID}); err != nil {
		return fmt.Errorf("complete idempotency key: %w", err)
	}
	return nil
}
