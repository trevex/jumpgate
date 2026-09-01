// Package enrollment mints single-use, asset-scoped agent enrollment tokens and
// exchanges them for short-lived asset-scoped mesh client certificates.
package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/mesh"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
)

const (
	enrollmentTokenTTL = 30 * time.Minute
	agentCertTTL       = 24 * time.Hour // renewal lands in slice 1b-ii
)

// ErrInvalidToken is returned when an enrollment token is unknown, expired, or
// already consumed. Deliberately opaque (no distinction) to avoid an oracle.
var ErrInvalidToken = errors.New("invalid enrollment token")

// ErrNoMeshCA is returned when no active mesh CA is provisioned.
var ErrNoMeshCA = errors.New("no active mesh CA")

// Service mints/consumes enrollment tokens and signs agent mesh certs.
type Service struct {
	pool   *pgxpool.Pool
	q      *sqlc.Queries
	sealer *secrets.Sealer
}

// NewService builds the enrollment service.
func NewService(pool *pgxpool.Pool, sealer *secrets.Sealer) *Service {
	return &Service{pool: pool, q: sqlc.New(pool), sealer: sealer}
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// Mint creates a single-use enrollment token bound to assetID and returns the
// raw token (shown once) and its expiry. Only the SHA-256 hash is stored.
func (s *Service) Mint(ctx context.Context, assetID uuid.UUID) (string, time.Time, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, fmt.Errorf("rand: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	exp := time.Now().Add(enrollmentTokenTTL)
	if _, err := s.q.CreateAgentEnrollmentToken(ctx, sqlc.CreateAgentEnrollmentTokenParams{
		AssetID:   assetID,
		TokenHash: hashToken(raw),
		ExpiresAt: pgtype.Timestamptz{Time: exp, Valid: true},
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("create enrollment token: %w", err)
	}
	return raw, exp, nil
}

// SignAgentCert atomically consumes rawToken (single-use, must be unexpired),
// then signs the CSR into a mesh leaf cert whose SPIFFE URI is derived from the
// bound asset (never from the CSR). Returns the leaf PEM and the mesh CA bundle.
func (s *Service) SignAgentCert(ctx context.Context, rawToken string, csrPEM []byte) (certPEM, caBundlePEM []byte, err error) {
	// Validate the CSR and load the CA BEFORE consuming the single-use token, so a
	// transient CA failure (e.g. mesh CA not yet provisioned at cluster bring-up)
	// doesn't burn the token and strand the agent with a dead credential. The
	// ConsumeAgentEnrollmentToken DELETE…RETURNING remains the atomic single-use
	// gate regardless of ordering.
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, nil, errors.New("invalid CSR PEM")
	}

	caRow, err := s.q.GetActiveCA(ctx, "mesh")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNoMeshCA
		}
		return nil, nil, fmt.Errorf("get mesh CA: %w", err)
	}
	keyDER, err := s.sealer.Open(caRow.Sealed, secrets.AADCA("mesh"))
	if err != nil {
		return nil, nil, fmt.Errorf("unseal mesh CA: %w", err)
	}
	mca, err := ca.LoadMeshCA(keyDER, []byte(caRow.PublicMaterial))
	if err != nil {
		return nil, nil, fmt.Errorf("load mesh CA: %w", err)
	}

	assetID, err := s.q.ConsumeAgentEnrollmentToken(ctx, hashToken(rawToken))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrInvalidToken
		}
		return nil, nil, fmt.Errorf("consume enrollment token: %w", err)
	}

	spiffeID := mesh.Identity{Role: "agent", ID: assetID.String()}.SpiffeID()
	return mca.SignCSR(block.Bytes, spiffeID, agentCertTTL)
}
