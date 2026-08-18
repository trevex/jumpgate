// Package session manages the DB-backed Ed25519 signing key used to mint and
// verify session tokens. The private half is sealed at rest via secrets.Sealer
// (envelope encryption); the KeyStore generates the first key (admin/init path)
// and unseals the active key at boot.
package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/secrets"
)

// ErrNoActiveKey is returned when no active session signing key exists.
var ErrNoActiveKey = errors.New("no active session signing key")

// KeyStore generates, seals, and loads the active Ed25519 session signing key.
type KeyStore struct {
	q      *gen.Queries
	sealer *secrets.Sealer
}

// NewKeyStore constructs a KeyStore. A nil sealer disables Init/LoadActive (they
// fail closed) — matching the vault-disabled posture.
func NewKeyStore(q *gen.Queries, sealer *secrets.Sealer) *KeyStore {
	return &KeyStore{q: q, sealer: sealer}
}

// Init generates a fresh Ed25519 keypair, seals the private half, and stores it as
// the active key. A second Init hits the unique-active index and errors.
func (k *KeyStore) Init(ctx context.Context) error {
	if k.sealer == nil {
		return secrets.ErrNotConfigured
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	sealed, err := k.sealer.Seal(priv)
	if err != nil {
		return err
	}
	if _, err := k.q.CreateSessionSigningKey(ctx, gen.CreateSessionSigningKeyParams{
		Sealed: sealed, PublicKey: pub,
	}); err != nil {
		return fmt.Errorf("store signing key: %w", err)
	}
	return nil
}

// LoadActive unseals and returns the active (private, public) key pair.
func (k *KeyStore) LoadActive(ctx context.Context) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if k.sealer == nil {
		return nil, nil, secrets.ErrNotConfigured
	}
	row, err := k.q.GetActiveSessionSigningKey(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNoActiveKey
	}
	if err != nil {
		return nil, nil, err
	}
	priv, err := k.sealer.Open(row.Sealed)
	if err != nil {
		return nil, nil, fmt.Errorf("open signing key: %w", err)
	}
	return ed25519.PrivateKey(priv), ed25519.PublicKey(row.PublicKey), nil
}
