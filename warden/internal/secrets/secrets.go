// Package secrets provides envelope encryption at rest: a random 256-bit DEK per
// secret encrypts the plaintext (AES-256-GCM); the DEK is wrapped by a master KEK.
// The wrapped-DEK step is the future KMS seam; master-key rotation re-wraps DEKs
// without touching ciphertexts.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// Sealer seals/opens secrets under a 32-byte master KEK.
type Sealer struct{ kek []byte }

// NewSealer validates the KEK is 32 bytes (AES-256).
func NewSealer(kek []byte) (*Sealer, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(kek))
	}
	return &Sealer{kek: append([]byte(nil), kek...)}, nil
}

// ErrNotConfigured is returned when no master key is present.
var ErrNotConfigured = errors.New("vault not configured (VAULT_MASTER_KEY unset)")

// MasterKeyFromConfig decodes a base64 32-byte key; empty → ErrNotConfigured.
func MasterKeyFromConfig(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, ErrNotConfigured
	}
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode VAULT_MASTER_KEY: %w", err)
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("VAULT_MASTER_KEY must decode to 32 bytes, got %d", len(k))
	}
	return k, nil
}

// Sealed-blob layout widths. wrappedDEKLen = 32B DEK + 16B GCM tag. Open parses
// these fixed widths, so gcmSeal asserts the GCM nonce size matches nonceLen —
// otherwise Seal's output and Open's parse would silently desync.
const (
	sealVersion   = 1
	nonceLen      = 12 // standard AES-GCM nonce size
	wrappedDEKLen = 48
	sealHeaderLen = 1 + nonceLen + wrappedDEKLen + nonceLen
)

func gcmSeal(key, pt []byte) (nonce, ct []byte, err error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, nil, err
	}
	if g.NonceSize() != nonceLen {
		return nil, nil, fmt.Errorf("unexpected GCM nonce size %d (want %d)", g.NonceSize(), nonceLen)
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, g.Seal(nil, nonce, pt, nil), nil
}

func gcmOpen(key, nonce, ct []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ct, nil)
}

// Seal returns a versioned sealed blob:
//
//	[1B version=1][dekNonce 12][wrappedDEK 48][ctNonce 12][ct...]
//
// wrappedDEK = 32B DEK + 16B GCM tag = 48; GCM nonce = 12. Fixed widths make
// parsing unambiguous.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	ctNonce, ct, err := gcmSeal(dek, plaintext)
	if err != nil {
		return nil, err
	}
	wrapNonce, wrapped, err := gcmSeal(s.kek, dek)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, sealHeaderLen+len(ct))
	out = append(out, sealVersion)
	out = append(out, wrapNonce...)
	out = append(out, wrapped...)
	out = append(out, ctNonce...)
	out = append(out, ct...)
	return out, nil
}

// Open reverses Seal. Fails (fail-closed) on a wrong KEK, a tampered blob, or a
// malformed layout.
func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < sealHeaderLen || sealed[0] != sealVersion {
		return nil, errors.New("malformed sealed blob")
	}
	p := 1
	wrapNonce := sealed[p : p+nonceLen]
	p += nonceLen
	wrapped := sealed[p : p+wrappedDEKLen]
	p += wrappedDEKLen
	ctNonce := sealed[p : p+nonceLen]
	p += nonceLen
	ct := sealed[p:]
	dek, err := gcmOpen(s.kek, wrapNonce, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK: %w", err)
	}
	return gcmOpen(dek, ctNonce, ct)
}
