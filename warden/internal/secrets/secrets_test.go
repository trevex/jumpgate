package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := NewSealer(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("super-secret-ca-seed")
	sealed, err := s.Seal(pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, pt) {
		t.Fatal("plaintext leaked into sealed blob")
	}
	got, err := s.Open(sealed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestWrongKeyFails(t *testing.T) {
	s1, _ := NewSealer(testKey(t))
	s2, _ := NewSealer(testKey(t))
	sealed, _ := s1.Seal([]byte("x"), nil)
	if _, err := s2.Open(sealed, nil); err == nil {
		t.Fatal("open with wrong KEK must fail")
	}
}

func TestTamperFails(t *testing.T) {
	s, _ := NewSealer(testKey(t))
	sealed, _ := s.Seal([]byte("hello world"), nil)
	sealed[len(sealed)-1] ^= 0xff
	if _, err := s.Open(sealed, nil); err == nil {
		t.Fatal("tampered blob must fail GCM")
	}
}

func TestNewSealerRejectsShortKey(t *testing.T) {
	if _, err := NewSealer(make([]byte, 16)); err == nil {
		t.Fatal("must reject non-32-byte KEK")
	}
}

func TestOpenRejectsMalformed(t *testing.T) {
	s, _ := NewSealer(testKey(t))
	for n := 0; n < sealHeaderLen; n++ { // short blobs must fail closed, not panic
		if _, err := s.Open(make([]byte, n), nil); err == nil {
			t.Fatalf("len %d must fail", n)
		}
	}
	good, _ := s.Seal([]byte("x"), nil)
	bad := append([]byte(nil), good...)
	bad[0] = 2 // wrong version
	if _, err := s.Open(bad, nil); err == nil {
		t.Fatal("wrong version must fail")
	}
	bad2 := append([]byte(nil), good...)
	bad2[1+nonceLen] ^= 0xff // tamper the wrapped-DEK region, not just the ct
	if _, err := s.Open(bad2, nil); err == nil {
		t.Fatal("tampered wrapped DEK must fail")
	}
}

func TestEmptyPlaintextRoundTrips(t *testing.T) {
	s, _ := NewSealer(testKey(t))
	sealed, err := s.Seal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Open(sealed, nil)
	if err != nil {
		t.Fatalf("empty round-trip: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d bytes", len(got))
	}
}

func TestSealAADMismatch(t *testing.T) {
	s, _ := NewSealer(testKey(t))
	pt := []byte("bound-to-asset-A")
	sealed, err := s.Seal(pt, AADAssetSecret(uuid.New()))
	if err != nil {
		t.Fatal(err)
	}
	// Relocation defense: opening with a DIFFERENT AAD must fail closed.
	if _, err := s.Open(sealed, AADAssetSecret(uuid.New())); err == nil {
		t.Fatal("open with mismatched AAD must fail")
	}
	if _, err := s.Open(sealed, AADCA("ssh")); err == nil {
		t.Fatal("open with wrong-namespace AAD must fail")
	}
	// Correctly-paired AAD round-trips.
	id := uuid.New()
	sealed2, _ := s.Seal(pt, AADAssetSecret(id))
	got, err := s.Open(sealed2, AADAssetSecret(id))
	if err != nil {
		t.Fatalf("matched AAD must open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestMasterKeyFromConfig(t *testing.T) {
	if _, err := MasterKeyFromConfig(""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("empty must be ErrNotConfigured, got %v", err)
	}
	if _, err := MasterKeyFromConfig("not-base64!!!"); err == nil {
		t.Fatal("bad base64 must error")
	}
	if _, err := MasterKeyFromConfig(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("16-byte key must error")
	}
	k, err := MasterKeyFromConfig(base64.StdEncoding.EncodeToString(testKey(t)))
	if err != nil || len(k) != 32 {
		t.Fatalf("valid key: %v len=%d", err, len(k))
	}
}
