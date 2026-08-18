package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
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
	sealed, err := s.Seal(pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, pt) {
		t.Fatal("plaintext leaked into sealed blob")
	}
	got, err := s.Open(sealed)
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
	sealed, _ := s1.Seal([]byte("x"))
	if _, err := s2.Open(sealed); err == nil {
		t.Fatal("open with wrong KEK must fail")
	}
}

func TestTamperFails(t *testing.T) {
	s, _ := NewSealer(testKey(t))
	sealed, _ := s.Seal([]byte("hello world"))
	sealed[len(sealed)-1] ^= 0xff
	if _, err := s.Open(sealed); err == nil {
		t.Fatal("tampered blob must fail GCM")
	}
}

func TestNewSealerRejectsShortKey(t *testing.T) {
	if _, err := NewSealer(make([]byte, 16)); err == nil {
		t.Fatal("must reject non-32-byte KEK")
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
