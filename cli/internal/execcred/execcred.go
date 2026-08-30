// Package execcred marshals client-go ExecCredential responses and manages the
// on-disk bearer-token cache for the `jumpgate k8s auth` exec-plugin. No client-go
// dependency — the ExecCredential JSON is a fixed, tiny shape.
package execcred

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// MarshalExecCredential renders a client.authentication.k8s.io/v1 ExecCredential
// with the bearer token + expiry, as kubectl expects on stdout.
func MarshalExecCredential(token string, expiry time.Time) ([]byte, error) {
	type status struct {
		Token               string `json:"token"`
		ExpirationTimestamp string `json:"expirationTimestamp"`
	}
	type cred struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     status `json:"status"`
	}
	return json.Marshal(cred{
		APIVersion: "client.authentication.k8s.io/v1",
		Kind:       "ExecCredential",
		Status:     status{Token: token, ExpirationTimestamp: expiry.UTC().Format(time.RFC3339)},
	})
}

// Entry is one cached token.
type Entry struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Cache is the on-disk token cache (default ~/.kube/cache/jumpgate).
type Cache struct {
	Dir    string
	Margin time.Duration // treat tokens expiring within Margin as misses
}

// DefaultCache builds a Cache at ~/.kube/cache/jumpgate with a 1-minute margin.
func DefaultCache() (*Cache, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &Cache{Dir: filepath.Join(home, ".kube", "cache", "jumpgate"), Margin: time.Minute}, nil
}

func (c *Cache) path(asset string) string { return filepath.Join(c.Dir, asset+".json") }

// Load returns a still-valid cached entry (expiry beyond now+Margin), else ok=false.
func (c *Cache) Load(asset string) (Entry, bool) {
	b, err := os.ReadFile(c.path(asset)) //nolint:gosec // path built from a resolved asset id
	if err != nil {
		return Entry{}, false
	}
	var e Entry
	if json.Unmarshal(b, &e) != nil {
		return Entry{}, false
	}
	if time.Now().Add(c.Margin).After(e.ExpiresAt) {
		return Entry{}, false
	}
	return e, true
}

// Store writes an entry atomically (temp file + rename), 0600, dir 0700.
// ponytail: atomic write-rename is the concurrency guard for parallel kubectl
// invocations racing the cache; a full flock is overkill for a last-writer-wins
// token cache — add one if two concurrent mints ever corrupt a read.
func (c *Cache) Store(asset, token string, expiry time.Time) error {
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(Entry{Token: token, ExpiresAt: expiry})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.Dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, c.path(asset))
}
