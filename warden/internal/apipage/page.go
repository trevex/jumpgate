// Package apipage provides the shared keyset-cursor pagination codec used by the
// ConnectRPC handlers. It is a transport leaf: it imports only connect and stdlib
// and never a domain module, so any domain handler may depend on it.
package apipage

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
)

// PageKey is the decoded keyset cursor. Exactly one of Name/Time is meaningful,
// matching the list's sort order; ID is always the unique tiebreak.
type PageKey struct {
	Name string     `json:"n,omitempty"`
	Time *time.Time `json:"t,omitempty"`
	ID   uuid.UUID  `json:"id"`
}

// ClampPageSize applies the [1,100] range with a default of 50. Returns int64 to
// match the sqlc LIMIT parameter type (Postgres LIMIT is bigint).
func ClampPageSize(n int32) int64 {
	if n <= 0 || n > 100 {
		return 50
	}
	return int64(n)
}

// EncodeNameToken encodes a name-ordered keyset cursor.
func EncodeNameToken(name string, id uuid.UUID) string {
	return encodeKey(PageKey{Name: name, ID: id})
}

// EncodeTimeToken encodes a time-ordered keyset cursor (normalized to UTC).
func EncodeTimeToken(ts time.Time, id uuid.UUID) string {
	t := ts.UTC()
	return encodeKey(PageKey{Time: &t, ID: id})
}

func encodeKey(k PageKey) string {
	b, _ := json.Marshal(k)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodePageToken returns nil,nil for an empty token; a malformed token yields a
// connect InvalidArgument error so handlers can return it directly.
func DecodePageToken(tok string) (*PageKey, error) {
	if tok == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad page_token"))
	}
	var k PageKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad page_token"))
	}
	// The tiebreak id is mandatory; a token without it (tampered/truncated) would
	// otherwise page against uuid.Nil and silently return wrong results.
	if k.ID == uuid.Nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad page_token"))
	}
	return &k, nil
}
