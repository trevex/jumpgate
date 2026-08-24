package rpc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
)

// pageKey is the decoded keyset cursor. Exactly one of Name/Time is meaningful,
// matching the list's sort order; ID is always the unique tiebreak.
type pageKey struct {
	Name string     `json:"n,omitempty"`
	Time *time.Time `json:"t,omitempty"`
	ID   uuid.UUID  `json:"id"`
}

// clampPageSize applies the [1,100] range with a default of 50.
func clampPageSize(n int32) int32 {
	if n <= 0 || n > 100 {
		return 50
	}
	return n
}

func encodeNameToken(name string, id uuid.UUID) string {
	return encodeKey(pageKey{Name: name, ID: id})
}

func encodeTimeToken(ts time.Time, id uuid.UUID) string {
	t := ts.UTC()
	return encodeKey(pageKey{Time: &t, ID: id})
}

func encodeKey(k pageKey) string {
	b, _ := json.Marshal(k)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodePageToken returns nil,nil for an empty token; a malformed token yields a
// connect InvalidArgument error so handlers can return it directly.
func decodePageToken(tok string) (*pageKey, error) {
	if tok == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad page_token"))
	}
	var k pageKey
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
