// Package pgconv holds the tiny pgtype<->Go conversion helpers shared across the
// domain services and handlers. It is a leaf: it imports only the pgx/uuid types,
// never a domain package, so any package may depend on it without forming a cycle.
package pgconv

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// UUID wraps a uuid.UUID as a valid pgtype.UUID.
func UUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// Text maps "" to a NULL pgtype.Text, else a valid one.
func Text(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// UUIDString renders a nullable pgtype.UUID as a string ("" for NULL).
func UUIDString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

// OptUUID parses a possibly-empty UUID string. Empty → (pgtype.UUID{}, false, nil);
// a valid string → (UUID(id), true, nil); a malformed string → the parse error.
func OptUUID(s string) (pgtype.UUID, bool, error) {
	if s == "" {
		return pgtype.UUID{}, false, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, false, err
	}
	return UUID(id), true, nil
}
