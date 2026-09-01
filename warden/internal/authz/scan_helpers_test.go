package authz

import (
	"fmt"

	"github.com/google/uuid"
)

// scanUUIDs collects a single-column uuid result into a slice. Test-only: the
// recursive-ltree and folder-anchor differential tests scan raw rows to compare
// against the production set-based queries.
func scanUUIDs(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]uuid.UUID, error) {
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan uuid: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// scanUUIDSet collects a single-column uuid result into a set. Test-only (see scanUUIDs).
func scanUUIDSet(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) (map[uuid.UUID]struct{}, error) {
	out := map[uuid.UUID]struct{}{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan uuid: %w", err)
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}
