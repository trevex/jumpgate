package rpc

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// pgUUID wraps a uuid.UUID as a valid pgtype.UUID.
func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

// joinPath builds an asset's DNS-style path: the asset name (the leaf) followed by
// its folder's leaf->root path. folderPath is the containing folder's own leaf-first
// path (empty only defensively — a real asset always has a folder).
func joinPath(folderPath, name string) string {
	if folderPath == "" {
		return name
	}
	return name + "." + folderPath
}
