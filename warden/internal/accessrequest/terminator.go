package accessrequest

import (
	"context"

	"github.com/google/uuid"
)

// GrantTerminator is notified when a grant is revoked or expires so any live
// sessions relying on it can be torn down. The dataplane terminator implements
// this against the gateway. (See docs/security.md — continuous revocation.)
type GrantTerminator interface {
	TerminateGrant(ctx context.Context, grantID uuid.UUID) error
}

// NoopTerminator is the default GrantTerminator: it does nothing.
type NoopTerminator struct{}

// TerminateGrant does nothing and never errors.
func (NoopTerminator) TerminateGrant(context.Context, uuid.UUID) error { return nil }
