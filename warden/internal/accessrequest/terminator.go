package accessrequest

import (
	"context"

	"github.com/google/uuid"
)

// GrantTerminator is notified when a grant is revoked or expires so any live
// sessions relying on it can be torn down. M4 implements this against the gateway;
// until then NoopTerminator is used. (See docs/security.md — continuous revocation.)
type GrantTerminator interface {
	TerminateGrant(ctx context.Context, grantID uuid.UUID) error
}

// NoopTerminator is the default GrantTerminator: it does nothing. It is used
// until M4 wires session teardown against the gateway.
type NoopTerminator struct{}

// TerminateGrant does nothing and never errors.
func (NoopTerminator) TerminateGrant(context.Context, uuid.UUID) error { return nil }
