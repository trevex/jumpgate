package rpc

import (
	"context"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
)

// requestReadAuthorizer authorizes display reads for callers who are party to a
// pending access request referencing the entity (the requester or a standing
// approver). It is additive to capability checks: handlers consult it only after
// a capability check denies. Backed by *accessrequest.Service; injected into the
// Catalog and Access servers so both can grant request-scoped decision-context
// reads without leaking secret material.
type requestReadAuthorizer interface {
	CanReadForRequest(ctx context.Context, caller uuid.UUID, kind accessrequest.ReqEntityKind, id uuid.UUID) (bool, error)
}
