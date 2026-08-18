package accessrequest

// Audit event types emitted by the JIT access-request workflow.
const (
	EventRequestCreated   = "access_request.created"
	EventRequestApproved  = "access_request.approved"
	EventRequestDenied    = "access_request.denied"
	EventRequestCancelled = "access_request.cancelled"
	EventGrantActivated   = "access_grant.activated"
	EventGrantRevoked     = "access_grant.revoked"
	EventGrantExpired     = "access_grant.expired"
)
