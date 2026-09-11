package auth

// Authentication audit event types. No raw email/password/token is ever placed
// in an event; a failed login against a real account carries the user id, an
// unknown email carries only reason=unknown_user.
const (
	EventLoginSucceeded  = "auth.login.succeeded"
	EventLoginFailed     = "auth.login.failed"
	EventLoginThrottled  = "auth.login.throttled"
	EventLogout          = "auth.logout"
	EventSessionRevoked  = "auth.session.revoked"
	EventSessionsRevoked = "auth.session.revoked_all"
)
