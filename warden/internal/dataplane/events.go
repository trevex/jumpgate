package dataplane

// Audit event types for the data-plane session lifecycle.
const (
	EventSessionStarted    = "session.started"
	EventSessionPrepared   = "session.prepared"
	EventSessionAborted    = "session.aborted"
	EventSessionEnded      = "session.ended"
	EventSessionTerminated = "session.terminated"

	// EventTargetIdentityVerified is recorded when a worker's observed target
	// identity matches a current active anchor and a credential is released.
	EventTargetIdentityVerified = "target.identity_verified"

	EventRecordingCompleted = "recording.completed"
	EventRecordingFailed    = "recording.failed"
	EventRecordingAccessed  = "recording.accessed"
)
