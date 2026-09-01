package dataplane

// Audit event types for the data-plane session lifecycle.
const (
	EventSessionStarted    = "session.started"
	EventSessionEnded      = "session.ended"
	EventSessionTerminated = "session.terminated"

	EventRecordingCompleted = "recording.completed"
	EventRecordingFailed    = "recording.failed"
	EventRecordingAccessed  = "recording.accessed"
)
