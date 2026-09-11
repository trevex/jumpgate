package identity

// EventLocalPasswordSet records a break-glass local password set or clear on a
// user (see Service.SetLocalPassword). Details carry {"action": "set"|"clear"}.
const EventLocalPasswordSet = "auth.local_password.set" //nolint:gosec // audit event name, not a secret
