package identity

// EventLocalPasswordSet records a break-glass local password set or clear on a
// user (see Service.SetLocalPassword). Details carry {"action": "set"|"clear"}.
const EventLocalPasswordSet = "auth.local_password.set" //nolint:gosec // audit event name, not a secret

// EventGroupExternalKeySet records a group's external_key (OIDC membership sync
// mapping key) being set or cleared (see Service.SetGroupExternalKey). Details
// carry {"action": "set"|"clear"}.
const EventGroupExternalKeySet = "identity.group.external_key_set"
