package vault

// EventCredentialIssued is the audit event type emitted when the Broker issues a
// credential (SSH certificate or stored secret) for an asset.
const EventCredentialIssued = "credential.issued" //nolint:gosec // audit event name, not a secret
