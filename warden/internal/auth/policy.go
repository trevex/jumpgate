package auth

import (
	"errors"
	"fmt"
	"strings"
)

// minPasswordLen is the local password-policy floor for local accounts.
const minPasswordLen = 12

// commonPasswords is a small embedded blocklist of the most-abused passwords.
// It is intentionally short — a full breach corpus is out of scope for a
// self-hosted, possibly air-gapped deployment (no external HIBP call).
// Entries shorter than minPasswordLen ("password", "changeme", "letmein") are
// unreachable via the length check above and are defense-in-depth only —
// they start mattering if minPasswordLen is ever lowered. Not dead code.
var commonPasswords = map[string]struct{}{
	"password":            {},
	"password1234":        {},
	"administrator":       {},
	"changeme":            {},
	"letmein":             {},
	"qwerty123456":        {},
	"111111111111":        {},
	"admin-password-1234": {},
}

// ValidatePassword enforces the local password policy. currentHash, when
// non-empty, is the account's existing hash; a new password equal to it is
// rejected (no reuse). It returns nil when the password is acceptable.
func ValidatePassword(pw, currentHash string) error {
	if len(pw) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	if _, bad := commonPasswords[strings.ToLower(pw)]; bad {
		return errors.New("password is too common")
	}
	// currentHash is "" from every current caller (CreateUser, EnsureAdmin,
	// SetLocalPassword); this branch only activates once a change-password RPC
	// passes the account's existing hash.
	if currentHash != "" {
		if ok, _ := VerifyPassword(pw, currentHash); ok {
			return errors.New("new password must differ from the current password")
		}
	}
	return nil
}

// NormalizeEmail lower-cases and trims an email for consistent login identity.
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }
