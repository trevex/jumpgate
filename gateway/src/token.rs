//! Offline verification of PASETO v4.public session tokens. The gateway verifies
//! the Ed25519 signature + time claims and reads `proto` for routing; it does NOT
//! check `cnf` (the worker re-checks the client key at SetupSession). Fail closed.
//!
//! Tokens are minted by warden's Go `sessiontoken` package (PASETO v4.public,
//! `aidanwoods.dev/go-paseto`) with registered claims `jti` (session id), `sub`
//! (user id), `exp`/`nbf`/`iat`, and custom `asset`, `proto`, `cnf`. We verify
//! with the Ed25519 *public* key alone — no warden round-trip on the hot path.

/// The claims the gateway needs for routing and logging.
#[derive(Debug, Clone)]
pub struct Claims {
    /// `jti` — the session id (also warden's live_sessions PK / teardown target).
    pub session_id: String,
    /// `sub` — the user id (identity for logging).
    pub user_id: String,
    /// `asset` — the target asset id.
    pub asset_id: String,
    /// `proto` — protocol, e.g. "ssh"; selects the worker pool.
    pub proto: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token verification failed")]
    Verify,
    #[error("bad public key")]
    Key,
    #[error("missing claim {0}")]
    MissingClaim(&'static str),
}

/// Verify a v4.public token against the 32-byte Ed25519 public key. Enforces the
/// signature and the `exp`/`nbf`/`iat` time claims (via the default
/// [`ClaimsValidationRules`]), then returns the routing claims. Any failure —
/// bad key, bad signature, expired/not-yet-valid, malformed token, or a missing
/// claim — returns `Err`; no partial or default [`Claims`] ever escape on error
/// (fail closed).
pub fn verify(token: &str, ed25519_public_key: &[u8]) -> Result<Claims, TokenError> {
    use pasetors::claims::ClaimsValidationRules;
    use pasetors::keys::AsymmetricPublicKey;
    use pasetors::token::UntrustedToken;
    use pasetors::version4::V4;
    use pasetors::{public, Public};

    let pk = AsymmetricPublicKey::<V4>::from(ed25519_public_key).map_err(|_| TokenError::Key)?;
    let untrusted =
        UntrustedToken::<Public, V4>::try_from(token).map_err(|_| TokenError::Verify)?;
    // Default rules validate `exp` (rejecting past expiry) and require + validate
    // `nbf`/`iat`. Custom claims (asset/proto/cnf) are not validated here.
    let rules = ClaimsValidationRules::new();
    let trusted =
        public::verify(&pk, &untrusted, &rules, None, None).map_err(|_| TokenError::Verify)?;
    let claims = trusted.payload_claims().ok_or(TokenError::Verify)?;

    let get = |k: &'static str| -> Result<String, TokenError> {
        claims
            .get_claim(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(TokenError::MissingClaim(k))
    };

    Ok(Claims {
        session_id: get("jti")?,
        user_id: get("sub")?,
        asset_id: get("asset")?,
        proto: get("proto")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasetors::claims::Claims as PasetoClaims;
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::public;
    use pasetors::version4::V4;

    /// Mint a v4.public token with warden's claim layout, signed with a freshly
    /// generated Ed25519 keypair. `exp_offset_secs` is relative to now: a negative
    /// value produces an already-expired token. Returns the token and the 32-byte
    /// Ed25519 public key that verifies it.
    fn mint_test_token(proto: &str, exp_offset_secs: i64) -> (String, Vec<u8>) {
        use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let pk_bytes = kp.public.as_bytes().to_vec();

        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::seconds(exp_offset_secs);
        // nbf/iat in the past so the token is currently valid (except for exp).
        let past = now - Duration::seconds(120);

        // Start from a non-expiring skeleton, then set our own time claims so we
        // can freely place `exp` in the past for the expiry test.
        let mut claims =
            PasetoClaims::new_expires_in(&core::time::Duration::from_secs(60)).unwrap();
        claims.expiration(&exp.format(&Rfc3339).unwrap()).unwrap();
        claims.not_before(&past.format(&Rfc3339).unwrap()).unwrap();
        claims.issued_at(&past.format(&Rfc3339).unwrap()).unwrap();

        claims
            .token_identifier("11111111-1111-1111-1111-111111111111")
            .unwrap();
        claims
            .subject("22222222-2222-2222-2222-222222222222")
            .unwrap();
        claims
            .add_additional("asset", "33333333-3333-3333-3333-333333333333")
            .unwrap();
        claims.add_additional("proto", proto).unwrap();
        claims
            .add_additional("cnf", "SHA256:testfingerprint")
            .unwrap();

        let token = public::sign(&kp.secret, &claims, None, None).unwrap();
        (token, pk_bytes)
    }

    #[test]
    fn verifies_valid_token_reads_proto() {
        let (tok, pk) = mint_test_token("ssh", 60);
        let claims = verify(&tok, &pk).unwrap();
        assert_eq!(claims.proto, "ssh");
        assert!(!claims.session_id.is_empty());
        assert!(!claims.user_id.is_empty());
        assert!(!claims.asset_id.is_empty());
    }

    #[test]
    fn rejects_wrong_key() {
        let (tok, _pk) = mint_test_token("ssh", 60);
        let (_t2, other_pk) = mint_test_token("ssh", 60);
        assert!(verify(&tok, &other_pk).is_err());
    }

    #[test]
    fn rejects_expired() {
        let (tok, pk) = mint_test_token("ssh", -60); // exp in the past
        assert!(verify(&tok, &pk).is_err());
    }

    #[test]
    fn rejects_tampered() {
        let (tok, pk) = mint_test_token("ssh", 60);
        let mut bad = tok.clone();
        bad.pop();
        bad.push('x');
        assert!(verify(&bad, &pk).is_err());
    }
}
