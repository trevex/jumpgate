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
    /// `mode` — admission mode. `"web"` for browser-terminal tickets (no client
    /// key, ticket-bound login); empty or `"ssh"` for the CLI tunnel path.
    /// Absent on older tokens → `""`.
    pub mode: String,
    /// `login` — the ticket-bound target login. Set on `mode="web"` tickets (the
    /// browser offers no SSH username); empty otherwise. Absent → `""`.
    pub login: String,
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
    // Optional claims default to "" when absent (older/SSH tokens omit them).
    let get_opt = |k: &'static str| -> String {
        claims
            .get_claim(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default()
    };

    Ok(Claims {
        session_id: get("jti")?,
        user_id: get("sub")?,
        asset_id: get("asset")?,
        proto: get("proto")?,
        mode: get_opt("mode"),
        login: get_opt("login"),
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

    /// Mint a web-mode ticket: `mode="web"`, a bound `login`, and an empty `cnf`
    /// (browser tickets carry no client-key confirmation). Returns the token and
    /// the verifying public key.
    fn mint_web_token(login: &str, exp_offset_secs: i64) -> (String, Vec<u8>) {
        use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let pk_bytes = kp.public.as_bytes().to_vec();

        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::seconds(exp_offset_secs);
        let past = now - Duration::seconds(120);

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
        claims.add_additional("proto", "ssh").unwrap();
        claims.add_additional("mode", "web").unwrap();
        claims.add_additional("login", login).unwrap();
        // Web tickets carry an empty cnf.
        claims.add_additional("cnf", "").unwrap();

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
    fn ssh_token_has_empty_mode_and_login() {
        // The CLI/SSH mint sets neither mode nor login → both read back "".
        let (tok, pk) = mint_test_token("ssh", 60);
        let claims = verify(&tok, &pk).unwrap();
        assert_eq!(claims.mode, "");
        assert_eq!(claims.login, "");
    }

    #[test]
    fn web_token_exposes_mode_and_login() {
        let (tok, pk) = mint_web_token("deploy", 60);
        let claims = verify(&tok, &pk).unwrap();
        assert_eq!(claims.mode, "web");
        assert_eq!(claims.login, "deploy");
        assert_eq!(claims.proto, "ssh");
    }

    #[test]
    fn web_token_rejected_when_expired() {
        let (tok, pk) = mint_web_token("deploy", -60);
        assert!(verify(&tok, &pk).is_err());
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

    /// Decode a hex string into bytes (two hex chars per byte). Dependency-free
    /// helper so the interop fixture below needs no new crate.
    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(
            s.len().is_multiple_of(2),
            "hex string must have even length"
        );
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn verifies_warden_go_minted_token() {
        // Fixture minted by warden's Go sessiontoken.NewMinter (deterministic key,
        // exp in the year ~2126). Regenerate via warden/cmd/_fixturegen if the token
        // format ever changes. This locks Go(mint)↔Rust(verify) interop.
        const PUB_HEX: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
        const TOKEN: &str = "v4.public.eyJhc3NldCI6IjMzMzMzMzMzLTMzMzMtMzMzMy0zMzMzLTMzMzMzMzMzMzMzMyIsImNuZiI6IlNIQTI1Njp0ZXN0ZnAiLCJleHAiOiIyMTI2LTA3LTI2VDAwOjA2OjIzKzAyOjAwIiwiaWF0IjoiMjAyNi0wOC0xOVQwMDowNjoyMyswMjowMCIsImp0aSI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSIsIm5iZiI6IjIwMjYtMDgtMTlUMDA6MDY6MjMrMDI6MDAiLCJwcm90byI6InNzaCIsInN1YiI6IjIyMjIyMjIyLTIyMjItMjIyMi0yMjIyLTIyMjIyMjIyMjIyMiJ918TzS_fvJksEalGIxAXrSnUNFsAyp7Xh_uHPRnPUt07eIVBIrgcDxXxHc_So3nXYb4BMoDPzIylhxGlX1VVOCA";
        let pk = hex_decode(PUB_HEX);
        let claims = verify(TOKEN, &pk).expect("warden-minted token must verify");
        assert_eq!(claims.proto, "ssh");
        assert_eq!(claims.session_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(claims.user_id, "22222222-2222-2222-2222-222222222222");
        assert_eq!(claims.asset_id, "33333333-3333-3333-3333-333333333333");
        // Negative control: flip one pubkey byte → must fail.
        let mut bad = pk.clone();
        bad[0] ^= 0xff;
        assert!(verify(TOKEN, &bad).is_err());
    }
}
