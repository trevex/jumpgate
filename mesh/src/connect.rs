//! Minimal HTTP/1.1 CONNECT handshake used on both gateway legs: the client
//! tunnels via `CONNECT <authority>` + `Authorization: Bearer <token>`, and the
//! gateway forwards the same shape to the chosen worker.
#![allow(dead_code)] // helpers used across the workspace; not every consumer uses all of them

use tokio::io::{AsyncRead, AsyncReadExt};

/// Parsed CONNECT request.
#[derive(Debug, Clone)]
pub struct ConnectReq {
    pub authority: String,
    pub token: String,
}

/// Max CONNECT header size we will buffer before giving up (abuse guard).
pub const MAX_HEADER: usize = 8 * 1024;

/// Errors from CONNECT parsing.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("malformed request")]
    Malformed,
    #[error("not a CONNECT request")]
    NotConnect,
    #[error("missing bearer authorization")]
    MissingAuth,
    #[error("header too large")]
    TooLarge,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("worker refused CONNECT: {0}")]
    WorkerStatus(u16),
}

/// Parse a CONNECT request from `buf`. Returns:
/// - `Ok(Some((req, consumed)))` when a full header is present,
/// - `Ok(None)` when more bytes are needed,
/// - `Err(..)` on a malformed / non-CONNECT / missing-auth request.
pub fn parse_connect(buf: &[u8]) -> Result<Option<(ConnectReq, usize)>, ConnectError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    let status = req.parse(buf).map_err(|_| ConnectError::Malformed)?;
    let consumed = match status {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Ok(None),
    };
    if !req
        .method
        .map(|m| m.eq_ignore_ascii_case("CONNECT"))
        .unwrap_or(false)
    {
        return Err(ConnectError::NotConnect);
    }
    let authority = req.path.ok_or(ConnectError::Malformed)?.to_string();
    let mut token = None;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("authorization") {
            if let Ok(v) = std::str::from_utf8(h.value) {
                if let Some(t) = v
                    .strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
                {
                    token = Some(t.trim().to_string());
                }
            }
        }
    }
    let token = token.ok_or(ConnectError::MissingAuth)?;
    if token.is_empty() {
        return Err(ConnectError::MissingAuth);
    }
    Ok(Some((ConnectReq { authority, token }, consumed)))
}

/// Read a full CONNECT request from an async stream (up to MAX_HEADER bytes).
pub async fn read_connect<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<ConnectReq, ConnectError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some((req, _consumed)) = parse_connect(&buf)? {
            return Ok(req);
        }
        if buf.len() > MAX_HEADER {
            return Err(ConnectError::TooLarge);
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(ConnectError::Malformed); // EOF before full header
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// The success response the gateway sends the client after a worker leg is up.
pub fn response_established() -> &'static [u8] {
    b"HTTP/1.1 200 Connection Established\r\n\r\n"
}

/// An error response line (close after writing).
pub fn response_status(code: u16, reason: &str) -> Vec<u8> {
    format!("HTTP/1.1 {code} {reason}\r\n\r\n").into_bytes()
}

/// Build the CONNECT request the gateway sends the worker.
pub fn write_connect_request(authority: &str, token: &str) -> Vec<u8> {
    format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {token}\r\n\r\n"
    )
    .into_bytes()
}

/// Read + validate the worker's CONNECT response status line (expect 200).
pub async fn read_worker_response<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(), ConnectError> {
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        // Look for end of status line/headers.
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf).map_err(|_| ConnectError::Malformed)? {
            httparse::Status::Complete(_) => {
                let code = resp.code.ok_or(ConnectError::Malformed)?;
                if code == 200 {
                    return Ok(());
                }
                return Err(ConnectError::WorkerStatus(code));
            }
            httparse::Status::Partial => {}
        }
        if buf.len() > MAX_HEADER {
            return Err(ConnectError::TooLarge);
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(ConnectError::Malformed);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_with_bearer() {
        let raw =
            b"CONNECT asset-1 HTTP/1.1\r\nHost: gw\r\nAuthorization: Bearer abc.def.ghi\r\n\r\n";
        let (req, consumed) = parse_connect(raw).unwrap().unwrap();
        assert_eq!(req.authority, "asset-1");
        assert_eq!(req.token, "abc.def.ghi");
        assert_eq!(consumed, raw.len());
    }

    #[test]
    fn incomplete_returns_none() {
        let raw = b"CONNECT asset-1 HTTP/1.1\r\nAuthorization: Bearer ab"; // no CRLFCRLF yet
        assert!(parse_connect(raw).unwrap().is_none());
    }

    #[test]
    fn rejects_non_connect() {
        let raw = b"GET / HTTP/1.1\r\nAuthorization: Bearer x\r\n\r\n";
        assert!(parse_connect(raw).is_err());
    }

    #[test]
    fn rejects_missing_authorization() {
        let raw = b"CONNECT asset-1 HTTP/1.1\r\nHost: gw\r\n\r\n";
        assert!(parse_connect(raw).is_err());
    }

    #[test]
    fn header_name_case_insensitive() {
        let raw = b"CONNECT a HTTP/1.1\r\nAUTHORIZATION: Bearer tok\r\n\r\n";
        let (req, _) = parse_connect(raw).unwrap().unwrap();
        assert_eq!(req.token, "tok");
    }

    #[test]
    fn writes_200_and_request() {
        assert_eq!(
            response_established(),
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        );
        let out = write_connect_request("asset-9", "tok-9");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("CONNECT asset-9 HTTP/1.1\r\n"));
        assert!(s.contains("Authorization: Bearer tok-9\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }
}
