//! The worker↔browser frame protocol carried over the mesh stream.
//!
//! The gateway relays the browser's WebSocket binary messages to this worker as
//! length-delimited `[u32 BE len][payload]` mesh frames (content-agnostic). Each
//! payload is `[u8 opcode][payload]` — so on the wire a frame is exactly
//! `[u32 BE len][opcode][payload]`, where `len` covers the opcode byte plus the
//! payload. This is the SAME framing the browser-terminal ingress uses; only the
//! opcode vocabulary differs.
//!
//! Opcodes (Task 2.7's web client mirrors these):
//! - `0x00 HEADER` (worker→browser, once, first frame): the `rdp-graphics-v1`
//!   [`crate::record_format::Header`] bytes built from the `ConnectionResult`.
//! - `0x01 PDU` (worker→browser): `[action:u8][rdp pdu bytes]`, action `0x00`
//!   FastPath / `0x03` X224 — exactly what `Framed::read_pdu()` yields.
//! - `0x02 INPUT` (browser→worker): raw bytes written straight to the target
//!   socket (the browser's already-wire-formatted ActiveStage input/response).
//! - `0x03 ERROR` (worker→browser): JSON `{"message":...}`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// worker→browser: negotiated session params (the seed [`crate::record_format::Header`]).
pub const OP_HEADER: u8 = 0x00;
/// worker→browser: one RDP PDU, payload `[action:u8][pdu bytes]`.
pub const OP_PDU: u8 = 0x01;
/// browser→worker: raw input bytes, written straight to the target socket.
pub const OP_INPUT: u8 = 0x02;
/// worker→browser: a worker-side error, payload JSON `{"message":...}`.
pub const OP_ERROR: u8 = 0x03;

/// Cap on a single frame's announced length (abuse guard). RDP graphics PDUs are
/// well under this; the browser's input frames are tiny.
pub const MAX_FRAME: u32 = 4 * 1024 * 1024;

/// Read one `[u32 BE len][opcode][payload]` frame from `r`.
///
/// A clean EOF at a frame boundary surfaces as `UnexpectedEof` (the caller treats
/// it as the browser closing). A zero length (no opcode) or one over [`MAX_FRAME`]
/// is `InvalidData`.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let len = r.read_u32().await?;
    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "rdp frame length 0 (no opcode)",
        ));
    }
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("rdp frame length {len} exceeds MAX_FRAME {MAX_FRAME}"),
        ));
    }
    let opcode = r.read_u8().await?;
    let payload_len = (len - 1) as usize;
    let mut payload = vec![0u8; payload_len];
    r.read_exact(&mut payload).await?;
    Ok((opcode, payload))
}

/// Write one `[u32 BE len][opcode][payload]` frame to `w` (not flushed).
///
/// `len` is `payload.len() + 1` (opcode). Errors if the payload is too large to
/// frame within [`MAX_FRAME`].
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = payload
        .len()
        .checked_add(1)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n <= MAX_FRAME)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "rdp frame payload too large to encode",
            )
        })?;
    w.write_u32(len).await?;
    w.write_u8(opcode).await?;
    w.write_all(payload).await?;
    Ok(())
}

/// Encode an `OP_ERROR` payload `{"message":"…"}` (message JSON-escaped).
pub fn error_payload(message: &str) -> Vec<u8> {
    let escaped = serde_json::to_string(message).unwrap_or_else(|_| "\"rdp error\"".to_string());
    format!("{{\"message\":{escaped}}}").into_bytes()
}

/// Best-effort `OP_ERROR` frame before closing (setup/connect failures). Ignores
/// write errors — the peer may already be gone.
pub async fn send_error<W: AsyncWrite + Unpin>(w: &mut W, message: &str) {
    let _ = write_frame(w, OP_ERROR, &error_payload(message)).await;
    let _ = w.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A round-trip through the framed codec: what `write_frame` emits, a
    /// `read_frame` on the same bytes recovers exactly.
    #[tokio::test]
    async fn frame_roundtrips() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, OP_HEADER, b"RDPG\x01").await.unwrap();
        write_frame(&mut buf, OP_PDU, &[0x00, 0xde, 0xad]).await.unwrap();
        write_frame(&mut buf, OP_INPUT, b"").await.unwrap(); // empty payload is legal

        let mut cur = std::io::Cursor::new(buf);
        let (op, data) = read_frame(&mut cur).await.unwrap();
        assert_eq!(op, OP_HEADER);
        assert_eq!(data, b"RDPG\x01");
        let (op, data) = read_frame(&mut cur).await.unwrap();
        assert_eq!(op, OP_PDU);
        assert_eq!(data, vec![0x00, 0xde, 0xad]);
        let (op, data) = read_frame(&mut cur).await.unwrap();
        assert_eq!(op, OP_INPUT);
        assert!(data.is_empty());
    }

    /// The exact wire layout: `[u32 BE len][opcode][payload]`, len covering the
    /// opcode byte. Locks the byte-for-byte contract the gateway relays.
    #[tokio::test]
    async fn frame_wire_layout() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, OP_PDU, b"ok").await.unwrap();
        // len = 1 (opcode) + 2 (payload) = 3.
        assert_eq!(&buf, &[0, 0, 0, 3, OP_PDU, b'o', b'k']);
    }

    /// A payload split across two reads (the mesh stream may deliver a frame in
    /// pieces) must still be reassembled — `read_exact` handles the boundary.
    #[tokio::test]
    async fn frame_reassembles_across_reads() {
        let full = {
            let mut b = Vec::new();
            write_frame(&mut b, OP_INPUT, b"hello").await.unwrap();
            b
        };
        let (mut client, mut server) = tokio::io::duplex(64);
        let split = full.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&split[..3]).await.unwrap();
            client.flush().await.unwrap();
            tokio::task::yield_now().await;
            client.write_all(&split[3..]).await.unwrap();
            client.flush().await.unwrap();
        });
        let (op, data) = read_frame(&mut server).await.unwrap();
        assert_eq!(op, OP_INPUT);
        assert_eq!(data, b"hello");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn zero_length_frame_is_invalid() {
        let buf = vec![0u8, 0, 0, 0]; // len = 0
        let mut cur = std::io::Cursor::new(buf);
        let err = read_frame(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn oversized_length_is_invalid() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        let mut cur = std::io::Cursor::new(buf);
        let err = read_frame(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn eof_at_boundary_is_unexpected_eof() {
        let mut cur = std::io::Cursor::new(Vec::<u8>::new());
        let err = read_frame(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn error_payload_is_json() {
        let e = error_payload(r#"boom "quoted""#);
        let v: serde_json::Value = serde_json::from_slice(&e).unwrap();
        assert_eq!(v["message"], r#"boom "quoted""#);
    }
}
