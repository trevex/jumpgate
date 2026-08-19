//! asciicast v2 encoding: a JSON header line followed by newline-delimited
//! [time, code, data] event lines (asciinema asciicast v2 format).

use serde::Serialize;

/// asciicast v2 stream header.
#[derive(Serialize, Debug, Clone)]
pub struct Header {
    pub version: u8, // always 2
    pub width: u16,
    pub height: u16,
    pub timestamp: i64, // unix seconds at session start
}

impl Header {
    /// Build a v2 header.
    pub fn new(width: u16, height: u16, timestamp: i64) -> Self {
        Self {
            version: 2,
            width,
            height,
            timestamp,
        }
    }

    /// Serialize the header line, including the trailing '\n'.
    pub fn to_line(&self) -> Vec<u8> {
        let mut s = serde_json::to_vec(self).expect("asciicast header serializes");
        s.push(b'\n');
        s
    }
}

/// The kind of an asciicast event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Output,
    Input,
    Resize,
}

impl EventKind {
    fn code(self) -> &'static str {
        match self {
            EventKind::Output => "o",
            EventKind::Input => "i",
            EventKind::Resize => "r",
        }
    }
}

/// Serialize one event line, including the trailing '\n'. `t` is seconds since
/// session start; `data` is the raw payload (for resize, the "<cols>x<rows>"
/// string). Non-UTF8 bytes are lossily encoded since asciicast data is a JSON
/// string.
pub fn event_line(t: f64, kind: EventKind, data: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(data);
    let mut s =
        serde_json::to_vec(&(t, kind.code(), text.as_ref())).expect("asciicast event serializes");
    s.push(b'\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_line_serializes() {
        let line = Header::new(80, 24, 1_700_000_000).to_line();
        let text = String::from_utf8(line).expect("utf8");
        assert!(
            text.starts_with(r#"{"version":2,"width":80,"height":24,"timestamp":1700000000}"#),
            "unexpected header: {text}"
        );
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn output_event() {
        assert_eq!(
            event_line(1.5, EventKind::Output, b"hi"),
            b"[1.5,\"o\",\"hi\"]\n"
        );
    }

    #[test]
    fn input_event() {
        // serde_json escapes the carriage return as \r inside the JSON string.
        assert_eq!(
            event_line(1.2, EventKind::Input, b"root\r"),
            b"[1.2,\"i\",\"root\\r\"]\n"
        );
    }

    #[test]
    fn resize_event() {
        // serde_json renders the f64 3.0 as "3.0" (keeps the decimal point).
        assert_eq!(
            event_line(3.0, EventKind::Resize, b"120x40"),
            b"[3.0,\"r\",\"120x40\"]\n"
        );
    }

    #[test]
    fn escapes_newline() {
        let line = event_line(0.0, EventKind::Output, b"a\nb");
        let text = String::from_utf8(line).expect("utf8");
        // The newline inside the payload must be escaped (\n), not a literal
        // newline that would break the newline-delimited event framing.
        assert!(text.contains("a\\nb"), "not escaped: {text}");
        assert!(
            !text[..text.len() - 1].contains('\n'),
            "raw newline: {text}"
        );
    }
}
