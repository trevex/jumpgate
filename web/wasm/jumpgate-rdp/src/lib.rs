//! Browser-side RDP graphics renderer (Rust -> WASM).
//!
//! Credentials never reach the browser: the `rdp-proxy` worker does the full
//! RDP handshake to the target, then streams the browser a seed [`Header`] plus
//! `(action, payload)` PDUs. This crate is exactly the offline replay pipeline
//! the P0 PoC proved (`ActiveStage` seeded from the header with an empty
//! `StaticChannelSet`, no live socket), plus input encoding for live use.
//!
//! It connects to nothing and does no TLS/auth — pure decode + input encode.
//! The JS side (Task 2.7) owns the WebSocket and the `[u8 opcode][payload]`
//! framing; this API works on already-de-framed inner payloads.

mod header;

use header::Header;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp_pdu::rdp::client_info::CompressionType;
use ironrdp_pdu::Action;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_svc::StaticChannelSet;
use wasm_bindgen::prelude::*;

/// A live browser RDP session: decodes graphics PDUs into a framebuffer and
/// encodes DOM input events into FastPath input frames.
#[wasm_bindgen]
pub struct RdpSession {
    active_stage: ActiveStage,
    image: DecodedImage,
    input_db: Database,
    width: u16,
    height: u16,
    terminated: bool,
}

#[wasm_bindgen]
impl RdpSession {
    /// Parse the seed [`Header`] and build a fresh `ActiveStage` + framebuffer,
    /// identical to the PoC's offline replay seeding.
    #[wasm_bindgen(constructor)]
    pub fn new(header_bytes: &[u8]) -> Result<RdpSession, JsValue> {
        let mut r = header_bytes;
        let header = Header::read(&mut r).map_err(err)?;

        let compression_type = match header.compression {
            header::compression::NONE => None,
            header::compression::K8 => Some(CompressionType::K8),
            header::compression::K64 => Some(CompressionType::K64),
            header::compression::RDP6 => Some(CompressionType::Rdp6),
            header::compression::RDP61 => Some(CompressionType::Rdp61),
            other => {
                return Err(JsValue::from_str(&format!(
                    "unknown compression discriminant {other}"
                )))
            }
        };

        let image = DecodedImage::new(PixelFormat::RgbA32, header.width, header.height);

        let active_stage = ActiveStageBuilder {
            static_channels: StaticChannelSet::new(), // fresh/empty — no live connect
            user_channel_id: header.user_channel_id,
            io_channel_id: header.io_channel_id,
            message_channel_id: header.message_channel_id,
            share_id: header.share_id,
            compression_type,
            enable_server_pointer: header.enable_server_pointer,
            pointer_software_rendering: header.pointer_software_rendering,
        }
        .build();

        Ok(RdpSession {
            active_stage,
            image,
            input_db: Database::new(),
            width: header.width,
            height: header.height,
            terminated: false,
        })
    }

    /// Feed one de-framed `(action, payload)` graphics PDU through the stage.
    /// Returns any `ResponseFrame` bytes the browser must send back as INPUT
    /// frames (usually empty). A decode error is returned, never a panic.
    pub fn process(&mut self, action: u8, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
        let action = match action {
            header::ACTION_FASTPATH => Action::FastPath,
            header::ACTION_X224 => Action::X224,
            other => {
                return Err(JsValue::from_str(&format!(
                    "unknown action discriminant {other}"
                )))
            }
        };

        let outputs = self
            .active_stage
            .process(&mut self.image, action, payload)
            .map_err(err)?;
        Ok(self.collect_response(outputs))
    }

    /// `true` once the server sent a graceful disconnect; JS should close.
    pub fn terminated(&self) -> bool {
        self.terminated
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }

    /// Pointer into WASM linear memory to the RGBA8 framebuffer
    /// (`width * height * 4` bytes). Zero-copy: JS reads it directly from
    /// `wasm.memory.buffer` via `new Uint8Array(mem, ptr, len)`. Valid until the
    /// next `process`/input call may reallocate; re-read the pointer each frame.
    pub fn framebuffer_ptr(&self) -> *const u8 {
        self.image.data().as_ptr()
    }

    pub fn framebuffer_len(&self) -> usize {
        self.image.data().len()
    }

    // --- Input encoding. Each builds Operation(s), applies them to the state
    // Database, encodes the resulting FastPath events, and returns the wire
    // bytes JS sends back as INPUT frames. ---

    /// `scancode` is a hardware scancode (extended bit at 0xE000, per
    /// `Scancode::from_u16`). JS passes DOM `KeyboardEvent.code`-derived
    /// scancodes straight through — no keymap here.
    // ponytail: raw scancode passthrough, no DOM->scancode keymap. Add a keymap
    // in JS (KeyboardEvent.code -> PC/AT set 1) rather than here if needed.
    pub fn send_key(&mut self, scancode: u16, down: bool) -> Result<Vec<u8>, JsValue> {
        let sc = Scancode::from_u16(scancode);
        let op = if down {
            Operation::KeyPressed(sc)
        } else {
            Operation::KeyReleased(sc)
        };
        self.apply_input(op)
    }

    pub fn send_mouse_move(&mut self, x: u16, y: u16) -> Result<Vec<u8>, JsValue> {
        self.apply_input(Operation::MouseMove(MousePosition { x, y }))
    }

    /// `button` is a DOM `MouseEvent.button` value (0=left, 1=middle, 2=right,
    /// 3=X1, 4=X2).
    pub fn send_mouse_button(&mut self, button: u8, down: bool) -> Result<Vec<u8>, JsValue> {
        let btn = MouseButton::from_web_button(button)
            .ok_or_else(|| JsValue::from_str(&format!("unknown mouse button {button}")))?;
        let op = if down {
            Operation::MouseButtonPressed(btn)
        } else {
            Operation::MouseButtonReleased(btn)
        };
        self.apply_input(op)
    }

    /// Vertical wheel; positive `delta` scrolls up (rotation units, as RDP
    /// expects). Horizontal wheels are uncommon and omitted.
    pub fn send_wheel(&mut self, delta: i16) -> Result<Vec<u8>, JsValue> {
        self.apply_input(Operation::WheelRotations(WheelRotations {
            is_vertical: true,
            rotation_units: delta,
        }))
    }

    fn apply_input(&mut self, op: Operation) -> Result<Vec<u8>, JsValue> {
        let events = self.input_db.apply([op]);
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let outputs = self
            .active_stage
            .process_fastpath_input(&mut self.image, &events)
            .map_err(err)?;
        Ok(self.collect_response(outputs))
    }

    fn collect_response(&mut self, outputs: Vec<ActiveStageOutput>) -> Vec<u8> {
        let mut frame = Vec::new();
        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(bytes) => frame.extend_from_slice(&bytes),
                ActiveStageOutput::Terminate(_) => self.terminated = true,
                _ => {} // graphics/pointer updates mutate `image` in place; JS blits it
            }
        }
        frame
    }
}

fn err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // Seeding compiles and runs from a synthetic header (no real capture.bin
    // fixture is committed); width/height flow through to the framebuffer.
    #[test]
    fn new_from_synthetic_header() {
        let h = Header {
            width: 1024,
            height: 768,
            user_channel_id: 1004,
            io_channel_id: 1003,
            message_channel_id: Some(1005),
            share_id: 0x1234_5678,
            compression: header::compression::NONE,
            enable_server_pointer: true,
            pointer_software_rendering: false,
        };
        let mut buf = Vec::new();
        h.write(&mut Cursor::new(&mut buf)).unwrap();

        let session = RdpSession::new(&buf).expect("seed from header");
        assert_eq!(session.width(), 1024);
        assert_eq!(session.height(), 768);
        assert_eq!(session.framebuffer_len(), 1024 * 768 * 4);
        assert!(!session.terminated());
    }
    // Note: a bad-header error path can't be unit-tested on the host target —
    // constructing the returned `JsValue` aborts on non-wasm32. `new` returns
    // `Err` (never unwraps) on a decode failure; verified by inspection.
}
