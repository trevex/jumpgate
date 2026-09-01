//! `rdp-graphics-v1` seed-header + frame wire format.
//!
//! A recording is: a fixed header capturing the negotiated session params
//! needed to re-seed a fresh `ActiveStage`, followed by a stream of framed
//! `(elapsed_millis, action, payload)` records — exactly the `(action,
//! payload)` pairs that `Framed::read_pdu()` yields and `ActiveStage::process`
//! consumes. Replay feeds these back through a fresh `ActiveStage` with an
//! empty `StaticChannelSet`, no live socket.
//!
//! In Phase 2 the worker uses only [`Header`] (built from `ConnectionResult`
//! and sent to the browser as the seed frame). The frame writer/reader are
//! shared with the Phase-3 recorder; kept here as the single source of the
//! wire format. All integers little-endian; pure std, no IronRDP types.

use std::io::{self, Read, Write};

pub const MAGIC: &[u8; 4] = b"RDPG";
pub const VERSION: u8 = 1;

pub const ACTION_FASTPATH: u8 = 0x00; // ironrdp_pdu::Action::FastPath
pub const ACTION_X224: u8 = 0x03; // ironrdp_pdu::Action::X224

#[derive(Debug, Clone)]
pub struct Header {
    pub width: u16,
    pub height: u16,
    pub user_channel_id: u16,
    pub io_channel_id: u16,
    pub message_channel_id: Option<u16>,
    pub share_id: u32,
    /// 0 = none, else CompressionType discriminant (see compression module).
    pub compression: u8,
    pub enable_server_pointer: bool,
    pub pointer_software_rendering: bool,
}

/// CompressionType <-> u8. 0 reserved for "none" (Option::None).
pub mod compression {
    pub const NONE: u8 = 0;
    pub const K8: u8 = 1;
    pub const K64: u8 = 2;
    pub const RDP6: u8 = 3;
    pub const RDP61: u8 = 4;
}

impl Header {
    pub fn write(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(MAGIC)?;
        w.write_all(&[VERSION])?;
        w.write_all(&self.width.to_le_bytes())?;
        w.write_all(&self.height.to_le_bytes())?;
        w.write_all(&self.user_channel_id.to_le_bytes())?;
        w.write_all(&self.io_channel_id.to_le_bytes())?;
        match self.message_channel_id {
            Some(id) => {
                w.write_all(&[1])?;
                w.write_all(&id.to_le_bytes())?;
            }
            None => w.write_all(&[0, 0, 0])?,
        }
        w.write_all(&self.share_id.to_le_bytes())?;
        w.write_all(&[
            self.compression,
            self.enable_server_pointer as u8,
            self.pointer_software_rendering as u8,
        ])?;
        Ok(())
    }

    pub fn read(r: &mut impl Read) -> io::Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
        }
        let mut ver = [0u8; 1];
        r.read_exact(&mut ver)?;
        if ver[0] != VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad version"));
        }
        let width = read_u16(r)?;
        let height = read_u16(r)?;
        let user_channel_id = read_u16(r)?;
        let io_channel_id = read_u16(r)?;
        let mut mc = [0u8; 3];
        r.read_exact(&mut mc)?;
        let message_channel_id = if mc[0] == 1 {
            Some(u16::from_le_bytes([mc[1], mc[2]]))
        } else {
            None
        };
        let share_id = read_u32(r)?;
        let mut tail = [0u8; 3];
        r.read_exact(&mut tail)?;
        Ok(Header {
            width,
            height,
            user_channel_id,
            io_channel_id,
            message_channel_id,
            share_id,
            compression: tail[0],
            enable_server_pointer: tail[1] != 0,
            pointer_software_rendering: tail[2] != 0,
        })
    }
}

/// One recorded PDU. `action` is the u8 discriminant (ACTION_*).
pub struct Frame {
    pub millis: u64,
    pub action: u8,
    pub payload: Vec<u8>,
}

pub fn write_frame(w: &mut impl Write, millis: u64, action: u8, payload: &[u8]) -> io::Result<()> {
    w.write_all(&millis.to_le_bytes())?;
    w.write_all(&[action])?;
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)?;
    Ok(())
}

/// Reads the next frame, or None at clean EOF.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Frame>> {
    let mut millis = [0u8; 8];
    match r.read_exact(&mut millis) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut act = [0u8; 1];
    r.read_exact(&mut act)?;
    let len = read_u32(r)? as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some(Frame {
        millis: u64::from_le_bytes(millis),
        action: act[0],
        payload,
    }))
}

fn read_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

// ponytail: minimal self-check — round-trips a header + two frames.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let h = Header {
            width: 1280,
            height: 1024,
            user_channel_id: 1004,
            io_channel_id: 1003,
            message_channel_id: Some(1005),
            share_id: 0x1234_5678,
            compression: compression::RDP61,
            enable_server_pointer: false,
            pointer_software_rendering: true,
        };
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        write_frame(&mut buf, 10, ACTION_FASTPATH, &[1, 2, 3]).unwrap();
        write_frame(&mut buf, 25, ACTION_X224, &[9, 9]).unwrap();

        let mut r = &buf[..];
        let h2 = Header::read(&mut r).unwrap();
        assert_eq!(h2.width, 1280);
        assert_eq!(h2.message_channel_id, Some(1005));
        assert_eq!(h2.share_id, 0x1234_5678);
        assert_eq!(h2.compression, compression::RDP61);
        assert!(h2.pointer_software_rendering);

        let f1 = read_frame(&mut r).unwrap().unwrap();
        assert_eq!(
            (f1.millis, f1.action, f1.payload),
            (10, ACTION_FASTPATH, vec![1, 2, 3])
        );
        let f2 = read_frame(&mut r).unwrap().unwrap();
        assert_eq!(
            (f2.millis, f2.action, f2.payload),
            (25, ACTION_X224, vec![9, 9])
        );
        assert!(read_frame(&mut r).unwrap().is_none());
    }
}
