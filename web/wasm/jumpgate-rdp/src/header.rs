//! `rdp-graphics-v1` seed header — byte-identical copy of the wire contract in
//! `workers/rdp-proxy/src/record_format.rs` (itself identical to the P0 PoC's
//! `Header`). The browser renderer only ever [`Header::read`]s the seed frame
//! the worker sends; `write` is kept so this file is the same single source of
//! the wire format and can round-trip in tests.
//!
//! All integers little-endian; pure std, no IronRDP types.
#![allow(dead_code)] // `write` + frame consts are the wire-contract reference.

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

// ponytail: same round-trip self-check as the worker — proves the header stays
// byte-identical to the wire contract the worker writes.
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

        let mut r = &buf[..];
        let h2 = Header::read(&mut r).unwrap();
        assert_eq!(h2.width, 1280);
        assert_eq!(h2.height, 1024);
        assert_eq!(h2.message_channel_id, Some(1005));
        assert_eq!(h2.share_id, 0x1234_5678);
        assert_eq!(h2.compression, compression::RDP61);
        assert!(h2.pointer_software_rendering);
        assert!(!h2.enable_server_pointer);
    }
}
