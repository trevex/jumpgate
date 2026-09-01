/**
 * rdp-graphics.ts — parses the `rdp-graphics-v1` recording container into a
 * header slice + ordered frame list for passive replay.
 *
 * Wire format source of truth: workers/rdp-proxy/src/record_format.rs
 * (`Header::write`/`read`, `write_frame`/`read_frame`). All integers LE.
 *
 * Header (HEADER_LEN=23 bytes): MAGIC "RDPG"(4) + version(1) + width(2) +
 * height(2) + user_channel_id(2) + io_channel_id(2) + message_channel_id
 * flag+u16(3 bytes, ALWAYS written whether present or not) + share_id(4) +
 * compression(1) + enable_server_pointer(1) + pointer_software_rendering(1).
 * `RdpSession.new` (wasm) takes this slice raw, so we only need its byte
 * length, not to decode the individual fields.
 *
 * Frame: [elapsed_millis:u64 LE][action:u8][len:u32 LE][payload].
 */

const MAGIC = "RDPG";
const VERSION = 1;

export const HEADER_LEN = 23;

export interface RdpFrame {
  millis: number;
  action: number;
  payload: Uint8Array;
}

export interface RdpGraphics {
  headerBytes: Uint8Array;
  frames: RdpFrame[];
}

const FRAME_PREFIX_LEN = 8 + 1 + 4; // millis(u64) + action(u8) + len(u32)

export function parseRdpGraphics(bytes: Uint8Array): RdpGraphics {
  if (bytes.length < HEADER_LEN) {
    throw new Error("rdp-graphics-v1: truncated header");
  }
  const magic = new TextDecoder().decode(bytes.subarray(0, 4));
  if (magic !== MAGIC) {
    throw new Error(`rdp-graphics-v1: bad magic ${JSON.stringify(magic)}`);
  }
  if (bytes[4] !== VERSION) {
    throw new Error(`rdp-graphics-v1: unsupported version ${bytes[4]}`);
  }
  const headerBytes = bytes.subarray(0, HEADER_LEN);

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const frames: RdpFrame[] = [];
  let off = HEADER_LEN;
  while (off < bytes.length) {
    if (off + FRAME_PREFIX_LEN > bytes.length) {
      throw new Error("rdp-graphics-v1: truncated frame header");
    }
    const millis = Number(view.getBigUint64(off, true));
    const action = view.getUint8(off + 8);
    const len = view.getUint32(off + 9, true);
    off += FRAME_PREFIX_LEN;
    if (off + len > bytes.length) {
      throw new Error("rdp-graphics-v1: truncated frame payload");
    }
    frames.push({ millis, action, payload: bytes.subarray(off, off + len) });
    off += len;
  }
  return { headerBytes, frames };
}
