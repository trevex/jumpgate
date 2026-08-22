/**
 * terminal-protocol.ts — browser-side wire codec for the in-browser terminal.
 *
 * Every WebSocket message is ONE binary frame: `[u8 opcode][payload]`. The
 * socket runs with `binaryType="arraybuffer"`, so message boundaries delimit
 * frames (no length prefix on the browser↔gateway hop — the gateway adds/strips
 * the length prefix on the mesh side).
 *
 * client → server            server → client
 *   0x00 DATA   raw bytes      0x00 DATA   raw bytes
 *   0x01 RESIZE JSON{cols,rows} 0x01 EXIT  JSON{code}
 *                              0x02 ERROR JSON{message}
 *
 * These helpers are pure (no DOM, no WebSocket) so they can be unit-tested.
 */

export const OP_DATA = 0x00;
export const OP_RESIZE = 0x01;
export const OP_EXIT = 0x01; // server→client: 0x01 is EXIT
export const OP_ERROR = 0x02;

const encoder = new TextEncoder();

/** Wraps raw keystroke bytes in a DATA frame: `[0x00, ...bytes]`. */
export function encodeData(bytes: Uint8Array): Uint8Array {
  const frame = new Uint8Array(bytes.length + 1);
  frame[0] = OP_DATA;
  frame.set(bytes, 1);
  return frame;
}

/** Encodes a RESIZE frame: `[0x01, ...utf8(JSON.stringify({cols,rows}))]`. */
export function encodeResize(cols: number, rows: number): Uint8Array {
  const json = encoder.encode(JSON.stringify({ cols, rows }));
  const frame = new Uint8Array(json.length + 1);
  frame[0] = OP_RESIZE;
  frame.set(json, 1);
  return frame;
}

export interface Frame {
  op: number;
  payload: Uint8Array;
}

/** Splits a received frame into its opcode byte and the remaining payload. */
export function decodeFrame(buf: Uint8Array): Frame {
  if (buf.length === 0) {
    return { op: OP_DATA, payload: new Uint8Array(0) };
  }
  return { op: buf[0], payload: buf.subarray(1) };
}
