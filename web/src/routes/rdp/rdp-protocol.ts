/**
 * rdp-protocol.ts — browser-side wire codec for the in-browser RDP client.
 *
 * Every WebSocket message is ONE binary frame: `[u8 opcode][payload]`. The
 * socket runs with `binaryType="arraybuffer"`, so message boundaries delimit
 * frames (no length prefix on the browser↔gateway hop).
 *
 * server → client              client → server
 *   0x00 HEADER  seed bytes       0x02 INPUT  wasm-encoded input bytes
 *   0x01 PDU     [u8 action][pdu bytes]
 *   0x03 ERROR   JSON{message}
 *
 * The PDU payload is itself `[u8 action][pdu bytes]` — callers split that
 * inner framing themselves before handing bytes to `RdpSession.process`.
 *
 * These helpers are pure (no DOM, no WebSocket) so they can be unit-tested.
 */

export const OP_HEADER = 0x00;
export const OP_PDU = 0x01;
export const OP_INPUT = 0x02;
export const OP_ERROR = 0x03;

export interface Frame {
  op: number;
  payload: Uint8Array;
}

/** Splits a received frame into its opcode byte and the remaining payload. */
export function decodeFrame(bytes: Uint8Array): Frame {
  if (bytes.length === 0) {
    return { op: OP_HEADER, payload: new Uint8Array(0) };
  }
  return { op: bytes[0], payload: bytes.subarray(1) };
}

/** Wraps input bytes (from `RdpSession.send_*`/`process`) in an INPUT frame. */
export function encodeInput(payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(payload.length + 1);
  frame[0] = OP_INPUT;
  frame.set(payload, 1);
  return frame;
}
