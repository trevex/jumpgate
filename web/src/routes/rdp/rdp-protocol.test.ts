import { describe, expect, it } from "vitest";
import {
  decodeFrame,
  encodeInput,
  OP_HEADER,
  OP_PDU,
  OP_INPUT,
  OP_ERROR,
} from "./rdp-protocol";

describe("decodeFrame", () => {
  it("decodes a server HEADER frame", () => {
    const body = new Uint8Array([1, 2, 3, 4]);
    const buf = new Uint8Array(body.length + 1);
    buf[0] = OP_HEADER;
    buf.set(body, 1);
    const { op, payload } = decodeFrame(buf);
    expect(op).toBe(OP_HEADER);
    expect(payload).toEqual(body);
  });

  it("decodes a server PDU frame with the inner [action][bytes] framing intact", () => {
    const inner = new Uint8Array([0x00, 0xaa, 0xbb, 0xcc]); // action=0x00, pdu bytes
    const buf = new Uint8Array(inner.length + 1);
    buf[0] = OP_PDU;
    buf.set(inner, 1);
    const { op, payload } = decodeFrame(buf);
    expect(op).toBe(OP_PDU);
    expect(payload[0]).toBe(0x00); // action
    expect(payload.subarray(1)).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc])); // pdu
  });

  it("decodes a server ERROR frame", () => {
    const body = new TextEncoder().encode(JSON.stringify({ message: "boom" }));
    const buf = new Uint8Array(body.length + 1);
    buf[0] = OP_ERROR;
    buf.set(body, 1);
    const { op, payload } = decodeFrame(buf);
    expect(op).toBe(OP_ERROR);
    expect(JSON.parse(new TextDecoder().decode(payload))).toEqual({
      message: "boom",
    });
  });

  it("treats an empty buffer as an empty HEADER frame", () => {
    const { op, payload } = decodeFrame(new Uint8Array(0));
    expect(op).toBe(OP_HEADER);
    expect(payload.length).toBe(0);
  });
});

describe("encodeInput", () => {
  it("prefixes payload with the INPUT opcode", () => {
    const bytes = new Uint8Array([1, 2, 3, 255, 0, 42]);
    const frame = encodeInput(bytes);
    expect(frame[0]).toBe(OP_INPUT);
    expect(frame.subarray(1)).toEqual(bytes);
  });

  it("round-trips through decodeFrame", () => {
    const bytes = new Uint8Array([9, 8, 7]);
    const { op, payload } = decodeFrame(encodeInput(bytes));
    expect(op).toBe(OP_INPUT);
    expect(payload).toEqual(bytes);
  });

  it("handles empty payloads", () => {
    const frame = encodeInput(new Uint8Array(0));
    expect(frame.length).toBe(1);
    expect(frame[0]).toBe(OP_INPUT);
    const { op, payload } = decodeFrame(frame);
    expect(op).toBe(OP_INPUT);
    expect(payload.length).toBe(0);
  });
});
