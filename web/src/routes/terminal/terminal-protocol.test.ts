import { describe, expect, it } from "vitest";
import {
  encodeData,
  encodeResize,
  decodeFrame,
  OP_DATA,
  OP_RESIZE,
  OP_EXIT,
  OP_ERROR,
} from "./terminal-protocol";

describe("encodeData", () => {
  it("prefixes payload with the DATA opcode", () => {
    const bytes = new TextEncoder().encode("ls -la\n");
    const frame = encodeData(bytes);
    expect(frame[0]).toBe(OP_DATA);
    expect(frame.subarray(1)).toEqual(bytes);
  });

  it("round-trips through decodeFrame", () => {
    const bytes = new Uint8Array([1, 2, 3, 255, 0, 42]);
    const { op, payload } = decodeFrame(encodeData(bytes));
    expect(op).toBe(OP_DATA);
    expect(payload).toEqual(bytes);
  });

  it("handles empty payloads", () => {
    const frame = encodeData(new Uint8Array(0));
    expect(frame.length).toBe(1);
    expect(frame[0]).toBe(OP_DATA);
    const { op, payload } = decodeFrame(frame);
    expect(op).toBe(OP_DATA);
    expect(payload.length).toBe(0);
  });
});

describe("encodeResize", () => {
  it("prefixes JSON dimensions with the RESIZE opcode", () => {
    const frame = encodeResize(120, 40);
    expect(frame[0]).toBe(OP_RESIZE);
    const json = JSON.parse(new TextDecoder().decode(frame.subarray(1)));
    expect(json).toEqual({ cols: 120, rows: 40 });
  });

  it("round-trips dimensions through decodeFrame + JSON parse", () => {
    const { op, payload } = decodeFrame(encodeResize(80, 24));
    expect(op).toBe(OP_RESIZE);
    expect(JSON.parse(new TextDecoder().decode(payload))).toEqual({
      cols: 80,
      rows: 24,
    });
  });
});

describe("decodeFrame", () => {
  it("decodes a server EXIT frame", () => {
    const body = new TextEncoder().encode(JSON.stringify({ code: 0 }));
    const buf = new Uint8Array(body.length + 1);
    buf[0] = OP_EXIT;
    buf.set(body, 1);
    const { op, payload } = decodeFrame(buf);
    expect(op).toBe(OP_EXIT);
    expect(JSON.parse(new TextDecoder().decode(payload))).toEqual({ code: 0 });
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

  it("treats an empty buffer as an empty DATA frame", () => {
    const { op, payload } = decodeFrame(new Uint8Array(0));
    expect(op).toBe(OP_DATA);
    expect(payload.length).toBe(0);
  });
});
