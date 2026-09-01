import { describe, expect, it } from "vitest";
import { parseRdpGraphics, HEADER_LEN } from "./rdp-graphics";

// Hand-writes a valid rdp-graphics-v1 header per record_format.rs Header::write:
// MAGIC(4) + version(1) + width(2) + height(2) + user_channel_id(2) +
// io_channel_id(2) + message_channel_id flag+u16(3) + share_id(4) +
// compression(1) + enable_server_pointer(1) + pointer_software_rendering(1).
function buildHeader(): number[] {
  return [
    ...[0x52, 0x44, 0x50, 0x47], // "RDPG"
    1, // version
    0x00, 0x05, // width = 1280 LE
    0x00, 0x04, // height = 1024 LE
    0xec, 0x03, // user_channel_id = 1004 LE
    0xeb, 0x03, // io_channel_id = 1003 LE
    1, 0xed, 0x03, // message_channel_id = Some(1005)
    0x78, 0x56, 0x34, 0x12, // share_id = 0x12345678 LE
    4, // compression = RDP61
    0, // enable_server_pointer = false
    1, // pointer_software_rendering = true
  ];
}

function buildFrame(millis: number, action: number, payload: number[]): number[] {
  const millisBytes = new Uint8Array(8);
  new DataView(millisBytes.buffer).setBigUint64(0, BigInt(millis), true);
  const lenBytes = new Uint8Array(4);
  new DataView(lenBytes.buffer).setUint32(0, payload.length, true);
  return [...millisBytes, action, ...lenBytes, ...payload];
}

describe("parseRdpGraphics", () => {
  it("parses a header and its frames", () => {
    const header = buildHeader();
    expect(header.length).toBe(HEADER_LEN);
    const bytes = new Uint8Array([
      ...header,
      ...buildFrame(10, 0x00, [1, 2, 3]),
      ...buildFrame(25, 0x03, [9, 9]),
    ]);

    const { headerBytes, frames } = parseRdpGraphics(bytes);
    expect(headerBytes).toEqual(new Uint8Array(header));
    expect(frames).toHaveLength(2);
    expect(frames[0]).toEqual({ millis: 10, action: 0x00, payload: new Uint8Array([1, 2, 3]) });
    expect(frames[1]).toEqual({ millis: 25, action: 0x03, payload: new Uint8Array([9, 9]) });
  });

  it("parses a header with no frames", () => {
    const header = buildHeader();
    const { headerBytes, frames } = parseRdpGraphics(new Uint8Array(header));
    expect(headerBytes).toEqual(new Uint8Array(header));
    expect(frames).toEqual([]);
  });

  it("throws on bad magic", () => {
    const bad = new Uint8Array(buildHeader());
    bad.set([0, 0, 0, 0], 0);
    expect(() => parseRdpGraphics(bad)).toThrow(/bad magic/);
  });

  it("throws on a truncated header", () => {
    expect(() => parseRdpGraphics(new Uint8Array(HEADER_LEN - 1))).toThrow(/truncated header/);
  });

  it("throws on a truncated frame payload", () => {
    const bytes = new Uint8Array([...buildHeader(), ...buildFrame(1, 0, [1, 2, 3])].slice(0, -1));
    expect(() => parseRdpGraphics(bytes)).toThrow(/truncated frame payload/);
  });
});
