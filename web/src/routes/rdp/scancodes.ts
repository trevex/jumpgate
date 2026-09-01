/**
 * scancodes.ts — DOM `KeyboardEvent.code` → PC/XT "Set 1" hardware scancode,
 * as `RdpSession.send_key` expects (see `Scancode::from_u16` in
 * web/wasm/jumpgate-rdp/src/lib.rs: extended keys set the 0xE000 bit, the
 * low byte is the base scancode).
 *
 * ponytail: common-key subset only (letters, digits, common punctuation,
 * whitespace/edit keys, arrows, modifiers, F1-F12). Extend this table if a
 * user needs numpad, media keys, or less-common punctuation.
 */

const EXTENDED = 0xe000;

export const SCANCODES: Record<string, number> = {
  // Row 1: Escape, digits, minus/equal, backspace
  Escape: 0x01,
  Digit1: 0x02,
  Digit2: 0x03,
  Digit3: 0x04,
  Digit4: 0x05,
  Digit5: 0x06,
  Digit6: 0x07,
  Digit7: 0x08,
  Digit8: 0x09,
  Digit9: 0x0a,
  Digit0: 0x0b,
  Minus: 0x0c,
  Equal: 0x0d,
  Backspace: 0x0e,

  // Row 2: Tab + QWERTY + brackets
  Tab: 0x0f,
  KeyQ: 0x10,
  KeyW: 0x11,
  KeyE: 0x12,
  KeyR: 0x13,
  KeyT: 0x14,
  KeyY: 0x15,
  KeyU: 0x16,
  KeyI: 0x17,
  KeyO: 0x18,
  KeyP: 0x19,
  BracketLeft: 0x1a,
  BracketRight: 0x1b,
  Enter: 0x1c,

  // Row 3: Ctrl + ASDF + punctuation
  ControlLeft: 0x1d,
  KeyA: 0x1e,
  KeyS: 0x1f,
  KeyD: 0x20,
  KeyF: 0x21,
  KeyG: 0x22,
  KeyH: 0x23,
  KeyJ: 0x24,
  KeyK: 0x25,
  KeyL: 0x26,
  Semicolon: 0x27,
  Quote: 0x28,
  Backquote: 0x29,

  // Row 4: Shift + ZXCV + punctuation
  ShiftLeft: 0x2a,
  Backslash: 0x2b,
  KeyZ: 0x2c,
  KeyX: 0x2d,
  KeyC: 0x2e,
  KeyV: 0x2f,
  KeyB: 0x30,
  KeyN: 0x31,
  KeyM: 0x32,
  Comma: 0x33,
  Period: 0x34,
  Slash: 0x35,
  ShiftRight: 0x36,

  // Row 5: Alt, space, caps lock
  AltLeft: 0x38,
  Space: 0x39,
  CapsLock: 0x3a,

  // Function keys
  F1: 0x3b,
  F2: 0x3c,
  F3: 0x3d,
  F4: 0x3e,
  F5: 0x3f,
  F6: 0x40,
  F7: 0x41,
  F8: 0x42,
  F9: 0x43,
  F10: 0x44,
  F11: 0x57,
  F12: 0x58,

  // Extended keys (0xE0-prefixed on real hardware)
  ControlRight: EXTENDED | 0x1d,
  AltRight: EXTENDED | 0x38,
  MetaLeft: EXTENDED | 0x5b,
  MetaRight: EXTENDED | 0x5c,
  ContextMenu: EXTENDED | 0x5d,
  ArrowUp: EXTENDED | 0x48,
  ArrowLeft: EXTENDED | 0x4b,
  ArrowRight: EXTENDED | 0x4d,
  ArrowDown: EXTENDED | 0x50,
  Insert: EXTENDED | 0x52,
  Delete: EXTENDED | 0x53,
  Home: EXTENDED | 0x47,
  End: EXTENDED | 0x4f,
  PageUp: EXTENDED | 0x49,
  PageDown: EXTENDED | 0x51,
};
