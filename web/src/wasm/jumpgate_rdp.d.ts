/* tslint:disable */
/* eslint-disable */

/**
 * A live browser RDP session: decodes graphics PDUs into a framebuffer and
 * encodes DOM input events into FastPath input frames.
 */
export class RdpSession {
    free(): void;
    [Symbol.dispose](): void;
    framebuffer_len(): number;
    /**
     * Pointer into WASM linear memory to the RGBA8 framebuffer
     * (`width * height * 4` bytes). Zero-copy: JS reads it directly from
     * `wasm.memory.buffer` via `new Uint8Array(mem, ptr, len)`. Valid until the
     * next `process`/input call may reallocate; re-read the pointer each frame.
     */
    framebuffer_ptr(): number;
    height(): number;
    /**
     * Parse the seed [`Header`] and build a fresh `ActiveStage` + framebuffer,
     * identical to the PoC's offline replay seeding.
     */
    constructor(header_bytes: Uint8Array);
    /**
     * Feed one de-framed `(action, payload)` graphics PDU through the stage.
     * Returns any `ResponseFrame` bytes the browser must send back as INPUT
     * frames (usually empty). A decode error is returned, never a panic.
     */
    process(action: number, payload: Uint8Array): Uint8Array;
    /**
     * `scancode` is a hardware scancode (extended bit at 0xE000, per
     * `Scancode::from_u16`). JS passes DOM `KeyboardEvent.code`-derived
     * scancodes straight through — no keymap here.
     */
    send_key(scancode: number, down: boolean): Uint8Array;
    /**
     * `button` is a DOM `MouseEvent.button` value (0=left, 1=middle, 2=right,
     * 3=X1, 4=X2).
     */
    send_mouse_button(button: number, down: boolean): Uint8Array;
    send_mouse_move(x: number, y: number): Uint8Array;
    /**
     * Vertical wheel; positive `delta` scrolls up (rotation units, as RDP
     * expects). Horizontal wheels are uncommon and omitted.
     */
    send_wheel(delta: number): Uint8Array;
    /**
     * `true` once the server sent a graceful disconnect; JS should close.
     */
    terminated(): boolean;
    width(): number;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_rdpsession_free: (a: number, b: number) => void;
    readonly rdpsession_framebuffer_len: (a: number) => number;
    readonly rdpsession_framebuffer_ptr: (a: number) => number;
    readonly rdpsession_height: (a: number) => number;
    readonly rdpsession_new: (a: number, b: number) => [number, number, number];
    readonly rdpsession_process: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly rdpsession_send_key: (a: number, b: number, c: number) => [number, number, number, number];
    readonly rdpsession_send_mouse_button: (a: number, b: number, c: number) => [number, number, number, number];
    readonly rdpsession_send_mouse_move: (a: number, b: number, c: number) => [number, number, number, number];
    readonly rdpsession_send_wheel: (a: number, b: number) => [number, number, number, number];
    readonly rdpsession_terminated: (a: number) => number;
    readonly rdpsession_width: (a: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
