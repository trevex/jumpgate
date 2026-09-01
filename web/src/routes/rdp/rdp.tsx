/**
 * rdp.tsx — full-screen in-browser RDP client.
 *
 * A chromeless, own-layout page (rendered OUTSIDE the AppShell): a slim top
 * bar (asset label + connection-status pill + close button) with a `<canvas>`
 * filling the rest of the viewport, painted by the `jumpgate-rdp` WASM
 * renderer (see web/wasm/jumpgate-rdp).
 *
 * Flow on mount:
 *   1. CreateRDPSession({assetId, login}) → {ticket, gatewayEndpoint, insecure}.
 *   2. Open  wss://<gatewayEndpoint>/rdp?ticket=<ticket>  (arraybuffer).
 *   3. First message is a HEADER frame — seeds a fresh `RdpSession`, which
 *      sizes the canvas to the remote desktop.
 *   4. Each PDU frame is fed to `RdpSession.process`, which mutates the wasm
 *      framebuffer in place; we blit it to the canvas and forward any
 *      returned response bytes back over the socket as an INPUT frame.
 *   5. DOM input listeners on the canvas (keyboard/mouse/wheel) encode local
 *      input via the same `RdpSession.send_*` calls and forward the result.
 *
 * Connection is explicit: on close/exit/error we surface a status and a
 * Reconnect button — there is NO automatic reconnect (a fresh ticket must be
 * minted).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useParams, useSearchParams, useNavigate } from "react-router-dom";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { X, RotateCw, Loader2, Monitor } from "lucide-react";
import init, { RdpSession } from "@/wasm/jumpgate_rdp.js";
import wasmUrl from "@/wasm/jumpgate_rdp_bg.wasm?url";
import { createRDPSession } from "@/gen/jumpgate/session/v1/session-SessionService_connectquery";
import { getAssetDisplay } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { connectErrorMessage } from "@/lib/format";
import { decodeFrame, encodeInput, OP_HEADER, OP_PDU } from "./rdp-protocol";
import { SCANCODES } from "./scancodes";

// ─── Connection status ────────────────────────────────────────────────────────

type Status =
  | { kind: "connecting" }
  | { kind: "connected" }
  | { kind: "exited" }
  | { kind: "closed" }
  | { kind: "error"; message: string };

const STATUS_META: Record<
  Status["kind"],
  { label: string; dot: string; text: string }
> = {
  connecting: {
    label: "Connecting",
    dot: "bg-warning-fg animate-pulse",
    text: "text-warning-fg",
  },
  connected: {
    label: "Connected",
    dot: "bg-success-fg",
    text: "text-success-fg",
  },
  exited: {
    label: "Session ended",
    dot: "bg-neutral-fg",
    text: "text-neutral-fg",
  },
  closed: {
    label: "Disconnected",
    dot: "bg-neutral-fg",
    text: "text-neutral-fg",
  },
  error: {
    label: "Error",
    dot: "bg-danger-fg",
    text: "text-danger-fg",
  },
};

function StatusPill({ status }: { status: Status }) {
  const meta = STATUS_META[status.kind];
  const detail = status.kind === "error" ? `: ${status.message}` : "";
  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={`Connection status: ${meta.label}${detail}`}
      className={cn(
        "flex items-center gap-1.5 rounded-full border border-border bg-muted px-2.5 py-1 text-micro font-medium",
        meta.text,
      )}
    >
      <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", meta.dot)} aria-hidden="true" />
      <span className="truncate max-w-[280px]">
        {meta.label}
        {detail}
      </span>
    </div>
  );
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ─── RDP page ─────────────────────────────────────────────────────────────────

export function RdpPage() {
  const { assetId = "" } = useParams<{ assetId: string }>();
  const [searchParams] = useSearchParams();
  const login = searchParams.get("login") ?? "";
  const navigate = useNavigate();

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const sessionRef = useRef<RdpSession | null>(null);
  const memoryRef = useRef<WebAssembly.Memory | null>(null);

  const [status, setStatus] = useState<Status>({ kind: "connecting" });
  // Bumping this re-runs the connect effect (explicit reconnect only).
  const [attempt, setAttempt] = useState(0);

  const { mutateAsync: createSession } = useMutation(createRDPSession);

  // Resolve the asset's DNS-style path for the header so we don't show the raw
  // route-param UUID. Falls back to name, then the short id.
  const { data: assetDisplayData } = useQuery(
    getAssetDisplay,
    { assetId },
    { enabled: Boolean(assetId) },
  );
  const assetLabel =
    assetDisplayData?.asset?.path ||
    assetDisplayData?.asset?.name ||
    (assetId.split("-")[0] ?? assetId);

  const close = useCallback(() => {
    if (window.history.length > 1) navigate(-1);
    else navigate("/");
  }, [navigate]);

  const reconnect = useCallback(() => {
    setStatus({ kind: "connecting" });
    setAttempt((n) => n + 1);
  }, []);

  // ─── Connect: mint ticket → open WS → bridge ────────────────────────────────
  useEffect(() => {
    let disposed = false;
    let ws: WebSocket | null = null;
    let cleanupInput: (() => void) | null = null;

    async function connect() {
      const canvas = canvasRef.current;
      if (!canvas) return;

      const wasm = await init(wasmUrl);
      if (disposed) return;
      memoryRef.current = wasm.memory;

      let ticket: string;
      let gatewayEndpoint: string;
      let insecure: boolean;
      try {
        const resp = await createSession({
          assetId,
          login,
          insecure: window.location.protocol === "http:",
        });
        ticket = resp.ticket;
        gatewayEndpoint = resp.gatewayEndpoint;
        insecure = resp.insecure;
      } catch (err) {
        if (!disposed) setStatus({ kind: "error", message: connectErrorMessage(err) });
        return;
      }
      if (disposed) return;

      const scheme = insecure ? "ws" : "wss";
      ws = new WebSocket(
        `${scheme}://${gatewayEndpoint}/rdp?ticket=${encodeURIComponent(ticket)}`,
      );
      ws.binaryType = "arraybuffer";
      wsRef.current = ws;

      // ponytail: e2e-only observability hook. The browser paints RDP to a
      // canvas whose framebuffer can't be scraped renderer-agnostically like the
      // xterm buffer, so expose a tiny liveness struct (connected on first HEADER,
      // a frame counter per processed PDU) for web/e2e/rdp.spec.ts to assert on.
      const rdpHook = { connected: false, framesProcessed: 0 };
      (window as unknown as { __jumpgateRdp?: typeof rdpHook }).__jumpgateRdp = rdpHook;

      // Blits the wasm framebuffer to the canvas. Re-reads the memory view
      // fresh each call — wasm memory can grow/detach between frames.
      function blit(session: RdpSession) {
        const canvasEl = canvasRef.current;
        const mem = memoryRef.current;
        if (!canvasEl || !mem) return;
        const w = session.width();
        const h = session.height();
        if (canvasEl.width !== w) canvasEl.width = w;
        if (canvasEl.height !== h) canvasEl.height = h;
        const ctx = canvasEl.getContext("2d");
        if (!ctx) return;
        const pixels = new Uint8ClampedArray(
          mem.buffer,
          session.framebuffer_ptr(),
          session.framebuffer_len(),
        );
        ctx.putImageData(new ImageData(pixels, w, h), 0, 0);
      }

      function sendInput(bytes: Uint8Array) {
        if (bytes.length > 0 && ws?.readyState === WebSocket.OPEN) {
          ws.send(encodeInput(bytes));
        }
      }

      ws.onmessage = (ev: MessageEvent) => {
        const { op, payload } = decodeFrame(new Uint8Array(ev.data as ArrayBuffer));
        if (op === OP_HEADER) {
          try {
            const session = new RdpSession(payload);
            sessionRef.current = session;
            blit(session);
            rdpHook.connected = true;
            setStatus({ kind: "connected" });
            canvasRef.current?.focus();
          } catch (err) {
            setStatus({ kind: "error", message: errMessage(err) });
            ws?.close();
          }
          return;
        }
        if (op === OP_PDU) {
          const session = sessionRef.current;
          if (!session) return; // PDU before HEADER — ignore defensively
          try {
            const out = session.process(payload[0], payload.subarray(1));
            blit(session);
            rdpHook.framesProcessed++;
            sendInput(out);
            if (session.terminated()) {
              setStatus({ kind: "exited" });
              ws?.close();
            }
          } catch (err) {
            setStatus({ kind: "error", message: errMessage(err) });
            ws?.close();
          }
          return;
        }
        // OP_ERROR
        let message = "session error";
        try {
          message = JSON.parse(new TextDecoder().decode(payload)).message ?? message;
        } catch {
          /* malformed error payload */
        }
        setStatus({ kind: "error", message });
        ws?.close();
      };

      ws.onerror = () => {
        if (disposed) return;
        setStatus((s) =>
          s.kind === "connected" || s.kind === "connecting"
            ? { kind: "error", message: "connection failed" }
            : s,
        );
      };

      ws.onclose = () => {
        if (disposed) return;
        setStatus((s) =>
          s.kind === "connected" || s.kind === "connecting"
            ? { kind: "closed" }
            : s,
        );
      };

      // ── Input: canvas-focused DOM listeners ⇄ RdpSession.send_* ──────────────
      function toCanvasCoords(e: MouseEvent, session: RdpSession) {
        const canvasEl = canvasRef.current;
        if (!canvasEl) return null;
        const rect = canvasEl.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return null;
        const w = session.width();
        const h = session.height();
        const x = Math.max(0, Math.min(w - 1, Math.round(((e.clientX - rect.left) / rect.width) * w)));
        const y = Math.max(0, Math.min(h - 1, Math.round(((e.clientY - rect.top) / rect.height) * h)));
        return { x, y };
      }

      const onKeyDown = (e: KeyboardEvent) => {
        const session = sessionRef.current;
        const scancode = SCANCODES[e.code];
        if (!session || scancode === undefined) return;
        e.preventDefault();
        sendInput(session.send_key(scancode, true));
      };
      const onKeyUp = (e: KeyboardEvent) => {
        const session = sessionRef.current;
        const scancode = SCANCODES[e.code];
        if (!session || scancode === undefined) return;
        e.preventDefault();
        sendInput(session.send_key(scancode, false));
      };
      const onMouseMove = (e: MouseEvent) => {
        const session = sessionRef.current;
        const pos = session && toCanvasCoords(e, session);
        if (!session || !pos) return;
        sendInput(session.send_mouse_move(pos.x, pos.y));
      };
      const onMouseDown = (e: MouseEvent) => {
        const session = sessionRef.current;
        if (!session) return;
        e.preventDefault();
        canvas.focus();
        sendInput(session.send_mouse_button(e.button, true));
      };
      const onMouseUp = (e: MouseEvent) => {
        const session = sessionRef.current;
        if (!session) return;
        e.preventDefault();
        sendInput(session.send_mouse_button(e.button, false));
      };
      const onWheel = (e: WheelEvent) => {
        const session = sessionRef.current;
        if (!session) return;
        e.preventDefault();
        // ponytail: coarse deltaY->rotation-units mapping (sign + fixed
        // 120/notch), ignores e.deltaMode/magnitude. Refine if fine-grained
        // scroll speed matters.
        sendInput(session.send_wheel(e.deltaY < 0 ? 120 : -120));
      };
      const onContextMenu = (e: Event) => e.preventDefault();

      canvas.addEventListener("keydown", onKeyDown);
      canvas.addEventListener("keyup", onKeyUp);
      canvas.addEventListener("mousemove", onMouseMove);
      canvas.addEventListener("mousedown", onMouseDown);
      canvas.addEventListener("mouseup", onMouseUp);
      canvas.addEventListener("wheel", onWheel, { passive: false });
      canvas.addEventListener("contextmenu", onContextMenu);

      cleanupInput = () => {
        canvas.removeEventListener("keydown", onKeyDown);
        canvas.removeEventListener("keyup", onKeyUp);
        canvas.removeEventListener("mousemove", onMouseMove);
        canvas.removeEventListener("mousedown", onMouseDown);
        canvas.removeEventListener("mouseup", onMouseUp);
        canvas.removeEventListener("wheel", onWheel);
        canvas.removeEventListener("contextmenu", onContextMenu);
      };
    }

    void connect();

    return () => {
      disposed = true;
      cleanupInput?.();
      wsRef.current?.close();
      wsRef.current = null;
      sessionRef.current?.free();
      sessionRef.current = null;
    };
    // Reconnect is explicit via `attempt`; assetId/login are route-stable.
  }, [attempt, assetId, login, createSession]);

  const terminated =
    status.kind === "closed" || status.kind === "exited" || status.kind === "error";

  return (
    <div className="flex h-dvh flex-col bg-background">
      {/* ── Top bar ─────────────────────────────────────────────────────────── */}
      <header className="flex h-11 shrink-0 items-center justify-between gap-3 border-b border-border bg-card px-3">
        <div className="flex min-w-0 items-center gap-2">
          <Monitor className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <h1 className="truncate text-body font-medium text-foreground">
            {login ? (
              <>
                <span className="font-mono">{login}</span>
                <span className="text-muted-foreground"> @ </span>
                <span className="font-mono text-muted-foreground" title={assetId}>
                  {assetLabel}
                </span>
              </>
            ) : (
              <span className="font-mono text-muted-foreground" title={assetId}>
                {assetLabel}
              </span>
            )}
          </h1>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <StatusPill status={status} />
          {terminated && (
            <Button
              variant="outline"
              size="sm"
              onClick={reconnect}
              className="h-7 gap-1.5 text-compact"
              aria-label="Reconnect"
            >
              <RotateCw className="h-3.5 w-3.5" aria-hidden="true" />
              Reconnect
            </Button>
          )}
          <Button
            variant="ghost"
            size="icon"
            onClick={close}
            className="h-7 w-7 text-muted-foreground hover:text-foreground"
            aria-label="Close RDP session"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </Button>
        </div>
      </header>

      {/* ── Desktop surface ─────────────────────────────────────────────────── */}
      <div className="relative flex min-h-0 flex-1 items-center justify-center overflow-auto bg-black">
        <canvas
          ref={canvasRef}
          tabIndex={0}
          className="max-h-full max-w-full outline-none"
          aria-label={`RDP desktop for ${login ? `${login}@` : ""}${assetId}`}
        />

        {status.kind === "connecting" && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <div className="flex items-center gap-2 rounded-md bg-black/50 px-3 py-2 text-compact text-slate-200">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              Opening session…
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
