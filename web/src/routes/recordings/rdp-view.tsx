import { useCallback, useEffect, useRef, useState } from "react";
import { RotateCw } from "lucide-react";
import init, { RdpSession } from "@/wasm/jumpgate_rdp.js";
import wasmUrl from "@/wasm/jumpgate_rdp_bg.wasm?url";
import { Button } from "@/components/ui/button";
import { parseRdpGraphics, type RdpFrame } from "./rdp-graphics";

// RdpView replays an `rdp-graphics-v1` recording into a canvas — the passive
// twin of the live client (web/src/routes/rdp/rdp.tsx): same WASM decode +
// blit, but frames are paced from the recorded `millis` offsets against a
// wall clock instead of arriving live over a socket, and `process()`'s
// returned input bytes are discarded (nothing to send back — this is replay,
// not a live session).
export function RdpView({ sessionId }: { sessionId: string }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const memoryRef = useRef<WebAssembly.Memory | null>(null);
  const sessionRef = useRef<RdpSession | null>(null);
  const framesRef = useRef<RdpFrame[]>([]);
  const headerBytesRef = useRef<Uint8Array | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [done, setDone] = useState(false);

  // Blits the wasm framebuffer to the canvas. Copied from rdp.tsx's `blit`:
  // re-reads the memory view fresh each call, since wasm memory can
  // grow/detach between frames.
  const blit = useCallback((session: RdpSession) => {
    const canvasEl = canvasRef.current;
    const mem = memoryRef.current;
    if (!canvasEl || !mem) return;
    const w = session.width();
    const h = session.height();
    if (canvasEl.width !== w) canvasEl.width = w;
    if (canvasEl.height !== h) canvasEl.height = h;
    const ctx = canvasEl.getContext("2d");
    if (!ctx) return;
    const pixels = new Uint8ClampedArray(mem.buffer, session.framebuffer_ptr(), session.framebuffer_len());
    ctx.putImageData(new ImageData(pixels, w, h), 0, 0);
  }, []);

  // Plays framesRef.current from index 0 against a wall clock, one
  // setTimeout-chain step per frame.
  // ponytail: naive setTimeout pacing, no seek/scrubber — add a proper
  // scrubber if reviewers need to jump around instead of watching linearly.
  const play = useCallback(() => {
    const session = sessionRef.current;
    if (!session) return;
    setDone(false);
    const startWall = performance.now();
    const step = (i: number) => {
      const frames = framesRef.current;
      if (i >= frames.length) {
        setDone(true);
        return;
      }
      const frame = frames[i];
      const delay = Math.max(0, frame.millis - (performance.now() - startWall));
      timerRef.current = setTimeout(() => {
        try {
          session.process(frame.action, frame.payload); // return value ignored: passive replay
          blit(session);
        } catch {
          // A recorded stream legitimately carries PDUs the PASSIVE replay
          // ActiveStage (seeded with an empty StaticChannelSet) can't route —
          // e.g. server data on a virtual channel the live browser negotiated
          // but this offline replay never joined ("unexpected channel received").
          // Those are safely skippable for graphics replay: skip the frame and
          // keep going rather than aborting the whole session (which blanked the
          // canvas). Graphics PDUs still render; only the unroutable frame is dropped.
        }
        setProgress({ current: i + 1, total: frames.length });
        step(i + 1);
      }, delay);
    };
    step(0);
  }, [blit]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setDone(false);
    setProgress({ current: 0, total: 0 });

    async function load() {
      const wasm = await init(wasmUrl);
      if (cancelled) return;
      memoryRef.current = wasm.memory;

      const resp = await fetch(`/api/recordings/${sessionId}/cast`, { credentials: "include" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const bytes = new Uint8Array(await resp.arrayBuffer());
      if (cancelled) return;

      const { headerBytes, frames } = parseRdpGraphics(bytes);
      headerBytesRef.current = headerBytes;
      framesRef.current = frames;

      const session = new RdpSession(headerBytes);
      sessionRef.current = session;
      blit(session);
      setProgress({ current: 0, total: frames.length });
      setLoading(false);
      play();
    }

    load().catch((err) => {
      if (!cancelled) {
        setError(err instanceof Error ? err.message : "load failed");
        setLoading(false);
      }
    });

    return () => {
      cancelled = true;
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = null;
      sessionRef.current?.free();
      sessionRef.current = null;
    };
    // Re-mount only when the sessionId changes; blit/play are stable callbacks.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  const restart = useCallback(() => {
    const headerBytes = headerBytesRef.current;
    if (!headerBytes) return;
    if (timerRef.current) clearTimeout(timerRef.current);
    sessionRef.current?.free();
    try {
      const session = new RdpSession(headerBytes);
      sessionRef.current = session;
      blit(session);
      setError(null);
      setProgress({ current: 0, total: framesRef.current.length });
      play();
    } catch (err) {
      setError(err instanceof Error ? err.message : "restart failed");
    }
  }, [blit, play]);

  if (error) {
    return <div className="p-4 text-body text-red-400 font-mono">Replay unavailable ({error}).</div>;
  }
  if (loading) {
    return <div className="p-4 text-body text-white/40 font-mono">Loading recording…</div>;
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center justify-between gap-3 px-4 py-2 border-b border-white/10 text-eyebrow text-white/50 font-mono shrink-0">
        <span>
          frame {progress.current}/{progress.total}
          {done && " · replay finished"}
        </span>
        <Button
          variant="ghost"
          size="sm"
          onClick={restart}
          className="h-6 gap-1 px-2 text-white/60 hover:text-white hover:bg-white/10"
        >
          <RotateCw className="h-3 w-3" aria-hidden="true" />
          Restart
        </Button>
      </div>
      <div className="relative flex flex-1 items-center justify-center overflow-auto bg-black">
        <canvas
          ref={canvasRef}
          className="max-h-full max-w-full"
          aria-label={`RDP session replay for session ${sessionId}`}
        />
      </div>
    </div>
  );
}
