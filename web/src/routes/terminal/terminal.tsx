/**
 * terminal.tsx — full-screen in-browser SSH terminal.
 *
 * A chromeless, own-layout page (rendered OUTSIDE the AppShell): a slim top bar
 * (asset label + connection-status pill + close button) with an xterm.js
 * terminal filling the rest of the viewport.
 *
 * Flow on mount:
 *   1. CreateWebSession({assetId, login}) → {ticket, gatewayEndpoint, insecure} —
 *      fetched right before the socket opens (the ticket is short-lived, ~60s).
 *   2. Open  wss://<gatewayEndpoint>/terminal?ticket=<ticket>  (arraybuffer). In the
 *      DEV plaintext env (console over http) warden may grant an insecure endpoint;
 *      then the scheme is ws:// instead. Production is always wss://.
 *   3. Bridge xterm.js ⇄ WebSocket via the [opcode][payload] frame protocol.
 *
 * Connection is explicit: on close/exit/error we surface a status and a
 * Reconnect button — there is NO automatic reconnect (a fresh ticket must be
 * minted, and re-entering an SSH shell silently would be surprising).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useParams, useSearchParams, useNavigate } from "react-router-dom";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebglAddon } from "@xterm/addon-webgl";
import { useTheme } from "next-themes";
import { X, RotateCw, Loader2, Terminal as TerminalIcon } from "lucide-react";
import "@xterm/xterm/css/xterm.css";
import { createWebSession } from "@/gen/jumpgate/session/v1/session-SessionService_connectquery";
import { getAssetDisplay } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { connectErrorMessage } from "@/lib/format";
import { encodeData, encodeResize, decodeFrame, OP_DATA, OP_EXIT } from "./terminal-protocol";

// ─── Connection status ────────────────────────────────────────────────────────

type Status =
  | { kind: "connecting" }
  | { kind: "connected" }
  | { kind: "exited"; code: number }
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
  const detail =
    status.kind === "exited"
      ? ` (${status.code})`
      : status.kind === "error"
        ? `: ${status.message}`
        : "";
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

// ─── xterm theme (token-derived, light + dark) ────────────────────────────────

// xterm.js paints to a canvas/webgl surface and cannot read CSS variables, so
// the palette is resolved from the semantic theme tokens per resolved theme.
function xtermTheme(dark: boolean) {
  return dark
    ? {
        background: "#0B1120",
        foreground: "#E2E8F0",
        cursor: "#E2E8F0",
        cursorAccent: "#0B1120",
        selectionBackground: "#334155",
      }
    : {
        background: "#0F172A", // keep the terminal itself dark for legibility
        foreground: "#E2E8F0",
        cursor: "#E2E8F0",
        cursorAccent: "#0F172A",
        selectionBackground: "#334155",
      };
}

// ─── Terminal page ────────────────────────────────────────────────────────────

export function TerminalPage() {
  const { assetId = "" } = useParams<{ assetId: string }>();
  const [searchParams] = useSearchParams();
  const login = searchParams.get("login") ?? "";
  const navigate = useNavigate();
  const { resolvedTheme } = useTheme();

  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const [status, setStatus] = useState<Status>({ kind: "connecting" });
  // Bumping this re-runs the connect effect (explicit reconnect only).
  const [attempt, setAttempt] = useState(0);

  const { mutateAsync: createSession } = useMutation(createWebSession);

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
    // Prefer going back so the catalog/prior view is restored; fall back to root.
    if (window.history.length > 1) navigate(-1);
    else navigate("/");
  }, [navigate]);

  const reconnect = useCallback(() => {
    setStatus({ kind: "connecting" });
    setAttempt((n) => n + 1);
  }, []);

  // ─── Terminal lifecycle: build once, dispose on unmount ─────────────────────
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const term = new XTerm({
      cursorBlink: true,
      fontFamily:
        'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
      fontSize: 13,
      theme: xtermTheme(resolvedTheme === "dark"),
      allowProposedApi: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(container);
    try {
      term.loadAddon(new WebglAddon());
    } catch {
      // WebGL unavailable (e.g. headless / no GPU) — fall back to the DOM/canvas
      // renderer silently.
    }
    fit.fit();

    termRef.current = term;
    fitRef.current = fit;
    // Expose the live terminal for e2e observability (reading the screen buffer is
    // renderer-agnostic, unlike scraping the canvas/DOM). Harmless — it's the
    // caller's own session.
    (window as unknown as { __jumpgateTerm?: XTerm }).__jumpgateTerm = term;

    return () => {
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
    // Rebuilt on theme change so the palette stays correct.
  }, [resolvedTheme]);

  // ─── Connect: mint ticket → open WS → bridge ────────────────────────────────
  useEffect(() => {
    let disposed = false;
    let ws: WebSocket | null = null;

    async function connect() {
      const term = termRef.current;
      const fit = fitRef.current;
      if (!term || !fit) return;

      let ticket: string;
      let gatewayEndpoint: string;
      let insecure: boolean;
      try {
        // Ask for the plaintext (ws://) endpoint only when the console itself is
        // served over plain http (dev). Warden honors it only if it allows insecure
        // sessions; otherwise it returns the secure endpoint (fail-closed).
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

      // Scheme follows the response: ws:// only when warden granted the insecure
      // endpoint, wss:// otherwise.
      const scheme = insecure ? "ws" : "wss";
      ws = new WebSocket(
        `${scheme}://${gatewayEndpoint}/terminal?ticket=${encodeURIComponent(ticket)}`,
      );
      ws.binaryType = "arraybuffer";
      wsRef.current = ws;

      const sendResize = () => {
        if (ws?.readyState !== WebSocket.OPEN) return;
        fit.fit();
        ws.send(encodeResize(term.cols, term.rows));
      };

      ws.onopen = () => {
        if (disposed) return;
        setStatus({ kind: "connected" });
        sendResize();
        term.focus();
      };

      ws.onmessage = (ev: MessageEvent) => {
        const { op, payload } = decodeFrame(new Uint8Array(ev.data as ArrayBuffer));
        if (op === OP_DATA) {
          term.write(payload);
        } else if (op === OP_EXIT) {
          let code = 0;
          try {
            code = JSON.parse(new TextDecoder().decode(payload)).code ?? 0;
          } catch {
            /* malformed exit — default 0 */
          }
          setStatus({ kind: "exited", code });
          ws?.close();
        } else {
          // OP_ERROR
          let message = "session error";
          try {
            message = JSON.parse(new TextDecoder().decode(payload)).message ?? message;
          } catch {
            /* malformed error payload */
          }
          setStatus({ kind: "error", message });
          ws?.close();
        }
      };

      ws.onerror = () => {
        if (disposed) return;
        // Only surface a generic error if we haven't already resolved to a more
        // specific terminal status (exit/error frame).
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

      // Keystrokes → DATA frames.
      const onData = term.onData((d) => {
        if (ws?.readyState === WebSocket.OPEN) {
          ws.send(encodeData(new TextEncoder().encode(d)));
        }
      });

      // Container resize → fit + RESIZE frame.
      const ro = new ResizeObserver(() => sendResize());
      if (containerRef.current) ro.observe(containerRef.current);

      // Attach teardown for this connect run.
      cleanupRef.current = () => {
        onData.dispose();
        ro.disconnect();
      };
    }

    // Per-connect cleanup (data listener + resize observer). Stored in a ref so
    // the outer cleanup can reach it regardless of async timing.
    const cleanupRef = { current: null as null | (() => void) };
    void connect();

    return () => {
      disposed = true;
      cleanupRef.current?.();
      wsRef.current?.close();
      wsRef.current = null;
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
          <TerminalIcon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
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
            aria-label="Close terminal"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </Button>
        </div>
      </header>

      {/* ── Terminal surface ────────────────────────────────────────────────── */}
      <div className="relative min-h-0 flex-1 bg-[#0F172A]">
        <div
          ref={containerRef}
          className="absolute inset-0 p-2"
          aria-label={`SSH terminal for ${login ? `${login}@` : ""}${assetId}`}
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
